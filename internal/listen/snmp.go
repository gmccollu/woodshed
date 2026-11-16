package listen

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
)

// The SNMP trap listener's socket (SPEC §11.2, §11.5): a UDP socket with its
// own receive queue and drainer, like syslog's. The reader reads a datagram,
// stamps it, applies the blocklist and allowlist and queues it; it never
// truncates (any datagram up to 65,507 bytes is kept whole). The drainer hands
// each datagram, in arrival order, to Options.Trap, which decodes it, stores it
// and answers informs through TrapPacket.Reply once the store has it.

// TrapPacket is one datagram the SNMP listener read, for Options.Trap. Raw is
// owned by the callee.
type TrapPacket struct {
	Raw      []byte
	From     netip.AddrPort // the sender's address and port (replies go back to it)
	Received time.Time      // UTC
	conn     *net.UDPConn
	srv      *Server
}

// Reply sends b back to the sender from the listener's socket (an inform's
// Response or a Report).
func (p *TrapPacket) Reply(b []byte) error {
	if p.conn == nil {
		return errors.New("listen: no socket to reply on")
	}
	_, err := p.conn.WriteToUDPAddrPort(b, p.From)
	return err
}

// Refuse counts the datagram as refused for its sender in /api/rejected, with
// reason (RejectCommunity for a community the list doesn't hold).
func (p *TrapPacket) Refuse(reason string) {
	if p.srv != nil {
		p.srv.rejects.add(p.From.Addr(), p.Received, 1, reason)
	}
}

// RejectCommunity is /api/rejected's reason for a v1/v2c trap refused by
// listeners.snmp.communities (SPEC §11.2.2).
const RejectCommunity = "community"

// TrapHandler handles one SNMP datagram (see Options.Trap).
type TrapHandler func(p *TrapPacket)

type snmpListener struct {
	srv     *Server
	conn    *net.UDPConn
	addr    string
	bound   netip.AddrPort
	q       *udpQueue
	done    chan struct{}
	drained chan struct{}
}

func listenSNMP(s *Server, ln config.Listener, rcvbuf int, q *udpQueue) (*snmpListener, error) {
	ap, err := bindAddr(ln)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	l := &snmpListener{srv: s, conn: conn, addr: ln.Addr, bound: conn.LocalAddr().(*net.UDPAddr).AddrPort(), q: q,
		done: make(chan struct{}), drained: make(chan struct{})}
	setRcvbuf(conn, rcvbuf)
	go l.run()
	go l.drain()
	return l, nil
}

func (l *snmpListener) status() ListenerStatus {
	return ListenerStatus{Proto: "snmp", Addr: l.addr, Port: int(l.bound.Port()), OK: true}
}

func (l *snmpListener) run() {
	defer close(l.done)
	buf := make([]byte, udpReadBuf)
	var errRun int
	var lastLog time.Time
	for {
		n, from, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if time.Since(lastLog) > time.Minute {
				l.srv.log.Warn("listen: SNMP read error", "err", err)
				lastLog = time.Now()
			}
			if errRun++; errRun > 100 {
				time.Sleep(10 * time.Millisecond)
			}
			continue
		}
		errRun = 0
		if n == 0 {
			continue
		}
		l.srv.enqueueTrap(l.q, l.conn, buf[:n], from)
	}
}

func (l *snmpListener) drain() {
	defer close(l.drained)
	conn := l.conn
	l.srv.drainQueueWith(l.q, func(e *queued) {
		p := &TrapPacket{Raw: e.raw, From: netip.AddrPortFrom(e.from, e.port), Received: e.at, conn: conn, srv: l.srv}
		l.srv.received.Add(1)
		l.srv.opts.Trap(p)
	}, l.srv.opts.OnTrapQueueDrop)
}

// close stops the reader, then drains the queue as the syslog UDP listener's
// close does (the drainer's replies still go out on the closed socket only
// until it's closed, so informs read before the stop are stored but may go
// unanswered; their senders retransmit).
func (l *snmpListener) close() {
	l.conn.Close()
	<-l.done
	l.q.close()
	t := time.NewTimer(l.srv.opts.DrainTimeout)
	defer t.Stop()
	select {
	case <-l.drained:
		return
	case <-t.C:
	}
	l.q.abandon()
	<-l.drained
	l.srv.log.Warn("listen: SNMP queue not drained in time at stop; the rest counted as dropped",
		"timeout", l.srv.opts.DrainTimeout)
}

// enqueueTrap is the SNMP reader's half: the blocklist and the allowlist, and
// a copy into q (never truncated), or, for a lone datagram, Options.TrapTry.
func (s *Server) enqueueTrap(q *udpQueue, conn *net.UDPConn, raw []byte, from netip.AddrPort) {
	now := s.opts.Clock().UTC()
	addr := from.Addr().Unmap()
	if r := s.allow.Load().refusal(addr); r != "" {
		s.rejects.add(addr, now, 1, r)
		return
	}
	e := queued{raw: append(make([]byte, 0, len(raw)), raw...), from: addr, port: from.Port(), at: now}
	if s.opts.TrapTry != nil && q.inline(now) {
		p := &TrapPacket{Raw: e.raw, From: netip.AddrPortFrom(addr, e.port), Received: now, conn: conn, srv: s}
		s.received.Add(1)
		e.finish = s.opts.TrapTry(p)
		if e.finish == nil {
			s.inline.Add(1)
			return
		}
		// The queue is empty (inline), so this can't be refused for room.
	}
	q.push(e)
}

// --- lifecycle (callers hold s.mu) ---

func (s *Server) startSNMP(ev *events) {
	s.snmpErr = nil
	l := s.cfg.SNMP.Listener()
	if !l.Enabled || s.closed {
		return
	}
	if s.opts.Trap == nil {
		st := ListenerStatus{Proto: "snmp", Addr: l.Addr, Port: l.Port, Error: "no trap receiver (internal error)"}
		s.snmpErr = &st
		ev.bind(st)
		return
	}
	q := newUDPQueue(0, 0, s.snmpHist)
	q.setLimits(queueLimits(s.cfg))
	sl, err := listenSNMP(s, l, rcvbufOf(s.cfg), q)
	if err != nil {
		st := ListenerStatus{Proto: "snmp", Addr: l.Addr, Port: l.Port, Error: osError(err)}
		if l.Port > 0 && isAddrInUse(err) {
			st.Holder = safeHolder(s.opts.Holder, "udp", l.Port)
		}
		s.log.Error("listen: bind failed", "proto", "snmp", "addr", l.Addr, "port", l.Port, "err", err, "holder", st.Holder)
		s.snmpErr = &st
		ev.bind(st)
		return
	}
	s.snmp, s.snmpQ = sl, q
	ev.add("snmp", LevelInfo, KindStart, fmt.Sprintf("SNMP trap listener started on UDP %s", hostPort(l.Addr, int(sl.bound.Port()))))
	s.log.Info("listen: SNMP listening", "addr", sl.bound)
}

func (s *Server) stopSNMP(ev *events) {
	s.snmpErr = nil
	if s.snmp == nil {
		return
	}
	s.snmp.close()
	ev.add("snmp", LevelInfo, KindStop, "SNMP trap listener on UDP "+hostPort(s.snmp.addr, int(s.snmp.bound.Port()))+" stopped")
	s.snmp = nil
}

// SNMPAddr returns the bound SNMP address, or false if it isn't running.
func (s *Server) SNMPAddr() (netip.AddrPort, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snmp == nil {
		return netip.AddrPort{}, false
	}
	return s.snmp.bound, true
}

// snmpChanged reports whether the SNMP listener must be rebound.
func snmpChanged(a, b config.SNMPListener) bool {
	return a.Enabled != b.Enabled || a.Addr != b.Addr || a.Port != b.Port
}
