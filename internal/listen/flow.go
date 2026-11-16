package listen

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
)

// The flow listener (SPEC §13.1): up to two UDP sockets, NetFlow (2055) and
// IPFIX (4739), that both read every version, feeding one receive queue of
// the listener's own size (flow packets are larger and come in bursts) and
// one drainer, which hands each packet in arrival order to Options.Flow. One
// drainer keeps the collector's template state single-threaded. Each reader
// applies the blocklist and the allowlist, like syslog's and the trap
// listener's; it never truncates. There's no inline fast path: flow
// exporters send steadily, so the queue's hand-off cost is spread over many
// records per packet.

// FlowPacket is one datagram a flow socket read, for Options.Flow. Data is
// owned by the callee.
type FlowPacket struct {
	Data     []byte
	From     netip.AddrPort // the exporter's address and source port
	Received time.Time      // UTC
	Proto    string         // the socket it came in on: "netflow" or "ipfix"
}

// FlowHandler handles one flow datagram (see Options.Flow).
type FlowHandler func(p *FlowPacket)

// flowSocket is one bound flow port.
type flowSocket struct {
	srv   *Server
	proto string
	conn  *net.UDPConn
	addr  string
	bound netip.AddrPort
	done  chan struct{}
}

// flowListener is the running flow listener: its sockets and the shared queue.
type flowListener struct {
	socks   []*flowSocket
	q       *udpQueue
	drained chan struct{}
}

func (f *flowSocket) status() ListenerStatus {
	return ListenerStatus{Proto: f.proto, Addr: f.addr, Port: int(f.bound.Port()), OK: true}
}

func (f *flowSocket) run(q *udpQueue) {
	defer close(f.done)
	buf := make([]byte, udpReadBuf)
	var errRun int
	var lastLog time.Time
	for {
		n, from, err := f.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if time.Since(lastLog) > time.Minute {
				f.srv.log.Warn("listen: flow read error", "proto", f.proto, "err", err)
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
		f.srv.enqueueFlow(q, buf[:n], from, f.proto)
	}
}

// enqueueFlow is a flow reader's half: the blocklist and the allowlist, and a
// copy into q (never truncated).
func (s *Server) enqueueFlow(q *udpQueue, raw []byte, from netip.AddrPort, proto string) {
	now := s.opts.Clock().UTC()
	addr := from.Addr().Unmap()
	if r := s.allow.Load().refusal(addr); r != "" {
		s.rejects.add(addr, now, 1, r)
		return
	}
	// Flow packets are never cut, so queued.truncated carries which socket
	// the packet came in on (true: IPFIX).
	q.push(queued{raw: append(make([]byte, 0, len(raw)), raw...), from: addr, port: from.Port(), at: now,
		truncated: proto == "ipfix"})
}

func (l *flowListener) drain(s *Server) {
	defer close(l.drained)
	s.drainQueueWith(l.q, func(e *queued) {
		proto := "netflow"
		if e.truncated {
			proto = "ipfix"
		}
		p := &FlowPacket{Data: e.raw, From: netip.AddrPortFrom(e.from, e.port), Received: e.at, Proto: proto}
		s.received.Add(1)
		s.opts.Flow(p)
	}, s.opts.OnFlowQueueDrop)
}

// close stops the readers, then drains the queue as the other UDP listeners'
// close does.
func (l *flowListener) close(s *Server) {
	for _, f := range l.socks {
		f.conn.Close()
		<-f.done
	}
	l.q.close()
	t := time.NewTimer(s.opts.DrainTimeout)
	defer t.Stop()
	select {
	case <-l.drained:
		return
	case <-t.C:
	}
	l.q.abandon()
	<-l.drained
	s.log.Warn("listen: flow queue not drained in time at stop; the rest counted as dropped", "timeout", s.opts.DrainTimeout)
}

// flowQueueLimits are the flow listener's queue size, or its defaults.
func flowQueueLimits(f config.FlowListener) (int, int64) {
	n, b := f.QueueMessages, f.QueueBytes
	if n <= 0 {
		n = config.DefaultFlowQueueMessages
	}
	if b <= 0 {
		b = config.DefaultFlowQueueBytes
	}
	return n, b
}

// --- lifecycle (callers hold s.mu) ---

// startFlow binds the enabled flow ports. A port that fails shows in Status
// with its error; the other still runs.
func (s *Server) startFlow(ev *events) {
	s.flowErrs = nil
	f := s.cfg.Flow
	if !f.Enabled || s.closed {
		return
	}
	ports := f.Ports()
	if s.opts.Flow == nil {
		for _, p := range ports {
			st := ListenerStatus{Proto: p.Proto, Addr: f.Addr, Port: p.Port, Error: "no flow collector (internal error)"}
			s.flowErrs = append(s.flowErrs, st)
			ev.bind(st)
		}
		return
	}
	q := newUDPQueue(0, 0, s.flowHist)
	q.setLimits(flowQueueLimits(f))
	l := &flowListener{q: q, drained: make(chan struct{})}
	for _, p := range ports {
		// A port of -1 binds an ephemeral port (tests; 0 turns a flow port off).
		ln := config.Listener{Enabled: true, Addr: f.Addr, Port: max(p.Port, 0)}
		sock, err := s.bindFlow(ln, p.Proto)
		if err != nil {
			st := ListenerStatus{Proto: p.Proto, Addr: f.Addr, Port: p.Port, Error: osError(err)}
			if p.Port > 0 && isAddrInUse(err) {
				st.Holder = safeHolder(s.opts.Holder, "udp", p.Port)
			}
			s.log.Error("listen: bind failed", "proto", p.Proto, "addr", f.Addr, "port", p.Port, "err", err, "holder", st.Holder)
			s.flowErrs = append(s.flowErrs, st)
			ev.bind(st)
			continue
		}
		l.socks = append(l.socks, sock)
		ev.add(p.Proto, LevelInfo, KindStart, fmt.Sprintf("%s listener started on UDP %s", flowLabel(p.Proto),
			hostPort(f.Addr, int(sock.bound.Port()))))
		s.log.Info("listen: flows listening", "proto", p.Proto, "addr", sock.bound)
	}
	s.flowQ = q
	if len(l.socks) == 0 {
		q.close()
		return
	}
	for _, sock := range l.socks {
		go sock.run(q)
	}
	go l.drain(s)
	s.flow = l
}

func (s *Server) bindFlow(ln config.Listener, proto string) (*flowSocket, error) {
	ap, err := bindAddr(ln)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	setRcvbuf(conn, rcvbufOf(s.cfg))
	return &flowSocket{srv: s, proto: proto, conn: conn, addr: ln.Addr,
		bound: conn.LocalAddr().(*net.UDPAddr).AddrPort(), done: make(chan struct{})}, nil
}

func flowLabel(proto string) string {
	if proto == "ipfix" {
		return "IPFIX"
	}
	return "NetFlow"
}

func (s *Server) stopFlow(ev *events) {
	s.flowErrs = nil
	if s.flow == nil {
		return
	}
	s.flow.close(s)
	for _, f := range s.flow.socks {
		ev.add(f.proto, LevelInfo, KindStop, flowLabel(f.proto)+" listener on UDP "+hostPort(f.addr, int(f.bound.Port()))+" stopped")
	}
	s.flow = nil
}

// FlowAddrs returns the bound flow ports by proto ("netflow", "ipfix").
func (s *Server) FlowAddrs() map[string]netip.AddrPort {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]netip.AddrPort{}
	if s.flow != nil {
		for _, f := range s.flow.socks {
			out[f.proto] = f.bound
		}
	}
	return out
}

// flowChanged reports whether the flow listener must be rebound.
func flowChanged(a, b config.FlowListener) bool {
	return a.Enabled != b.Enabled || a.Addr != b.Addr || a.NetFlowPort != b.NetFlowPort || a.IPFIXPort != b.IPFIXPort
}

// flowStatus appends the flow listener's entries: each enabled port, bound
// or with its error.
func (s *Server) flowStatus(st *Status) {
	if !s.cfg.Flow.Enabled {
		return
	}
	if s.flow != nil {
		for _, f := range s.flow.socks {
			st.Listeners = append(st.Listeners, f.status())
		}
	}
	st.Listeners = append(st.Listeners, s.flowErrs...)
	port := 0
	if s.flow != nil && len(s.flow.socks) > 0 {
		port = int(s.flow.socks[0].bound.Port())
	}
	q := s.flowQ
	if q == nil {
		q = newUDPQueue(0, 0, s.flowHist)
		q.setLimits(flowQueueLimits(s.cfg.Flow))
	}
	st.UDPQueues = append(st.UDPQueues, q.status("flow", port, s.opts.Clock(), s.started))
}
