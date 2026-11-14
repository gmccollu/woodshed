package listen

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/syslog"
)

// udpReadBuf is the read buffer: big enough for any UDP datagram (65,507 bytes
// over IPv4, 65,527 over IPv6), so the OS never cuts one before we see its length.
const udpReadBuf = 64 << 10

type udpListener struct {
	srv       *Server
	conn      *net.UDPConn
	addr      string // as configured
	bound     netip.AddrPort
	requested int
	granted   int
	q         *udpQueue
	done      chan struct{} // the reader ended
	drained   chan struct{} // the drainer ended
}

func listenUDP(s *Server, ln config.Listener, rcvbuf int, q *udpQueue) (*udpListener, error) {
	ap, err := bindAddr(ln)
	if err != nil {
		return nil, err
	}
	// "udp" with a wildcard address binds dual-stack (IPv4 and IPv6) where the OS
	// supports it.
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	u := &udpListener{
		srv:       s,
		conn:      conn,
		addr:      ln.Addr,
		bound:     conn.LocalAddr().(*net.UDPAddr).AddrPort(),
		requested: rcvbuf,
		q:         q,
		done:      make(chan struct{}),
		drained:   make(chan struct{}),
	}
	u.granted = setRcvbuf(conn, rcvbuf)
	go u.run()
	go u.drain()
	return u, nil
}

func (u *udpListener) status() ListenerStatus {
	return ListenerStatus{Proto: "udp", Addr: u.addr, Port: int(u.bound.Port()), OK: true}
}

// run reads datagrams until the socket is closed. One datagram is one message.
// It only reads, stamps, applies the blocklist and allowlist and queues
// (SPEC §11.5): parsing and the store are the drainer's, so a slow disk can't
// hold up the socket.
func (u *udpListener) run() {
	defer close(u.done)
	buf := make([]byte, udpReadBuf)
	var errRun int
	var lastLog time.Time
	for {
		n, from, err := u.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient errors (ICMP-induced resets on Windows, ENOBUFS, ...). Log at
			// most once a minute and back off if they persist, so a broken socket
			// can't spin a core.
			if time.Since(lastLog) > time.Minute {
				u.srv.log.Warn("listen: UDP read error", "err", err)
				lastLog = time.Now()
			}
			if errRun++; errRun > 100 {
				time.Sleep(10 * time.Millisecond)
			}
			continue
		}
		errRun = 0
		msg := syslog.TrimDatagram(buf[:n])
		if len(msg) == 0 {
			continue
		}
		u.srv.enqueue(u.q, msg, from.Addr())
	}
}

// drain hands queued messages to the sink in arrival order until the queue is
// closed and empty, and reports queue drops.
func (u *udpListener) drain() {
	defer close(u.drained)
	u.srv.drainQueue(u.q)
}

// close stops the reader, then lets the drainer empty the queue into the sink
// for at most the drain timeout. Whatever is still queued then is counted as
// dropped; close still waits for the message being delivered, so no sink call
// happens after it returns.
func (u *udpListener) close() {
	u.conn.Close()
	<-u.done
	u.q.close()
	t := time.NewTimer(u.srv.opts.DrainTimeout)
	defer t.Stop()
	select {
	case <-u.drained:
		return
	case <-t.C:
	}
	u.q.abandon()
	<-u.drained
	u.srv.log.Warn("listen: UDP queue not drained in time at stop; the rest counted as dropped",
		"timeout", u.srv.opts.DrainTimeout)
}

// setRcvbuf asks for a receive buffer of want bytes and returns what the OS
// granted. macOS refuses sizes above kern.ipc.maxsockbuf outright (ENOBUFS)
// instead of capping them, so on refusal it searches for the largest size the OS
// accepts.
func setRcvbuf(c *net.UDPConn, want int) int {
	if want <= 0 {
		return getRcvbuf(c)
	}
	if err := c.SetReadBuffer(want); err != nil {
		lo, hi := 0, want // lo: accepted (or untried 0), hi: refused
		for hi-lo > 16<<10 {
			mid := lo + (hi-lo)/2
			if c.SetReadBuffer(mid) == nil {
				lo = mid
			} else {
				hi = mid
			}
		}
		if lo > 0 {
			c.SetReadBuffer(lo)
		}
	}
	return getRcvbuf(c)
}

// getRcvbuf returns the socket's receive buffer size as the OS reports it (on
// Linux, which doubles the value for its own bookkeeping, halved back so it
// compares with the request).
func getRcvbuf(c *net.UDPConn) int {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0
	}
	n := 0
	rc.Control(func(fd uintptr) { n = sockRcvbuf(fd) })
	return n
}
