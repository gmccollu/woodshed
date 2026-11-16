package poller

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// The poller's one UDP socket (SPEC §12.2): an ephemeral port on the wildcard
// address, opened when the first target is polled and closed when none is
// left, so polling opens no listening port of its own. Every request goes out
// on it to a configured target only; a reply is delivered to its request only
// when it comes from the address and port polled and carries an outstanding
// request ID (or v3 msgID). Anything else is dropped and counted (unmatched);
// a reply with a matching ID from another address is also noted on the
// request, so the test poll can say the agent answers from the wrong address.

// socket is the shared socket.
type socket struct {
	conn *net.UDPConn
	// onSend, when set, sees every destination (tests).
	onSend func(netip.AddrPort)

	mu      sync.Mutex
	waiters map[int64]*waiter

	unmatched atomic.Int64
	closed    chan struct{}
}

type waiter struct {
	to    netip.AddrPort
	ch    chan []byte
	wrong netip.AddrPort // a matching ID from another address, if seen
}

func openSocket(onSend func(netip.AddrPort)) (*socket, error) {
	conn, err := listenWildcard()
	if err != nil {
		return nil, err
	}
	s := &socket{conn: conn, onSend: onSend, waiters: map[int64]*waiter{}, closed: make(chan struct{})}
	go s.read()
	return s, nil
}

// listenWildcard opens the dual-stack wildcard socket on a port no IPv4
// socket holds. macOS hands a dual-stack [::]:0 an ephemeral port a socket on
// 127.0.0.1 may already hold (seen as 3 in 30,000); replies from a target on
// loopback then go to that socket, not ours. An explicit bind is checked
// against IPv4 sockets, so the port is picked on IPv4 first, then bound on
// the wildcard; a race lost to another program is retried.
func listenWildcard() (*net.UDPConn, error) {
	for range 20 {
		pick, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
		if err != nil {
			break
		}
		port := pick.LocalAddr().(*net.UDPAddr).Port
		pick.Close()
		if conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port}); err == nil {
			return conn, nil
		}
	}
	return net.ListenUDP("udp", &net.UDPAddr{})
}

func (s *socket) close() {
	s.conn.Close()
	<-s.closed
}

func norm(ap netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()) }

func (s *socket) read() {
	defer close(s.closed)
	buf := make([]byte, 65535)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Windows reports an ICMP port-unreachable as an error on the next
			// read of an unconnected socket; it can't be told apart per target.
			continue
		}
		from = norm(from)
		_, id, ok := snmp.PeekID(buf[:n])
		if !ok {
			s.unmatched.Add(1)
			continue
		}
		s.mu.Lock()
		w := s.waiters[id]
		if w != nil && w.to != from {
			w.wrong = from
			w = nil
		}
		s.mu.Unlock()
		if w == nil {
			s.unmatched.Add(1)
			continue
		}
		select {
		case w.ch <- append([]byte(nil), buf[:n]...):
		default:
			s.unmatched.Add(1) // a duplicate
		}
	}
}

// transport is the Transport for one target.
type transport struct {
	s  *socket
	to netip.AddrPort
	// wrongFrom is the last address a matching reply came from instead of the
	// target's (nil if none).
	wrongFrom atomic.Pointer[netip.AddrPort]
}

// wrong is the last wrong source seen (zero if none).
func (t *transport) wrong() netip.AddrPort {
	if p := t.wrongFrom.Load(); p != nil {
		return *p
	}
	return netip.AddrPort{}
}

func (s *socket) transport(to netip.AddrPort) *transport { return &transport{s: s, to: norm(to)} }

// errIDInUse is a request ID already outstanding (31 random bits: retried).
var errIDInUse = errors.New("poller: request ID in use")

func (t *transport) Exchange(ctx context.Context, req []byte, id int64, timeout time.Duration) ([]byte, error) {
	w := &waiter{to: t.to, ch: make(chan []byte, 1)}
	t.s.mu.Lock()
	if _, busy := t.s.waiters[id]; busy {
		t.s.mu.Unlock()
		return nil, errIDInUse
	}
	t.s.waiters[id] = w
	t.s.mu.Unlock()
	defer func() {
		t.s.mu.Lock()
		delete(t.s.waiters, id)
		if w.wrong.IsValid() {
			wf := w.wrong
			t.wrongFrom.Store(&wf)
		}
		t.s.mu.Unlock()
	}()
	if t.s.onSend != nil {
		t.s.onSend(t.to)
	}
	if _, err := t.s.conn.WriteToUDPAddrPort(req, t.to); err != nil {
		if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
			return nil, errors.Join(snmp.ErrUnreachable, err)
		}
		return nil, err
	}
	tm := time.NewTimer(timeout)
	defer tm.Stop()
	select {
	case b := <-w.ch:
		return b, nil
	case <-tm.C:
		return nil, snmp.ErrTimeout
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
