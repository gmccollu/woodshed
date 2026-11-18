package listen

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/syslog"
)

// TCP abuse limits (security review M6). One host must not be able to take every
// connection slot by opening many connections and dribbling a byte now and then:
//
//   - at most tcp_max_conns_per_source connections per sender address, and at most
//     tcp_max_conns_per_prefix per IPv6 /64 (one host can pick from a whole /64,
//     but a server VLAN shares one too). At the limit, a newcomer evicts that
//     address's (or /64's) connection idle longest, if one has had no complete
//     message for more than EvictIdle and has no message in progress; otherwise
//     it's refused. So a sender that rebooted without closing its connections
//     isn't locked out by its own dead ones for the whole idle timeout;
//   - once a message starts, all of it must arrive within tcp_frame_timeout, or
//     the connection is closed and the part that arrived is stored, marked
//     incomplete;
//   - between messages, the idle timeout (tcp_idle_timeout, default 24 h) is
//     renewed only by complete messages. It's long on purpose: some senders
//     keep one connection for days without keepalives and notice it was closed
//     only when a later write fails, losing what they send until they reconnect;
//   - when MaxConns are open, a newcomer evicts the connection idle longest (no
//     complete message for more than EvictIdle); if none is, the oldest connection
//     of the biggest source (IPv4 address or IPv6 /64), so busy sources can't
//     pin every slot. A newcomer whose own source is the biggest is refused;
//   - TCP keepalives are on for every accepted connection (tcpKeepAlive), so a
//     connection to a sender that rebooted or vanished is closed within minutes,
//     whatever the idle timeout.

// tcpKeepAlive is set on every accepted connection: the first probe after 15 s
// without traffic, then every 15 s, and the connection is closed after 9
// unanswered ones (Go's defaults, set explicitly). A sender that rebooted answers
// the first probe with a reset.
var tcpKeepAlive = net.KeepAliveConfig{Enable: true, Idle: 15 * time.Second, Interval: 15 * time.Second, Count: 9}

// connPool is the connection table the TCP and TLS listeners share (SPEC
// §10.3.5): MaxConns, the per-address and per-/64 limits and eviction count both
// together. A TLS connection joins it only once its handshake completes.
type connPool struct {
	mu       sync.Mutex
	conns    map[*tconn]struct{}
	perAddr  map[netip.Addr]int   // open connections per sender address
	perGroup map[netip.Prefix]int // per source group: the IPv4 address, or the IPv6 /64
	seq      uint64               // last accept number handed out
}

func newConnPool() *connPool {
	return &connPool{conns: map[*tconn]struct{}{}, perAddr: map[netip.Addr]int{}, perGroup: map[netip.Prefix]int{}}
}

// tcpListener is the TCP listener, or with tls set the TLS one (tls.go).
type tcpListener struct {
	srv   *Server
	ln    *net.TCPListener
	addr  string // as configured
	bound netip.AddrPort
	proto string // "tcp" or "tls"

	*connPool // shared with the other stream listener; its mu guards closing too

	tls     *tlsState    // nil for plain TCP
	frames  *frameCounts // this protocol's, on the Server (kept across rebinds)
	closing bool
	wg      sync.WaitGroup // the accept loop, every connection and (TLS) every handshake
}

// tconn is one open connection.
type tconn struct {
	c       net.Conn // what serve reads: the TCP connection, or the TLS one over it
	raw     net.Conn // the TCP connection, closed directly so a TLS close writes nothing back
	owner   *tcpListener
	from    netip.Addr
	addr    netip.Addr   // from without a zone, for the per-address count
	group   netip.Prefix // sourceKey(from)
	connAt  time.Time
	seq     uint64       // accept order; "oldest" goes by this, not connAt (Windows' clock can tie)
	last    atomic.Int64 // UnixNano of the connect or the last complete message
	inFrame atomic.Bool  // a message has started arriving and isn't complete yet
	cut     atomic.Bool  // we closed it (eviction or shutdown): a partial message is incomplete
	blocked atomic.Bool  // closed because its sender was blocked: nothing more is stored
}

func listenTCP(s *Server, ln config.Listener) (*tcpListener, error) {
	return listenStream(s, ln, "tcp", nil)
}

func listenStream(s *Server, ln config.Listener, proto string, ts *tlsState) (*tcpListener, error) {
	ap, err := bindAddr(ln)
	if err != nil {
		return nil, err
	}
	l, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	t := &tcpListener{
		srv:      s,
		ln:       l,
		addr:     ln.Addr,
		bound:    l.Addr().(*net.TCPAddr).AddrPort(),
		proto:    proto,
		connPool: s.pool,
		tls:      ts,
		frames:   &s.tcpFrames,
	}
	if proto == "tls" {
		t.frames = &s.tlsFrames
	}
	t.wg.Add(1)
	go t.accept()
	return t, nil
}

func (t *tcpListener) status() ListenerStatus {
	return ListenerStatus{Proto: t.proto, Addr: t.addr, Port: int(t.bound.Port()), OK: true}
}

// sourceKey is a connection's source group: the IPv4 address, or the IPv6 /64.
func sourceKey(a netip.Addr) netip.Prefix {
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	p, _ := a.Prefix(64)
	return p
}

func (t *tcpListener) accept() {
	defer t.wg.Done()
	var backoff time.Duration
	var lastLog time.Time
	for {
		c, err := t.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Out of file descriptors and the like: back off (5 ms doubling to 1 s), as
			// net/http does, instead of spinning.
			if backoff == 0 {
				backoff = 5 * time.Millisecond
			} else if backoff *= 2; backoff > time.Second {
				backoff = time.Second
			}
			if time.Since(lastLog) > time.Minute {
				t.srv.log.Warn("listen: accept error", "proto", t.proto, "err", err, "retry_in", backoff)
				lastLog = time.Now()
			}
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		if tc, ok := c.(*net.TCPConn); ok {
			// Best effort: some systems can't set every field (older Windows, the count).
			_ = tc.SetKeepAliveConfig(tcpKeepAlive)
		}
		from := addrOf(c.RemoteAddr())
		if r := t.srv.allow.Load().refusal(from); r != "" {
			t.srv.rejects.add(from, t.srv.opts.Clock().UTC(), 1, r)
			c.Close()
			continue
		}
		if t.tls != nil {
			t.handshake(c, from) // joins the pool once it completes (tls.go)
			continue
		}
		tc := newTconn(c, from, time.Now())
		if !t.track(tc) {
			c.Close()
			continue
		}
		go t.serve(tc)
	}
}

func newTconn(c net.Conn, from netip.Addr, now time.Time) *tconn {
	tc := &tconn{c: c, raw: c, from: from, addr: from.Unmap().WithZone(""), group: sourceKey(from), connAt: now}
	tc.last.Store(now.UnixNano())
	return tc
}

// track registers a connection. It reports false (and counts why) if the listener
// is closing, the sender's address or IPv6 /64 is at its limit with none of its
// connections idle enough to evict, or the table is full and the newcomer's own
// source holds the most connections.
func (t *tcpListener) track(tc *tconn) bool {
	s := t.srv
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closing {
		return false
	}
	tc.owner = t
	now := time.Now()
	overAddr := t.perAddr[tc.addr] >= int(s.perSource.Load())
	overPrefix := tc.addr.Is6() && t.perGroup[tc.group] >= int(s.perPrefix.Load())
	if overAddr || overPrefix {
		// Make room from the newcomer's own address (or /64): one of its
		// connections it has stopped using, such as those it left open when it
		// rebooted. Evicting one of the address's frees a place in its /64 too.
		same := func(c *tconn) bool { return c.addr == tc.addr }
		if !overAddr {
			same = func(c *tconn) bool { return c.group == tc.group }
		}
		victim := t.idlestOf(now, same)
		if victim == nil {
			s.rejects.add(tc.from, s.opts.Clock().UTC(), 1, RejectPerSource)
			if s.perSourceRefused.Add(1)%1000 == 1 {
				s.log.Warn("listen: TCP connections per source limit reached; refusing", "from", tc.from.String(),
					"per_address", s.perSource.Load(), "per_ipv6_64", s.perPrefix.Load())
			}
			return false
		}
		t.evictLocked(victim, "its own source's idle longest")
	}
	if len(t.conns) >= s.opts.MaxConns {
		victim, why := t.longestIdle(now), "idle longest"
		if victim == nil {
			victim, why = t.oldestOfBiggest(tc.group), "oldest of the biggest source"
		}
		if victim == nil {
			if s.connsRefused.Add(1)%1000 == 1 {
				s.log.Warn("listen: TCP connection limit reached and the newcomer's source holds the most; refusing",
					"limit", s.opts.MaxConns, "from", tc.from.String())
			}
			return false
		}
		t.evictLocked(victim, why)
	}
	t.seq++
	tc.seq = t.seq
	t.conns[tc] = struct{}{}
	t.perAddr[tc.addr]++
	t.perGroup[tc.group]++
	s.conns.Add(1)
	t.wg.Add(1)
	return true
}

// oldestOfBiggest returns the oldest connection of the source group holding the
// most connections, or nil if the newcomer's group holds at least as many as any
// other (t.mu held).
func (t *tcpListener) oldestOfBiggest(newcomer netip.Prefix) *tconn {
	var big netip.Prefix
	most := 0
	for g, n := range t.perGroup {
		if g != newcomer && (n > most || (n == most && g.Addr().Less(big.Addr()))) {
			big, most = g, n
		}
	}
	if most == 0 || t.perGroup[newcomer] >= most {
		return nil
	}
	var oldest *tconn
	for c := range t.conns {
		if c.group == big && (oldest == nil || c.seq < oldest.seq) {
			oldest = c
		}
	}
	return oldest
}

// evictLocked closes victim to make room for a newcomer and frees its slot now
// (its goroutine finishes on its own). A partial message it had is stored,
// marked incomplete (t.mu held).
func (t *tcpListener) evictLocked(victim *tconn, why string) {
	s := t.srv
	victim.cut.Store(true)
	victim.raw.Close()
	t.removeLocked(victim)
	if s.evicted.Add(1)%1000 == 1 {
		s.log.Warn("listen: TCP connection limit reached; closing a connection", "limit", s.opts.MaxConns,
			"per_address", s.perSource.Load(), "per_ipv6_64", s.perPrefix.Load(),
			"evicted", victim.from.String(), "why", why)
	}
}

// idlestOf returns, among the connections match accepts, the one whose last
// complete message (or connect) is oldest, if that was more than EvictIdle ago
// and no message is in progress on it; else nil (t.mu held).
func (t *tcpListener) idlestOf(now time.Time, match func(*tconn) bool) *tconn {
	var best *tconn
	var bestAt int64
	for c := range t.conns {
		if !match(c) || c.inFrame.Load() {
			continue
		}
		if at := c.last.Load(); best == nil || at < bestAt || (at == bestAt && c.seq < best.seq) {
			best, bestAt = c, at
		}
	}
	if best == nil || now.Sub(time.Unix(0, bestAt)) <= t.srv.opts.EvictIdle {
		return nil
	}
	return best
}

// longestIdle returns the connection with the oldest complete message (or connect),
// if that was more than EvictIdle ago (t.mu held).
func (t *tcpListener) longestIdle(now time.Time) *tconn {
	var best *tconn
	var bestAt int64
	for c := range t.conns {
		if at := c.last.Load(); best == nil || at < bestAt || (at == bestAt && c.seq < best.seq) {
			best, bestAt = c, at
		}
	}
	if best == nil || now.Sub(time.Unix(0, bestAt)) <= t.srv.opts.EvictIdle {
		return nil
	}
	return best
}

func (t *connPool) removeLocked(tc *tconn) {
	if _, ok := t.conns[tc]; !ok {
		return
	}
	delete(t.conns, tc)
	if t.perAddr[tc.addr]--; t.perAddr[tc.addr] <= 0 {
		delete(t.perAddr, tc.addr)
	}
	if t.perGroup[tc.group]--; t.perGroup[tc.group] <= 0 {
		delete(t.perGroup, tc.group)
	}
	if tc.owner != nil {
		tc.owner.srv.conns.Add(-1)
	}
}

func (t *tcpListener) untrack(tc *tconn) {
	t.mu.Lock()
	t.removeLocked(tc)
	t.mu.Unlock()
	t.wg.Done()
}

func (t *tcpListener) serve(tc *tconn) {
	defer t.untrack(tc)
	defer tc.raw.Close() // for TLS, no close_notify: these senders never read (SPEC §10.3.5)
	fr := &frameReader{c: tc.c, idle: &t.srv.idleTimeout, frameTimeout: &t.srv.frameTimeout, last: &tc.last, inFrame: &tc.inFrame}
	r := syslog.NewStreamReader(fr, int(t.srv.maxSize.Load()))
	for {
		fails := fr.fails
		msg, truncated, err := r.Next()
		if err != nil {
			if fr.frameCut {
				t.frames.timeouts.Add(1)
			}
			return // EOF, a deadline, reset, or closed by close() or an eviction
		}
		// A message returned by the call in which the connection ended is the
		// unterminated last one. An octet-counted frame shorter than its count is
		// incomplete whoever ended the connection (the sender's EOF, a reset, a TLS
		// close, our deadline or an eviction): the reader says so. A line is
		// incomplete if we ended it or the sender reset the connection; a last
		// line without its LF before a clean close (FIN, TLS close) is normal (RFC
		// 6587 non-transparent framing can't tell).
		var end frameEnd
		if arrived, length, ok := r.Incomplete(); ok {
			end = frameEnd{incomplete: true, arrived: arrived, length: length}
		} else if fr.fails != fails && (fr.timedOut || tc.cut.Load() || fr.reset) {
			end.incomplete = true
		}
		if tc.blocked.Load() {
			return
		}
		if end.incomplete {
			t.frames.incomplete.Add(1)
		}
		if len(msg) == 0 {
			continue // only a frame's header arrived: counted, nothing to store; the stream has ended
		}
		if t.srv.deliver(msg, tc.from, truncated, end) == RejectBlocked {
			return // blocked since it connected: close it
		}
		if t.tls != nil {
			t.srv.tlsStats.delivered(tc.addr)
		}
		fr.frameDone(r.Buffered() > 0)
	}
}

// frameEnd says how a TCP or TLS message's frame ended, when not whole.
type frameEnd struct {
	incomplete      bool  // it ended before all of it arrived
	arrived, length int64 // an octet-counted frame's (0, 0 for a line)
}

// frameCounts are one stream protocol's frame counters since Start.
type frameCounts struct {
	incomplete atomic.Int64 // messages whose frame ended before all of it arrived
	timeouts   atomic.Int64 // connections closed on tcp_frame_timeout
}

// closeBlocked closes the open TCP and TLS connections whose sender al blocks,
// each counted once as a refusal. Their partial messages aren't stored.
func (s *Server) closeBlocked(al *allowlist) {
	now := s.opts.Clock().UTC()
	p := s.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	for c := range p.conns {
		if al.isBlocked(c.from) && !c.blocked.Swap(true) {
			c.raw.Close()
			s.rejects.add(c.from, now, 1, RejectBlocked)
		}
	}
}

// close stops accepting, closes this listener's connections (and, for TLS, its
// handshakes in progress) and waits for their goroutines. The other listener's
// connections in the shared pool are left alone.
func (t *tcpListener) close() {
	t.mu.Lock()
	t.closing = true
	t.ln.Close()
	for c := range t.conns {
		if c.owner == t {
			c.cut.Store(true)
			c.raw.Close()
		}
	}
	t.mu.Unlock()
	if t.tls != nil {
		t.tls.closeHandshakes()
	}
	t.wg.Wait()
}

// frameReader sets the read deadline before every read: between messages, the idle
// timeout from the last complete message (bytes alone don't renew it); once a
// message's first byte has arrived, the frame timeout from that byte, if sooner.
// Both timeouts are read live, so a new value applies from the next read.
//
// It hands the StreamReader errors only with no data (a read returning both is
// split), so that "the reader failed during this Next" means "this message is
// the unterminated last one". The frame clock starts at the first read that
// brings a byte other than LF, CR or NUL (the junk the StreamReader skips between
// messages), or as soon as a message completes if the next one has already
// started arriving (StreamReader.Buffered).
type frameReader struct {
	c            net.Conn
	idle         *atomic.Int64    // time.Duration, live from config
	frameTimeout *atomic.Int64    // time.Duration, live from config
	last         *atomic.Int64    // UnixNano of the last complete message (or the connect)
	inFrame      *atomic.Bool     // set while a message is in progress (nil: not tracked)
	now          func() time.Time // time.Now if nil (tests pass a fake clock)

	frameStart time.Time // zero between messages
	stashed    error
	fails      int  // errors returned to the StreamReader
	timedOut   bool // the connection ended on one of our deadlines
	frameCut   bool // ... on the frame deadline
	reset      bool // the connection ended on the sender's reset
}

func (r *frameReader) Read(p []byte) (int, error) {
	if r.stashed != nil {
		r.fails++
		return 0, r.stashed
	}
	deadline := time.Unix(0, r.last.Load()).Add(time.Duration(r.idle.Load()))
	frameBound := false
	if !r.frameStart.IsZero() {
		if fd := r.frameStart.Add(time.Duration(r.frameTimeout.Load())); fd.Before(deadline) {
			deadline, frameBound = fd, true
		}
	}
	if err := r.c.SetReadDeadline(deadline); err != nil {
		r.fails++
		return 0, err
	}
	n, err := r.c.Read(p)
	if n > 0 && r.frameStart.IsZero() && hasMessageByte(p[:n]) {
		r.frameStart = r.clock()
		r.setInFrame(true)
	}
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			r.timedOut, r.frameCut = true, frameBound
		}
		r.reset = isConnReset(err)
		if n > 0 {
			r.stashed = err
			return n, nil
		}
		r.fails++
		return 0, err
	}
	return n, nil
}

// frameDone records a complete message: it renews the idle timeout, and restarts
// the frame clock if the next message is already buffered (else stops it).
func (r *frameReader) frameDone(nextStarted bool) {
	now := r.clock()
	r.frameStart = time.Time{}
	if nextStarted {
		r.frameStart = now
	}
	r.setInFrame(nextStarted)
	r.last.Store(now.UnixNano())
}

func (r *frameReader) setInFrame(v bool) {
	if r.inFrame != nil {
		r.inFrame.Store(v)
	}
}

func (r *frameReader) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// hasMessageByte reports whether b holds a byte other than the LF, CR and NUL
// junk the StreamReader skips between messages.
func hasMessageByte(b []byte) bool {
	for _, c := range b {
		if c != '\n' && c != '\r' && c != 0 {
			return true
		}
	}
	return false
}
