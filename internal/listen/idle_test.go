package listen

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/syslog"
)

// clockConn is a net.Conn on a fake clock. Each Read moves the clock on by the
// next step's wait, then fails with os.ErrDeadlineExceeded if that passed the
// read deadline, or returns the step's data. Past the last step it times out.
type clockConn struct {
	net.Conn // nil: only Read and SetReadDeadline are used
	now      time.Time
	deadline time.Time
	steps    []clockStep
}

type clockStep struct {
	wait time.Duration
	data string
}

func (c *clockConn) Read(p []byte) (int, error) {
	if len(c.steps) == 0 {
		c.now = c.deadline.Add(time.Nanosecond)
		return 0, os.ErrDeadlineExceeded
	}
	st := c.steps[0]
	c.steps = c.steps[1:]
	c.now = c.now.Add(st.wait)
	if !c.deadline.IsZero() && c.now.After(c.deadline) {
		return 0, os.ErrDeadlineExceeded
	}
	return copy(p, st.data), nil
}

func (c *clockConn) SetReadDeadline(t time.Time) error { c.deadline = t; return nil }
func (c *clockConn) Close() error                      { return nil }

// readIdle runs the serve loop's reading (frameReader + StreamReader) over
// steps with the given idle timeout, and returns the messages read and how the
// connection ended.
func readIdle(t *testing.T, idle time.Duration, steps []clockStep) (msgs []string, timedOut bool) {
	t.Helper()
	start := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	c := &clockConn{now: start, steps: steps}
	var idleD, frameD, last atomic.Int64
	idleD.Store(int64(idle))
	frameD.Store(int64(time.Minute))
	last.Store(start.UnixNano()) // the connect
	fr := &frameReader{c: c, idle: &idleD, frameTimeout: &frameD, last: &last, now: func() time.Time { return c.now }}
	r := syslog.NewStreamReader(fr, 0)
	for {
		msg, _, err := r.Next()
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read error %v", err)
			}
			return msgs, fr.timedOut
		}
		msgs = append(msgs, string(msg))
		fr.frameDone(r.Buffered() > 0)
	}
}

// A sender that keeps its connection open with no keepalives and sends again
// after 11 minutes, then after 23 hours: the default idle timeout (24 h) keeps
// it open, where 1.0.0's 10 minutes closed it (and the sender lost what it sent
// until it noticed).
func TestIdleConnectionSurvivesLongGaps(t *testing.T) {
	if DefaultIdleTimeout != 24*time.Hour {
		t.Fatalf("DefaultIdleTimeout %v, want 24h", DefaultIdleTimeout)
	}
	steps := func() []clockStep {
		return []clockStep{
			{0, "<13>hello\n"},
			{11 * time.Minute, "<13>after 11 minutes\n"},
			{23 * time.Hour, "<13>after 23 hours\n"},
			// Then silence: the connection is closed 24 h after the last message.
		}
	}
	msgs, timedOut := readIdle(t, DefaultIdleTimeout, steps())
	if len(msgs) != 3 || msgs[2] != "<13>after 23 hours" || !timedOut {
		t.Errorf("24h: %q timedOut=%v", msgs, timedOut)
	}
	// The same sender with the old 10 minutes loses the connection before its
	// second message.
	msgs, timedOut = readIdle(t, 10*time.Minute, steps())
	if len(msgs) != 1 || !timedOut {
		t.Errorf("10m: %q timedOut=%v", msgs, timedOut)
	}
	// Silence just past 24 h does close it.
	msgs, timedOut = readIdle(t, DefaultIdleTimeout, []clockStep{{0, "<13>a\n"}, {24*time.Hour + time.Second, "<13>too late\n"}})
	if len(msgs) != 1 || !timedOut {
		t.Errorf("past 24h: %q timedOut=%v", msgs, timedOut)
	}
}

// listeners.tcp_idle_timeout sets the idle timeout (the default when unset), is
// applied by Reconfigure, and Options.IdleTimeout overrides it.
func TestIdleTimeoutFromConfig(t *testing.T) {
	s, _, _ := start(t, loopback(0, 0), nil)
	if got := time.Duration(s.idleTimeout.Load()); got != 24*time.Hour {
		t.Errorf("default %v", got)
	}
	cfg := loopback(0, 0)
	cfg.TCPIdleTimeout = config.Duration(2 * time.Hour)
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	if got := time.Duration(s.idleTimeout.Load()); got != 2*time.Hour {
		t.Errorf("reconfigured %v", got)
	}
	s2, _, _ := start(t, cfg, func(o *Options) { o.IdleTimeout = time.Second })
	if got := time.Duration(s2.idleTimeout.Load()); got != time.Second {
		t.Errorf("option override %v", got)
	}
}

// With the 24 h idle timeout, idle connections still don't pin the table: when
// MaxConns are open, each newcomer evicts the one idle longest (over EvictIdle),
// until every original slot has been freed.
func TestLongIdleTimeoutStillEvictsUnderPressure(t *testing.T) {
	s, c, _ := start(t, loopback(0, 0), func(o *Options) {
		o.MaxConns = 3
		o.EvictIdle = 300 * time.Millisecond
	})
	if got := time.Duration(s.idleTimeout.Load()); got != 24*time.Hour {
		t.Fatalf("idle timeout %v", got)
	}
	addr := tcpAddr(t, s)
	dial := func(msg string) net.Conn {
		cn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cn.Close() })
		fmt.Fprintf(cn, "%s\n", msg)
		return cn
	}
	var idle []net.Conn
	for i := range 3 {
		idle = append(idle, dial(fmt.Sprintf("<13>idle %d", i)))
		c.wait(t, i+1)
	}
	time.Sleep(500 * time.Millisecond) // all three idle past EvictIdle, far within 24 h
	// Each newcomer sends at once, so the originals stay the ones idle longest.
	for i := range 3 {
		dial(fmt.Sprintf("<13>new %d", i))
		c.wait(t, 4+i)
		waitFor(t, "an eviction", func() bool { return s.Status().TCPConnsEvicted == int64(i+1) })
	}
	for i, cn := range idle {
		if !closedByServer(cn, 5*time.Second) {
			t.Errorf("idle connection %d wasn't evicted", i)
		}
	}
	if st := s.Status(); st.TCPConns != 3 || st.TCPConnsEvicted != 3 || st.TCPConnsRefused != 0 {
		t.Errorf("status %+v", st)
	}
}

// addIdle tracks a pipe connection from ip whose connect (or last complete
// message) was idleFor ago, and returns the far end.
func (t *tcpListener) addIdle(ip string, idleFor time.Duration) (far net.Conn, ok bool) {
	near, far := net.Pipe()
	tc := newTconn(near, netip.MustParseAddr(ip), time.Now().Add(-idleFor))
	ok = t.track(tc)
	return far, ok
}

// A sender that rebooted without closing its connections left them all open
// (here 3, its per-address limit). Its new connections each evict one of its own
// idle ones instead of being refused, until none is idle; then it's refused.
// Another sender's idle connection is never taken for it.
func TestPerSourceLimitEvictsOwnIdle(t *testing.T) {
	tl := trackTable(10000, 3, 256)
	tl.srv.opts.EvictIdle = time.Minute
	other, ok := tl.addIdle("198.51.100.9", time.Hour)
	if !ok {
		t.Fatal("other sender refused")
	}
	var dead []net.Conn
	for i := range 3 {
		far, ok := tl.addIdle("192.0.2.1", time.Duration(10-i)*time.Minute) // the first one idle longest
		if !ok {
			t.Fatalf("conn %d refused", i)
		}
		dead = append(dead, far)
	}
	for i := range 3 {
		if _, ok := tl.addIdle("192.0.2.1", 0); !ok {
			t.Fatalf("newcomer %d refused with an idle connection of its own to evict", i)
		}
		if !pipeClosed(dead[i]) {
			t.Errorf("newcomer %d didn't evict the connection idle longest (%d)", i, i)
		}
	}
	if _, ok := tl.addIdle("192.0.2.1", 0); ok {
		t.Error("accepted over the limit with no idle connection to evict")
	}
	if pipeClosed(other) {
		t.Error("another sender's idle connection was evicted")
	}
	s := tl.srv
	if s.evicted.Load() != 3 || s.perSourceRefused.Load() != 1 || tl.perAddr[netip.MustParseAddr("192.0.2.1")] != 3 || len(tl.conns) != 4 {
		t.Errorf("evicted %d refused %d per-address %d conns %d", s.evicted.Load(), s.perSourceRefused.Load(),
			tl.perAddr[netip.MustParseAddr("192.0.2.1")], len(tl.conns))
	}
	if rej := s.rejects.list(fixedNow, 0); len(rej) != 1 || rej[0].Reason != RejectPerSource {
		t.Errorf("rejected %+v", rej)
	}
}

// A connection with a message in progress, or one that completed a message within
// EvictIdle, isn't evicted for its own source's newcomer.
func TestPerSourceLimitKeepsBusyConnections(t *testing.T) {
	tl := trackTable(10000, 2, 256)
	tl.srv.opts.EvictIdle = time.Minute
	if _, ok := tl.addIdle("192.0.2.1", 30*time.Second); !ok { // completed a message recently
		t.Fatal("refused")
	}
	if _, ok := tl.addIdle("192.0.2.1", time.Hour); !ok {
		t.Fatal("refused")
	}
	for c := range tl.conns {
		if time.Since(time.Unix(0, c.last.Load())) > 2*time.Minute {
			c.inFrame.Store(true) // idle since its last message, but a new one has started
		}
	}
	if _, ok := tl.addIdle("192.0.2.1", 0); ok {
		t.Error("evicted a connection that was mid-message or recently active")
	}
	if tl.srv.evicted.Load() != 0 || tl.srv.perSourceRefused.Load() != 1 {
		t.Errorf("evicted %d refused %d", tl.srv.evicted.Load(), tl.srv.perSourceRefused.Load())
	}
}

// At the IPv6 /64 limit, a newcomer from any address in the /64 evicts the /64's
// connection idle longest.
func TestPerPrefixLimitEvictsOwnIdle(t *testing.T) {
	tl := trackTable(10000, 32, 3)
	tl.srv.opts.EvictIdle = time.Minute
	var fars []net.Conn
	for i := range 3 {
		far, ok := tl.addIdle(fmt.Sprintf("2001:db8:1:2::%d", i+1), time.Duration(10-i)*time.Minute)
		if !ok {
			t.Fatalf("conn %d refused", i)
		}
		fars = append(fars, far)
	}
	if _, ok := tl.addIdle("2001:db8:1:2::99", 0); !ok {
		t.Fatal("newcomer on the /64 refused with an idle connection to evict")
	}
	if !pipeClosed(fars[0]) || pipeClosed(fars[1]) {
		t.Error("the /64's connection idle longest wasn't the one evicted")
	}
	if n := tl.perGroup[sourceKey(netip.MustParseAddr("2001:db8:1:2::1"))]; n != 3 || tl.srv.evicted.Load() != 1 {
		t.Errorf("/64 holds %d, evicted %d", n, tl.srv.evicted.Load())
	}
}

// The same over real sockets: a sender at its per-address limit (2 here) whose
// connections went quiet reconnects, and its new connection gets in.
func TestPerSourceLimitEvictsOverSockets(t *testing.T) {
	const evictIdle = 300 * time.Millisecond
	cfg := loopback(0, 0)
	cfg.TCPMaxConnsPerSource = 2
	s, c, _ := start(t, cfg, func(o *Options) { o.EvictIdle = evictIdle })
	addr := tcpAddr(t, s)
	dial := func(msg string) net.Conn {
		cn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cn.Close() })
		fmt.Fprintf(cn, "%s\n", msg)
		return cn
	}
	// lastOf waits until the server is done with cn's message and returns the
	// connection's last-activity time. The collector has a message before its
	// connection records it (serve delivers, then frameDone), so waiting for
	// the message alone let a's time land after b's on a busy runner, and b
	// was evicted as the idlest (CI, 3df7ecb). inFrame is set from the
	// message's first byte, so once it's delivered, false means frameDone ran.
	lastOf := func(cn net.Conn) int64 {
		t.Helper()
		var at int64
		waitFor(t, "the connection's message recorded", func() bool {
			s.pool.mu.Lock()
			defer s.pool.mu.Unlock()
			for tc := range s.pool.conns {
				if tc.raw.RemoteAddr().String() == cn.LocalAddr().String() {
					at = tc.last.Load()
					return !tc.inFrame.Load()
				}
			}
			return false
		})
		return at
	}
	a := dial("<13>a")
	c.wait(t, 1)
	aLast := lastOf(a)
	for time.Now().UnixNano() <= aLast { // b's time strictly after a's, on any clock resolution
		time.Sleep(time.Millisecond)
	}
	b := dial("<13>b")
	c.wait(t, 2)
	bLast := lastOf(b)
	if bLast <= aLast {
		t.Fatalf("b's last activity %d isn't after a's %d", bLast, aLast)
	}
	for time.Since(time.Unix(0, bLast)) <= evictIdle { // both idle past EvictIdle: the sender "rebooted"
		time.Sleep(10 * time.Millisecond)
	}
	dial("<13>after the reboot")
	if got := c.wait(t, 3); string(got[2].Raw) != "<13>after the reboot" {
		t.Errorf("got %q", got[2].Raw)
	}
	if !closedByServer(a, 5*time.Second) {
		t.Error("the connection idle longest wasn't evicted")
	}
	if closedByServer(b, 50*time.Millisecond) {
		t.Error("a second connection was evicted")
	}
	if st := s.Status(); st.TCPConnsEvicted != 1 || st.TCPConnsPerSourceRefused != 0 || st.TCPConns != 2 {
		t.Errorf("status %+v", st)
	}
}
