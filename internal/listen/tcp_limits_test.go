package listen

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// closedByServer reports whether the server closed c (EOF or reset) within d.
func closedByServer(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return false
	}
	return err != nil
}

// dialRetry dials addr, retrying for a while if the OS refuses the connection
// (a full listen backlog).
func dialRetry(addr string) (net.Conn, error) {
	var err error
	for try := 0; try < 50; try++ {
		var c net.Conn
		if c, err = net.Dial("tcp", addr); err == nil {
			return c, nil
		}
		time.Sleep(time.Duration(try+1) * 5 * time.Millisecond)
	}
	return nil, err
}

func TestSourceKey(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.7":                 "192.0.2.7/32",
		"::ffff:192.0.2.7":          "192.0.2.7/32",
		"2001:db8:1:2:aaaa::1":      "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9%eth0": "2001:db8:1:2::/64",
	} {
		if got := sourceKey(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}

// TestOneSourceCantTakeAllSlots is the review's M6 attack: 1,000 connections from
// one host, each sending one byte. With the default limits only 32 get in, and a
// second source still delivers.
func TestOneSourceCantTakeAllSlots(t *testing.T) {
	// A dual-stack wildcard listener, so 127.0.0.1 and ::1 are two sources.
	cfg := config.Listeners{TCP: config.Listener{Enabled: true, Addr: "::", Port: 0}}
	s, c, _ := start(t, cfg, nil)
	ap, _ := s.TCPAddr()
	v4 := fmt.Sprintf("127.0.0.1:%d", ap.Port())
	var conns []net.Conn
	defer func() {
		for _, cn := range conns {
			cn.Close()
		}
	}()
	// Dial in batches smaller than the OS listen backlog (Windows caps it near
	// 200 and resets the overflow) and let Woodshed account for each batch, so
	// every refusal below is Woodshed's, not the kernel's. A kernel refusal is
	// retried; it never reached Woodshed, so it doesn't change the counts.
	handled := func() int64 { st := s.Status(); return int64(st.TCPConns) + st.TCPConnsPerSourceRefused }
	const batch = 50
	for i := 0; i < DefaultMaxConns; i++ {
		cn, err := dialRetry(v4)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, cn)
		cn.Write([]byte("<"))
		if (i+1)%batch == 0 || i+1 == DefaultMaxConns {
			want := int64(i + 1)
			waitFor(t, fmt.Sprintf("Woodshed to handle %d connections", want), func() bool { return handled() == want })
		}
	}
	refused := int64(DefaultMaxConns - config.DefaultTCPMaxConnsPerSource)
	st := s.Status()
	if st.TCPConns != config.DefaultTCPMaxConnsPerSource || st.TCPConnsRefused != 0 || st.TCPConnsEvicted != 0 {
		t.Errorf("status %+v", st)
	}
	rej := s.Rejected()
	if len(rej) != 1 || rej[0].IP != "127.0.0.1" || rej[0].Count24h != refused || rej[0].Reason != RejectPerSource {
		t.Errorf("rejected %+v", rej)
	}

	// A second source gets in and its message is stored.
	other, err := net.Dial("tcp", fmt.Sprintf("[::1]:%d", ap.Port()))
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	defer other.Close()
	other.Write([]byte("<13>real sender\n"))
	got := c.wait(t, 1)
	if string(got[0].Raw) != "<13>real sender" || got[0].Sender != netip.MustParseAddr("::1") {
		t.Errorf("got %q from %v", got[0].Raw, got[0].Sender)
	}
}

func TestFrameDeadlineCutsTrickler(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.TCPFrameTimeout = config.Duration(300 * time.Millisecond)
	s, c, _ := start(t, cfg, nil)
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := "<13>a message sent one byte at a time"
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for i := 0; i < len(msg); i++ {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := conn.Write([]byte{msg[i]}); err != nil {
				return
			}
		}
	}()
	start := time.Now()
	if !closedByServer(conn, 5*time.Second) {
		t.Fatal("trickling connection still open after 5 s")
	}
	if d := time.Since(start); d < 250*time.Millisecond || d > 2*time.Second {
		t.Errorf("cut after %v, want about 300 ms after the first byte", d)
	}
	got := c.wait(t, 1)
	if !got[0].Truncated || len(got[0].Raw) == 0 || !strings.HasPrefix(msg, string(got[0].Raw)) || len(got[0].Raw) == len(msg) {
		t.Errorf("partial: %q truncated=%v", got[0].Raw, got[0].Truncated)
	}
	if st := s.Status(); st.TCPFrameTimeouts != 1 || st.Truncated != 1 {
		t.Errorf("status %+v", st)
	}
}

func TestPauseBetweenFramesKept(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.TCPFrameTimeout = config.Duration(200 * time.Millisecond)
	s, c, _ := start(t, cfg, nil)
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i, m := range []string{"<13>a", "<13>b", "<13>c"} {
		if i > 0 {
			time.Sleep(600 * time.Millisecond) // three frame timeouts between messages
		}
		if _, err := conn.Write([]byte(m + "\n")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	got := c.wait(t, 3)
	for i, w := range []string{"<13>a", "<13>b", "<13>c"} {
		if string(got[i].Raw) != w || got[i].Truncated {
			t.Errorf("[%d] %q truncated=%v", i, got[i].Raw, got[i].Truncated)
		}
	}
	if closedByServer(conn, 100*time.Millisecond) {
		t.Error("server closed a connection that paused between messages")
	}
	if st := s.Status(); st.TCPConns != 1 || st.TCPFrameTimeouts != 0 {
		t.Errorf("status %+v", st)
	}
}

// Single bytes don't renew the idle timeout; only complete messages do.
func TestIdleRenewedOnlyByFrames(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.TCPFrameTimeout = config.Duration(time.Hour)
	s, c, _ := start(t, cfg, func(o *Options) { o.IdleTimeout = 400 * time.Millisecond })
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("<13>first\n"))
	c.wait(t, 1)
	start := time.Now()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(100 * time.Millisecond):
			}
			if _, err := conn.Write([]byte("x")); err != nil {
				return
			}
		}
	}()
	if !closedByServer(conn, 5*time.Second) {
		t.Fatal("a byte every 100 ms kept the connection open")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("closed after %v, want about the 400 ms idle timeout", d)
	}
	got := c.wait(t, 2)
	if !got[1].Truncated || !strings.HasPrefix(string(got[1].Raw), "x") {
		t.Errorf("partial %q truncated=%v", got[1].Raw, got[1].Truncated)
	}
}

func TestEvictLongestIdle(t *testing.T) {
	cfg := loopback(0, 0)
	s, c, _ := start(t, cfg, func(o *Options) {
		o.MaxConns = 3
		o.EvictIdle = time.Second // wide, so B, C and D never look idle on a slow runner
	})
	addr := tcpAddr(t, s)
	dial := func() net.Conn {
		cn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cn.Close() })
		return cn
	}
	// A: a partial message, then nothing.
	a := dial()
	a.Write([]byte("<13>half a mess"))
	waitFor(t, "A", func() bool { return s.Status().TCPConns == 1 })
	time.Sleep(1300 * time.Millisecond)
	// B and C are fresh.
	b, cc := dial(), dial()
	fmt.Fprintf(b, "<13>b\n")
	fmt.Fprintf(cc, "<13>c\n")
	c.wait(t, 2)

	// D finds the table full and evicts A, the one idle longest.
	d := dial()
	fmt.Fprintf(d, "<13>d\n")
	if !closedByServer(a, 5*time.Second) {
		t.Fatal("the idle connection wasn't evicted")
	}
	got := c.wait(t, 4)
	var partial, fromD bool
	for _, m := range got {
		switch string(m.Raw) {
		case "<13>half a mess":
			partial = m.Truncated
		case "<13>d":
			fromD = true
		}
	}
	if !partial || !fromD {
		t.Errorf("evicted partial truncated=%v, D delivered=%v: %v", partial, fromD, got)
	}
	st := s.Status()
	if st.TCPConnsEvicted != 1 || st.TCPConns != 3 || st.TCPConnsRefused != 0 {
		t.Errorf("status %+v", st)
	}

	// Nobody is idle long enough now: the next newcomer is refused. B, C and D
	// send again first, so a stall since B's first message (EvictIdle is only 1 s)
	// can't make B look idle when E arrives.
	for i, cn := range []net.Conn{b, cc, d} {
		fmt.Fprintf(cn, "<13>again %d\n", i)
	}
	c.wait(t, 7)
	e := dial()
	if !closedByServer(e, 5*time.Second) {
		t.Error("newcomer accepted with no idle connection to evict")
	}
	waitFor(t, "the refusal", func() bool { return s.Status().TCPConnsRefused == 1 })
	if st := s.Status(); st.TCPConnsEvicted != 1 {
		t.Errorf("status %+v", st)
	}
	for _, cn := range []net.Conn{b, cc, d} {
		if closedByServer(cn, 20*time.Millisecond) {
			t.Error("an active connection was closed")
		}
	}
}

// The start of the next message arriving in the same read as the end of the
// previous one starts its frame clock at once, not at the next read.
func TestFrameClockStartsOnBufferedNext(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.TCPFrameTimeout = config.Duration(300 * time.Millisecond)
	s, c, _ := start(t, cfg, nil) // idle timeout stays 10 min
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	conn.Write([]byte("<13>whole\n<13>then a trickle"))
	if !closedByServer(conn, 5*time.Second) {
		t.Fatal("the buffered partial message wasn't cut")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("cut after %v, want about the 300 ms frame timeout", d)
	}
	got := c.wait(t, 2)
	if string(got[0].Raw) != "<13>whole" || got[0].Truncated || string(got[1].Raw) != "<13>then a trickle" || !got[1].Truncated {
		t.Errorf("got %q (%v), %q (%v)", got[0].Raw, got[0].Truncated, got[1].Raw, got[1].Truncated)
	}
	if st := s.Status(); st.TCPFrameTimeouts != 1 {
		t.Errorf("frame timeouts %d", st.TCPFrameTimeouts)
	}
}

// Blank lines between messages don't start the frame clock: a sender that ends
// each octet-counted frame with an LF and then pauses is kept.
func TestJunkBetweenFramesKept(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.TCPFrameTimeout = config.Duration(200 * time.Millisecond)
	s, c, _ := start(t, cfg, nil)
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("9 <13>first"))
	time.Sleep(20 * time.Millisecond)
	conn.Write([]byte("\n")) // the LF in its own segment
	time.Sleep(600 * time.Millisecond)
	conn.Write([]byte("10 <13>second\n\r\n"))
	time.Sleep(600 * time.Millisecond)
	conn.Write([]byte("9 <13>third"))
	got := c.wait(t, 3)
	for i, w := range []string{"<13>first", "<13>second", "<13>third"} {
		if string(got[i].Raw) != w || got[i].Truncated {
			t.Errorf("[%d] %q truncated=%v", i, got[i].Raw, got[i].Truncated)
		}
	}
	if st := s.Status(); st.TCPFrameTimeouts != 0 || st.TCPConns != 1 {
		t.Errorf("status %+v", st)
	}
}

// trackTable is a tcpListener with no socket, for driving track with pipe
// connections from any source address.
func trackTable(maxConns, perAddr, perPrefix int) *tcpListener {
	s := &Server{
		opts:    Options{MaxConns: maxConns, EvictIdle: time.Hour, Clock: func() time.Time { return fixedNow }, Logger: quiet},
		log:     quiet,
		rejects: newRejects(maxRejectedIPs),
		pool:    newConnPool(),
	}
	s.perSource.Store(int64(perAddr))
	s.perPrefix.Store(int64(perPrefix))
	return &tcpListener{srv: s, proto: "tcp", connPool: s.pool}
}

var pipeEpoch = time.Now()

// add tracks a pipe connection from ip, connected at pipeEpoch+seq ms, and
// returns the far end (it reads EOF once the server side is closed).
func (t *tcpListener) addPipe(ip string, seq int) (far net.Conn, ok bool) {
	near, far := net.Pipe()
	tc := newTconn(near, netip.MustParseAddr(ip), pipeEpoch.Add(time.Duration(seq)*time.Millisecond))
	ok = t.track(tc)
	return far, ok
}

func pipeClosed(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	return err == io.EOF || errors.Is(err, io.ErrClosedPipe)
}

func TestPerAddressAndPrefixLimits(t *testing.T) {
	tl := trackTable(10000, 32, 80)
	seq := 0
	add := func(ip string) bool { seq++; _, ok := tl.addPipe(ip, seq); return ok }
	// One IPv6 address: 32, then refused.
	for i := 0; i < 32; i++ {
		if !add("2001:db8:1:2::1") {
			t.Fatalf("conn %d refused", i)
		}
	}
	if add("2001:db8:1:2::1") {
		t.Error("33rd connection from one address accepted")
	}
	// Other hosts on the same /64 (a server VLAN) still get in, up to the /64 cap.
	for i := 0; i < 48; i++ {
		if !add(fmt.Sprintf("2001:db8:1:2::%x", 0x100+i)) {
			t.Fatalf("host %d on the /64 refused at %d connections", i, tl.perGroup[sourceKey(netip.MustParseAddr("2001:db8:1:2::1"))])
		}
	}
	if add("2001:db8:1:2::ffff") {
		t.Error("81st connection on the /64 accepted (cap 80)")
	}
	if !add("2001:db8:1:3::1") {
		t.Error("another /64 refused")
	}
	// IPv4 has no prefix cap: 100 hosts in one /24.
	for i := 0; i < 100; i++ {
		if !add(fmt.Sprintf("192.0.2.%d", i+1)) {
			t.Fatalf("IPv4 host %d refused", i)
		}
	}
	if n := tl.srv.perSourceRefused.Load(); n != 2 {
		t.Errorf("per-source refusals %d", n)
	}
	rej := tl.srv.rejects.list(fixedNow, 0)
	if len(rej) != 2 || rej[0].Reason != RejectPerSource || rej[1].Reason != RejectPerSource {
		t.Errorf("rejected %+v", rej)
	}
}

// When the table is full of busy connections (none idle enough to evict), a
// newcomer evicts the oldest connection of the biggest source instead of being
// refused, unless its own source is the biggest.
func TestEvictFromBiggestSource(t *testing.T) {
	tl := trackTable(10, 32, 256)
	var aFar []net.Conn
	seq := 0
	for i := 0; i < 5; i++ { // A: 5 connections, oldest first
		seq++
		far, ok := tl.addPipe("192.0.2.1", seq)
		if !ok {
			t.Fatal("A refused")
		}
		aFar = append(aFar, far)
	}
	for i := 0; i < 3; i++ { // V6: one /64, 3 addresses (one group of 3)
		seq++
		if _, ok := tl.addPipe(fmt.Sprintf("2001:db8::%d", i+1), seq); !ok {
			t.Fatal("v6 refused")
		}
	}
	for i := 0; i < 2; i++ { // B: 2
		seq++
		if _, ok := tl.addPipe("198.51.100.1", seq); !ok {
			t.Fatal("B refused")
		}
	}
	// Full (10). A newcomer from a new source evicts A's oldest.
	seq++
	if _, ok := tl.addPipe("203.0.113.9", seq); !ok {
		t.Fatal("newcomer refused")
	}
	if !pipeClosed(aFar[0]) || pipeClosed(aFar[1]) {
		t.Error("didn't evict exactly A's oldest connection")
	}
	if len(tl.conns) != 10 || tl.perAddr[netip.MustParseAddr("192.0.2.1")] != 4 || tl.srv.evicted.Load() != 1 {
		t.Errorf("conns %d, A %d, evicted %d", len(tl.conns), tl.perAddr[netip.MustParseAddr("192.0.2.1")], tl.srv.evicted.Load())
	}
	// A newcomer from A, still the biggest source, is refused.
	seq++
	if _, ok := tl.addPipe("192.0.2.1", seq); ok {
		t.Error("the biggest source evicted its own connection to get in")
	}
	if tl.srv.connsRefused.Load() != 1 {
		t.Errorf("refused %d", tl.srv.connsRefused.Load())
	}
	// From the v6 /64 (3, behind A's 4): A's next oldest goes.
	seq++
	if _, ok := tl.addPipe("2001:db8::99", seq); !ok {
		t.Fatal("v6 newcomer refused")
	}
	if !pipeClosed(aFar[1]) {
		t.Error("A's second-oldest wasn't evicted")
	}
	// Now the /64 holds the most (4, A 3): its next newcomer is refused.
	seq++
	if _, ok := tl.addPipe("2001:db8::100", seq); ok {
		t.Error("the /64, now the biggest source, got in by evicting A")
	}
	// Idle eviction still comes first.
	tl.srv.opts.EvictIdle = time.Nanosecond
	var idlest *tconn
	for c := range tl.conns {
		if idlest == nil || c.last.Load() < idlest.last.Load() {
			idlest = c
		}
	}
	seq++
	if _, ok := tl.addPipe("2001:db8::101", seq); !ok {
		t.Fatal("refused with an idle connection to evict")
	}
	if _, still := tl.conns[idlest]; still {
		t.Error("the longest-idle connection wasn't the one evicted")
	}
}

// The same over real sockets: a busy source can't pin the table.
func TestBusyTableEvictsBiggestSource(t *testing.T) {
	cfg := config.Listeners{TCP: config.Listener{Enabled: true, Addr: "::", Port: 0}}
	s, c, _ := start(t, cfg, func(o *Options) { o.MaxConns = 4 }) // EvictIdle stays 30 s: nobody is idle
	ap, _ := s.TCPAddr()
	v4, v6 := fmt.Sprintf("127.0.0.1:%d", ap.Port()), fmt.Sprintf("[::1]:%d", ap.Port())
	dial := func(addr string, n int) net.Conn {
		cn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Skipf("dial %s: %v", addr, err)
		}
		t.Cleanup(func() { cn.Close() })
		fmt.Fprintf(cn, "<13>m%d\n", n)
		c.wait(t, n)
		return cn
	}
	old := dial(v4, 1)
	dial(v4, 2)
	dial(v4, 3)
	dial(v6, 4)
	fresh := dial(v6, 5) // the table was full: 127.0.0.1's oldest goes
	// The eviction happened when the listener accepted it; the bounds are only
	// generous for slow runners.
	waitFor(t, "the eviction", func() bool { return s.Status().TCPConnsEvicted == 1 })
	if !closedByServer(old, 30*time.Second) {
		t.Fatal("the oldest connection of the biggest source wasn't evicted")
	}
	if closedByServer(fresh, 50*time.Millisecond) {
		t.Fatal("the newcomer was closed")
	}
	if st := s.Status(); st.TCPConnsEvicted != 1 || st.TCPConns != 4 {
		t.Errorf("status %+v", st)
	}
	// 2 and 2 now: a newcomer from either source is refused.
	extra, err := net.Dial("tcp", v4)
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if !closedByServer(extra, 30*time.Second) {
		t.Error("newcomer from a source holding as many as any other was accepted")
	}
	waitFor(t, "the refusal", func() bool { return s.Status().TCPConnsRefused == 1 })
}

// Accept times can tie (Windows' clock is coarse); "oldest" is the accept order.
func TestEvictOldestOnClockTie(t *testing.T) {
	tl := trackTable(4, 32, 256)
	near := func(ip string) (*tconn, net.Conn) {
		a, b := net.Pipe()
		tc := newTconn(a, netip.MustParseAddr(ip), pipeEpoch) // the same instant for all
		if !tl.track(tc) {
			t.Fatalf("%s refused", ip)
		}
		return tc, b
	}
	for round := 0; round < 20; round++ { // map order is random: try it many times
		tl = trackTable(4, 32, 256)
		_, first := near("192.0.2.1")
		near("192.0.2.1")
		near("192.0.2.1")
		near("198.51.100.1")
		near("198.51.100.2")
		if !pipeClosed(first) {
			t.Fatalf("round %d: evicted a newer connection, not the first accepted", round)
		}
	}
}
