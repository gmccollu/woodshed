package listen

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/model"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// collector is a Sink that keeps every message.
type collector struct {
	mu   sync.Mutex
	msgs []model.Message
	ch   chan struct{}
}

func newCollector() *collector { return &collector{ch: make(chan struct{}, 1<<16)} }

func (c *collector) sink(m model.Message) {
	c.mu.Lock()
	c.msgs = append(c.msgs, m)
	c.mu.Unlock()
	select {
	case c.ch <- struct{}{}:
	default:
	}
}

func (c *collector) wait(t *testing.T, n int) []model.Message {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		c.mu.Lock()
		if len(c.msgs) >= n {
			out := append([]model.Message(nil), c.msgs...)
			c.mu.Unlock()
			return out
		}
		c.mu.Unlock()
		select {
		case <-c.ch:
		case <-deadline:
			c.mu.Lock()
			defer c.mu.Unlock()
			t.Fatalf("got %d messages, want %d", len(c.msgs), n)
			return nil
		}
	}
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func (e *eventLog) add(ev Event) { e.mu.Lock(); e.ev = append(e.ev, ev); e.mu.Unlock() }

func (e *eventLog) kinds() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []string
	for _, ev := range e.ev {
		out = append(out, ev.Kind+":"+strings.SplitN(ev.Text, " ", 2)[0])
	}
	return out
}

func (e *eventLog) find(kind string) (Event, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.ev {
		if ev.Kind == kind {
			return ev, true
		}
	}
	return Event{}, false
}

var fixedNow = time.Date(2026, 11, 10, 20, 41, 7, 112_000_000, time.UTC)

func loopback(udpPort, tcpPort int) config.Listeners {
	return config.Listeners{
		UDP: config.Listener{Enabled: true, Addr: "127.0.0.1", Port: udpPort},
		TCP: config.Listener{Enabled: true, Addr: "127.0.0.1", Port: tcpPort},
	}
}

func start(t *testing.T, cfg config.Listeners, mod func(*Options)) (*Server, *collector, *eventLog) {
	t.Helper()
	c := newCollector()
	ev := &eventLog{}
	opts := Options{Sink: c.sink, Logger: quiet, OnEvent: ev.add, Clock: func() time.Time { return fixedNow },
		Holder: func(string, int) string { return "" }}
	if mod != nil {
		mod(&opts)
	}
	s, err := Start(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, c, ev
}

func udpAddr(t *testing.T, s *Server) string {
	ap, ok := s.UDPAddr()
	if !ok {
		t.Fatal("UDP not running")
	}
	return ap.String()
}

func tcpAddr(t *testing.T, s *Server) string {
	ap, ok := s.TCPAddr()
	if !ok {
		t.Fatal("TCP not running")
	}
	return ap.String()
}

func sendUDP(t *testing.T, addr string, msgs ...string) {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, m := range msgs {
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUDPReceive(t *testing.T) {
	s, c, ev := start(t, loopback(0, 0), nil)
	sendUDP(t, udpAddr(t, s), "<134>Nov 10 20:41:07 host1 app: hello\n", "\n", "no pri at all\r\n\x00")
	got := c.wait(t, 2)
	m := got[0]
	if string(m.Raw) != "<134>Nov 10 20:41:07 host1 app: hello" {
		t.Errorf("raw %q", m.Raw)
	}
	if m.Severity != 6 || m.Facility != 16 || m.Hostname != "host1" || m.App != "app" {
		t.Errorf("parsed %+v", m)
	}
	if !m.Received.Equal(fixedNow) || m.Received.Location() != time.UTC {
		t.Errorf("received %v", m.Received)
	}
	if m.Sender != netip.MustParseAddr("127.0.0.1") || m.Truncated {
		t.Errorf("sender %v truncated %v", m.Sender, m.Truncated)
	}
	if string(got[1].Raw) != "no pri at all" || got[1].Severity != model.Unknown {
		t.Errorf("second %q sev %d", got[1].Raw, got[1].Severity)
	}
	time.Sleep(50 * time.Millisecond)
	if n := c.count(); n != 2 {
		t.Errorf("empty datagram delivered: %d messages", n)
	}
	st := s.Status()
	if len(st.Listeners) != 2 || !st.Listeners[0].OK || st.Listeners[0].Proto != "udp" || st.Listeners[1].Proto != "tcp" {
		t.Errorf("status %+v", st.Listeners)
	}
	if st.Received != 2 || st.UDPRcvbufBytes <= 0 || st.UDPRcvbufRequestedBytes != config.DefaultUDPRcvbufBytes {
		t.Errorf("status %+v", st)
	}
	if st.KernelDropsVisible != (runtime.GOOS == "linux") {
		t.Errorf("kernel drops visible = %v on %s", st.KernelDropsVisible, runtime.GOOS)
	}
	t.Logf("UDP rcvbuf granted %d of %d requested", st.UDPRcvbufBytes, st.UDPRcvbufRequestedBytes)
	if k := ev.kinds(); len(k) != 2 || k[0] != "start:UDP" || k[1] != "start:TCP" {
		t.Errorf("events %v", k)
	}
	if e, _ := ev.find(KindStart); !strings.Contains(e.Text, "granted of 32 MiB requested") {
		t.Errorf("start event %q", e.Text)
	}
}

func TestRcvbufFallback(t *testing.T) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// 1 GiB is above every default OS limit: we must get the largest size the OS
	// accepts, not an error or the OS default.
	def := getRcvbuf(c)
	got := setRcvbuf(c, 1<<30)
	t.Logf("default %d, granted for a 1 GiB request %d", def, got)
	if got <= 0 || got < def {
		t.Errorf("granted %d (default %d)", got, def)
	}
	if got2 := setRcvbuf(c, 256<<10); got2 < 256<<10 {
		t.Errorf("256 KiB request granted %d", got2)
	}
}

func TestUDPTruncation(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.MaxMessageBytes = 100
	s, c, _ := start(t, cfg, nil)
	long := "<13>" + strings.Repeat("x", 300)
	sendUDP(t, udpAddr(t, s), long, "<13>short")
	got := c.wait(t, 2)
	if len(got[0].Raw) != 100 || !got[0].Truncated || string(got[0].Raw) != long[:100] {
		t.Errorf("truncated message: len %d truncated %v", len(got[0].Raw), got[0].Truncated)
	}
	if got[1].Truncated {
		t.Error("short message marked truncated")
	}
	if st := s.Status(); st.Truncated != 1 {
		t.Errorf("truncated counter %d", st.Truncated)
	}
}

func TestTCPFraming(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.MaxMessageBytes = 64
	s, c, _ := start(t, cfg, nil)
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	long := "<14>" + strings.Repeat("y", 100)
	stream := "<13>lf one\n" +
		"<13>crlf two\r\n" +
		"123 not a count\n" +
		"15 <13>octet three" + // octet-counted, then the rest of the connection may omit '<'
		"\n\n" +
		long + "\n" +
		"<13>nul five\x00" +
		"<13>tail without newline"
	// Write in small pieces so frames straddle reads.
	for i := 0; i < len(stream); i += 7 {
		if _, err := conn.Write([]byte(stream[i:min(i+7, len(stream))])); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()
	got := c.wait(t, 7)
	want := []string{"<13>lf one", "<13>crlf two", "123 not a count", "<13>octet three", long[:64], "<13>nul five", "<13>tail without newline"}
	for i, w := range want {
		if string(got[i].Raw) != w {
			t.Errorf("[%d] %q, want %q", i, got[i].Raw, w)
		}
		if got[i].Truncated != (i == 4) {
			t.Errorf("[%d] truncated = %v", i, got[i].Truncated)
		}
		if got[i].Sender != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("[%d] sender %v", i, got[i].Sender)
		}
	}
	if st := s.Status(); st.Truncated != 1 || st.Received != 7 {
		t.Errorf("counters %+v", st)
	}
}

func TestAllowlistRejects(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.Allowlist = []string{"192.0.2.0/24", "2001:db8::1"}
	s, c, _ := start(t, cfg, nil)
	sendUDP(t, udpAddr(t, s), "<13>a", "<13>b", "<13>c")
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("<13>tcp\n"))
	// The server closes a refused connection at once.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("refused TCP connection is still open")
	}
	conn.Close()
	deadline := time.Now().Add(5 * time.Second)
	for s.Status().Rejected < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.count() != 0 {
		t.Errorf("%d messages from a refused sender reached the sink", c.count())
	}
	rej := s.Rejected()
	if len(rej) != 1 || rej[0].IP != "127.0.0.1" || rej[0].Count24h != 4 || !rej[0].LastSeen.Equal(fixedNow) {
		t.Errorf("rejected %+v", rej)
	}
	if n := s.Rejected24h(); n != 4 {
		t.Errorf("rejected_24h %d", n)
	}

	// Allow loopback live; the next message gets through.
	cfg.Allowlist = []string{"127.0.0.1"}
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	sendUDP(t, udpAddr(t, s), "<13>now allowed")
	if got := c.wait(t, 1); string(got[0].Raw) != "<13>now allowed" {
		t.Errorf("got %q", got[0].Raw)
	}
	cfg.Allowlist = []string{"not an ip"}
	if err := s.Reconfigure(cfg); err == nil {
		t.Error("bad allowlist accepted")
	}
}

func TestRejectsTable(t *testing.T) {
	r := newRejects(3)
	t0 := time.Date(2026, 11, 10, 10, 30, 0, 0, time.UTC)
	ip := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}) }
	r.add(ip(1), t0, 5, RejectAllowlist)
	r.add(ip(2), t0.Add(time.Minute), 1, RejectAllowlist)
	r.add(ip(3), t0.Add(2*time.Minute), 2, RejectAllowlist)
	r.add(ip(1), t0.Add(3*time.Minute), 1, RejectAllowlist) // 1 is now the most recent
	r.add(ip(4), t0.Add(4*time.Minute), 3, RejectAllowlist) // evicts 2, the least recently seen
	if r.size() != 3 {
		t.Fatalf("size %d", r.size())
	}
	got := r.list(t0.Add(5*time.Minute), 0)
	want := []string{"198.51.100.1:6", "198.51.100.4:3", "198.51.100.3:2"}
	if len(got) != len(want) {
		t.Fatalf("list %+v", got)
	}
	for i, w := range want {
		if fmt.Sprintf("%s:%d", got[i].IP, got[i].Count24h) != w {
			t.Errorf("[%d] %+v, want %s", i, got[i], w)
		}
	}
	if l := r.list(t0.Add(5*time.Minute), 2); len(l) != 2 {
		t.Errorf("limit: %d entries", len(l))
	}
	// The total keeps the evicted IP's rejection.
	if n := r.total24h(t0.Add(5 * time.Minute)); n != 12 {
		t.Errorf("total24h %d", n)
	}
	// 24 h later everything has aged out and is pruned.
	later := t0.Add(25 * time.Hour)
	if l := r.list(later, 0); len(l) != 0 || r.size() != 0 {
		t.Errorf("after 25 h: %+v (size %d)", l, r.size())
	}
	if n := r.total24h(later); n != 0 {
		t.Errorf("total24h after 25 h: %d", n)
	}
	// Ties sort by last seen, newest first.
	r.add(ip(7), later, 1, RejectAllowlist)
	r.add(ip(8), later.Add(time.Second), 1, RejectAllowlist)
	if l := r.list(later.Add(time.Minute), 0); l[0].IP != "198.51.100.8" {
		t.Errorf("tie order %+v", l)
	}
}

func TestRejectsFull(t *testing.T) {
	r := newRejects(maxRejectedIPs)
	now := fixedNow
	for i := 0; i < maxRejectedIPs+500; i++ {
		r.add(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), now, 1, RejectAllowlist)
	}
	if r.size() != maxRejectedIPs {
		t.Errorf("size %d", r.size())
	}
	if l := r.list(now, MaxRejectedList); len(l) != MaxRejectedList {
		t.Errorf("list %d", len(l))
	}
	if n := r.total24h(now); n != maxRejectedIPs+500 {
		t.Errorf("total %d", n)
	}
}

// occupy binds proto on 127.0.0.1 at an ephemeral port and returns the port and a
// closer.
func occupy(t *testing.T, proto string) (int, func()) {
	t.Helper()
	if proto == "udp" {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return c.LocalAddr().(*net.UDPAddr).Port, func() { c.Close() }
	}
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	return l.Addr().(*net.TCPAddr).Port, func() { l.Close() }
}

func TestBindClashAndRetry(t *testing.T) {
	up, freeU := occupy(t, "udp")
	tp, freeT := occupy(t, "tcp")
	var holderCalls atomic.Int32
	s, c, ev := start(t, loopback(up, tp), func(o *Options) {
		o.Holder = func(proto string, port int) string {
			holderCalls.Add(1)
			return "otherd (pid 4242)"
		}
	})
	st := s.Status()
	if len(st.Listeners) != 2 {
		t.Fatalf("listeners %+v", st.Listeners)
	}
	for i, proto := range []string{"udp", "tcp"} {
		l := st.Listeners[i]
		if l.Proto != proto || l.OK || l.Error != "bind: address already in use" || l.Holder != "otherd (pid 4242)" || l.Addr != "127.0.0.1" {
			t.Errorf("%s status %+v", proto, l)
		}
	}
	if st.Listeners[0].Port != up || st.Listeners[1].Port != tp {
		t.Errorf("ports %+v", st.Listeners)
	}
	if holderCalls.Load() != 2 {
		t.Errorf("holder lookups %d", holderCalls.Load())
	}
	e, ok := ev.find(KindBind)
	if !ok || e.Level != LevelError || !strings.Contains(e.Text, "UDP 127.0.0.1:"+strconv.Itoa(up)) ||
		!strings.Contains(e.Text, "held by otherd (pid 4242)") {
		t.Errorf("bind event %+v", e)
	}

	// Free UDP only: Retry brings it up and TCP stays down.
	freeU()
	st = s.Retry()
	if !st.Listeners[0].OK || st.Listeners[0].Error != "" || st.Listeners[1].OK {
		t.Fatalf("after first retry %+v", st.Listeners)
	}
	udp1, _ := s.UDPAddr()
	sendUDP(t, udp1.String(), "<13>after retry")
	c.wait(t, 1)

	// Free TCP: Retry binds it without touching the healthy UDP socket.
	s.mu.Lock()
	udpBefore := s.udp
	s.mu.Unlock()
	freeT()
	st = s.Retry()
	if !st.Listeners[0].OK || !st.Listeners[1].OK {
		t.Fatalf("after second retry %+v", st.Listeners)
	}
	s.mu.Lock()
	same := s.udp == udpBefore
	s.mu.Unlock()
	if !same {
		t.Error("Retry rebound the healthy UDP listener")
	}
	k := ev.kinds()
	want := []string{"bind:UDP", "bind:TCP", "start:UDP", "bind:TCP", "start:TCP"} // the first Retry tried TCP again
	if strings.Join(k, ",") != strings.Join(want, ",") {
		t.Errorf("events %v, want %v", k, want)
	}
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("<13>tcp after retry\n"))
	conn.Close()
	c.wait(t, 2)
}

func TestPortHolderFindsUs(t *testing.T) {
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/usr/sbin/lsof"); err != nil {
			t.Skip("no lsof")
		}
	} else if runtime.GOOS != "linux" {
		t.Skip("holder lookup is checked on darwin and linux")
	}
	for _, proto := range []string{"udp", "tcp"} {
		port, free := occupy(t, proto)
		t0 := time.Now()
		h := PortHolder(proto, port)
		took := time.Since(t0)
		free()
		// Best effort by design, but for our own process it should work, unless the
		// lookup ran out of its time budget (lsof on a loaded machine).
		if h == "" && took >= holderTimeout {
			t.Logf("%s: no holder: the lookup used its whole %v budget (%v)", proto, holderTimeout, took)
			continue
		}
		if !strings.Contains(h, "pid "+strconv.Itoa(os.Getpid())) {
			t.Errorf("%s: holder %q, want our pid %d", proto, h, os.Getpid())
		}
		t.Logf("%s holder: %q", proto, h)
	}
	if h := PortHolder("tcp", 0); h != "" {
		t.Errorf("port 0: %q", h)
	}
}

func TestConnectionLimit(t *testing.T) {
	s, c, _ := start(t, loopback(0, 0), func(o *Options) { o.MaxConns = 3 })
	addr := tcpAddr(t, s)
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		fmt.Fprintf(conn, "<13>conn %d\n", i)
	}
	c.wait(t, 3)
	if n := s.Status().TCPConns; n != 3 {
		t.Fatalf("open conns %d", n)
	}
	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	extra.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := extra.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("4th connection: read err %v, want EOF (closed by the server)", err)
	}
	extra.Close()
	if n := s.Status().TCPConnsRefused; n != 1 {
		t.Errorf("refused %d", n)
	}
	// Closing one frees a slot.
	conns[0].Close()
	deadline := time.Now().Add(5 * time.Second)
	for s.Status().TCPConns != 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	again, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(again, "<13>again\n")
	c.wait(t, 4)
	again.Close()
	for _, cn := range conns[1:] {
		cn.Close()
	}
}

func TestIdleTimeout(t *testing.T) {
	s, c, _ := start(t, loopback(0, 0), func(o *Options) { o.IdleTimeout = 150 * time.Millisecond })
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("<13>partial, never terminated"))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	startT := time.Now()
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Errorf("read err %v, want EOF after the idle timeout", err)
	}
	if d := time.Since(startT); d > 3*time.Second {
		t.Errorf("idle close took %v", d)
	}
	// The partial message is delivered when the connection ends.
	if got := c.wait(t, 1); string(got[0].Raw) != "<13>partial, never terminated" {
		t.Errorf("got %q", got[0].Raw)
	}
}

func TestReconfigure(t *testing.T) {
	s, c, ev := start(t, loopback(0, 0), nil)
	oldUDP := udpAddr(t, s)
	conn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "<13>before\n")
	c.wait(t, 1)

	// Move UDP to a new port; TCP is unchanged, so its connection stays open.
	newPort, free := occupy(t, "udp")
	free()
	cfg := loopback(newPort, 0)
	s.mu.Lock()
	cfg.TCP = s.cfg.TCP
	s.mu.Unlock()
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	if got := udpAddr(t, s); got == oldUDP || !strings.HasSuffix(got, ":"+strconv.Itoa(newPort)) {
		t.Fatalf("UDP at %s (was %s), want port %d", got, oldUDP, newPort)
	}
	sendUDP(t, udpAddr(t, s), "<13>new port")
	fmt.Fprintf(conn, "<13>tcp still open\n")
	got := c.wait(t, 3)
	seen := map[string]bool{}
	for _, m := range got {
		seen[string(m.Raw)] = true
	}
	if !seen["<13>new port"] || !seen["<13>tcp still open"] {
		t.Errorf("got %v", seen)
	}
	k := strings.Join(ev.kinds(), ",")
	if k != "start:UDP,start:TCP,stop:UDP,start:UDP" {
		t.Errorf("events %s", k)
	}

	// A new buffer size applies to the running socket.
	cfg.UDPRcvbufBytes = 256 << 10
	s.Reconfigure(cfg)
	if st := s.Status(); st.UDPRcvbufRequestedBytes != 256<<10 || st.UDPRcvbufBytes < 256<<10 {
		t.Errorf("rcvbuf %d of %d", st.UDPRcvbufBytes, st.UDPRcvbufRequestedBytes)
	}
	if k2 := strings.Join(ev.kinds(), ","); k2 != k {
		t.Errorf("a buffer change rebound a listener: %s", k2)
	}

	// Disable TCP: it stops and leaves the status list.
	cfg.TCP.Enabled = false
	s.Reconfigure(cfg)
	if st := s.Status(); len(st.Listeners) != 1 || st.Listeners[0].Proto != "udp" {
		t.Errorf("listeners %+v", st.Listeners)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Error("TCP connection survived disabling TCP")
	}
}

func TestDualStackWildcard(t *testing.T) {
	cfg := config.Listeners{UDP: config.Listener{Enabled: true, Addr: "0.0.0.0", Port: 0}}
	s, c, _ := start(t, cfg, nil)
	ap, _ := s.UDPAddr()
	port := strconv.Itoa(int(ap.Port()))
	sendUDP(t, "127.0.0.1:"+port, "<13>v4")
	got := c.wait(t, 1)
	if got[0].Sender != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("v4 sender %v (should be unmapped)", got[0].Sender)
	}
	conn, err := net.Dial("udp6", "[::1]:"+port)
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	conn.Write([]byte("<13>v6"))
	conn.Close()
	got = c.wait(t, 2)
	if got[1].Sender != netip.MustParseAddr("::1") {
		t.Errorf("v6 sender %v", got[1].Sender)
	}
}

func TestCloseStopsSink(t *testing.T) {
	s, c, ev := start(t, loopback(0, 0), nil)
	addr := tcpAddr(t, s)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "<13>one\n")
	c.wait(t, 1)
	s.Close()
	n := c.count()
	conn.Write([]byte("<13>after close\n"))
	time.Sleep(50 * time.Millisecond)
	if c.count() != n {
		t.Error("sink called after Close")
	}
	if k := strings.Join(ev.kinds(), ","); k != "start:UDP,start:TCP,stop:UDP,stop:TCP" {
		t.Errorf("events %s", k)
	}
	if err := s.Reconfigure(loopback(0, 0)); err == nil {
		t.Error("Reconfigure after Close succeeded")
	}
	s.Close() // idempotent
}

func TestStartErrors(t *testing.T) {
	if _, err := Start(loopback(0, 0), Options{}); err == nil {
		t.Error("no sink accepted")
	}
	cfg := loopback(0, 0)
	cfg.Allowlist = []string{"x"}
	if _, err := Start(cfg, Options{Sink: func(model.Message) {}}); err == nil {
		t.Error("bad allowlist accepted")
	}
}

func TestOsError(t *testing.T) {
	_, err := net.Listen("tcp", "256.0.0.1:1")
	if err == nil {
		t.Skip()
	}
	if s := osError(err); strings.HasPrefix(s, "listen ") {
		t.Errorf("prefix kept: %q", s)
	}
}

func TestHourWindow(t *testing.T) {
	var h hours
	t0 := time.Date(2026, 11, 10, 0, 10, 0, 0, time.UTC)
	for i := 0; i < 30; i++ {
		h.add(t0.Add(time.Duration(i)*time.Hour), 1)
	}
	// At hour 29 the window holds hours 6..29.
	if s := h.sum(t0.Add(29 * time.Hour)); s != 24 {
		t.Errorf("sum %d", s)
	}
	if s := h.sum(t0.Add(60 * time.Hour)); s != 0 {
		t.Errorf("stale sum %d", s)
	}
}

func TestSizeText(t *testing.T) {
	for n, want := range map[int]string{32 << 20: "32 MiB", 7456540: "7.1 MiB", 786896: "768 KiB", 100: "100 bytes"} {
		if got := sizeText(n); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}
