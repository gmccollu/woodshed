package listen

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
)

// filterCounts records OnFiltered's calls.
type filterCounts struct {
	mu sync.Mutex
	n  map[netip.Addr][8]int64
}

func (f *filterCounts) add(from netip.Addr, _ time.Time, sev int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n == nil {
		f.n = map[netip.Addr][8]int64{}
	}
	c := f.n[from]
	c[sev]++
	f.n[from] = c
}

func (f *filterCounts) of(a string) [8]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n[netip.MustParseAddr(a)]
}

func raws(t *testing.T, c *collector, n int) []string {
	t.Helper()
	var out []string
	for _, m := range c.wait(t, n) {
		out = append(out, string(m.Raw))
	}
	return out
}

// The per-sender resolution on the reader's own path: an override wins (in
// either direction), a sender without one follows the default, a message
// without a valid PRI is always kept, and a filter that keeps everything
// isn't even read.
func TestSeverityFilterResolution(t *testing.T) {
	var fc filterCounts
	s, c, _ := start(t, config.Listeners{}, func(o *Options) {
		o.OnFiltered = fc.add
		o.SeverityFilter = &SeverityFilter{Min: 5, ByDevice: map[netip.Addr]int{
			netip.MustParseAddr("192.0.2.10"): 6, // the access point: info and above
			netip.MustParseAddr("192.0.2.20"): 7, // everything, whatever the default
		}}
	})
	ap, loud, other := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20"), netip.MustParseAddr("192.0.2.30")
	for _, from := range []netip.Addr{ap, loud, other, netip.MustParseAddr("::ffff:192.0.2.10")} {
		for _, m := range []string{"<15>debug", "<14>info", "<13>notice", "<11>err", "no pri", "<192>bad pri", " <191>debug after a blank"} {
			s.deliver([]byte(m), from, false, frameEnd{})
		}
	}
	got := raws(t, c, 21)
	if len(got) != 21 {
		t.Fatalf("kept %d: %q", len(got), got)
	}
	if n := fc.of("192.0.2.10"); n[7] != 4 || n[6] != 0 {
		t.Errorf("the AP's filtered %v", n)
	}
	if n := fc.of("192.0.2.20"); n != [8]int64{} {
		t.Errorf("the override to everything filtered %v", n)
	}
	if n := fc.of("192.0.2.30"); n[7] != 2 || n[6] != 1 {
		t.Errorf("the default's filtered %v", n)
	}
	if st := s.Status(); st.Filtered != 7 || st.Received != 21 {
		t.Errorf("status filtered %d received %d", st.Filtered, st.Received)
	}
	// Keeping everything removes the filter.
	s.SetSeverityFilter(SeverityFilter{Min: 7, ByDevice: map[netip.Addr]int{ap: 7}})
	if s.sevf.Load() != nil {
		t.Fatal("a filter that keeps everything is still set")
	}
	s.deliver([]byte("<15>debug"), ap, false, frameEnd{})
	if c.wait(t, 22); s.Status().Filtered != 7 {
		t.Error("filtered with no filter")
	}
}

// Over real sockets (UDP, TCP and TLS): the filtered messages never reach
// the sink, each is counted once, and a change applies from the next message,
// on an open TCP connection too. Every phase ends with a message that's kept,
// so waiting for it means everything before it was decided (each socket is
// read in order).
func TestSeverityFilterOverSockets(t *testing.T) {
	var fc filterCounts
	cfg := loopback(0, 0)
	cfg.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: 0}
	s, c, pool := startTLS(t, cfg, func(o *Options) {
		o.OnFiltered = fc.add
		o.SeverityFilter = &SeverityFilter{Min: 7, ByDevice: map[netip.Addr]int{netip.MustParseAddr("127.0.0.1"): 6}}
	})
	const lo = "127.0.0.1"
	sendUDPSeen(t, s, "<15>udp debug 1", "<15>udp debug 2", "<14>udp info", "udp no pri", "<11>udp err")
	tcp, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	tcp.Write([]byte("<15>tcp debug\n<14>tcp info\n13 <15>tcp octet"))
	tl, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	tl.Write([]byte("<15>tls debug\n<13>tls notice\n"))
	got := raws(t, c, 5)
	for _, want := range []string{"<14>udp info", "udp no pri", "<11>udp err", "<14>tcp info", "<13>tls notice"} {
		if !strings.Contains(strings.Join(got, "|"), want) {
			t.Errorf("%q not kept: %q", want, got)
		}
	}
	// The TCP octet frame comes after the last kept TCP message: wait for
	// its count too.
	waitCount(t, &fc, lo, 7, 5)

	// The override changes on the open connections: notice and above.
	s.SetSeverityFilter(SeverityFilter{Min: 7, ByDevice: map[netip.Addr]int{netip.MustParseAddr(lo): 5}})
	// UDP first: sendUDPSeen counts what the listeners took in, so nothing
	// else may be in flight while it waits.
	sendUDPSeen(t, s, "<14>udp info now filtered", "<12>udp warning kept")
	tcp.Write([]byte("<14>tcp info now filtered\n<13>tcp notice kept\n"))
	tl.Write([]byte("<14>tls info now filtered\n<12>tls warning kept\n"))
	got = raws(t, c, 8)
	for _, m := range got {
		if strings.Contains(m, "now filtered") {
			t.Errorf("stored %q after the change", m)
		}
	}
	waitCount(t, &fc, lo, 6, 3)
	// Back to the default (everything).
	s.SetSeverityFilter(SeverityFilter{Min: 7})
	tcp.Write([]byte("<15>tcp debug kept\n"))
	if got = raws(t, c, 9); got[8] != "<15>tcp debug kept" {
		t.Errorf("last %q", got[8])
	}
	if n := fc.of(lo); n[7] != 5 || n[6] != 3 {
		t.Errorf("counts changed: %v", n)
	}
}

// waitCount waits for OnFiltered's count of severity sev from a to reach
// want: the messages after the last kept one on each socket may still be
// on their way when the kept ones arrive from another socket.
func waitCount(t *testing.T, fc *filterCounts, a string, sev int, want int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for fc.of(a)[sev] != want {
		if time.Now().After(deadline) {
			t.Fatalf("filtered %v, want %d of severity %d", fc.of(a), want, sev)
		}
		time.Sleep(time.Millisecond)
	}
}

// A filtered UDP datagram never takes room in the queue: with the fast path
// off every kept datagram is queued, and filtered ones aren't.
func TestSeverityFilterBeforeTheQueue(t *testing.T) {
	var fc filterCounts
	s, c, _ := start(t, config.Listeners{}, func(o *Options) {
		o.OnFiltered = fc.add
		o.SeverityFilter = &SeverityFilter{Min: 6}
	})
	q := newUDPQueue(config.MinUDPQueueMessages, config.MaxUDPQueueBytes, &queueHist{})
	from := netip.MustParseAddr("192.0.2.10")
	for i := 0; i < 3*config.MinUDPQueueMessages; i++ {
		s.enqueue(q, []byte("<15>debug flood"), from)
	}
	s.enqueue(q, []byte("<14>info"), from)
	if st := q.status("udp", 0, fixedNow, fixedNow); st.Depth != 1 || st.Dropped24h != 0 {
		t.Fatalf("queue %+v", st)
	}
	done := make(chan struct{})
	go func() { defer close(done); s.drainQueue(q) }()
	q.close()
	<-done
	if got := raws(t, c, 1); got[0] != "<14>info" {
		t.Fatalf("got %q", got)
	}
	if n := fc.of("192.0.2.10"); n[7] != 3*config.MinUDPQueueMessages {
		t.Fatalf("filtered %v", n)
	}
}

// The filter reads the PRI from the bytes that are stored and parsed: a PRI
// past the max message size (after a long run of blanks) isn't in the stored
// copy, which has no severity, so the message is kept, as Parse sees it.
func TestSeverityFilterReadsTheStoredBytes(t *testing.T) {
	var fc filterCounts
	s, c, _ := start(t, config.Listeners{MaxMessageBytes: config.MinMaxMessageBytes}, func(o *Options) {
		o.OnFiltered = fc.add
		o.SeverityFilter = &SeverityFilter{Min: 6}
	})
	from := netip.MustParseAddr("192.0.2.10")
	s.deliver([]byte(strings.Repeat(" ", config.MinMaxMessageBytes)+"<15>debug past the cut"), from, false, frameEnd{})
	s.deliver([]byte("<15>debug"), from, false, frameEnd{})
	s.deliver([]byte("<14>info"), from, false, frameEnd{})
	got := c.wait(t, 2)
	if len(got) != 2 || got[0].Severity != -1 || !got[0].Truncated || string(got[1].Raw) != "<14>info" {
		t.Fatalf("kept %+v", got)
	}
	if n := fc.of("192.0.2.10"); n[7] != 1 {
		t.Errorf("filtered %v", n)
	}
}

// sendUDPSeen sends each datagram and waits until the UDP reader took it off
// the socket (its own counter, before any queue or drainer), sending it again
// only if the reader never got it: these tests are about the filter, not
// UDP's losses. A datagram on loopback is in the socket buffer at once, so
// one the reader hasn't read in 10 s was lost, not slow; a slow drainer can't
// cause a resend.
func sendUDPSeen(t *testing.T, s *Server, msgs ...string) {
	t.Helper()
	c, err := net.Dial("udp", udpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, m := range msgs {
		before, ok := s.udp.read.Load(), false
		for try := 0; try < 3 && !ok; try++ {
			if _, err := c.Write([]byte(m)); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
				if ok = s.udp.read.Load() > before; ok {
					break
				}
			}
		}
		if !ok {
			t.Fatalf("the reader never got %q", m)
		}
	}
}
