package listen

import (
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/model"
)

// orderLog records every delivery, by either path, in one sequence.
type orderLog struct {
	mu  sync.Mutex
	all []string // "<path>:<raw>"
}

func (o *orderLog) add(path, raw string) {
	o.mu.Lock()
	o.all = append(o.all, path+":"+raw)
	o.mu.Unlock()
}

func (o *orderLog) snapshot() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.all...)
}

// startInline starts a UDP-only server on the real clock with a Sink (the
// drainer's path) gated by ss, and a TrySink that accepts when try returns true.
func startInline(t *testing.T, try func(raw string) bool) (*Server, *slowSink, *orderLog, *atomic.Int64, net.Conn) {
	t.Helper()
	ss := &slowSink{}
	log := &orderLog{}
	var tries atomic.Int64
	cfg := config.Listeners{UDP: config.Listener{Enabled: true, Addr: "127.0.0.1"}}
	s, err := Start(cfg, Options{Logger: quiet, Holder: func(string, int) string { return "" },
		Sink: func(m model.Message) { ss.sink(m); log.add("queue", string(m.Raw)) },
		TrySink: func(m model.Message) bool {
			tries.Add(1)
			if m.Severity != 5 || m.Facility != 1 {
				t.Errorf("TrySink got an unparsed message: %+v", m)
			}
			if !try(string(m.Raw)) {
				return false
			}
			log.add("inline", string(m.Raw))
			return true
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.resume(); s.Close() })
	conn, err := net.Dial("udp", udpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return s, ss, log, &tries, conn
}

// sendSpaced sends <13>m<i> for i in [from, to), each after a quiet gap, so
// each one is a lone datagram.
func sendSpaced(conn net.Conn, from, to int) {
	for i := from; i < to; i++ {
		time.Sleep(2 * time.Millisecond)
		fmt.Fprintf(conn, "<13>m%d", i)
	}
}

func wantOrder(t *testing.T, got []string, n int, path func(i int) string) {
	t.Helper()
	if len(got) != n {
		t.Fatalf("%d deliveries, want %d: %q", len(got), n, got)
	}
	for i, g := range got {
		want := fmt.Sprintf("%s:<13>m%d", path(i), i)
		if path(i) == "" {
			want = fmt.Sprintf("<13>m%d", i)
			if _, after, ok := cut(g, ":"); !ok || after != want {
				t.Fatalf("delivery %d is %q, want %q", i, g, want)
			}
			continue
		}
		if g != want {
			t.Fatalf("delivery %d is %q, want %q", i, g, want)
		}
	}
}

// idle reports whether q's drainer has nothing queued or in hand. It clears
// busy only when it next looks for work, a moment after its last delivery, so
// a test expecting the next lone datagram to go inline waits for this first.
func idle(q *udpQueue) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n == 0 && !q.busy
}

func queueOf(s *Server, snmp bool) *udpQueue {
	s.mu.Lock()
	defer s.mu.Unlock()
	if snmp {
		return s.snmpQ
	}
	return s.udpQ
}

// seqOf is i in "<13>m<i>".
func seqOf(raw string) int {
	var i int
	fmt.Sscanf(raw, "<13>m%d", &i)
	return i
}

func cut(s, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(s); i++ {
		if s[i:i+len(sep)] == sep {
			return s[:i], s[i+len(sep):], true
		}
	}
	return s, "", false
}

// A lone datagram is delivered by the reader through TrySink: the drainer never
// wakes, and nothing is queued.
func TestInlineLoneDatagrams(t *testing.T) {
	s, _, log, _, conn := startInline(t, func(string) bool { return true })
	// Each one sent 2 ms after the one before was delivered: lone by construction
	// (an idle queue and far more than inlineGap since the last read), so every
	// one goes inline whatever the scheduler does.
	for i := 0; i < 20; i++ {
		sendSpaced(conn, i, i+1)
		waitFor(t, "delivered", func() bool { return len(log.snapshot()) == i+1 })
	}
	wantOrder(t, log.snapshot(), 20, func(int) string { return "inline" })
	// A stream spaced the same way without waiting: order is exact whichever path
	// each one took. On a busy runner the reader can find several waiting and
	// correctly queue them, so how many go inline is only logged.
	sendSpaced(conn, 20, 40)
	waitFor(t, "40 delivered", func() bool { return len(log.snapshot()) == 40 })
	got := log.snapshot()
	wantOrder(t, got, 40, func(i int) string {
		if i < 20 {
			return "inline"
		}
		return ""
	})
	inline := 0
	for _, g := range got[20:] {
		if p, _, _ := cut(g, ":"); p == "inline" {
			inline++
		}
	}
	t.Logf("%d of 20 spaced datagrams sent without waiting went inline", inline)
	// The inline path counts a message after TrySink takes it (listen.go enqueue),
	// so the last one can be delivered and not yet counted.
	waitFor(t, "40 received", func() bool { return s.Status().Received >= 40 })
	st := s.Status()
	if st.Received != 40 || st.UDPQueues[0].HighWater24h > 20-inline {
		t.Errorf("received %d, queue high-water %d with %d queued", st.Received, st.UDPQueues[0].HighWater24h, 20-inline)
	}
}

// When TrySink would block, the datagram goes through the queue, in order with
// the ones delivered inline.
func TestInlineFallsBackToQueue(t *testing.T) {
	s, _, log, _, conn := startInline(t, func(raw string) bool { return seqOf(raw)%3 != 0 }) // m0, m3, m6, m9 "would block"
	q := queueOf(s, false)
	for i := 0; i < 12; i++ {
		sendSpaced(conn, i, i+1)
		// Each settles before the next, the drainer included.
		waitFor(t, "delivered", func() bool { return len(log.snapshot()) == i+1 && idle(q) })
	}
	wantOrder(t, log.snapshot(), 12, func(i int) string {
		if i%3 == 0 {
			return "queue"
		}
		return "inline"
	})
	// Counted after TrySink takes it (listen.go enqueue): wait for the last one's count.
	waitFor(t, "12 received", func() bool { return s.Status().Received >= 12 })
	if st := s.Status(); st.Received != 12 {
		t.Errorf("received %d", st.Received)
	}
}

// While the drainer has messages in hand (here: stalled in the sink), the
// reader never delivers inline, so arrival order holds; TrySink isn't even
// asked.
func TestInlineWaitsForBusyDrainer(t *testing.T) {
	s, ss, log, tries, conn := startInline(t, func(raw string) bool { return raw != "<13>m0" })
	ss.stall()
	sendSpaced(conn, 0, 1) // would block: queued, and the drainer stalls on it
	waitFor(t, "the drainer to block", func() bool { return ss.inside.Load() == 1 })
	sendSpaced(conn, 1, 6) // lone, but the drainer is busy
	// All five read (queued behind m0) before the drainer is let go: a reader
	// that got to m5 only after the drain would rightly send it inline.
	waitFor(t, "m1-m5 queued", func() bool { return s.Status().UDPQueues[0].Depth == 5 })
	if n := tries.Load(); n != 1 {
		t.Fatalf("TrySink asked %d times while the drainer was busy", n)
	}
	ss.resume()
	waitFor(t, "6 delivered and the drainer idle", func() bool { return len(log.snapshot()) == 6 && idle(queueOf(s, false)) })
	wantOrder(t, log.snapshot(), 6, func(int) string { return "queue" })
	// Idle again: the next lone one goes inline.
	sendSpaced(conn, 6, 7)
	waitFor(t, "7 delivered", func() bool { return len(log.snapshot()) == 7 })
	if got := log.snapshot()[6]; got != "inline:<13>m6" {
		t.Errorf("after the drain: %q", got)
	}
}

// Datagrams read back to back (a burst, or a backlog in the socket buffer) go
// through the queue even when the drainer is idle: the inline path is for lone
// ones.
func TestInlineGap(t *testing.T) {
	q := newUDPQueue(1000, 1<<20, &queueHist{})
	t0 := time.Now()
	if !q.inline(t0) {
		t.Fatal("the first datagram isn't lone")
	}
	if q.inline(t0.Add(inlineGap / 2)) {
		t.Error("a datagram right after another went inline")
	}
	if !q.inline(t0.Add(inlineGap/2 + inlineGap)) {
		t.Error("a datagram after a quiet gap didn't")
	}
	q.push(queued{raw: []byte("x"), at: t0})
	if q.inline(t0.Add(time.Hour)) {
		t.Error("inline with a message queued")
	}
}

// A trap that TrapTry can't finish without blocking is finished by the drainer,
// in order: TrapTry returns the rest as a func, which runs exactly once.
func TestTrapTryFinish(t *testing.T) {
	cfg := config.Listeners{SNMP: config.SNMPListener{Enabled: true, Addr: "127.0.0.1", Port: 0}}
	log := &orderLog{}
	var finishes atomic.Int64
	s, _, _ := start(t, cfg, func(o *Options) {
		o.Clock = time.Now
		o.Trap = func(p *TrapPacket) { log.add("queue", string(p.Raw)) }
		o.TrapTry = func(p *TrapPacket) func() {
			raw := string(p.Raw)
			if seqOf(raw)%2 == 0 { // m0, m2, …: the write would block
				return func() { finishes.Add(1); log.add("finish", raw) }
			}
			log.add("inline", raw)
			return nil
		}
	})
	ap, _ := s.SNMPAddr()
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	q := queueOf(s, true)
	for i := 0; i < 6; i++ {
		sendSpaced(c, i, i+1)
		waitFor(t, "handled", func() bool { return len(log.snapshot()) == i+1 && idle(q) })
	}
	wantOrder(t, log.snapshot(), 6, func(i int) string {
		if i%2 == 0 {
			return "finish"
		}
		return "inline"
	})
	if finishes.Load() != 3 || s.Status().Received != 6 {
		t.Errorf("%d finishes, received %d", finishes.Load(), s.Status().Received)
	}
}
