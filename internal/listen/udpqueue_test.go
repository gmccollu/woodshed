package listen

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/model"
)

func qe(i int, from netip.Addr, size int) queued {
	raw := []byte(fmt.Sprintf("%08d", i))
	if size > len(raw) {
		raw = append(raw, make([]byte, size-len(raw))...)
	}
	return queued{raw: raw, from: from, at: fixedNow}
}

func popAll(t *testing.T, q *udpQueue) []queued {
	t.Helper()
	var out []queued
	for {
		q.mu.Lock()
		n := q.n
		q.mu.Unlock()
		if n == 0 {
			return out
		}
		out, _ = q.pop(out, drainBatch)
	}
}

var (
	ipA = netip.MustParseAddr("192.0.2.1")
	ipB = netip.MustParseAddr("192.0.2.2")
)

func TestQueueLimitByCount(t *testing.T) {
	h := &queueHist{}
	q := newUDPQueue(3, 1<<20, h)
	for i := 0; i < 5; i++ {
		ok := q.push(qe(i, ipA, 0))
		if ok != (i < 3) {
			t.Fatalf("push %d: %v", i, ok)
		}
	}
	st := q.status("udp", 514, fixedNow, time.Time{})
	if st.Depth != 3 || st.Dropped != 2 || st.Dropped24h != 2 || st.DroppedLastHour != 2 || st.LastFullBy != FullByMessages ||
		st.CapacityMessages != 3 || st.CapacityBytes != 1<<20 || st.DepthBytes != 24 || st.LastDrop == nil {
		t.Fatalf("status %+v", st)
	}
	// Room again once the drainer takes some.
	if got := popAll(t, q); len(got) != 3 {
		t.Fatalf("popped %d", len(got))
	}
	if !q.push(qe(5, ipA, 0)) {
		t.Fatal("refused after draining")
	}
}

func TestQueueLimitByBytes(t *testing.T) {
	q := newUDPQueue(1000, 100, &queueHist{})
	if !q.push(qe(0, ipA, 40)) || !q.push(qe(1, ipA, 40)) {
		t.Fatal("refused under the byte limit")
	}
	if q.push(qe(2, ipA, 40)) {
		t.Fatal("accepted past the byte limit")
	}
	if !q.push(qe(3, ipA, 20)) { // exactly 100
		t.Fatal("refused at exactly the byte limit")
	}
	st := q.status("udp", 514, fixedNow, time.Time{})
	if st.Depth != 3 || st.DepthBytes != 100 || st.Dropped != 1 || st.LastFullBy != FullByBytes {
		t.Fatalf("status %+v", st)
	}
	popAll(t, q)
	if st := q.status("udp", 514, fixedNow, time.Time{}); st.Depth != 0 || st.DepthBytes != 0 {
		t.Fatalf("after draining %+v", st)
	}
	// Lowering the limits below the depth drops nothing queued.
	for i := 0; i < 5; i++ {
		q.push(qe(i, ipA, 10))
	}
	q.setLimits(2, 100)
	if q.push(qe(9, ipA, 1)) {
		t.Fatal("accepted over the lowered limit")
	}
	if got := popAll(t, q); len(got) != 5 {
		t.Fatalf("popped %d after lowering", len(got))
	}
}

// FIFO across chunk boundaries, with pushes and pops interleaved.
func TestQueueFIFO(t *testing.T) {
	q := newUDPQueue(100000, 1<<30, &queueHist{})
	next, want := 0, 0
	check := func(es []queued) {
		t.Helper()
		for _, e := range es {
			if got, _ := strconv.Atoi(string(e.raw[:8])); got != want {
				t.Fatalf("popped %d, want %d", got, want)
			}
			want++
		}
	}
	for round := 0; round < 20; round++ {
		for i := 0; i < 1500+round*37; i++ {
			if !q.push(qe(next, ipA, 0)) {
				t.Fatal("refused")
			}
			next++
		}
		// Take part of it, so the head chunk is partly used.
		es, _ := q.pop(nil, 700)
		check(es)
	}
	check(popAll(t, q))
	if want != next {
		t.Fatalf("got %d of %d", want, next)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.head != q.tail || q.hi != 0 || q.ti != 0 || q.bytes != 0 {
		t.Fatalf("empty queue not reset: hi %d ti %d bytes %d", q.hi, q.ti, q.bytes)
	}
}

// One reader, one drainer, concurrently (run with -race): every message comes
// out once, in order.
func TestQueueConcurrent(t *testing.T) {
	q := newUDPQueue(5000, 1<<30, &queueHist{})
	const n = 200000
	var got []int
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf []queued
		for {
			var ok bool
			buf, ok = q.pop(buf[:0], drainBatch)
			for _, e := range buf {
				v, _ := strconv.Atoi(string(e.raw[:8]))
				got = append(got, v)
			}
			if !ok {
				return
			}
		}
	}()
	pushed := 0
	for i := 0; i < n; i++ {
		for !q.push(qe(i, ipA, 0)) {
			// Full: a real reader drops; here wait so the order check covers all.
			time.Sleep(time.Microsecond)
		}
		pushed++
	}
	q.close()
	<-done
	if len(got) != n {
		t.Fatalf("got %d of %d", len(got), n)
	}
	for i, v := range got {
		if v != i {
			t.Fatalf("message %d is %d", i, v)
		}
	}
}

// Drops are counted per sender for OnQueueDrop, and past the table's size
// without one, so the total stays exact.
func TestQueueDropAccounting(t *testing.T) {
	q := newUDPQueue(1000, 1<<20, &queueHist{})
	q.setLimits(0, 1<<20) // full from the start
	for i := 0; i < 3; i++ {
		q.push(qe(i, ipA, 0))
	}
	q.push(qe(9, ipB, 0))
	p, other := q.takeDrops()
	if len(p) != 2 || p[ipA].n != 3 || p[ipB].n != 1 || other.n != 0 || !p[ipA].at.Equal(fixedNow) {
		t.Fatalf("pending %+v other %+v", p, other)
	}
	if p, _ := q.takeDrops(); p != nil {
		t.Fatalf("taken twice: %+v", p)
	}
	// More senders than the table holds.
	for i := 0; i < maxPendingDrops+10; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		q.push(queued{raw: []byte("x"), from: a, at: fixedNow})
	}
	q.push(qe(0, netip.AddrFrom4([4]byte{10, 0, 0, 1}), 0)) // a sender already in the table still counts there
	p, other = q.takeDrops()
	var sum int64
	for _, d := range p {
		sum += d.n
	}
	if len(p) != maxPendingDrops || other.n != 10 || sum != maxPendingDrops+1 {
		t.Fatalf("%d senders, %d in them, %d other", len(p), sum, other.n)
	}
	if st := q.status("udp", 0, fixedNow, time.Time{}); st.Dropped != 4+maxPendingDrops+11 {
		t.Fatalf("total %d", st.Dropped)
	}
}

// The high-water mark per hour: oldest first, from Start or 24 hours back; the
// drop windows age out.
func TestQueueHighWaterByHour(t *testing.T) {
	h := &queueHist{}
	q := newUDPQueue(10, 1<<20, h)
	t0 := time.Date(2026, 11, 14, 0, 30, 0, 0, time.UTC)
	at := func(hours float64) time.Time { return t0.Add(time.Duration(hours * float64(time.Hour))) }
	pushAt := func(when time.Time, n int) {
		for i := 0; i < n; i++ {
			q.push(queued{raw: []byte("x"), from: ipA, at: when})
		}
	}
	pushAt(at(0), 3) // hour 0: 3
	popAll(t, q)
	pushAt(at(1), 7) // hour 1: 7
	popAll(t, q)
	pushAt(at(3), 12) // hour 3: 10, and 2 dropped
	st := q.status("udp", 514, at(3), t0)
	if fmt.Sprint(st.HighWaterByHour) != "[3 7 0 10]" || st.HighWater24h != 10 || st.Dropped24h != 2 || st.DroppedLastHour != 2 {
		t.Fatalf("status %+v", st)
	}
	// An hour on the queue is still full and nothing moved: the current hour
	// shows the depth.
	st = q.status("udp", 514, at(4), t0)
	if fmt.Sprint(st.HighWaterByHour) != "[3 7 0 10 10]" || st.DroppedLastHour != 0 || st.Dropped24h != 2 {
		t.Fatalf("an hour later %+v", st)
	}
	popAll(t, q)
	// A day on: 24 entries, the old hours gone.
	st = q.status("udp", 514, at(27.5), t0)
	if len(st.HighWaterByHour) != 24 || st.HighWater24h != 0 || st.Dropped24h != 0 || st.Dropped != 2 {
		t.Fatalf("a day later %+v", st)
	}
	// Started this hour: one entry.
	if st := q.status("udp", 514, at(27.7), at(27.6)); len(st.HighWaterByHour) != 1 {
		t.Fatalf("since start %+v", st.HighWaterByHour)
	}
}

// slowSink blocks while its gate is closed, like a store whose write stalls.
type slowSink struct {
	mu     sync.Mutex
	gate   chan struct{} // nil: open
	got    []string
	inside atomic.Int32
}

func (s *slowSink) sink(m model.Message) {
	s.mu.Lock()
	g := s.gate
	s.mu.Unlock()
	if g != nil {
		s.inside.Add(1)
		<-g
		s.inside.Add(-1)
	}
	s.mu.Lock()
	s.got = append(s.got, string(m.Raw))
	s.mu.Unlock()
}

func (s *slowSink) stall() {
	s.mu.Lock()
	s.gate = make(chan struct{})
	s.mu.Unlock()
}

func (s *slowSink) resume() {
	s.mu.Lock()
	if s.gate != nil {
		close(s.gate)
		s.gate = nil
	}
	s.mu.Unlock()
}

func (s *slowSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

type dropRec struct {
	mu sync.Mutex
	n  map[netip.Addr]int64
}

func (d *dropRec) add(from netip.Addr, _ time.Time, n int64) {
	d.mu.Lock()
	if d.n == nil {
		d.n = map[netip.Addr]int64{}
	}
	d.n[from] += n
	d.mu.Unlock()
}

func (d *dropRec) total() int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	var s int64
	for _, v := range d.n {
		s += v
	}
	return s
}

// stallOn stalls the sink on one message, so everything after it waits in the
// queue (the drainer holds only that one).
func stallOn(t *testing.T, ss *slowSink, conn net.Conn) {
	t.Helper()
	ss.stall()
	conn.Write([]byte("<13>m0"))
	waitFor(t, "the drainer to block", func() bool { return ss.inside.Load() == 1 })
}

// startQueued starts a UDP-only server with a slow sink, a queue of maxMsgs
// and a drop recorder.
func startQueued(t *testing.T, maxMsgs int, drain time.Duration) (*Server, *slowSink, *dropRec, net.Conn) {
	t.Helper()
	ss := &slowSink{}
	dr := &dropRec{}
	cfg := config.Listeners{UDP: config.Listener{Enabled: true, Addr: "127.0.0.1"}, UDPQueueMessages: maxMsgs}
	s, err := Start(cfg, Options{Sink: ss.sink, Logger: quiet, OnQueueDrop: dr.add, DrainTimeout: drain,
		Holder: func(string, int) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.resume(); s.Close() })
	conn, err := net.Dial("udp", udpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return s, ss, dr, conn
}

// While the sink is stalled, the reader keeps reading into the queue; once it
// resumes, every message comes out in order. Past capacity, drops are counted
// for the sender, exactly.
func TestStalledSinkQueuesThenDrops(t *testing.T) {
	s, ss, dr, conn := startQueued(t, 1000, time.Second)
	stallOn(t, ss, conn)
	const n = 1500
	for i := 1; i <= n; i++ {
		fmt.Fprintf(conn, "<13>m%d", i)
		if i%100 == 0 {
			time.Sleep(time.Millisecond) // a steady rate; loopback never drops this little
		}
	}
	// m0 is in the sink, 1000 queued, the rest dropped.
	waitFor(t, "the reader to read them all", func() bool {
		st := s.Status().UDPQueues[0]
		return int64(st.Depth)+st.Dropped == n
	})
	st := s.Status().UDPQueues[0]
	if st.Depth != 1000 || st.Dropped != n-1000 || st.HighWater24h != 1000 || st.LastFullBy != FullByMessages {
		t.Fatalf("queue %+v", st)
	}
	if dr.total() != 0 {
		t.Fatal("drops reported while the drainer is stalled") // they wait for the sink
	}
	ss.resume()
	waitFor(t, "the drain", func() bool { return ss.count() == 1001 })
	waitFor(t, "the drop report", func() bool { return dr.total() == n-1000 })
	ss.mu.Lock()
	for i, m := range ss.got {
		if m != fmt.Sprintf("<13>m%d", i) {
			t.Fatalf("message %d is %q", i, m)
		}
	}
	ss.mu.Unlock()
	if got := dr.n[netip.MustParseAddr("127.0.0.1")]; got != n-1000 {
		t.Fatalf("drops for 127.0.0.1: %d", got)
	}
	if st := s.Status(); st.Received != 1001 || st.UDPQueues[0].Depth != 0 {
		t.Fatalf("status %+v", st)
	}
}

// Close drains what's queued into the sink before it returns, and returns at
// once when the queue is empty.
func TestCloseDrainsQueue(t *testing.T) {
	s, ss, dr, conn := startQueued(t, 10000, 5*time.Second)
	stallOn(t, ss, conn)
	for i := 1; i < 500; i++ {
		fmt.Fprintf(conn, "<13>m%d", i)
	}
	waitFor(t, "500 read", func() bool { st := s.Status(); return st.UDPQueues[0].Depth == 499 })
	go func() { time.Sleep(100 * time.Millisecond); ss.resume() }()
	t0 := time.Now()
	s.Close()
	if ss.count() != 500 || dr.total() != 0 {
		t.Fatalf("after Close: %d delivered, %d dropped", ss.count(), dr.total())
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Errorf("Close took %v", d)
	}
	// Empty: prompt.
	s2, _, _, _ := startQueued(t, 10000, 5*time.Second)
	t0 = time.Now()
	s2.Close()
	if d := time.Since(t0); d > 500*time.Millisecond {
		t.Errorf("Close of an idle listener took %v", d)
	}
}

// If the sink stays stuck past the drain timeout, Close counts what's still
// queued as dropped (none lost uncounted) and returns once the message in the
// sink is done.
func TestCloseGivesUpDraining(t *testing.T) {
	s, ss, dr, conn := startQueued(t, 10000, 200*time.Millisecond)
	stallOn(t, ss, conn)
	for i := 1; i < 300; i++ {
		fmt.Fprintf(conn, "<13>m%d", i)
	}
	waitFor(t, "300 read", func() bool { return s.Status().UDPQueues[0].Depth == 299 })
	go func() { time.Sleep(time.Second); ss.resume() }()
	t0 := time.Now()
	s.Close()
	d := time.Since(t0)
	if ss.count() != 1 || dr.total() != 299 {
		t.Fatalf("after Close: %d delivered, %d dropped", ss.count(), dr.total())
	}
	if d < 900*time.Millisecond || d > 3*time.Second {
		t.Errorf("Close took %v (it must wait for the sink call in progress)", d)
	}
	if st := s.Status().UDPQueues[0]; st.Dropped != 299 || st.Depth != 0 {
		t.Fatalf("queue %+v", st)
	}
	if ss.inside.Load() != 0 {
		t.Fatal("a sink call outlived Close")
	}
}

// A rebind (a changed UDP setting) keeps the queue's history; the limits apply
// live; and the queue is reported while the listener is down.
func TestQueueAcrossReconfigure(t *testing.T) {
	s, ss, _, conn := startQueued(t, 1000, time.Second)
	stallOn(t, ss, conn)
	for i := 1; i < 1200; i++ {
		fmt.Fprintf(conn, "<13>m%d", i)
		if i%100 == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	waitFor(t, "1200 read", func() bool { st := s.Status().UDPQueues[0]; return int64(st.Depth)+st.Dropped == 1199 })
	ss.resume()
	waitFor(t, "the drain", func() bool { return ss.count() == 1001 })

	cfg := config.Listeners{UDP: config.Listener{Enabled: true, Addr: "127.0.0.1"}, UDPQueueMessages: 5000, UDPQueueBytes: 2 << 20}
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	st := s.Status().UDPQueues[0]
	if st.CapacityMessages != 5000 || st.CapacityBytes != 2<<20 || st.Dropped != 199 || st.HighWater24h != 1000 {
		t.Fatalf("after the limits changed %+v", st)
	}
	port, release := occupy(t, "udp")
	release()
	cfg.UDP.Port = port // rebinds
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	if st := s.Status().UDPQueues; len(st) != 1 || st[0].Dropped != 199 || st[0].HighWater24h != 1000 || st[0].Port == 0 {
		t.Fatalf("after the rebind %+v", st)
	}
	cfg.UDP.Enabled = false
	s.Reconfigure(cfg)
	if st := s.Status().UDPQueues; len(st) != 0 {
		t.Fatalf("disabled UDP still has a queue: %+v", st)
	}
}

// A UDP listener that never bound still reports its (empty) queue.
func TestQueueStatusWhileDown(t *testing.T) {
	port, release := occupy(t, "udp")
	defer release()
	cfg := config.Listeners{UDP: config.Listener{Enabled: true, Addr: "127.0.0.1", Port: port}}
	s, _, _ := start(t, cfg, nil)
	st := s.Status()
	if len(st.UDPQueues) != 1 || st.UDPQueues[0].Port != 0 || st.UDPQueues[0].CapacityMessages != config.DefaultUDPQueueMessages ||
		st.UDPQueues[0].CapacityBytes != config.DefaultUDPQueueBytes || len(st.UDPQueues[0].HighWaterByHour) != 1 {
		t.Fatalf("status %+v", st.UDPQueues)
	}
}
