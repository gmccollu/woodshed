package listen

import (
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
)

// The UDP receive queue (SPEC §11.5). Each UDP socket has one: its reader only
// reads a datagram, stamps it, applies the blocklist and allowlist and pushes
// it here; one drainer goroutine pops it, parses it and calls the sink in
// arrival order. A store that stalls (an fsync, a rotation, a gzip pass, the
// hourly roll-up) then stalls only the drainer, and the queue absorbs it. When
// the queue is full a datagram is dropped at once and counted for its sender
// (reason queue_full), so a stall caused by Woodshed is never a silent kernel
// drop.

// queued is one datagram waiting for the drainer.
type queued struct {
	raw       []byte // owned: becomes the message's Raw
	from      netip.Addr
	at        time.Time // when the reader read it (the message's Received time)
	truncated bool      // raw was cut at the max message size
}

// queueChunk is a fixed block of the FIFO, so memory follows the depth: a
// drained queue holds one spare chunk, not its high-water mark.
const queueChunk = 1024

type chunk struct {
	e    [queueChunk]queued
	next *chunk
}

// drainBatch is how many messages the drainer takes per lock.
const drainBatch = 256

// maxPendingDrops bounds the per-sender drop counts waiting for the drainer to
// report (a spoofed flood can't grow it). Beyond it, drops are reported without
// a sender (Options.OnQueueDrop with an invalid address), so totals stay exact.
const maxPendingDrops = 65536

// Full reasons, for the banner's advice.
const (
	FullByMessages = "messages"
	FullByBytes    = "bytes"
)

type pendingDrop struct {
	n  int64
	at time.Time // the latest
}

// udpQueue is a bounded FIFO between one reader and one drainer.
type udpQueue struct {
	mu       sync.Mutex
	maxMsgs  int
	maxBytes int64
	head     *chunk // pop from head at hi
	tail     *chunk // push to tail at ti
	hi, ti   int
	spare    *chunk
	n        int
	bytes    int64
	waiting  bool // the drainer is waiting on wake
	closed   bool
	wake     chan struct{}
	hist     *queueHist // survives rebinds (the Server keeps it per listener)

	pend      map[netip.Addr]pendingDrop // drops not yet reported to OnQueueDrop
	pendOther pendingDrop                // past maxPendingDrops senders
	pendN     atomic.Int64               // drops in pend and pendOther, read without the lock

	abort atomic.Bool // shutdown gave up draining: count what's left as dropped
}

func newUDPQueue(maxMsgs int, maxBytes int64, hist *queueHist) *udpQueue {
	q := &udpQueue{wake: make(chan struct{}, 1), hist: hist, pend: map[netip.Addr]pendingDrop{}}
	q.setLimits(maxMsgs, maxBytes)
	return q
}

// queueLimits returns the configured limits, or the defaults for zero values.
func queueLimits(l config.Listeners) (int, int64) {
	n, b := l.UDPQueueMessages, l.UDPQueueBytes
	if n <= 0 {
		n = config.DefaultUDPQueueMessages
	}
	if b <= 0 {
		b = config.DefaultUDPQueueBytes
	}
	return n, b
}

// setLimits changes the capacity. Lowering it below the depth drops nothing:
// new messages are refused until the queue drains below it.
func (q *udpQueue) setLimits(maxMsgs int, maxBytes int64) {
	q.mu.Lock()
	q.maxMsgs, q.maxBytes = maxMsgs, maxBytes
	q.mu.Unlock()
}

// push adds e, or counts it as dropped when the queue is full. It never
// blocks on the drainer.
func (q *udpQueue) push(e queued) bool {
	sz := int64(len(e.raw))
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return false
	}
	full := ""
	switch {
	case q.n >= q.maxMsgs:
		full = FullByMessages
	case q.bytes+sz > q.maxBytes:
		full = FullByBytes
	}
	if full != "" {
		q.dropLocked(e.from, e.at, 1)
		q.hist.lastFullBy = full
		q.mu.Unlock()
		return false
	}
	if q.tail == nil || q.ti == queueChunk {
		c := q.spare
		if c != nil {
			q.spare = nil
		} else {
			c = new(chunk)
		}
		if q.tail == nil {
			q.head, q.hi = c, 0
		} else {
			q.tail.next = c
		}
		q.tail, q.ti = c, 0
	}
	q.tail.e[q.ti] = e
	q.ti++
	q.n++
	q.bytes += sz
	q.hist.depth(e.at, q.n)
	if q.waiting {
		q.waiting = false
		select {
		case q.wake <- struct{}{}:
		default:
		}
	}
	q.mu.Unlock()
	return true
}

// pop appends up to max messages, oldest first, to dst. It waits while the
// queue is empty, and returns false once the queue is closed and empty.
func (q *udpQueue) pop(dst []queued, max int) ([]queued, bool) {
	q.mu.Lock()
	for q.n == 0 {
		if q.closed {
			q.mu.Unlock()
			return dst, false
		}
		q.waiting = true
		q.mu.Unlock()
		<-q.wake
		q.mu.Lock()
	}
	for k := 0; q.n > 0 && k < max; k++ {
		e := &q.head.e[q.hi]
		dst = append(dst, *e)
		q.bytes -= int64(len(e.raw))
		*e = queued{} // let the bytes go once the sink is done with them
		q.hi++
		q.n--
		if q.hi == queueChunk || q.n == 0 {
			q.advanceLocked()
		}
	}
	q.mu.Unlock()
	return dst, true
}

// advanceLocked frees the head chunk once it's used up (or the queue is empty).
func (q *udpQueue) advanceLocked() {
	if q.n == 0 {
		// Empty: reuse the chunk from its start.
		if q.head != q.tail {
			q.spare = q.head
			q.spare.next = nil
		}
		q.head, q.hi, q.ti = q.tail, 0, 0
		return
	}
	old := q.head
	q.head, q.hi = old.next, 0
	old.next = nil
	q.spare = old
}

// close stops further pushes and wakes the drainer, which empties the queue
// and then ends.
func (q *udpQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.waiting = false
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// abandon is shutdown giving up on the drain: every message still queued is
// counted as dropped (queue_full: the queue couldn't hand it to the disk in
// time), and the drainer stops after the message it's delivering.
func (q *udpQueue) abandon() {
	q.abort.Store(true)
	q.mu.Lock()
	for q.n > 0 {
		e := &q.head.e[q.hi]
		q.dropLocked(e.from, e.at, 1)
		q.bytes -= int64(len(e.raw))
		*e = queued{}
		q.hi++
		q.n--
		if q.hi == queueChunk || q.n == 0 {
			q.advanceLocked()
		}
	}
	q.mu.Unlock()
}

// dropBatch counts messages the drainer popped but won't deliver (abandon).
func (q *udpQueue) dropBatch(es []queued) {
	q.mu.Lock()
	for i := range es {
		q.dropLocked(es[i].from, es[i].at, 1)
		es[i] = queued{}
	}
	q.mu.Unlock()
}

func (q *udpQueue) dropLocked(from netip.Addr, at time.Time, n int64) {
	q.hist.drop(at, n)
	if p, ok := q.pend[from]; ok || len(q.pend) < maxPendingDrops {
		p.n += n
		if at.After(p.at) {
			p.at = at
		}
		q.pend[from] = p
	} else {
		q.pendOther.n += n
		if at.After(q.pendOther.at) {
			q.pendOther.at = at
		}
	}
	q.pendN.Add(n)
}

// takeDrops returns the drops not yet reported and forgets them.
func (q *udpQueue) takeDrops() (map[netip.Addr]pendingDrop, pendingDrop) {
	if q.pendN.Load() == 0 {
		return nil, pendingDrop{}
	}
	q.mu.Lock()
	p, o := q.pend, q.pendOther
	q.pend, q.pendOther = make(map[netip.Addr]pendingDrop, min(len(p), 64)), pendingDrop{}
	q.pendN.Store(0)
	q.mu.Unlock()
	return p, o
}

// QueueStatus is one UDP listener's queue, for /api/stats udp_queue.
type QueueStatus struct {
	Listener         string // "udp" (syslog), later "snmp"
	Port             int    // the bound port (0 while the listener is down)
	CapacityMessages int
	CapacityBytes    int64
	Depth            int    // messages waiting now
	DepthBytes       int64  // and their bytes
	HighWater24h     int    // the most messages waiting at once in the last 24 hours
	HighWaterByHour  []int  // per hour, oldest first, from the later of 24 hours ago and Start; the last is the current hour
	Dropped24h       int64  // dropped because the queue was full, last 24 hours
	DroppedLastHour  int64  // the last 60 minutes (the udp_queue_full banner)
	Dropped          int64  // since Start
	LastFullBy       string // FullByMessages or FullByBytes: which limit refused the latest drop ("" if none)
	LastDrop         *time.Time
}

func (q *udpQueue) status(name string, port int, now time.Time, since time.Time) QueueStatus {
	q.mu.Lock()
	defer q.mu.Unlock()
	st := q.hist.status(now, since, q.n)
	st.Listener, st.Port = name, port
	st.CapacityMessages, st.CapacityBytes = q.maxMsgs, q.maxBytes
	st.Depth, st.DepthBytes = q.n, q.bytes
	return st
}

// queueHist is a listener's queue history: the hourly high-water mark and the
// drop counts. The Server keeps one per UDP listener so a rebind keeps it; it's
// guarded by the lock of the queue that holds it.
type queueHist struct {
	hw         [24]struct{ hour, max int64 }
	drops      hours
	minutes    [60]struct{ min, n int64 }
	total      int64
	lastFullBy string
	lastDrop   time.Time
}

func (h *queueHist) depth(at time.Time, n int) {
	hr := hourOf(at)
	b := &h.hw[hr%24]
	if b.hour != hr {
		b.hour, b.max = hr, 0
	}
	if int64(n) > b.max {
		b.max = int64(n)
	}
}

func (h *queueHist) drop(at time.Time, n int64) {
	h.drops.add(at, n)
	m := at.Unix() / 60
	b := &h.minutes[m%60]
	if b.min != m {
		b.min, b.n = m, 0
	}
	b.n += n
	h.total += n
	if at.After(h.lastDrop) {
		h.lastDrop = at
	}
}

func (h *queueHist) status(now, since time.Time, depth int) QueueStatus {
	st := QueueStatus{Dropped24h: h.drops.sum(now), Dropped: h.total, LastFullBy: h.lastFullBy}
	nowH := hourOf(now)
	first := nowH - 23
	if s := hourOf(since); !since.IsZero() && s > first {
		first = s
	}
	if first > nowH {
		first = nowH
	}
	for hr := first; hr <= nowH; hr++ {
		v := 0
		if b := h.hw[hr%24]; b.hour == hr {
			v = int(b.max)
		}
		if hr == nowH && depth > v {
			v = depth
		}
		st.HighWaterByHour = append(st.HighWaterByHour, v)
		st.HighWater24h = max(st.HighWater24h, v)
	}
	m := now.Unix() / 60
	for _, b := range h.minutes {
		if d := m - b.min; d >= 0 && d < 60 {
			st.DroppedLastHour += b.n
		}
	}
	if !h.lastDrop.IsZero() {
		t := h.lastDrop.UTC()
		st.LastDrop = &t
	}
	return st
}
