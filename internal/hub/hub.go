// Package hub is Woodshed's live tail (SPEC §3.6): an in-memory ring buffer of the
// most recent messages, and subscribers with server-side filters that receive new
// messages as they arrive, sampled down to about 50 a second each. ServeSSE serves
// /api/live (docs/api.md) on top of it.
//
// Publishing never blocks on a subscriber: one that falls behind loses messages
// (counted), and ingest carries on.
package hub

import (
	"math"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
)

// Defaults for Options.
const (
	DefaultRingSize  = 5000
	DefaultRingBytes = 64 << 20
	DefaultRate      = 50
	DefaultReplay    = 200
	DefaultBuffer    = 256
	DefaultHeartbeat = 15 * time.Second
)

// rateWindow is the number of whole seconds Rate averages over.
const rateWindow = 5

// Options configures a Hub. Zero fields take the defaults.
type Options struct {
	RingSize  int // messages kept for replay (default 5,000)
	RingBytes int // and at most this many raw bytes (default 64 MiB), so 5,000 64 KiB messages can't take 320 MiB
	Rate      int // messages per second per subscriber before sampling (default 50)
	Replay    int // matching messages replayed on subscribe (default 200)
	Buffer    int // per-subscriber queue; when full, messages are dropped for that subscriber (default 256)
	Heartbeat time.Duration

	// GroupOf returns a device's group ("" for none), for the group and ungrouped
	// filters. It's called while the hub's lock is held, at most once per published
	// message, so it must be fast (a map lookup) and must not call the Hub. Nil
	// means every device is ungrouped.
	GroupOf func(deviceID string) string
	// HiddenOf reports whether a device is hidden: a hidden device's messages
	// reach only subscribers that name it in Filter.Devices (docs/api.md, the
	// same rule as search). Same constraints as GroupOf; it's read per message,
	// so un-hiding takes effect without resubscribing. Nil means none is hidden.
	HiddenOf func(deviceID string) bool
	// Clock is the time source for sampling and the rate (default time.Now).
	Clock func() time.Time
}

// Entry is one message as the live tail sees it. Its JSON form is the data of a
// "message" event.
type Entry struct {
	Received time.Time
	DeviceID string
	Severity int // 0-7, or model.Unknown
	Raw      []byte
	// The message's marks (2.0), as on its stored line (model.Message).
	Truncated, Incomplete     bool
	FrameArrived, FrameLength int64
}

// Notice is the data of a "sampled" event: the subscriber's matching rate and how
// many of those messages it was sent in the last window.
type Notice struct {
	Rate  float64 `json:"rate"`
	Shown int     `json:"shown"`
}

// Item is what a subscription receives: an Entry or a Notice.
type Item struct {
	Entry   *Entry
	Sampled *Notice
}

// Stats are the hub's counters.
type Stats struct {
	Published   int64   // messages published since New
	Subscribers int     // open subscriptions
	Dropped     int64   // messages dropped for slow subscribers, all subscribers
	Rate        float64 // ingest messages/s (see Hub.Rate)
}

// Hub fans published messages out to subscribers. It is safe for concurrent use.
type Hub struct {
	opts Options

	mu        sync.Mutex
	ring      []Entry
	head      int // index of the oldest entry
	n         int // entries in the ring
	bytes     int
	subs      map[*Subscription]struct{}
	closed    bool
	published int64
	dropped   int64

	// ingest rate: per-second counts
	secs    [rateWindow + 2]int64
	secAt   [rateWindow + 2]int64 // Unix second each slot holds
	startAt int64
}

// New returns a Hub.
func New(opts Options) *Hub {
	if opts.RingSize <= 0 {
		opts.RingSize = DefaultRingSize
	}
	if opts.RingBytes <= 0 {
		opts.RingBytes = DefaultRingBytes
	}
	if opts.Rate <= 0 {
		opts.Rate = DefaultRate
	}
	if opts.Replay <= 0 {
		opts.Replay = DefaultReplay
	}
	if opts.Buffer <= 0 {
		opts.Buffer = DefaultBuffer
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = DefaultHeartbeat
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.GroupOf == nil {
		opts.GroupOf = func(string) string { return "" }
	}
	if opts.HiddenOf == nil {
		opts.HiddenOf = func(string) bool { return false }
	}
	return &Hub{
		opts:    opts,
		ring:    make([]Entry, opts.RingSize),
		subs:    map[*Subscription]struct{}{},
		startAt: opts.Clock().Unix(),
	}
}

// Publish adds a message to the ring and offers it to every subscriber. It keeps
// m.Raw (the caller must not modify it afterwards) and never blocks on a
// subscriber. It's the hub's Sink.
func (h *Hub) Publish(m model.Message) {
	e := Entry{Received: m.Received.UTC(), DeviceID: model.DeviceID(m.Sender), Severity: m.Severity, Raw: m.Raw,
		Truncated: m.Truncated, Incomplete: m.Incomplete, FrameArrived: m.FrameArrived, FrameLength: m.FrameLength}
	now := h.opts.Clock()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.published++
	h.countSecond(now.Unix())
	h.push(e)
	if len(h.subs) == 0 {
		return
	}
	g := groupLookup{f: h.opts.GroupOf, hf: h.opts.HiddenOf, id: e.DeviceID}
	ep := &e // shared by every subscriber, never modified (ring slots are reused)
	for s := range h.subs {
		if s.filter.match(ep, &g) {
			h.offer(s, ep, now)
		}
	}
}

// push appends e, evicting the oldest entries to stay within RingSize and RingBytes.
func (h *Hub) push(e Entry) {
	for h.n > 0 && (h.n == len(h.ring) || h.bytes+len(e.Raw) > h.opts.RingBytes) {
		h.bytes -= len(h.ring[h.head].Raw)
		h.ring[h.head] = Entry{}
		h.head = (h.head + 1) % len(h.ring)
		h.n--
	}
	h.ring[(h.head+h.n)%len(h.ring)] = e
	h.n++
	h.bytes += len(e.Raw)
}

// offer applies s's sampling to one matching entry (h.mu held).
//
// Each subscriber has a token bucket: Rate tokens a second, holding at most Rate,
// one per message sent. Under Rate msg/s everything is sent; above it the sample is
// spread evenly over each second (at 5,000 msg/s, one message every 20 ms) instead
// of being the first lines of each second. On top of that, at most Rate messages
// go out per window of at least a second, and the bucket doesn't refill while
// that cap holds, so the start of a burst can't send 2*Rate in its first second.
// When a window in which some matches weren't sent ends, the subscriber gets a
// Notice with the matching rate and the number shown.
func (h *Hub) offer(s *Subscription, e *Entry, now time.Time) {
	rate := float64(h.opts.Rate)
	if s.winStart.IsZero() {
		s.winStart, s.last, s.tokens = now, now, rate
	} else if el := now.Sub(s.winStart); el >= time.Second {
		if s.matched > s.shown {
			r := float64(s.matched) / el.Seconds()
			s.send(h, Item{Sampled: &Notice{Rate: math.Round(r*10) / 10, Shown: s.shown}})
		}
		s.winStart, s.matched, s.shown = now, 0, 0
	}
	s.matched++
	el := now.Sub(s.last)
	s.last = now
	if s.shown >= h.opts.Rate {
		return
	}
	if el > 0 {
		s.tokens = min(rate, s.tokens+el.Seconds()*rate)
	}
	if s.tokens < 1 {
		return
	}
	if s.send(h, Item{Entry: e}) {
		s.tokens--
		s.shown++
	}
}

// Subscribe registers a subscriber. Its Replay holds up to Options.Replay of the
// newest matching messages already in the ring, oldest first; C delivers every
// later match (sampled), with nothing lost or repeated between the two. Close the
// subscription when done.
func (h *Hub) Subscribe(f Filter) *Subscription {
	cf := compile(f)
	s := &Subscription{h: h, filter: cf, ch: make(chan Item, h.opts.Buffer)}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		close(s.ch)
		s.closed = true
		return s
	}
	// Newest first, then reversed.
	var rev []Entry
	g := groupLookup{f: h.opts.GroupOf, hf: h.opts.HiddenOf}
	for i := h.n - 1; i >= 0 && len(rev) < h.opts.Replay; i-- {
		e := &h.ring[(h.head+i)%len(h.ring)]
		g.id, g.done, g.hdone = e.DeviceID, false, false
		if cf.match(e, &g) {
			rev = append(rev, *e)
		}
	}
	s.Replay = make([]Entry, len(rev))
	for i, e := range rev {
		s.Replay[len(rev)-1-i] = e
	}
	h.subs[s] = struct{}{}
	return s
}

// Rate returns the ingest rate in messages per second, averaged over the last 5
// whole seconds (fewer just after New).
func (h *Hub) Rate() float64 {
	now := h.opts.Clock().Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rateLocked(now)
}

func (h *Hub) rateLocked(now int64) float64 {
	span := int64(rateWindow)
	if d := now - h.startAt; d < span {
		span = d
	}
	if span <= 0 {
		return 0
	}
	var sum int64
	for i := range h.secs {
		if d := now - h.secAt[i]; d >= 1 && d <= span {
			sum += h.secs[i]
		}
	}
	return math.Round(float64(sum)/float64(span)*10) / 10
}

func (h *Hub) countSecond(sec int64) {
	i := int(sec % int64(len(h.secs)))
	if h.secAt[i] != sec {
		h.secAt[i], h.secs[i] = sec, 0
	}
	h.secs[i]++
}

// Stats returns the hub's counters.
func (h *Hub) Stats() Stats {
	now := h.opts.Clock().Unix()
	h.mu.Lock()
	defer h.mu.Unlock()
	return Stats{Published: h.published, Subscribers: len(h.subs), Dropped: h.dropped, Rate: h.rateLocked(now)}
}

// Close ends every subscription (their channels close, so ServeSSE streams end)
// and ignores later Publish calls.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for s := range h.subs {
		s.closeLocked()
	}
}

// Subscription is one live-tail subscriber.
type Subscription struct {
	// Replay is the backlog at subscribe time, oldest first.
	Replay []Entry

	h      *Hub
	filter *compiled
	ch     chan Item
	closed bool

	// sampling state, guarded by h.mu
	winStart time.Time // start of the current window
	matched  int       // matches in the window
	shown    int       // sent in the window
	last     time.Time // last match, for the token refill
	tokens   float64
	dropped  int64
}

// C delivers new matching messages and sampling notices. It's closed when the
// subscription or the hub is closed.
func (s *Subscription) C() <-chan Item { return s.ch }

// Dropped returns how many messages were dropped because this subscriber's queue
// was full.
func (s *Subscription) Dropped() int64 {
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	return s.dropped
}

// Close unsubscribes and closes C. It's safe to call more than once.
func (s *Subscription) Close() {
	s.h.mu.Lock()
	defer s.h.mu.Unlock()
	s.closeLocked()
}

func (s *Subscription) closeLocked() {
	if s.closed {
		return
	}
	s.closed = true
	delete(s.h.subs, s)
	close(s.ch)
}

// send queues an item without blocking, and counts a drop when the queue is full.
func (s *Subscription) send(h *Hub, it Item) bool {
	select {
	case s.ch <- it:
		return true
	default:
		if it.Entry != nil {
			s.dropped++
			h.dropped++
		}
		return false
	}
}

// groupLookup calls GroupOf and HiddenOf at most once per message each, and
// only if a filter needs them.
type groupLookup struct {
	f     func(string) string
	hf    func(string) bool
	id    string
	g     string
	done  bool
	h     bool
	hdone bool
}

func (g *groupLookup) hidden() bool {
	if !g.hdone {
		g.h, g.hdone = g.hf != nil && g.hf(g.id), true
	}
	return g.h
}

func (g *groupLookup) get() string {
	if !g.done {
		g.g, g.done = g.f(g.id), true
	}
	return g.g
}
