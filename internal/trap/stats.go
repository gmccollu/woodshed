package trap

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// The receiver's counts (GET /api/snmp counts_24h), the failing senders (GET
// /api/snmp/failures) and the reply limits (SPEC §11.2.3).

// hourly keeps 24 hourly buckets of one counter.
type hourly struct {
	n     [24]int64
	stamp [24]int64
}

func (h *hourly) add(at time.Time, n int64) {
	hr := at.Unix() / 3600
	i := int(hr % 24)
	if h.stamp[i] != hr {
		h.stamp[i], h.n[i] = hr, 0
	}
	h.n[i] += n
}

func (h *hourly) sum(now time.Time) int64 {
	hr := now.Unix() / 3600
	var t int64
	for i := range h.n {
		if d := hr - h.stamp[i]; d >= 0 && d < 24 {
			t += h.n[i]
		}
	}
	return t
}

// counts are the last 24 hours' receiver counts.
type counts struct {
	mu                                                       sync.Mutex
	received, answered, limited, discovery, resyncs, refused hourly
	byStatus                                                 [16]hourly
}

func (c *counts) addStatus(at time.Time, st snmp.Status) {
	c.mu.Lock()
	c.received.add(at, 1)
	if int(st) < len(c.byStatus) {
		c.byStatus[st].add(at, 1)
	}
	c.mu.Unlock()
}

func (c *counts) inc(h *hourly, at time.Time) {
	c.mu.Lock()
	h.add(at, 1)
	c.mu.Unlock()
}

func (c *counts) snapshot(now time.Time) api.SNMPCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := api.SNMPCounts{Received: c.received.sum(now), InformsAnswered: c.answered.sum(now), RepliesRateLimited: c.limited.sum(now),
		DiscoveryReports: c.discovery.sum(now), TimeResyncs: c.resyncs.sum(now), ByStatus: map[string]int64{}}
	for i, name := range snmp.Statuses() {
		if n := c.byStatus[i].sum(now); n > 0 {
			out.ByStatus[name] = n
		}
	}
	return out
}

// MaxFailureSenders is how many senders the failure list tracks (docs/api.md).
const MaxFailureSenders = 10000

type failure struct {
	n, resyncs hourly
	last       time.Time
	status     string
	detail     string
}

// failures are the senders whose v3 traps failed or whose packets were
// malformed, and the v3 clock relearns (SPEC §11.8 #28), per sender.
type failures struct {
	mu sync.Mutex
	m  map[netip.Addr]*failure
}

func (f *failures) get(a netip.Addr, at time.Time) *failure {
	x := f.m[a]
	if x == nil {
		if len(f.m) >= MaxFailureSenders {
			var old netip.Addr
			var ot time.Time
			for k, v := range f.m {
				if ot.IsZero() || v.last.Before(ot) {
					old, ot = k, v.last
				}
			}
			delete(f.m, old)
		}
		x = &failure{}
		f.m[a] = x
	}
	if at.After(x.last) {
		x.last = at
	}
	return x
}

func (f *failures) add(a netip.Addr, at time.Time, status, detail string) {
	f.mu.Lock()
	x := f.get(a, at)
	x.n.add(at, 1)
	x.status, x.detail = status, detail
	f.mu.Unlock()
}

func (f *failures) resync(a netip.Addr, at time.Time) {
	f.mu.Lock()
	f.get(a, at).resyncs.add(at, 1)
	f.mu.Unlock()
}

func (f *failures) list(now time.Time) []api.SNMPFailure {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []api.SNMPFailure
	for a, x := range f.m {
		n, r := x.n.sum(now), x.resyncs.sum(now)
		if n == 0 && r == 0 {
			continue
		}
		st := x.status
		if n == 0 {
			st = "not_in_time"
		}
		out = append(out, api.SNMPFailure{IP: a.String(), Count24h: n, LastSeen: x.last.UTC(), Status: st, Detail: x.detail,
			DeviceID: model.DeviceID(a), TimeResyncs24h: r})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count24h != out[j].Count24h {
			return out[i].Count24h > out[j].Count24h
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// Reply limits (SPEC §11.2.3): 100 a second per source address, 1,000 a
// second in all.
const (
	ReplyPerSource = 100
	ReplyTotal     = 1000
	maxLimiters    = 10000
)

type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) take(now time.Time, rate float64) bool {
	if b.at.IsZero() {
		b.tokens = rate
	} else if now.After(b.at) {
		b.tokens = min(rate, b.tokens+now.Sub(b.at).Seconds()*rate)
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type limiter struct {
	mu        sync.Mutex
	total     bucket
	per       map[netip.Addr]*bucket
	perSource float64 // replies a second per source (ReplyPerSource)
	all       float64 // in all (ReplyTotal)
}

// allow takes a token for one reply to a, from a's bucket and the total.
func (l *limiter) allow(a netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.per[a]
	if b == nil {
		if len(l.per) >= maxLimiters {
			for k, v := range l.per {
				if now.Sub(v.at) > time.Second {
					delete(l.per, k)
				}
			}
			if len(l.per) >= maxLimiters {
				return false // a spoofed flood of sources: the limit holds
			}
		}
		b = &bucket{}
		l.per[a] = b
	}
	// Peek the total first so a refused reply costs the source nothing.
	t := l.total
	if !t.take(now, l.all) {
		l.total = t
		return false
	}
	if !b.take(now, l.perSource) {
		return false
	}
	l.total = t
	return true
}

// dedup remembers informs for 60 s, to mark a retransmission dup=1 (SPEC
// §11.2.3: the same source, engine and request ID).
type dedup struct {
	mu   sync.Mutex
	seen map[string]time.Time
	last time.Time // last sweep
}

const (
	dupWindow = 60 * time.Second
	maxDedup  = 200000
)

func (d *dedup) check(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Sub(d.last) > dupWindow || len(d.seen) >= maxDedup {
		for k, t := range d.seen {
			if now.Sub(t) > dupWindow {
				delete(d.seen, k)
			}
		}
		d.last = now
		if len(d.seen) >= maxDedup {
			clear(d.seen) // a flood of distinct informs: forget, never grow
		}
	}
	t, ok := d.seen[key]
	d.seen[key] = now
	return ok && now.Sub(t) <= dupWindow
}
