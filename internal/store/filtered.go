package store

import (
	"cmp"
	"math"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
)

// The severity filter's counts (SPEC §13.10 decision 86). The listeners leave
// out the syslog messages less severe than the filter keeps before copying
// them, and count each here: per sender, minute and severity, into the
// device's stats (index.Counts.Filtered) on the next maintenance pass, like
// its stored messages. They're never drops.

// filtShards spreads the pending counts over a few locks, so the UDP reader
// and the TCP connections' goroutines rarely meet on one.
const filtShards = 16

// maxFiltPending caps the pending (sender, minute) entries per shard between
// two maintenance passes for senders that aren't devices yet; beyond it (a
// flood of spoofed senders) their counts go to index.RefusedDeviceID, so the
// total stays exact and memory bounded. Devices the store knows are always
// counted under their own ID (their number is bounded by the device cap).
const maxFiltPending = 4096

type filtKey struct {
	addr   netip.Addr
	minute int64 // unix minute
}

type filtAcc struct {
	n           index.SevCounts
	first, last int64 // unix ms
}

func (a *filtAcc) add(ms int64, sev int) {
	if a.n.Total() == 0 || ms < a.first {
		a.first = ms
	}
	if ms > a.last {
		a.last = ms
	}
	a.n[sev]++
}

type filtShard struct {
	mu    sync.Mutex
	m     map[filtKey]*filtAcc
	other map[int64]*filtAcc // over maxFiltPending, by minute
	_     [64]byte           // keep shards on their own cache lines
}

type filtTable struct {
	shards [filtShards]filtShard
}

// Filtered counts one syslog message from from, received at at, of severity
// sev (0-7), that the severity filter left out. It's the listeners' hot path
// (listen.Options.OnFiltered): a lock held for a map update, nothing else; the
// device's stats get it on the next maintenance pass.
func (s *Store) Filtered(from netip.Addr, at time.Time, sev int) {
	if sev < 0 || sev > 7 || s.closed.Load() {
		return
	}
	if at.IsZero() {
		at = s.clock()
	}
	ms := at.UnixMilli()
	from = from.Unmap()
	k := filtKey{from, ms / 60000}
	sh := &s.filt.shards[from.As16()[15]%filtShards]
	sh.mu.Lock()
	a := sh.m[k]
	if a == nil {
		if !from.IsValid() || (len(sh.m) >= maxFiltPending && !s.knownSender(from)) {
			if sh.other == nil {
				sh.other = map[int64]*filtAcc{}
			}
			if a = sh.other[k.minute]; a == nil {
				a = &filtAcc{}
				sh.other[k.minute] = a
			}
		} else {
			if sh.m == nil {
				sh.m = map[filtKey]*filtAcc{}
			}
			a = &filtAcc{}
			sh.m[k] = a
		}
	}
	a.add(ms, sev)
	sh.mu.Unlock()
	s.filtered.Add(1)
}

// knownSender reports whether from is a device the store knows (resident, or
// with logs or messages since Open), for the overflow rule above. Only a new
// key in a full shard asks, and it takes no lock: the UDP reader calls it
// with a shard locked, during exactly the flood of new senders in which
// admissions hold devMu (two sync.Map reads).
func (s *Store) knownSender(from netip.Addr) bool {
	if _, ok := s.devices.Load(streamKey{from, 0}); ok {
		return true
	}
	_, ok := s.knownIDs.Load(model.DeviceID(from))
	return ok
}

// collectFiltered moves the pending filtered counts into each sender's
// device stats. The device is found or admitted as for Write (a filtered
// message is a message the device sent: it counts as heard, for last_heard
// and the device cap); a sender that isn't admitted, and the overflow, count
// under index.RefusedDeviceID. The maintenance loop and Close call it, never
// the listeners.
func (s *Store) collectFiltered() {
	var acts []index.Activity
	for i := range s.filt.shards {
		sh := &s.filt.shards[i]
		sh.mu.Lock()
		m, other := sh.m, sh.other
		sh.m, sh.other = nil, nil
		sh.mu.Unlock()
		for k, a := range m {
			id := model.DeviceID(k.addr)
			if !s.filteredInto(k, a) {
				acts = append(acts, refusedFiltered(k.minute, a))
				id = index.RefusedDeviceID
			}
			s.ftot.add(id, k.minute/60, a.n)
		}
		for min, a := range other {
			acts = append(acts, refusedFiltered(min, a))
			s.ftot.add(index.RefusedDeviceID, min/60, a.n)
		}
	}
	s.ftot.prune(s.clock())
	if len(acts) > 0 {
		s.qMu.Lock()
		s.qAct = append(s.qAct, acts...)
		s.qMu.Unlock()
	}
}

func refusedFiltered(minute int64, a *filtAcc) index.Activity {
	return index.Activity{DeviceID: index.RefusedDeviceID, Minute: time.UnixMilli(minute * 60000).UTC(), Counts: index.Counts{Filtered: a.n}}
}

// filteredInto adds a's counts to the sender's syslog stream, and reports
// whether it could (false: the sender wasn't admitted, or the store closed).
func (s *Store) filteredInto(k filtKey, a *filtAcc) bool {
	first, last := time.UnixMilli(a.first).UTC(), time.UnixMilli(a.last).UTC()
	for {
		d, err := s.deviceFor(streamKey{k.addr, 0}, true, false)
		if err != nil {
			return false
		}
		d.mu.Lock()
		if d.evicted {
			d.mu.Unlock()
			continue // evicted between the lookup and the lock: look it up again
		}
		if d.closed {
			d.mu.Unlock()
			return false
		}
		if last.After(d.lastHeard) {
			d.heardLocked(last)
		}
		acc := d.accFor(&d.act, first)
		if last.After(acc.last) {
			acc.last = last
		}
		acc.c.Filtered.Add(a.n)
		d.collectLocked()
		d.mu.Unlock()
		return true
	}
}

// ---- Running 24-hour totals ----
//
// Every reader of "left out in the last 24 hours" (the run-state file each
// second, /api/stats, the device pages) reads these, not the index: a sum
// over the hours with any (at most 25) per device that has any. They're seeded from the
// index at Open and moved on by each maintenance pass, the same counts the
// index gets, so they agree with it to the hour: the window starts at the
// hour 24 hours ago (as the index's hourly buckets do).

// filtHourSpan is the window's hours: this hour and the 24 before it.
const filtHourSpan = 25

// maxFiltTracked caps the device IDs with running totals. Only admitted
// senders get an ID, but the new-device rate admits a few hundred thousand a
// day under a sustained spoof; past the cap a new ID's counts go to
// index.RefusedDeviceID (the index still has them per device), so memory
// stays bounded (about 140 bytes an ID with one hour, 1.25 KB with all 25:
// 7 MB to 62 MB at the cap).
const maxFiltTracked = 50_000

// sevHour is one hour's counts; a device keeps only hours with any, oldest
// first, at most filtHourSpan of them. 36 bytes: uint32 counts (one device
// would need 1.2 million left-out messages a second to fill one in an hour;
// they saturate rather than wrap).
type sevHour struct {
	hour int32 // unix hour
	n    [8]uint32
}

func (e *sevHour) add(c index.SevCounts) {
	for i, v := range c {
		e.n[i] = uint32(min(int64(e.n[i])+v, math.MaxUint32))
	}
}

type filtTotals struct {
	mu  sync.Mutex
	dev map[string][]sevHour
	// lastPrune: unix minute of the last prune.
	lastPrune int64
}

func (t *filtTotals) add(id string, hour int64, c index.SevCounts) {
	if c.Total() == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.dev == nil {
		t.dev = map[string][]sevHour{}
	}
	h, ok := t.dev[id]
	if !ok && len(t.dev) >= maxFiltTracked && id != index.RefusedDeviceID {
		id = index.RefusedDeviceID
		h = t.dev[id]
	}
	hr := int32(hour)
	switch n := len(h); {
	case n > 0 && h[n-1].hour == hr:
		h[n-1].add(c)
	case n == 0 || h[n-1].hour < hr:
		h = append(h, sevHour{hour: hr})
		h[len(h)-1].add(c)
	default: // an older hour (the seed): keep the order
		k, found := slices.BinarySearchFunc(h, hr, func(e sevHour, x int32) int { return cmp.Compare(e.hour, x) })
		if !found {
			h = slices.Insert(h, k, sevHour{hour: hr})
		}
		h[k].add(c)
	}
	// Hours before the newest's window can't be read again.
	k := 0
	for k < len(h) && h[k].hour <= h[len(h)-1].hour-filtHourSpan {
		k++
	}
	if k > 0 {
		h = slices.Delete(h, 0, k)
	}
	t.dev[id] = h
}

// sumHours is h's total over the window ending in hour now.
func sumHours(h []sevHour, now int64) (c index.SevCounts) {
	for _, e := range h {
		if d := now - int64(e.hour); d >= 0 && d < filtHourSpan {
			for i, v := range e.n {
				c[i] += int64(v)
			}
		}
	}
	return c
}

// prune drops devices with nothing in the window, at most once a minute.
func (t *filtTotals) prune(now time.Time) {
	min, hr := now.Unix()/60, now.Unix()/3600
	t.mu.Lock()
	defer t.mu.Unlock()
	if min == t.lastPrune {
		return
	}
	t.lastPrune = min
	for id, h := range t.dev {
		if sumHours(h, hr).Total() == 0 {
			delete(t.dev, id)
		}
	}
}

// seedFiltered loads the last 24 hours' filtered counts from the index (at
// Open, before any maintenance pass adds to them).
func (s *Store) seedFiltered() error {
	now := s.clock()
	by, err := s.idx.FilteredByHour(s.ctx, now.Add(-(filtHourSpan-1)*time.Hour))
	if err != nil {
		return err
	}
	for id, hours := range by {
		for h, c := range hours {
			s.ftot.add(id, h, c)
		}
	}
	return nil
}

// Filtered24h returns the severity filter's left-out counts over the last 24
// hours (from the hour 24 hours ago), per device ID, from memory: ids nil is
// every device with any (index.RefusedDeviceID included), otherwise only those
// asked for that have any. Counts reach it with the maintenance pass that
// writes them to the index.
func (s *Store) Filtered24h(ids []string) map[string]index.SevCounts {
	hr := s.clock().Unix() / 3600
	out := map[string]index.SevCounts{}
	s.ftot.mu.Lock()
	defer s.ftot.mu.Unlock()
	if ids == nil {
		for id, h := range s.ftot.dev {
			if c := sumHours(h, hr); c.Total() > 0 {
				out[id] = c
			}
		}
		return out
	}
	for _, id := range ids {
		if h := s.ftot.dev[id]; h != nil {
			if c := sumHours(h, hr); c.Total() > 0 {
				out[id] = c
			}
		}
	}
	return out
}
