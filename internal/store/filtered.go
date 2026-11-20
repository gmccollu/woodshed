package store

import (
	"net/netip"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
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
// two maintenance passes; beyond it (a flood of spoofed senders) the counts
// go to index.RefusedDeviceID, so the total stays exact and memory bounded.
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
		if len(sh.m) >= maxFiltPending || !from.IsValid() {
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
			if !s.filteredInto(k, a) {
				acts = append(acts, refusedFiltered(k.minute, a))
			}
		}
		for min, a := range other {
			acts = append(acts, refusedFiltered(min, a))
		}
	}
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
		d, err := s.device(streamKey{k.addr, 0}, true)
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
