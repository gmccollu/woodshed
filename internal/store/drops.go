package store

import (
	"net/netip"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
)

// DropReasons counts dropped messages by why (docs/api.md, dropped_by_reason).
// They sum to every drop dropped_24h counts, except across a restart: these are
// kept in memory, the index's per-device counts aren't.
type DropReasons struct {
	Paused     int64 `json:"paused"`      // the low-disk guard had paused writing (queued UDP messages included)
	WriteError int64 `json:"write_error"` // a write to the log file failed
	Refused    int64 `json:"refused"`     // a new sender over the device cap or new-device rate
	QueueFull  int64 `json:"queue_full"`  // a UDP listener's queue was full (SPEC §11.5)
}

// reasonHours keeps the last 24 hours of drops per reason in hourly buckets.
type reasonHours struct {
	mu    sync.Mutex
	n     [24][4]int64
	stamp [24]int64 // Unix hour each bucket holds
}

func (r *reasonHours) add(at time.Time, reason dropReason, n int64) {
	hr := at.Unix() / 3600
	i := int(hr % 24)
	r.mu.Lock()
	if r.stamp[i] != hr {
		r.stamp[i], r.n[i] = hr, [4]int64{}
	}
	r.n[i][reason] += n
	r.mu.Unlock()
}

func (r *reasonHours) sum(now time.Time) DropReasons {
	hr := now.Unix() / 3600
	var t [4]int64
	r.mu.Lock()
	for i := range r.n {
		if d := hr - r.stamp[i]; d >= 0 && d < 24 {
			for k := range t {
				t[k] += r.n[i][k]
			}
		}
	}
	r.mu.Unlock()
	return DropReasons{Paused: t[dropPaused], WriteError: t[dropWriteError], Refused: t[dropRefused], QueueFull: t[dropQueueFull]}
}

// DropsByReason24h returns the last 24 hours' drops by reason, since Open.
func (s *Store) DropsByReason24h() DropReasons { return s.reasons.sum(s.clock()) }

// DropQueued counts n UDP messages from one sender, the latest received at at,
// that its listener's queue had no room for (SPEC §11.5): dropped for the
// sender's device (the stats' dropped column, so dropped_24h), with reason
// queue_full, and in the events log at most once a minute. The device is found
// or admitted as for Write, so these count where the messages would have been
// stored. A sender that isn't admitted (the device cap or new-device rate), or
// an invalid from (the listener's per-sender table was full), is counted under
// index.RefusedDeviceID, still as queue_full.
func (s *Store) DropQueued(from netip.Addr, at time.Time, n int64) {
	if n <= 0 || s.closed.Load() {
		return
	}
	if at.IsZero() {
		at = s.clock()
	}
	at = time.UnixMilli(at.UnixMilli()).UTC()
	if from.IsValid() {
		addr := from.Unmap()
		for {
			d, err := s.device(addr, true)
			if err != nil {
				break
			}
			d.mu.Lock()
			if d.evicted {
				d.mu.Unlock()
				continue // evicted between the lookup and the lock: look it up again
			}
			if !d.closed {
				d.dropLocked(at, n, dropQueueFull)
			}
			d.mu.Unlock()
			return
		}
	}
	s.dropped.Add(n)
	s.reasons.add(at, dropQueueFull, n)
	s.noteDrop("", dropQueueFull, n)
	s.qMu.Lock()
	s.qAct = append(s.qAct, index.Activity{DeviceID: index.RefusedDeviceID, Minute: at.Truncate(time.Minute),
		Counts: index.Counts{Dropped: n}})
	s.qMu.Unlock()
}
