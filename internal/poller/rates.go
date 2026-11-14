package poller

import (
	"math"
	"time"
)

// Rates and their rules (SPEC §12.2.1, §12.2.2). Everything here is a pure
// function of two samples, so FuzzRates can check it on any sequence.

// sample is a counter's previous reading.
type sample struct {
	value uint64
	at    time.Time // the response's received time (monotonic)
	ok    bool
}

// counterKind says how a counter wraps.
type counterKind uint8

const (
	counter32 counterKind = iota + 1
	counter64
)

// wrap32 is 2^32.
const wrap32 = 1 << 32

// deltaResult is what a counter did between two samples.
type deltaResult struct {
	delta   uint64
	seconds float64
	ok      bool // a valid delta (no discontinuity)
	wrapped bool // a Counter32 wrap was accepted
}

// counterDelta computes a counter's delta between prev and cur. bound is the
// largest plausible delta for a Counter32 wrap (0: at most 2^32 per interval,
// which a single wrap always is). uptimeForward says sysUpTime moved forward
// (no agent restart); disc says the interface had a discontinuity.
//
//   - A Counter64 that went down is a discontinuity (a real wrap takes years).
//   - A Counter32 that went down is a wrap only with uptime forward, no
//     discontinuity, and a plausible result; otherwise a discontinuity.
//   - No previous sample, or no time between them, is no delta.
func counterDelta(prev sample, cur uint64, at time.Time, kind counterKind, bound uint64, uptimeForward, disc bool) deltaResult {
	if !prev.ok || disc || !uptimeForward {
		return deltaResult{}
	}
	secs := at.Sub(prev.at).Seconds()
	if secs <= 0 {
		return deltaResult{}
	}
	if kind == counter32 && (cur >= wrap32 || prev.value >= wrap32) {
		return deltaResult{}
	}
	if cur >= prev.value {
		return deltaResult{delta: cur - prev.value, seconds: secs, ok: true}
	}
	if kind == counter64 {
		return deltaResult{}
	}
	d := cur + wrap32 - prev.value
	if bound > 0 && d > bound {
		return deltaResult{}
	}
	return deltaResult{delta: d, seconds: secs, ok: true, wrapped: true}
}

// octetBound is the largest plausible octet delta in secs for an interface of
// speedMbps (1.1 × ifHighSpeed), or 0 when the speed isn't known.
func octetBound(speedMbps uint64, secs float64) uint64 {
	if speedMbps == 0 || secs <= 0 {
		return 0
	}
	b := float64(speedMbps) * 1e6 * secs * 11 / 80 // 1.1 × the speed, in octets
	if b >= wrap32 {
		return wrap32
	}
	return uint64(math.Ceil(b))
}

// The sysUpTime 497-day wrap (SPEC §12.2.2): from within an hour of 2^32
// ticks to a small value, about an interval after the last one.
const uptimeWrapWindow = 360000 // ticks (1 h)

// uptimeDropped reports whether sysUpTime (or hrSystemUptime) went down from
// prev to cur in elapsed: an agent restart, not the 497-day wrap.
func uptimeDropped(prev, cur uint64, elapsed time.Duration) bool {
	if cur >= prev {
		return false
	}
	if prev >= wrap32-uptimeWrapWindow {
		// Where it could have got to: twice the elapsed time plus a minute
		// (agents update uptime coarsely).
		el := uint64(max(elapsed, 0) / (10 * time.Millisecond))
		if reach := prev + 2*el + 6000; reach >= wrap32 && cur <= reach-wrap32 {
			return false // the wrap
		}
	}
	return true
}
