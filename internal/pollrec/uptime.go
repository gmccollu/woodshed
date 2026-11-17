package pollrec

import "time"

// The uptime rules (SPEC §12.2.2), shared by the poller, which writes restart
// lines from them, and the bundle, which reads a trap against the polls
// around it (§12.6).

// uptimeWrap is 2^32 ticks, where TimeTicks wrap (about 497 days).
const uptimeWrap = 1 << 32

// uptimeWrapWindow is how close to the wrap an uptime must be for a small
// value after it to be the 497-day wrap, not a restart.
const uptimeWrapWindow = 360000 // ticks (1 h)

// uptimeSlack is how far an uptime may fall behind the time between two
// samples without counting as a restart: agents update it coarsely, and the
// two receive times stand for the agent's own reading times only to within a
// round trip.
func uptimeSlack(el uint64) uint64 { return max(500, el/50) } // 5 s, or 2 % of the interval

// UptimeDropped reports whether sysUpTime (or hrSystemUptime) restarted
// between two samples elapsed apart: it went down (but not by its 497-day
// wrap), or it went up by clearly less than the time between them. The second
// is a restart soon after the previous one (an agent up 6 s, restarted, and
// polled again 7 s later reads 6.5 s: lower than it should be, not lower than
// before), which a "went down" rule alone misses. An uptime that didn't move
// at all is a stuck counter (macOS's snmpd reports hrSystemUptime as 0), not
// a restart.
func UptimeDropped(prev, cur uint64, elapsed time.Duration) bool {
	el := uint64(max(elapsed, 0) / (10 * time.Millisecond))
	if cur < prev && prev >= uptimeWrap-uptimeWrapWindow {
		// Where it could have got to: twice the elapsed time plus a minute
		// (agents update uptime coarsely).
		if reach := prev + 2*el + 6000; reach >= uptimeWrap && cur <= reach-uptimeWrap {
			return false // the wrap
		}
	}
	switch {
	case cur < prev:
		return true
	case cur == prev:
		return false // a value that doesn't move is a stuck counter, not a restart
	}
	return cur+uptimeSlack(el) < prev+el
}
