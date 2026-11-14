package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Time and duration arguments of `woodshed search` (and `woodshed bundle`'s
// --at, SPEC §11.3): the forms a person types.

// localLayouts are the local-time forms of parseTimeArg, longest first.
var localLayouts = []string{
	"2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05", "2006-01-02T15:04:05",
	"2006-01-02 15:04", "2006-01-02T15:04",
}

// parseTimeArg reads a time argument:
//
//   - RFC 3339 ("2026-11-14T09:30:00Z", "2026-11-14T04:30:00-05:00");
//   - "YYYY-MM-DD HH:MM[:SS]" (or with a T), in loc (the local time zone, or UTC
//     with --utc);
//   - "now";
//   - a duration back from now: "-15m", "-2h", "-7d".
func parseTimeArg(s string, now time.Time, loc *time.Location) (time.Time, error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return time.Time{}, fmt.Errorf("a time is empty")
	case strings.EqualFold(s, "now"):
		return now, nil
	case s[0] == '-':
		d, err := parseDurationArg(s[1:])
		if err != nil {
			return time.Time{}, fmt.Errorf("%q: %v", s, err)
		}
		return now.Add(-d), nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	for _, l := range localLayouts {
		if t, err := time.ParseInLocation(l, s, loc); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q isn't a time: use RFC 3339 (2026-11-14T09:30:00Z), local time (2026-11-14 09:30), now, or -15m", s)
}

// durationUnits are parseDurationArg's units.
var durationUnits = map[string]time.Duration{
	"ms": time.Millisecond, "s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour,
}

// parseDurationArg reads a positive duration such as "15m", "1h30m", "24h",
// "7d" or "2w" (days are 24 hours).
func parseDurationArg(s string) (time.Duration, error) {
	in := s
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("a duration is empty (e.g. 15m, 1h, 24h, 7d)")
	}
	var total time.Duration
	for s != "" {
		i := 0
		for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.') {
			i++
		}
		j := i
		for j < len(s) && (s[j] < '0' || s[j] > '9') && s[j] != '.' {
			j++
		}
		n, err := strconv.ParseFloat(s[:i], 64)
		unit, ok := durationUnits[strings.ToLower(s[i:j])]
		if i == 0 || err != nil || !ok {
			return 0, fmt.Errorf("%q isn't a duration (e.g. 15m, 1h, 24h, 7d)", in)
		}
		total += time.Duration(n * float64(unit))
		s = s[j:]
	}
	if total <= 0 {
		return 0, fmt.Errorf("%q isn't a positive duration", in)
	}
	return total, nil
}
