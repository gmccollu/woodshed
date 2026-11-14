package model

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Spans: the incident bundle's before and after (docs/api.md, SPEC §11.3),
// read the same way by the API and `woodshed bundle`.

// spanUnits are ParseSpan's units.
var spanUnits = map[string]time.Duration{"ms": time.Millisecond, "s": time.Second, "m": time.Minute, "h": time.Hour,
	"d": 24 * time.Hour}

// ParseSpan reads a bundle's before or after: "0" or a sequence of numbers
// with units ms, s, m, h and d ("30m", "1h30m", "7d", "0s"). Days are 24
// hours. The range (0 to MaxSpan) is checked by the request.
func ParseSpan(s string) (time.Duration, error) {
	in := s
	s = strings.TrimSpace(s)
	if s == "0" {
		return 0, nil
	}
	bad := fmt.Errorf("%q isn't a duration (e.g. 15m, 1h, 1h30m, 7d, 0s)", in)
	if s == "" {
		return 0, bad
	}
	var total float64
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
		unit, ok := spanUnits[strings.ToLower(s[i:j])]
		if i == 0 || err != nil || !ok {
			return 0, bad
		}
		total += n * float64(unit)
		if total > float64(1<<62) {
			return 0, fmt.Errorf("%q is too long", in)
		}
		s = s[j:]
	}
	return time.Duration(total).Round(time.Millisecond), nil
}

// FormatSpan writes a span the way ParseSpan reads it, shortest form first:
// "0s", "30m", "1h30m", "7d", "1d2h", "1s500ms".
func FormatSpan(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	var b strings.Builder
	for _, u := range []struct {
		name string
		d    time.Duration
	}{{"d", 24 * time.Hour}, {"h", time.Hour}, {"m", time.Minute}, {"s", time.Second}, {"ms", time.Millisecond}} {
		if n := d / u.d; n > 0 {
			fmt.Fprintf(&b, "%d%s", n, u.name)
			d -= n * u.d
		}
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}
