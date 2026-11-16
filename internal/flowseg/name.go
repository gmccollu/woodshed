package flowseg

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Ext is a segment file's extension.
const Ext = ".wsf"

// Name is a segment's file name (SPEC §13.2): "<YYYY-MM-DD>T<HH>.wsf" for the
// hour's first part, "<YYYY-MM-DD>T<HH>.<NNN>.wsf" for the next ones (part 1
// up), received hour UTC.
type Name struct {
	Day  string // YYYY-MM-DD
	Hour int    // 0–23
	Part int    // 0 for the first part
}

// NameFor is the first part's name for the hour holding t.
func NameFor(t time.Time) Name {
	t = t.UTC()
	return Name{Day: t.Format(time.DateOnly), Hour: t.Hour()}
}

func (n Name) String() string {
	if n.Part == 0 {
		return fmt.Sprintf("%sT%02d%s", n.Day, n.Hour, Ext)
	}
	return fmt.Sprintf("%sT%02d.%03d%s", n.Day, n.Hour, n.Part, Ext)
}

// Time is the start of the name's hour, UTC.
func (n Name) Time() time.Time {
	d, err := time.Parse(time.DateOnly, n.Day)
	if err != nil {
		return time.Time{}
	}
	return d.Add(time.Duration(n.Hour) * time.Hour)
}

// Less orders names by hour, then part.
func (n Name) Less(o Name) bool {
	if n.Day != o.Day {
		return n.Day < o.Day
	}
	if n.Hour != o.Hour {
		return n.Hour < o.Hour
	}
	return n.Part < o.Part
}

// ParseName reads a segment file name; false for anything else.
func ParseName(s string) (Name, bool) {
	rest, ok := strings.CutSuffix(s, Ext)
	if !ok || len(rest) < 13 || rest[10] != 'T' {
		return Name{}, false
	}
	day := rest[:10]
	if _, err := time.Parse(time.DateOnly, day); err != nil {
		return Name{}, false
	}
	hh := rest[11:13]
	h, err := strconv.Atoi(hh)
	if err != nil || h < 0 || h > 23 || hh[0] < '0' || hh[0] > '9' {
		return Name{}, false
	}
	n := Name{Day: day, Hour: h}
	rest = rest[13:]
	if rest == "" {
		return n, true
	}
	if len(rest) != 4 || rest[0] != '.' {
		return Name{}, false
	}
	p, err := strconv.Atoi(rest[1:])
	if err != nil || p < 1 || rest[1] < '0' || rest[1] > '9' {
		return Name{}, false
	}
	n.Part = p
	return n, n.String() == s
}
