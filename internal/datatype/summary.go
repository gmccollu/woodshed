package datatype

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// A data type's part of the incident bundle's summary (SPEC §11.3): each type
// counts one device's records as they stream into the zip, and says how its
// counts read in README.txt and manifest.json.

// Summary is one device's records of one type in a bundle, counted as they
// are written. Lines, first and last are the bundle's (the same for every
// type); a Summary holds the type's own breakdown and the reboots its records
// show.
type Summary interface {
	// Add counts one record (the stored record, unescaped) received at t.
	Add(rec []byte, t time.Time)
	// Key is the breakdown's name in manifest.json ("by_severity", "by_trap").
	Key() string
	// Counts is the breakdown, in the order README.txt shows it.
	Counts() Counts
	// Reboots are the records that show the device restarting, oldest first.
	Reboots() []Reboot
	// README is the type's lines in README.txt's per-device summary, after the
	// type's label: n records (n > 0), the first and last received times
	// already formatted.
	README(n int64, first, last string) []string
}

// Count is one entry of a breakdown.
type Count struct {
	Name string
	N    int64
}

// Counts is a breakdown in display order. It is a JSON object, in that order.
type Counts []Count

// MarshalJSON writes the counts as one object, keys in order.
func (c Counts) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, x := range c {
		if i > 0 {
			b.WriteByte(',')
		}
		k, err := json.Marshal(x.Name)
		if err != nil {
			return nil, err
		}
		b.Write(k)
		b.WriteByte(':')
		b.WriteString(strconv.FormatInt(x.N, 10))
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// UnmarshalJSON reads an object, keeping its key order.
func (c *Counts) UnmarshalJSON(b []byte) error {
	*c = nil
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	t, err := d.Token()
	if err != nil {
		return err
	}
	if t == nil {
		return nil
	}
	if t != json.Delim('{') {
		return errors.New("counts: not an object")
	}
	for d.More() {
		kt, err := d.Token()
		if err != nil {
			return err
		}
		var n json.Number
		if err := d.Decode(&n); err != nil {
			return err
		}
		v, err := n.Int64()
		if err != nil {
			return err
		}
		*c = append(*c, Count{Name: kt.(string), N: v})
	}
	_, err = d.Token()
	return err
}

// Reboot is a record showing that the device restarted.
type Reboot struct {
	Time   time.Time `json:"time"`
	Source string    `json:"source"` // what showed it: "coldStart trap", "poll", or both: "poll, coldStart trap"
	// Detail is a poll restart's evidence ("sysUpTime and hrSystemUptime
	// reset"); absent for a trap's.
	Detail string `json:"detail,omitempty"`
}

// Thousands formats n with commas (12,408), as README.txt shows counts.
func Thousands(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	if neg {
		b.WriteByte('-')
	}
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---- syslog ----

// syslogSummary counts by severity.
type syslogSummary struct{ n [9]int64 } // 0-7, then unknown

func (*syslogSummary) Key() string { return "by_severity" }

func (s *syslogSummary) Add(rec []byte, _ time.Time) {
	v := Severity(rec)
	if v < 0 || v > 7 {
		v = 8
	}
	s.n[v]++
}

// Counts is every severity, emerg to debug then unknown, zeros included (the
// field's whole domain, so a reader sees what was absent).
func (s *syslogSummary) Counts() Counts {
	out := make(Counts, 0, 9)
	for i, c := range s.n {
		name := "unknown"
		if i < 8 {
			name = SeverityNames[i]
		}
		out = append(out, Count{Name: name, N: c})
	}
	return out
}

func (*syslogSummary) Reboots() []Reboot { return nil }

func (s *syslogSummary) README(n int64, first, last string) []string {
	unit := "messages"
	if n == 1 {
		unit = "message"
	}
	var have, none []string
	for _, c := range s.Counts() {
		if c.N == 0 {
			none = append(none, c.Name)
		} else {
			have = append(have, c.Name+" "+Thousands(c.N))
		}
	}
	l2 := strings.Join(have, ", ")
	if len(none) > 0 {
		l2 += " (none of " + strings.Join(none, ", ") + ")"
	}
	return []string{Thousands(n) + " " + unit + ", first " + first + ", last " + last, l2}
}

// ---- traps ----

// trapSummaryNames is how many trap names README.txt lists before "and N
// more"; manifest.json has them all.
const trapSummaryNames = 10

// trapSummary counts by trap name (or OID), and finds coldStart and warmStart.
type trapSummary struct {
	t       trapType
	by      map[string]int64
	first   map[string]int // first appearance, for ties
	reboots []Reboot
}

func (*trapSummary) Key() string { return "by_trap" }

func (s *trapSummary) Add(rec []byte, t time.Time) {
	r, err := snmp.ParseRecordHeader(rec)
	k := r.Trap
	switch {
	case err != nil && k == "":
		k = "(malformed)"
	case k == "":
		k = "(" + r.Status + ")"
	default:
		// A retransmitted inform (dup=1) is the same reboot again.
		if name, ok := IsReboot(k); ok && !r.Dup {
			what := "trap"
			if r.PDU == "inform" {
				what = "inform"
			}
			s.reboots = append(s.reboots, Reboot{Time: t, Source: name + " " + what})
		}
		k = s.t.ValueLabel(FieldTrapOID, k)
	}
	if s.by == nil {
		s.by, s.first = map[string]int64{}, map[string]int{}
	}
	if _, ok := s.by[k]; !ok {
		s.first[k] = len(s.first)
	}
	s.by[k]++
}

// Counts is the trap names, most first (ties in order of appearance).
func (s *trapSummary) Counts() Counts {
	out := make(Counts, 0, len(s.by))
	for k, n := range s.by {
		out = append(out, Count{Name: k, N: n})
	}
	sortCounts(out, s.first)
	return out
}

func (s *trapSummary) Reboots() []Reboot { return s.reboots }

func (s *trapSummary) README(n int64, first, last string) []string {
	cs := s.Counts()
	var parts []string
	for i, c := range cs {
		if i == trapSummaryNames {
			var rest int64
			for _, r := range cs[i:] {
				rest += r.N
			}
			parts = append(parts, "and "+Thousands(int64(len(cs)-i))+" more ("+Thousands(rest)+")")
			break
		}
		parts = append(parts, c.Name+" "+Thousands(c.N))
	}
	return []string{Thousands(n) + ": " + strings.Join(parts, ", ") + "; first " + first + ", last " + last}
}

func sortCounts(cs Counts, first map[string]int) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].N != cs[j].N {
			return cs[i].N > cs[j].N
		}
		return first[cs[i].Name] < first[cs[j].Name]
	})
}
