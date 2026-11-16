package datatype

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/pollrec"
)

// The poll type's part of the incident bundle (SPEC §12.6): the Polls lines of
// README.txt, the manifest's "poll" object, and the restarts as reboots.

// PollStats is a device's polls in a bundle (manifest.json summary "poll",
// docs/api.md). A zero value means "not measured" and is null in JSON.
type PollStats struct {
	Cycles       int64        `json:"cycles"`
	Answered     int64        `json:"answered"`
	IntervalS    *int64       `json:"interval_s"`
	UptimeEndS   *int64       `json:"uptime_end_s"`
	PeakInBps    *float64     `json:"peak_in_bps"`
	PeakInIf     string       `json:"peak_in_if"`
	PeakOutBps   *float64     `json:"peak_out_bps"`
	PeakOutIf    string       `json:"peak_out_if"`
	CPUPeak      *float64     `json:"cpu_peak"`
	MemPeakPct   *float64     `json:"mem_peak_pct"`
	ErrorsInD    *int64       `json:"errors_in_d"`
	ErrorsOutD   *int64       `json:"errors_out_d"`
	DiscardsInD  *int64       `json:"discards_in_d"`
	DiscardsOutD *int64       `json:"discards_out_d"`
	OperChanges  []OperChange `json:"oper_changes"`

	peakInAt, peakOutAt, cpuAt time.Time
}

// OperChange is an interface going down (and back up, when it did in the
// window).
type OperChange struct {
	If   string     `json:"if"`
	Down *time.Time `json:"down"`
	Up   *time.Time `json:"up"`
}

// PollSummary counts one device's poll records in a bundle.
type PollSummary struct {
	kinds    map[string]int64
	cycles   map[uint64]bool // every cycle seen
	answered map[uint64]bool // cycles with an answer
	stats    PollStats
	reboots  []Reboot
	perIf    map[string]*ifTotals
	ifOrder  []string
	open     map[string]int // interface -> index of its open (down) change
}

type ifTotals struct{ inErr, outErr, inDisc, outDisc int64 }

// Stats is the manifest's "poll" object.
func (s *PollSummary) Stats() PollStats {
	st := s.stats
	st.Cycles, st.Answered = int64(len(s.cycles)), int64(len(s.answered))
	if st.OperChanges == nil {
		st.OperChanges = []OperChange{}
	}
	return st
}

func (*PollSummary) Key() string { return "by_kind" }

func setMax(p **float64, v float64) bool {
	if *p == nil || v > **p {
		*p = &v
		return true
	}
	return false
}

func addTo(p **int64, v int64) {
	if *p == nil {
		*p = new(int64)
	}
	**p += v
}

func (s *PollSummary) Add(rec []byte, t time.Time) {
	r, err := pollrec.Parse(rec)
	if err != nil {
		return
	}
	if s.kinds == nil {
		s.kinds, s.cycles, s.answered = map[string]int64{}, map[uint64]bool{}, map[uint64]bool{}
		s.perIf, s.open = map[string]*ifTotals{}, map[string]int{}
	}
	s.kinds[r.Kind]++
	if r.Kind != pollrec.KindInfo && r.Kind != pollrec.KindRestart {
		s.cycles[r.Cycle] = true
	}
	st := &s.stats
	if v, ok := r.Uint("interval_s"); ok {
		n := int64(v)
		st.IntervalS = &n
	}
	switch r.Kind {
	case pollrec.KindStatus:
	case pollrec.KindRestart:
		s.reboots = append(s.reboots, Reboot{Time: t, Source: "poll", Detail: RestartDetail(&r)})
	case pollrec.KindSys:
		s.answered[r.Cycle] = true
		if v, ok := r.Uint("uptime"); ok {
			n := int64(v / 100)
			st.UptimeEndS = &n
		}
		if v, ok := r.Float("cpu"); ok && setMax(&st.CPUPeak, v) {
			st.cpuAt = t
		}
		used, ok1 := r.Float("mem_used")
		total, ok2 := r.Float("mem_total")
		if ok1 && ok2 && total > 0 {
			setMax(&st.MemPeakPct, math.Round(used/total*1000)/10)
		}
	case pollrec.KindIf:
		s.answered[r.Cycle] = true
		name := pollrec.IfName(&r)
		if v, ok := r.Float("in_bps"); ok && setMax(&st.PeakInBps, v) {
			st.PeakInIf, st.peakInAt = name, t
		}
		if v, ok := r.Float("out_bps"); ok && setMax(&st.PeakOutBps, v) {
			st.PeakOutIf, st.peakOutAt = name, t
		}
		it := s.perIf[name]
		if it == nil {
			it = &ifTotals{}
			s.perIf[name] = it
			s.ifOrder = append(s.ifOrder, name)
		}
		for _, x := range []struct {
			key string
			sum **int64
			per *int64
		}{{"in_err_d", &st.ErrorsInD, &it.inErr}, {"out_err_d", &st.ErrorsOutD, &it.outErr},
			{"in_disc_d", &st.DiscardsInD, &it.inDisc}, {"out_disc_d", &st.DiscardsOutD, &it.outDisc}} {
			if v, ok := r.Uint(x.key); ok {
				addTo(x.sum, int64(v))
				*x.per += int64(v)
			}
		}
		if was, ok := r.Get("oper_was"); ok {
			oper := r.Value("oper")
			tt := t.UTC()
			switch {
			case oper != "up" && was == "up":
				st.OperChanges = append(st.OperChanges, OperChange{If: name, Down: &tt})
				s.open[name] = len(st.OperChanges) - 1
			case oper == "up":
				if i, ok := s.open[name]; ok {
					st.OperChanges[i].Up = &tt
					delete(s.open, name)
				} else {
					st.OperChanges = append(st.OperChanges, OperChange{If: name, Up: &tt})
				}
			}
		}
	default: // oid
		s.answered[r.Cycle] = true
	}
}

// Counts is the records by kind, in the schema's order.
func (s *PollSummary) Counts() Counts {
	out := Counts{}
	for _, k := range pollrec.Kinds() {
		out = append(out, Count{Name: k, N: s.kinds[k]})
	}
	return out
}

func (s *PollSummary) Reboots() []Reboot { return s.reboots }

// FormatBps is a rate as README.txt shows it: "812 Mb/s", "1.2 Gb/s", "95 b/s".
func FormatBps(v float64) string {
	units := []string{"b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"}
	i := 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if v >= 10 || i == 0 {
		return strconv.FormatFloat(math.Round(v), 'f', 0, 64) + " " + units[i]
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + " " + units[i]
}

// FormatUptime is "12 d 3 h", "3 h 5 min", "5 min" or "42 s".
func FormatUptime(sec int64) string {
	d, h, m := sec/86400, sec%86400/3600, sec%3600/60
	switch {
	case d > 0:
		return fmt.Sprintf("%d d %d h", d, h)
	case h > 0:
		return fmt.Sprintf("%d h %d min", h, m)
	case m > 0:
		return fmt.Sprintf("%d min", m)
	}
	return fmt.Sprintf("%d s", sec)
}

// README is the Polls lines (SPEC §12.6). first and last are formatted by the
// bundle; a date in them means the window spans days, so times get dates too.
func (s *PollSummary) README(_ int64, first, _ string) []string {
	st := s.Stats()
	dated := strings.Contains(first, "-")
	at := func(t time.Time, sec bool) string {
		t = t.UTC()
		f := "15:04"
		if sec {
			f = "15:04:05"
		}
		if dated {
			f = "2006-01-02 " + f
		}
		return t.Format(f)
	}
	l1 := fmt.Sprintf("%s of %s cycles answered", Thousands(st.Answered), Thousands(st.Cycles))
	if st.IntervalS != nil {
		l1 += fmt.Sprintf(" (%d s)", *st.IntervalS)
	}
	if st.UptimeEndS != nil {
		l1 += "; uptime " + FormatUptime(*st.UptimeEndS) + " at the end of the window"
	}
	out := []string{l1}
	var l2 []string
	var peaks []string
	if st.PeakInBps != nil {
		peaks = append(peaks, fmt.Sprintf("peak in %s (%s, %s)", FormatBps(*st.PeakInBps), st.PeakInIf, at(st.peakInAt, false)))
	}
	if st.PeakOutBps != nil {
		peaks = append(peaks, fmt.Sprintf("peak out %s (%s, %s)", FormatBps(*st.PeakOutBps), st.PeakOutIf, at(st.peakOutAt, false)))
	}
	if len(peaks) > 0 {
		l2 = append(l2, strings.Join(peaks, ", "))
	}
	var sys []string
	if st.CPUPeak != nil {
		sys = append(sys, fmt.Sprintf("CPU peak %s %% (%s)", FormatFloatShort(*st.CPUPeak), at(st.cpuAt, false)))
	}
	if st.MemPeakPct != nil {
		sys = append(sys, fmt.Sprintf("memory peak %s %%", FormatFloatShort(math.Round(*st.MemPeakPct))))
	}
	if len(sys) > 0 {
		l2 = append(l2, strings.Join(sys, ", "))
	}
	if len(l2) > 0 {
		out = append(out, strings.Join(l2, "; "))
	}
	// Errors and discards, naming the interface with the most of each.
	most := func(get func(*ifTotals) int64) string {
		best, n := "", int64(0)
		for _, name := range s.ifOrder {
			if v := get(s.perIf[name]); v > n {
				best, n = name, v
			}
		}
		if best == "" {
			return ""
		}
		return " (" + best + ")"
	}
	var l3 []string
	pair := func(what string, in, outv *int64, gi, go_ func(*ifTotals) int64) {
		if in == nil && outv == nil {
			return
		}
		var a, b int64
		if in != nil {
			a = *in
		}
		if outv != nil {
			b = *outv
		}
		l3 = append(l3, fmt.Sprintf("%s +%s in%s, +%s out%s", what, Thousands(a), most(gi), Thousands(b), most(go_)))
	}
	pair("errors", st.ErrorsInD, st.ErrorsOutD, func(t *ifTotals) int64 { return t.inErr }, func(t *ifTotals) int64 { return t.outErr })
	pair("discards", st.DiscardsInD, st.DiscardsOutD, func(t *ifTotals) int64 { return t.inDisc }, func(t *ifTotals) int64 { return t.outDisc })
	const operLimit = 3
	for i, c := range st.OperChanges {
		if i == operLimit {
			l3 = append(l3, fmt.Sprintf("and %d more oper changes", len(st.OperChanges)-i))
			break
		}
		switch {
		case c.Down != nil && c.Up != nil:
			l3 = append(l3, fmt.Sprintf("%s down %s to %s", c.If, at(*c.Down, true), at(*c.Up, true)))
		case c.Down != nil:
			l3 = append(l3, fmt.Sprintf("%s down %s, still down at the end", c.If, at(*c.Down, true)))
		default:
			l3 = append(l3, fmt.Sprintf("%s up %s", c.If, at(*c.Up, true)))
		}
	}
	if len(l3) > 0 {
		out = append(out, strings.Join(l3, "; "))
	}
	return out
}

// FormatFloatShort is a number with at most one decimal ("91", "72.5").
func FormatFloatShort(v float64) string {
	if v == math.Trunc(v) {
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strconv.FormatFloat(v, 'f', 1, 64)
}
