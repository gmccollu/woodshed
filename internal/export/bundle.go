package export

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
)

// The incident bundle (SPEC §11.3, docs/api.md "Exports"): an export of
// every record around a moment, with a summary per device. It goes through
// the export queue (Manager.Create with Kind "bundle") or, for `woodshed
// bundle`, Prepare and Plan.Write on a read-only index; both write the zip
// with builder.write, so the two zips hold the same files.

// MaxSpan is the longest before or after (docs/api.md: 0s to 7d each).
const MaxSpan = 7 * 24 * time.Hour

// Default spans when a request names none (the CLI's defaults, SPEC §11.3).
const (
	DefaultBefore = 30 * time.Minute
	DefaultAfter  = 10 * time.Minute
)

// builder writes zips. It reads the index and the log files only.
type builder struct {
	idx          *index.DB
	eng          *search.Engine
	version      string
	now          func() time.Time
	level        int
	loc          *time.Location
	zip64Limit   int64
	testHookLine func()
}

func newBuilder(o Options) builder {
	b := builder{idx: o.Index, eng: o.Search, version: o.Version, now: o.Now, level: o.Level, loc: o.Location,
		zip64Limit: o.zip64Limit, testHookLine: o.testHookLine}
	if b.now == nil {
		b.now = time.Now
	}
	if b.level == 0 {
		b.level = 5
	}
	if b.loc == nil {
		b.loc = time.Local
	}
	return b
}

// ParseSpan and FormatSpan read and write a bundle's before and after
// (model.ParseSpan).
var (
	ParseSpan  = model.ParseSpan
	FormatSpan = model.FormatSpan
)

// humanSpan is a span in README.txt's words: "30 min", "1 h 30 min", "7 days".
func humanSpan(d time.Duration) string {
	if d <= 0 {
		return "nothing"
	}
	var parts []string
	for _, u := range []struct {
		one, many string
		d         time.Duration
	}{{"1 day", "%d days", 24 * time.Hour}, {"1 h", "%d h", time.Hour}, {"1 min", "%d min", time.Minute},
		{"1 s", "%d s", time.Second}, {"1 ms", "%d ms", time.Millisecond}} {
		if n := d / u.d; n > 0 {
			if n == 1 {
				parts = append(parts, u.one)
			} else {
				parts = append(parts, fmt.Sprintf(u.many, n))
			}
			d -= n * u.d
		}
	}
	return strings.Join(parts, " ")
}

// resolveBundle validates a bundle and resolves its window (From, To), its
// devices and its types (every type with data in the window when it names
// none) into r.
func (b *builder) resolveBundle(ctx context.Context, r *Request) ([]string, error) {
	f := &r.Filters
	bad := func(format string, a ...any) ([]string, error) {
		return nil, &RequestError{Msg: fmt.Sprintf(format, a...)}
	}
	if f.At == nil || f.At.IsZero() {
		return bad("at is required: the moment the bundle is around (RFC 3339).")
	}
	at := f.At.UTC()
	f.At = &at
	for _, s := range []struct {
		name string
		d    time.Duration
	}{{"before", f.Before}, {"after", f.After}} {
		if s.d < 0 || s.d > MaxSpan {
			return bad("%s must be from 0s to 7d, not %s.", s.name, FormatSpan(s.d))
		}
	}
	if f.Before == 0 && f.After == 0 {
		return bad("before and after can't both be 0s: the window would be empty.")
	}
	now := b.now()
	if at.After(now) {
		return bad("at (%s) is in the future.", at.Format(time.RFC3339Nano))
	}
	from, to := at.Add(-f.Before), at.Add(f.After)
	if to.After(now) {
		to = now // a bundle "around now" is cut at now
	}
	if !from.Before(to) {
		return bad("The window from %s to %s is empty (a bundle's window ends at the latest now).",
			from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano))
	}
	r.From, r.To = from.UTC(), to.UTC()

	switch {
	case r.AllDevices:
		return bad("all_devices: a bundle takes active_devices (every device that stored anything in the window), devices, group or ungrouped.")
	case len(r.ExcludeDevices) > 0:
		return bad("exclude_devices: a bundle takes no filters; pick its devices with active_devices, devices, group or ungrouped.")
	case !r.filtersEmpty() || r.Terms || r.Regex || r.Case:
		return bad("A bundle takes no filters: it's everything around the moment. Filter with a plain export instead.")
	}
	picks := 0
	for _, p := range []bool{f.ActiveDevices, len(r.Devices) > 0, f.Group != "", f.Ungrouped} {
		if p {
			picks++
		}
	}
	switch {
	case picks == 0:
		return bad("Pick the devices: active_devices, devices, group or ungrouped.")
	case picks > 1:
		return bad("active_devices, devices, group and ungrouped are alternatives; send one.")
	}
	var types []string
	for _, t := range f.Types {
		if datatype.Get(t) == nil || t == "" {
			return bad("types: unknown data type %q.", t)
		}
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	all := types
	if len(all) == 0 {
		all = datatype.Names()
	}
	active, err := b.eng.Active(ctx, all, r.From, r.To)
	if err != nil {
		return nil, err
	}
	// Every non-hidden device, or the named ones (hidden ones too), the group's
	// or the ungrouped ones, as for exports.
	devs, err := b.eng.ResolveDevices(ctx, r.Devices, f.Group, f.Ungrouped, nil)
	if err != nil {
		return nil, err
	}
	if f.ActiveDevices {
		devs = slices.DeleteFunc(devs, func(d string) bool { return len(active[d]) == 0 })
		if len(devs) == 0 {
			what := "anything"
			if len(types) > 0 {
				what = typeList(types)
			}
			return nil, &RequestError{Empty: true, Msg: fmt.Sprintf("No device stored %s between %s and %s.", what,
				r.From.Format(time.RFC3339Nano), r.To.Format(time.RFC3339Nano))}
		}
	}
	if len(devs) == 0 {
		return bad("No device matches the selection.")
	}
	if len(types) == 0 {
		for _, t := range all {
			for _, d := range devs {
				if slices.Contains(active[d], t) {
					types = append(types, t)
					break
				}
			}
		}
	}
	f.Types = types
	return devs, nil
}

// typeList names data types in a sentence: "syslog and SNMP traps".
func typeList(types []string) string {
	var ls []string
	for _, t := range types {
		ls = append(ls, typeWord(t))
	}
	switch len(ls) {
	case 0:
		return "none"
	case 1:
		return ls[0]
	}
	return strings.Join(ls[:len(ls)-1], ", ") + " and " + ls[len(ls)-1]
}

// typeWord is a type's label inside a sentence ("syslog", "SNMP traps").
func typeWord(t string) string {
	if t == datatype.Syslog {
		return "syslog"
	}
	if ty := datatype.Get(t); ty != nil {
		return ty.Label()
	}
	return t
}

// ---- building offline (woodshed bundle) ----

// Plan is a resolved export or bundle, ready to write without a Manager:
// `woodshed bundle` resolves its request on a read-only index and writes
// the zip itself.
type Plan struct {
	b    builder
	Info Info
}

// Prepare resolves r as Manager.Create does: the window, the devices and the
// types. A bad request is a *RequestError (Empty when no device stored
// anything in the window).
func Prepare(ctx context.Context, opts Options, r Request) (*Plan, error) {
	b := newBuilder(opts)
	devs, err := b.resolve(ctx, &r)
	if err != nil {
		return nil, err
	}
	now := b.now().UTC()
	return &Plan{b: b, Info: Info{ID: newID(), Created: now, Devices: devs, From: r.From.UTC(), To: r.To.UTC(),
		State: Building, Filters: r.Filters, Named: r.Devices}}, nil
}

// Estimate is the plan's upper bound from the index, as POST
// /api/exports/estimate gives it.
func (p *Plan) Estimate(ctx context.Context) (search.Estimate, error) {
	req := Request{Devices: p.Info.Named, From: p.Info.From, To: p.Info.To, Filters: p.Info.Filters}
	var est search.Estimate
	for _, t := range req.TypesOrSyslog() {
		e, err := p.b.eng.Estimate(ctx, p.Info.Devices, req.typeFilter(t))
		if err != nil {
			return est, err
		}
		est.Lines += e.Lines
		est.Bytes += e.Bytes
		est.Files += e.Files
	}
	return est, nil
}

// Result is what Plan.Write wrote.
type Result struct {
	Lines   int64           // records in the zip
	Size    int64           // the zip's size
	Files   int             // record files in the zip
	Summary []DeviceSummary // a bundle's, per device
	Gaps    []Gap
}

// Write writes the zip to f (empty, open for reading and writing; it isn't
// synced or closed). progress may be nil.
func (p *Plan) Write(ctx context.Context, f *os.File, progress func(float64)) (Result, error) {
	if progress == nil {
		progress = func(float64) {}
	}
	res, err := p.b.write(ctx, f, p.Info, progress)
	return Result{Lines: res.lines, Size: res.size, Files: res.files, Summary: res.summary, Gaps: res.gaps}, err
}

// BundleFileName is a bundle's zip name, for the CLI's default --out and the
// download: woodshed-bundle-<host>-<at, UTC>.zip.
func BundleFileName(host string, at time.Time) string {
	h := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, host)
	h = strings.Trim(h, ".")
	if h == "" {
		h = "woodshed"
	}
	return "woodshed-bundle-" + h + "-" + at.UTC().Format("20060102T150405Z") + ".zip"
}

// ---- the summary ----

// SummaryNote says where the summary's numbers come from (manifest.json).
const SummaryNote = "Per device: lines, first and last are the records in this zip, by type (for polls, the CSV rows); " +
	"by_severity, by_trap and by_kind count them. reboots come from coldStart and warmStart traps (a retransmitted inform " +
	"isn't counted again) and from poll restarts (source \"poll\", with the detail); a trap and a poll restart within 2 " +
	"minutes are one reboot naming both sources. poll sums up the device's polls (null: not measured). gaps " +
	"are the bundle's (see gaps_note), the same for every device. dropped and truncated are Woodshed's own counts from " +
	"its statistics, per minute (per hour past 24 hours), for the buckets that start inside the window, so a bucket " +
	"that straddles an edge counts whole."

// TypeSummary is one device's records of one type in a bundle.
type TypeSummary struct {
	Lines       int64
	First, Last *time.Time
	Key         string          // the breakdown's name ("by_severity", "by_trap")
	Counts      datatype.Counts // the breakdown
	readme      []string
}

// MarshalJSON writes {"lines", "first", "last", <Key>}.
func (t TypeSummary) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"lines":`)
	b.WriteString(strconv.FormatInt(t.Lines, 10))
	for _, x := range []struct {
		k string
		v *time.Time
	}{{"first", t.First}, {"last", t.Last}} {
		v, err := json.Marshal(x.v)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, `,%q:%s`, x.k, v)
	}
	if t.Key != "" {
		c, err := json.Marshal(t.Counts)
		if err != nil {
			return nil, err
		}
		k, _ := json.Marshal(t.Key)
		fmt.Fprintf(&b, `,%s:%s`, k, c)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// UnmarshalJSON reads what MarshalJSON writes.
func (t *TypeSummary) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*t = TypeSummary{}
	for k, v := range m {
		var err error
		switch k {
		case "lines":
			err = json.Unmarshal(v, &t.Lines)
		case "first":
			err = json.Unmarshal(v, &t.First)
		case "last":
			err = json.Unmarshal(v, &t.Last)
		default:
			if t.Key != "" {
				return errors.New("summary: two breakdowns")
			}
			t.Key = k
			err = json.Unmarshal(v, &t.Counts)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// DeviceSummary is one device's part of a bundle's summary (manifest.json
// "summary", and README.txt).
type DeviceSummary struct {
	DeviceID string                 `json:"device_id"`
	IP       string                 `json:"ip"`
	Name     string                 `json:"name"`
	Group    string                 `json:"group"`
	Types    map[string]TypeSummary `json:"types"`
	Reboots  []datatype.Reboot      `json:"reboots"`
	// Poll is the device's polls in the window (a bundle with the poll type).
	Poll      *datatype.PollStats `json:"poll,omitempty"`
	Gaps      []Gap               `json:"gaps"`
	Dropped   int64               `json:"dropped"`
	Truncated int64               `json:"truncated"`
	hidden    bool
}

// Heading is the device as README.txt and `woodshed bundle` name it:
// "edge-fw-01 (10.1.0.1), group HQ".
func (d DeviceSummary) Heading() string {
	addr := d.IP
	if addr == "" {
		addr = d.DeviceID
	}
	s := addr
	if d.Name != "" {
		s = d.Name + " (" + addr + ")"
	}
	if d.Group != "" {
		s += ", group " + d.Group
	}
	if d.hidden {
		s += ", hidden"
	}
	return s
}

// Line is the device's summary in one line, for `woodshed bundle`'s output:
// "syslog 12,408, SNMP traps 7, reboots 1, dropped 0, truncated 0".
func (d DeviceSummary) Line(types []string) string {
	var parts []string
	for _, t := range types {
		parts = append(parts, typeWord(t)+" "+datatype.Thousands(d.Types[t].Lines))
	}
	if slices.Contains(types, datatype.Trap) || slices.Contains(types, datatype.Poll) {
		parts = append(parts, "reboots "+datatype.Thousands(int64(len(d.Reboots))))
	}
	parts = append(parts, "dropped "+datatype.Thousands(d.Dropped), "truncated "+datatype.Thousands(d.Truncated))
	return strings.Join(parts, ", ")
}

// typeCount counts one device's records of one type as they're written.
type typeCount struct {
	lines       int64
	first, last time.Time
	sum         datatype.Summary
}

func (c *typeCount) add(rec []byte, t time.Time) {
	if c.lines == 0 || t.Before(c.first) {
		c.first = t
	}
	if c.lines == 0 || t.After(c.last) {
		c.last = t
	}
	c.lines++
	c.sum.Add(rec, t)
}

// summaries are a bundle's counts, per device and type.
type summaries struct {
	m map[[2]string]*typeCount
}

func newSummaries(devs, types []string) *summaries {
	s := &summaries{m: map[[2]string]*typeCount{}}
	for _, d := range devs {
		for _, t := range types {
			s.m[[2]string{d, t}] = &typeCount{sum: datatype.Get(t).NewSummary()}
		}
	}
	return s
}

func (s *summaries) of(dev, typ string) *typeCount { return s.m[[2]string{dev, typ}] }

// summarize builds the per-device summary from the counts, the gaps and the
// stats' drops and truncations in the window.
func (b *builder) summarize(ctx context.Context, info Info, s *summaries, devs []ManifestDevice, gaps []Gap) ([]DeviceSummary, error) {
	types := info.Filters.TypesOrSyslog()
	out := make([]DeviceSummary, 0, len(devs))
	ms := func(t time.Time) *time.Time { t = t.UTC(); return &t }
	for _, d := range devs {
		ds := DeviceSummary{DeviceID: d.ID, IP: d.IP, Name: d.Name, Group: d.Group, Types: map[string]TypeSummary{},
			Reboots: []datatype.Reboot{}, Gaps: nonNil(gaps), hidden: d.hidden}
		for _, t := range types {
			c := s.of(d.ID, t)
			ts := TypeSummary{Lines: c.lines, Key: c.sum.Key(), Counts: c.sum.Counts()}
			if c.lines > 0 {
				ts.First, ts.Last = ms(c.first), ms(c.last)
			}
			ds.Types[t] = ts
			ds.Reboots = append(ds.Reboots, c.sum.Reboots()...)
			if ps, ok := c.sum.(*datatype.PollSummary); ok {
				st := ps.Stats()
				ds.Poll = &st
			}
		}
		sort.SliceStable(ds.Reboots, func(i, j int) bool { return ds.Reboots[i].Time.Before(ds.Reboots[j].Time) })
		for i := range ds.Reboots {
			ds.Reboots[i].Time = ds.Reboots[i].Time.UTC()
		}
		ds.Reboots = mergeReboots(ds.Reboots)
		cnt, err := b.idx.Counts(ctx, []string{d.ID}, info.From, info.To)
		if err != nil {
			return nil, err
		}
		ds.Dropped, ds.Truncated = cnt.Dropped, cnt.Truncated
		out = append(out, ds)
	}
	// README lines, with the times formatted for this window.
	tf := newTimeFmt(info)
	for i := range out {
		for _, t := range types {
			ts := out[i].Types[t]
			if ts.Lines > 0 {
				ts.readme = s.of(out[i].DeviceID, t).sum.README(ts.Lines, tf.record(*ts.First), tf.record(*ts.Last))
			}
			out[i].Types[t] = ts
		}
	}
	return out, nil
}

// timeFmt formats times in a bundle's README: UTC, with the date only when
// the window spans more than one UTC day.
type timeFmt struct{ dated bool }

func newTimeFmt(info Info) timeFmt {
	return timeFmt{dated: info.From.UTC().Format(time.DateOnly) != info.To.Add(-time.Millisecond).UTC().Format(time.DateOnly)}
}

// clock is a time of day, with milliseconds when it has any.
func clockOf(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1e6 != 0 {
		return t.Format("15:04:05.000")
	}
	return t.Format("15:04:05")
}

// record is a record's received time: always with milliseconds.
func (f timeFmt) record(t time.Time) string {
	t = t.UTC()
	if f.dated {
		return t.Format("2006-01-02 15:04:05.000")
	}
	return t.Format("15:04:05.000")
}

// edge is any other time in the window (a gap's edges).
func (f timeFmt) edge(t time.Time) string {
	if f.dated {
		return t.UTC().Format(time.DateOnly) + " " + clockOf(t)
	}
	return clockOf(t)
}

// lossNote says what the drop counts cover on this OS.
func lossNote() string {
	if runtime.GOOS == "linux" {
		return "Woodshed's own counts; the kernel's UDP drops are counted per listener, not per device"
	}
	return "Woodshed's own counts; kernel UDP drops aren't visible on this OS"
}

// rebootMerge is how close a coldStart or warmStart trap and a poll restart
// must be to be one reboot (SPEC §12.2.2).
const rebootMerge = 2 * time.Minute

// mergeReboots joins each poll restart with the nearest trap reboot within
// rebootMerge (each used once): one reboot at the earlier time, source "poll,
// <trap>", with the poll's detail. rs is sorted by time.
func mergeReboots(rs []datatype.Reboot) []datatype.Reboot {
	used := make([]bool, len(rs))
	out := []datatype.Reboot{}
	for i, r := range rs {
		if used[i] || r.Source != "poll" {
			continue
		}
		best := -1
		for j, o := range rs {
			if used[j] || j == i || o.Source == "poll" {
				continue
			}
			d := o.Time.Sub(r.Time)
			if d < 0 {
				d = -d
			}
			if d <= rebootMerge && (best < 0 || d < absDur(rs[best].Time.Sub(r.Time))) {
				best = j
			}
		}
		if best >= 0 {
			used[best] = true
			at := r.Time
			if rs[best].Time.Before(at) {
				at = rs[best].Time
			}
			rs[i] = datatype.Reboot{Time: at, Source: "poll, " + rs[best].Source, Detail: r.Detail}
		}
	}
	for i, r := range rs {
		if !used[i] {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// rebootWords is a reboot in README.txt: "poll: sysUpTime and hrSystemUptime
// reset; coldStart trap", "coldStart trap".
func rebootWords(r datatype.Reboot) string {
	parts := strings.Split(r.Source, ", ")
	for i, p := range parts {
		if p == "poll" && r.Detail != "" {
			parts[i] = "poll: " + r.Detail
		}
	}
	return strings.Join(parts, "; ")
}

// rebootLimit is how many reboots a README line lists.
const rebootLimit = 5

// bundleReadme is a bundle's README.txt: the moment, the window, the
// summary per device (SPEC §11.3), then what each file is.
func (b *builder) bundleReadme(info Info, sum []DeviceSummary) string {
	f := info.Filters
	types := f.TypesOrSyslog()
	tf := newTimeFmt(info)
	at := f.At.UTC()
	var w bytes.Buffer
	fmt.Fprintf(&w, "Incident bundle around %s %s UTC (%s before, %s after)\n", at.Format(time.DateOnly), clockOf(at),
		humanSpan(f.Before), humanSpan(f.After))
	to := clockOf(info.To)
	if tf.dated {
		to = info.To.UTC().Format(time.DateOnly) + " " + to
	}
	cut := ""
	if at.Add(f.After).After(info.To) {
		cut = ", cut at the time it was built"
	}
	fmt.Fprintf(&w, "Window: %s %s to %s UTC%s (local time UTC%s)\n", info.From.UTC().Format(time.DateOnly), clockOf(info.From), to,
		cut, at.In(b.loc).Format("-07:00"))
	var how string
	switch {
	case f.ActiveDevices:
		how = "every device that sent anything in the window"
	case f.Group != "":
		how = "the group " + f.Group
	case f.Ungrouped:
		how = "the devices in no group"
	default:
		how = "chosen by name"
	}
	var labels []string
	for _, t := range types {
		labels = append(labels, typeWord(t))
	}
	tl := strings.Join(labels, ", ")
	if len(labels) == 0 {
		tl = "none (nothing was stored in the window)"
	}
	fmt.Fprintf(&w, "Devices: %d, %s. Types: %s.\n", len(sum), how, tl)
	hasTrap := slices.Contains(types, datatype.Trap)
	hasPoll := slices.Contains(types, datatype.Poll)
	if hasTrap {
		w.WriteString("Communities in traps are shown as a hash prefix and masked in raw=, by design.\n")
	}

	const col = 13
	row := func(label string, lines ...string) {
		for i, l := range lines {
			if i == 0 {
				fmt.Fprintf(&w, "  %-*s%s\n", col, label, l)
			} else {
				fmt.Fprintf(&w, "  %*s%s\n", col, "", l)
			}
		}
	}
	for _, d := range sum {
		w.WriteString("\n" + d.Heading() + "\n")
		if len(types) == 0 {
			w.WriteString("  Nothing was stored in the window.\n")
		}
		for _, t := range types {
			ts := d.Types[t]
			label := datatype.Get(t).Label()
			if t == datatype.Poll {
				label = "Polls" // SPEC §12.6
			}
			if ts.Lines == 0 {
				row(label, "none")
				continue
			}
			row(label, ts.readme...)
		}
		switch {
		case !hasTrap && !hasPoll:
			row("Reboots", "not known (no SNMP traps or polls in this bundle)")
		case len(d.Reboots) == 0 && hasTrap && hasPoll:
			row("Reboots", "none (no coldStart or warmStart trap, no restart in the polls)")
		case len(d.Reboots) == 0 && hasPoll:
			row("Reboots", "none (no restart in the polls)")
		case len(d.Reboots) == 0:
			row("Reboots", "none (no coldStart or warmStart trap)")
		default:
			var rs []string
			for i, r := range d.Reboots {
				if i == rebootLimit {
					rs = append(rs, fmt.Sprintf("and %d more", len(d.Reboots)-i))
					break
				}
				rs = append(rs, tf.record(r.Time)+" ("+rebootWords(r)+")")
			}
			row("Reboots", fmt.Sprintf("%d: %s", len(d.Reboots), strings.Join(rs, ", ")))
		}
		if len(d.Gaps) == 0 {
			row("Gaps", "none of 1 s or more (Woodshed and its listeners were up the whole window)")
		} else {
			var gs []string
			for _, g := range d.Gaps {
				gs = append(gs, tf.edge(g.From)+" to "+tf.edge(g.To)+"  "+gapWords(g))
			}
			row("Gaps", gs...)
		}
		row("Losses", fmt.Sprintf("dropped %s, truncated %s (%s)", datatype.Thousands(d.Dropped), datatype.Thousands(d.Truncated), lossNote()))
	}
	w.WriteString("\n")
	w.WriteString(readmeFiles(info))
	return w.String()
}

// gapWords says what a gap was.
func gapWords(g Gap) string {
	if g.Kind == GapListenerDown {
		return strings.ToUpper(g.Proto) + " " + g.Detail
	}
	return g.Detail
}
