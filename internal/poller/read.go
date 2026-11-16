package poller

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The poll data for graphs (docs/api.md "Poll data for graphs"): series,
// timeline strips and the device panel, read from the headline rollups when
// they're enough, otherwise from one device's poll files for the window.

// Index is what the readers need from the index.
type Index interface {
	FilesInRangeOf(ctx context.Context, typ string, deviceIDs []string, from, to time.Time) ([]index.FileSpan, error)
	PollHourly(ctx context.Context, deviceID string, series []string, from, to time.Time) ([]pollrec.Hourly, error)
}

// Reader reads poll data.
type Reader struct {
	Idx     Index
	DataDir string
	// Budget bounds a file read (the summary's, 2 s by default); a read that
	// runs out is partial.
	Budget time.Duration
	Now    func() time.Time
}

// Limits.
const (
	MaxSeries          = 16
	MaxMarkersPerStrip = 100
	MaxStrips          = 4
	ChartedInterfaces  = 4
)

// Point is one bucket of a series ("count 0" is not measured: a gap).
type Point struct {
	Start time.Time `json:"start"`
	Avg   *float64  `json:"avg"`
	Max   *float64  `json:"max"`
	Count int64     `json:"count"`
}

// Series is one series' points.
type Series struct {
	Key    string  `json:"key"`
	Label  string  `json:"label"`
	Unit   string  `json:"unit"`
	Points []Point `json:"points"`
}

// Marker is a restart or an oper-status change.
type Marker struct {
	DeviceID string `json:"device_id,omitempty"`
	Time     string `json:"time"`
	Kind     string `json:"kind"` // "restart" or "oper"
	Reboot   string `json:"reboot,omitempty"`
	If       string `json:"if,omitempty"`
	Oper     string `json:"oper,omitempty"`
	Was      string `json:"was,omitempty"`
	Detail   string `json:"detail"`
	at       time.Time
}

// SeriesResult is GET /api/poll/series.
type SeriesResult struct {
	DeviceID      string   `json:"device_id"`
	BucketSeconds int64    `json:"bucket_seconds"`
	Source        string   `json:"source"` // "files" or "rollup"
	Series        []Series `json:"series"`
	Markers       []Marker `json:"markers"`
	Partial       bool     `json:"partial"`
	NextCursor    string   `json:"next_cursor"`
}

// SeriesError is a bad series request (a 400).
type SeriesError struct{ Msg string }

func (e *SeriesError) Error() string { return e.Msg }

var headlineLabels = map[string][2]string{
	pollrec.SeriesInBps:     {"In (all interfaces)", "bit/s"},
	pollrec.SeriesOutBps:    {"Out (all interfaces)", "bit/s"},
	pollrec.SeriesMaxIfIn:   {"In (busiest interface)", "bit/s"},
	pollrec.SeriesMaxIfOut:  {"Out (busiest interface)", "bit/s"},
	pollrec.SeriesErrorsD:   {"Errors (all interfaces)", "per cycle"},
	pollrec.SeriesDiscardsD: {"Discards (all interfaces)", "per cycle"},
	pollrec.SeriesCPU:       {"CPU", "%"},
	pollrec.SeriesMemPct:    {"Memory used", "%"},
	"uptime_s":              {"Uptime", "s"},
}

var ifMetrics = map[string][2]string{
	"in_bps": {"in", "bit/s"}, "out_bps": {"out", "bit/s"}, "in_err_d": {"in errors", "per cycle"},
	"out_err_d": {"out errors", "per cycle"}, "in_disc_d": {"in discards", "per cycle"},
	"out_disc_d": {"out discards", "per cycle"}, "oper": {"oper status", "1 up, 2 down"},
}

// seriesKey is a parsed series key.
type seriesKey struct {
	key    string
	kind   string // "head", "uptime", "if", "oid"
	ifName string // if.<name>.<metric>
	metric string
	oid    string // oid.<oid>[.<row>]: the full OID with the row
}

// ParseSeriesKeys checks a series= list (at most 16; unknown keys are a 400).
func ParseSeriesKeys(keys []string) ([]seriesKey, error) {
	if len(keys) == 0 {
		return nil, &SeriesError{"series: at least one series is needed."}
	}
	if len(keys) > MaxSeries {
		return nil, &SeriesError{fmt.Sprintf("series: at most %d series per request.", MaxSeries)}
	}
	var out []seriesKey
	for _, k := range keys {
		switch {
		case pollrec.IsHeadline(k):
			out = append(out, seriesKey{key: k, kind: "head"})
		case k == "uptime_s":
			out = append(out, seriesKey{key: k, kind: "uptime"})
		case strings.HasPrefix(k, "if."):
			rest := k[3:]
			i := strings.LastIndexByte(rest, '.')
			if i <= 0 {
				return nil, &SeriesError{fmt.Sprintf("series: %q isn't if.<ifName or index>.<metric>.", k)}
			}
			m := rest[i+1:]
			if _, ok := ifMetrics[m]; !ok {
				return nil, &SeriesError{fmt.Sprintf("series: %q: the metric is one of in_bps, out_bps, in_err_d, out_err_d, in_disc_d, out_disc_d, oper.", k)}
			}
			out = append(out, seriesKey{key: k, kind: "if", ifName: rest[:i], metric: m})
		case strings.HasPrefix(k, "oid."):
			o := k[4:]
			if _, err := strconv.ParseUint(strings.ReplaceAll(o, ".", ""), 10, 64); err != nil && !allDigitsDots(o) {
				return nil, &SeriesError{fmt.Sprintf("series: %q isn't oid.<oid>[.<row>].", k)}
			}
			out = append(out, seriesKey{key: k, kind: "oid", oid: o})
		default:
			return nil, &SeriesError{fmt.Sprintf("series: %q is not a series (in_bps, out_bps, max_if_in_bps, max_if_out_bps, errors_d, discards_d, cpu, mem_used_pct, uptime_s, if.<ifName>.<metric>, oid.<oid>).", k)}
		}
	}
	return out, nil
}

func allDigitsDots(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if (s[i] < '0' || s[i] > '9') && s[i] != '.' {
			return false
		}
	}
	return true
}

func (k seriesKey) label() (string, string) {
	switch k.kind {
	case "head", "uptime":
		l := headlineLabels[k.key]
		return l[0], l[1]
	case "if":
		m := ifMetrics[k.metric]
		return k.ifName + " " + m[0], m[1]
	}
	return k.oid, ""
}

// weekOrigin puts 7-day buckets on Mondays (as the summary does).
const weekOrigin = 4 * 24 * 3600 * 1000

func bucketStart(t time.Time, size time.Duration) time.Time {
	ms, sz := t.UnixMilli(), size.Milliseconds()
	off := int64(0)
	if size == 7*24*time.Hour {
		off = weekOrigin
	}
	q := (ms - off) / sz
	if (ms-off)%sz != 0 && ms-off < 0 {
		q--
	}
	return time.UnixMilli(q*sz + off).UTC()
}

// buckets is a series' accumulators over the window.
type buckets struct {
	from  time.Time
	size  time.Duration
	n     int
	sum   []float64
	max   []float64
	count []int64
}

func newBuckets(from, to time.Time, size time.Duration) *buckets {
	first := bucketStart(from, size)
	n := int(bucketStart(to.Add(-time.Millisecond), size).Sub(first)/size) + 1
	n = max(n, 0)
	return &buckets{from: first, size: size, n: n, sum: make([]float64, n), max: make([]float64, n), count: make([]int64, n)}
}

func (b *buckets) add(t time.Time, v float64) {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return
	}
	i := int(bucketStart(t, b.size).Sub(b.from) / b.size)
	if i < 0 || i >= b.n {
		return
	}
	if b.count[i] == 0 || v > b.max[i] {
		b.max[i] = v
	}
	b.sum[i] += v
	b.count[i]++
}

func (b *buckets) addAgg(t time.Time, sum, mx float64, count int64) {
	i := int(bucketStart(t, b.size).Sub(b.from) / b.size)
	if i < 0 || i >= b.n || count == 0 {
		return
	}
	if b.count[i] == 0 || mx > b.max[i] {
		b.max[i] = mx
	}
	b.sum[i] += sum
	b.count[i] += count
}

func (b *buckets) points() []Point {
	out := make([]Point, b.n)
	for i := range out {
		out[i].Start = b.from.Add(time.Duration(i) * b.size)
		if c := b.count[i]; c > 0 {
			avg, mx := b.sum[i]/float64(c), b.max[i]
			out[i].Avg, out[i].Max, out[i].Count = &avg, &mx, c
		}
	}
	return out
}

// scan reads a device's poll records in [from, to), calling fn for each, in
// file order. It stops at the budget (partial, with the time it got to).
func (r *Reader) scan(ctx context.Context, device string, from, to time.Time, filter func(line []byte) bool,
	fn func(at time.Time, rec *pollrec.Record)) (partial bool, reached time.Time, err error) {
	spans, err := r.Idx.FilesInRangeOf(ctx, logfile.TypePoll, []string{device}, from, to)
	if err != nil {
		return false, time.Time{}, err
	}
	budget := r.Budget
	if budget <= 0 {
		budget = 2 * time.Second
	}
	deadline := time.Now().Add(budget)
	var buf []byte
	for _, sp := range spans {
		if err := ctx.Err(); err != nil {
			return false, time.Time{}, err
		}
		f, err := logfile.OpenAt(filepath.Join(r.DataDir, filepath.FromSlash(sp.Path)), sp.Start.Offset)
		if errors.Is(err, os.ErrNotExist) {
			continue // compressed or deleted meanwhile
		}
		if err != nil {
			return false, time.Time{}, err
		}
		br := bufio.NewReaderSize(f, 256<<10)
		n := 0
		for {
			line, rerr := br.ReadSlice('\n')
			if errors.Is(rerr, bufio.ErrBufferFull) {
				buf = append(buf[:0], line...)
				for errors.Is(rerr, bufio.ErrBufferFull) {
					line, rerr = br.ReadSlice('\n')
					buf = append(buf, line...)
				}
				line = buf
			}
			if len(line) > 0 && line[len(line)-1] == '\n' && (filter == nil || filter(line)) {
				if l, perr := logfile.ParseLine(line); perr == nil && !l.Received.Before(from) && l.Received.Before(to) {
					if rec, perr := pollrec.Parse(l.Raw()); perr == nil {
						fn(l.Received, &rec)
					}
				}
			}
			if rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					f.Close()
					return false, time.Time{}, rerr
				}
				break
			}
			if n++; n%4096 == 0 && time.Now().After(deadline) {
				f.Close()
				if l, perr := logfile.ParseLine(line); perr == nil {
					return true, l.Received, nil
				}
				return true, from, nil
			}
		}
		f.Close()
	}
	return false, to, nil
}

var (
	restartTag = []byte(" kind=restart ")
	operWasTag = []byte(" oper_was=")
)

// restartLines and markerLines are cheap prefilters on the stored line.
func restartLines(line []byte) bool { return bytes.Contains(line, restartTag) }
func markerLines(line []byte) bool {
	return bytes.Contains(line, restartTag) || bytes.Contains(line, operWasTag)
}

// cycleFeed groups a scan's records into cycles for the headline series.
type cycleFeed struct {
	dev string
	cur *pollrec.Cycle
	out func(c *pollrec.Cycle)
}

func (f *cycleFeed) add(at time.Time, rec *pollrec.Record) {
	if rec.Kind != pollrec.KindSys && rec.Kind != pollrec.KindIf {
		return
	}
	if f.cur == nil || f.cur.Cycle != rec.Cycle {
		f.flush()
		f.cur = pollrec.NewCycle(f.dev, rec.Cycle, at)
	}
	f.cur.Add(rec)
}

func (f *cycleFeed) flush() {
	if f.cur != nil {
		f.out(f.cur)
		f.cur = nil
	}
}

// restartMarker builds a restart line's marker.
func restartMarker(dev string, at time.Time, rec *pollrec.Record) Marker {
	// The same reasons, in the same words, as the bundle README (datatype.RestartDetail).
	detail := "agent restart"
	if parts := pollrec.RestartReasons(rec); len(parts) > 0 {
		detail = strings.Join(parts, ", ")
	}
	if rec.Value("reboot") == "?" {
		detail += " (the device may have rebooted)"
	}
	return Marker{DeviceID: dev, Time: at.UTC().Format("2006-01-02T15:04:05.000Z"), Kind: "restart", Reboot: rec.Value("reboot"), Detail: detail, at: at}
}

func operMarker(dev string, at time.Time, rec *pollrec.Record) Marker {
	name := pollrec.IfName(rec)
	return Marker{DeviceID: dev, Time: at.UTC().Format("2006-01-02T15:04:05.000Z"), Kind: "oper", If: name, Oper: rec.Value("oper"),
		Was: rec.Value("oper_was"), Detail: fmt.Sprintf("%s %s (was %s)", name, rec.Value("oper"), rec.Value("oper_was")), at: at}
}

// SeriesQuery is a series request.
type SeriesQuery struct {
	Device   string
	From, To time.Time
	Bucket   time.Duration
	Keys     []string
	Cursor   string
}

// Series reads a device's series.
func (r *Reader) Series(ctx context.Context, q SeriesQuery) (SeriesResult, error) {
	keys, err := ParseSeriesKeys(q.Keys)
	if err != nil {
		return SeriesResult{}, err
	}
	from := q.From
	if q.Cursor != "" {
		c, err := parseCursor(q.Cursor)
		if err != nil || c.Before(q.From) || !c.Before(q.To) {
			return SeriesResult{}, &SeriesError{"cursor: not a cursor for this range."}
		}
		from = c
	}
	res := SeriesResult{DeviceID: q.Device, BucketSeconds: int64(q.Bucket / time.Second), Source: "files", Markers: []Marker{}}
	bs := make([]*buckets, len(keys))
	for i := range keys {
		bs[i] = newBuckets(q.From, q.To, q.Bucket)
	}
	allHead := true
	ifs := map[string]bool{}
	for _, k := range keys {
		if k.kind != "head" {
			allHead = false
		}
		if k.kind == "if" {
			ifs[k.ifName] = true
		}
	}
	if allHead && q.Bucket >= time.Hour {
		res.Source = "rollup"
		var names []string
		for _, k := range keys {
			names = append(names, k.key)
		}
		rows, err := r.Idx.PollHourly(ctx, q.Device, names, q.From, q.To)
		if err != nil {
			return res, err
		}
		for _, h := range rows {
			if h.Hour.Before(bucketStart(q.From, time.Hour)) || !h.Hour.Before(q.To) {
				continue
			}
			for i, k := range keys {
				if k.key == h.Series {
					bs[i].addAgg(h.Hour, h.Sum, h.Max, h.Count)
				}
			}
		}
		// Markers still come from the files: restart lines only (cheap prefilter).
		partial, reached, err := r.scan(ctx, q.Device, from, q.To, restartLines, func(at time.Time, rec *pollrec.Record) {
			if rec.Kind == pollrec.KindRestart && len(res.Markers) < MaxMarkersPerStrip {
				res.Markers = append(res.Markers, restartMarker("", at, rec))
			}
		})
		if err != nil {
			return res, err
		}
		res.Partial, res.NextCursor = partial, cursorAt(partial, reached)
	} else {
		feed := &cycleFeed{dev: q.Device, out: func(c *pollrec.Cycle) {
			vals := c.Values()
			for i, k := range keys {
				if k.kind == "head" {
					if v, ok := vals[k.key]; ok {
						bs[i].add(c.At, v)
					}
				}
			}
		}}
		partial, reached, err := r.scan(ctx, q.Device, from, q.To, nil, func(at time.Time, rec *pollrec.Record) {
			feed.add(at, rec)
			switch rec.Kind {
			case pollrec.KindRestart:
				if len(res.Markers) < MaxMarkersPerStrip {
					res.Markers = append(res.Markers, restartMarker("", at, rec))
				}
			case pollrec.KindSys:
				if v, ok := rec.Float("uptime"); ok {
					for i, k := range keys {
						if k.kind == "uptime" {
							bs[i].add(at, v/100)
						}
					}
				}
			case pollrec.KindIf:
				name, idx := rec.Value("name"), rec.Value("if")
				if !ifs[name] && !ifs[idx] {
					return
				}
				if rec.Value("oper_was") != "" && len(res.Markers) < MaxMarkersPerStrip {
					res.Markers = append(res.Markers, operMarker("", at, rec))
				}
				for i, k := range keys {
					if k.kind != "if" || (k.ifName != name && k.ifName != idx) {
						continue
					}
					if k.metric == "oper" {
						if o := rec.Value("oper"); o != "" {
							bs[i].add(at, float64(slices.Index(pollrec.OperNames, o)+1))
						}
					} else if v, ok := rec.Float(k.metric); ok {
						bs[i].add(at, v)
					}
				}
			case pollrec.KindOID:
				full := rec.Value("oid")
				if row := rec.Value("row"); row != "" {
					full += "." + row
				}
				for i, k := range keys {
					if k.kind != "oid" || (k.oid != full && k.oid != rec.Value("oid")) {
						continue
					}
					if v, ok := rec.Float("rate"); ok {
						bs[i].add(at, v)
					} else if t := rec.Value("type"); t == "int" || t == "g32" || t == "ticks" {
						if v, ok := rec.Float("value"); ok {
							bs[i].add(at, v)
						}
					}
				}
			}
		})
		feed.flush()
		if err != nil {
			return res, err
		}
		res.Partial, res.NextCursor = partial, cursorAt(partial, reached)
	}
	for i, k := range keys {
		label, unit := k.label()
		res.Series = append(res.Series, Series{Key: k.key, Label: label, Unit: unit, Points: bs[i].points()})
	}
	sortMarkers(res.Markers)
	return res, nil
}

func sortMarkers(ms []Marker) {
	sort.SliceStable(ms, func(i, j int) bool { return ms[i].at.Before(ms[j].at) })
}

func cursorAt(partial bool, t time.Time) string {
	if !partial {
		return ""
	}
	return "t" + strconv.FormatInt(t.UnixMilli(), 10)
}

func parseCursor(s string) (time.Time, error) {
	if !strings.HasPrefix(s, "t") {
		return time.Time{}, errors.New("bad cursor")
	}
	n, err := strconv.ParseInt(s[1:], 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.UnixMilli(n).UTC(), nil
}

// ---- the device panel ----

// Peak is a value now and its peak in the range.
type Peak struct {
	Now    *float64   `json:"now"`
	Peak   *float64   `json:"peak"`
	PeakAt *time.Time `json:"peak_at"`
}

func (p *Peak) add(at time.Time, v float64) {
	vv := v
	p.Now = &vv
	if p.Peak == nil || v > *p.Peak {
		pk, t := v, at.UTC()
		p.Peak, p.PeakAt = &pk, &t
	}
}

// PanelSystem is the panel's system part.
type PanelSystem struct {
	SysName     string     `json:"sys_name"`
	SysDescr    string     `json:"sys_descr"`
	UptimeS     *float64   `json:"uptime_s"`
	LastRestart *time.Time `json:"last_restart"`
	CPU         Peak       `json:"cpu"`
	MemUsedPct  Peak       `json:"mem_used_pct"`
}

// PanelInterface is one row of the interface table.
type PanelInterface struct {
	Index       int      `json:"index"`
	Name        string   `json:"name"`
	Alias       string   `json:"alias"`
	Oper        string   `json:"oper"`
	SpeedMbps   *uint64  `json:"speed_mbps"`
	InBps       *float64 `json:"in_bps"`
	OutBps      *float64 `json:"out_bps"`
	PeakInBps   *float64 `json:"peak_in_bps"`
	PeakOutBps  *float64 `json:"peak_out_bps"`
	InErrD      int64    `json:"in_err_d"`
	OutErrD     int64    `json:"out_err_d"`
	InDiscD     int64    `json:"in_disc_d"`
	OutDiscD    int64    `json:"out_disc_d"`
	OperChanges int      `json:"oper_changes"`
	Bits32      bool     `json:"bits_32,omitempty"`
}

// Panel is GET /api/poll/device/{id}.
type Panel struct {
	DeviceID          string           `json:"device_id"`
	TargetID          string           `json:"target_id"`
	Address           string           `json:"address"`
	System            PanelSystem      `json:"system"`
	Interfaces        []PanelInterface `json:"interfaces"`
	Charted           []string         `json:"charted"`
	InterfacesLeftOut int              `json:"interfaces_left_out"`
	HCCounters        *bool            `json:"hc_counters"`
	HostResources     *bool            `json:"host_resources"`
	LastCycle         *time.Time       `json:"last_cycle"`
	RTTms             *int64           `json:"rtt_ms"`
	Markers           []Marker         `json:"markers"`
	Partial           bool             `json:"partial"`
}

// Panel reads the device panel for [from, to).
func (r *Reader) Panel(ctx context.Context, device string, from, to time.Time) (Panel, error) {
	p := Panel{DeviceID: device, Interfaces: []PanelInterface{}, Charted: []string{}, Markers: []Marker{}}
	ifs := map[int]*PanelInterface{}
	alias := map[int]string{}
	get := func(idx int) *PanelInterface {
		pi := ifs[idx]
		if pi == nil {
			pi = &PanelInterface{Index: idx}
			ifs[idx] = pi
		}
		return pi
	}
	var total, polled int64 = -1, -1
	var lastCycle time.Time
	feed := &cycleFeed{dev: device, out: func(c *pollrec.Cycle) {
		v := c.Values()
		if x, ok := v[pollrec.SeriesCPU]; ok {
			p.System.CPU.add(c.At, x)
		}
		if x, ok := v[pollrec.SeriesMemPct]; ok {
			p.System.MemUsedPct.add(c.At, math.Round(x*10)/10)
		}
	}}
	partial, _, err := r.scan(ctx, device, from, to, nil, func(at time.Time, rec *pollrec.Record) {
		feed.add(at, rec)
		switch rec.Kind {
		case pollrec.KindSys:
			if v, ok := rec.Float("uptime"); ok {
				u := v / 100
				p.System.UptimeS = &u
			}
			if v, ok := rec.Uint("rtt_ms"); ok {
				n := int64(v)
				p.RTTms = &n
			}
			lastCycle = at
		case pollrec.KindRestart:
			t := at.UTC()
			p.System.LastRestart = &t
			if len(p.Markers) < MaxMarkersPerStrip {
				p.Markers = append(p.Markers, restartMarker("", at, rec))
			}
		case pollrec.KindInfo:
			if idx, ok := rec.Uint("if"); ok {
				alias[int(idx)] = rec.Value("alias")
				pi := get(int(idx))
				if n := rec.Value("name"); n != "" {
					pi.Name = n
				}
				if s, ok := rec.Uint("speed_mbps"); ok {
					pi.SpeedMbps = &s
				}
				return
			}
			if v := rec.Value("sys_name"); v != "" {
				p.System.SysName = v
			}
			if v := rec.Value("sys_descr"); v != "" {
				p.System.SysDescr = v
			}
			if v, ok := rec.Get("hc"); ok {
				b := v == "1"
				p.HCCounters = &b
			}
			if v, ok := rec.Get("hr"); ok {
				b := v == "1"
				p.HostResources = &b
			}
			if v, ok := rec.Uint("ifs_total"); ok {
				total = int64(v)
			}
			if v, ok := rec.Uint("ifs_polled"); ok {
				polled = int64(v)
			}
		case pollrec.KindIf:
			idx, ok := rec.Uint("if")
			if !ok {
				return
			}
			pi := get(int(idx))
			if n := rec.Value("name"); n != "" {
				pi.Name = n
			}
			if o := rec.Value("oper"); o != "" {
				pi.Oper = o
			}
			if rec.Value("oper_was") != "" {
				pi.OperChanges++
				if len(p.Markers) < MaxMarkersPerStrip {
					p.Markers = append(p.Markers, operMarker("", at, rec))
				}
			}
			if s, ok := rec.Uint("speed_mbps"); ok {
				pi.SpeedMbps = &s
			}
			pi.Bits32 = rec.Value("bits") == "32"
			pi.InBps, pi.OutBps = nil, nil
			if v, ok := rec.Float("in_bps"); ok {
				pi.InBps = &v
				if pi.PeakInBps == nil || v > *pi.PeakInBps {
					pk := v
					pi.PeakInBps = &pk
				}
			}
			if v, ok := rec.Float("out_bps"); ok {
				pi.OutBps = &v
				if pi.PeakOutBps == nil || v > *pi.PeakOutBps {
					pk := v
					pi.PeakOutBps = &pk
				}
			}
			for key, dst := range map[string]*int64{"in_err_d": &pi.InErrD, "out_err_d": &pi.OutErrD, "in_disc_d": &pi.InDiscD, "out_disc_d": &pi.OutDiscD} {
				if v, ok := rec.Uint(key); ok {
					*dst += int64(v)
				}
			}
		}
	})
	feed.flush()
	if err != nil {
		return p, err
	}
	p.Partial = partial
	for idx, a := range alias {
		if pi := ifs[idx]; pi != nil {
			pi.Alias = a
		}
	}
	for _, pi := range ifs {
		if pi.Name == "" {
			pi.Name = strconv.Itoa(pi.Index)
		}
		p.Interfaces = append(p.Interfaces, *pi)
	}
	peak := func(pi PanelInterface) float64 {
		v := 0.0
		if pi.PeakInBps != nil {
			v += *pi.PeakInBps
		}
		if pi.PeakOutBps != nil {
			v += *pi.PeakOutBps
		}
		return v
	}
	sort.SliceStable(p.Interfaces, func(i, j int) bool {
		a, b := peak(p.Interfaces[i]), peak(p.Interfaces[j])
		if a != b {
			return a > b
		}
		return p.Interfaces[i].Index < p.Interfaces[j].Index
	})
	for i := 0; i < len(p.Interfaces) && i < ChartedInterfaces; i++ {
		p.Charted = append(p.Charted, p.Interfaces[i].Name)
	}
	if total >= 0 && polled >= 0 && total > polled {
		p.InterfacesLeftOut = int(total - polled)
	}
	if !lastCycle.IsZero() {
		t := lastCycle.UTC()
		p.LastCycle = &t
	}
	sortMarkers(p.Markers)
	return p, nil
}

// ---- the timeline strips ----

// TimelineDevice is one device's strips.
type TimelineDevice struct {
	DeviceID string   `json:"device_id"`
	Series   []Series `json:"series"`
}

// Timeline is GET /api/poll/timeline.
type Timeline struct {
	BucketSeconds int64            `json:"bucket_seconds"`
	Devices       []TimelineDevice `json:"devices"`
	Markers       []Marker         `json:"markers"`
	More          int              `json:"more"`
	Partial       bool             `json:"partial"`
}

// Timeline reads the strips for the polled devices among those selected: one
// device gets total in/out, CPU and errors; several get total in/out each, at
// most 4 (the busiest by peak traffic in the range), with the rest counted in
// More. Restart and oper markers come for every selected polled device.
func (r *Reader) Timeline(ctx context.Context, devices []string, from, to time.Time, bucket time.Duration) (Timeline, error) {
	tl := Timeline{BucketSeconds: int64(bucket / time.Second), Devices: []TimelineDevice{}, Markers: []Marker{}}
	if len(devices) == 0 {
		return tl, nil
	}
	chosen := devices
	if len(devices) > 1 {
		type ranked struct {
			id   string
			peak float64
		}
		var rs []ranked
		for _, d := range devices {
			rows, err := r.Idx.PollHourly(ctx, d, []string{pollrec.SeriesInBps, pollrec.SeriesOutBps}, from, to)
			if err != nil {
				return tl, err
			}
			pk := 0.0
			for _, h := range rows {
				pk = max(pk, h.Max)
			}
			rs = append(rs, ranked{d, pk})
		}
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].peak != rs[j].peak {
				return rs[i].peak > rs[j].peak
			}
			return rs[i].id < rs[j].id
		})
		chosen = nil
		for i, x := range rs {
			if i < MaxStrips {
				chosen = append(chosen, x.id)
			}
		}
		tl.More = max(len(rs)-MaxStrips, 0)
	}
	keys := []string{pollrec.SeriesInBps, pollrec.SeriesOutBps}
	if len(devices) == 1 {
		keys = append(keys, pollrec.SeriesCPU, pollrec.SeriesErrorsD)
	}
	for _, d := range chosen {
		sr, err := r.Series(ctx, SeriesQuery{Device: d, From: from, To: to, Bucket: bucket, Keys: keys})
		if err != nil {
			return tl, err
		}
		tl.Partial = tl.Partial || sr.Partial
		tl.Devices = append(tl.Devices, TimelineDevice{DeviceID: d, Series: sr.Series})
	}
	for _, d := range devices {
		n := 0
		partial, _, err := r.scan(ctx, d, from, to, markerLines, func(at time.Time, rec *pollrec.Record) {
			if n >= MaxMarkersPerStrip {
				return
			}
			switch {
			case rec.Kind == pollrec.KindRestart:
				tl.Markers = append(tl.Markers, restartMarker(d, at, rec))
				n++
			case rec.Kind == pollrec.KindIf && rec.Value("oper_was") != "":
				tl.Markers = append(tl.Markers, operMarker(d, at, rec))
				n++
			}
		})
		if err != nil {
			return tl, err
		}
		tl.Partial = tl.Partial || partial
	}
	sortMarkers(tl.Markers)
	return tl, nil
}
