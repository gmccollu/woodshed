package search

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
)

// bruteSummary counts recs (already filtered) the way a summary must.
type bruteSummary struct {
	n          int64
	dev        map[string]int64
	sev, fac   map[string]int64
	host, app  map[string]int64 // by folded key
	hostN, apN int64            // lines without one
	hist       map[int64]int64  // by bucket start
}

func newBrute() bruteSummary {
	return bruteSummary{dev: map[string]int64{}, sev: map[string]int64{}, fac: map[string]int64{}, host: map[string]int64{},
		app: map[string]int64{}, hist: map[int64]int64{}}
}

// bruteFrom is the brute-force count of recs at or after fromMs. A summary's
// counted_from only moves back from page to page, so it adds the newly
// covered records to the last count instead of recounting: checking every page
// of a many-page summary costs about one pass over recs in all. It recounts
// from scratch when fromMs moves forward or the bucket size changes.
type bruteFrom struct {
	sorted           []rec // newest first
	fromMs, bucketMs int64
	i                int // sorted[:i] are counted
	b                bruteSummary
}

func newBruteFrom(recs []rec) *bruteFrom {
	s := slices.Clone(recs)
	slices.SortStableFunc(s, func(a, b rec) int { return cmpInt(b.ms, a.ms) })
	return &bruteFrom{sorted: s}
}

func (c *bruteFrom) at(fromMs, bucketMs int64) bruteSummary {
	if c.b.dev == nil || fromMs > c.fromMs || bucketMs != c.bucketMs {
		c.b, c.i, c.bucketMs = newBrute(), 0, bucketMs
	}
	c.fromMs = fromMs
	for ; c.i < len(c.sorted) && c.sorted[c.i].ms >= fromMs; c.i++ {
		c.b.add(c.sorted[c.i], bucketMs)
	}
	return c.b
}

// add counts r, as a summary must.
func (b *bruteSummary) add(r rec, bucketMs int64) {
	b.n++
	b.dev[r.dev]++
	key := func(v int) string {
		if v == model.Unknown {
			return "unknown"
		}
		return fmt.Sprint(v)
	}
	b.sev[key(r.sev)]++
	b.fac[key(r.fac)]++
	if r.host == "" {
		b.hostN++
	} else {
		b.host[strings.ToLower(r.host)]++
	}
	if app := strings.TrimPrefix(r.app, "%"); app == "" {
		b.apN++
	} else {
		b.app[strings.ToLower(app)]++
	}
	b.hist[bucketStart(r.ms, bucketMs)]++
}

// checkSummary compares a summary response with the brute-force counts of
// the matching lines in [counted_from, to).
func checkSummary(t *testing.T, what string, s Summary, recs *bruteFrom) {
	t.Helper()
	from := s.CountedFrom.UnixMilli()
	b := recs.at(from, s.Histogram.BucketSeconds*1000)
	if s.Matched != b.n {
		t.Fatalf("%s: matched %d, brute force %d over [%s, %s)", what, s.Matched, b.n, s.CountedFrom.Format(time.RFC3339Nano), s.To.Format(time.RFC3339))
	}
	for _, fc := range s.Fields {
		want := map[string]map[string]int64{"device": b.dev, "severity": b.sev, "facility": b.fac, "host": b.host, "app": b.app}[fc.Key]
		var sum int64
		for _, v := range fc.Values {
			k := v.Value
			if fc.Key == "host" || fc.Key == "app" {
				k = foldKey(v.Value, fc.Key == "app")
			}
			if want[k] != v.Count {
				t.Fatalf("%s: %s %q = %d, brute force %d", what, fc.Key, v.Value, v.Count, want[k])
			}
			sum += v.Count
		}
		var none int64
		switch fc.Key {
		case "host":
			none = b.hostN
		case "app":
			none = b.apN
		}
		if fc.None != none || sum+fc.Other+fc.None != b.n {
			t.Fatalf("%s: %s none %d (want %d), listed %d + other %d + none, matched %d", what, fc.Key, fc.None, none, sum, fc.Other, b.n)
		}
		if fc.Key != "severity" && fc.Key != "facility" && fc.Distinct != len(want) {
			t.Fatalf("%s: %s distinct %d, want %d", what, fc.Key, fc.Distinct, len(want))
		}
	}
	if s.Histogram.Source == "scan" {
		var sum int64
		for _, bk := range s.Histogram.Buckets {
			end := bk.Start.UnixMilli() + s.Histogram.BucketSeconds*1000
			if bk.Count == nil {
				if end > from && s.NextCursor != "" || s.NextCursor == "" {
					t.Fatalf("%s: bucket %s is null but counted_from is %s", what, bk.Start, s.CountedFrom)
				}
				continue
			}
			if *bk.Count != b.hist[bk.Start.UnixMilli()] {
				t.Fatalf("%s: bucket %s = %d, brute force %d", what, bk.Start, *bk.Count, b.hist[bk.Start.UnixMilli()])
			}
			sum += *bk.Count
		}
		if sum != b.n {
			t.Fatalf("%s: histogram sums to %d, matched %d", what, sum, b.n)
		}
	}
}

// runSummary pages a summary to the end, checking every response.
func (f *fixture) runSummary(t *testing.T, what string, q SummaryQuery, want []rec) (Summary, int) {
	t.Helper()
	pages := 0
	last := q.To
	counts := newBruteFrom(want)
	for {
		s, err := f.eng.Summary(bg, q)
		if err != nil {
			t.Fatalf("%s: page %d: %v", what, pages, err)
		}
		pages++
		checkSummary(t, fmt.Sprintf("%s page %d", what, pages), s, counts)
		if !last.IsZero() && s.CountedFrom.After(last) {
			t.Fatalf("%s: counted_from went up", what)
		}
		last = s.CountedFrom
		if s.NextCursor == "" {
			if !s.CountedFrom.Equal(s.From) || s.Partial {
				t.Fatalf("%s: complete at %s, from %s, partial %v", what, s.CountedFrom, s.From, s.Partial)
			}
			return s, pages
		}
		q.Cursor = s.NextCursor
		if pages > 10000 {
			t.Fatalf("%s: no end", what)
		}
	}
}

func TestSummaryExact(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 3, 400)
	all := Filter{From: f.day0.Add(3 * time.Hour), To: f.day0.Add(70 * time.Hour)}
	cases := map[string]SummaryQuery{
		"everything":     {Filter: all},
		"text":           {Filter: withF(all, func(x *Filter) { x.Q = "seq=00" })},
		"terms":          {Filter: withF(all, func(x *Filter) { x.Terms = true; x.Q = `(deny OR accepted OR "link down") NOT seq=0001` })},
		"severities":     {Filter: withF(all, func(x *Filter) { x.Severities = sevs(0, 4, model.Unknown) })},
		"facilities":     {Filter: withF(all, func(x *Filter) { x.Facilities = facs(20, 4, 1) })},
		"apps":           {Filter: withF(all, func(x *Filter) { x.Apps = []string{"%FW-*", "sshd"} })},
		"exclude host":   {Filter: withF(all, func(x *Filter) { x.ExcludeHosts = []string{"host"}; x.ExcludeApps = []string{"kernel"} })},
		"group":          {Filter: all, Group: "HQ"},
		"exclude device": {Filter: all, ExcludeDevices: []string{"192.0.2.1"}},
		"hidden named":   {Filter: all, Devices: []string{"2001_db8__5", "192.0.2.2"}},
		"fields subset":  {Filter: all, Fields: []string{"host", "app"}, Bucket: 15 * time.Minute},
		"no histogram":   {Filter: withF(all, func(x *Filter) { x.Q = "seq" }), NoHistogram: true},
	}
	for _, steps := range []int{0, 3} {
		f.eng.testMaxSteps = steps
		for name, q := range cases {
			label := fmt.Sprintf("%s (steps %d)", name, steps)
			want := f.expect(Query{Filter: q.Filter, Devices: q.Devices, Group: q.Group, ExcludeDevices: q.ExcludeDevices})
			if len(want) == 0 {
				t.Fatalf("%s: nothing matches; the case tests nothing", label)
			}
			q.forceScan = true
			q.Top = MaxTop
			if q.NoHistogram {
				// checkSummary reads the bucket size from the histogram.
				s, err := f.eng.Summary(bg, q)
				if err != nil || s.Histogram != nil {
					t.Fatalf("%s: %v %+v", label, err, s.Histogram)
				}
				q.NoHistogram = false
			}
			s, pages := f.runSummary(t, label, q, want)
			if steps > 0 && pages < 3 {
				t.Errorf("%s: %d pages; the partial path isn't exercised", label, pages)
			}
			if s.Matched != int64(len(want)) {
				t.Errorf("%s: matched %d, want %d", label, s.Matched, len(want))
			}
		}
	}
}

func TestSummaryExactBigFixture(t *testing.T) {
	t.Parallel()
	f := newBigFixture(t)
	all := Filter{From: f.day0.Add(5 * time.Hour), To: f.day0.Add(47 * time.Hour)}
	for _, steps := range []int{0, 7} {
		f.eng.testMaxSteps = steps
		for name, flt := range map[string]Filter{
			"everything": all,
			"text":       withF(all, func(x *Filter) { x.Q = "seq=00" }),
			"terms":      withF(all, func(x *Filter) { x.Terms = true; x.Q = "deny OR built OR kernel" }),
		} {
			want := f.expect(Query{Filter: flt})
			_, pages := f.runSummary(t, fmt.Sprintf("%s (steps %d)", name, steps), SummaryQuery{Filter: flt, Top: MaxTop, forceScan: true}, want)
			if steps > 0 && pages < 5 {
				t.Errorf("%s: %d pages", name, pages)
			}
		}
	}
}

func withF(f Filter, fn func(*Filter)) Filter {
	fn(&f)
	return f
}

// TestSummaryHistogramIndexMatchesScan: on unfiltered data the index source
// (stats and checkpoints) gives exactly the scan's buckets.
func TestSummaryHistogramIndexMatchesScan(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 3, 400)
	end := f.day0.Add(72 * time.Hour) // the fixture's clock is just before this
	type tc struct {
		name   string
		now    time.Time
		q      SummaryQuery
		source string // what the index buckets should come from (for the log)
		exact  bool   // every bucket must equal the scan's
	}
	cases := []tc{
		{"1h on minutes (minute stats)", end, SummaryQuery{Filter: Filter{From: end.Add(-2 * time.Hour), To: end.Add(-time.Hour)}}, "minute", true},
		{"24h (minute stats)", end, SummaryQuery{Filter: Filter{From: end.Add(-24 * time.Hour), To: end}}, "minute", true},
		{"48h hourly (both tables)", end, SummaryQuery{Filter: Filter{From: end.Add(-48 * time.Hour), To: end}, Bucket: time.Hour}, "hour", true},
		{"3 days by day (stats)", end, SummaryQuery{Filter: Filter{From: f.day0, To: end}, Bucket: 24 * time.Hour}, "hour", true},
		{"3 days by day, 30 days later (checkpoints)", end.Add(30 * 24 * time.Hour), SummaryQuery{Filter: Filter{From: f.day0, To: end}, Bucket: 24 * time.Hour}, "checkpoints", true},
		{"group, 7d buckets", end, SummaryQuery{Filter: Filter{From: f.day0, To: end}, Group: "HQ", Bucket: 7 * 24 * time.Hour}, "hour", true},
		{"exclude device", end, SummaryQuery{Filter: Filter{From: end.Add(-24 * time.Hour), To: end}, ExcludeDevices: []string{"192.0.2.2"}}, "minute", true},
		{"hourly, 30 days later (checkpoints)", end.Add(30 * 24 * time.Hour), SummaryQuery{Filter: Filter{From: f.day0, To: end}, Bucket: time.Hour}, "checkpoints", false},
	}
	for _, c := range cases {
		eng := New(Options{DataDir: f.dir, Index: f.idx, Now: func() time.Time { return c.now }, Logger: quiet})
		q := c.q
		q.Fields = []string{}
		idx, err := eng.Summary(bg, q)
		if err != nil {
			t.Fatal(c.name, err)
		}
		if idx.Histogram.Source != "index" || idx.NextCursor != "" || idx.Partial || !idx.CountedFrom.Equal(idx.From) {
			t.Fatalf("%s: source %s cursor %q partial %v", c.name, idx.Histogram.Source, idx.NextCursor, idx.Partial)
		}
		q.forceScan = true
		var scan Summary
		for {
			if scan, err = eng.Summary(bg, q); err != nil {
				t.Fatal(c.name, err)
			}
			if scan.NextCursor == "" {
				break
			}
			q.Cursor = scan.NextCursor
		}
		if scan.Histogram.Source != "scan" || len(scan.Histogram.Buckets) != len(idx.Histogram.Buckets) {
			t.Fatalf("%s: %s, %d vs %d buckets", c.name, scan.Histogram.Source, len(scan.Histogram.Buckets), len(idx.Histogram.Buckets))
		}
		var si, ss int64
		for i, b := range idx.Histogram.Buckets {
			sb := scan.Histogram.Buckets[i]
			si, ss = si+*b.Count, ss+*sb.Count
			if !b.Start.Equal(sb.Start) {
				t.Fatalf("%s: bucket %d starts %s vs %s", c.name, i, b.Start, sb.Start)
			}
			if c.exact && (*b.Count != *sb.Count || b.Approx) {
				t.Errorf("%s: bucket %s index %d (approx %v), scan %d", c.name, b.Start, *b.Count, b.Approx, *sb.Count)
			}
			if !b.Approx && *b.Count != *sb.Count {
				t.Errorf("%s: bucket %s not approx but %d vs scan %d", c.name, b.Start, *b.Count, *sb.Count)
			}
		}
		if idx.Matched != si || d(si-ss) > int64(len(idx.Histogram.Buckets)) {
			t.Errorf("%s: index total %d (matched %d), scan %d", c.name, si, idx.Matched, ss)
		}
		if ss == 0 {
			t.Errorf("%s: nothing counted; the case tests nothing", c.name)
		}
	}
}

func d(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func TestSummaryIndexSkipsStatsBeforeOldestFile(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 3, 400)
	end := f.day0.Add(72 * time.Hour)
	// Retention took the first day's files of every device; their stats stay.
	files, _ := f.idx.Files(bg, "")
	var ops []index.FileOp
	for _, fl := range files {
		if fl.Day == f.day0.Format("2006-01-02") {
			ops = append(ops, index.FileOp{Kind: index.OpDelete, File: fl})
			if err := os.Remove(filepath.Join(f.dir, filepath.FromSlash(fl.Path))); err != nil {
				t.Fatal(err)
			}
		}
	}
	if len(ops) == 0 {
		t.Fatal("no first-day files")
	}
	if err := f.idx.Apply(bg, index.Batch{Files: ops}); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.idx.Counts(bg, nil, f.day0, f.day0.Add(24*time.Hour)); c.Msgs == 0 {
		t.Fatal("the stats should still have the first day")
	}
	eng := New(Options{DataDir: f.dir, Index: f.idx, Now: func() time.Time { return end }, Logger: quiet})
	q := SummaryQuery{Filter: Filter{From: f.day0, To: end}, Bucket: time.Hour, Fields: []string{}}
	idx, err := eng.Summary(bg, q)
	if err != nil {
		t.Fatal(err)
	}
	q.forceScan = true
	scan, _ := eng.Summary(bg, q)
	for scan.NextCursor != "" {
		q.Cursor = scan.NextCursor
		scan, _ = eng.Summary(bg, q)
	}
	for i, b := range idx.Histogram.Buckets {
		sb := scan.Histogram.Buckets[i]
		if b.Start.Before(f.day0.Add(24*time.Hour)) && *b.Count != 0 {
			t.Errorf("bucket %s from stats before the oldest file: %d", b.Start, *b.Count)
		}
		if !b.Approx && *b.Count != *sb.Count {
			t.Errorf("bucket %s: index %d, scan %d", b.Start, *b.Count, *sb.Count)
		}
	}
	if idx.Matched == 0 || d(idx.Matched-scan.Matched) > 2 {
		t.Errorf("index %d, scan %d", idx.Matched, scan.Matched)
	}
}

func TestSummaryCursorAndState(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 2, 300)
	clock := f.day0.Add(48 * time.Hour)
	f.clock.Set(clock)
	f.eng.testMaxSteps = 2
	q := SummaryQuery{Filter: Filter{From: f.day0, To: f.day0.Add(48 * time.Hour), Q: "seq"}}
	s, err := f.eng.Summary(bg, q)
	if err != nil || s.NextCursor == "" || !s.Partial {
		t.Fatalf("%v %+v", err, s)
	}
	var qe *QueryError
	// Every parameter is bound, the summary's own ones included.
	for i, change := range []func(q *SummaryQuery){
		func(q *SummaryQuery) { q.Q = "seq=" },
		func(q *SummaryQuery) { q.Terms = true },
		func(q *SummaryQuery) { q.Facilities = facs(4) },
		func(q *SummaryQuery) { q.Severities = sevs(4) },
		func(q *SummaryQuery) { q.ExcludeDevices = []string{"192.0.2.1"} },
		func(q *SummaryQuery) { q.ExcludeApps = []string{"x"} },
		func(q *SummaryQuery) { q.ExcludeHosts = []string{"x"} },
		func(q *SummaryQuery) { q.Apps = []string{"x"} },
		func(q *SummaryQuery) { q.Hosts = []string{"x"} },
		func(q *SummaryQuery) { q.Exclude = "x" },
		func(q *SummaryQuery) { q.Devices = []string{"192.0.2.1"} },
		func(q *SummaryQuery) { q.Group = "HQ" },
		func(q *SummaryQuery) { q.Ungrouped = true },
		func(q *SummaryQuery) { q.From = q.From.Add(time.Second) },
		func(q *SummaryQuery) { q.Fields = []string{"host"} },
		func(q *SummaryQuery) { q.Bucket = time.Hour },
		func(q *SummaryQuery) { q.NoHistogram = true },
	} {
		q2 := q
		q2.Cursor = s.NextCursor
		change(&q2)
		if _, err := f.eng.Summary(bg, q2); !errors.As(err, &qe) || !strings.Contains(qe.Msg, "different search") {
			t.Errorf("change %d: %v", i, err)
		}
	}
	// top and the budget may change between requests.
	q2 := q
	q2.Cursor, q2.Top, q2.Budget = s.NextCursor, 3, time.Second
	s2, err := f.eng.Summary(bg, q2)
	if err != nil {
		t.Fatal(err)
	}
	for _, fc := range s2.Fields {
		if fc.Key == "host" && len(fc.Values) > 3 {
			t.Errorf("top 3: %d values", len(fc.Values))
		}
	}
	// The used cursor is spent: its counts moved on.
	q2.Cursor = s.NextCursor
	if _, err := f.eng.Summary(bg, q2); !errors.Is(err, ErrSummaryExpired) {
		t.Errorf("reused cursor: %v", err)
	}
	// Running counts are kept for 10 minutes after the last request.
	q2.Cursor = s2.NextCursor
	f.clock.Set(clock.Add(SummaryTTL + time.Second))
	if _, err := f.eng.Summary(bg, q2); !errors.Is(err, ErrSummaryExpired) {
		t.Errorf("after the TTL: %v", err)
	}
	f.clock.Set(clock)
	// At most MaxSummaries; the least recently used goes first.
	var curs []string
	for i := 0; i <= MaxSummaries; i++ {
		s, err := f.eng.Summary(bg, q)
		if err != nil {
			t.Fatal(err)
		}
		curs = append(curs, s.NextCursor)
	}
	q2 = q
	q2.Cursor = curs[0]
	if _, err := f.eng.Summary(bg, q2); !errors.Is(err, ErrSummaryExpired) {
		t.Errorf("evicted: %v", err)
	}
	q2.Cursor = curs[MaxSummaries]
	if _, err := f.eng.Summary(bg, q2); err != nil {
		t.Errorf("newest: %v", err)
	}
	// A cancelled request stops and drops its counts.
	q2.Cursor = curs[MaxSummaries-1]
	ctx, cancel := context.WithCancel(bg)
	cancel()
	if _, err := f.eng.Summary(ctx, q2); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
	if _, err := f.eng.Summary(bg, q2); !errors.Is(err, ErrSummaryExpired) {
		t.Errorf("after cancel: %v", err)
	}
	// A tampered cursor is invalid.
	q2.Cursor = curs[MaxSummaries-2][:len(curs[MaxSummaries-2])-2] + "AA"
	if _, err := f.eng.Summary(bg, q2); !errors.As(err, &qe) || !strings.Contains(qe.Msg, "isn't valid") {
		t.Errorf("tampered: %v", err)
	}
}

func TestSummaryScanLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 1, 200)
	q := SummaryQuery{Filter: Filter{From: f.day0, To: f.day0.Add(24 * time.Hour), Q: "seq"}, Budget: 30 * time.Millisecond}
	// Two scans already running: a third waits within its budget and returns
	// what it has (nothing yet), with a cursor to continue.
	f.eng.sums.sem <- struct{}{}
	f.eng.sums.sem <- struct{}{}
	s, err := f.eng.Summary(bg, q)
	if err != nil || s.NextCursor == "" || s.Matched != 0 || !s.CountedFrom.Equal(s.To) || !s.Partial {
		t.Fatalf("%v %+v", err, s)
	}
	for _, b := range s.Histogram.Buckets {
		if b.Count != nil {
			t.Fatal("a bucket counted with no scan")
		}
	}
	<-f.eng.sums.sem
	<-f.eng.sums.sem
	q.Cursor, q.Budget = s.NextCursor, 0
	s, err = f.eng.Summary(bg, q)
	if err != nil || s.NextCursor != "" || s.Matched != int64(len(f.expect(Query{Filter: q.Filter}))) {
		t.Fatalf("%v %+v", err, s)
	}
}

func TestSummaryRequestErrors(t *testing.T) {
	t.Parallel()
	f := newFixture(t, 1, 50)
	day := Filter{From: f.day0, To: f.day0.Add(24 * time.Hour)}
	var qe *QueryError
	for _, c := range []struct {
		q    SummaryQuery
		want string
	}{
		{SummaryQuery{Filter: day, Fields: []string{"nope"}}, `fields: unknown field "nope".`},
		{SummaryQuery{Filter: day, Bucket: 7 * time.Second}, "bucket must be one of"},
		{SummaryQuery{Filter: day, Bucket: time.Minute}, "bucket=60 gives 1440 buckets"},
		{SummaryQuery{Filter: withF(day, func(x *Filter) { x.Q = "("; x.Terms = true })}, `Missing ")"`},
		{SummaryQuery{Filter: withF(day, func(x *Filter) { x.Q = "a"; x.Terms = true; x.Regex = true })}, ErrTermsWithRegex},
	} {
		if _, err := f.eng.Summary(bg, c.q); !errors.As(err, &qe) || !strings.Contains(qe.Msg, c.want) {
			t.Errorf("%+v: %v, want %q", c.q, err, c.want)
		}
	}
	// 1,000 buckets is the limit, not an error.
	if _, err := f.eng.Summary(bg, SummaryQuery{Filter: Filter{From: f.day0, To: f.day0.Add(1000 * time.Second)}, Bucket: time.Second}); err != nil {
		t.Error(err)
	}
	// Default bucket sizes (SPEC 10.1.2) and their counts for the presets.
	for _, c := range []struct {
		rng  time.Duration
		want time.Duration
	}{{15 * time.Minute, 15 * time.Second}, {time.Hour, time.Minute}, {24 * time.Hour, 15 * time.Minute}, {7 * 24 * time.Hour, 2 * time.Hour},
		{2 * time.Minute, time.Second}, {121 * time.Second, 5 * time.Second}, {200 * 24 * time.Hour, 7 * 24 * time.Hour}} {
		if got := DefaultBucket(c.rng); got != c.want {
			t.Errorf("DefaultBucket(%s) = %s, want %s", c.rng, got, c.want)
		}
	}
	// 7-day buckets start on Mondays, 00:00 UTC.
	mon := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	if got := bucketStart(mon.Add(3*24*time.Hour).UnixMilli(), 7*24*3600*1000); got != mon.UnixMilli() {
		t.Errorf("week bucket starts %s", time.UnixMilli(got).UTC())
	}
	// fields=none with an unfiltered query: the index histogram alone, complete at once.
	s, err := f.eng.Summary(bg, SummaryQuery{Filter: day, Fields: []string{}})
	if err != nil || s.Histogram.Source != "index" || s.NextCursor != "" {
		t.Fatalf("%v %+v", err, s)
	}
	var sum int64
	for _, b := range s.Histogram.Buckets {
		sum += *b.Count
	}
	// Every device's first file starts inside the first buckets, which are
	// spread from its (one) checkpoint, so they are approximate.
	if s.Matched != sum || d(sum-int64(len(f.expect(Query{Filter: day})))) > 5 {
		t.Fatalf("matched %d, histogram %d, lines %d", s.Matched, sum, len(f.expect(Query{Filter: day})))
	}
	// severities=none matches nothing, at once.
	s, err = f.eng.Summary(bg, SummaryQuery{Filter: withF(day, func(x *Filter) { x.Facilities = FacilityNone })})
	if err != nil || s.Matched != 0 || s.NextCursor != "" {
		t.Fatalf("%v %+v", err, s)
	}
}

func TestTallyCap(t *testing.T) {
	t.Parallel()
	tl := newTally()
	for i := 0; i < MaxDistinct+5; i++ {
		tl.add(tl.id(fmt.Sprintf("Host-%d", i), false))
	}
	tl.add(tl.id("HOST-1", false)) // tracked: the same key as Host-1
	tl.add(tl.id("", false))
	if len(tl.slots) != MaxDistinct || !tl.capped || tl.overflow != 5 || tl.none != 1 || tl.slots[1].n != 2 || tl.slots[1].value != "Host-1" {
		t.Fatalf("%d slots, capped %v, overflow %d, none %d, %+v", len(tl.slots), tl.capped, tl.overflow, tl.none, tl.slots[1])
	}
	if foldKey("%FW-6-1", true) != "fw-6-1" || foldKey("web-01", false) != "web-01" {
		t.Error("foldKey")
	}
	for v, want := range map[string]bool{"a,b": false, " a": false, "sshd": true, "ssh*": false} {
		if filterable(v, true) != want {
			t.Errorf("filterable(%q)", v)
		}
	}
}
