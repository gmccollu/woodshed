package search

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/syslog"
)

var bg = context.Background()

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

// rec is one message the fixture wrote, with what syslog.Parse makes of it
// (parsed once here, so the brute-force checks don't parse every line again
// for every query and every page).
type rec struct {
	ms    int64
	dev   string
	raw   string
	seq   int
	lower string // strings.ToLower(raw)
	sev   int
	fac   int
	host  string
	app   string
}

func newRec(ms int64, dev, raw string, seq int) rec {
	var m model.Message
	syslog.Parse([]byte(raw), &m)
	return rec{ms: ms, dev: dev, raw: raw, seq: seq, lower: strings.ToLower(raw), sev: m.Severity, fac: m.Facility,
		host: m.Hostname, app: m.App}
}

type fixture struct {
	t     testing.TB
	dir   string
	idx   *index.DB
	st    *store.Store
	clock *fakeClock
	recs  []rec
	eng   *Engine
	day0  time.Time
	devs  []netip.Addr
}

var (
	devA = netip.MustParseAddr("192.0.2.1")
	devB = netip.MustParseAddr("192.0.2.2")
	devC = netip.MustParseAddr("198.51.100.7")
	devH = netip.MustParseAddr("2001:db8::5") // hidden
)

// newFixture writes perDay messages per device per day for days days through a
// real store with small parts, so the data dir has compressed parts and day
// files, and plain active files on the last day. Devices A and B are in group
// HQ, C has no group and H is hidden.
func newFixture(t testing.TB, days, perDay int) *fixture {
	t.Helper()
	return newFixtureParts(t, days, perDay, 16<<10)
}

// newBigFixture has files large enough for many checkpoints (one every ~64 KiB
// written over more than a minute), so time ranges seek inside files.
func newBigFixture(t testing.TB) *fixture {
	t.Helper()
	if testing.Short() {
		t.Skip("big fixture")
	}
	return newFixtureParts(t, 2, 10000, 512<<10)
}

func newFixtureParts(t testing.TB, days, perDay int, partBytes int64) *fixture {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(dir + "/" + index.FileName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	day0 := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: day0}
	st, err := store.Open(store.Options{
		DataDir: dir, Index: idx, PartBytes: partBytes, Manual: true, Clock: clock.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, dir: dir, idx: idx, st: st, clock: clock, day0: day0, devs: []netip.Addr{devA, devB, devC, devH}}
	t.Cleanup(func() { st.Close() })
	seq := 0
	for d := 0; d < days; d++ {
		start := day0.Add(time.Duration(d) * 24 * time.Hour)
		clock.Set(start.Add(time.Second))
		if err := st.Maintain(); err != nil {
			t.Fatal(err)
		}
		step := (24 * time.Hour) / time.Duration(perDay*len(f.devs)+1)
		at := start.Add(time.Second)
		for i := 0; i < perDay; i++ {
			for _, a := range f.devs {
				at = at.Add(step)
				f.write(a, at, seq)
				seq++
			}
			if i%max(perDay/6, 1) == 0 {
				clock.Set(at)
				if err := st.Maintain(); err != nil {
					t.Fatal(err)
				}
			}
		}
		clock.Set(at)
		if err := st.Maintain(); err != nil {
			t.Fatal(err)
		}
	}
	f.flush()
	for _, a := range []netip.Addr{devA, devB} {
		g := "HQ"
		if _, err := idx.UpdateDevice(bg, model.DeviceID(a), index.DeviceUpdate{Group: &g}); err != nil {
			t.Fatal(err)
		}
	}
	yes := true
	if _, err := idx.UpdateDevice(bg, model.DeviceID(devH), index.DeviceUpdate{Hidden: &yes}); err != nil {
		t.Fatal(err)
	}
	f.eng = New(Options{DataDir: dir, Index: idx, Now: clock.Now, Logger: quiet, block: 4 << 10})
	return f
}

// msgText makes a varied message for seq.
func msgText(seq int) string {
	sev := seq % 8
	switch seq % 13 {
	case 0:
		return fmt.Sprintf("no pri: Link down seq=%06d", seq)
	case 1:
		return fmt.Sprintf("<%d>host app: multi\nline\r\nmsg seq=%06d", 8+sev, seq)
	case 2:
		return fmt.Sprintf(`<%d>host app: path C:\temp\new seq=%06d \n literal`, 16+sev, seq)
	case 3:
		return fmt.Sprintf("<%d>host app: Ünïcode WARNING seq=%06d", 24+sev, seq)
	case 4:
		return fmt.Sprintf("\xef\xbb\xbf<%d>1 2026-11-10T00:00:00Z host app - - - Link DOWN on port %d seq=%06d", sev, seq%48, seq)
	case 5:
		return fmt.Sprintf("<999>bad pri seq=%06d", seq)
	case 6:
		return fmt.Sprintf("<%d>Nov 10 00:00:00 edge-fw-01 %%FW-6-302013: Built conn seq=%06d", 160+sev, seq)
	case 7:
		return fmt.Sprintf("<%d>Nov 10 00:00:00 Edge-FW-02 : %%FW-4-106023: Deny tcp seq=%06d", 160+sev, seq)
	case 8:
		return fmt.Sprintf("<%d>Nov 10 00:00:00 Web-01 sshd[42]: Accepted publickey seq=%06d", 32+sev, seq)
	case 9:
		return fmt.Sprintf("<%d>Nov 10 00:00:00 web-02 kernel: eth0 link up seq=%06d", sev, seq)
	}
	return fmt.Sprintf("<%d>Nov 10 00:00:00 host app[%d]: conn opened tcp 203.0.113.%d seq=%06d", 128+sev, seq%7, seq%250, seq)
}

func (f *fixture) write(a netip.Addr, at time.Time, seq int) {
	raw := msgText(seq)
	if err := f.st.Write(model.Message{Received: at, Sender: a, Raw: []byte(raw)}); err != nil {
		f.t.Fatal(err)
	}
	f.recs = append(f.recs, newRec(at.UnixMilli(), model.DeviceID(a), raw, seq))
}

func (f *fixture) flush() {
	if err := f.st.Flush(); err != nil {
		f.t.Fatal(err)
	}
	if err := f.st.Maintain(); err != nil {
		f.t.Fatal(err)
	}
}

// expect is the brute-force answer to q over everything written.
func (f *fixture) expect(q Query) []rec {
	fromMs, toMs, err := f.eng.resolveRange(q.Filter)
	if err != nil {
		f.t.Fatal(err)
	}
	devs := map[string]bool{}
	named := map[string]bool{}
	for _, d := range q.Devices {
		named[d] = true
	}
	dropped := map[string]bool{}
	for _, d := range q.ExcludeDevices {
		dropped[d] = true
	}
	for _, a := range f.devs {
		id := model.DeviceID(a)
		group := ""
		if a == devA || a == devB {
			group = "HQ"
		}
		if len(named) > 0 && !named[id] || len(named) == 0 && a == devH {
			continue
		}
		if q.Group != "" && group != q.Group || q.Ungrouped && group != "" || dropped[id] {
			continue
		}
		devs[id] = true
	}
	// textMatch is q's rule for any needle, for Q and for Exclude. It's built
	// once per needle (the terms tree, the regex), then run on each record.
	textMatch := func(needle string) func(r rec) bool {
		switch {
		case q.Terms:
			// The tree from the parser (its grammar is tested on its own), with
			// each term matched as text mode matches q.
			e, err := parseTerms(needle, q.Case)
			if err != nil {
				f.t.Fatal(err)
			}
			if e == nil {
				return func(rec) bool { return true }
			}
			var eval func(n *termNode, r *rec) bool
			eval = func(n *termNode, r *rec) bool {
				switch n.op {
				case opTerm:
					if q.Case {
						return strings.Contains(r.raw, n.text)
					}
					return strings.Contains(r.lower, strings.ToLower(n.text))
				case opNot:
					return !eval(n.kids[0], r)
				case opAnd:
					for _, k := range n.kids {
						if !eval(k, r) {
							return false
						}
					}
					return true
				}
				for _, k := range n.kids {
					if eval(k, r) {
						return true
					}
				}
				return false
			}
			return func(r rec) bool { return eval(e, &r) }
		case q.Regex:
			expr := needle
			if !q.Case {
				expr = "(?i)" + expr
			}
			re := regexp.MustCompile(expr)
			return func(r rec) bool { return re.MatchString(r.raw) }
		case q.Case:
			return func(r rec) bool { return strings.Contains(r.raw, needle) }
		default:
			low := strings.ToLower(needle)
			return func(r rec) bool { return strings.Contains(r.lower, low) }
		}
	}
	var qMatch, exMatch func(rec) bool
	if q.Q != "" {
		qMatch = textMatch(q.Q)
	}
	if q.Exclude != "" {
		exMatch = textMatch(q.Exclude)
	}
	// fieldsMatch is the app and host filters' rule, written out plainly.
	fieldsMatch := func(r rec) bool {
		if len(q.Hosts) > 0 && !slices.ContainsFunc(q.Hosts, func(h string) bool { return strings.EqualFold(h, r.host) }) {
			return false
		}
		if r.host != "" && slices.ContainsFunc(q.ExcludeHosts, func(h string) bool { return strings.EqualFold(strings.TrimSpace(h), r.host) }) {
			return false
		}
		app := strings.ToLower(strings.TrimPrefix(r.app, "%"))
		appMatch := func(a string) bool {
			if a = strings.TrimSpace(a); a == "" {
				return false
			}
			a = strings.ToLower(strings.TrimPrefix(a, "%"))
			if p, ok := strings.CutSuffix(a, "*"); ok {
				return strings.HasPrefix(app, p)
			}
			return app == a
		}
		if app != "" && slices.ContainsFunc(q.ExcludeApps, appMatch) {
			return false
		}
		if len(q.Apps) == 0 {
			return true
		}
		return app != "" && slices.ContainsFunc(q.Apps, appMatch)
	}
	var out []rec
	for _, r := range f.recs {
		if !devs[r.dev] || r.ms < fromMs || r.ms >= toMs {
			continue
		}
		if q.Severities != 0 && !q.Severities.Has(r.sev) {
			continue
		}
		if q.Facilities != 0 {
			fac := r.fac
			if r.sev == model.Unknown {
				fac = model.Unknown
			}
			if !q.Facilities.Has(fac) {
				continue
			}
		}
		if qMatch != nil && !qMatch(r) {
			continue
		}
		if exMatch != nil && exMatch(r) {
			continue
		}
		if !fieldsMatch(r) {
			continue
		}
		out = append(out, r)
	}
	slices.SortStableFunc(out, func(a, b rec) int {
		if a.ms != b.ms {
			if q.Asc {
				return cmpInt(a.ms, b.ms)
			}
			return cmpInt(b.ms, a.ms)
		}
		if a.dev != b.dev {
			return strings.Compare(a.dev, b.dev)
		}
		if q.Asc {
			return a.seq - b.seq
		}
		return b.seq - a.seq
	})
	return out
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// all pages through q and returns every result, checking each page.
func (f *fixture) all(q Query) ([]Line, int) {
	f.t.Helper()
	var out []Line
	pages := 0
	for {
		p, err := f.eng.Search(bg, q)
		if err != nil {
			f.t.Fatalf("page %d: %v", pages, err)
		}
		pages++
		if len(p.Results) > max(q.Limit, 0) && q.Limit > 0 {
			f.t.Fatalf("page %d has %d results, limit %d", pages, len(p.Results), q.Limit)
		}
		out = append(out, p.Results...)
		if p.NextCursor == "" {
			return out, pages
		}
		q.Cursor = p.NextCursor
		if pages > 100000 {
			f.t.Fatal("no end")
		}
	}
}

// same compares results with the expected records.
func same(t *testing.T, what string, got []Line, want []rec) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: %d results, want %d", what, len(got), len(want))
	}
	for i := 0; i < min(len(got), len(want)); i++ {
		g, w := got[i], want[i]
		if g.Received.UnixMilli() != w.ms || g.DeviceID != w.dev || string(g.Raw) != w.raw {
			t.Errorf("%s: result %d = %s %s %q, want %s %s %q", what, i, g.Received.Format(time.RFC3339Nano), g.DeviceID, g.Raw,
				time.UnixMilli(w.ms).UTC().Format(time.RFC3339Nano), w.dev, w.raw)
			return
		}
		// w holds syslog.Parse of the same raw bytes.
		if g.Severity != w.sev {
			t.Errorf("%s: result %d severity %d, want %d", what, i, g.Severity, w.sev)
			return
		}
		if g.App != w.app || g.Host != w.host {
			t.Errorf("%s: result %d app/host %q/%q, want %q/%q", what, i, g.App, g.Host, w.app, w.host)
			return
		}
	}
}

func sevs(v ...int) hub.SeveritySet {
	var s hub.SeveritySet
	for _, x := range v {
		s = s.With(x)
	}
	return s
}
