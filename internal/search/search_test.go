package search

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
	"github.com/gmccollu/woodshed/internal/syslog"
)

func TestSeverityAgreesWithParse(t *testing.T) {
	corpus := []string{"", "<", "<>", "<1>", "<191>x", "<192>x", "<0>", "<007>x", "<1234>x", "<12", " <13>x", "\t\r\n\x00<14>x",
		"\xef\xbb\xbf<15>x", "\xef\xbb\xbf \xef\xbb\xbf<11>x", "x<13>", "\xef\xbb<13>", "<-1>x", "<+1>x", "<1 >x", "\n\n<165>1 - - -"}
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("<>0123456789 \t\r\n\x00\xef\xbb\xbfa")
	for i := 0; i < 20000; i++ {
		b := make([]byte, rng.Intn(10))
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		corpus = append(corpus, string(b))
	}
	for _, s := range corpus {
		var m model.Message
		syslog.Parse([]byte(s), &m)
		if got := Severity([]byte(s)); got != m.Severity {
			t.Fatalf("Severity(%q) = %d, syslog.Parse says %d", s, got, m.Severity)
		}
	}
}

func TestParseMillis(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for i := 0; i < 20000; i++ {
		tm := time.UnixMilli(rng.Int63n(1 << 42)).UTC()
		b := logfile.AppendTime(nil, tm)
		ms, ok := parseMillis(b)
		if !ok || ms != tm.UnixMilli() {
			t.Fatalf("%s: %d %v", b, ms, ok)
		}
	}
	line := []byte("2026-11-10T20:41:07.112+00:00 192.0.2.1 <134>hi")
	ms, esc, ok := splitLine(line)
	if !ok || string(esc) != "<134>hi" || ms != time.Date(2026, 11, 10, 20, 41, 7, 112e6, time.UTC).UnixMilli() {
		t.Errorf("slow path: %d %q %v", ms, esc, ok)
	}
	for _, bad := range []string{"", "2026-11-10T20:41:07.112Z", "2026-11-10T20:41:07.112Z 192.0.2.1", "garbage line here"} {
		if _, _, ok := splitLine([]byte(bad)); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestMatcher(t *testing.T) {
	cases := []struct {
		q            string
		regex, cs    bool
		raw          string
		want, prefil bool
	}{
		{"link down", false, false, "<11>Link DOWN on port", true, true},
		{"LINK", false, true, "<11>Link DOWN", false, true},
		{"Link", false, true, "<11>Link DOWN", true, true},
		{"ünï", false, false, "<11>ÜNÏCODE", true, false},
		{`a\nb`, false, false, "x a\\nb y", true, false},
		{"port [0-9]+$", true, false, "Link down on PORT 12", true, true},
		{"PORT [0-9]+$", true, true, "Link down on port 12", false, true},
		{"^no p[ra]i", true, false, "NO PRI here", true, true},
		{"(a|b)x", true, false, "bx", true, false},
		{"ünï.", true, false, "ÜNÏC", true, false},
		{`a\nb`, true, true, "a\\nb", false, false},
		{"zz", false, false, "z", false, true},
		{"", false, false, "anything", true, false},
	}
	for _, c := range cases {
		m, err := newMatcher(c.q, c.regex, c.cs)
		if err != nil {
			t.Fatal(err)
		}
		if got := m.match([]byte(c.raw)); got != c.want {
			t.Errorf("%q regex=%v case=%v on %q: %v", c.q, c.regex, c.cs, c.raw, got)
		}
		if m.prefilter != c.prefil {
			t.Errorf("%q: prefilter %v", c.q, m.prefilter)
		}
	}
	_, err := newMatcher("(unclosed", true, false)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.HasPrefix(qe.Msg, "error parsing regexp: missing closing )") {
		t.Errorf("regex error: %v", err)
	}
	// The fold prefilter finds every occurrence, either case, in a long buffer.
	m, _ := newMatcher("abc", false, false)
	buf := []byte(strings.Repeat("xaBx", 1000) + "xAbC" + strings.Repeat("a", 5000) + "ABC")
	var found []int
	for i := 0; ; {
		j := m.next(buf, i)
		if j < 0 {
			break
		}
		found = append(found, j)
		i = j + 1
	}
	if len(found) != 2 || found[0] != 4001 || found[1] != len(buf)-3 {
		t.Errorf("fold prefilter found %v", found)
	}
}

func TestSearchFilters(t *testing.T) {
	t.Run("small files", func(t *testing.T) { testSearchFilters(t, newFixture(t, 3, 400)) })
	t.Run("checkpointed files", func(t *testing.T) { testSearchFilters(t, newBigFixture(t)) })
}

func testSearchFilters(t *testing.T, f *fixture) {
	all := Filter{From: f.day0, To: f.day0.Add(72 * time.Hour)}
	with := func(fn func(q *Query)) Query {
		q := Query{Filter: all, Limit: MaxLimit}
		fn(&q)
		return q
	}
	cases := map[string]Query{
		"everything":            with(func(q *Query) {}),
		"q fold":                with(func(q *Query) { q.Q = "LINK down" }),
		"q case":                with(func(q *Query) { q.Q = "Link DOWN"; q.Case = true }),
		"q unicode fold":        with(func(q *Query) { q.Q = "ünïCODE" }),
		"q across escapes":      with(func(q *Query) { q.Q = "multi\nline\r\n" }),
		"q backslash":           with(func(q *Query) { q.Q = `C:\temp\new` }),
		"q not in prefix":       with(func(q *Query) { q.Q = "192.0.2.1" }),
		"regex":                 with(func(q *Query) { q.Q = `port \d+ seq=0+1\d`; q.Regex = true }),
		"regex case":            with(func(q *Query) { q.Q = `^<1[0-9]>host`; q.Regex = true; q.Case = true }),
		"regex anchors raw":     with(func(q *Query) { q.Q = `^no pri`; q.Regex = true }),
		"devices":               with(func(q *Query) { q.Devices = []string{"198.51.100.7", "192.0.2.2"} }),
		"group":                 with(func(q *Query) { q.Group = "HQ" }),
		"ungrouped":             with(func(q *Query) { q.Ungrouped = true }),
		"hidden named":          with(func(q *Query) { q.Devices = []string{"2001_db8__5"} }),
		"group and devices":     with(func(q *Query) { q.Group = "HQ"; q.Devices = []string{"192.0.2.1", "198.51.100.7"} }),
		"severities":            with(func(q *Query) { q.Severities = sevs(0, 3, model.Unknown) }),
		"severities unknown":    with(func(q *Query) { q.Severities = hub.SeverityUnknownBit }),
		"severities none":       with(func(q *Query) { q.Severities = hub.SeverityNone }),
		"time range":            with(func(q *Query) { q.From = f.day0.Add(30 * time.Hour); q.To = f.day0.Add(31*time.Hour + 7*time.Minute) }),
		"time range within day": with(func(q *Query) { q.From = f.day0.Add(20 * time.Hour); q.To = f.day0.Add(20*time.Hour + 30*time.Minute) }),
		"combined":              with(func(q *Query) { q.Q = "seq=0"; q.Group = "HQ"; q.Severities = sevs(1, 2, 6) }),
		"app exact":             with(func(q *Query) { q.Apps = []string{"SSHD"} }),
		"app list":              with(func(q *Query) { q.Apps = []string{"kernel", " app ", ""} }),
		"app pct tag":           with(func(q *Query) { q.Apps = []string{"%fw-6-302013"} }),
		"app pct tag no pct":    with(func(q *Query) { q.Apps = []string{"FW-6-302013"} }),
		"app prefix":            with(func(q *Query) { q.Apps = []string{"%FW-*"} }),
		"app prefix no pct":     with(func(q *Query) { q.Apps = []string{"fw-4-*"} }),
		"app prefix plain":      with(func(q *Query) { q.Apps = []string{"ss*"} }),
		"app any":               with(func(q *Query) { q.Apps = []string{"*"} }),
		"app none":              with(func(q *Query) { q.Apps = []string{"no-such-app"} }),
		"host":                  with(func(q *Query) { q.Hosts = []string{"EDGE-fw-01"} }),
		"host list":             with(func(q *Query) { q.Hosts = []string{"edge-fw-02", "web-01", "web-0"} }),
		"host and app":          with(func(q *Query) { q.Hosts = []string{"host"}; q.Apps = []string{"app"} }),
		"exclude":               with(func(q *Query) { q.Exclude = "CONN opened" }),
		"exclude case":          with(func(q *Query) { q.Exclude = "Link DOWN"; q.Case = true }),
		"exclude regex":         with(func(q *Query) { q.Exclude = `seq=\d+[13579]$`; q.Regex = true }),
		"exclude with q":        with(func(q *Query) { q.Q = "seq=00"; q.Exclude = "fw-"; q.Severities = sevs(4, 5, 6) }),
		"exclude across escape": with(func(q *Query) { q.Exclude = "multi\nline" }),
		"all new filters": with(func(q *Query) {
			q.Q = "seq"
			q.Apps = []string{"%FW-*", "sshd"}
			q.Hosts = []string{"edge-fw-01", "web-01"}
			q.Exclude = "5$"
			q.Regex = true
		}),
		"default range": {Filter: Filter{}, Limit: MaxLimit},
		// 1.1 (docs/api.md): facilities, the exclude forms and syntax=terms.
		"facilities":            with(func(q *Query) { q.Facilities = facs(0, 4, 20) }),
		"facilities unknown":    with(func(q *Query) { q.Facilities = FacilityUnknownBit }),
		"facilities none":       with(func(q *Query) { q.Facilities = FacilityNone }),
		"facilities and sev":    with(func(q *Query) { q.Facilities = facs(20, 1); q.Severities = sevs(4, 6) }),
		"exclude devices":       with(func(q *Query) { q.ExcludeDevices = []string{"192.0.2.2"} }),
		"exclude devices group": with(func(q *Query) { q.Group = "HQ"; q.ExcludeDevices = []string{"192.0.2.1"} }),
		"exclude named device": with(func(q *Query) {
			q.Devices = []string{"192.0.2.1", "192.0.2.2"}
			q.ExcludeDevices = []string{"192.0.2.1"}
		}),
		"exclude all devices":    with(func(q *Query) { q.Devices = []string{"192.0.2.1"}; q.ExcludeDevices = []string{"192.0.2.1"} }),
		"exclude app":            with(func(q *Query) { q.ExcludeApps = []string{"%FW-*", "SSHD"} }),
		"exclude app with app":   with(func(q *Query) { q.Apps = []string{"%FW-*"}; q.ExcludeApps = []string{"fw-4-*"} }),
		"exclude app wins":       with(func(q *Query) { q.Apps = []string{"sshd"}; q.ExcludeApps = []string{"sshd"} }),
		"exclude host":           with(func(q *Query) { q.ExcludeHosts = []string{"HOST", "web-01"} }),
		"exclude host with host": with(func(q *Query) { q.Hosts = []string{"web-01", "web-02"}; q.ExcludeHosts = []string{"WEB-02"} }),
		"terms and":              with(func(q *Query) { q.Terms = true; q.Q = "seq=00 conn" }),
		"terms or":               with(func(q *Query) { q.Terms = true; q.Q = "Deny OR accepted" }),
		"terms not":              with(func(q *Query) { q.Terms = true; q.Q = "NOT conn" }),
		"terms phrase":           with(func(q *Query) { q.Terms = true; q.Q = `"link down" OR "conn opened tcp"` }),
		"terms nested":           with(func(q *Query) { q.Terms = true; q.Q = `(deny OR built) NOT (seq=0001 OR seq=0002) "fw-"` }),
		"terms case":             with(func(q *Query) { q.Terms = true; q.Case = true; q.Q = "Deny OR Link" }),
		"terms escapes":          with(func(q *Query) { q.Terms = true; q.Q = `"multi\nline" OR "C:\\temp"` }),
		"terms across escape":    with(func(q *Query) { q.Terms = true; q.Q = "multi\nline seq" }),
		"terms unicode":          with(func(q *Query) { q.Terms = true; q.Q = "ÜNÏCODE warning" }),
		"terms exclude":          with(func(q *Query) { q.Terms = true; q.Q = "seq"; q.Exclude = "conn OR deny" }),
		"terms empty":            with(func(q *Query) { q.Terms = true; q.Q = "   " }),
		"every 1.1 filter at once": with(func(q *Query) {
			q.Terms = true
			q.Q = `seq NOT "seq=0000"`
			q.Exclude = "opened"
			q.Facilities = facs(20, 4, 1)
			q.ExcludeApps = []string{"kernel"}
			q.ExcludeHosts = []string{"edge-fw-02"}
			q.ExcludeDevices = []string{"198.51.100.7"}
		}),
	}
	f.clock.Set(f.day0.Add(40 * time.Hour)) // "now" for the default range
	// The checkpointed fixture must really seek: a 1 h range reads far less than
	// the files.
	{
		p, err := f.eng.Search(bg, Query{Filter: Filter{From: f.day0.Add(30 * time.Hour), To: f.day0.Add(31 * time.Hour)}, Limit: MaxLimit})
		if err != nil {
			t.Fatal(err)
		}
		files, _ := f.idx.Files(bg, "")
		var total int64
		for _, fl := range files {
			total += fl.RawSize
		}
		t.Logf("1 h of %d bytes: scanned %d bytes in %d files", total, p.ScannedBytes, p.ScannedFiles)
	}
	for name, q := range cases {
		for _, asc := range []bool{false, true} {
			q.Asc = asc
			got, _ := f.all(q)
			label := name + map[bool]string{true: " asc", false: " desc"}[asc]
			want := f.expect(q)
			if len(want) == 0 && name != "severities none" && name != "q not in prefix" && name != "app none" &&
				name != "facilities none" && name != "exclude all devices" && name != "exclude app wins" {
				t.Errorf("%s: the fixture has no matches; the case tests nothing", label)
			}
			same(t, label, got, want)
		}
	}
	got, pages := f.all(Query{Filter: all, Limit: MaxLimit})
	if pages == 0 {
		t.Fatal("no pages")
	}
	for _, l := range got {
		if l.DeviceID == "2001_db8__5" {
			t.Fatal("hidden device searched without being named")
		}
	}
}

func facs(v ...int) FacilitySet {
	var s FacilitySet
	for _, x := range v {
		s = s.With(x)
	}
	return s
}

func TestFacilityAgreesWithParse(t *testing.T) {
	for _, raw := range []string{"<0>x", "<191>x", "<192>x", "x", "<13>x", "\xef\xbb\xbf<165>1 - -", "<8>", "<"} {
		var m model.Message
		syslog.Parse([]byte(raw), &m)
		if got := Facility([]byte(raw)); got != m.Facility {
			t.Errorf("Facility(%q) = %d, syslog.Parse says %d", raw, got, m.Facility)
		}
	}
	for _, c := range []struct {
		in   string
		want FacilitySet
		bad  bool
	}{
		{"", 0, false}, {"0,4,23", facs(0, 4, 23), false}, {"unknown", FacilityUnknownBit, false}, {"none", FacilityNone, false},
		{" 4 , ,16", facs(4, 16), false}, {"24", 0, true}, {"-1", 0, true}, {"x", 0, true}, {"none,4", 0, true}, {"004", 0, true},
	} {
		got, err := ParseFacilities(c.in)
		if (err != nil) != c.bad || got != c.want {
			t.Errorf("ParseFacilities(%q) = %v, %v", c.in, got, err)
		}
	}
	all := ""
	for i := 0; i < 24; i++ {
		all += fmt.Sprint(i, ",")
	}
	if got, _ := ParseFacilities(all + "unknown"); got != 0 {
		t.Errorf("every facility is no filter: %v", got)
	}
}

func TestPaginationContinuity(t *testing.T) {
	f := newFixture(t, 3, 300)
	for _, q := range []Query{
		{Filter: Filter{From: f.day0, To: f.day0.Add(72 * time.Hour)}},
		{Filter: Filter{From: f.day0, To: f.day0.Add(72 * time.Hour), Q: "seq=00"}},
		{Filter: Filter{From: f.day0.Add(20 * time.Hour), To: f.day0.Add(52 * time.Hour), Severities: sevs(4, 5, model.Unknown)}},
	} {
		for _, asc := range []bool{false, true} {
			q.Asc = asc
			full := q
			full.Limit = MaxLimit
			one, _ := f.all(full)
			// The full search equals the brute force; the pages below equal it.
			same(t, "full", one, f.expect(q))
			for _, limit := range []int{1, 7, 64} {
				if limit == 1 && q.Q == "" {
					continue // thousands of pages; 7 covers the same paths
				}
				q.Limit = limit
				paged, pages := f.all(q)
				if pages < 2 {
					t.Fatalf("limit %d: only %d page", limit, pages)
				}
				same(t, "paged", paged, toRecs(one))
			}
		}
	}
	if f.eng.passes.hits.Load() == 0 || f.eng.readers.hits.Load() == 0 || f.eng.prefetches.Load() == 0 {
		t.Errorf("caches unused: %d pass hits, %d reader hits, %d prefetches", f.eng.passes.hits.Load(), f.eng.readers.hits.Load(), f.eng.prefetches.Load())
	}
	// limit may change from page to page.
	q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(72 * time.Hour)}, Limit: 5}
	var got []Line
	for i := 0; ; i++ {
		p, err := f.eng.Search(bg, q)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, p.Results...)
		if p.NextCursor == "" {
			break
		}
		q.Cursor, q.Limit = p.NextCursor, 1+i%900
	}
	same(t, "changing limit", got, f.expect(q))
}

func toRecs(ls []Line) []rec {
	out := make([]rec, len(ls))
	for i, l := range ls {
		out[i] = newRec(l.Received.UnixMilli(), l.DeviceID, string(l.Raw), 0)
	}
	return out
}

func TestPartialAndResume(t *testing.T) {
	f := newFixture(t, 3, 300)
	f.eng.testMaxSteps = 1 // every request reads one block, then stops (not a time: Windows timers are coarse)
	for _, asc := range []bool{false, true} {
		for _, text := range []string{"", "seq=0001", "nothing matches this"} {
			q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(72 * time.Hour), Q: text}, Asc: asc, Limit: 100}
			var got []Line
			partials := 0
			for n := 0; ; n++ {
				p, err := f.eng.Search(bg, q)
				if err != nil {
					t.Fatal(err)
				}
				if p.Partial {
					partials++
					if p.NextCursor == "" {
						t.Fatal("partial without a cursor")
					}
				}
				if p.ScannedFiles > 4 {
					t.Fatalf("one-block budget read %d files", p.ScannedFiles)
				}
				got = append(got, p.Results...)
				if p.NextCursor == "" {
					break
				}
				q.Cursor = p.NextCursor
				if n > 200000 {
					t.Fatal("no progress")
				}
			}
			if partials == 0 {
				t.Errorf("%q asc=%v: never partial", text, asc)
			}
			same(t, "partial "+text, got, f.expect(q))
		}
	}
}

func TestCursorTamperAndBinding(t *testing.T) {
	f := newFixture(t, 1, 200)
	q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(24 * time.Hour), Q: "seq"}, Limit: 10}
	p, err := f.eng.Search(bg, q)
	if err != nil || p.NextCursor == "" {
		t.Fatal(err, p.NextCursor)
	}
	var qe *QueryError
	reject := func(what, cur string) {
		t.Helper()
		q2 := q
		q2.Cursor = cur
		if _, err := f.eng.Search(bg, q2); !errors.As(err, &qe) {
			t.Fatalf("%s accepted: %v", what, err)
		}
	}
	// Every other character at every position of the text, including the
	// last one's unused low bits (which non-strict base64 decodes to the same
	// bytes, so such a cursor would alias the original rather than tamper with
	// it; strict decoding refuses it).
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for i := 0; i < len(p.NextCursor); i++ {
		for _, c := range []byte(alphabet) {
			if c == p.NextCursor[i] {
				continue
			}
			b := []byte(p.NextCursor)
			b[i] = c
			reject(fmt.Sprintf("character %d changed to %q", i, c), string(b))
		}
	}
	// Every bit of every decoded byte (version, parameter hash, payload, MAC),
	// re-encoded canonically.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(p.NextCursor)
	if err != nil {
		t.Fatal(err)
	}
	for i := range raw {
		for bit := 0; bit < 8; bit++ {
			b := bytes.Clone(raw)
			b[i] ^= 1 << bit
			reject(fmt.Sprintf("byte %d bit %d flipped", i, bit), base64.RawURLEncoding.EncodeToString(b))
		}
	}
	// Truncated, extended, padded.
	reject("truncated", p.NextCursor[:len(p.NextCursor)-1])
	reject("extended", p.NextCursor+"A")
	reject("padded", p.NextCursor+"=")
	reject("empty MAC", base64.RawURLEncoding.EncodeToString(raw[:len(raw)-macLen]))
	for _, change := range []func(q *Query){
		func(q *Query) { q.Q = "seq=" },
		func(q *Query) { q.Asc = true },
		func(q *Query) { q.Devices = []string{"192.0.2.1"} },
		func(q *Query) { q.To = q.To.Add(time.Second) },
		func(q *Query) { q.Severities = sevs(3) },
		func(q *Query) { q.Regex = true },
		func(q *Query) { q.Exclude = "x" },
		func(q *Query) { q.Apps = []string{"app"} },
		func(q *Query) { q.Hosts = []string{"host"} },
		// 1.1: every new parameter is bound too.
		func(q *Query) { q.Terms = true },
		func(q *Query) { q.Facilities = facs(4) },
		func(q *Query) { q.ExcludeDevices = []string{"192.0.2.1"} },
		func(q *Query) { q.ExcludeApps = []string{"app"} },
		func(q *Query) { q.ExcludeHosts = []string{"host"} },
	} {
		q2 := q
		q2.Cursor = p.NextCursor
		change(&q2)
		if _, err := f.eng.Search(bg, q2); !errors.As(err, &qe) || !strings.Contains(qe.Msg, "different search") {
			t.Errorf("changed parameters: %v", err)
		}
	}
	// A cursor from another process (another key) is refused.
	other := New(Options{DataDir: f.dir, Index: f.idx, Now: f.clock.Now, Logger: quiet})
	q.Cursor = p.NextCursor
	if _, err := other.Search(bg, q); !errors.As(err, &qe) || !strings.Contains(qe.Msg, "restarted") {
		t.Errorf("foreign cursor: %v", err)
	}
	// Regex errors and bad ranges are QueryErrors too.
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Q: "a(", Regex: true}}); !errors.As(err, &qe) {
		t.Errorf("regex: %v", err)
	}
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Exclude: "a(", Regex: true}}); !errors.As(err, &qe) ||
		!strings.HasPrefix(qe.Msg, "exclude: error parsing regexp") {
		t.Errorf("exclude regex: %v", err)
	}
	if err := f.eng.CheckFilter(Filter{Exclude: "[", Regex: true}); !errors.As(err, &qe) {
		t.Errorf("CheckFilter exclude regex: %v", err)
	}
	// The same list in another order, or repeated, is the same search.
	qa := Query{Filter: Filter{From: f.day0, To: f.day0.Add(24 * time.Hour), Apps: []string{"app", "sshd"}, Hosts: []string{"host", "web-01"}}, Limit: 10}
	pa, err := f.eng.Search(bg, qa)
	if err != nil || pa.NextCursor == "" {
		t.Fatal(err, pa.NextCursor)
	}
	qa.Apps, qa.Hosts, qa.Cursor = []string{"sshd", "app", "app"}, []string{"web-01", "host"}, pa.NextCursor
	if _, err := f.eng.Search(bg, qa); err != nil {
		t.Errorf("reordered lists: %v", err)
	}
	if _, err := f.eng.Search(bg, Query{Filter: Filter{From: f.day0, To: f.day0}}); !errors.As(err, &qe) {
		t.Errorf("empty range: %v", err)
	}
}

func TestContextAcrossFiles(t *testing.T) {
	f := newFixture(t, 2, 600)
	devA := model.DeviceID(devA)
	var mine []rec
	for _, r := range f.recs {
		if r.dev == devA {
			mine = append(mine, r)
		}
	}
	files, err := f.idx.Files(bg, devA)
	if err != nil || len(files) < 4 {
		t.Fatalf("want several files, have %d (%v)", len(files), err)
	}
	q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(48 * time.Hour)}, Devices: []string{devA}, Asc: true, Limit: MaxLimit}
	res, _ := f.all(q)
	if len(res) != len(mine) {
		t.Fatalf("%d results, %d written", len(res), len(mine))
	}
	// Every file's first line: context crosses back into the previous file.
	check := func(i, before, after int) {
		t.Helper()
		cp, err := f.eng.Context(bg, res[i].Ref, before, after)
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		lo, hi := max(i-before, 0), min(i+after, len(mine)-1)
		same(t, "context", cp.Lines, mine[lo:hi+1])
		if cp.HitIndex != i-lo {
			t.Errorf("line %d: hit index %d, want %d", i, cp.HitIndex, i-lo)
		}
		if cp.AtStart != (i-before <= 0) || cp.AtEnd != (i+after >= len(mine)-1) {
			t.Errorf("line %d (±%d/%d): at_start %v at_end %v", i, before, after, cp.AtStart, cp.AtEnd)
		}
		if cp.Lines[cp.HitIndex].Ref != res[i].Ref {
			t.Errorf("line %d: the hit's ref changed", i)
		}
	}
	idxOfFile := map[int64]int{}
	for i, r := range res {
		id, _, _, _ := decodeRef(r.Ref)
		if _, ok := idxOfFile[id]; !ok {
			idxOfFile[id] = i
		}
	}
	if len(idxOfFile) < 4 {
		t.Fatalf("results span %d files", len(idxOfFile))
	}
	for _, i := range idxOfFile {
		check(i, 50, 50)
		if i > 0 {
			check(i-1, 3, 3) // the last line of the previous file
		}
	}
	check(0, 50, 5)
	check(len(res)-1, 5, 50)
	check(len(res)/2, 500, 500)
	check(len(res)/3, 0, 0)

	var qe *QueryError
	if _, err := f.eng.Context(bg, "!!!", 5, 5); !errors.As(err, &qe) {
		t.Errorf("bad ref: %v", err)
	}
	id, off, ms, _ := decodeRef(res[10].Ref)
	if _, err := f.eng.Context(bg, encodeRef(id, off+3, ms), 5, 5); !errors.As(err, &qe) {
		t.Errorf("misaligned ref: %v", err)
	}
	if _, err := f.eng.Context(bg, encodeRef(999999, 0, ms), 5, 5); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown file: %v", err)
	}
}

func TestVanishingFileIsSkipped(t *testing.T) {
	f := newFixture(t, 3, 300)
	files, _ := f.idx.Files(bg, model.DeviceID(devB))
	victim := files[len(files)/2]
	var deleted atomic.Bool // opens run in parallel (prefetch)
	f.eng.testHookOpen = func(rel string) {
		if rel == victim.Path && deleted.CompareAndSwap(false, true) {
			os.Remove(filepath.Join(f.dir, filepath.FromSlash(victim.Path)))
		}
	}
	for _, asc := range []bool{false, true} {
		q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(72 * time.Hour)}, Asc: asc, Limit: 97}
		got, _ := f.all(q)
		if !deleted.Load() {
			t.Fatal("hook didn't fire")
		}
		// Everything except the victim's lines.
		var want []rec
		for _, r := range f.expect(q) {
			if r.dev == victim.DeviceID && r.ms >= victim.FirstReceived.UnixMilli() && r.ms <= victim.LastReceived.UnixMilli() {
				continue
			}
			want = append(want, r)
		}
		same(t, "after a vanished file", got, want)
	}
}

func TestBigFixturePartialAndContext(t *testing.T) {
	f := newBigFixture(t)
	// A compressed file read newest-first needs one forward pass; a budget far
	// below one pass makes that quadratic, so give each request a few blocks.
	f.eng.testMaxSteps, f.eng.block = 8, 64<<10
	for _, asc := range []bool{false, true} {
		q := Query{Filter: Filter{From: f.day0.Add(5 * time.Hour), To: f.day0.Add(40 * time.Hour), Q: "seq=0012"}, Asc: asc, Limit: 50}
		got, pages := f.all(q)
		if pages < 2 {
			t.Errorf("asc=%v: %d pages with a tiny budget", asc, pages)
		}
		same(t, "big partial", got, f.expect(q))
	}
	f.eng.testMaxSteps = 0
	dev := model.DeviceID(devC)
	q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(48 * time.Hour)}, Devices: []string{dev}, Asc: true, Limit: MaxLimit}
	res, _ := f.all(q)
	mine := f.expect(q)
	seen := map[int64]bool{}
	for i, r := range res {
		id, _, _, _ := decodeRef(r.Ref)
		if seen[id] && i%997 != 0 {
			continue
		}
		seen[id] = true
		for _, n := range []int{1, 500} {
			cp, err := f.eng.Context(bg, r.Ref, n, n)
			if err != nil {
				t.Fatal(err)
			}
			lo, hi := max(i-n, 0), min(i+n, len(mine)-1)
			same(t, "big context", cp.Lines, mine[lo:hi+1])
			if cp.HitIndex != i-lo {
				t.Fatalf("hit index %d, want %d", cp.HitIndex, i-lo)
			}
		}
	}
}

// TestSearchWhileWriting pages through searches while the store writes,
// rotates parts, compresses and deletes by retention underneath. No request may
// fail, no line may repeat, and each device's lines come in file order.
func TestSearchWhileWriting(t *testing.T) {
	f := newFixture(t, 2, 200)
	f.st.SetLimits(store.Limits{RetentionDays: 30, RetentionBytes: 64 << 10, PartBytes: 8 << 10})
	// The writer and the searches interleave by construction, not by timing:
	// each page the searches read lets the writer write a batch (rotating parts,
	// compressing, deleting by retention), and the writer stops once retention
	// has deleted wantDeleted files. A slow disk (fsync on Windows) only makes
	// the test take more pages. Each batch moves the fake clock 6 hours on, so the
	// writes span days: the size cap never takes an established device's last two
	// days, so it needs older days to delete.
	const wantDeleted = 60
	grant := make(chan struct{}, 1)
	done := make(chan struct{})
	var werr error
	go func() {
		defer close(done)
		at := f.day0.Add(48*time.Hour + time.Minute)
		seq := 1 << 20
		for batch := 0; batch < 20000; batch++ {
			<-grant
			for i := 0; i < 30; i++ {
				for _, a := range f.devs {
					at = at.Add(time.Millisecond)
					f.st.Write(model.Message{Received: at, Sender: a, Raw: []byte(msgText(seq))})
					seq++
				}
			}
			at = at.Add(6 * time.Hour)
			f.clock.Set(at)
			f.st.Maintain()
			if hist, err := f.idx.Deletions(bg, time.Time{}, time.Time{}, 0); err != nil {
				werr = err
				return
			} else if len(hist) >= wantDeleted {
				return
			}
		}
		werr = errors.New("retention never deleted enough files")
	}()
	writing := func() bool {
		select {
		case <-done:
			return false
		default:
			return true
		}
	}
	rounds := 0
	for writing() {
		for _, asc := range []bool{false, true} {
			q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(60 * 24 * time.Hour)}, Asc: asc, Limit: 37}
			seen := map[string]bool{}
			last := map[string]int64{}
			for n := 0; ; n++ {
				p, err := f.eng.Search(bg, q)
				if err != nil {
					t.Fatalf("round %d page %d: %v", rounds, n, err)
				}
				select {
				case grant <- struct{}{}:
				default:
				}
				for _, l := range p.Results {
					if seen[l.Ref] {
						t.Fatalf("line repeated: %s %q", l.DeviceID, l.Raw)
					}
					seen[l.Ref] = true
					if prev, ok := last[l.DeviceID]; ok && (asc && l.Received.UnixMilli() < prev || !asc && l.Received.UnixMilli() > prev) {
						t.Fatalf("device %s out of order", l.DeviceID)
					}
					last[l.DeviceID] = l.Received.UnixMilli()
				}
				if p.NextCursor == "" || n > 300 {
					break
				}
				q.Cursor = p.NextCursor
			}
			rounds++
		}
	}
	if werr != nil {
		t.Fatal(werr)
	}
	hist, _ := f.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	t.Logf("%d search rounds; %d files deleted by retention meanwhile", rounds, len(hist))
	if rounds < 2 {
		t.Errorf("only %d search rounds overlapped the writes", rounds)
	}
}

// TestDeepPaginationSmallRing pages newest-first through compressed files whose
// matches don't fit one pass's ring, so pages are served from cached passes
// that dropped older matches, then from passes over the rest.
func TestDeepPaginationSmallRing(t *testing.T) {
	f := newBigFixture(t)
	f.eng.ringBytes = 8 << 10
	for _, text := range []string{"", "conn opened"} {
		q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(48 * time.Hour), Q: text}, Limit: 997}
		t0 := time.Now()
		got, pages := f.all(q)
		same(t, "small ring "+text, got, f.expect(q))
		t.Logf("%q: %d results, %d pages, %v", text, len(got), pages, time.Since(t0).Round(time.Millisecond))
	}
	if f.eng.passes.hits.Load() == 0 {
		t.Error("no cached pass served")
	}
}

// TestFieldFiltersReadCompressedFiles checks the app, host and exclude filters
// reach lines in .gz files as well as plain ones, in both orders.
func TestFieldFiltersReadCompressedFiles(t *testing.T) {
	f := newFixture(t, 3, 400)
	files, err := f.idx.Files(bg, "")
	if err != nil {
		t.Fatal(err)
	}
	gz := map[int64]bool{}
	for _, fl := range files {
		gz[fl.ID] = fl.Compressed
	}
	for _, asc := range []bool{false, true} {
		q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(72 * time.Hour), Apps: []string{"%FW-*"}, Hosts: []string{"edge-fw-01", "edge-fw-02"},
			Exclude: "deny"}, Asc: asc, Limit: 100}
		got, _ := f.all(q)
		same(t, "gz fields", got, f.expect(q))
		var inGz, inPlain int
		for _, l := range got {
			id, _, _, _ := decodeRef(l.Ref)
			if gz[id] {
				inGz++
			} else {
				inPlain++
			}
			if l.App != "%FW-6-302013" || l.Host != "edge-fw-01" {
				t.Fatalf("result app/host %q/%q", l.App, l.Host)
			}
		}
		if inGz == 0 || inPlain == 0 {
			t.Errorf("asc=%v: %d results from .gz files and %d from plain ones; want both", asc, inGz, inPlain)
		}
	}
}

func TestFields(t *testing.T) {
	for _, c := range []struct{ raw, app, host string }{
		{"<166>Nov 10 20:41:07 edge-fw-01 %FW-6-302013: Built conn", "%FW-6-302013", "edge-fw-01"},
		{"<86>Nov 10 20:41:07 web-01 sshd[4721]: Accepted publickey", "sshd", "web-01"},
		{"<13>1 2026-11-10T20:41:07Z web-02 kernel - - - eth0 up", "kernel", "web-02"},
		{"no header at all", "", ""},
	} {
		if app, host := Fields([]byte(c.raw)); app != c.app || host != c.host {
			t.Errorf("%q: %q/%q, want %q/%q", c.raw, app, host, c.app, c.host)
		}
	}
	fm := newFieldMatcher([]string{"FW-6-*", "SSHD", "%kernel"}, nil, nil, nil)
	var m model.Message
	for raw, want := range map[string]bool{
		"<166>Nov 10 20:41:07 h %FW-6-302013: x": true,
		"<166>Nov 10 20:41:07 h %FW-4-106023: x": false,
		"<86>Nov 10 20:41:07 h sshd[1]: x":       true,
		"<86>Nov 10 20:41:07 h sshd2[1]: x":      false,
		"<6>Nov 10 20:41:07 h kernel: x":         true,
		"<6>Nov 10 20:41:07 x":                   false,
	} {
		if got := fm.match([]byte(raw), &m); got != want {
			t.Errorf("%q: %v", raw, got)
		}
	}
	if newFieldMatcher([]string{" ", ""}, []string{""}, nil, nil) != nil {
		t.Error("blank values make a filter")
	}
}
