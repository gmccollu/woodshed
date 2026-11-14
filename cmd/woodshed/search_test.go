package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/store"
)

var updateSearchGolden = flag.Bool("update-search-golden", false, "rewrite testdata/search/*.golden")

// The search fixture: four devices over three days (2026-11-08 to 10), the
// first two days compressed, split into parts, the last one plain.
var (
	fxDay0  = time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	fxNow   = fxDay0.Add(2*24*time.Hour + 12*time.Hour) // 2026-11-10 12:00 UTC
	fxDevs  = []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::5")}
	fxRange = []string{"--from", "2026-11-08T00:00:00Z", "--to", "2026-11-11T00:00:00Z"}
)

const fxPerDay = 12 // messages per device per day

// fxRec is one message the fixture wrote.
type fxRec struct {
	at   time.Time
	dev  string // the device ID
	addr string // the sender address, as in the stored line
	raw  string
}

func fxMessage(seq int) string {
	switch seq % 6 {
	case 0:
		return fmt.Sprintf("<187>Nov 10 00:00:00 edge-fw-01 %%FW-3-LINK: Link DOWN on Gi0/%d seq=%04d", seq%4, seq)
	case 1:
		return fmt.Sprintf("<134>Nov 10 00:00:00 web-01 sshd[42]: Accepted publickey for admin seq=%04d", seq)
	case 2:
		return fmt.Sprintf("<14>Nov 10 00:00:00 web-02 kernel: eth0 link up seq=%04d", seq)
	case 3:
		return fmt.Sprintf("<165>Nov 10 00:00:00 edge-fw-02 %%FW-5-DENY: Deny tcp src 203.0.113.%d seq=%04d", seq%9, seq)
	case 4:
		return fmt.Sprintf("no pri: multi\nline message seq=%04d", seq)
	}
	return fmt.Sprintf(`<11>Nov 10 00:00:00 db-01 app: error: disk C:\data full seq=%04d`, seq)
}

type searchFixture struct {
	dir  string
	recs []fxRec
}

// newSearchFixture writes the fixture through a real store and closes it, so
// the folder has no -wal or -shm (the service is stopped).
func newSearchFixture(t *testing.T) *searchFixture {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	now := fxDay0
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	set := func(t time.Time) { mu.Lock(); now = t; mu.Unlock() }
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 1 << 10, Manual: true, Clock: clock,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f := &searchFixture{dir: dir}
	seq := 0
	for d := 0; d < 3; d++ {
		start := fxDay0.Add(time.Duration(d) * 24 * time.Hour)
		set(start.Add(time.Second))
		if err := st.Maintain(); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < fxPerDay; i++ {
			for k, a := range fxDevs {
				at := start.Add(time.Hour + time.Duration(i)*90*time.Minute + time.Duration(k)*time.Minute)
				raw := fxMessage(seq)
				if err := st.Write(model.Message{Received: at, Sender: a, Raw: []byte(raw)}); err != nil {
					t.Fatal(err)
				}
				f.recs = append(f.recs, fxRec{at: at, dev: model.DeviceID(a), addr: a.String(), raw: raw})
				seq++
			}
			if i%4 == 3 {
				set(start.Add(time.Hour + time.Duration(i)*90*time.Minute + 5*time.Minute))
				if err := st.Maintain(); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	set(fxNow)
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := st.Maintain(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	name, grp := "edge-fw-01", "HQ"
	idx.UpdateDevice(ctx, "192.0.2.1", index.DeviceUpdate{Name: &name, Group: &grp})
	idx.UpdateDevice(ctx, "192.0.2.2", index.DeviceUpdate{Group: &grp})
	yes := true
	idx.UpdateDevice(ctx, model.DeviceID(fxDevs[3]), index.DeviceUpdate{Hidden: &yes})
	if err := idx.Close(); err != nil {
		t.Fatal(err)
	}
	return f
}

// files lists the fixture's log files.
func (f *searchFixture) files(t *testing.T) []string {
	var out []string
	filepath.WalkDir(filepath.Join(f.dir, "logs"), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			rel, _ := filepath.Rel(f.dir, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

// runSearch runs `woodshed search` in-process at fxNow over the fixture.
func runSearch(t *testing.T, dir string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	searchNow = func() time.Time { return fxNow }
	searchLocation = func() *time.Location { return time.FixedZone("UTC-5", -5*3600) }
	t.Cleanup(func() { searchNow, searchLocation = time.Now, func() *time.Location { return time.Local } })
	return runCLI(append([]string{"search", "--data", dir}, args...)...)
}

var summaryRE = regexp.MustCompile(`^\d+ match(es)?, \d+\.\d MiB read from \d+ files? in \d+\.\d\ds(; \d+ files? skipped \(deleted or unreadable during the search\))?( \(interrupted\))?\n$`)

func TestSearchFixtureShape(t *testing.T) {
	f := newSearchFixture(t)
	files := f.files(t)
	var gz, plain, parts int
	for _, p := range files {
		switch {
		case strings.HasSuffix(p, ".gz"):
			gz++
		default:
			plain++
		}
		if regexp.MustCompile(`\.\d{3}\.log`).MatchString(p) {
			parts++
		}
	}
	if gz == 0 || plain == 0 || parts == 0 {
		t.Fatalf("the fixture needs plain, compressed and part files: %v", files)
	}
	for _, s := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(filepath.Join(f.dir, index.FileName+s)); err == nil {
			t.Fatalf("%s left behind", s)
		}
	}
}

// goldenCases are `woodshed search` runs over the fixture whose standard
// output is kept in testdata/search/<name>.golden.
var goldenCases = []struct {
	name string
	args []string
	code int
}{
	{"all", nil, 0},
	{"text-link-down", []string{"link down"}, 0},
	{"raw", []string{"--raw", "multi"}, 0},
	{"json-devices", []string{"--json", "--devices", "192.0.2.1,2001:db8::5", "seq=00"}, 0},
	{"context-2", []string{"--context", "2", "deny"}, 0},
	{"context-1-desc", []string{"--context", "1", "--order", "desc", "--devices", "192.0.2.2", "error"}, 0},
	{"context-devices", []string{"--context", "1", "--terms", "link OR accepted", "--from", "2026-11-09T00:00:00Z", "--to", "2026-11-09T12:00:00Z"}, 0},
	{"context-merged", []string{"--context", "3", "--devices", "198.51.100.7", "--terms", "link OR accepted"}, 0},
	{"json-context", []string{"--json", "--context", "1", "--devices", "192.0.2.1", "seq=001"}, 0},
	{"raw-context", []string{"--raw", "--context", "1", "--devices", "192.0.2.1", "seq=0004"}, 0},
	{"count", []string{"--count", "link"}, 0},
	{"count-json", []string{"--count", "--json", "--severities", "3"}, 0},
	{"desc-limit", []string{"--order", "desc", "--limit", "5"}, 0},
	{"terms", []string{"--terms", `(deny OR "link down") AND NOT gi0/0`}, 0},
	{"regex-case", []string{"--regex", "--case", `Link DOWN on Gi0/[12]`}, 0},
	{"exclude", []string{"seq=", "--exclude", "link"}, 0},
	{"severities", []string{"--severities", "3,unknown"}, 0},
	{"facilities", []string{"--facilities", "20"}, 0},
	{"app", []string{"--app", "%FW-*", "--exclude-app", "FW-5-DENY"}, 0},
	{"host", []string{"--host", "web-01,WEB-02", "--exclude-host", "web-02"}, 0},
	{"group", []string{"--group", "HQ", "--severities", "5"}, 0},
	{"ungrouped", []string{"--ungrouped", "--severities", "3"}, 0},
	{"exclude-devices", []string{"--exclude-devices", "192.0.2.1,192.0.2.2", "--severities", "6"}, 0},
	{"field", []string{"--field", "host=edge-fw-01", "--field", "device=192.0.2.1"}, 0},
	{"not-field", []string{"--not-field", "severity=6,unknown", "--not-field", "app=FW-5-DENY", "--devices", "192.0.2.1"}, 0},
	{"not-field-facility", []string{"--not-field", "facility=1,16,20,23"}, 0},
	{"across-gz-days", []string{"--from", "2026-11-08T16:00:00Z", "--to", "2026-11-09T03:00:00Z"}, 0},
	{"local-time", []string{"--from", "2026-11-09 18:00", "--to", "2026-11-09 22:00"}, 0},
	{"utc-time", []string{"--from", "2026-11-09 23:00", "--to", "2026-11-10 03:00", "--utc"}, 0},
	{"last", []string{"--last", "3h"}, 0},
	{"default-range", []string{"--devices", "192.0.2.1"}, 0},
	{"none", []string{"no such text anywhere"}, 1},
}

func TestSearchGolden(t *testing.T) {
	f := newSearchFixture(t)
	for _, c := range goldenCases {
		t.Run(c.name, func(t *testing.T) {
			args := c.args
			if !slices.ContainsFunc(args, func(a string) bool { return a == "--from" || a == "--last" }) && c.name != "default-range" {
				args = append(slices.Clone(fxRange), args...)
			}
			code, out, errOut := runSearch(t, f.dir, args...)
			if code != c.code {
				t.Fatalf("exit %d, want %d; stderr %s", code, c.code, errOut)
			}
			if strings.Contains(strings.Join(args, " "), "--json") {
				var sum map[string]any
				if err := json.Unmarshal([]byte(errOut), &sum); err != nil || sum["matches"] == nil {
					t.Fatalf("JSON summary %q: %v", errOut, err)
				}
			} else if !summaryRE.MatchString(errOut) {
				t.Fatalf("summary %q", errOut)
			}
			// Refs hold file IDs, which depend on the order the store's writers
			// reached the index; TestSearchJSONMatchesAPI checks them.
			out = refRE.ReplaceAllString(out, `"ref":"<ref>"`)
			path := filepath.Join("testdata", "search", c.name+".golden")
			if *updateSearchGolden {
				os.MkdirAll(filepath.Dir(path), 0o755)
				if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update-search-golden)", err)
			}
			if out != string(want) {
				t.Fatalf("output differs from %s:\n%s", path, diffLines(string(want), out))
			}
		})
	}
}

var refRE = regexp.MustCompile(`"ref":"[A-Za-z0-9_-]*"`)

func diffLines(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < max(len(w), len(g)); i++ {
		var a, b string
		if i < len(w) {
			a = w[i]
		}
		if i < len(g) {
			b = g[i]
		}
		if a != b {
			return fmt.Sprintf("line %d:\nwant %q\ngot  %q\n(%d lines, want %d)", i+1, a, b, len(g), len(w))
		}
	}
	return ""
}

// The golden outputs agree with the records the fixture wrote, worked out
// here by brute force (so an -update can't bless a wrong answer silently).
func TestSearchGoldenAgreesWithRecords(t *testing.T) {
	f := newSearchFixture(t)
	from, to := fxDay0, fxDay0.Add(72*time.Hour)
	stored := func(r fxRec) string {
		esc := strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`).Replace(r.raw)
		return r.at.Format("2006-01-02T15:04:05.000Z") + " " + r.addr + " " + esc
	}
	hidden := model.DeviceID(fxDevs[3])
	visible := func(r fxRec) bool { return r.dev != hidden }
	check := func(name string, keep func(fxRec) bool, desc bool, args ...string) {
		t.Helper()
		var want []string
		for _, r := range f.recs {
			if !r.at.Before(from) && r.at.Before(to) && keep(r) {
				want = append(want, stored(r))
			}
		}
		slices.SortStableFunc(want, func(a, b string) int { return strings.Compare(a[:24], b[:24]) })
		if desc {
			slices.Reverse(want)
		}
		code, out, errOut := runSearch(t, f.dir, append(slices.Clone(fxRange), args...)...)
		got := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		if out == "" {
			got = nil
		}
		if code > 1 || !slices.Equal(got, want) {
			t.Errorf("%s: exit %d %s\n got %d lines, want %d\n%s", name, code, errOut, len(got), len(want), diffLines(strings.Join(want, "\n"), strings.Join(got, "\n")))
		}
	}
	check("all", visible, false)
	check("link down", func(r fxRec) bool { return visible(r) && strings.Contains(strings.ToLower(r.raw), "link down") }, false, "link down")
	check("desc hidden named", func(r fxRec) bool { return r.dev == hidden }, true, "--order", "desc", "--devices", "2001:db8::5")
	check("severity 3", func(r fxRec) bool {
		return visible(r) && (strings.HasPrefix(r.raw, "<187>") || strings.HasPrefix(r.raw, "<11>"))
	}, false, "--severities", "3")
	check("not severity 6", func(r fxRec) bool {
		return visible(r) && !strings.HasPrefix(r.raw, "<134>") && !strings.HasPrefix(r.raw, "<14>")
	}, false, "--not-field", "severity=6")
}

// The JSON output is /api/search's: the same results, refs and fields as
// paging through the API's engine with the same query.
func TestSearchJSONMatchesAPI(t *testing.T) {
	f := newSearchFixture(t)
	idx, err := index.OpenReadOnly(filepath.Join(f.dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	eng := search.New(search.Options{DataDir: f.dir, Index: idx, Now: func() time.Time { return fxNow }})
	for _, c := range []struct {
		args   []string
		params url.Values
	}{
		{[]string{"link"}, url.Values{"q": {"link"}}},
		{[]string{"--order", "desc", "--severities", "3,5"}, url.Values{"severities": {"3,5"}, "order": {"desc"}}},
		{[]string{"--terms", "deny OR error", "--group", "HQ"}, url.Values{"q": {"deny OR error"}, "syntax": {"terms"}, "group": {"HQ"}}},
		{[]string{"--app", "sshd", "--devices", "2001:db8::5,192.0.2.2"}, url.Values{"app": {"sshd"}, "devices": {"2001_db8__5,192.0.2.2"}}},
	} {
		c.params.Set("from", "2026-11-08T00:00:00Z")
		c.params.Set("to", "2026-11-11T00:00:00Z")
		if c.params.Get("order") == "" {
			c.params.Set("order", "asc")
		}
		c.params.Set("limit", "7")
		req, err := api.ParseSearch(c.params)
		if err != nil {
			t.Fatal(err)
		}
		q := server.SearchQuery(req)
		var want []string
		for {
			p, err := eng.Search(context.Background(), q)
			if err != nil {
				t.Fatal(err)
			}
			for _, l := range p.Results {
				b, _ := api.SearchLine{Received: l.Received, DeviceID: l.DeviceID, Severity: l.Severity, Raw: l.Raw, Ref: l.Ref, App: l.App, Host: l.Host}.MarshalJSON()
				want = append(want, string(b))
			}
			if p.NextCursor == "" {
				break
			}
			q.Cursor = p.NextCursor
		}
		code, out, errOut := runSearch(t, f.dir, append(append(slices.Clone(fxRange), "--json"), c.args...)...)
		if code != 0 {
			t.Fatalf("%v: exit %d %s", c.args, code, errOut)
		}
		var got []string
		sc := bufio.NewScanner(strings.NewReader(out))
		for sc.Scan() {
			var m map[string]any
			if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
				t.Fatal(err)
			}
			if m["type"] != "syslog" {
				t.Fatalf("type %v", m["type"])
			}
			if name := m["device_name"]; (m["device_id"] == "192.0.2.1") != (name == "edge-fw-01") {
				t.Fatalf("device_name %v for %v", name, m["device_id"])
			}
			delete(m, "type")
			delete(m, "device_name")
			b, _ := json.Marshal(m)
			var w map[string]any
			json.Unmarshal(b, &w)
			got = append(got, string(b))
		}
		norm := func(ss []string) []string {
			out := make([]string, len(ss))
			for i, s := range ss {
				var m map[string]any
				json.Unmarshal([]byte(s), &m)
				b, _ := json.Marshal(m)
				out[i] = string(b)
			}
			return out
		}
		if !slices.Equal(norm(got), norm(want)) || len(want) == 0 {
			t.Fatalf("%v: CLI %d results, API %d\n%s", c.args, len(got), len(want), diffLines(strings.Join(norm(want), "\n"), strings.Join(norm(got), "\n")))
		}
	}
}

func TestSearchExitCodes(t *testing.T) {
	f := newSearchFixture(t)
	empty := t.TempDir()
	cases := []struct {
		name string
		dir  string
		args []string
		code int
		msg  string // in stderr
	}{
		{"match", f.dir, []string{"link"}, 0, ""},
		{"no match", f.dir, []string{"nothing like this"}, 1, "0 matches"},
		{"unknown flag", f.dir, []string{"--bogus"}, 2, "flag provided but not defined"},
		{"two queries", f.dir, []string{"a", "b"}, 2, `unexpected argument "b"`},
		{"bad regex", f.dir, []string{"--regex", "("}, 2, "QUERY: error parsing regexp"},
		{"bad exclude regex", f.dir, []string{"--regex", "--exclude", "[", "x"}, 2, "--exclude: error parsing regexp"},
		{"terms position", f.dir, []string{"--terms", "deny AND"}, 2, "character"},
		{"terms and regex", f.dir, []string{"--terms", "--regex", "x"}, 2, "--terms and --regex"},
		{"group and ungrouped", f.dir, []string{"--group", "HQ", "--ungrouped"}, 2, "--group and --ungrouped"},
		{"json and raw", f.dir, []string{"--json", "--raw"}, 2, "--json and --raw"},
		{"count and context", f.dir, []string{"--count", "--context", "2"}, 2, "--count"},
		{"type trap", f.dir, []string{"--type", "trap"}, 2, `--type: unknown data type "trap" (this build searches syslog)`},
		{"type syslog", f.dir, []string{"--type", "syslog", "link"}, 0, ""},
		{"bad severity", f.dir, []string{"--severities", "9"}, 2, `--severities: "9" is not a severity`},
		{"bad severity via field", f.dir, []string{"--field", "severity=9"}, 2, `--field severity: "9" is not a severity`},
		{"bad not-field value", f.dir, []string{"--not-field", "severity=9"}, 2, `--not-field "severity=9": "9" isn't a severity`},
		{"unknown field", f.dir, []string{"--field", "colour=red"}, 2, `syslog has no field "colour" (fields: device, severity, facility, host, app)`},
		{"field without value", f.dir, []string{"--field", "host"}, 2, "use KEY=V1,V2"},
		{"bad facility", f.dir, []string{"--facilities", "99"}, 2, "--facilities:"},
		{"bad order", f.dir, []string{"--order", "up"}, 2, "--order:"},
		{"context too big", f.dir, []string{"--context", "501"}, 2, "--context must be from 0 to 500"},
		{"bad last", f.dir, []string{"--last", "5x"}, 2, `--last: "5x" isn't a duration`},
		{"last and from", f.dir, []string{"--last", "1h", "--from", "now"}, 2, "--last is instead of"},
		{"bad from", f.dir, []string{"--from", "yesterday"}, 2, `--from: "yesterday" isn't a time`},
		{"from after to", f.dir, []string{"--from", "2026-11-09T00:00:00Z", "--to", "2026-11-08T00:00:00Z"}, 2, "--from must be before --to"},
		{"negative limit", f.dir, []string{"--limit", "-1"}, 2, "--limit"},
		{"no folder", filepath.Join(empty, "missing"), nil, 4, "there's no data folder at"},
		{"no index", empty, nil, 4, "there's no index (index.db) in"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := runSearch(t, c.dir, c.args...)
			if code != c.code || !strings.Contains(errOut, c.msg) {
				t.Fatalf("exit %d, want %d; stderr %q, want it to hold %q", code, c.code, errOut, c.msg)
			}
		})
	}
	// --config naming a missing file, and one naming the fixture.
	code, _, errOut := runCLI("search", "--config", filepath.Join(empty, "nope.toml"))
	if code != 4 || !strings.Contains(errOut, "there's no config file at") {
		t.Fatalf("missing config: %d %s", code, errOut)
	}
	cfg := filepath.Join(empty, "woodshed.toml")
	os.WriteFile(cfg, []byte(fmt.Sprintf("[storage]\ndata_dir = %q\n", f.dir)), 0o600)
	searchNow = func() time.Time { return fxNow }
	defer func() { searchNow = time.Now }()
	if code, out, errOut := runCLI("search", "--config", cfg, "--count", "--devices", "192.0.2.1"); code != 0 || out != "12\n" {
		t.Fatalf("--config: %d %q %s", code, out, errOut)
	}
	// help
	if code, out, _ := runCLI("help", "search"); code != 0 || !strings.Contains(out, "--not-field") || !strings.Contains(out, "Exit status") {
		t.Fatalf("help: %d %s", code, out)
	}
	if code, out, _ := runCLI("help"); code != 0 || !strings.Contains(out, "search          search the stored logs") {
		t.Fatalf("usage: %d %s", code, out)
	}
	// A query starting with "-" after "--".
	if code, _, errOut := runSearch(t, f.dir, append(slices.Clone(fxRange), "--", "-nothing")...); code != 1 {
		t.Fatalf("-- query: %d %s", code, errOut)
	}
}

// interruptAfter makes the search's context cancelled by the first write to
// standard output, as a Ctrl-C would.
type cancelWriter struct {
	w      io.Writer
	cancel context.CancelFunc
}

func (c *cancelWriter) Write(p []byte) (int, error) { c.cancel(); return c.w.Write(p) }

func TestSearchInterrupted(t *testing.T) {
	f := newSearchFixture(t)
	var cancel context.CancelFunc
	searchSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel = context.WithCancel(ctx)
		return ctx, cancel
	}
	searchFlushEvery = time.Millisecond
	defer func() {
		searchSignals = func(ctx context.Context) (context.Context, context.CancelFunc) { return context.WithCancel(ctx) }
		searchFlushEvery = 200 * time.Millisecond
	}()
	searchNow = func() time.Time { return fxNow }
	defer func() { searchNow = time.Now }()
	var out, errOut bytes.Buffer
	// A slow consumer: the flusher's first write cancels the run.
	cw := &cancelWriter{w: &out, cancel: func() {
		if cancel != nil {
			cancel()
		}
	}}
	code := cmdSearch(append([]string{"--data", f.dir}, fxRange...), cw, &errOut)
	if code != 130 || !strings.Contains(errOut.String(), "(interrupted)") {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	n := strings.Count(out.String(), "\n")
	if n == 0 || n >= 12*4*3 {
		t.Fatalf("%d lines printed before the interrupt", n)
	}
	if !strings.HasSuffix(out.String(), "\n") {
		t.Fatal("a partial line was left")
	}
}

// treeState is every entry of dir: mode, size, mtime and a hash of the bytes.
func treeState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		v := fmt.Sprintf("%v %d %d", fi.Mode(), fi.Size(), fi.ModTime().UnixNano())
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h := sha256.Sum256(b)
			v += " " + hex.EncodeToString(h[:])
		}
		v += ownerOf(fi)
		out[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSearchIsReadOnly(t *testing.T) {
	f := newSearchFixture(t)
	time.Sleep(10 * time.Millisecond)
	before := treeState(t, f.dir)
	for _, args := range [][]string{nil, {"--json"}, {"--context", "3", "link"}, {"--order", "desc", "--context", "2", "deny"},
		{"--count"}, {"--raw", "--order", "desc"}, {"--regex", "("}, {"--type", "trap"}} {
		runSearch(t, f.dir, append(slices.Clone(fxRange), args...)...)
	}
	if after := treeState(t, f.dir); !maps.Equal(before, after) {
		for k, v := range after {
			if before[k] != v {
				t.Errorf("changed or new: %s", k)
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				t.Errorf("gone: %s", k)
			}
		}
	}
}

// TestSearchBesideWriter searches while a store appends, rotates parts and
// compresses days: no error, no duplicate, and every line written before the
// search started is found.
func TestSearchBesideWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	var mu sync.Mutex
	now := fxDay0.Add(time.Hour)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 8 << 10, Manual: true, Clock: clock,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var flushedUpTo int64 = -1
	var wmu sync.Mutex
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		seq := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			mu.Lock()
			now = now.Add(7 * time.Second) // crosses midnight a few times over the test
			at := now
			mu.Unlock()
			for k, a := range fxDevs[:3] {
				raw := fmt.Sprintf("<134>Nov 10 00:00:00 web-01 app: writer line seq=%06d", seq)
				st.Write(model.Message{Received: at.Add(time.Duration(k) * time.Millisecond), Sender: a, Raw: []byte(raw)})
				seq++
			}
			if seq%60 == 0 {
				st.Flush()
				st.Maintain() // parts, the day change and compression
				wmu.Lock()
				flushedUpTo = int64(seq - 1)
				wmu.Unlock()
			}
		}
	}()
	defer func() { close(stop); <-done }()
	time.Sleep(300 * time.Millisecond)
	searchNow = func() time.Time { return clock().Add(time.Hour) }
	defer func() { searchNow = time.Now }()
	for round := 0; round < 6; round++ {
		wmu.Lock()
		upTo := flushedUpTo
		wmu.Unlock()
		for _, order := range []string{"asc", "desc"} {
			var out, errOut bytes.Buffer
			code := cmdSearch([]string{"--data", dir, "--from", fxDay0.Format(time.RFC3339), "--to", fxDay0.Add(30 * 24 * time.Hour).Format(time.RFC3339),
				"--order", order, "--raw", "writer line"}, &out, &errOut)
			if code != 0 {
				t.Fatalf("round %d %s: exit %d %s", round, order, code, errOut.String())
			}
			seen := map[string]bool{}
			for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
				i := strings.Index(l, "seq=")
				s := l[i+4:]
				if seen[s] {
					t.Fatalf("round %d %s: seq %s twice", round, order, s)
				}
				seen[s] = true
			}
			for s := int64(0); s <= upTo; s++ {
				if !seen[fmt.Sprintf("%06d", s)] {
					t.Fatalf("round %d %s: seq %d (written before the search) missing; %d found, %d flushed", round, order, s, len(seen), upTo+1)
				}
			}
			if strings.Contains(errOut.String(), "level=") {
				t.Fatalf("warnings: %s", errOut.String())
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if upTo := flushedUpTo; upTo < 600 {
		t.Logf("only %d lines written", upTo)
	}
}

func TestPortableDataFolderIsFound(t *testing.T) {
	f := newSearchFixture(t)
	bin := t.TempDir()
	if err := os.Rename(f.dir, filepath.Join(bin, portableDirName)); err != nil {
		t.Fatal(err)
	}
	searchExe = func() (string, error) { return filepath.Join(bin, "woodshed"), nil }
	defer func() { searchExe = os.Executable }()
	searchNow = func() time.Time { return fxNow }
	defer func() { searchNow = time.Now }()
	code, out, errOut := runCLI(append([]string{"search", "--count"}, fxRange...)...)
	if code != 0 || out != "108\n" {
		t.Fatalf("portable: %d %q %s", code, out, errOut)
	}
}

func TestTimeArgs(t *testing.T) {
	now := time.Date(2026, 11, 14, 15, 0, 0, 0, time.UTC)
	loc := time.FixedZone("UTC-5", -5*3600)
	for in, want := range map[string]time.Time{
		"2026-11-14T09:30:00Z":      time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC),
		"2026-11-14T04:30:00-05:00": time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC),
		"2026-11-14 04:30":          time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC),
		"2026-11-14 04:30:15":       time.Date(2026, 11, 14, 9, 30, 15, 0, time.UTC),
		"2026-11-14T04:30":          time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC),
		"now":                       now,
		"-15m":                      now.Add(-15 * time.Minute),
		"-7d":                       now.Add(-7 * 24 * time.Hour),
	} {
		got, err := parseTimeArg(in, now, loc)
		if err != nil || !got.Equal(want) {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "yesterday", "-", "-5x", "2026-13-01 00:00", "14/11/2026"} {
		if _, err := parseTimeArg(bad, now, loc); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for in, want := range map[string]time.Duration{"15m": 15 * time.Minute, "1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour,
		"1h30m": 90 * time.Minute, "2w": 14 * 24 * time.Hour, "1.5h": 90 * time.Minute, "90s": 90 * time.Second} {
		if got, err := parseDurationArg(in); err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0m", "h", "5", "5x", "1h-2m"} {
		if _, err := parseDurationArg(bad); err == nil {
			t.Errorf("duration %q accepted", bad)
		}
	}
}

// writerStarts opens the index as a writer (and writes) on the first output
// write: the service starting while a search runs.
type writerStarts struct {
	w    io.Writer
	dir  string
	t    *testing.T
	idx  *index.DB
	once sync.Once
}

func (ws *writerStarts) Write(p []byte) (int, error) {
	ws.once.Do(func() {
		idx, err := index.Open(filepath.Join(ws.dir, index.FileName))
		if err != nil {
			ws.t.Error(err)
			return
		}
		name := "renamed"
		if _, err := idx.UpdateDevice(context.Background(), "192.0.2.2", index.DeviceUpdate{Name: &name}); err != nil {
			ws.t.Error(err)
		}
		ws.idx = idx
	})
	return ws.w.Write(p)
}

// A search that read the index immutable (no writer) warns when a writer
// started during it, and keeps its exit code.
func TestSearchWarnsWhenAWriterStarts(t *testing.T) {
	f := newSearchFixture(t)
	searchNow = func() time.Time { return fxNow }
	defer func() { searchNow = time.Now }()
	const warning = "warning: Woodshed started writing while this search ran; results may be incomplete. Run it again.\n"

	var out, errOut bytes.Buffer
	ws := &writerStarts{w: &out, dir: f.dir, t: t}
	code := cmdSearch(append([]string{"--data", f.dir}, fxRange...), ws, &errOut)
	if ws.idx != nil {
		defer ws.idx.Close()
	}
	if code != 0 || !strings.HasSuffix(errOut.String(), warning) || strings.Count(out.String(), "\n") != 108 {
		t.Fatalf("exit %d, %d lines, stderr %q", code, strings.Count(out.String(), "\n"), errOut.String())
	}

	// Beside a writer that was already running (WAL, not immutable): no warning.
	out.Reset()
	errOut.Reset()
	if code := cmdSearch(append([]string{"--data", f.dir}, fxRange...), &out, &errOut); code != 0 || strings.Contains(errOut.String(), "warning") {
		t.Fatalf("beside a writer: exit %d, stderr %q", code, errOut.String())
	}
	// With the writer gone again (immutable once more), --json warns too.
	ws.idx.Close()
	out.Reset()
	errOut.Reset()
	ws2 := &writerStarts{w: &out, dir: f.dir, t: t}
	if code := cmdSearch(append([]string{"--data", f.dir, "--json"}, fxRange...), ws2, &errOut); code != 0 || !strings.HasSuffix(errOut.String(), warning) {
		t.Fatalf("json: exit %d, stderr %q", code, errOut.String())
	}
	if ws2.idx != nil {
		ws2.idx.Close()
	}
}
