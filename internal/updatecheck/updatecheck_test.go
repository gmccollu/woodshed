package updatecheck_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/updatecheck"
	"github.com/gmccollu/woodshed/internal/updatecheck/uctest"
)

const releases = "https://github.com/gmccollu/woodshed/releases"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestVersionCompare(t *testing.T) {
	// Each is older than the next.
	order := []string{"0.9.0-rc3", "0.9.0", "1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-beta", "1.0.0-beta2", "1.0.0-beta10",
		"1.0.0-rc1", "1.0.0-rc2", "1.0.0-rc9", "1.0.0-rc10", "1.0.0", "1.0.1", "1.1.0-rc.1", "1.1.0-rc.2", "1.1.0", "1.10.0", "2.0.0"}
	for i := range order {
		for j := range order {
			a, ok1 := updatecheck.ParseVersion(order[i])
			b, ok2 := updatecheck.ParseVersion(order[j])
			if !ok1 || !ok2 {
				t.Fatalf("parse %q %q", order[i], order[j])
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := a.Compare(b); got != want {
				t.Errorf("%s vs %s: %d, want %d", order[i], order[j], got, want)
			}
		}
	}
	if v, ok := updatecheck.ParseVersion("v1.2.3"); !ok || v.String() != "1.2.3" {
		t.Errorf("v1.2.3: %v %v", v, ok)
	}
	for _, bad := range []string{"", "1.2", "1.2.3.4", "01.2.3", "1.2.3-", "1.2.3-rc..1", "1.2.3+build", "1.2.3-01", "x1.2.3",
		"1.2.3-<b>", strings.Repeat("1", 70) + ".0.0"} {
		if _, ok := updatecheck.ParseVersion(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestReleaseBuild(t *testing.T) {
	for v, want := range map[string]bool{
		"1.1.0": true, "1.1.0-rc1": true, "1.1.0-rc.2": true, "0.9.0-rc3": true, "1.2.0-beta": true, "0.0.1": true,
		"0.0.0-dev": false, "0.0.0-ci+abc1234": false, "0.0.0": false, "1.0.0-5-gabc1234": false, "1.0.0-5-gabc1234-dirty": false,
		"1.0.1-snapshot.abc1234": false, "1.0.1-snapshot.1234567": false, "1.1.0+meta": false, "abc1234": false, "1.1.0-dev": false,
		"1.1.0-dirty": false, "": false,
	} {
		if _, got := updatecheck.ReleaseBuild(v); got != want {
			t.Errorf("ReleaseBuild(%q) = %v, want %v", v, got, want)
		}
	}
}

// harness is a checker against the fake host, on a fake clock.
type harness struct {
	t     *testing.T
	clock *uctest.FakeClock
	srv   *uctest.Server
	c     *updatecheck.Checker
	dir   string
	stop  func()
	start time.Time
}

func newHarness(t *testing.T, version, check string, dir string, clock *uctest.FakeClock, srv *uctest.Server) *harness {
	t.Helper()
	if clock == nil {
		clock = uctest.NewFakeClock(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC))
	}
	if srv == nil {
		srv = uctest.NewServer(t, clock)
	}
	if dir == "" {
		dir = t.TempDir()
	}
	h := &harness{t: t, clock: clock, srv: srv, dir: dir, start: clock.Now()}
	hooks := srv.Hooks(clock)
	n := 0
	hooks.Rand = func() float64 { n++; return []float64{0.5, 0.1, 0.9, 0.3}[n%4] }
	h.c = updatecheck.New(updatecheck.Options{Version: version, ReleasesURL: releases, DataDir: dir, Check: check, Logger: quiet, Testing: hooks})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.c.Run(ctx) }()
	h.stop = func() { cancel(); <-done }
	t.Cleanup(h.stop)
	return h
}

// waitLimit bounds each wait for the checker: generous, as each returns as soon
// as its condition holds (the server's copy of this harness ran past 5 s on a
// starved runner).
const waitLimit = 20 * time.Second

// next waits for the checker to schedule a check and moves the clock to it.
func (h *harness) next() time.Time {
	h.t.Helper()
	d, ok := h.clock.WaitTimer(waitLimit)
	if !ok {
		h.t.Fatal("no check scheduled")
	}
	h.clock.Advance(d.Sub(h.clock.Now()))
	return d
}

// request waits for the request the last next() triggered and for its result.
func (h *harness) request() uctest.Request {
	h.t.Helper()
	r, ok := h.srv.WaitRequest(waitLimit)
	if !ok {
		h.t.Fatal("no request")
	}
	h.settle()
	return r
}

// settle waits until the check has finished (the next one is scheduled).
func (h *harness) settle() {
	h.t.Helper()
	deadline := time.Now().Add(waitLimit)
	for time.Now().Before(deadline) {
		if in := h.c.Info(); in.LastCheck != nil && !in.LastCheck.Before(h.clock.Now()) {
			if _, ok := h.clock.Pending(); ok {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatal("the check didn't finish")
}

func TestScheduleOn(t *testing.T) {
	h := newHarness(t, "1.1.0", "on", "", nil, nil)
	first := h.next()
	if d := first.Sub(h.start); d < 2*time.Minute || d >= 10*time.Minute {
		t.Errorf("first check %v after start, want 2-10 min", d)
	}
	r := h.request()
	checkRequest(t, r)
	in := h.c.Info()
	if in.LastResult != "ok" || in.Latest == nil || in.Latest.Version != "1.2.0" || !in.UpdateAvailable ||
		in.Latest.URL != releases+"/tag/v1.2.0" {
		t.Fatalf("info %+v latest %+v", in, in.Latest)
	}
	if in.NextCheck == nil {
		t.Fatal("no next check")
	}
	bs := h.c.Banners()
	if len(bs) != 1 || bs[0].Kind != "update_available" || bs[0].Text != "Woodshed 1.2.0 is available (this is 1.1.0)." ||
		bs[0].URL != releases+"/tag/v1.2.0" || bs[0].Action != "update_dismiss" || bs[0].Level != "info" {
		t.Errorf("banners %+v", bs)
	}
	prev := first
	for range 4 {
		at := h.next()
		if gap := at.Sub(prev); gap < 23*time.Hour || gap > 25*time.Hour {
			t.Errorf("gap %v, want 24 h ± 1 h", gap)
		}
		checkRequest(t, h.request())
		prev = at
	}
	if n := len(h.srv.Requests()); n != 5 {
		t.Errorf("%d requests, want 5", n)
	}
	// The state file is 0640 and holds the result.
	fi, err := os.Stat(filepath.Join(h.dir, updatecheck.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o640 {
		t.Errorf("state file mode %v", fi.Mode().Perm())
	}
}

func checkRequest(t *testing.T, r uctest.Request) {
	t.Helper()
	if r.Method != "GET" || r.Host != updatecheck.Host || r.Path != "/woodshed/releases.json" || r.Query != "" {
		t.Errorf("request %s %s %s ?%s", r.Method, r.Host, r.Path, r.Query)
	}
	want := map[string]string{"User-Agent": "Woodshed", "Accept": "application/json", "Accept-Encoding": "gzip"}
	if len(r.Header) != len(want) {
		t.Errorf("headers %v, want exactly %v", r.Header, want)
	}
	for k, v := range want {
		if got := r.Header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("header %s = %v, want %q", k, got, v)
		}
	}
}

func TestAskAndOffNeverDial(t *testing.T) {
	for _, check := range []string{"ask", "off"} {
		t.Run(check, func(t *testing.T) {
			h := newHarness(t, "1.1.0", check, "", nil, nil)
			for range 3 * 24 {
				h.clock.Advance(time.Hour)
			}
			_ = h.c.CheckNow()
			time.Sleep(20 * time.Millisecond)
			if n := len(h.srv.Dials()); n != 0 {
				t.Errorf("%d dials", n)
			}
			if _, ok := h.clock.Pending(); ok {
				t.Error("a check is scheduled")
			}
			if !errors.Is(h.c.CheckNow(), updatecheck.ErrNotOn) {
				t.Error("CheckNow didn't say it's off")
			}
			bs := h.c.Banners()
			if check == "ask" && (len(bs) != 1 || bs[0].Kind != "update_prompt" || bs[0].Action != "update_choice" || bs[0].Text != updatecheck.PromptText) {
				t.Errorf("ask banners %+v", bs)
			}
			if check == "off" && len(bs) != 0 {
				t.Errorf("off banners %+v", bs)
			}
			if in := h.c.Info(); in.NextCheck != nil || in.Latest != nil || !in.Available {
				t.Errorf("info %+v", in)
			}
		})
	}
}

func TestDevBuildNeverChecksOrAsks(t *testing.T) {
	for _, v := range []string{"0.0.0-dev", "1.0.0-3-gabc1234"} {
		h := newHarness(t, v, "on", "", nil, nil)
		h.clock.Advance(48 * time.Hour)
		time.Sleep(20 * time.Millisecond)
		if len(h.srv.Dials()) != 0 || len(h.c.Banners()) != 0 || h.c.Available() {
			t.Errorf("%s: dials %v banners %v", v, h.srv.Dials(), h.c.Banners())
		}
		if !errors.Is(h.c.CheckNow(), updatecheck.ErrUnavailable) {
			t.Errorf("%s: CheckNow", v)
		}
		if _, err := os.Stat(filepath.Join(h.dir, updatecheck.StateFile)); err == nil {
			t.Errorf("%s: wrote a state file", v)
		}
	}
	// No releases page: unavailable too.
	c := updatecheck.New(updatecheck.Options{Version: "1.1.0", DataDir: t.TempDir(), Check: "ask", Logger: quiet})
	if c.Available() || len(c.Banners()) != 0 {
		t.Error("no releases_url: available")
	}
}

func TestTurnOffWhileWaiting(t *testing.T) {
	h := newHarness(t, "1.1.0", "on", "", nil, nil)
	h.next()
	h.request()
	if len(h.c.Banners()) != 1 {
		t.Fatal("no banner")
	}
	h.c.SetCheck("off")
	if len(h.c.Banners()) != 0 || h.c.Info().Latest != nil {
		t.Error("turning it off didn't clear the banner")
	}
	for range 4 * 24 {
		h.clock.Advance(time.Hour)
	}
	time.Sleep(20 * time.Millisecond)
	if n := len(h.srv.Requests()); n != 1 {
		t.Errorf("%d requests after turning it off", n)
	}
	// Turning it on checks within a minute.
	on := h.clock.Now()
	h.c.SetCheck("on")
	at := h.next()
	if d := at.Sub(on); d <= 0 || d > time.Minute {
		t.Errorf("turned on: checked after %v", d)
	}
	h.request()
	if len(h.srv.Requests()) != 2 {
		t.Error("no check after turning it on")
	}
}

func TestRestartWithin24h(t *testing.T) {
	clock := uctest.NewFakeClock(time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC))
	srv := uctest.NewServer(t, clock)
	dir := t.TempDir()
	h := newHarness(t, "1.1.0", "on", dir, clock, srv)
	checked := h.next()
	h.request()
	h.stop()

	clock.Advance(3 * time.Hour)
	h2 := newHarness(t, "1.1.0", "on", dir, clock, srv)
	if len(h2.c.Banners()) != 1 {
		t.Error("the banner didn't survive the restart")
	}
	at := h2.next()
	if want := checked.Add(24 * time.Hour); !at.Equal(want) {
		t.Errorf("after a restart the next check is at %v, want %v (24 h after the last)", at, want)
	}
	h2.request()
	if n := len(srv.Requests()); n != 2 {
		t.Errorf("%d requests", n)
	}
	// A restart more than 24 h later checks in the start-up window again.
	h2.stop()
	clock.Advance(30 * time.Hour)
	h3 := newHarness(t, "1.1.0", "on", dir, clock, srv)
	if d := h3.next().Sub(h3.start); d < 2*time.Minute || d >= 10*time.Minute {
		t.Errorf("late restart: first check after %v", d)
	}
}

func TestCheckNowLimit(t *testing.T) {
	h := newHarness(t, "1.1.0", "on", "", nil, nil)
	if err := h.c.CheckNow(); err != nil {
		t.Fatal(err)
	}
	h.request()
	var ts *updatecheck.TooSoonError
	if err := h.c.CheckNow(); !errors.As(err, &ts) || ts.RetryAfter <= 0 || ts.RetryAfter > time.Minute {
		t.Errorf("second CheckNow: %v", err)
	}
	h.clock.Advance(61 * time.Second)
	if err := h.c.CheckNow(); err != nil {
		t.Errorf("after a minute: %v", err)
	}
	h.request()
}

func TestDismiss(t *testing.T) {
	h := newHarness(t, "1.1.0", "on", "", nil, nil)
	h.next()
	h.request()
	if h.c.Dismiss("not a version") {
		t.Error("dismissed a non-version")
	}
	if !h.c.Dismiss("1.2.0") || len(h.c.Banners()) != 0 || h.c.Info().DismissedVersion != "1.2.0" {
		t.Errorf("dismiss: %+v", h.c.Banners())
	}
	// A newer version shows it again.
	h.srv.Handle(h.srv.Releases("v1.3.0", ""))
	h.next()
	h.request()
	if bs := h.c.Banners(); len(bs) != 1 || !strings.Contains(bs[0].Text, "1.3.0") {
		t.Errorf("newer version: %+v", bs)
	}
}

func TestPrereleaseRules(t *testing.T) {
	for _, tc := range []struct {
		current, stable, pre string
		want                 string // latest version
		avail                bool
	}{
		{"1.1.0", "v1.2.0", "v1.3.0-rc1", "1.2.0", true},         // a release build ignores prereleases
		{"1.1.0", "v1.1.0", "v1.2.0-rc1", "1.1.0", false},        // up to date
		{"1.2.0-rc1", "v1.1.0", "v1.2.0-rc2", "1.2.0-rc2", true}, // a prerelease build sees prereleases
		{"1.2.0-rc9", "v1.1.0", "v1.2.0-rc10", "1.2.0-rc10", true},
		{"1.2.0-rc2", "v1.2.0", "v1.3.0-rc1", "1.3.0-rc1", true}, // the newer of the two
		{"1.2.0-rc2", "v1.2.0", "v1.2.0-rc3", "1.2.0", true},
		{"1.2.0-rc2", "v1.1.0", "", "1.1.0", false},
		{"1.2.0-rc2", "", "v1.2.0-rc1", "1.2.0-rc1", false},
	} {
		t.Run(tc.current+"_"+tc.stable+"_"+tc.pre, func(t *testing.T) {
			h := newHarness(t, tc.current, "on", "", nil, nil)
			h.srv.Handle(h.srv.Releases(tc.stable, tc.pre))
			h.next()
			h.request()
			in := h.c.Info()
			if in.LastResult != "ok" || in.Latest == nil || in.Latest.Version != tc.want || in.UpdateAvailable != tc.avail {
				t.Errorf("info %+v latest %+v", in, in.Latest)
			}
			if got := len(h.c.Banners()) == 1; got != tc.avail {
				t.Errorf("banner %v, want %v", h.c.Banners(), tc.avail)
			}
		})
	}
}

// Bad responses: an error in Settings, no banner, and one retry (1-2 h later),
// then the next daily check.
func TestBadResponses(t *testing.T) {
	big := strings.Repeat(" ", 1<<20+1)
	jsonCT := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, body)
		}
	}
	for _, tc := range []struct {
		name string
		h    http.HandlerFunc
		kind string
	}{
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+updatecheck.Host+"/elsewhere.json", http.StatusFound)
		}, updatecheck.KindRedirect},
		{"404", func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) }, updatecheck.KindHTTPStatus},
		{"too_large", jsonCT(`{"stable":null}` + big), updatecheck.KindTooLarge},
		{"too_large_gzip", func(w http.ResponseWriter, r *http.Request) {
			var b bytes.Buffer
			z := gzip.NewWriter(&b)
			z.Write([]byte(`{"stable":null,"x":"` + big + `"}`))
			z.Close()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(b.Bytes())
		}, updatecheck.KindTooLarge},
		{"not_json", jsonCT(`<html>hi</html>`), updatecheck.KindBadJSON},
		{"html_type", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, uctest.ReleasesJSON("v1.2.0", ""))
		}, updatecheck.KindBadJSON},
		{"offsite_html_url", jsonCT(`{"stable":{"tag_name":"v1.2.0","html_url":"https://evil.example/woodshed"},"prerelease":null}`), updatecheck.KindBadJSON},
		{"lookalike_html_url", jsonCT(`{"stable":{"tag_name":"v1.2.0","html_url":"` + releases + `.evil.example/tag/v1.2.0"},"prerelease":null}`), updatecheck.KindBadJSON},
		{"bad_tag", jsonCT(`{"stable":{"tag_name":"v1.2.0<script>","html_url":""},"prerelease":null}`), updatecheck.KindBadJSON},
		{"prerelease_as_stable", jsonCT(`{"stable":{"tag_name":"v1.2.0-rc1","html_url":""},"prerelease":null}`), updatecheck.KindBadJSON},
		{"no_release", jsonCT(`{"generated_at":"2026-11-13T00:00:00Z","stable":null,"prerelease":null}`), updatecheck.KindNoRelease},
		{"array", jsonCT(`[]`), updatecheck.KindBadJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, "1.1.0", "on", "", nil, nil)
			h.srv.Handle(tc.h)
			first := h.next()
			h.request()
			in := h.c.Info()
			if in.LastResult != "error" || in.LastErrorKind != tc.kind || in.LastError == "" || in.Latest != nil {
				t.Errorf("info %+v", in)
			}
			if strings.Contains(in.LastError, "evil") || strings.Contains(in.LastError, "script") || strings.Contains(in.LastError, "html") && tc.name != "not_json" {
				t.Errorf("the error repeats the response: %q", in.LastError)
			}
			if len(h.c.Banners()) != 0 {
				t.Errorf("banners %+v", h.c.Banners())
			}
			retry := h.next()
			if d := retry.Sub(first); d < time.Hour || d > 2*time.Hour {
				t.Errorf("retry after %v, want 1-2 h", d)
			}
			h.request()
			daily := h.next()
			if d := daily.Sub(first); d < 23*time.Hour || d > 25*time.Hour {
				t.Errorf("after the retry, next check %v after the first, want 24 h ± 1 h", d)
			}
			h.request()
			if n := len(h.srv.Requests()); n != 3 {
				t.Errorf("%d requests, want 3 (no retry beyond the one)", n)
			}
		})
	}
}

func TestHTMLURLRules(t *testing.T) {
	for _, tc := range []struct{ html, want string }{
		{releases + "/tag/v1.2.0", releases + "/tag/v1.2.0"},
		{releases + "/tag/v9.9.9", releases},
		{releases + "/latest", releases},
		{"", releases},
	} {
		h := newHarness(t, "1.1.0", "on", "", nil, nil)
		h.srv.Handle(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"stable":{"tag_name":"v1.2.0","html_url":%q},"prerelease":null}`, tc.html)
		})
		h.next()
		h.request()
		if bs := h.c.Banners(); len(bs) != 1 || bs[0].URL != tc.want {
			t.Errorf("html_url %q: banners %+v, want url %q", tc.html, bs, tc.want)
		}
	}
}

func TestTLSUntrusted(t *testing.T) {
	h := newHarness(t, "1.1.0", "off", "", nil, nil)
	// Another checker on the same server without its CA.
	hooks := h.srv.Hooks(h.clock)
	hooks.RootCAs = nil
	dir := t.TempDir()
	c := updatecheck.New(updatecheck.Options{Version: "1.1.0", ReleasesURL: releases, DataDir: dir, Check: "on", Logger: quiet, Testing: hooks})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	if err := c.CheckNow(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for c.Info().LastCheck == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if in := c.Info(); in.LastErrorKind != updatecheck.KindTLS {
		t.Errorf("info %+v", in)
	}
}

func TestStateFileIsSmall(t *testing.T) {
	h := newHarness(t, "1.1.0", "on", "", nil, nil)
	h.next()
	h.request()
	b, err := os.ReadFile(filepath.Join(h.dir, updatecheck.StateFile))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"last_check", "last_result", "latest", "dismissed_version"} {
		if _, ok := m[k]; !ok {
			t.Errorf("state file lacks %s: %s", k, b)
		}
	}
	last, result, _, latest, ok := updatecheck.ReadState(h.dir)
	if !ok || last == nil || result != "ok" || latest == nil || latest.Version != "1.2.0" {
		t.Errorf("ReadState: %v %q %+v %v", last, result, latest, ok)
	}
}
