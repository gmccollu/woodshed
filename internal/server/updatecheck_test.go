package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/peer"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
	"github.com/gmccollu/woodshed/internal/updatecheck"
	"github.com/gmccollu/woodshed/internal/updatecheck/uctest"
)

// The update check is the only thing in Woodshed that connects out, only while
// updates.check is "on", and only to the releases file (SPEC §10.2). These run
// the real server with the default transport and resolver hooked (as in
// internal/api's TestNoHandlerDialsOut), the checker's dialer pointed at a local
// TLS server, and a fake clock for the checker's schedule.

const testReleases = "https://github.com/gmccollu/woodshed/releases"

// netHooks counts what goes through the default transport and resolver.
type netHooks struct{ rt, lookups atomic.Int64 }

func hookDefaultNet(t *testing.T) *netHooks {
	h := &netHooks{}
	oldT, oldR := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		h.rt.Add(1)
		return nil, fmt.Errorf("outbound request to %s blocked by test", r.URL.Host)
	})
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		h.lookups.Add(1)
		return nil, errors.New("DNS blocked by test")
	}}
	t.Cleanup(func() { http.DefaultTransport, net.DefaultResolver = oldT, oldR })
	return h
}

func (h *netHooks) check(t *testing.T) {
	t.Helper()
	if n := h.rt.Load(); n != 0 {
		t.Errorf("%d requests through the default transport", n)
	}
	if n := h.lookups.Load(); n != 0 {
		t.Errorf("%d DNS lookups through the default resolver", n)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// updServer is a running server whose checker uses fake.
type updServer struct {
	*running
	clock  *uctest.FakeClock
	fake   *uctest.Server
	client *http.Client
}

func startUpd(t *testing.T, cfgPath, version string, clock *uctest.FakeClock, fake *uctest.Server) *updServer {
	t.Helper()
	// No poll targets in these servers: the poller must send nothing.
	return startUpdWith(t, cfgPath, version, clock, fake, func(ap netip.AddrPort) {
		t.Errorf("an SNMP poll request to %s with no poll targets", ap)
	})
}

func startUpdWith(t *testing.T, cfgPath, version string, clock *uctest.FakeClock, fake *uctest.Server, onSend func(netip.AddrPort)) *updServer {
	t.Helper()
	srv, err := Open(cfgPath, Options{Version: version, Commit: "abc1234", ReleasesURL: testReleases, Logger: quiet,
		updateTesting: fake.Hooks(clock), pollOnSend: onSend, pollUnit: pollUnit})
	if err != nil {
		t.Fatal(err)
	}
	srv.be.peers.find = func(context.Context, peer.Options) (peer.Info, bool) { return peer.Info{}, false }
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{srv: srv, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- srv.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !srv.UIState().Listening {
		if time.Now().After(deadline) {
			t.Fatalf("UI didn't start: %v", srv.UIState().Err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.base = "http://" + srv.UIState().Addr
	t.Cleanup(func() { r.stop(t) })
	// The test's own client has its own transport (the default one is hooked).
	return &updServer{running: r, clock: clock, fake: fake, client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}}}
}

func (u *updServer) call(t *testing.T, method, path, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, u.base+path, rd)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := u.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// exercise requests every route once, the update routes too (setting check
// only to keep, never to change).
func (u *updServer) exercise(t *testing.T, keep string) {
	t.Helper()
	_, settings := u.call(t, "GET", "/api/settings", "")
	for _, rq := range [][3]string{
		{"GET", "/", ""}, {"GET", "/healthz", ""}, {"GET", "/api/status", ""}, {"GET", "/api/stats", ""},
		{"GET", "/api/rejected", ""}, {"GET", "/api/devices", ""}, {"GET", "/api/groups", ""},
		{"PATCH", "/api/devices/none", `{}`}, {"POST", "/api/listeners/retry", ""},
		{"PUT", "/api/settings", settings}, {"GET", "/api/storage/history", ""},
		{"GET", "/api/storage/estimate?retention_bytes=21474836480", ""},
		{"GET", "/api/search?range=24h", ""}, {"GET", "/api/context?ref=x", ""},
		{"GET", "/api/exports", ""}, {"POST", "/api/exports/estimate", `{"range":{"last":"1h"}}`},
		{"GET", "/api/session", ""}, {"GET", "/api/updates", ""}, {"POST", "/api/updates/check", ""},
		{"POST", "/api/updates/dismiss", `{"version":"9.9.9"}`}, {"PUT", "/api/updates", `{"check":"ask"}`},
	} {
		u.call(t, rq[0], rq[1], rq[2])
	}
	if keep == "on" || keep == "off" {
		if code, body := u.call(t, "PUT", "/api/updates", `{"check":"`+keep+`"}`); code != 200 {
			t.Fatalf("PUT /api/updates %s: %d %s", keep, code, body)
		}
	}
	// The live tail: open and close.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	req, _ := http.NewRequestWithContext(ctx, "GET", u.base+"/api/live", nil)
	if resp, err := u.client.Do(req); err == nil {
		resp.Body.Close()
	}
	cancel()
}

// waitLimit bounds each wait for the checker below: generous, as each returns as
// soon as its condition holds (a starved runner took over 5 s on the 1 MiB case).
const waitLimit = 20 * time.Second

// waitCheck waits for the checker to schedule its next check and moves the
// clock there, then waits for that check's request and result.
func (u *updServer) next(t *testing.T) time.Time {
	t.Helper()
	d, ok := u.clock.WaitTimer(waitLimit)
	if !ok {
		t.Fatal("no check scheduled")
	}
	u.clock.Advance(d.Sub(u.clock.Now()))
	if _, ok := u.fake.WaitRequest(waitLimit); !ok {
		t.Fatal("no request")
	}
	deadline := time.Now().Add(waitLimit)
	for {
		in := u.srv.be.updates.Info()
		if _, pending := u.clock.Pending(); pending && in.LastCheck != nil && !in.LastCheck.Before(u.clock.Now()) {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatal("the check didn't finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func (u *updServer) banners(t *testing.T) []api.Banner {
	t.Helper()
	st, err := u.srv.be.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return slices.DeleteFunc(st.Banners, func(b api.Banner) bool { return !strings.HasPrefix(b.Kind, "update_") })
}

func newUpdConfig(t *testing.T, check string) string {
	t.Helper()
	return writeConfig(t, t.TempDir(), freePort(t), 0, func(c *config.Config) { c.Updates.Check = check })
}

func checkReq(t *testing.T, r uctest.Request) {
	t.Helper()
	if r.Method != "GET" || r.Host != updatecheck.Host || r.Path != "/woodshed/releases.json" || r.Query != "" {
		t.Errorf("request %s %s%s?%s", r.Method, r.Host, r.Path, r.Query)
	}
	want := map[string]string{"User-Agent": "Woodshed", "Accept": "application/json", "Accept-Encoding": "gzip"}
	if len(r.Header) != len(want) {
		t.Errorf("headers %v, want exactly %v", r.Header, want)
	}
	for k, v := range want {
		if got := r.Header.Values(k); len(got) != 1 || got[0] != v {
			t.Errorf("%s: %v, want %q", k, got, v)
		}
	}
}

func onlyHostDials(t *testing.T, fake *uctest.Server) {
	t.Helper()
	for _, d := range fake.Dials() {
		if d != net.JoinHostPort(updatecheck.Host, "443") {
			t.Errorf("the checker dialed %s", d)
		}
	}
}

func TestOnlyUpdateCheckDials(t *testing.T) {
	if os.Getenv(proxyChildEnv) != "" {
		t.Skip("the proxy child runs TestUpdateCheckProxyChild only")
	}
	nh := hookDefaultNet(t)
	newClock := func() *uctest.FakeClock { return uctest.NewFakeClock(time.Now().UTC()) }

	for _, check := range []string{"ask", "off"} {
		t.Run(check, func(t *testing.T) {
			clock := newClock()
			fake := uctest.NewServer(t, clock)
			u := startUpd(t, newUpdConfig(t, check), "1.1.0", clock, fake)
			for range 3 {
				for range 24 {
					clock.Advance(time.Hour)
				}
				u.exercise(t, check)
			}
			time.Sleep(20 * time.Millisecond)
			if d := fake.Dials(); len(d) != 0 {
				t.Errorf("dials %v", d)
			}
			if n := len(fake.Requests()); n != 0 {
				t.Errorf("%d requests", n)
			}
			bs := u.banners(t)
			if check == "ask" && (len(bs) != 1 || bs[0].Kind != "update_prompt") {
				t.Errorf("ask: banners %+v", bs)
			}
			if check == "off" && len(bs) != 0 {
				t.Errorf("off: banners %+v", bs)
			}
			nh.check(t)
		})
	}

	t.Run("on", func(t *testing.T) {
		clock := newClock()
		start := clock.Now()
		fake := uctest.NewServer(t, clock)
		u := startUpd(t, newUpdConfig(t, "on"), "1.1.0", clock, fake)
		first := u.next(t)
		if d := first.Sub(start); d < 2*time.Minute || d >= 10*time.Minute {
			t.Errorf("first check %v after start, want 2-10 min", d)
		}
		prev := first
		for range 3 {
			u.exercise(t, "on")
			at := u.next(t)
			if gap := at.Sub(prev); gap < 23*time.Hour || gap > 25*time.Hour {
				t.Errorf("gap %v, want 24 h ± 1 h", gap)
			}
			prev = at
		}
		reqs := fake.Requests()
		// Check now in exercise() runs once a day too, a minute apart at most.
		if len(reqs) < 4 {
			t.Errorf("%d requests, want at least 4", len(reqs))
		}
		for _, r := range reqs {
			checkReq(t, r)
		}
		onlyHostDials(t, fake)
		if bs := u.banners(t); len(bs) != 1 || bs[0].Kind != "update_available" || bs[0].URL != testReleases+"/tag/v1.2.0" {
			t.Errorf("banners %+v", bs)
		}
		nh.check(t)
	})

	t.Run("scheduled_only", func(t *testing.T) {
		// Without Check now: exactly one request in the start-up window, then one a day.
		clock := newClock()
		fake := uctest.NewServer(t, clock)
		u := startUpd(t, newUpdConfig(t, "on"), "1.1.0", clock, fake)
		for i := range 4 {
			u.next(t)
			if n := len(fake.Requests()); n != i+1 {
				t.Fatalf("after check %d: %d requests", i+1, n)
			}
		}
		onlyHostDials(t, fake)
		nh.check(t)
	})

	t.Run("off_while_waiting", func(t *testing.T) {
		clock := newClock()
		fake := uctest.NewServer(t, clock)
		u := startUpd(t, newUpdConfig(t, "on"), "1.1.0", clock, fake)
		u.next(t)
		if len(u.banners(t)) != 1 {
			t.Fatal("no banner after the check")
		}
		if code, body := u.call(t, "PUT", "/api/updates", `{"check":"off"}`); code != 200 || !strings.Contains(body, `"latest":null`) {
			t.Fatalf("PUT off: %d %s", code, body)
		}
		if len(u.banners(t)) != 0 {
			t.Error("the banner stayed after turning it off")
		}
		for range 3 * 24 {
			clock.Advance(time.Hour)
		}
		time.Sleep(20 * time.Millisecond)
		if n := len(fake.Requests()); n != 1 {
			t.Errorf("%d requests, want 1", n)
		}
		cfg, _, err := LoadConfig(u.srv.ConfigPath())
		if err != nil || cfg.Updates.Check != "off" {
			t.Errorf("config: %q %v", cfg.Updates.Check, err)
		}
		nh.check(t)
	})

	t.Run("restart_within_24h", func(t *testing.T) {
		clock := newClock()
		fake := uctest.NewServer(t, clock)
		cfgPath := newUpdConfig(t, "on")
		u := startUpd(t, cfgPath, "1.1.0", clock, fake)
		checked := u.next(t)
		u.stop(t)
		clock.Advance(3 * time.Hour)
		u2 := startUpd(t, cfgPath, "1.1.0", clock, fake)
		for range 12 {
			clock.Advance(time.Minute)
		}
		time.Sleep(20 * time.Millisecond)
		if n := len(fake.Requests()); n != 1 {
			t.Fatalf("a restart within 24 h checked at start-up (%d requests)", n)
		}
		if bs := u2.banners(t); len(bs) != 1 || bs[0].Kind != "update_available" {
			t.Errorf("banner after the restart: %+v", bs)
		}
		if at := u2.next(t); !at.Equal(checked.Add(24 * time.Hour)) {
			t.Errorf("next check at %v, want 24 h after %v", at, checked)
		}
		nh.check(t)
	})

	t.Run("prerelease", func(t *testing.T) {
		for _, tc := range []struct{ version, want string }{{"1.1.0", "1.2.0"}, {"1.2.0-rc1", "1.3.0-rc2"}} {
			clock := newClock()
			fake := uctest.NewServer(t, clock)
			fake.Handle(fake.Releases("v1.2.0", "v1.3.0-rc2"))
			u := startUpd(t, newUpdConfig(t, "on"), tc.version, clock, fake)
			u.next(t)
			bs := u.banners(t)
			if want := "Woodshed " + tc.want + " is available (this is " + tc.version + ")."; len(bs) != 1 || bs[0].Text != want {
				t.Errorf("%s: banners %+v, want %q", tc.version, bs, want)
			}
		}
		nh.check(t)
	})

	t.Run("bad_responses", func(t *testing.T) {
		big := strings.Repeat(" ", 1<<20+1)
		js := func(body string) http.HandlerFunc {
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
				http.Redirect(w, r, "https://"+updatecheck.Host+"/moved.json", http.StatusMovedPermanently)
			}, "redirect"},
			{"huge", js(`{"stable":null}` + big), "too_large"},
			{"not_json", js(`not json`), "bad_json"},
			{"offsite_html_url", js(`{"stable":{"tag_name":"v1.2.0","html_url":"https://evil.example/x"},"prerelease":null}`), "bad_json"},
			{"no_release", js(`{"stable":null,"prerelease":null}`), "no_release"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				clock := newClock()
				fake := uctest.NewServer(t, clock)
				fake.Handle(tc.h)
				u := startUpd(t, newUpdConfig(t, "on"), "1.1.0", clock, fake)
				first := u.next(t)
				code, body := u.call(t, "GET", "/api/updates", "")
				if code != 200 || !strings.Contains(body, `"last_result":"error"`) || !strings.Contains(body, `"last_error_kind":"`+tc.kind+`"`) ||
					!strings.Contains(body, `"latest":null`) {
					t.Errorf("updates: %d %s", code, body)
				}
				if bs := u.banners(t); len(bs) != 0 {
					t.Errorf("banners %+v", bs)
				}
				retry := u.next(t)
				if d := retry.Sub(first); d < time.Hour || d > 2*time.Hour {
					t.Errorf("retry after %v", d)
				}
				daily := u.next(t)
				if d := daily.Sub(first); d < 23*time.Hour || d > 25*time.Hour {
					t.Errorf("then the daily check %v after the first", d)
				}
				if n := len(fake.Requests()); n != 3 {
					t.Errorf("%d requests, want 3: one retry, then the daily check", n)
				}
				onlyHostDials(t, fake)
			})
		}
		nh.check(t)
	})

	// The proxy: in a child process, because Go reads HTTPS_PROXY and NO_PROXY
	// once per process.
	for _, mode := range []string{"proxy", "no_proxy"} {
		t.Run(mode, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestUpdateCheckProxyChild$", "-test.v", "-test.count=1")
			cmd.Env = append(os.Environ(), proxyChildEnv+"="+mode)
			out, err := cmd.CombinedOutput()
			if err != nil || !strings.Contains(string(out), "--- PASS: TestUpdateCheckProxyChild") {
				t.Fatalf("child: %v\n%s", err, out)
			}
		})
	}

	// Since 1.3 (SPEC §12.4): with no poll targets the poller sends nothing
	// (startUpd fails any send above); with one, its requests go only to the
	// target's address and port, and the update check still dials nothing.
	t.Run("poll_targets", func(t *testing.T) {
		clock := newClock()
		fake := uctest.NewServer(t, clock)
		a, err := agenttest.Start(agenttest.Options{Community: "nodial-test-comm"})
		if err != nil {
			t.Fatal(err)
		}
		defer a.Close()
		var mu sync.Mutex
		dst := map[netip.AddrPort]int{}
		u := startUpdWith(t, newUpdConfig(t, "off"), "1.1.0", clock, fake, func(ap netip.AddrPort) {
			mu.Lock()
			dst[ap]++
			mu.Unlock()
		})
		body := fmt.Sprintf(`{"address":"127.0.0.1","port":%d,"version":"2c","community":"nodial-test-comm"}`, a.Addr().Port())
		if code, out := u.call(t, "POST", "/api/poll/targets", body); code != 201 {
			t.Fatalf("add a target: %d %s", code, out)
		}
		waitFor(t, "a poll", func() bool { return a.Requests()["get"] > 0 })
		mu.Lock()
		for ap := range dst {
			if ap != a.Addr() {
				t.Errorf("a poll request to %s; the only target is %s", ap, a.Addr())
			}
		}
		mu.Unlock()
		if d := fake.Dials(); len(d) != 0 {
			t.Errorf("dials %v", d)
		}
		for src := range a.Sources() {
			if !src.Addr().IsLoopback() {
				t.Errorf("a request from %s", src)
			}
		}
		nh.check(t)
	})
}

const proxyChildEnv = "WOODSHED_TEST_UPDATECHECK_PROXY_CHILD"

// TestUpdateCheckProxyChild runs only as TestOnlyUpdateCheckDials's child: with
// HTTPS_PROXY set, the one connection is a CONNECT to Host:443 through the
// proxy; with a matching NO_PROXY, it goes direct.
func TestUpdateCheckProxyChild(t *testing.T) {
	mode := os.Getenv(proxyChildEnv)
	if mode == "" {
		t.Skip("runs as a child of TestOnlyUpdateCheckDials")
	}
	nh := hookDefaultNet(t)
	clock := uctest.NewFakeClock(time.Now().UTC())
	fake := uctest.NewServer(t, clock)
	proxy := uctest.NewProxy(t, fake)
	proxyAddr := proxy.Listener.Addr().String()
	// Before anything in this process reads the proxy variables.
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		os.Unsetenv(k)
	}
	os.Setenv("HTTPS_PROXY", "http://"+proxyAddr)
	if mode == "no_proxy" {
		os.Setenv("NO_PROXY", "example.net,"+updatecheck.Host)
	}
	u := startUpd(t, newUpdConfig(t, "on"), "1.1.0", clock, fake)
	u.next(t)
	checkReq(t, fake.Requests()[0])
	connects, other := proxy.Connects()
	dials := fake.Dials()
	switch mode {
	case "proxy":
		if !slices.Equal(dials, []string{proxyAddr}) {
			t.Errorf("dials %v, want only the proxy %s", dials, proxyAddr)
		}
		if !slices.Equal(connects, []string{net.JoinHostPort(updatecheck.Host, "443")}) || other != 0 {
			t.Errorf("proxy saw CONNECT %v and %d other requests", connects, other)
		}
	case "no_proxy":
		if !slices.Equal(dials, []string{net.JoinHostPort(updatecheck.Host, "443")}) {
			t.Errorf("dials %v, want direct", dials)
		}
		if len(connects) != 0 || other != 0 {
			t.Errorf("the proxy was used: %v %d", connects, other)
		}
	}
	if in := u.srv.be.updates.Info(); in.LastResult != "ok" {
		t.Errorf("result %+v", in)
	}
	nh.check(t)
}
