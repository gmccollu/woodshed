package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gmccollu/woodshed/internal/peer"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/store"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// freePort returns a port that is free for both UDP and TCP on 127.0.0.1.
//
// Windows hands out ephemeral ports in sequence, and a run of them can sit inside
// the other protocol's excluded port range (seen on the windows-11-arm runner:
// 50 TCP ports in a row with UDP refused on each). So the tries alternate between
// an ephemeral UDP port (then TCP on the same number) and a random port below the
// ephemeral range (UDP and TCP both).
func freePort(t *testing.T) int {
	t.Helper()
	both := func(port int) bool {
		u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		defer u.Close()
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return false
		}
		l.Close()
		return true
	}
	for i := range 1000 {
		if i%2 == 0 {
			u, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := u.LocalAddr().(*net.UDPAddr).Port
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			u.Close()
			if err == nil {
				l.Close()
				if claimPort(port) {
					return port
				}
			}
			continue
		}
		if port := 20000 + rand.IntN(20000); both(port) && claimPort(port) {
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

// handedOut holds every port freePort and freeUDP have returned in this test
// binary. Each one is closed again before the server binds it, so without this
// two calls in one test (syslog and TLS, syslog and SNMP) can return the same
// number and the second listener fails to bind.
var handedOut struct {
	sync.Mutex
	ports map[int]bool
}

// claimPort reports whether port hadn't been handed out yet, and marks it.
func claimPort(port int) bool {
	handedOut.Lock()
	defer handedOut.Unlock()
	if handedOut.ports == nil {
		handedOut.ports = map[int]bool{}
	}
	if handedOut.ports[port] {
		return false
	}
	handedOut.ports[port] = true
	return true
}

// writeConfig writes a config for a test server on 127.0.0.1 and returns its path.
func writeConfig(t *testing.T, dir string, syslogPort, uiPort int, edit func(*config.Config)) string {
	t.Helper()
	c := config.Default()
	c.Listeners.UDP = config.Listener{Enabled: true, Addr: "127.0.0.1", Port: syslogPort}
	c.Listeners.TCP = config.Listener{Enabled: true, Addr: "127.0.0.1", Port: syslogPort}
	c.Storage.DataDir = filepath.Join(dir, "data")
	if uiPort == 0 {
		for uiPort == 0 || uiPort == syslogPort {
			uiPort = freePort(t)
		}
	}
	c.UI.Port = uiPort
	if edit != nil {
		edit(&c)
	}
	path := filepath.Join(dir, "woodshed.toml")
	if err := config.Save(path, c); err != nil {
		t.Fatal(err)
	}
	return path
}

type running struct {
	srv    *Server
	cancel context.CancelFunc
	done   chan error
	base   string
	port   int
}

func start(t *testing.T, cfgPath string) *running {
	t.Helper()
	srv, err := Open(cfgPath, Options{Version: "1.2.3", Commit: "abc1234", Logger: testLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	// No real peer lookup: a Woodshed service installed on the test machine
	// would change the banners (peer_test.go covers that path with fakes).
	srv.be.peers.find = func(context.Context, peer.Options) (peer.Info, bool) { return peer.Info{}, false }
	srv.be.peers.readConfig = func(string) (config.Config, error) { return config.Config{}, os.ErrNotExist } // never the real service's
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
	return r
}

func (r *running) stop(t *testing.T) {
	t.Helper()
	if r.cancel == nil {
		return
	}
	stopAt := time.Now()
	// A shutdown still running after slowStopDump: keep every stack from then,
	// and show them if it turns out slow (where a slow step waits).
	var slowDump atomic.Pointer[string]
	dumpTimer := time.AfterFunc(slowStopDump, func() { d := allStacks(); slowDump.Store(&d) })
	defer func() {
		dumpTimer.Stop()
		took := time.Since(stopAt)
		t.Logf("shutdown took %v", took.Round(time.Millisecond))
		if d := slowDump.Load(); d != nil {
			t.Logf("still shutting down after %v:\n%s", slowStopDump, *d)
		}
	}()
	r.cancel()
	r.cancel = nil
	select {
	case err := <-r.done:
		if err != nil {
			// A shutdown past its limit: the stuck step's goroutine is still
			// running, so every stack shows where it waits.
			t.Errorf("Run: %v\n%s", err, allStacks())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("Run didn't return\n%s", allStacks())
	}
}

// testLogger logs the server's warnings and errors (a slow shutdown step says
// which, and how long) to the test's log, and drops anything logged after the
// test ended (a goroutine still stuck in a shutdown past its limit).
func testLogger(t *testing.T) *slog.Logger {
	w := &testLog{t: t}
	t.Cleanup(func() { w.mu.Lock(); w.done = true; w.mu.Unlock() }) // runs after the server's stop: Cleanups are LIFO
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

type testLog struct {
	mu   sync.Mutex
	t    *testing.T
	done bool
}

func (w *testLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.done {
		w.t.Log(strings.TrimRight(string(p), "\n"))
	}
	return len(p), nil
}

// slowStopDump is when a test's server shutdown counts as slow enough to keep
// a goroutine dump (shown with -v, or with a failure).
var slowStopDump = 5 * time.Second

// allStacks is every goroutine's stack, for a shutdown that didn't finish.
func allStacks() string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return "goroutine dump:\n" + string(buf[:n])
		}
		buf = make([]byte, 2*len(buf))
	}
}

func (r *running) do(t *testing.T, method, path string, body any, out any) int {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, r.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatalf("%s %s: decode: %v", method, path, err)
		}
	}
	return resp.StatusCode
}

func TestServerEndToEndInProcess(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, func(c *config.Config) {
		c.Listeners.MaxMessageBytes = 4096 // a file-only field that a settings PUT must keep
	})
	r := start(t, cfgPath)

	var st api.Status
	if code := r.do(t, "GET", "/api/status", nil, &st); code != 200 {
		t.Fatalf("status %d", code)
	}
	if st.Version != "1.2.3" || st.Build != "abc1234" || st.FirstMessageAt != nil || len(st.Listeners) != 2 || len(hostBanners(st.Banners)) != 0 {
		t.Fatalf("status = %+v", st)
	}
	for _, l := range st.Listeners {
		if !l.OK || l.Port != port {
			t.Errorf("listener %+v", l)
		}
	}

	// Messages over both protocols reach the disk and the device list.
	run := loadgen.NewRunID()
	for i, proto := range []string{"udp", "tcp"} {
		if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
			Addr: fmt.Sprintf("127.0.0.1:%d", port), Proto: proto, Count: 500, RunID: run, FirstSeq: i * 500, Rate: 5000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	var devs []api.Device
	waitFor(t, "1000 messages in the index", func() bool {
		var page api.DevicePage
		r.do(t, "GET", "/api/devices", nil, &page)
		devs = page.Devices
		return len(devs) == 1 && devs[0].TotalMsgs == 1000 && page.Total == 1
	})
	if d := devs[0]; d.ID != "127.0.0.1" || d.Status != "online" || d.MsgsPerMin <= 0 || d.BytesOnDisk <= 0 {
		t.Errorf("device = %+v", d)
	}
	r.do(t, "GET", "/api/status", nil, &st)
	if st.FirstMessageAt == nil {
		t.Error("first_message_at still null")
	}
	var stats api.Stats
	r.do(t, "GET", "/api/stats", nil, &stats)
	if stats.Devices.Total != 1 || stats.Devices.Online != 1 || stats.Disk.UsedBytes <= 0 || stats.Disk.DaysKept != 1 ||
		len(stats.Sparkline) != 60 || stats.Disk.CapBytes != config.DefaultRetentionBytes {
		t.Errorf("stats = %+v", stats)
	}

	// PATCH: rename and group; the live-tail group cache follows.
	var d api.Device
	if code := r.do(t, "PATCH", "/api/devices/127.0.0.1", map[string]any{"name": "test-box", "group": "lab"}, &d); code != 200 {
		t.Fatalf("patch %d", code)
	}
	if d.Name != "test-box" || d.Group != "lab" || r.srv.be.groupOf("127.0.0.1") != "lab" {
		t.Errorf("patched = %+v, group cache %q", d, r.srv.be.groupOf("127.0.0.1"))
	}
	if code := r.do(t, "PATCH", "/api/devices/192.0.2.99", map[string]any{"name": "x"}, nil); code != 404 {
		t.Errorf("patch of an unknown device: %d", code)
	}

	// Settings: a bad PUT is a 400 with dotted keys and changes nothing.
	var set api.Settings
	r.do(t, "GET", "/api/settings", nil, &set)
	bad := set
	bad.Listeners.UDP.Port = 70000
	bad.Listeners.Allowlist = []string{"10.0.0.0/8", "nope"}
	var verr struct {
		Errors map[string]string `json:"errors"`
	}
	if code := r.do(t, "PUT", "/api/settings", bad, &verr); code != 400 {
		t.Fatalf("bad PUT: %d", code)
	}
	if verr.Errors["listeners.udp.port"] == "" || verr.Errors["listeners.allowlist[1]"] == "" {
		t.Errorf("errors = %v", verr.Errors)
	}

	// A good PUT is saved (file-only fields kept) and applied live.
	newPort := freePort(t)
	good := set
	good.Listeners.UDP.Port = newPort
	good.Storage.RetentionDays = 7
	good.Quiet.QuietAfterSeconds = 60
	var saved api.Settings
	if code := r.do(t, "PUT", "/api/settings", good, &saved); code != 200 {
		t.Fatalf("good PUT: %d", code)
	}
	if saved.Listeners.UDP.Port != newPort || saved.Storage.RetentionDays != 7 {
		t.Errorf("saved = %+v", saved)
	}
	onDisk, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if onDisk.Listeners.UDP.Port != newPort || onDisk.Storage.RetentionDays != 7 || onDisk.Listeners.MaxMessageBytes != 4096 ||
		onDisk.Quiet.QuietAfterSeconds != 60 {
		t.Errorf("config on disk = %+v", onDisk)
	}
	if got := r.srv.store.Limits().RetentionDays; got != 7 {
		t.Errorf("store retention = %d, want 7", got)
	}
	r.do(t, "GET", "/api/status", nil, &st)
	if st.Listeners[0].Proto != "udp" || st.Listeners[0].Port != newPort || !st.Listeners[0].OK {
		t.Errorf("UDP after the PUT = %+v", st.Listeners[0])
	}
	// A data_dir change is refused.
	moved := saved
	moved.Storage.DataDir = filepath.Join(dir, "elsewhere")
	verr.Errors = nil
	if code := r.do(t, "PUT", "/api/settings", moved, &verr); code != 400 || verr.Errors["storage.data_dir"] == "" {
		t.Errorf("data_dir PUT: %d %v", code, verr.Errors)
	}

	// The lock keeps a second server (and reindex) off the data dir.
	if _, err := Open(cfgPath, Options{Logger: quiet}); !errors.Is(err, ErrLocked) {
		t.Errorf("second Open: %v, want ErrLocked", err)
	}
	if inUse, err := DataDirInUse(filepath.Join(dir, "data")); err != nil || !inUse {
		t.Errorf("DataDirInUse = %v, %v", inUse, err)
	}
	// The run-state file is written by its own goroutine when the UI's state
	// changes, so wait for it rather than race it.
	var rs RunState
	waitFor(t, "the run-state file to show the UI listening", func() bool {
		var err error
		rs, err = ReadState(filepath.Join(dir, "data"))
		return err == nil && rs.UI.Listening
	})
	if rs.PID != os.Getpid() {
		t.Errorf("run state = %+v", rs)
	}

	r.stop(t)

	// Clean stop: everything on disk, start and stop events, lock released.
	v, err := loadgen.Verify(filepath.Join(dir, "data"), run, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if v.Missing != 0 || v.Duplicates != 0 {
		t.Errorf("verify = %+v", v)
	}
	if inUse, _ := DataDirInUse(filepath.Join(dir, "data")); inUse {
		t.Error("lock still held after Run returned")
	}
	if _, err := os.Stat(filepath.Join(dir, "data", StateFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("run-state file left behind: %v", err)
	}
	idx, err := index.Open(filepath.Join(dir, "data", index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	evs, err := idx.Events(context.Background(), time.Time{}, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[index.Kind]int{}
	for _, e := range evs {
		kinds[e.Kind]++
	}
	if kinds[index.KindStart] < 1 || kinds[index.KindStop] < 1 || kinds[index.KindUI] < 1 {
		t.Errorf("event kinds = %v", kinds)
	}
	if last := evs[len(evs)-1]; last.Kind != index.KindStop || last.Level != index.LevelInfo {
		t.Errorf("last event = %+v, want a clean stop", last)
	}
}

func TestPortClashDoesNotStopStartup(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	hold, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	r := start(t, writeConfig(t, dir, port, 0, nil))

	var st api.Status
	r.do(t, "GET", "/api/status", nil, &st)
	if len(st.Listeners) != 2 || st.Listeners[0].OK || !st.Listeners[1].OK || st.Listeners[0].Error == "" {
		t.Fatalf("listeners = %+v", st.Listeners)
	}
	if len(st.Banners) != 1 || st.Banners[0].Kind != "listener_bind" || st.Banners[0].Action != "retry_listeners" ||
		st.Banners[0].Level != "error" || !strings.Contains(st.Banners[0].Text, fmt.Sprintf("UDP %d", port)) {
		t.Fatalf("banners = %+v", st.Banners)
	}
	if code := r.do(t, "POST", "/api/listeners/retry", nil, nil); code != 204 {
		t.Fatalf("retry: %d", code)
	}
	r.do(t, "GET", "/api/status", nil, &st)
	if st.Listeners[0].OK {
		t.Fatal("UDP came up while the port is still held")
	}
	hold.Close()
	waitFor(t, "UDP up after Retry", func() bool {
		r.do(t, "POST", "/api/listeners/retry", nil, nil)
		st = api.Status{}
		r.do(t, "GET", "/api/status", nil, &st)
		return st.Listeners[0].OK && len(hostBanners(st.Banners)) == 0
	})
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// hostBanners drops udp_buffer_small, which the test machine's sysctl decides
// (a Linux runner's default rmem_max grants about 208 KiB).
func hostBanners(bs []api.Banner) []api.Banner {
	return slices.DeleteFunc(slices.Clone(bs), func(b api.Banner) bool { return b.Kind == "udp_buffer_small" })
}

func TestBanners(t *testing.T) {
	down := []listen.ListenerStatus{
		{Proto: "udp", Addr: "0.0.0.0", Port: 514, Error: "listen udp 0.0.0.0:514: bind: address already in use", Holder: "syslogd (pid 312)"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 514, OK: true},
	}
	bs := buildBanners(down, store.Usage{VolumeBytes: 100 << 30, FreeBytes: 50 << 30, ReserveBytes: 5 << 30}, "/data")
	if len(bs) != 1 || bs[0].Kind != "listener_bind" || bs[0].Action != "retry_listeners" || !strings.Contains(bs[0].Text, "UDP 514 isn't listening: another program") {
		t.Errorf("one down: %+v", bs)
	}
	down[1] = listen.ListenerStatus{Proto: "tcp", Port: 514, Error: "listen tcp 0.0.0.0:514: bind: permission denied"}
	bs = buildBanners(down, store.Usage{}, "/data")
	if len(bs) != 1 || !strings.Contains(bs[0].Text, "UDP 514 and TCP 514 aren't listening") {
		t.Errorf("two down: %+v", bs)
	}
	bs = buildBanners(nil, store.Usage{WritesPaused: true, FreeBytes: 10 << 20, VolumeBytes: 100 << 30, ReserveBytes: 5 << 30, Dropped: 42}, "/data")
	if len(bs) != 1 || bs[0].Kind != "writes_paused" || bs[0].Level != "error" || !strings.Contains(bs[0].Text, "42") {
		t.Errorf("paused: %+v", bs)
	}
	bs = buildBanners(nil, store.Usage{FreeBytes: 1 << 30, VolumeBytes: 100 << 30, ReserveBytes: 5 << 30}, "/data")
	if len(bs) != 1 || bs[0].Kind != "low_disk" || bs[0].Level != "warn" {
		t.Errorf("low disk: %+v", bs)
	}
	if bs := buildBanners(nil, store.Usage{}, "/data"); len(bs) != 0 {
		t.Errorf("healthy, before the first disk check: %+v", bs)
	}
}

func TestDeviceStatus(t *testing.T) {
	q := config.Quiet{QuietAfterSeconds: 300, OfflineAfterSeconds: 3600}
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		ago  time.Duration
		want string
	}{{0, "online"}, {300 * time.Second, "online"}, {301 * time.Second, "quiet"}, {time.Hour, "quiet"}, {time.Hour + time.Second, "offline"}} {
		if got := deviceStatus(now.Add(-c.ago), now, q); got != c.want {
			t.Errorf("%v ago: %s, want %s", c.ago, got, c.want)
		}
	}
	if got := deviceStatus(time.Time{}, now, q); got != "offline" {
		t.Errorf("never heard: %s", got)
	}
}

func TestLoadConfigDataDirNextToConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "woodshed.toml")
	c, created, err := LoadConfig(path)
	if err != nil || !created {
		t.Fatalf("LoadConfig: %v, created %v", err, created)
	}
	if want := filepath.Join(filepath.Dir(path), "woodshed-data"); c.Storage.DataDir != want {
		t.Errorf("data_dir = %s, want %s", c.Storage.DataDir, want)
	}
	if errs := c.Validate(nil); len(errs) > 0 {
		t.Errorf("a new config doesn't validate: %v", errs)
	}
	if _, created, _ := LoadConfig(path); created {
		t.Error("created twice")
	}
}

func TestOpenRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, 15514, 0, func(c *config.Config) { c.Storage.RetentionDays = 0 })
	_, err := Open(path, Options{Logger: quiet})
	if err == nil || !strings.Contains(err.Error(), "storage.retention_days") {
		t.Fatalf("Open = %v", err)
	}
	// Nothing is left locked.
	if inUse, _ := DataDirInUse(filepath.Join(dir, "data")); inUse {
		t.Error("data dir locked after a failed Open")
	}
}

func TestLock(t *testing.T) {
	dir := t.TempDir()
	if inUse, err := DataDirInUse(dir); err != nil || inUse {
		t.Fatalf("before: %v %v", inUse, err)
	}
	l, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockDataDir(dir); !errors.Is(err, ErrLocked) {
		t.Errorf("second lock: %v", err)
	}
	if inUse, err := DataDirInUse(dir); err != nil || !inUse {
		t.Errorf("held: %v %v", inUse, err)
	}
	if err := l.Unlock(); err != nil {
		t.Fatal(err)
	}
	if inUse, _ := DataDirInUse(dir); inUse {
		t.Error("still in use after Unlock")
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"} {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestPerMinute(t *testing.T) {
	now := time.Date(2026, 11, 10, 12, 0, 30, 0, time.UTC)
	from := now.Truncate(time.Minute).Add(-time.Minute) // 11:59:00, a 90 s window
	r := rates{from: from, counts: map[string]index.Counts{"a": {Msgs: 900}, "b": {Msgs: 100}, "c": {Msgs: 1}}}
	old := index.Device{ID: "a", FirstSeen: now.Add(-time.Hour)}
	if got := r.perMinute(old, now); got != 600 {
		t.Errorf("steady device: %d/min, want 600", got)
	}
	young := index.Device{ID: "b", FirstSeen: now.Add(-20 * time.Second)}
	if got := r.perMinute(young, now); got != 300 {
		t.Errorf("device first seen 20 s ago with 100 messages: %d/min, want 300", got)
	}
	brandNew := index.Device{ID: "c", FirstSeen: now.Add(-time.Second)}
	if got := r.perMinute(brandNew, now); got != 6 {
		t.Errorf("one message a second ago: %d/min, want 6 (10 s minimum window)", got)
	}
	if got := r.perMinute(index.Device{ID: "zzz"}, now); got != 0 {
		t.Errorf("silent device: %d", got)
	}
}

func TestLiveDevices(t *testing.T) {
	l := newLiveDevices()
	a, v6 := netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::1")
	t0 := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	// 40 msg/s for 90 s from a; one message from v6 at t0+89s.
	for s := range 90 {
		for k := range 40 {
			l.add(a, t0.Add(time.Duration(s)*time.Second+time.Duration(k)*25*time.Millisecond))
		}
	}
	l.add(a, t0.Add(10*time.Second)) // a late, interleaved message doesn't move last-heard back
	l.add(v6, t0.Add(89*time.Second))
	now := t0.Add(89*time.Second + 999*time.Millisecond)
	snap := l.snapshot(now)
	if got := snap["192.0.2.7"]; got.MsgsPerMin != 2400 || !got.LastHeard.Equal(t0.Add(89*time.Second+975*time.Millisecond)) {
		t.Errorf("steady sender: %+v, want 2400/min", got)
	}
	if got := snap["2001_db8__1"]; got.MsgsPerMin != 6 {
		t.Errorf("one message just now: %+v, want 6/min (10 s minimum window)", got)
	}
	// After 30 s of silence, the rate covers only the last 30 s of sending.
	if got := l.snapshot(now.Add(30 * time.Second))["192.0.2.7"]; got.MsgsPerMin != 1200 {
		t.Errorf("30 s after stopping: %d/min, want 1200", got.MsgsPerMin)
	}
	if got := l.snapshot(now.Add(2 * time.Minute))["192.0.2.7"]; got.MsgsPerMin != 0 {
		t.Errorf("2 min after stopping: %d/min, want 0", got.MsgsPerMin)
	}
	// A device sending for 20 s is scaled over those 20 s.
	l2 := newLiveDevices()
	for s := range 20 {
		for range 10 {
			l2.add(a, t0.Add(time.Duration(s)*time.Second))
		}
	}
	if got := l2.snapshot(t0.Add(20 * time.Second))["192.0.2.7"]; got.MsgsPerMin != 600 {
		t.Errorf("20 s at 10/s: %d/min, want 600", got.MsgsPerMin)
	}
}
