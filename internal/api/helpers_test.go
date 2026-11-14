package api

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

// ---- fake backend ----

func ts(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

type fakeBackend struct {
	mu        sync.Mutex
	status    Status
	stats     Stats
	rejected  []RejectedSender
	devices   map[string]Device
	order     []string
	settings  Settings
	history   []StorageEntry
	saveErr   error // returned by SaveSettings when set
	statusErr error
	retries   int
	patches   []DevicePatch
	events    []Event
	live      http.Handler

	searches   []SearchRequest
	searchErr  error
	contextErr error
	exportReqs []ExportRequest
	exportErr  error
	exports    map[string]ExportInfo
	zip        []byte // the content of every ready export

	updates     UpdateInfo
	checkNowErr error
	checkNows   int
	dismissed   []string
	summaries   []SummaryRequest
	saved       map[string]SavedSearch
	savedSeq    int
}

func newFakeBackend() *fakeBackend {
	first := ts("2026-11-10T20:00:05Z")
	b := &fakeBackend{
		status: Status{
			Version: "0.1.0", Build: "abc1234", OS: "darwin/arm64",
			DataDir:        "/Library/Application Support/Woodshed",
			StartedAt:      ts("2026-11-10T20:00:00Z"),
			FirstMessageAt: &first,
			UDPRcvbufBytes: 33554432, UDPRcvbufRequestedBytes: 33554432,
			Listeners: []Listener{
				{Proto: "udp", Addr: "0.0.0.0", Port: 514, OK: true},
				{Proto: "tcp", Addr: "0.0.0.0", Port: 514, OK: false, Error: "bind: address already in use", Holder: "syslogd (pid 312)"},
			},
			HostIPs: []string{"10.1.0.50", "fd00::50"},
			Banners: []Banner{{Kind: "listener_bind", Level: "error", Text: "TCP 514 is in use by syslogd (pid 312).", Action: "retry_listeners"}},
		},
		stats: Stats{
			MsgsPerSec: 1284.2,
			Sparkline:  []float64{1100, 1180, 1250},
			Devices:    DeviceCounts{Total: 3, Online: 1, Quiet: 1, Offline: 1},
			Disk: Disk{UsedBytes: 3435973836, CapBytes: 21474836480, FreeBytes: 400000000000, DaysKept: 30,
				BytesPerDay: ptr(int64(2361393152)), CompressionRatio: ptr(9.2), EstimatedDays: ptr(9.1), LimitedBy: ptr("cap")},
			UDPQueue: []UDPQueue{{Listener: "udp", Port: 514, CapacityMessages: 100000, CapacityBytes: 67108864, Depth: 12,
				HighWater24h: 3210, HighWaterByHour: []int{120, 3210, 88}}},
		},
		rejected: []RejectedSender{{IP: "198.51.100.7", Count24h: 120, LastSeen: ts("2026-11-10T20:30:00Z"), Reason: "allowlist"}},
		devices:  map[string]Device{},
		settings: Settings{
			Listeners: ListenersSettings{
				UDP:        ListenerSettings{Enabled: true, Addr: "0.0.0.0", Port: 514},
				TCP:        ListenerSettings{Enabled: true, Addr: "0.0.0.0", Port: 514},
				MaxDevices: 10000, NewDeviceBurst: 5000, NewDevicesPerMinute: 200,
			},
			Storage: StorageSettings{DataDir: "/data", RetentionDays: 30, RetentionBytes: 21474836480, PartBytes: 104857600},
			UI:      UISettings{Port: 0}, // tests run on port 0; a different port here would restart the server onto it
			Quiet:   QuietSettings{QuietAfterSeconds: 300, OfflineAfterSeconds: 3600},
			Updates: &UpdatesSettings{Check: "ask"},
		},
		updates: UpdateInfo{
			Check: "ask", Available: true, URL: "https://releases.example/woodshed/releases.json", Current: "1.1.0",
			LastCheck: ptr(ts("2026-11-13T09:12:44Z")), LastResult: "ok", NextCheck: ptr(ts("2026-11-14T08:40:02Z")),
			Latest:          &LatestRelease{Version: "1.2.0", URL: "https://example.invalid/releases/tag/v1.2.0"},
			UpdateAvailable: true,
		},
		history: []StorageEntry{{Time: ts("2026-11-09T00:00:01Z"), File: "logs/10.1.0.1/2026-10-10.log.gz", DeviceID: "10.1.0.1", Bytes: 1234, Reason: "age"}},
	}
	for i, d := range []Device{
		{ID: "10.1.0.1", IP: "10.1.0.1", Name: "edge-fw-01", Group: "HQ", Status: "online", MsgsPerMin: 36720, TotalMsgs: 9123456, BytesOnDisk: 123456789},
		{ID: "10.1.0.2", IP: "10.1.0.2", Name: "core-sw-01", Group: "HQ", Status: "quiet"},
		{ID: "fd00_1__5", IP: "fd00:1::5", Status: "offline", Hidden: true},
	} {
		d.FirstSeen = ts("2026-11-01T00:00:00Z").Add(time.Duration(i) * time.Hour)
		d.LastHeard = ts("2026-11-10T20:59:00Z")
		b.devices[d.ID] = d
		b.order = append(b.order, d.ID)
	}
	b.live = http.HandlerFunc(fakeLive)
	return b
}

// fakeLive writes one event echoing the query, then holds the stream open
// until the request ends.
func fakeLive(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	data, _ := json.Marshal(map[string]any{
		"received": "2026-11-10T20:41:07.112Z", "device_id": "10.1.0.1", "severity": 6,
		"raw": "<134>query=" + r.URL.RawQuery,
	})
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", data)
	_ = http.NewResponseController(w).Flush()
	<-r.Context().Done()
}

func (b *fakeBackend) Status(ctx context.Context) (Status, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.status, b.statusErr
}
func (b *fakeBackend) Stats(ctx context.Context) (Stats, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.stats, nil
}

func ptr[T any](v T) *T { return &v }

// StorageEstimate scales the fake's stats estimate to the cap; under 1 GiB is
// refused like the setting.
func (b *fakeBackend) StorageEstimate(_ context.Context, n int64) (StorageEstimate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 1<<30 {
		return StorageEstimate{}, &RequestError{Msg: "retention_bytes must be at least 1 GiB (1073741824)"}
	}
	d := b.stats.Disk
	est := StorageEstimate{BytesPerDay: d.BytesPerDay, CompressionRatio: d.CompressionRatio}
	if d.BytesPerDay != nil && *d.BytesPerDay > 0 {
		est.EstimatedDays = ptr(float64(n) / float64(*d.BytesPerDay))
	}
	return est, nil
}
func (b *fakeBackend) Rejected(ctx context.Context) ([]RejectedSender, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rejected, nil
}
func (b *fakeBackend) Devices(ctx context.Context) ([]Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []Device
	for _, id := range b.order {
		out = append(out, b.devices[id])
	}
	return out, nil
}
func (b *fakeBackend) UpdateDevice(ctx context.Context, id string, p DevicePatch) (Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	d, ok := b.devices[id]
	if !ok {
		return Device{}, fmt.Errorf("device %q: %w", id, ErrNotFound)
	}
	b.patches = append(b.patches, p)
	if p.Name != nil {
		d.Name = *p.Name
	}
	if p.Group != nil {
		d.Group = *p.Group
	}
	if p.Hidden != nil {
		d.Hidden = *p.Hidden
	}
	if p.Blocked != nil {
		d.Blocked = *p.Blocked
		if d.Blocked {
			d.Status = "blocked"
		}
	}
	b.devices[id] = d
	return d, nil
}
func (b *fakeBackend) Settings(ctx context.Context) (Settings, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.settings, nil
}
func (b *fakeBackend) SaveSettings(ctx context.Context, s Settings, ifMatch string) (Settings, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.saveErr != nil {
		return Settings{}, b.saveErr
	}
	if ifMatch != "" && ifMatch != SettingsETag(b.settings) {
		return Settings{}, ErrSettingsChanged
	}
	if s.Updates == nil {
		s.Updates = b.settings.Updates // a PUT without it keeps it
	}
	b.settings = s
	b.updates.Check = s.Updates.Check
	return s, nil
}
func (b *fakeBackend) RetryListeners(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.retries++
	return nil
}
func (b *fakeBackend) StorageHistory(ctx context.Context) ([]StorageEntry, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.history, nil
}
func (b *fakeBackend) LiveHandler() http.Handler { return b.live }
func (b *fakeBackend) Updates(ctx context.Context) (UpdateInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.updates, nil
}
func (b *fakeBackend) SetUpdateCheck(ctx context.Context, check string) (UpdateInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.saveErr != nil {
		return UpdateInfo{}, b.saveErr
	}
	b.settings.Updates = &UpdatesSettings{Check: check}
	b.updates.Check = check
	return b.updates, nil
}
func (b *fakeBackend) CheckUpdatesNow(ctx context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.checkNows++
	return b.checkNowErr
}
func (b *fakeBackend) DismissUpdate(ctx context.Context, version string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if version == "" || strings.ContainsAny(version, " <>") {
		return &RequestError{Msg: "version must be a version, e.g. 1.2.0"}
	}
	b.dismissed = append(b.dismissed, version)
	return nil
}
func (b *fakeBackend) RecordEvent(ctx context.Context, e Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.events = append(b.events, e)
	return nil
}

func (b *fakeBackend) Search(ctx context.Context, r SearchRequest) (SearchPage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.searches = append(b.searches, r)
	if b.searchErr != nil {
		return SearchPage{}, b.searchErr
	}
	return SearchPage{
		Results: []SearchLine{{Received: ts("2026-11-10T20:41:07Z").Add(112 * time.Millisecond), DeviceID: "10.1.0.1", Severity: 6,
			Raw: []byte("<134>conn opened \xff"), Ref: "ref1", App: "%FW-6-1", Host: "edge-fw-01"},
			{Received: ts("2026-11-10T20:41:06Z"), DeviceID: "10.1.0.2", Severity: Unknown, Raw: []byte("no pri \xff"), Ref: "ref2"}},
		NextCursor: "next", ScannedBytes: 123456, ScannedFiles: 12, ElapsedMS: 840,
	}, nil
}
func (b *fakeBackend) Context(ctx context.Context, ref string, before, after int) (ContextPage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.contextErr != nil {
		return ContextPage{}, b.contextErr
	}
	return ContextPage{Lines: []SearchLine{{Received: ts("2026-11-10T20:41:07Z"), DeviceID: "10.1.0.1", Severity: 3,
		Raw: []byte(fmt.Sprintf("%s %d %d", ref, before, after)), Ref: ref}}, HitIndex: 0, AtStart: true}, nil
}
func (b *fakeBackend) CreateExport(ctx context.Context, r ExportRequest) (ExportInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exportReqs = append(b.exportReqs, r)
	if b.exportErr != nil {
		return ExportInfo{}, b.exportErr
	}
	if b.exports == nil {
		b.exports = map[string]ExportInfo{}
	}
	id := fmt.Sprintf("exp_%016x", len(b.exports)+1)
	e := ExportInfo{ID: id, Created: ts("2026-11-10T21:00:00Z"), Devices: r.Devices, From: r.From, To: r.To, State: "queued",
		Filters: ExportFilters{Group: r.Group, Ungrouped: r.Ungrouped, Severities: r.Severities, Q: r.Q, Regex: r.Regex, Case: r.Case,
			App: r.App, Host: r.Host, Exclude: r.Exclude}}
	b.exports[id] = e
	return e, nil
}
func (b *fakeBackend) EstimateExport(ctx context.Context, r ExportRequest) (ExportEstimate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.exportReqs = append(b.exportReqs, r)
	if b.exportErr != nil {
		return ExportEstimate{}, b.exportErr
	}
	return ExportEstimate{Lines: 123456, Bytes: 45678901, Files: 12}, nil
}
func (b *fakeBackend) Exports(ctx context.Context) ([]ExportInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []ExportInfo
	for _, e := range b.exports {
		out = append(out, e)
	}
	return out, nil
}
func (b *fakeBackend) Export(ctx context.Context, id string) (ExportInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.exports[id]
	if !ok {
		return ExportInfo{}, ErrNotFound
	}
	return e, nil
}
func (b *fakeBackend) OpenExport(ctx context.Context, id string) (ExportDownload, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.exports[id]
	switch {
	case !ok || e.State == "expired":
		return ExportDownload{}, ErrNotFound
	case e.State != "ready":
		return ExportDownload{}, ErrNotReady
	}
	return ExportDownload{File: nopCloser{bytes.NewReader(b.zip)}, ModTime: ts("2026-11-10T21:00:05Z")}, nil
}
func (b *fakeBackend) DeleteExport(ctx context.Context, id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.exports[id]; !ok {
		return ErrNotFound
	}
	delete(b.exports, id)
	return nil
}

type nopCloser struct{ *bytes.Reader }

func (nopCloser) Close() error { return nil }

func (b *fakeBackend) eventTexts() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for _, e := range b.events {
		out = append(out, e.Kind+"/"+e.Level+": "+e.Text)
	}
	return out
}

// ---- fake clock ----

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: ts("2026-11-10T21:00:00Z")} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ---- test server ----

var testArgon = argonParams{Time: 1, Memory: 64, Threads: 1, KeyLen: 32, SaltLen: 16}

func testIdentity() (hostIdentity, error) {
	return hostIdentity{
		Names: []string{"localhost", "testhost"},
		IPs:   []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.IPv6Loopback()},
	}, nil
}

var testStatic = fstest.MapFS{
	"index.html":                {Data: []byte(`<!doctype html><html><head><script type="module" src="./assets/index-BHAE32ir.js"></script></head><body><div id="app"></div></body></html>`)},
	"favicon.svg":               {Data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`)},
	"assets/index-BHAE32ir.js":  {Data: []byte(`console.log("hi")`)},
	"assets/index-VoJOug0b.css": {Data: []byte(`body{}`)},
	".keep":                     {Data: nil},
}

type testServer struct {
	*Server
	b      *fakeBackend
	clock  *fakeClock
	cancel context.CancelFunc
	done   chan struct{}
}

type serverOpt func(*Options)

func startServer(t *testing.T, b *fakeBackend, cfg UIConfig, opts ...serverOpt) *testServer {
	t.Helper()
	if b == nil {
		b = newFakeBackend()
	}
	clock := newFakeClock()
	o := Options{
		Backend:  b,
		DataDir:  t.TempDir(),
		UI:       cfg,
		Static:   testStatic,
		Logger:   discardLogger(),
		now:      clock.Now,
		argon:    testArgon,
		identity: testIdentity,
		lanAddr:  "127.0.0.1", // never bind every interface in tests
	}
	for _, f := range opts {
		f(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv := &testServer{Server: s, b: b, clock: clock, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(srv.done)
		_ = s.Run(ctx)
	}()
	t.Cleanup(srv.stop)
	deadline := time.Now().Add(5 * time.Second)
	for !srv.State().Listening {
		if time.Now().After(deadline) {
			t.Fatalf("server not listening after 5s: %+v", srv.State())
		}
		time.Sleep(5 * time.Millisecond)
	}
	return srv
}

func (ts *testServer) stop() {
	ts.cancel()
	<-ts.done
}

// waitListening waits until the server listens in the given mode.
func (ts *testServer) waitListening(t *testing.T, lan bool) State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := ts.State()
		if st.Listening && st.LANMode == lan {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server not listening (lan=%v) after 5s: %+v", lan, ts.State())
	return State{}
}

// waitNewAddr waits for the server to listen in mode lan on an address other
// than old (after a restart).
func (ts *testServer) waitRestart(t *testing.T, lan bool, old State) State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := ts.State()
		if st.Listening && st.LANMode == lan && st != old {
			return st
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("server didn't restart (lan=%v): %+v", lan, ts.State())
	return State{}
}

func (ts *testServer) url(path string) string {
	st := ts.State()
	scheme := "http"
	if st.LANMode {
		scheme = "https"
	}
	return scheme + "://" + st.Addr + path
}

// httpClient talks to the localhost-mode server with a matching Host header
// (127.0.0.1:port, which is what Addr is).
func httpClient() *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// tlsClient trusts the server's certificate from the data dir and keeps cookies.
func tlsClient(t *testing.T, dataDir string) *http.Client {
	t.Helper()
	pemBytes, err := os.ReadFile(filepath.Join(dataDir, CertFile))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("bad cert PEM")
	}
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout:       10 * time.Second,
		Jar:           jar,
		Transport:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type resp struct {
	code   int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.body, &m); err != nil {
		t.Fatalf("not a JSON object (%d): %q", r.code, r.body)
	}
	return m
}

// do sends a request; body may be "" for none. Extra headers are "Key: value".
func do(t *testing.T, c *http.Client, method, url, body string, headers ...string) resp {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, h := range headers {
		k, v, _ := strings.Cut(h, ": ")
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{code: res.StatusCode, header: res.Header, body: b}
}

// wantError checks a non-2xx JSON error body.
func wantError(t *testing.T, r resp, code int, contains string) {
	t.Helper()
	if r.code != code {
		t.Fatalf("status %d, want %d; body %s", r.code, code, r.body)
	}
	if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("error Content-Type %q", ct)
	}
	m := r.json(t)
	msg, ok := m["error"].(string)
	if !ok || msg == "" {
		t.Fatalf("no error message in %s", r.body)
	}
	if contains != "" && !strings.Contains(msg, contains) {
		t.Fatalf("error %q doesn't contain %q", msg, contains)
	}
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// pageDevices filters, sorts and pages ds (every device, normalized).
func pageDevices(ds []Device, q DeviceQuery) DevicePage {
	needle := strings.ToLower(q.Q)
	out := make([]Device, 0, len(ds))
	for _, d := range ds {
		switch {
		case q.Hidden == "only" && !d.Hidden, q.Hidden == "exclude" && d.Hidden:
			continue
		case q.Blocked == "only" && !d.Blocked, q.Blocked == "exclude" && d.Blocked:
			continue
		case q.Group != "" && d.Group != q.Group, q.Ungrouped && d.Group != "":
			continue
		case needle != "" && !strings.Contains(strings.ToLower(d.ID), needle) && !strings.Contains(strings.ToLower(d.IP), needle) &&
			!strings.Contains(strings.ToLower(d.Name), needle):
			continue
		}
		out = append(out, d)
	}
	byID := func(a, b Device) int { return strings.Compare(a.ID, b.ID) }
	slices.SortStableFunc(out, func(a, b Device) int {
		var c int
		switch q.Sort {
		case "name":
			an, bn := a.Name, b.Name // a device without a name sorts by its IP
			if an == "" {
				an = a.IP
			}
			if bn == "" {
				bn = b.IP
			}
			c = cmp.Compare(strings.ToLower(an), strings.ToLower(bn))
		case "last_heard":
			c = b.LastHeard.Compare(a.LastHeard)
		case "first_seen":
			c = b.FirstSeen.Compare(a.FirstSeen)
		default:
			c = cmp.Compare(b.MsgsPerMin, a.MsgsPerMin)
		}
		if c == 0 {
			c = byID(a, b)
		}
		return c
	})
	page := DevicePage{Total: len(out), Devices: []Device{}}
	if q.Offset < len(out) {
		page.Devices = out[q.Offset:min(q.Offset+q.Limit, len(out))]
	}
	return page
}

// groupsOf counts the non-hidden devices of each group, sorted by name;
// ungrouped devices aren't listed (groups whose devices are all hidden are,
// with 0, as the index does).
func groupsOf(ds []Device) []Group {
	n := map[string]int{}
	for _, d := range ds {
		if d.Group == "" {
			continue
		}
		if _, ok := n[d.Group]; !ok {
			n[d.Group] = 0
		}
		if !d.Hidden {
			n[d.Group]++
		}
	}
	out := make([]Group, 0, len(n))
	for g, c := range n {
		out = append(out, Group{Name: g, Devices: c})
	}
	slices.SortFunc(out, func(a, b Group) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func (b *fakeBackend) QueryDevices(ctx context.Context, q DeviceQuery) (DevicePage, error) {
	ds, _ := b.Devices(ctx)
	for i := range ds {
		ds[i].normalize()
	}
	return pageDevices(ds, q), nil
}

func (b *fakeBackend) Groups(ctx context.Context) ([]Group, error) {
	ds, _ := b.Devices(ctx)
	return groupsOf(ds), nil
}

// ---- Events v2 ----

func (b *fakeBackend) SearchSchema(ctx context.Context) ([]SearchType, error) {
	return []SearchType{{Type: "syslog", Label: "Syslog", Default: true, Fields: []SearchField{
		{Key: "device", Label: "Device", Param: "devices", ExcludeParam: "exclude_devices"},
		{Key: "severity", Label: "Severity", Param: "severities", Domain: []DomainValue{{"0", "emerg"}, {"unknown", "unknown"}}},
	}}}, nil
}

func (b *fakeBackend) Summary(ctx context.Context, r SummaryRequest) (SummaryPage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.summaries = append(b.summaries, r)
	if b.searchErr != nil {
		return SummaryPage{}, b.searchErr
	}
	n := int64(812)
	p := SummaryPage{From: ts("2026-11-13T14:00:00Z"), To: ts("2026-11-13T15:00:00Z"), Matched: 48210, CountedFrom: ts("2026-11-13T14:00:00Z"),
		Fields: []SummaryField{{Key: "host", Label: "Host", Values: []SummaryValue{{Value: "web-01", Label: "web-01", Count: 20311, Filterable: true}},
			Other: 1204, None: 37, Distinct: 14}}}
	if r.Histogram {
		p.Histogram = &SummaryHistogram{BucketSeconds: 60, Source: "index", Buckets: []SummaryBucket{{Start: ts("2026-11-13T14:00:00Z"), Count: &n},
			{Start: ts("2026-11-13T14:01:00Z")}}}
	}
	return p, nil
}

func (b *fakeBackend) SavedSearches(ctx context.Context, typ string) ([]SavedSearch, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.saved == nil {
		b.saved = map[string]SavedSearch{}
		b.savedSeq++
		b.saved["ss_00000001"] = SavedSearch{ID: "ss_00000001", Name: "Edge denies", Type: "syslog", Created: ts("2026-11-13T14:02:11Z"),
			Updated: ts("2026-11-13T14:02:11Z"), Version: 1, Query: SavedQuery{Q: "deny NOT 10.0.0.1", Syntax: "terms", Devices: []string{"10.1.0.1", "10.9.9.9"},
				App: []string{"%FW-6-*"}, Range: SavedRange{Last: "1h"}}, MissingDevices: []string{"10.9.9.9"}}
	}
	var out []SavedSearch
	for _, s := range b.saved {
		if s.Type == typ {
			out = append(out, s)
		}
	}
	slices.SortFunc(out, func(a, c SavedSearch) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(c.Name)) })
	return out, nil
}

func (b *fakeBackend) SavedSearch(ctx context.Context, id string) (SavedSearch, error) {
	b.SavedSearches(ctx, "syslog") // seed
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.saved[id]
	if !ok {
		return SavedSearch{}, ErrNotFound
	}
	return s, nil
}

func (b *fakeBackend) CreateSavedSearch(ctx context.Context, in SavedSearchInput) (SavedSearch, error) {
	b.SavedSearches(ctx, "syslog")
	b.mu.Lock()
	defer b.mu.Unlock()
	if in.Query.Q == "bad(" {
		return SavedSearch{}, &ValidationError{Fields: map[string]string{"query.q": "Unclosed quote starting at character 12."}}
	}
	if len(b.saved) >= 200 {
		return SavedSearch{}, ErrSavedSearchLimit
	}
	for _, s := range b.saved {
		if strings.EqualFold(s.Name, in.Name) {
			return SavedSearch{}, &NameTakenError{Name: in.Name}
		}
	}
	b.savedSeq++
	s := SavedSearch{ID: fmt.Sprintf("ss_%08x", b.savedSeq), Name: in.Name, Type: in.Type, Query: in.Query, Version: 1,
		Created: ts("2026-11-13T15:00:00Z"), Updated: ts("2026-11-13T15:00:00Z")}
	b.saved[s.ID] = s
	return s, nil
}

func (b *fakeBackend) UpdateSavedSearch(ctx context.Context, id string, in SavedSearchInput, ifVersion int64) (SavedSearch, error) {
	b.SavedSearches(ctx, "syslog")
	b.mu.Lock()
	defer b.mu.Unlock()
	s, ok := b.saved[id]
	if !ok {
		return SavedSearch{}, ErrNotFound
	}
	if ifVersion > 0 && ifVersion != s.Version {
		return SavedSearch{}, ErrSavedSearchChanged
	}
	s.Name, s.Type, s.Query = in.Name, in.Type, in.Query
	s.Version++
	b.saved[id] = s
	return s, nil
}

func (b *fakeBackend) DeleteSavedSearch(ctx context.Context, id string) error {
	b.SavedSearches(ctx, "syslog")
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.saved[id]; !ok {
		return ErrNotFound
	}
	delete(b.saved, id)
	return nil
}
