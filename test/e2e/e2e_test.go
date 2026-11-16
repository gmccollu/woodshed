// Package e2e tests the real woodshed binary end to end: it builds it, runs it on
// high ports with a temporary data dir, sends it syslog with loadgen, and checks
// the API, the files on disk, a clean SIGTERM and a restart.
//
// It binds only 127.0.0.x, so it never opens a firewall prompt. Skipped with
// -short.
package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

var binary string // built once by TestMain

func TestMain(m *testing.M) {
	code := func() int {
		if testingShort() {
			return m.Run()
		}
		dir, err := os.MkdirTemp("", "woodshed-e2e-bin-*")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		binary = filepath.Join(dir, "woodshed"+exeSuffix())
		root, err := moduleRoot()
		if err != nil {
			fmt.Fprintln(os.Stderr, "e2e:", err)
			return 1
		}
		trackSources(root)
		cmd := exec.Command(goTool(), "build", "-o", binary, "./cmd/woodshed")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: building the binary: %v\n%s", err, out)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

// trackSources stats every file the binary is built from. The go command's test
// cache records the files a test opens or stats, so a change to any of them
// reruns this test instead of reusing a result for an older binary (the build
// itself runs in a child process the cache can't see).
func trackSources(root string) {
	for _, dir := range []string{"cmd", "internal", "web/dist", "go.mod", "go.sum"} {
		_ = filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				_, _ = os.Stat(path)
			}
			return nil
		})
	}
}

func testingShort() bool {
	for _, a := range os.Args[1:] {
		if a == "-test.short" || a == "-test.short=true" {
			return true
		}
	}
	return false
}

func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func goTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	return filepath.Join(runtime.GOROOT(), "bin", "go"+exeSuffix())
}

func moduleRoot() (string, error) {
	out, err := exec.Command(goTool(), "env", "GOMOD").Output()
	if err != nil {
		return "", err
	}
	mod := strings.TrimSpace(string(out))
	if mod == "" || mod == os.DevNull {
		return "", fmt.Errorf("not in a module")
	}
	return filepath.Dir(mod), nil
}

// ---- the process under test ----

type proc struct {
	t       *testing.T
	cmd     *exec.Cmd
	cfgPath string
	dataDir string
	base    string // http://127.0.0.1:<ui port>
	logPath string
	exited  chan struct{}
	exitErr error
}

func startWoodshed(t *testing.T, cfgPath, dataDir string, uiPort int) *proc {
	t.Helper()
	logPath := filepath.Join(filepath.Dir(cfgPath), fmt.Sprintf("woodshed-%d.log", time.Now().UnixNano()))
	logf, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "--config", cfgPath)
	cmd.Stdout, cmd.Stderr = logf, logf
	prepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &proc{t: t, cmd: cmd, cfgPath: cfgPath, dataDir: dataDir, logPath: logPath,
		base: fmt.Sprintf("http://127.0.0.1:%d", uiPort), exited: make(chan struct{})}
	go func() {
		p.exitErr = cmd.Wait()
		logf.Close()
		close(p.exited)
	}()
	t.Cleanup(func() {
		select {
		case <-p.exited:
		default:
			_ = cmd.Process.Kill() // only our own child, by PID
			<-p.exited
		}
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("woodshed log (%s):\n%s", logPath, tail(string(b), 60))
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for {
		resp, err := http.Get(p.base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return p
			}
		}
		select {
		case <-p.exited:
			b, _ := os.ReadFile(logPath)
			t.Fatalf("woodshed exited at startup: %v\n%s", p.exitErr, b)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("woodshed's UI didn't answer within 20 s: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stop sends SIGTERM (Ctrl-Break on Windows) and waits for a clean exit.
func (p *proc) stop() {
	p.t.Helper()
	t0 := time.Now()
	if err := terminate(p.cmd); err != nil {
		p.t.Fatalf("signal: %v", err)
	}
	select {
	case <-p.exited:
	case <-time.After(30 * time.Second):
		p.t.Fatal("woodshed didn't exit within 30 s of SIGTERM")
	}
	if p.exitErr != nil {
		p.t.Fatalf("woodshed exited with %v after SIGTERM", p.exitErr)
	}
	b, _ := os.ReadFile(p.logPath)
	if !strings.Contains(string(b), "stopped cleanly") {
		p.t.Fatalf("no clean-stop line in the log:\n%s", tail(string(b), 20))
	}
	took := time.Since(t0)
	p.t.Logf("clean shutdown in %v", took.Round(time.Millisecond))
	if took > time.Second {
		p.t.Logf("slow shutdown; the log's tail:\n%s", tail(string(b), 12))
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (p *proc) do(method, path string, body any) (int, []byte) {
	p.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			p.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, p.base+path, rd)
	if err != nil {
		p.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// getJSON GETs path, requires 200 and decodes into out (a map or a slice).
func (p *proc) getJSON(path string, out any) {
	p.t.Helper()
	code, b := p.do("GET", path, nil)
	if code != 200 {
		p.t.Fatalf("GET %s: %d %s", path, code, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		p.t.Fatalf("GET %s: %v in %s", path, err, b)
	}
}

// ---- contract shape checks (docs/api.md) ----

// shape checks that obj has every key with the given JSON type: "string",
// "number", "bool", "array", "object", "null", or alternatives like "null|string".
func shape(t *testing.T, what string, obj map[string]any, want map[string]string) {
	t.Helper()
	for k, types := range want {
		v, ok := obj[k]
		if !ok {
			t.Errorf("%s: missing %q", what, k)
			continue
		}
		got := jsonType(v)
		if !strings.Contains("|"+types+"|", "|"+got+"|") {
			t.Errorf("%s.%s is %s (%v), want %s", what, k, got, v, types)
		}
	}
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return fmt.Sprintf("%T", v)
}

var (
	statusShape = map[string]string{
		"version": "string", "build": "string", "os": "string", "data_dir": "string", "started_at": "string",
		"first_message_at": "null|string", "udp_rcvbuf_bytes": "number", "udp_rcvbuf_requested_bytes": "number",
		"releases_url": "string", "kernel_drops_visible": "bool", "listeners": "array", "host_ips": "array", "banners": "array",
	}
	listenerShape = map[string]string{"proto": "string", "addr": "string", "port": "number", "ok": "bool", "error": "string"}
	bannerShape   = map[string]string{"kind": "string", "level": "string", "text": "string", "action": "string"}
	statsShape    = map[string]string{
		"msgs_per_sec": "number", "sparkline": "array", "devices": "object", "disk": "object", "dropped_24h": "number",
		"kernel_dropped_24h": "null|number", "truncated_24h": "number", "rejected_24h": "number",
		"flow_parts_early": "number",
	}
	statsDevicesShape = map[string]string{"total": "number", "online": "number", "quiet": "number", "offline": "number"}
	diskShape         = map[string]string{"used_bytes": "number", "cap_bytes": "number", "free_bytes": "number", "days_kept": "number"}
	deviceShape       = map[string]string{
		"id": "string", "ip": "string", "name": "string", "group": "string", "hidden": "bool", "first_seen": "string",
		"last_heard": "string", "status": "string", "msgs_per_min": "number", "total_msgs": "number", "bytes_on_disk": "number",
	}
	rejectedShape = map[string]string{"ip": "string", "count_24h": "number", "last_seen": "string", "reason": "string"}
	liveShape     = map[string]string{"received": "string", "device_id": "string", "severity": "null|number", "raw": "string"}
)

func checkStatus(t *testing.T, st map[string]any) {
	t.Helper()
	shape(t, "status", st, statusShape)
	for i, l := range asSlice(st["listeners"]) {
		shape(t, fmt.Sprintf("status.listeners[%d]", i), l.(map[string]any), listenerShape)
	}
	for i, b := range asSlice(st["banners"]) {
		shape(t, fmt.Sprintf("status.banners[%d]", i), b.(map[string]any), bannerShape)
	}
	if _, err := time.Parse(time.RFC3339, fmt.Sprint(st["started_at"])); err != nil {
		t.Errorf("started_at: %v", err)
	}
}

// hostBanners is asSlice of a banner list without udp_buffer_small, which the
// test machine's sysctl decides (a Linux runner's default rmem_max is small).
func hostBanners(v any) []any {
	var out []any
	for _, b := range asSlice(v) {
		if m, ok := b.(map[string]any); !ok || m["kind"] != "udp_buffer_small" {
			out = append(out, b)
		}
	}
	return out
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

// ---- ports and sender addresses ----

// pickPorts returns a syslog port free for UDP and TCP on 127.0.0.1 and a UI
// port, preferring 15514 and 18514.
func pickPorts(t *testing.T) (syslogPort, uiPort int) {
	t.Helper()
	free := func(p int, udp bool) bool {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			return false
		}
		l.Close()
		if !udp {
			return true
		}
		u, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			return false
		}
		u.Close()
		return true
	}
	random := func(udp bool) int {
		for range 100 {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			p := l.Addr().(*net.TCPAddr).Port
			l.Close()
			if free(p, udp) {
				return p
			}
		}
		t.Fatal("no free port")
		return 0
	}
	syslogPort, uiPort = 15514, 18514
	if !free(syslogPort, true) {
		syslogPort = random(true)
	}
	if !free(uiPort, false) || uiPort == syslogPort {
		uiPort = random(false)
	}
	return syslogPort, uiPort
}

// senderIPs returns 5 source addresses: 127.0.0.1 to .5 where this OS has them
// (Linux routes all of 127/8 to lo; macOS has only 127.0.0.1 unless aliases are
// configured), else 127.0.0.1 repeated.
func senderIPs(t *testing.T) []string {
	ips := []string{"127.0.0.1"}
	missing := 0
	for i := 2; i <= 5; i++ {
		ip := fmt.Sprintf("127.0.0.%d", i)
		c, err := net.ListenPacket("udp", ip+":0")
		if err != nil {
			missing++
			ips = append(ips, "127.0.0.1")
			continue
		}
		c.Close()
		ips = append(ips, ip)
	}
	if missing > 0 {
		t.Logf("NOTE: %d of 127.0.0.2-5 can't be bound on %s (no loopback aliases), so those senders use 127.0.0.1; "+
			"the run has %d distinct sender IPs", missing, runtime.GOOS, 5-missing)
	}
	return ips
}

func distinct(ss []string) map[string]int {
	m := map[string]int{}
	for _, s := range ss {
		m[s]++
	}
	return m
}

// ---- live tail ----

type liveStream struct {
	cancel context.CancelFunc
	mu     sync.Mutex
	events []map[string]any
	got    chan struct{} // closed at the first message event
	once   sync.Once
}

// openLive subscribes to /api/live with query q.
func openLive(t *testing.T, base, query string) *liveStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/live?"+query, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		cancel()
		t.Fatalf("/api/live: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	ls := &liveStream{cancel: cancel, got: make(chan struct{})}
	go func() {
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 1<<16), 1<<20)
		event := ""
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: ") && event == "message":
				var m map[string]any
				if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m) == nil {
					ls.mu.Lock()
					ls.events = append(ls.events, m)
					ls.mu.Unlock()
					ls.once.Do(func() { close(ls.got) })
				}
			case line == "":
				event = ""
			}
		}
	}()
	t.Cleanup(cancel)
	return ls
}

func (ls *liveStream) wait(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-ls.got:
	case <-time.After(d):
		t.Fatal("the live tail delivered nothing")
	}
}

func (ls *liveStream) count() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.events)
}

// ---- sending ----

type sender struct {
	ip, proto, framing string
}

var senderMix = []struct{ proto, framing string }{{"udp", ""}, {"tcp", "lf"}, {"udp", ""}, {"tcp", "octet"}, {"tcp", "lf"}}

// sendAll has each sender send per messages of run, sequence numbers starting at
// first + i*per, concurrently, at rate msg/s each.
func sendAll(t *testing.T, port int, senders []sender, run string, first, per int, rate float64) {
	t.Helper()
	var wg sync.WaitGroup
	errs := make(chan error, len(senders))
	for i, s := range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := loadgen.Send(context.Background(), loadgen.SendOptions{
				Addr: fmt.Sprintf("127.0.0.1:%d", port), Proto: s.proto, Framing: s.framing, Source: s.ip,
				Count: per, Rate: rate, RunID: run, FirstSeq: first + i*per,
			})
			if err == nil && res.Sent != per {
				err = fmt.Errorf("sent %d of %d", res.Sent, per)
			}
			if err != nil {
				errs <- fmt.Errorf("sender %d (%s %s %s): %w", i, s.ip, s.proto, s.framing, err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func writeConfig(t *testing.T, dir string, syslogPort, uiPort int) (cfgPath, dataDir string) {
	t.Helper()
	c := config.Default()
	c.Listeners.UDP = config.Listener{Enabled: true, Addr: "127.0.0.1", Port: syslogPort}
	c.Listeners.TCP = config.Listener{Enabled: true, Addr: "127.0.0.1", Port: syslogPort}
	c.Storage.DataDir = filepath.Join(dir, "data")
	c.UI.Port = uiPort
	cfgPath = filepath.Join(dir, "woodshed.toml")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	return cfgPath, c.Storage.DataDir
}

func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func totalMsgs(p *proc) (sum int, devs []any) {
	var page map[string]any
	p.getJSON("/api/devices?limit=1000", &page)
	devs = asSlice(page["devices"])
	if int(num(page["total"])) != len(devs) {
		p.t.Fatalf("/api/devices total %v, %d devices", page["total"], len(devs))
	}
	for _, d := range devs {
		sum += int(num(d.(map[string]any)["total_msgs"]))
	}
	return sum, devs
}

// ---- the tests ----

const (
	perSender  = 10000
	numSenders = 5
	phase1     = perSender * numSenders // 50,000
	perStop    = 1000                   // per sender, just before SIGTERM
	phase2     = perStop * numSenders
	afterRe    = 1000
)

func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	cfgPath, dataDir := writeConfig(t, dir, syslogPort, uiPort)
	t.Logf("syslog on 127.0.0.1:%d (UDP and TCP), UI on 127.0.0.1:%d, data in %s", syslogPort, uiPort, dataDir)
	p := startWoodshed(t, cfgPath, dataDir, uiPort)

	// Before any message: the welcome-page state.
	var st map[string]any
	p.getJSON("/api/status", &st)
	checkStatus(t, st)
	if st["first_message_at"] != nil {
		t.Errorf("first_message_at = %v before any message", st["first_message_at"])
	}
	for _, l := range asSlice(st["listeners"]) {
		if l := l.(map[string]any); l["ok"] != true || int(num(l["port"])) != syslogPort {
			t.Errorf("listener %v", l)
		}
	}
	if len(hostBanners(st["banners"])) != 0 {
		t.Errorf("banners on a clean start: %v", st["banners"])
	}

	ips := senderIPs(t)
	var senders []sender
	for i, ip := range ips {
		senders = append(senders, sender{ip: ip, proto: senderMix[i].proto, framing: senderMix[i].framing})
	}
	run := loadgen.NewRunID()
	live := openLive(t, p.base, "q="+url.QueryEscape(loadgen.SeqTag(run)))

	t0 := time.Now()
	sendAll(t, syslogPort, senders, run, 0, perSender, 2500)
	t.Logf("sent %d messages from %d senders (%d distinct IPs) in %v", phase1, numSenders, len(distinct(ips)), time.Since(t0).Round(time.Millisecond))

	live.wait(t, 5*time.Second)
	live.mu.Lock()
	shape(t, "live message", live.events[0], liveShape)
	if !strings.Contains(fmt.Sprint(live.events[0]["raw"]), loadgen.SeqTag(run)) || num(live.events[0]["severity"]) != 6 {
		t.Errorf("live message = %v", live.events[0])
	}
	live.mu.Unlock()

	waitFor(t, fmt.Sprintf("%d messages in /api/devices", phase1), 30*time.Second, func() bool {
		n, _ := totalMsgs(p)
		return n == phase1
	})
	t.Logf("live tail delivered %d messages (sampled to about 50/s)", live.count())

	// /api/devices: one device per distinct IP, with its share of the messages.
	_, devs := totalMsgs(p)
	wantPer := distinct(ips)
	if len(devs) != len(wantPer) {
		t.Fatalf("%d devices, want %d", len(devs), len(wantPer))
	}
	for i, d := range devs {
		m := d.(map[string]any)
		shape(t, fmt.Sprintf("devices[%d]", i), m, deviceShape)
		ip := m["ip"].(string)
		if m["id"] != ip || m["status"] != "online" || m["hidden"] != false {
			t.Errorf("device %v", m)
		}
		if got, want := int(num(m["total_msgs"])), wantPer[ip]*perSender; got != want {
			t.Errorf("device %s total_msgs = %d, want %d", ip, got, want)
		}
		if num(m["bytes_on_disk"]) <= 0 || num(m["msgs_per_min"]) <= 0 {
			t.Errorf("device %s: bytes_on_disk %v, msgs_per_min %v", ip, m["bytes_on_disk"], m["msgs_per_min"])
		}
		fs, _ := time.Parse(time.RFC3339, m["first_seen"].(string))
		lh, _ := time.Parse(time.RFC3339, m["last_heard"].(string))
		if fs.IsZero() || lh.Before(fs) {
			t.Errorf("device %s: first_seen %v, last_heard %v", ip, fs, lh)
		}
	}

	// /api/status and /api/stats after traffic.
	st = nil
	p.getJSON("/api/status", &st)
	checkStatus(t, st)
	firstMsg, ok := st["first_message_at"].(string)
	if !ok {
		t.Fatalf("first_message_at = %v after traffic", st["first_message_at"])
	}
	if num(st["udp_rcvbuf_bytes"]) <= 0 || num(st["udp_rcvbuf_requested_bytes"]) != float64(config.DefaultUDPRcvbufBytes) {
		t.Errorf("rcvbuf: %v of %v", st["udp_rcvbuf_bytes"], st["udp_rcvbuf_requested_bytes"])
	}
	t.Logf("UDP receive buffer: %.0f granted of %.0f requested", num(st["udp_rcvbuf_bytes"]), num(st["udp_rcvbuf_requested_bytes"]))

	var stats map[string]any
	p.getJSON("/api/stats", &stats)
	shape(t, "stats", stats, statsShape)
	shape(t, "stats.devices", stats["devices"].(map[string]any), statsDevicesShape)
	shape(t, "stats.disk", stats["disk"].(map[string]any), diskShape)
	sd, disk := stats["devices"].(map[string]any), stats["disk"].(map[string]any)
	if int(num(sd["total"])) != len(wantPer) || int(num(sd["online"])) != len(wantPer) {
		t.Errorf("stats.devices = %v", sd)
	}
	if num(disk["used_bytes"]) <= 0 || num(disk["cap_bytes"]) != float64(config.DefaultRetentionBytes) || num(disk["days_kept"]) < 1 || num(disk["free_bytes"]) <= 0 {
		t.Errorf("stats.disk = %v", disk)
	}
	if len(asSlice(stats["sparkline"])) != 60 || num(stats["dropped_24h"]) != 0 || num(stats["truncated_24h"]) != 0 {
		t.Errorf("stats = %v", stats)
	}
	if (runtime.GOOS == "linux") != (stats["kernel_dropped_24h"] != nil) {
		t.Errorf("kernel_dropped_24h = %v on %s", stats["kernel_dropped_24h"], runtime.GOOS)
	}
	if runtime.GOOS == "linux" && num(stats["kernel_dropped_24h"]) != 0 {
		t.Errorf("kernel dropped %v UDP messages", stats["kernel_dropped_24h"])
	}

	// The allowlist refuses other senders, live, and /api/rejected shows them.
	var settings map[string]any
	p.getJSON("/api/settings", &settings)
	listeners := settings["listeners"].(map[string]any)
	listeners["allowlist"] = []any{"192.0.2.1"}
	if code, b := p.do("PUT", "/api/settings", settings); code != 200 {
		t.Fatalf("PUT allowlist: %d %s", code, b)
	}
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort), Proto: "udp", Count: 10, Rate: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	var rejected []any
	waitFor(t, "10 rejected messages", 10*time.Second, func() bool {
		rejected = nil
		p.getJSON("/api/rejected", &rejected)
		return len(rejected) == 1 && num(rejected[0].(map[string]any)["count_24h"]) == 10
	})
	shape(t, "rejected[0]", rejected[0].(map[string]any), rejectedShape)
	if rejected[0].(map[string]any)["reason"] != "allowlist" {
		t.Errorf("rejected reason %v", rejected[0])
	}
	if rejected[0].(map[string]any)["ip"] != "127.0.0.1" {
		t.Errorf("rejected = %v", rejected)
	}
	stats = nil
	p.getJSON("/api/stats", &stats)
	if num(stats["rejected_24h"]) != 10 {
		t.Errorf("rejected_24h = %v", stats["rejected_24h"])
	}
	listeners["allowlist"] = []any{}
	if code, b := p.do("PUT", "/api/settings", settings); code != 200 {
		t.Fatalf("PUT empty allowlist: %d %s", code, b)
	}

	// A settings PUT with a bad port: 400 with dotted keys, nothing saved.
	bad := map[string]any{}
	b, _ := json.Marshal(settings)
	json.Unmarshal(b, &bad)
	bad["listeners"].(map[string]any)["udp"].(map[string]any)["port"] = 70000
	bad["listeners"].(map[string]any)["allowlist"] = []any{"10.0.0.0/8", "not-a-cidr"}
	code, body := p.do("PUT", "/api/settings", bad)
	var verr struct {
		Error  string            `json:"error"`
		Errors map[string]string `json:"errors"`
	}
	json.Unmarshal(body, &verr)
	if code != 400 || verr.Errors["listeners.udp.port"] == "" || verr.Errors["listeners.allowlist[1]"] == "" || verr.Error == "" {
		t.Errorf("bad PUT: %d %s", code, body)
	}
	if onDisk, err := config.Load(cfgPath); err != nil || onDisk.Listeners.UDP.Port != syslogPort {
		t.Errorf("the bad PUT changed the file: %+v %v", onDisk.Listeners.UDP, err)
	}

	// PATCH rename (persistence is checked after the restart).
	renamed := "127.0.0.1"
	code, body = p.do("PATCH", "/api/devices/"+renamed, map[string]any{"name": "e2e-sender", "group": "lab"})
	var dev map[string]any
	json.Unmarshal(body, &dev)
	if code != 200 || dev["name"] != "e2e-sender" || dev["group"] != "lab" {
		t.Fatalf("PATCH: %d %s", code, body)
	}
	shape(t, "patched device", dev, deviceShape)

	// `woodshed status` reads the same API.
	out, err := exec.Command(binary, "status", "--config", cfgPath).CombinedOutput()
	if err != nil || !strings.Contains(string(out), fmt.Sprintf("UDP 127.0.0.1:%d: listening", syslogPort)) ||
		!strings.Contains(string(out), fmt.Sprintf("http://localhost:%d/", uiPort)) {
		t.Errorf("woodshed status: %v\n%s", err, out)
	}

	// SIGTERM right after a burst: whatever was received must be on disk. Wait
	// until the live tail has seen each sender's last message (so the server has
	// handed it to the store, which still holds it in a buffer), then stop.
	var lasts []*liveStream
	for i := range senders {
		lastSeq := phase1 + i*perStop + perStop - 1
		// Sequence numbers here have 5 digits and none has 6, so the tag is unique.
		lasts = append(lasts, openLive(t, p.base, "q="+url.QueryEscape(loadgen.SeqTag(run)+fmt.Sprint(lastSeq))))
	}
	sendAll(t, syslogPort, senders, run, phase1, perStop, 5000)
	for _, ls := range lasts {
		ls.wait(t, 10*time.Second)
	}
	p.stop()

	v, err := loadgen.Verify(dataDir, run, phase1+phase2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("on disk after SIGTERM: %d received, %d missing, %d duplicates, %d other lines", v.Received, v.Missing, v.Duplicates, v.Foreign)
	if v.Missing != 0 || v.Duplicates != 0 || v.Received != phase1+phase2 {
		t.Fatalf("verify after SIGTERM = %+v", v)
	}
	checkEvents(t, dataDir, 1)

	// Restart on the same data: devices, names and totals are back.
	p2 := startWoodshed(t, cfgPath, dataDir, uiPort)
	st = nil
	p2.getJSON("/api/status", &st)
	if st["first_message_at"] != firstMsg {
		t.Errorf("first_message_at after restart = %v, want %s", st["first_message_at"], firstMsg)
	}
	n, devs := totalMsgs(p2)
	if n != phase1+phase2 || len(devs) != len(wantPer) {
		t.Errorf("after restart: %d messages over %d devices, want %d over %d", n, len(devs), phase1+phase2, len(wantPer))
	}
	found := false
	for _, d := range devs {
		if m := d.(map[string]any); m["id"] == renamed {
			found = m["name"] == "e2e-sender" && m["group"] == "lab"
		}
	}
	if !found {
		t.Errorf("the PATCH rename didn't survive the restart: %v", devs)
	}
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort), Proto: "tcp", Count: afterRe, RunID: run, FirstSeq: phase1 + phase2,
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the post-restart messages", 15*time.Second, func() bool {
		n, _ := totalMsgs(p2)
		return n == phase1+phase2+afterRe
	})
	p2.stop()
	v, err = loadgen.Verify(dataDir, run, phase1+phase2+afterRe)
	if err != nil {
		t.Fatal(err)
	}
	if v.Missing != 0 || v.Duplicates != 0 {
		t.Fatalf("verify after the restart = %+v", v)
	}
	t.Logf("after restart and %d more: %d received, %d missing, %d duplicates", afterRe, v.Received, v.Missing, v.Duplicates)
	checkEvents(t, dataDir, 2)
}

// checkEvents checks the event log has `runs` start and stop events, the last
// one a clean stop.
func checkEvents(t *testing.T, dataDir string, runs int) {
	t.Helper()
	idx, err := index.Open(filepath.Join(dataDir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	evs, err := idx.Events(context.Background(), time.Time{}, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	n := map[index.Kind]int{}
	for _, e := range evs {
		if e.Kind == index.KindStart || e.Kind == index.KindStop {
			if strings.HasPrefix(e.Text, "Woodshed") {
				n[e.Kind]++
			}
		}
	}
	if n[index.KindStart] != runs || n[index.KindStop] != runs {
		t.Errorf("service start/stop events = %v, want %d each", n, runs)
	}
	if last := evs[len(evs)-1]; last.Kind != index.KindStop || last.Text != "Woodshed stopped." {
		t.Errorf("last event = %+v, want a clean stop", last)
	}
}

func TestPortClash(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	cfgPath, dataDir := writeConfig(t, dir, syslogPort, uiPort)
	hold, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", syslogPort))
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()

	p := startWoodshed(t, cfgPath, dataDir, uiPort) // the UI starts despite the clash
	var st map[string]any
	p.getJSON("/api/status", &st)
	checkStatus(t, st)
	ls := asSlice(st["listeners"])
	udp, tcp := ls[0].(map[string]any), ls[1].(map[string]any)
	if udp["proto"] != "udp" || udp["ok"] != false || udp["error"] == "" || tcp["ok"] != true {
		t.Fatalf("listeners = %v", ls)
	}
	t.Logf("UDP error: %v; holder: %v", udp["error"], udp["holder"])
	bs := asSlice(st["banners"])
	if len(bs) != 1 {
		t.Fatalf("banners = %v", bs)
	}
	b := bs[0].(map[string]any)
	if b["kind"] != "listener_bind" || b["level"] != "error" || b["action"] != "retry_listeners" ||
		!strings.Contains(b["text"].(string), fmt.Sprintf("UDP %d", syslogPort)) {
		t.Errorf("banner = %v", b)
	}
	t.Logf("banner: %v", b["text"])

	// Retry while the port is still held: 204, still down.
	if code, body := p.do("POST", "/api/listeners/retry", nil); code != 204 {
		t.Fatalf("retry: %d %s", code, body)
	}
	st = nil
	p.getJSON("/api/status", &st)
	if asSlice(st["listeners"])[0].(map[string]any)["ok"] != false {
		t.Fatal("UDP is up while the port is still held")
	}

	// Free it; Retry until the listener is up and the banner is gone.
	hold.Close()
	tries := 0
	waitFor(t, "UDP up after Retry", 15*time.Second, func() bool {
		tries++
		p.do("POST", "/api/listeners/retry", nil)
		st = nil
		p.getJSON("/api/status", &st)
		return asSlice(st["listeners"])[0].(map[string]any)["ok"] == true && len(hostBanners(st["banners"])) == 0
	})
	t.Logf("UDP up after %d retries", tries)

	run := loadgen.NewRunID()
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort), Proto: "udp", Count: 100, RunID: run, Rate: 1000,
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "100 messages", 10*time.Second, func() bool { n, _ := totalMsgs(p); return n == 100 })
	p.stop()
	v, err := loadgen.Verify(dataDir, run, 100)
	if err != nil || v.Missing != 0 || v.Duplicates != 0 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
}
