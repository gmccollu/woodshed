package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

// sevSender sends raw syslog messages to a test server over each protocol.
type sevSender struct {
	t        *testing.T
	udp, tcp net.Conn
	tls      *tls.Conn
	r        *running
}

// udpRead is how many datagrams the syslog UDP reader took off the socket.
func (s *sevSender) udpRead() int64 {
	ln := s.r.srv.be.ln.Load()
	if ln == nil {
		return 0
	}
	return ln.Status().UDPRead
}

// sendUDP sends one datagram and waits until the UDP reader took it off the
// socket (its own counter, before the filter, the queue and the drainer),
// sending it again only if the reader never got it: UDP may lose one on
// loopback, and nothing here is about that. One unread for 10 s was lost, not
// slow, so a slow drainer can't cause a duplicate.
func (s *sevSender) sendUDP(raw string) {
	s.t.Helper()
	before := s.udpRead()
	for try := 0; try < 3; try++ {
		if _, err := s.udp.Write([]byte(raw)); err != nil {
			s.t.Fatal(err)
		}
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if s.udpRead() > before {
				return
			}
		}
	}
	s.t.Fatalf("the reader never got %q", raw)
}

func newSevSender(t *testing.T, r *running, port, tlsPort int, dataDir string) *sevSender {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	pem, err := os.ReadFile(filepath.Join(dataDir, tlscert.CAFile))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(caFile, pem, 0o600)
	tcfg, err := loadgen.ClientTLSConfig(caFile, "localhost", false)
	if err != nil {
		t.Fatal(err)
	}
	s := &sevSender{t: t, r: r}
	if s.udp, err = net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		t.Fatal(err)
	}
	if s.tcp, err = net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		t.Fatal(err)
	}
	if s.tls, err = tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort), tcfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.udp.Close(); s.tcp.Close(); s.tls.Close() })
	return s
}

// phase sends, over each protocol, 3 debug, 2 info and 1 notice message and
// one without a PRI, each with its own text ("<tag>-<proto>-<sev>-<i>").
func (s *sevSender) phase(tag string) (sent []string) {
	s.t.Helper()
	for _, proto := range []string{"udp", "tcp", "tls"} {
		for _, m := range []struct {
			pri string
			sev string
			n   int
		}{{"<15>", "debug", 3}, {"<14>", "info", 2}, {"<13>", "notice", 1}, {"", "nopri", 1}} {
			for i := 0; i < m.n; i++ {
				text := fmt.Sprintf("%s-%s-%s-%d", tag, proto, m.sev, i)
				sent = append(sent, text)
				raw := m.pri + "ap-01 wlan: " + text
				var err error
				switch proto {
				case "udp":
					s.sendUDP(raw)
				case "tcp":
					_, err = s.tcp.Write([]byte(raw + "\n"))
				case "tls":
					_, err = s.tls.Write([]byte(raw + "\n"))
				}
				if err != nil {
					s.t.Fatal(err)
				}
			}
		}
	}
	return sent
}

// storedLines are the device's stored lines, every file of today.
func storedLines(t *testing.T, dataDir, id string) string {
	t.Helper()
	var b strings.Builder
	files, _ := filepath.Glob(filepath.Join(dataDir, "logs", id, "*.log"))
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
	}
	return b.String()
}

func deviceOf(t *testing.T, r *running, id string) api.Device {
	t.Helper()
	var page api.DevicePage
	r.do(t, "GET", "/api/devices?q="+id, nil, &page)
	for _, d := range page.Devices {
		if d.ID == id {
			return d
		}
	}
	return api.Device{}
}

// The access point case end to end, over UDP, TCP and TLS: with the default
// at notice the device follows it; its own setting (info and above, set on
// the device API) applies from the next message, on the open TCP and TLS
// connections too; back to the default. Left-out messages are never stored,
// are counted exactly per severity, show on the device, in /api/stats and in
// events, and the counts survive a restart.
func TestSeverityFilterEndToEnd(t *testing.T) {
	dir := t.TempDir()
	port, tlsPort := freePort(t), freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, func(c *config.Config) {
		c.Listeners.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: tlsPort}
		c.Syslog.MinSeverity = "notice"
	})
	dataDir := filepath.Join(dir, "data")
	r := start(t, cfgPath)
	snd := newSevSender(t, r, port, tlsPort, dataDir)
	const id = "127.0.0.1"

	// Phase 1: no override, the default (notice and above): per protocol the
	// notice and the message without a PRI are stored, 3 debug and 2 info not.
	p1 := snd.phase("p1")
	waitFor(t, "phase 1 counted", func() bool {
		d := deviceOf(t, r, id)
		return d.TotalMsgs == 6 && d.Filtered24h == 15
	})
	d := deviceOf(t, r, id)
	if d.MinSeverity != "default" || d.MinSeverityEffective != "notice" || d.FilteredBySeverity24h["debug"] != 9 ||
		d.FilteredBySeverity24h["info"] != 6 || len(d.FilteredBySeverity24h) != 2 || d.Status != "online" {
		t.Fatalf("phase 1 device %+v", d)
	}

	// Phase 2: the device's own setting, info and above.
	var pd api.Device
	if code := r.do(t, "PATCH", "/api/devices/"+id, map[string]any{"min_severity": "info"}, &pd); code != 200 {
		t.Fatalf("patch %d", code)
	}
	if pd.MinSeverity != "info" || pd.MinSeverityEffective != "info" || pd.Filtered24h != 15 {
		t.Fatalf("patched %+v", pd)
	}
	p2 := snd.phase("p2")
	waitFor(t, "phase 2 counted", func() bool {
		d := deviceOf(t, r, id)
		return d.TotalMsgs == 18 && d.Filtered24h == 24
	})
	if d := deviceOf(t, r, id); d.FilteredBySeverity24h["debug"] != 18 || d.FilteredBySeverity24h["info"] != 6 {
		t.Fatalf("phase 2 device %+v", d)
	}

	// Phase 3: back to the default.
	if code := r.do(t, "PATCH", "/api/devices/"+id, map[string]any{"min_severity": "default"}, &pd); code != 200 ||
		pd.MinSeverity != "default" || pd.MinSeverityEffective != "notice" {
		t.Fatalf("patch default %d %+v", code, pd)
	}
	p3 := snd.phase("p3")
	waitFor(t, "phase 3 counted", func() bool {
		d := deviceOf(t, r, id)
		return d.TotalMsgs == 24 && d.Filtered24h == 39
	})

	// Exactly the kept messages are on disk, each once.
	lines := storedLines(t, dataDir, id)
	for _, text := range append(append(p1, p2...), p3...) {
		keep := strings.Contains(text, "-notice-") || strings.Contains(text, "-nopri-") ||
			(strings.HasPrefix(text, "p2-") && strings.Contains(text, "-info-"))
		if n := strings.Count(lines, text+"\n"); (keep && n != 1) || (!keep && n != 0) {
			t.Errorf("%s stored %d times", text, n)
		}
	}
	if n := strings.Count(lines, "\n"); n != 24 {
		t.Errorf("%d lines stored", n)
	}

	// /api/stats: not a drop.
	var st api.Stats
	r.do(t, "GET", "/api/stats", nil, &st)
	sf := st.SeverityFilter
	if sf.MinSeverity != "notice" || sf.DeviceOverrides != 0 || sf.Filtered24h != 39 || sf.BySeverity24h["debug"] != 27 ||
		sf.BySeverity24h["info"] != 12 || sf.Devices24h != 1 || st.Dropped24h != 0 {
		t.Errorf("stats %+v dropped %d", sf, st.Dropped24h)
	}

	// Events: one per change, naming the device.
	evs, err := r.srv.be.idx.Events(t.Context(), time.Time{}, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, e := range evs {
		if e.Kind == index.KindSeverityFilter {
			texts = append(texts, e.Text)
			if e.DeviceID != id && e.DeviceID != "" {
				t.Errorf("event %+v", e)
			}
		}
	}
	if strings.Join(texts, "|") != "default severity filter set to notice and above, was everything (changed while Woodshed was stopped)|"+
		"severity filter for 127.0.0.1 set to info and above, was the default (notice and above)|"+
		"severity filter for 127.0.0.1 set to the default (notice and above), was info and above" {
		t.Errorf("events %q", texts)
	}

	// A bad value changes nothing.
	var bad struct {
		Errors map[string]string `json:"errors"`
	}
	if code := r.do(t, "PATCH", "/api/devices/"+id, map[string]any{"min_severity": "loud"}, &bad); code != 400 || bad.Errors["min_severity"] == "" {
		t.Errorf("bad patch %d %v", code, bad)
	}

	// After a restart the counts are the same.
	snd.udp.Close()
	snd.tcp.Close()
	snd.tls.Close()
	r.stop(t)
	r = start(t, cfgPath)
	if d := deviceOf(t, r, id); d.Filtered24h != 39 || d.FilteredBySeverity24h["debug"] != 27 || d.TotalMsgs != 24 {
		t.Errorf("after the restart %+v", d)
	}
}

// The default from Settings: a PUT changes it from the next message, a
// device's own setting survives the PUT (the settings object doesn't carry
// it), a bad value is a 400 on syslog.min_severity, and a PUT without syslog
// (a 2.0 client) keeps it.
func TestSeverityFilterSettings(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, nil)
	r := start(t, cfgPath)
	const id = "127.0.0.1"
	// TCP: this test is about the settings, not UDP, so no datagram can be lost.
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("<15>debug before\n"))
	waitFor(t, "the first message", func() bool { return deviceOf(t, r, id).TotalMsgs == 1 })

	var set api.Settings
	r.do(t, "GET", "/api/settings", nil, &set)
	if set.Syslog == nil || set.Syslog.MinSeverity != "debug" {
		t.Fatalf("settings syslog %+v", set.Syslog)
	}
	// A device with its own setting: notice.
	if code := r.do(t, "PATCH", "/api/devices/"+id, map[string]any{"min_severity": "5"}, nil); code != 200 {
		t.Fatalf("patch %d", code)
	}
	r.do(t, "GET", "/api/settings", nil, &set)
	set.Syslog.MinSeverity = "warn"
	var saved api.Settings
	if code := r.do(t, "PUT", "/api/settings", set, &saved); code != 200 || saved.Syslog == nil || saved.Syslog.MinSeverity != "warning" {
		t.Fatalf("PUT %d %+v", code, saved.Syslog)
	}
	if d := deviceOf(t, r, id); d.MinSeverity != "notice" || d.MinSeverityEffective != "notice" {
		t.Fatalf("the device's own setting after the PUT: %+v", d)
	}
	cfg, err := config.Read(cfgPath)
	if err != nil || cfg.Syslog.MinSeverity != "warning" || cfg.Syslog.MinSeverityByDevice[id] != "notice" {
		t.Fatalf("config %+v %v", cfg.Syslog, err)
	}
	c.Write([]byte("<14>info after\n<13>notice after\n"))
	waitFor(t, "the notice", func() bool { d := deviceOf(t, r, id); return d.TotalMsgs == 2 && d.Filtered24h == 1 })

	set.Syslog.MinSeverity = "loud"
	var verr struct {
		Errors map[string]string `json:"errors"`
	}
	if code := r.do(t, "PUT", "/api/settings", set, &verr); code != 400 || verr.Errors["syslog.min_severity"] == "" {
		t.Errorf("bad PUT %d %v", code, verr)
	}
	set.Syslog = nil
	if code := r.do(t, "PUT", "/api/settings", set, &saved); code != 200 || saved.Syslog.MinSeverity != "warning" {
		t.Errorf("PUT without syslog %d %+v", code, saved.Syslog)
	}
	evs, _ := r.srv.be.idx.Events(t.Context(), time.Time{}, time.Time{}, 0)
	var texts []string
	for _, e := range evs {
		if e.Kind == index.KindSeverityFilter {
			texts = append(texts, e.Text)
		}
	}
	want := []string{"severity filter for 127.0.0.1 set to notice and above, was the default (store everything)",
		"default severity filter set to warning and above (was everything); 1 device keeps its own setting"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("events %q", texts)
	}
}

// The run-state file (rewritten every second), /api/stats and the device
// list read the severity filter's 24-hour counts from memory: none of them
// queries the index's filtered counts, however many devices and minutes it
// holds (SPEC §13.10 decision 86).
func TestSeverityCountsStayOffTheIndex(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, func(c *config.Config) { c.Syslog.MinSeverity = "info" })
	r := start(t, cfgPath)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "<15>left out\n<15>left out\n<14>kept\n")
	waitFor(t, "counted", func() bool { d := deviceOf(t, r, "127.0.0.1"); return d.TotalMsgs == 1 && d.Filtered24h == 2 })

	before := r.srv.be.idx.FilteredReads()
	for i := 0; i < 5; i++ {
		var rs RunState
		r.srv.be.fillRunState(&rs)
		if rs.SeverityFilter == nil || rs.SeverityFilter.Filtered24h != 2 {
			t.Fatalf("run state %+v", rs.SeverityFilter)
		}
	}
	var st api.Stats
	r.do(t, "GET", "/api/stats", nil, &st)
	if st.SeverityFilter.Filtered24h != 2 {
		t.Fatalf("stats %+v", st.SeverityFilter)
	}
	if d := deviceOf(t, r, "127.0.0.1"); d.FilteredBySeverity24h["debug"] != 2 {
		t.Fatalf("device %+v", d)
	}
	if n := r.srv.be.idx.FilteredReads() - before; n != 0 {
		t.Fatalf("%d index reads of the filtered counts", n)
	}
}

// A change made while Woodshed was stopped (woodshed severity-filter, a hand
// edit of the config) is recorded as an event at the next start, once; a
// start with nothing changed records none.
func TestSeverityFilterChangedWhileStopped(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, nil)
	r := start(t, cfgPath)
	r.stop(t)
	cfg, err := config.Read(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Syslog.MinSeverity = "info"
	cfg.Syslog.SetDevice(netip.MustParseAddr("192.0.2.10"), 3)
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	r = start(t, cfgPath)
	r.stop(t)
	cfg, _ = config.Read(cfgPath)
	cfg.Syslog.SetDevice(netip.MustParseAddr("192.0.2.10"), -1)
	config.Save(cfgPath, cfg)
	r = start(t, cfgPath)
	r.stop(t)
	r = start(t, cfgPath) // nothing changed
	evs, err := r.srv.be.idx.Events(t.Context(), time.Time{}, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var texts []string
	for _, e := range evs {
		if e.Kind == index.KindSeverityFilter {
			texts = append(texts, e.DeviceID+": "+e.Text)
		}
	}
	want := []string{
		": default severity filter set to info and above, was everything (changed while Woodshed was stopped)",
		"192.0.2.10: severity filter for 192.0.2.10 set to err and above, was the default (store everything) (changed while Woodshed was stopped)",
		"192.0.2.10: severity filter for 192.0.2.10 set to the default (info and above), was err and above (changed while Woodshed was stopped)",
	}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("events\n%s", strings.Join(texts, "\n"))
	}
}

// A device ID alone gives an address only when it's a plain one: a zoned ID
// is lossy ("fe80__1_5" is fe80::1%5 or fe80::1:5), so it gives none.
func TestDeviceIPParsesIDs(t *testing.T) {
	for _, c := range []struct {
		id, want string
	}{
		{"192.0.2.10", "192.0.2.10"},
		{"2001_db8__1", "2001:db8::1"},
		{"fe80__1", "fe80::1"},
		{"fe80__1_en0", ""},
		{"refused", ""},
		{"", ""},
	} {
		a, ok := deviceIP(c.id)
		if got := map[bool]string{true: a.String(), false: ""}[ok]; got != c.want {
			t.Errorf("%q: %q, want %q", c.id, got, c.want)
		}
	}
	// "fe80__1_5" parses as an address, but the wrong one: callers with a
	// device row use its IP instead.
	if a, ok := deviceAddr("fe80__1_5", "fe80::1%5"); !ok || a.String() != "fe80::1%5" {
		t.Errorf("row IP: %v %v", a, ok)
	}
}

// A link-local sender's device (its row's IP keeps the zone; its ID is lossy)
// takes its own setting for its address without the zone, as the listener
// looks it up, and shows it; a device ID without an address is a 400.
func TestSeverityFilterZonedDevice(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeConfig(t, dir, freePort(t), 0, nil)
	r := start(t, cfgPath)
	at := time.Now().UTC().Truncate(time.Minute)
	if err := r.srv.be.idx.Apply(t.Context(), index.Batch{Activity: []index.Activity{
		{DeviceID: "fe80__1_5", IP: "fe80::1%5", Minute: at, FirstHeard: at, LastHeard: at, Counts: index.Counts{Msgs: 1}},
		{DeviceID: "fe80__a_bad", IP: "fe80::a%bad", Minute: at, FirstHeard: at, LastHeard: at, Counts: index.Counts{Msgs: 1}},
		{DeviceID: "no-address", IP: "", Minute: at, FirstHeard: at, LastHeard: at, Counts: index.Counts{Msgs: 1}},
	}}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ id, sender, addr string }{{"fe80__1_5", "fe80::1%5", "fe80::1"}, {"fe80__a_bad", "fe80::a%bad", "fe80::a"}} {
		var d api.Device
		if code := r.do(t, "PATCH", "/api/devices/"+c.id, map[string]any{"min_severity": "Info"}, &d); code != 200 ||
			d.MinSeverity != "info" || d.MinSeverityEffective != "info" {
			t.Fatalf("%s PATCH %d %+v", c.id, code, d)
		}
		if got := deviceOf(t, r, c.id); got.MinSeverity != "info" {
			t.Fatalf("%s %+v", c.id, got)
		}
		cfg, err := config.Read(cfgPath)
		if err != nil || cfg.Syslog.MinSeverityByDevice[c.addr] != "info" {
			t.Fatalf("%s saved for %v (%v)", c.id, cfg.Syslog.MinSeverityByDevice, err)
		}
		// What the listener uses: the zoned sender's own setting.
		if n, own := cfg.Syslog.DeviceLevel(netip.MustParseAddr(c.sender)); n != 6 || !own {
			t.Fatalf("%s level %d %v", c.id, n, own)
		}
		if code := r.do(t, "PATCH", "/api/devices/"+c.id, map[string]any{"min_severity": "Default"}, &d); code != 200 || d.MinSeverity != "default" {
			t.Fatalf("%s Default %d %+v", c.id, code, d)
		}
	}
	if cfg, _ := config.Read(cfgPath); len(cfg.Syslog.MinSeverityByDevice) != 0 {
		t.Fatalf("left %v", cfg.Syslog.MinSeverityByDevice)
	}
	var e struct {
		Errors map[string]string `json:"errors"`
	}
	if code := r.do(t, "PATCH", "/api/devices/no-address", map[string]any{"min_severity": "info"}, &e); code != 400 || e.Errors["min_severity"] == "" {
		t.Fatalf("no address %d %v", code, e)
	}
}

// The CLI trusts a run-state file's config only while its writer holds the
// data folder's lock: not after the server stopped (a crash leaves the file),
// and not when the file's PID isn't the lock holder's.
func TestRunningState(t *testing.T) {
	dir := t.TempDir()
	if err := writeState(dir, RunState{PID: os.Getpid(), Config: "/x/woodshed.toml"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := RunningState(dir); ok {
		t.Fatal("trusted without the lock")
	}
	lock, err := LockDataDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	if rs, ok := RunningState(dir); !ok || rs.Config != "/x/woodshed.toml" {
		t.Fatalf("the holder's %+v %v", rs, ok)
	}
	// A PID that isn't the holder's: a process that has exited. Not
	// os.Getpid()+1: Windows ignores a PID's low two bits, so that is this
	// process there, and on Windows (where the locked lock file can't be read)
	// RunningState can only check that the state's PID is alive.
	child := exec.Command(os.Args[0], "-test.run=^$")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	if err := writeState(dir, RunState{PID: child.Process.Pid, Config: "/x/woodshed.toml"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := RunningState(dir); ok {
		t.Fatal("trusted a file that isn't the lock holder's")
	}
}

// A live change whose record didn't get saved (RecordSeverityFilter failed)
// isn't logged again at the next start as made while stopped: the newest
// event already says it.
func TestSeverityFilterNoDuplicateEventAtStart(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, nil)
	r := start(t, cfgPath)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "<14>hello\n")
	waitFor(t, "the device", func() bool { return deviceOf(t, r, "127.0.0.1").TotalMsgs == 1 })
	c.Close()
	if code := r.do(t, "PATCH", "/api/devices/127.0.0.1", map[string]any{"min_severity": "err"}, nil); code != 200 {
		t.Fatalf("patch %d", code)
	}
	var set api.Settings
	r.do(t, "GET", "/api/settings", nil, &set)
	set.Syslog.MinSeverity = "notice"
	if code := r.do(t, "PUT", "/api/settings", set, nil); code != 200 {
		t.Fatalf("put %d", code)
	}
	// As if both records had failed: the index still has the start's filter.
	if err := r.srv.be.idx.RecordSeverityFilter(t.Context(), index.SeverityFilterState{Default: 7, ByDevice: map[string]int{}}); err != nil {
		t.Fatal(err)
	}
	r.stop(t)
	r = start(t, cfgPath)
	evs, _ := r.srv.be.idx.Events(t.Context(), time.Time{}, time.Time{}, 0)
	var texts []string
	for _, e := range evs {
		if e.Kind == index.KindSeverityFilter {
			texts = append(texts, e.Text)
		}
	}
	want := []string{"severity filter for 127.0.0.1 set to err and above, was the default (store everything)",
		"default severity filter set to notice and above (was everything); 1 device keeps its own setting"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("events %q", texts)
	}
	if st, ok, err := r.srv.be.idx.RecordedSeverityFilter(t.Context()); err != nil || !ok || st.Default != 5 || st.ByDevice["127.0.0.1"] != 3 {
		t.Errorf("recorded %+v %v %v", st, ok, err)
	}
}
