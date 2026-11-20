package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
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
}

func newSevSender(t *testing.T, port, tlsPort int, dataDir string) *sevSender {
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
	s := &sevSender{t: t}
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
					_, err = s.udp.Write([]byte(raw))
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
	snd := newSevSender(t, port, tlsPort, dataDir)
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
			if e.DeviceID != id {
				t.Errorf("event %+v", e)
			}
		}
	}
	if strings.Join(texts, "|") != "severity filter for 127.0.0.1 set to info and above|severity filter for 127.0.0.1 set to the default (notice and above)" {
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
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("<15>debug before"))
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
	c.Write([]byte("<14>info after"))
	c.Write([]byte("<13>notice after"))
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
	want := []string{"severity filter for 127.0.0.1 set to notice and above",
		"default severity filter set to warning and above (was everything); 1 device keeps its own setting"}
	if strings.Join(texts, "|") != strings.Join(want, "|") {
		t.Errorf("events %q", texts)
	}
}
