package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/service"
)

func TestSeverityFilterCommand(t *testing.T) {
	defer noService()
	cfgPath, dataDir := testConfig(t, nil)
	code, out, errOut := runCLI("severity-filter", "--config", cfgPath)
	if code != 0 || errOut != "" || !strings.Contains(out, "Default: store everything (syslog.min_severity = debug).") ||
		!strings.Contains(out, "No device has its own setting.") {
		t.Fatalf("show: %d %q %q", code, out, errOut)
	}
	code, out, errOut = runCLI("severity-filter", "info", "--config", cfgPath)
	if code != 0 || errOut != "" || !strings.Contains(out, "Set the default severity filter to store info and above (was everything).") ||
		!strings.Contains(out, "isn't running") {
		t.Fatalf("set the default: %d %q %q", code, out, errOut)
	}
	if c := loadCfg(t, cfgPath); c.Syslog.MinSeverity != "info" {
		t.Fatalf("saved %+v", c.Syslog)
	}
	if code, out, _ := runCLI("severity-filter", "6", "--config", cfgPath); code != 0 || !strings.Contains(out, "already stores info and above") {
		t.Errorf("again: %d %q", code, out)
	}
	// A device's own, by its address or its device ID; then the default again.
	code, out, errOut = runCLI("severity-filter", "--device", "2001:db8::7", "debug", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "2001:db8::7 now stores everything (its own setting).") {
		t.Fatalf("device: %d %q %q", code, out, errOut)
	}
	code, out, _ = runCLI("severity-filter", "--device", "192.0.2.10", "warn", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "192.0.2.10 now stores warning and above") {
		t.Fatalf("device 2: %d %q", code, out)
	}
	if c := loadCfg(t, cfgPath); c.Syslog.MinSeverityByDevice["2001:db8::7"] != "debug" || c.Syslog.MinSeverityByDevice["192.0.2.10"] != "warning" {
		t.Fatalf("saved %+v", c.Syslog)
	}
	code, out, _ = runCLI("severity-filter", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Devices with their own setting:\n  192.0.2.10") || !strings.Contains(out, "2001:db8::7") {
		t.Errorf("show: %q", out)
	}
	code, out, _ = runCLI("severity-filter", "--device", "2001_db8__7", "default", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "2001:db8::7 follows the default again: it stores info and above.") {
		t.Errorf("default: %d %q", code, out)
	}
	if _, ok := loadCfg(t, cfgPath).Syslog.MinSeverityByDevice["2001:db8::7"]; ok {
		t.Error("the override is still there")
	}
	// Usage errors change nothing.
	for _, args := range [][]string{{"loud"}, {"default"}, {"--device", "nope", "info"}, {"--device", "192.0.2.10"}} {
		code, _, errOut := runCLI(append([]string{"severity-filter", "--config", cfgPath}, args...)...)
		if code != 2 || !strings.Contains(errOut, "woodshed severity-filter: ") {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	if c := loadCfg(t, cfgPath); c.Syslog.MinSeverity != "info" || len(c.Syslog.MinSeverityByDevice) != 1 {
		t.Errorf("after the errors %+v", c.Syslog)
	}

	// A running service is restarted to use it.
	lock, err := server.LockDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	restarts := 0
	serviceStatus = func() (service.State, error) { return service.StateRunning, nil }
	serviceRestart = func() error { restarts++; return nil }
	code, out, errOut = runCLI("severity-filter", "notice", "--config", cfgPath)
	if code != 0 || restarts != 1 || !strings.Contains(out, "Restarted the service") || !strings.Contains(out, "The 1 device with its own setting keeps it.") {
		t.Errorf("restart: %d restarts=%d %q %q", code, restarts, out, errOut)
	}
	// --no-restart while it runs is refused: the service would write its own
	// config back on its next save from the UI.
	code, out, errOut = runCLI("severity-filter", "err", "--no-restart", "--config", cfgPath)
	if code != 1 || restarts != 1 || out != "" || !strings.Contains(errOut, "Woodshed is running") || !strings.Contains(errOut, "nothing changed") {
		t.Errorf("--no-restart while running: %d restarts=%d %q %q", code, restarts, out, errOut)
	}
	if c := loadCfg(t, cfgPath); c.Syslog.MinSeverity != "notice" {
		t.Errorf("--no-restart changed it: %+v", c.Syslog)
	}
	lock.Unlock()
	serviceStatus = func() (service.State, error) { return service.StateStopped, nil }
	code, out, errOut = runCLI("severity-filter", "err", "--no-restart", "--config", cfgPath)
	if code != 0 || restarts != 1 || !strings.Contains(out, "to store err and above") || errOut != "" {
		t.Errorf("--no-restart while stopped: %d restarts=%d %q %q", code, restarts, out, errOut)
	}
	if c := loadCfg(t, cfgPath); c.Syslog.MinSeverity != "err" {
		t.Errorf("--no-restart while stopped didn't save: %+v", c.Syslog)
	}
}

func TestStatusSeverityRows(t *testing.T) {
	var b bytes.Buffer
	w := &tabw{w: &b}
	cfg := config.Default()
	statusSeverityRows(w, cfg, &server.RunState{})
	if b.Len() != 0 {
		t.Errorf("a row while it stores everything: %q", b.String())
	}
	cfg.Syslog.MinSeverity = "info"
	cfg.Syslog.MinSeverityByDevice = map[string]config.SeverityText{"192.0.2.10": "notice"}
	rs := &server.RunState{SeverityFilter: &api.SeverityFilterStats{MinSeverity: "info", DeviceOverrides: 1, Filtered24h: 12346,
		BySeverity24h: map[string]int64{"debug": 12345, "info": 1}, Devices24h: 2}}
	statusSeverityRows(w, cfg, rs)
	want := "Severity:   stores info and above by default, 1 device with its own; not stored in the last 24 h: 12,346 (12,345 debug, 1 info from 2 devices)\n"
	if b.String() != want {
		t.Errorf("got  %q\nwant %q", b.String(), want)
	}
	b.Reset()
	rs.SeverityFilter = &api.SeverityFilterStats{MinSeverity: "info", BySeverity24h: map[string]int64{}}
	statusSeverityRows(w, cfg, rs)
	if !strings.HasSuffix(b.String(), "; nothing left out in the last 24 h\n") {
		t.Errorf("got %q", b.String())
	}
}

// With the service stopped, a run-state file a crash left behind gives the
// last run's counts, labelled so, with the file's time.
func TestStatusSeverityRowsLastRun(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.DataDir = t.TempDir()
	cfg.Syslog.MinSeverity = "info"
	st := server.RunState{PID: 1, SeverityFilter: &api.SeverityFilterStats{MinSeverity: "info", Filtered24h: 5,
		BySeverity24h: map[string]int64{"debug": 5}, Devices24h: 1}}
	raw, _ := json.Marshal(st)
	path := filepath.Join(cfg.Storage.DataDir, server.StateFileName)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 11, 20, 9, 30, 0, 0, time.Local)
	os.Chtimes(path, when, when)
	var b bytes.Buffer
	statusSeverityRows(&tabw{w: &b}, cfg, nil)
	want := "Severity:   stores info and above by default; not stored in the last run's last 24 h (as of 2026-11-20 09:30:00; Woodshed isn't running): 5 (5 debug from 1 device)\n"
	if b.String() != want {
		t.Errorf("got  %q\nwant %q", b.String(), want)
	}
	// No file (a clean stop removes it): the setting only.
	os.Remove(path)
	b.Reset()
	statusSeverityRows(&tabw{w: &b}, cfg, nil)
	if b.String() != "Severity:   stores info and above by default\n" {
		t.Errorf("no file: %q", b.String())
	}
}
