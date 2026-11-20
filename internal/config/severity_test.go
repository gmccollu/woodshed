package config

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]int{
		"emerg": 0, "EMERG": 0, "emergency": 0, "panic": 0, "alert": 1, "crit": 2, "critical": 2, "err": 3, "error": 3,
		"warning": 4, "warn": 4, "notice": 5, "info": 6, "Informational": 6, "debug": 7, " debug ": 7,
		"0": 0, "6": 6, "7": 7,
	} {
		if got, ok := ParseSeverity(in); !ok || got != want {
			t.Errorf("ParseSeverity(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "8", "-1", "06", "1.0", "verbose", "default", "infos"} {
		if _, ok := ParseSeverity(in); ok {
			t.Errorf("ParseSeverity(%q) accepted", in)
		}
	}
	if SeverityPhrase(7) != "everything" || SeverityPhrase(6) != "info and above" || SeverityPhrase(0) != "emerg only" {
		t.Error(SeverityPhrase(7), SeverityPhrase(6), SeverityPhrase(0))
	}
}

// The default keeps everything, a file without the [syslog] table (every
// config before this) reads as the default, and names and bare numbers both
// read and are written back as names.
func TestSyslogSeverityFile(t *testing.T) {
	c := testConfig(t)
	if c.Syslog.Level() != SeverityDebug || c.Syslog.Filtering() {
		t.Fatalf("default: %+v", c.Syslog)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	old := "[storage]\ndata_dir = " + tomlString(dir) + "\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Syslog.MinSeverity != "debug" || len(got.Syslog.MinSeverityByDevice) != 0 || got.Syslog.Filtering() {
		t.Fatalf("an old file: %+v", got.Syslog)
	}
	if errs := got.Validate(nil); errs != nil {
		t.Fatal(errs)
	}

	file := old + "[syslog]\nmin_severity = 6\n[syslog.min_severity_by_device]\n\"192.0.2.10\" = \"Debug\"\n\"2001:db8::1\" = 3\n\"::ffff:198.51.100.7\" = \"warn\"\n"
	if err := os.WriteFile(path, []byte(file), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err = Load(path); err != nil {
		t.Fatal(err)
	}
	if errs := got.Validate(nil); errs != nil {
		t.Fatal(errs)
	}
	want := map[string]SeverityText{"192.0.2.10": "debug", "2001:db8::1": "err", "198.51.100.7": "warning"}
	if got.Syslog.MinSeverity != "info" || len(got.Syslog.MinSeverityByDevice) != 3 {
		t.Fatalf("read %+v", got.Syslog)
	}
	for k, v := range want {
		if got.Syslog.MinSeverityByDevice[k] != v {
			t.Errorf("%s: %q, want %q", k, got.Syslog.MinSeverityByDevice[k], v)
		}
	}
	if err := Save(path, got); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "min_severity = 'info'") || !strings.Contains(string(b), "'2001:db8::1' = 'err'") {
		t.Errorf("written:\n%s", b)
	}
	again, err := Load(path)
	if err != nil || again.Syslog.MinSeverity != "info" || again.Syslog.MinSeverityByDevice["198.51.100.7"] != "warning" {
		t.Fatalf("round trip: %+v %v", again.Syslog, err)
	}
}

func tomlString(s string) string { b, _ := json.Marshal(s); return string(b) }

func TestSyslogSeverityValidate(t *testing.T) {
	c := testConfig(t)
	c.Syslog.MinSeverity = "loud"
	c.Syslog.MinSeverityByDevice = map[string]SeverityText{"not-an-ip": "info", "192.0.2.1": "9", "fe80::1%en0": "info"}
	errs := c.Validate(nil)
	for _, k := range []string{"syslog.min_severity", `syslog.min_severity_by_device["not-an-ip"]`,
		`syslog.min_severity_by_device["192.0.2.1"]`, `syslog.min_severity_by_device["fe80::1%en0"]`} {
		if errs[k] == "" {
			t.Errorf("no error for %s: %v", k, errs)
		}
	}
}

// The per-device resolution: an override wins, a device without one follows
// the default, and the API's JSON never carries the overrides (the device API
// sets them), so a settings PUT keeps them.
func TestSyslogDeviceLevel(t *testing.T) {
	c := Default()
	c.Syslog.MinSeverity = "notice"
	ap, other := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.11")
	if !c.Syslog.SetDevice(ap, 6) || c.Syslog.SetDevice(ap, 6) {
		t.Fatal("SetDevice's changed flag")
	}
	if n, own := c.Syslog.DeviceLevel(ap); n != 6 || !own {
		t.Errorf("override: %d %v", n, own)
	}
	if n, own := c.Syslog.DeviceLevel(netip.MustParseAddr("::ffff:192.0.2.10")); n != 6 || !own {
		t.Errorf("a mapped address: %d %v", n, own)
	}
	if n, own := c.Syslog.DeviceLevel(other); n != 5 || own {
		t.Errorf("default: %d %v", n, own)
	}
	if got := c.Syslog.DeviceLevels(); len(got) != 1 || got[ap] != 6 {
		t.Errorf("DeviceLevels %v", got)
	}
	cl := c.Clone()
	cl.Syslog.SetDevice(other, 0)
	if _, ok := c.Syslog.MinSeverityByDevice["192.0.2.11"]; ok {
		t.Error("Clone shares the overrides")
	}
	b, _ := json.Marshal(c)
	if strings.Contains(string(b), "by_device") || !strings.Contains(string(b), `"syslog":{"min_severity":"notice"}`) {
		t.Errorf("JSON %s", b)
	}
	next := c.Clone()
	if err := json.Unmarshal([]byte(`{"syslog":{"min_severity":"debug"}}`), &next); err != nil {
		t.Fatal(err)
	}
	if next.Syslog.MinSeverity != "debug" || next.Syslog.MinSeverityByDevice["192.0.2.10"] != "info" {
		t.Errorf("after a PUT: %+v", next.Syslog)
	}
	if !c.Syslog.SetDevice(ap, -1) || c.Syslog.SetDevice(ap, -1) {
		t.Fatal("removing an override")
	}
	if n, own := c.Syslog.DeviceLevel(ap); n != 5 || own {
		t.Errorf("after removing: %d %v", n, own)
	}
	c.Syslog.MinSeverity = "debug"
	if c.Syslog.Filtering() {
		t.Error("nothing filters")
	}
	c.Syslog.SetDevice(ap, 7)
	if c.Syslog.Filtering() {
		t.Error("an explicit debug override filters nothing")
	}
}

// Two spellings of one device's address in min_severity_by_device resolve the
// same way every time (the canonical key wins, the other is kept as written)
// and Validate refuses the second as a duplicate.
func TestSyslogDuplicateDeviceKeys(t *testing.T) {
	for i := 0; i < 20; i++ {
		c := testConfig(t)
		c.Syslog.MinSeverityByDevice = map[string]SeverityText{"::ffff:192.0.2.10": "info", "192.0.2.10": "err", " 192.0.2.11 ": "notice"}
		c.Normalize()
		if got := c.Syslog.MinSeverityByDevice; got["192.0.2.10"] != "err" || got["::ffff:192.0.2.10"] != "info" || got["192.0.2.11"] != "notice" || len(got) != 3 {
			t.Fatalf("normalized %v", got)
		}
		errs := c.Validate(nil)
		if errs[`syslog.min_severity_by_device["::ffff:192.0.2.10"]`] != `the same device as "192.0.2.10"; keep one of them` || len(errs) != 1 {
			t.Fatalf("errors %v", errs)
		}
	}
	// Only the mapped spelling: it's the device's, not a duplicate.
	c := testConfig(t)
	c.Syslog.MinSeverityByDevice = map[string]SeverityText{"::ffff:192.0.2.10": "info"}
	c.Normalize()
	if got := c.Syslog.MinSeverityByDevice; got["192.0.2.10"] != "info" || len(got) != 1 || len(c.Validate(nil)) != 0 {
		t.Fatalf("one spelling %v %v", got, c.Validate(nil))
	}
}
