package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSNMPDefaultsOff(t *testing.T) {
	c := Default()
	s := c.Listeners.SNMP
	if s.Enabled || s.Port != 162 || s.Addr != "0.0.0.0" || !s.AnswerInforms || s.V3StrictTime || s.Communities == nil {
		t.Fatalf("defaults: %+v", s)
	}
}

// A 1.1 file has no [listeners.snmp]: it loads with the listener off (SPEC §11.7).
func TestSNMP11FileLoadsOff(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, FileName)
	if err := os.WriteFile(p, []byte("[listeners.udp]\nenabled = true\nport = 514\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listeners.SNMP.Enabled || c.Listeners.SNMP.Port != 162 || !c.Listeners.SNMP.AnswerInforms {
		t.Fatalf("1.1 file: %+v", c.Listeners.SNMP)
	}
}

// Communities are secrets: never in the TOML (SPEC §11.2.1).
func TestSNMPCommunitiesNotInTOML(t *testing.T) {
	c := Default()
	c.Storage.DataDir = "/data"
	c.Listeners.SNMP.Communities = []string{"s3cret-community"}
	b, err := Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "s3cret-community") || strings.Contains(string(b), "communities =") {
		t.Fatalf("communities in the TOML:\n%s", b)
	}
	if !strings.Contains(string(b), "[listeners.snmp]") || !strings.Contains(string(b), "v3_strict_time = false") {
		t.Fatalf("no [listeners.snmp]:\n%s", b)
	}
}

func TestSNMPValidate(t *testing.T) {
	cases := []struct {
		name, key string
		mod       func(*SNMPListener, *Listeners)
	}{
		{"port", "listeners.snmp.port", func(s *SNMPListener, _ *Listeners) { s.Port = 0 }},
		{"same as udp", "listeners.snmp.port", func(s *SNMPListener, _ *Listeners) { s.Port = 514 }},
		{"mib_dir relative", "listeners.snmp.mib_dir", func(s *SNMPListener, _ *Listeners) { s.MIBDir = "mibs" }},
		{"engine hex", "listeners.snmp.engine_id", func(s *SNMPListener, _ *Listeners) { s.EngineID = "zz" }},
		{"engine short", "listeners.snmp.engine_id", func(s *SNMPListener, _ *Listeners) { s.EngineID = "80000000" }},
		{"engine zeros", "listeners.snmp.engine_id", func(s *SNMPListener, _ *Listeners) { s.EngineID = "0000000000" }},
		{"community empty", "listeners.snmp.communities[0]", func(s *SNMPListener, _ *Listeners) { s.Communities = []string{""} }},
		{"communities many", "listeners.snmp.communities", func(s *SNMPListener, _ *Listeners) { s.Communities = make([]string, 101) }},
		{"darwin specific addr", "listeners.snmp.addr", func(s *SNMPListener, _ *Listeners) { s.Enabled = true; s.Addr = "127.0.0.1" }},
	}
	for _, tc := range cases {
		c := testConfig(t)
		tc.mod(&c.Listeners.SNMP, &c.Listeners)
		errs := c.validate("darwin", nil)
		if errs[tc.key] == "" {
			t.Errorf("%s: no error on %s: %v", tc.name, tc.key, errs)
		}
	}
	c := testConfig(t)
	c.Listeners.SNMP.EngineID = "8000000005a1b2c3d4e5f60718"
	c.Listeners.SNMP.Port = 25162
	c.Listeners.SNMP.Enabled = true
	c.Listeners.SNMP.Addr = "127.0.0.1"
	if errs := c.validate("darwin", nil); errs != nil {
		t.Errorf("valid: %v", errs)
	}
}
