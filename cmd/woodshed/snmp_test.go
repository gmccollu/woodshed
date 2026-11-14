package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/snmp"
)

func TestSNMPCommandLinux(t *testing.T) {
	defer noService()
	fw := withFirewall(t, "linux")
	cfgPath, dataDir := testConfig(t, nil)

	code, out, errOut := runCLI("snmp", "on", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Turned the SNMP trap receiver on (UDP port 162)") || !strings.Contains(out, "Opened 162/udp in ufw") ||
		!strings.Contains(out, "isn't running") || !strings.Contains(out, "Settings") {
		t.Fatalf("on: %d %q %q", code, out, errOut)
	}
	c := loadCfg(t, cfgPath)
	if !c.Listeners.SNMP.Enabled || c.Listeners.TLS.Enabled {
		t.Errorf("config: %+v", c.Listeners.SNMP)
	}
	if _, err := os.Stat(filepath.Join(dataDir, fwrule.SNMPRecordFile)); err != nil {
		t.Errorf("firewall record: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, fwrule.RecordFile)); !os.IsNotExist(err) {
		t.Error("snmp on wrote the TLS firewall record")
	}
	// On again: already on, nothing saved.
	if code, out, _ := runCLI("snmp", "on", "--config", cfgPath); code != 0 || !strings.Contains(out, "already on") {
		t.Errorf("on again: %d %q", code, out)
	}

	code, out, _ = runCLI("snmp", "off", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Turned the SNMP trap receiver off") || !strings.Contains(out, "losed 162/udp in ufw") {
		t.Fatalf("off: %d %q", code, out)
	}
	if c := loadCfg(t, cfgPath); c.Listeners.SNMP.Enabled {
		t.Error("still enabled")
	}
	if !strings.Contains(strings.Join(fw.calls, "\n"), "ufw delete allow 162/udp") {
		t.Errorf("calls %v", fw.calls)
	}

	// A port that clashes with the UDP syslog listener.
	if code, _, errOut := runCLI("snmp", "on", "--port", "15599", "--config", cfgPath); code != 1 || !strings.Contains(errOut, "listeners.snmp.port") {
		t.Errorf("clash: %d %q", code, errOut)
	}
	if code, out, _ := runCLI("snmp", "on", "--port", "25162", "--config", cfgPath); code != 0 || !strings.Contains(out, "UDP port 25162") {
		t.Errorf("on with a port: %d %q", code, out)
	}
	if c := loadCfg(t, cfgPath); c.Listeners.SNMP.Port != 25162 {
		t.Errorf("port %d", c.Listeners.SNMP.Port)
	}
	for _, args := range [][]string{{"snmp"}, {"snmp", "maybe"}, {"snmp", "on", "extra"}, {"snmp", "off", "--port", "7"},
		{"snmp", "on", "--user", "x"}, {"snmp", "on", "--auth-pass", "x"}} {
		if code, _, _ := runCLI(append(args, "--config", cfgPath)...); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
}

// v3 users and communities are Settings-only: the help says so and offers no
// flag for a secret.
func TestSNMPHelpNoSecrets(t *testing.T) {
	code, out, errOut := runCLI("snmp", "--help")
	help := out + errOut
	if code != 0 || !strings.Contains(help, "never on the command line") || !strings.Contains(help, "Settings") {
		t.Fatalf("help: %d %q", code, help)
	}
	for _, bad := range []string{"-pass", "-community", "-user"} {
		if strings.Contains(help, bad) {
			t.Errorf("help offers %s", bad)
		}
	}
}

func TestSNMPCommandWindowsRule(t *testing.T) {
	defer noService()
	fw := withFirewall(t, "windows")
	cfgPath, _ := testConfig(t, nil)
	code, out, errOut := runCLI("snmp", "on", "--config", cfgPath)
	if code != 0 || !fw.enabled || !strings.Contains(out, "Enabled the Windows firewall rule \""+fwrule.SNMPRuleName+"\" for UDP 162") {
		t.Fatalf("on: %d %q %q %v", code, out, errOut, fw.calls)
	}
	if !strings.Contains(strings.Join(fw.calls, "\n"), "name="+fwrule.SNMPRuleName) {
		t.Errorf("calls %v", fw.calls)
	}
	if code, out, _ := runCLI("snmp", "off", "--config", cfgPath); code != 0 || fw.enabled || !strings.Contains(out, "Disabled the Windows firewall rule") {
		t.Errorf("off: %d %q", code, out)
	}
	if code, out, _ := runCLI("snmp", "status", "--config", cfgPath); code != 0 || !strings.Contains(out, fwrule.SNMPRuleName) {
		t.Errorf("status: %d %q", code, out)
	}
}

func TestSNMPStatusFromFiles(t *testing.T) {
	defer noService()
	withFirewall(t, "darwin")
	cfgPath, dataDir := testConfig(t, func(c *config.Config) { c.Listeners.SNMP.Enabled = true; c.Listeners.SNMP.Port = 25162 })
	code, out, _ := runCLI("snmp", "status", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "on, UDP 25162, informs answered") || !strings.Contains(out, "not made yet") ||
		!strings.Contains(out, "not running") {
		t.Fatalf("status before the engine file: %d %q", code, out)
	}
	eng := `{"engine_id": "8000000005a1b2c3d4e5f60718", "engine_boots": 3}`
	if err := os.WriteFile(filepath.Join(dataDir, snmp.EngineFile), []byte(eng), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runCLI("snmp", "status", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "8000000005a1b2c3d4e5f60718 (boots 3)") {
		t.Fatalf("status: %d %q", code, out)
	}
	// Status only looks: the boots aren't raised.
	if b, _ := os.ReadFile(filepath.Join(dataDir, snmp.EngineFile)); string(b) != eng {
		t.Errorf("engine file changed: %s", b)
	}
}

func TestSNMPRows(t *testing.T) {
	var b bytes.Buffer
	w := &tabw{w: &b}
	at := time.Date(2026, 11, 14, 9, 10, 0, 0, time.UTC)
	rs := &server.RunState{SNMP: &server.RunStateSNMP{Enabled: true, Port: 162, AnswerInforms: true,
		EngineID: "8000000005a1b2c3d4e5f60718", EngineBoots: 12, Received24h: 15230, InformsAnswered24h: 212, TimeResyncs24h: 2,
		ByStatus24h: map[string]int64{"ok": 15201, "auth_failed": 25, "malformed": 4}, Users: 2, UnreadableUsers: 1, MIBNames: 1800,
		Failures: []server.RunStateSNMPFailure{{IP: "198.51.100.7", Count24h: 25, Status: "auth_failed", Detail: "user monitor: wrong digest", LastSeen: at}}}}
	statusSNMPRows(w, config.Default(), rs)
	out := b.String()
	for _, want := range []string{"on, UDP 162, informs answered", "8000000005a1b2c3d4e5f60718 (boots 12)",
		"15230 received, 212 informs answered, 0 replies rate-limited, 2 time resyncs", "by status: ok 15201, auth_failed 25, malformed 4",
		"2 v3 users (1 need their passphrases again", "198.51.100.7: auth_failed (user monitor: wrong digest), 25 in 24 h"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// Off and never reported: no rows.
	b.Reset()
	statusSNMPRows(w, config.Default(), &server.RunState{})
	if b.Len() != 0 {
		t.Errorf("rows for an SNMP receiver that's off: %q", b.String())
	}
}
