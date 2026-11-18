package main

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

// fakeFirewall records commands and answers like an active ufw, or a Windows
// firewall (netsh changes, ListRules reads) with the rule present (disabled).
type fakeFirewall struct {
	calls   []string
	enabled bool
}

func (f *fakeFirewall) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, filepath.Base(name)+" "+strings.Join(args, " "))
	// The code runs ufw and firewall-cmd by full path when the host has them
	// (/usr/sbin/ufw on CI runners): match on the base name, whatever is installed.
	if b := filepath.Base(name); b == "ufw" || b == "firewall-cmd" {
		name = b
	}
	switch {
	case name == "ufw" && args[0] == "status":
		return "Status: active", nil
	case name == "ufw" && args[0] == "allow":
		return "Rule added", nil
	case name == "ufw":
		return "Rule deleted", nil
	case strings.HasSuffix(name, "netsh.exe") && args[2] == "set":
		f.enabled = strings.Contains(strings.Join(args, " "), "enable=yes")
		return "Ok.", nil
	}
	return "", errors.New("not installed")
}

// list is fwrule.ListRules: every rule asked for is present, on 6514.
func (f *fakeFirewall) list(names ...string) ([]fwrule.WinRule, error) {
	f.calls = append(f.calls, "ListRules "+strings.Join(names, ", "))
	var out []fwrule.WinRule
	for _, n := range names {
		out = append(out, fwrule.WinRule{Name: n, LocalPorts: "6514", Direction: fwrule.RuleDirIn, Enabled: f.enabled,
			Action: fwrule.RuleActionAllow})
	}
	return out, nil
}

func withFirewall(t *testing.T, goos string) *fakeFirewall {
	f := &fakeFirewall{}
	oldRun, oldOS, oldList := fwRun, fwOS, fwrule.ListRules
	fwRun, fwOS, fwrule.ListRules = f.run, goos, f.list
	t.Cleanup(func() { fwRun, fwOS, fwrule.ListRules = oldRun, oldOS, oldList })
	return f
}

func TestTLSCommandLinux(t *testing.T) {
	defer noService()
	fw := withFirewall(t, "linux")
	cfgPath, dataDir := testConfig(t, nil)

	code, out, errOut := runCLI("tls", "on", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Turned syslog over TLS on (TCP port 6514)") || !strings.Contains(out, "Opened 6514/tcp in ufw") ||
		!strings.Contains(out, "isn't running") {
		t.Fatalf("on: %d %q %q", code, out, errOut)
	}
	if c := loadCfg(t, cfgPath); !c.Listeners.TLS.Enabled {
		t.Error("not enabled in the config")
	}
	if _, err := os.Stat(filepath.Join(dataDir, fwrule.RecordFile)); err != nil {
		t.Errorf("firewall record: %v", err)
	}
	// The CLI never makes key files: the service does, as its own account.
	if _, err := os.Stat(filepath.Join(dataDir, tlscert.KeyFile)); !os.IsNotExist(err) {
		t.Error("the CLI made a key file")
	}

	// status names what tls on opened, not the generic "open the port" hint.
	if _, sout, _ := runCLI("tls", "status", "--config", cfgPath); !strings.Contains(sout, "opened by woodshed tls on: ufw 6514/tcp") ||
		strings.Contains(sout, "if devices can't connect") {
		t.Errorf("status after on: %q", sout)
	}

	code, out, _ = runCLI("tls", "off", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Turned syslog over TLS off") || !strings.Contains(out, "losed 6514/tcp in ufw") {
		t.Fatalf("off: %d %q", code, out)
	}
	if c := loadCfg(t, cfgPath); c.Listeners.TLS.Enabled {
		t.Error("still enabled")
	}
	if !strings.Contains(strings.Join(fw.calls, "\n"), "ufw delete allow 6514/tcp") {
		t.Errorf("calls %v", fw.calls)
	}

	// A port clash.
	if code, _, errOut := runCLI("tls", "on", "--port", "15599", "--config", cfgPath); code != 1 || !strings.Contains(errOut, "listeners.tls.port") {
		t.Errorf("clash: %d %q", code, errOut)
	}
	// Renew before TLS was ever on.
	if code, _, errOut := runCLI("tls", "renew", "--config", cfgPath); code != 1 || !strings.Contains(errOut, "turn TLS on first") {
		t.Errorf("renew without a CA: %d %q", code, errOut)
	}
	for _, args := range [][]string{{"tls"}, {"tls", "maybe"}, {"tls", "on", "extra"}, {"tls", "off", "--new-ca"}, {"tls", "renew", "--port", "7"}} {
		if code, _, _ := runCLI(append(args, "--config", cfgPath)...); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
}

func TestTLSRenewAndStatus(t *testing.T) {
	defer noService()
	withFirewall(t, "darwin")
	cfgPath, dataDir := testConfig(t, nil)
	if code, out, _ := runCLI("tls", "on", "--port", "16514", "--config", cfgPath); code != 0 || strings.Contains(out, "firewall") {
		t.Fatalf("on (macOS changes no firewall): %d %q", code, out)
	}
	// What the service would have made at its start.
	m := tlscert.New(tlscert.Options{DataDir: dataDir, Identity: func() (tlscert.Identity, error) {
		return tlscert.Identity{Host: "box", Primary: "box", Names: []string{"box", "localhost"}, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, nil
	}})
	if _, err := m.Load(true); err != nil {
		t.Fatal(err)
	}
	st := m.Status()

	code, out, _ := runCLI("tls", "status", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "on, TCP 16514, Woodshed's own CA") || !strings.Contains(out, st.CA.SHA256) ||
		!strings.Contains(out, st.CA.SHA1) || !strings.Contains(out, st.Cert.SHA256) || !strings.Contains(out, "2037-12-31") {
		t.Errorf("status: %d %q", code, out)
	}

	code, out, errOut := runCLI("tls", "renew", "--new-ca", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "import the new CA") {
		t.Fatalf("renew: %d %q %q", code, out, errOut)
	}
	b, err := os.ReadFile(filepath.Join(dataDir, server.TLSRenewRequestFile))
	if err != nil || !strings.Contains(string(b), `"new_ca":true`) {
		t.Errorf("request %s %v", b, err)
	}
	// Nothing was renewed by the CLI itself.
	if m2 := tlscert.New(tlscert.Options{DataDir: dataDir}); m2.Status().CA.SHA256 != st.CA.SHA256 {
		t.Error("the CLI changed the CA")
	}
}

func TestTLSCommandWindowsRule(t *testing.T) {
	defer noService()
	fw := withFirewall(t, "windows")
	cfgPath, _ := testConfig(t, nil)
	code, out, errOut := runCLI("tls", "on", "--config", cfgPath)
	if code != 0 || !fw.enabled || !strings.Contains(out, "Enabled the Windows firewall rule") {
		t.Fatalf("on: %d %q %q %v", code, out, errOut, fw.calls)
	}
	if code, out, _ := runCLI("tls", "off", "--config", cfgPath); code != 0 || fw.enabled || !strings.Contains(out, "Disabled the Windows firewall rule") {
		t.Errorf("off: %d %q", code, out)
	}
}
