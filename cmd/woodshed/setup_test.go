package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/setuphelper"
)

func TestSetupSnippetCLI(t *testing.T) {
	dir := t.TempDir()
	c := config.Default()
	c.Storage.DataDir = filepath.Join(dir, "data")
	c.Listeners.TLS.Enabled = true
	c.Listeners.TLS.Port = 16514
	c.Listeners.SNMP.Enabled = true
	c.Listeners.SNMP.Port = 10162
	c.UI.ExtraHostnames = []string{"logs.example.net"}
	c.Listeners.Flow.Enabled = true
	c.Listeners.Flow.FlowPort, c.Listeners.Flow.IPFIXPort = 12055, 14739
	cfg := filepath.Join(dir, "woodshed.toml")
	if err := config.Save(cfg, c); err != nil {
		t.Fatal(err)
	}

	// The snippet on stdout, filled from the config; the notes on stderr.
	code, out, errOut := runCLI("setup", "snippet", "--config", cfg, "--family", "rsyslog", "--what", "syslog", "--transport", "tls",
		"--address", "logs.example.net", "--severity", "warning")
	if code != 0 || !strings.Contains(out, `target="logs.example.net" port="16514"`) || !strings.Contains(out, "*.warning") ||
		strings.Contains(out, "Tested") || !strings.Contains(errOut, "Tested: CI applies it") || !strings.Contains(errOut, "Fill in: <CA-FILE>") {
		t.Errorf("rsyslog tls: %d\n%s\n%s", code, out, errOut)
	}
	// --type is --what; the trap port comes from the config.
	code, out, errOut = runCLI("setup", "snippet", "--config", cfg, "--family", "line-cli", "--type", "trap", "--source-interface", "Vlan10")
	if code != 0 || !strings.Contains(out, "udp-port 10162") || !strings.Contains(out, "snmp-server trap-source Vlan10") ||
		!strings.Contains(errOut, setuphelper.ReferenceOnlyNote) {
		t.Errorf("line-cli trap: %d\n%s\n%s", code, out, errOut)
	}
	// The flow listener's ports from the config, per version.
	code, out, errOut = runCLI("setup", "snippet", "--config", cfg, "--family", "softflowd", "--what", "flow", "--transport", "ipfix",
		"--interface", "eth1", "--address", "192.0.2.10")
	if code != 0 || !strings.Contains(out, "softflowd -i eth1 -n 192.0.2.10:14739 -v 10") || strings.Contains(errOut, "listener is off") {
		t.Errorf("softflowd ipfix: %d\n%s\n%s", code, out, errOut)
	}
	// --json is the API's shape.
	code, out, _ = runCLI("setup", "snippet", "--config", cfg, "--family", "net-snmp", "--what", "poll", "--transport", "v3", "--json")
	var sn setuphelper.Snippet
	if err := json.Unmarshal([]byte(out), &sn); code != 0 || err != nil || sn.Verification != "tested" || !strings.Contains(sn.Text, "rouser <V3-USER> priv") {
		t.Errorf("json: %d %v %s", code, err, out)
	}
	// Usage errors are exit 2 and name the flag.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--family", "rsyslog"}, "--family and --what are required"},
		{[]string{"--family", "rsyslog", "--what", "syslog", "--type", "trap"}, "--type and --what"},
		{[]string{"--family", "rsyslog", "--what", "syslog", "--source-interface", "eth0"}, "--source-interface doesn't apply"},
		{[]string{"--family", "nope", "--what", "syslog"}, "--family \"nope\" isn't a setup family"},
		{[]string{"--family", "net-snmp", "--what", "poll", "--agent-port", "99999"}, "--agent-port must be"},
	} {
		code, _, errOut := runCLI(append([]string{"setup", "snippet", "--config", cfg}, c.args...)...)
		if code != 2 || !strings.Contains(errOut, c.want) {
			t.Errorf("%v: %d %q", c.args, code, errOut)
		}
	}
	// No config file: the defaults, said on stderr.
	code, out, errOut = runCLI("setup", "snippet", "--config", filepath.Join(dir, "missing.toml"), "--family", "web-ui", "--what", "syslog")
	if code != 0 || !strings.Contains(out, "Port: 514") || !strings.Contains(errOut, "using the default settings") {
		t.Errorf("no config: %d\n%s\n%s", code, out, errOut)
	}
	if code, out, _ := runCLI("setup", "families"); code != 0 || !strings.Contains(out, "Linux: softflowd") || !strings.Contains(out, "Reference only") {
		t.Errorf("families: %d %s", code, out)
	}
	if code, out, _ := runCLI("setup", "snippet", "--help"); code != 0 || !strings.HasPrefix(out, "usage: woodshed setup snippet") {
		t.Errorf("help: %d %s", code, out)
	}
	if code, _, errOut := runCLI("setup"); code != 2 || !strings.Contains(errOut, "usage: woodshed setup") {
		t.Errorf("no subcommand: %d %s", code, errOut)
	}
}
