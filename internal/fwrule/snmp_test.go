package fwrule

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeWinRules is a Windows firewall holding any number of named rules, so
// the TLS and SNMP rules are seen to stay apart.
type fakeWinRules struct {
	rules map[string]*fakeWin
	calls []string
}

func (f *fakeWinRules) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	if !strings.HasSuffix(name, "netsh.exe") {
		return "", errors.New("unexpected program " + name)
	}
	kv := map[string]string{}
	for _, a := range args {
		if k, v, ok := strings.Cut(a, "="); ok {
			kv[k] = v
		}
	}
	r := f.rules[kv["name"]]
	if r == nil {
		r = &fakeWin{}
		f.rules[kv["name"]] = r
	}
	if args[2] == "add" {
		if kv["protocol"] == "" {
			return "", errors.New("no protocol")
		}
		r.calls = append(r.calls, "protocol="+kv["protocol"])
	}
	return r.run(name, args...)
}

// list is ListRules over every rule present.
func (f *fakeWinRules) list(names ...string) ([]WinRule, error) {
	var out []WinRule
	for name, r := range f.rules {
		if len(names) == 0 || slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, name) }) {
			out = append(out, r.rules(name)...)
		}
	}
	return out, nil
}

func TestSNMPWindowsRule(t *testing.T) {
	f := &fakeWinRules{rules: map[string]*fakeWin{}}
	useRules(t, f.list)
	exe := `C:\Program Files\Woodshed\woodshed.exe`
	if s := SNMPWindowsState(f.run, 162); s != StateMissing {
		t.Errorf("no rule: %s", s)
	}
	// Install: created disabled on UDP 162, the TLS rule untouched.
	if created, err := SNMPWindowsEnsure(f.run, exe); err != nil || !created {
		t.Fatalf("ensure: %v %v", created, err)
	}
	r := f.rules[SNMPRuleName]
	if !r.present || r.enabled || r.port != "162" || r.program != exe {
		t.Fatalf("rule after install: %+v", r)
	}
	if !strings.Contains(strings.Join(r.calls, " "), "protocol=UDP") {
		t.Errorf("not UDP: %v", r.calls)
	}
	if tls := f.rules[RuleName]; tls != nil && tls.present {
		t.Errorf("SNMP ensure created the TLS rule")
	}
	if s := SNMPWindowsState(f.run, 162); s != StateDisabled {
		t.Errorf("after install: %s", s)
	}
	// TLS ensure makes its own rule, TCP; the two are independent.
	if _, err := WindowsEnsure(f.run, exe); err != nil {
		t.Fatal(err)
	}
	if err := SNMPWindowsEnable(f.run, exe, 25162); err != nil || !r.enabled || r.port != "25162" {
		t.Fatalf("enable: %v %+v", err, r)
	}
	if f.rules[RuleName].enabled {
		t.Error("snmp on enabled the TLS rule")
	}
	if s := SNMPWindowsState(f.run, 25162); s != StateOK {
		t.Errorf("on: %s", s)
	}
	if s := SNMPWindowsState(f.run, 162); s != StateWrongPort {
		t.Errorf("other port: %s", s)
	}
	// An upgrade (ensure again) keeps the state.
	if created, err := SNMPWindowsEnsure(f.run, exe); err != nil || created || !r.enabled {
		t.Errorf("re-ensure changed the rule: %v %v %+v", created, err, r)
	}
	if err := SNMPWindowsDisable(f.run); err != nil || r.enabled || !r.present {
		t.Errorf("disable: %v %+v", err, r)
	}
	if err := SNMPWindowsRemove(f.run); err != nil || r.present {
		t.Errorf("remove: %v %+v", err, r)
	}
	if !f.rules[RuleName].present {
		t.Error("SNMP remove deleted the TLS rule")
	}
	if err := SNMPWindowsRemove(f.run); err != nil {
		t.Errorf("remove twice: %v", err)
	}
}

func TestSNMPLinuxUfwOnOffLeavesRulesAsTheyWere(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{ufw: true, ufwRules: map[string]bool{"22/tcp": true, "6514/tcp": true}}
	msg, err := SNMPLinuxOpen(f.run, dir, 162)
	if err != nil || !strings.Contains(msg, "162/udp") || !f.ufwRules["162/udp"] {
		t.Fatalf("open: %q %v %v", msg, err, f.ufwRules)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, SNMPRecordFile)); !strings.Contains(string(b), "162/udp") {
		t.Errorf("record %s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, RecordFile)); !os.IsNotExist(err) {
		t.Error("SNMP wrote the TLS record")
	}
	// The TLS record and rules are left alone.
	if _, err := SNMPLinuxClose(f.run, dir); err != nil {
		t.Fatal(err)
	}
	if len(f.ufwRules) != 2 || !f.ufwRules["22/tcp"] || !f.ufwRules["6514/tcp"] {
		t.Fatalf("close: %v", f.ufwRules)
	}
	if _, err := os.Stat(filepath.Join(dir, SNMPRecordFile)); !os.IsNotExist(err) {
		t.Error("record left behind")
	}
}

func TestSNMPLinuxFirewalldAndNone(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{firewalld: true, fwdPorts: map[string]bool{}}
	if _, err := SNMPLinuxOpen(f.run, dir, 162); err != nil || !f.fwdPorts["162/udp"] {
		t.Fatalf("open: %v %v", err, f.fwdPorts)
	}
	if _, err := SNMPLinuxClose(f.run, dir); err != nil || len(f.fwdPorts) != 0 {
		t.Fatalf("close: %v %v", err, f.fwdPorts)
	}
	n := &fakeLinux{}
	msg, err := SNMPLinuxOpen(n.run, dir, 162)
	if err != nil || !strings.Contains(msg, "sudo ufw allow 162/udp") || !strings.Contains(msg, "inbound UDP port 162") {
		t.Errorf("no firewall: %q %v", msg, err)
	}
	if !strings.Contains(SNMPLinuxCommands(10162), "--add-port=10162/udp") {
		t.Error(SNMPLinuxCommands(10162))
	}
}
