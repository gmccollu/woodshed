package fwrule

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFlowWindowsRules(t *testing.T) {
	f := &fakeWinRules{rules: map[string]*fakeWin{}}
	useRules(t, f.list)
	exe := `C:\Program Files\Woodshed\woodshed.exe`
	if st := FlowWindowsStates(f.run, 2055, 4739); !slices.Equal(st, []FlowRuleState{{FlowPortRuleName, StateMissing},
		{FlowIPFIXRuleName, StateMissing}}) {
		t.Errorf("no rules: %v", st)
	}
	created, err := FlowWindowsEnsure(f.run, exe)
	if err != nil || len(created) != 2 {
		t.Fatalf("ensure: %v %v", created, err)
	}
	nf, ix := f.rules[FlowPortRuleName], f.rules[FlowIPFIXRuleName]
	if !nf.present || nf.enabled || nf.port != "2055" || !ix.present || ix.enabled || ix.port != "4739" ||
		!strings.Contains(strings.Join(nf.calls, " "), "protocol=UDP") {
		t.Fatalf("after install: %+v %+v", nf, ix)
	}
	// Both disabled: both named (lab, 2.0.0-rc1: only the first was).
	if st := FlowWindowsStates(f.run, 2055, 4739); !slices.Equal(st, []FlowRuleState{{FlowPortRuleName, StateDisabled},
		{FlowIPFIXRuleName, StateDisabled}}) {
		t.Errorf("after install: %v", st)
	}
	// on with IPFIX off: the flow port enabled on its port, IPFIX disabled and not checked.
	if err := FlowWindowsEnable(f.run, exe, 12055, 0); err != nil || !nf.enabled || nf.port != "12055" || ix.enabled {
		t.Fatalf("enable: %v %+v %+v", err, nf, ix)
	}
	if st := FlowWindowsStates(f.run, 12055, 0); len(st) != 0 {
		t.Errorf("on: %v", st)
	}
	if st := FlowWindowsStates(f.run, 12055, 4739); !slices.Equal(st, []FlowRuleState{{FlowIPFIXRuleName, StateDisabled}}) {
		t.Errorf("ipfix off: %v", st)
	}
	if st := FlowWindowsStates(f.run, 2055, 0); !slices.Equal(st, []FlowRuleState{{FlowPortRuleName, StateWrongPort}}) {
		t.Errorf("wrong port: %v", st)
	}
	if created, err := FlowWindowsEnsure(f.run, exe); err != nil || len(created) != 0 || !nf.enabled {
		t.Errorf("re-ensure changed the rules: %v %v", created, err)
	}
	if err := FlowWindowsDisable(f.run); err != nil || nf.enabled || !nf.present {
		t.Errorf("disable: %v %+v", err, nf)
	}
	if err := FlowWindowsRemove(f.run); err != nil || nf.present || ix.present {
		t.Errorf("remove: %v", err)
	}
	if f.rules[RuleName] != nil && f.rules[RuleName].present || f.rules[SNMPRuleName] != nil && f.rules[SNMPRuleName].present {
		t.Error("flow rules touched another rule")
	}
}

func TestFlowLinuxUfw(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{ufw: true, ufwRules: map[string]bool{"22/tcp": true, "162/udp": true}}
	msg, err := FlowLinuxOpen(f.run, dir, 2055, 4739)
	if err != nil || !f.ufwRules["2055/udp"] || !f.ufwRules["4739/udp"] || !strings.Contains(msg, "4739/udp") {
		t.Fatalf("open: %q %v %v", msg, err, f.ufwRules)
	}
	for _, rf := range []string{FlowPortRecordFile, FlowIPFIXRecordFile} {
		if _, err := os.Stat(filepath.Join(dir, rf)); err != nil {
			t.Errorf("record %s: %v", rf, err)
		}
	}
	// Turning IPFIX's port off closes only what flow on opened for it.
	if _, err := FlowLinuxOpen(f.run, dir, 2055, 0); err != nil || f.ufwRules["4739/udp"] || !f.ufwRules["2055/udp"] {
		t.Fatalf("ipfix off: %v %v", err, f.ufwRules)
	}
	if _, err := FlowLinuxClose(f.run, dir); err != nil {
		t.Fatal(err)
	}
	if len(f.ufwRules) != 2 || !f.ufwRules["22/tcp"] || !f.ufwRules["162/udp"] {
		t.Fatalf("close: %v", f.ufwRules)
	}
	if !strings.Contains(FlowLinuxCommands(2055, 0), "2055/udp") || strings.Contains(FlowLinuxCommands(2055, 0), "4739") {
		t.Error(FlowLinuxCommands(2055, 0))
	}
}

func TestFlowLinuxFirewalld(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{firewalld: true, fwdPorts: map[string]bool{}}
	if _, err := FlowLinuxOpen(f.run, dir, 2055, 4739); err != nil || !f.fwdPorts["2055/udp"] || !f.fwdPorts["4739/udp"] {
		t.Fatalf("open: %v %v", err, f.fwdPorts)
	}
	if _, err := FlowLinuxClose(f.run, dir); err != nil || len(f.fwdPorts) != 0 {
		t.Fatalf("close: %v %v", err, f.fwdPorts)
	}
}

// FlowLinuxState: what `flow on` recorded, else what the firewall allows now,
// else nothing (lab, 2.0.0-rc1: flow status said to open the ports after
// flow on had).
func TestFlowLinuxState(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{ufw: true, ufwRules: map[string]bool{"22/tcp": true}}
	if st := FlowLinuxState(f.run, dir, 2055, 4739); !slices.Equal(st, []FlowLinuxPort{{Port: 2055}, {Port: 4739}}) {
		t.Errorf("nothing open: %+v", st)
	}
	f.ufwRules["4739/udp"] = true // allowed before flow on: not recorded, left alone
	if _, err := FlowLinuxOpen(f.run, dir, 2055, 4739); err != nil {
		t.Fatal(err)
	}
	if st := FlowLinuxState(f.run, dir, 2055, 4739); !slices.Equal(st, []FlowLinuxPort{{Port: 2055, Opened: "ufw"}, {Port: 4739, Allowed: "ufw"}}) {
		t.Errorf("after on: %+v", st)
	}
	if st := FlowLinuxState(f.run, dir, 2055, 0); !slices.Equal(st, []FlowLinuxPort{{Port: 2055, Opened: "ufw"}}) {
		t.Errorf("ipfix off: %+v", st)
	}
	// A bare port rule ("ufw allow 12055") covers UDP too; another port doesn't.
	f.ufwRules["12055"] = true
	if st := FlowLinuxState(f.run, dir, 12055, 14739); !slices.Equal(st, []FlowLinuxPort{{Port: 12055, Allowed: "ufw"}, {Port: 14739}}) {
		t.Errorf("other ports: %+v", st)
	}
	// ufw it can't read (not root): unknown, so nothing is claimed.
	f.ufw = false
	if st := FlowLinuxState(f.run, t.TempDir(), 2055, 0); !slices.Equal(st, []FlowLinuxPort{{Port: 2055}}) {
		t.Errorf("ufw inactive: %+v", st)
	}

	dir = t.TempDir()
	g := &fakeLinux{firewalld: true, fwdPorts: map[string]bool{"4739/udp": true}}
	if _, err := FlowLinuxOpen(g.run, dir, 2055, 4739); err != nil {
		t.Fatal(err)
	}
	if st := FlowLinuxState(g.run, dir, 2055, 4739); !slices.Equal(st, []FlowLinuxPort{{Port: 2055, Opened: "firewalld"}, {Port: 4739, Allowed: "firewalld"}}) {
		t.Errorf("firewalld: %+v", st)
	}
	if _, err := FlowLinuxClose(g.run, dir); err != nil {
		t.Fatal(err)
	}
	if st := FlowLinuxState(g.run, dir, 2055, 4739); !slices.Equal(st, []FlowLinuxPort{{Port: 2055}, {Port: 4739, Allowed: "firewalld"}}) {
		t.Errorf("firewalld after off: %+v", st)
	}
	// It only reads.
	n := len(g.calls)
	FlowLinuxState(g.run, dir, 2055, 4739)
	for _, c := range g.calls[n:] {
		if c != "ufw status" && c != "firewall-cmd --state" && !strings.HasPrefix(c, "firewall-cmd --permanent --query-port=") {
			t.Errorf("state ran %q", c)
		}
	}
}
