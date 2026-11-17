package fwrule

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeWin is a Windows firewall holding at most our one rule.
type fakeWin struct {
	present, enabled bool
	port, program    string
	calls            []string
	unreadable       bool // another language
}

func (f *fakeWin) run(name string, args ...string) (string, error) {
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
	switch args[2] {
	case "show":
		if !f.present {
			return "\r\nNo rules match the specified criteria.\r\n", errors.New("exit status 1")
		}
		if f.unreadable {
			return "Nom de la règle: " + RuleName + "\r\nActivé: Oui\r\n", nil
		}
		en := "No"
		if f.enabled {
			en = "Yes"
		}
		return "\r\nRule Name:                            " + RuleName + "\r\n" +
			"----------------------------------------------------------------------\r\n" +
			"Enabled:                              " + en + "\r\nDirection:                            In\r\n" +
			"Profiles:                             Domain,Private,Public\r\nLocalPort:                            " + f.port + "\r\n" +
			"Program:                              " + f.program + "\r\nAction:                               Allow\r\nOk.\r\n", nil
	case "add":
		f.present, f.enabled, f.port, f.program = true, kv["enable"] == "yes", kv["localport"], kv["program"]
	case "set":
		if v, ok := kv["enable"]; ok {
			f.enabled = v == "yes"
		}
		if v, ok := kv["localport"]; ok {
			f.port = v
		}
	case "delete":
		f.present = false
	}
	return "Ok.", nil
}

func TestWindowsRule(t *testing.T) {
	f := &fakeWin{}
	exe := `C:\Program Files\Woodshed\woodshed.exe`
	if s := WindowsState(f.run, 6514); s != StateMissing {
		t.Errorf("no rule: %s", s)
	}
	// Install: created disabled on 6514.
	if created, err := WindowsEnsure(f.run, exe); err != nil || !created || !f.present || f.enabled || f.port != "6514" || f.program != exe {
		t.Fatalf("ensure: %v %v %+v", created, err, f)
	}
	if s := WindowsState(f.run, 6514); s != StateDisabled {
		t.Errorf("after install: %s", s)
	}
	// tls on with another port.
	if err := WindowsEnable(f.run, exe, 7514); err != nil || !f.enabled || f.port != "7514" {
		t.Fatalf("enable: %v %+v", err, f)
	}
	if s := WindowsState(f.run, 7514); s != StateOK {
		t.Errorf("on: %s", s)
	}
	if s := WindowsState(f.run, 6514); s != StateWrongPort {
		t.Errorf("other port: %s", s)
	}
	// A reinstall (or an upgrade) leaves an existing rule as it is.
	f.calls = nil
	if created, err := WindowsEnsure(f.run, exe); err != nil || created || !f.enabled {
		t.Errorf("re-ensure changed the rule: %v %v %+v", created, err, f)
	}
	for _, c := range f.calls {
		if !strings.Contains(c, "show") {
			t.Errorf("re-ensure ran %q", c)
		}
	}
	if err := WindowsDisable(f.run); err != nil || f.enabled || !f.present {
		t.Errorf("disable: %v %+v", err, f)
	}
	if err := WindowsRemove(f.run); err != nil || f.present {
		t.Errorf("remove: %v %+v", err, f)
	}
	if err := WindowsDisable(f.run); err != nil {
		t.Errorf("disable without a rule: %v", err)
	}
	// tls on with no rule (portable, or an older install) creates it enabled.
	if err := WindowsEnable(f.run, exe, 6514); err != nil || !f.enabled {
		t.Errorf("enable without a rule: %v %+v", err, f)
	}
	f.unreadable = true
	if s := WindowsState(f.run, 6514); s != StateUnknown {
		t.Errorf("unreadable: %s", s)
	}
}

// fakeLinux is a host with ufw and/or firewalld.
type fakeLinux struct {
	ufw, firewalld bool
	ufwRules       map[string]bool
	fwdPorts       map[string]bool
	calls          []string
}

func (f *fakeLinux) run(name string, args ...string) (string, error) {
	name = filepath.Base(name) // the code runs /usr/sbin/ufw etc. when it exists
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "ufw":
		if f.ufwRules == nil {
			return "", errors.New("exec: \"ufw\": executable file not found in $PATH")
		}
		switch {
		case args[0] == "status":
			if f.ufw {
				out := "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"
				for _, r := range slices.Sorted(maps.Keys(f.ufwRules)) {
					out += fmt.Sprintf("%-26s ALLOW       Anywhere\n%-26s ALLOW       Anywhere (v6)\n", r, r+" (v6)")
				}
				return out, nil
			}
			return "Status: inactive", nil
		case args[0] == "allow":
			if f.ufwRules[args[1]] {
				return "Skipping adding existing rule\nSkipping adding existing rule (v6)", nil
			}
			f.ufwRules[args[1]] = true
			return "Rule added\nRule added (v6)", nil
		case args[0] == "delete":
			delete(f.ufwRules, args[2])
			return "Rule deleted", nil
		}
	case "firewall-cmd":
		if f.fwdPorts == nil {
			return "", errors.New("exec: \"firewall-cmd\": executable file not found in $PATH")
		}
		switch {
		case args[0] == "--state":
			if f.firewalld {
				return "running", nil
			}
			return "not running", errors.New("exit status 252")
		case args[0] == "--reload":
			return "success", nil
		case strings.HasPrefix(args[1], "--query-port="):
			if f.fwdPorts[strings.TrimPrefix(args[1], "--query-port=")] {
				return "yes", nil
			}
			return "no", errors.New("exit status 1")
		case strings.HasPrefix(args[1], "--add-port="):
			f.fwdPorts[strings.TrimPrefix(args[1], "--add-port=")] = true
			return "success", nil
		case strings.HasPrefix(args[1], "--remove-port="):
			delete(f.fwdPorts, strings.TrimPrefix(args[1], "--remove-port="))
			return "success", nil
		}
	}
	return "", errors.New("unexpected " + name)
}

func TestLinuxUfwOnOffLeavesRulesAsTheyWere(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{ufw: true, ufwRules: map[string]bool{"22/tcp": true}}
	msg, err := LinuxOpen(f.run, dir, 6514)
	if err != nil || !strings.Contains(msg, "ufw") || !f.ufwRules["6514/tcp"] {
		t.Fatalf("open: %q %v %v", msg, err, f.ufwRules)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, RecordFile)); !strings.Contains(string(b), "6514/tcp") {
		t.Errorf("record %s", b)
	}
	msg, err = LinuxClose(f.run, dir)
	if err != nil || f.ufwRules["6514/tcp"] || !f.ufwRules["22/tcp"] || len(f.ufwRules) != 1 {
		t.Fatalf("close: %q %v %v", msg, err, f.ufwRules)
	}
	if _, err := os.Stat(filepath.Join(dir, RecordFile)); !os.IsNotExist(err) {
		t.Error("record left behind")
	}
	// A rule the user already had is never recorded, so off leaves it.
	f.ufwRules["6514/tcp"] = true
	msg, _ = LinuxOpen(f.run, dir, 6514)
	if !strings.Contains(msg, "already") {
		t.Errorf("already open: %q", msg)
	}
	LinuxClose(f.run, dir)
	if !f.ufwRules["6514/tcp"] {
		t.Error("off removed the user's own rule")
	}
}

func TestLinuxFirewalld(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{firewalld: true, fwdPorts: map[string]bool{}, ufwRules: map[string]bool{}} // ufw installed but inactive
	if _, err := LinuxOpen(f.run, dir, 7514); err != nil || !f.fwdPorts["7514/tcp"] {
		t.Fatalf("open: %v %v", err, f.fwdPorts)
	}
	reloads := 0
	for _, c := range f.calls {
		if c == "firewall-cmd --reload" {
			reloads++
		}
	}
	if reloads != 1 {
		t.Errorf("reloads %d (%v)", reloads, f.calls)
	}
	if _, err := LinuxClose(f.run, dir); err != nil || len(f.fwdPorts) != 0 {
		t.Fatalf("close: %v %v", err, f.fwdPorts)
	}
}

func TestLinuxNoFirewall(t *testing.T) {
	dir := t.TempDir()
	f := &fakeLinux{} // neither installed
	msg, err := LinuxOpen(f.run, dir, 6514)
	if err != nil || !strings.Contains(msg, "sudo ufw allow 6514/tcp") || !strings.Contains(msg, "--add-port=6514/tcp") {
		t.Errorf("open: %q %v", msg, err)
	}
	if _, err := os.Stat(filepath.Join(dir, RecordFile)); !os.IsNotExist(err) {
		t.Error("recorded something with no firewall")
	}
	msg, err = LinuxClose(f.run, dir)
	if err != nil || !strings.Contains(msg, "didn't open") {
		t.Errorf("close: %q %v", msg, err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, "allow") || strings.Contains(c, "add-port") {
			t.Errorf("changed a firewall: %s", c)
		}
	}
}
