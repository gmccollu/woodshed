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

// fakeWin is a Windows firewall holding at most our one rule. netsh changes it;
// list reads it as ListRules (the COM API) would. netsh's own `show rule`
// answers in German, as on a German Windows (the wording is illustrative), so
// nothing may depend on it.
type fakeWin struct {
	present, enabled bool
	port, program    string
	proto            int32
	calls            []string
	unreadable       bool // the firewall can't be read (its service stopped, say)
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
			return "\r\nKeine Regeln entsprechen den angegebenen Kriterien.\r\n", errors.New("exit status 1")
		}
		en := "Nein"
		if f.enabled {
			en = "Ja"
		}
		return "\r\nRegelname:                            " + RuleName + "\r\nAktiviert:                            " + en +
			"\r\nLokaler Port:                         " + f.port + "\r\nOK.\r\n", nil
	case "add":
		f.present, f.enabled, f.port, f.program = true, kv["enable"] == "yes", kv["localport"], kv["program"]
		f.proto = map[string]int32{"TCP": 6, "UDP": 17}[kv["protocol"]]
	case "set":
		if v, ok := kv["enable"]; ok {
			f.enabled = v == "yes"
		}
		if v, ok := kv["localport"]; ok {
			f.port = v
		}
		if v, ok := kv["program"]; ok {
			f.program = v
		}
	case "delete":
		f.present = false
	}
	return "OK.", nil
}

// rules is the rule as ListRules returns it, named name: INetFwRule's
// properties (the values netsh's add sets: dir=in is NET_FW_RULE_DIR_IN,
// action=allow NET_FW_ACTION_ALLOW, protocol=TCP 6).
func (f *fakeWin) rules(name string) []WinRule {
	if !f.present {
		return nil
	}
	return []WinRule{{Name: name, ApplicationName: f.program, Protocol: f.proto, LocalPorts: f.port,
		Direction: RuleDirIn, Enabled: f.enabled, Action: RuleActionAllow}}
}

func (f *fakeWin) list(names ...string) ([]WinRule, error) {
	if f.unreadable {
		return nil, errors.New("fwrule: INetFwPolicy2.Rules: HRESULT 0x800706D9")
	}
	if len(names) == 0 || slices.ContainsFunc(names, func(n string) bool { return strings.EqualFold(n, RuleName) }) {
		return f.rules(RuleName), nil
	}
	return nil, nil
}

// useRules points ListRules at a fake for the test.
func useRules(t *testing.T, list func(...string) ([]WinRule, error)) {
	t.Helper()
	old := ListRules
	ListRules = list
	t.Cleanup(func() { ListRules = old })
}

func TestWindowsRule(t *testing.T) {
	f := &fakeWin{}
	useRules(t, f.list)
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
	// Nothing reads netsh's output, which is in the display language (here
	// German: the old parser read every state as unknown and every missing
	// rule as an error, so the installers never created the rules).
	for _, c := range f.calls {
		if strings.Contains(c, " show ") {
			t.Errorf("ran %q", c)
		}
	}
	// A firewall that can't be read: unknown, and nothing is changed.
	f.unreadable = true
	if s := WindowsState(f.run, 6514); s != StateUnknown {
		t.Errorf("unreadable: %s", s)
	}
	f.calls = nil
	if _, err := WindowsEnsure(f.run, exe); err == nil || !strings.Contains(err.Error(), RuleName) {
		t.Errorf("ensure, unreadable: %v", err)
	}
	if err := WindowsEnable(f.run, exe, 6514); err == nil || len(f.calls) != 0 {
		t.Errorf("enable, unreadable: %v %v", err, f.calls)
	}
}

// The states from rules as the COM API gives them (INetFwRule's properties,
// https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule:
// LocalPorts is a comma-separated list, Enabled a VARIANT_BOOL). These
// records are what a German or French Windows returns too: no field is
// translated.
func TestWindowsStateFromRules(t *testing.T) {
	exe := `C:\Program Files\Woodshed\woodshed.exe`
	on := WinRule{Name: RuleName, ApplicationName: exe, Protocol: 6, LocalPorts: "6514", Direction: RuleDirIn, Enabled: true,
		Action: RuleActionAllow}
	off := on
	off.Enabled = false
	other := on
	other.LocalPorts = "7514"
	list := on
	list.LocalPorts = "514, 6514"
	prefix := on
	prefix.LocalPorts = "65140"
	for name, c := range map[string]struct {
		rules []WinRule
		err   error
		want  string
	}{
		"none":                  {nil, nil, StateMissing},
		"enabled":               {[]WinRule{on}, nil, StateOK},
		"disabled":              {[]WinRule{off}, nil, StateDisabled},
		"other port":            {[]WinRule{other}, nil, StateWrongPort},
		"a list with the port":  {[]WinRule{list}, nil, StateOK},
		"a longer port":         {[]WinRule{prefix}, nil, StateWrongPort},
		"two, one enabled here": {[]WinRule{off, other, on}, nil, StateOK},
		"two, both disabled":    {[]WinRule{off, off}, nil, StateDisabled},
		"unreadable":            {nil, errors.New("HRESULT 0x80070005"), StateUnknown},
	} {
		var asked []string
		useRules(t, func(names ...string) ([]WinRule, error) { asked = names; return c.rules, c.err })
		if got := WindowsState(nil, 6514); got != c.want {
			t.Errorf("%s: %s, want %s", name, got, c.want)
		}
		if !slices.Equal(asked, []string{RuleName}) {
			t.Errorf("%s: asked for %q", name, asked)
		}
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
