package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/server"
)

func TestChooseDataDir(t *testing.T) {
	tmp := t.TempDir()
	exe := filepath.Join(tmp, "dl", "woodshed")
	home := filepath.Join(tmp, "home")
	readonly := map[string]bool{}
	env := dirEnv{
		exe:  func() (string, error) { return exe, nil },
		home: func() (string, error) { return home, nil },
		writable: func(d string) error {
			if readonly[d] {
				return &os.PathError{Op: "open", Path: d, Err: os.ErrPermission}
			}
			return nil
		},
	}
	// Next to the binary.
	if dir, note, err := chooseDataDir("", env); err != nil || dir != filepath.Join(tmp, "dl", "woodshed-data") || note != "" {
		t.Errorf("default = %q %q %v", dir, note, err)
	}
	// Not writable there (read-only media, Program Files): ~/Woodshed, with a note.
	readonly[filepath.Join(tmp, "dl", "woodshed-data")] = true
	dir, note, err := chooseDataDir("", env)
	if err != nil || dir != filepath.Join(home, "Woodshed") || !strings.Contains(note, "can't be written") {
		t.Errorf("fallback = %q %q %v", dir, note, err)
	}
	// macOS App Translocation: straight to the fallback.
	exe = "/private/var/folders/x/AppTranslocation/ABC/d/woodshed"
	if dir, note, _ := chooseDataDir("", env); dir != filepath.Join(home, "Woodshed") || !strings.Contains(note, "read-only") {
		t.Errorf("translocated = %q %q", dir, note)
	}
	// Neither writable: a clear error.
	readonly[filepath.Join(home, "Woodshed")] = true
	exe = filepath.Join(tmp, "dl", "woodshed")
	if _, _, err := chooseDataDir("", env); err == nil || !strings.Contains(err.Error(), "can't be written either") {
		t.Errorf("both read-only: %v", err)
	}
	// --dir: used as given, no fallback.
	if dir, _, err := chooseDataDir(filepath.Join(tmp, "case-42"), env); err != nil || dir != filepath.Join(tmp, "case-42") {
		t.Errorf("--dir = %q %v", dir, err)
	}
	readonly[filepath.Join(tmp, "ro")] = true
	if _, _, err := chooseDataDir(filepath.Join(tmp, "ro"), env); err == nil {
		t.Error("read-only --dir accepted")
	}
	env.exe = func() (string, error) { return "", errors.New("no /proc") }
	delete(readonly, filepath.Join(home, "Woodshed"))
	if dir, _, err := chooseDataDir("", env); err != nil || dir != filepath.Join(home, "Woodshed") {
		t.Errorf("unknown exe: %q %v", dir, err)
	}
}

func TestPickUIPort(t *testing.T) {
	taken := map[int]bool{8514: true, 8515: true}
	free := func(p int) bool { return !taken[p] }
	if p, fb, err := pickUIPort(8514, free); err != nil || p != 8516 || !fb {
		t.Errorf("= %d %v %v, want 8516 after 8514/8515", p, fb, err)
	}
	if p, fb, _ := pickUIPort(9000, free); p != 9000 || fb {
		t.Errorf("free port: %d %v", p, fb)
	}
	for p := 8514; p <= 8530; p++ {
		taken[p] = true
	}
	if _, _, err := pickUIPort(8514, free); err == nil {
		t.Error("all 17 taken: no error")
	}
	taken[8530] = false
	if p, _, _ := pickUIPort(8514, free); p != 8530 {
		t.Errorf("last in range: %d", p)
	}
}

func TestClassifyLaunch(t *testing.T) {
	count := func(n int) func() int { return func() int { return n } }
	tty := func(b bool) func() bool { return func() bool { return b } }
	for _, c := range []struct {
		p    launchProbe
		want launch
	}{
		{launchProbe{goos: "windows", consoleProcesses: count(1)}, launchDoubleClick}, // Explorer gave us a new console
		{launchProbe{goos: "windows", consoleProcesses: count(2)}, launchTerminal},    // cmd.exe or PowerShell shares it
		{launchProbe{goos: "windows", consoleProcesses: count(0)}, launchTerminal},    // unknown: assume a terminal
		{launchProbe{goos: "linux", stdinTerminal: tty(false)}, launchDoubleClick},    // a file manager, no terminal
		{launchProbe{goos: "linux", stdinTerminal: tty(true)}, launchTerminal},
		{launchProbe{goos: "darwin", stdinTerminal: tty(true)}, launchTerminal}, // Finder opens Terminal: looks the same
	} {
		if got := classifyLaunch(c.p); got != c.want {
			t.Errorf("%+v: %v, want %v", c.p.goos, got, c.want)
		}
	}
}

func TestBannerText(t *testing.T) {
	ok := []api.Listener{{Proto: "udp", Addr: "0.0.0.0", Port: 514, OK: true}, {Proto: "tcp", Addr: "0.0.0.0", Port: 514, OK: true}}
	b := bannerText(bannerInfo{Version: "1.0.0", DataDir: "/x/woodshed-data", URL: "http://localhost:8514/",
		Listeners: ok, HostIPs: []string{"192.0.2.10", "2001:db8::10"}, GOOS: "linux"})
	for _, want := range []string{"Woodshed 1.0.0, portable mode", "Data folder:  /x/woodshed-data", "Listening on UDP 514 and TCP 514\n",
		"Send logs to: 192.0.2.10, 2001:db8::10", "Web UI:       http://localhost:8514/"} {
		if !strings.Contains(b, want) {
			t.Errorf("banner lacks %q:\n%s", want, b)
		}
	}

	// Linux without root: the fix.
	denied := []api.Listener{
		{Proto: "udp", Addr: "0.0.0.0", Port: 514, Error: "listen udp 0.0.0.0:514: bind: permission denied"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 514, Error: "listen tcp 0.0.0.0:514: bind: permission denied"},
	}
	b = bannerText(bannerInfo{URL: "http://localhost:8515/", UIFellBackFrom: 8514, Listeners: denied, GOOS: "linux"})
	if strings.Count(b, "setcap") != 1 || !strings.Contains(b, "UDP and TCP 514 need extra rights") ||
		strings.Index(b, "setcap") > strings.Index(b, "sudo ./woodshed") {
		t.Errorf("one combined hint, setcap first:\n%s", b)
	}
	for _, want := range []string{"NOT listening on UDP 514", "sudo ./woodshed", "sudo setcap cap_net_bind_service=+ep ./woodshed",
		"port 8514 is in use, maybe by an installed Woodshed, so this copy uses 8515"} {
		if !strings.Contains(b, want) {
			t.Errorf("denied banner lacks %q:\n%s", want, b)
		}
	}

	// In use by the OS's syslog daemon, or by an installed Woodshed.
	inUse := []api.Listener{{Proto: "udp", Addr: "0.0.0.0", Port: 514, Error: "bind: address already in use", Holder: "rsyslogd (pid 812)"},
		{Proto: "tcp", Addr: "0.0.0.0", Port: 514, OK: true}}
	b = bannerText(bannerInfo{Listeners: inUse, GOOS: "linux"})
	if !strings.Contains(b, "UDP 514: in use by rsyslogd (pid 812)") || !strings.Contains(b, "system's own syslog service") ||
		!strings.Contains(b, "Listening on TCP 514") || strings.Contains(b, "setcap") {
		t.Errorf("in-use banner:\n%s", b)
	}
	inUse[0].Holder = "woodshed.exe (pid 4)"
	if b := bannerText(bannerInfo{Listeners: inUse, GOOS: "windows"}); !strings.Contains(b, "installed Woodshed service") {
		t.Errorf("held by Woodshed:\n%s", b)
	}

	// Bound to one address: that's what devices must use.
	one := []api.Listener{{Proto: "udp", Addr: "127.0.0.1", Port: 15514, OK: true}, {Proto: "tcp", Addr: "127.0.0.1", Port: 15514, OK: true}}
	b = bannerText(bannerInfo{Listeners: one, HostIPs: []string{"192.0.2.10"}})
	if !strings.Contains(b, "Listening on UDP 15514 and TCP 15514 on 127.0.0.1") || !strings.Contains(b, "Send logs to: 127.0.0.1\n") {
		t.Errorf("single-address banner:\n%s", b)
	}
	// The fallback note when the data folder isn't next to the binary.
	if b := bannerText(bannerInfo{DirNote: "Using /h/Woodshed because x."}); !strings.Contains(b, "(Using /h/Woodshed because x.)") {
		t.Errorf("dir note:\n%s", b)
	}
}

func TestNewDeviceLine(t *testing.T) {
	if got := newDeviceLine(api.Device{IP: "10.1.2.3"}); !strings.HasPrefix(got, "New device 10.1.2.3 (first message ") {
		t.Errorf("%q", got)
	}
	if got := newDeviceLine(api.Device{IP: "10.1.2.3", Name: "edge-fw"}); !strings.HasPrefix(got, "New device edge-fw (10.1.2.3)") {
		t.Errorf("%q", got)
	}
}

func TestBrowserCommand(t *testing.T) {
	for goos, want := range map[string]string{"windows": "rundll32 url.dll,FileProtocolHandler U", "darwin": "open U", "linux": "xdg-open U"} {
		n, a := browserCommand(goos, "U")
		if got := strings.Join(append([]string{n}, a...), " "); got != want {
			t.Errorf("%s: %q", goos, got)
		}
	}
}

func TestPortableRefusesASecondCopy(t *testing.T) {
	dir := t.TempDir()
	lock, err := lockForTest(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock()
	code, _, errOut := runCLI("portable", "--dir", dir, "--port", "15599", "--listen", "127.0.0.1", "--ui-port", "18599", "--no-browser")
	if code != 1 || !strings.Contains(errOut, "already running on "+dir) || !strings.Contains(errOut, "--dir <folder>") {
		t.Errorf("%d %q", code, errOut)
	}
}

func lockForTest(dir string) (func(), error) {
	l, err := server.LockDataDir(dir)
	if err != nil {
		return nil, err
	}
	return func() { l.Unlock() }, nil
}

func TestFirewallRuleState(t *testing.T) {
	exe := `C:\Users\me\Downloads\woodshed.exe`
	// Rules as fwrule.ListRules gives them (INetFwRule's properties).
	rule := func(name string, enabled bool, action int32, program string) fwrule.WinRule {
		return fwrule.WinRule{Name: name, ApplicationName: program, Protocol: 17, LocalPorts: "514", Direction: fwrule.RuleDirIn,
			Enabled: enabled, Action: action}
	}
	const allow, block = fwrule.RuleActionAllow, 0
	other := rule("Core Networking", true, allow, `C:\Windows\system32\svchost.exe`)
	out := rule("woodshed.exe", true, allow, exe)
	out.Direction = 2 // outbound: doesn't let devices in
	for name, c := range map[string]struct {
		rules []fwrule.WinRule
		want  ruleState
	}{
		"none":            {[]fwrule.WinRule{other}, ruleUnknown},
		"allowed":         {[]fwrule.WinRule{other, rule("woodshed.exe", true, allow, exe)}, ruleAllows},
		"blocked":         {[]fwrule.WinRule{other, rule("woodshed.exe", true, block, exe)}, ruleBlocks},
		"disabled allow":  {[]fwrule.WinRule{rule("woodshed.exe", false, allow, exe)}, ruleBlocks},
		"block and allow": {[]fwrule.WinRule{rule("woodshed.exe", true, block, exe), rule("Woodshed (portable)", true, allow, strings.ToUpper(exe))}, ruleAllows},
		"outbound only":   {[]fwrule.WinRule{out}, ruleUnknown},
	} {
		if got := firewallRuleState(c.rules, exe); got != c.want {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
}

// Re-test N17: the suggested rules open only the syslog port, UDP and TCP, on
// Private and Domain networks.
func TestFirewallCommands(t *testing.T) {
	c := firewallCommands(`C:\w\woodshed.exe`, 514)
	for _, want := range []string{
		`program="C:\w\woodshed.exe" protocol=UDP localport=514 profile=private,domain`,
		`program="C:\w\woodshed.exe" protocol=TCP localport=514 profile=private,domain`,
		"Public",
	} {
		if !strings.Contains(c, want) {
			t.Errorf("lacks %q:\n%s", want, c)
		}
	}
	if strings.Count(c, "netsh") != 2 {
		t.Errorf("want two rules:\n%s", c)
	}
}
