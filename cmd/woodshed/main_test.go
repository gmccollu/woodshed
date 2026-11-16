package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/peer"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/service"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// TestMain keeps every test away from the real service manager: on a machine
// with Woodshed installed, reset-password would otherwise restart (or fail to
// restart) the real service, and status would report it.
func TestMain(m *testing.M) {
	noService()
	os.Exit(m.Run())
}

var errNoServiceManager = errors.New("test: no service manager")

// noService puts the service hooks back to "not installed" fakes.
func noService() {
	serviceStatus = func() (service.State, error) { return service.StateNotInstalled, nil }
	serviceRestart = func() error { return errNoServiceManager }
	serviceInstall = func(service.InstallOptions) (service.Result, error) { return service.Result{}, errNoServiceManager }
	serviceUninstall = func(service.UninstallOptions) (service.Result, error) { return service.Result{}, errNoServiceManager }
	serviceLegacy = func() (service.Legacy, error) { return service.Legacy{}, nil }
	findPeer = func(context.Context, peer.Options) (peer.Info, bool) { return peer.Info{}, false }
	// No terminal and no run-state waits either.
	stdin = strings.NewReader("")
	readSecret = func(string, io.Writer) (string, error) { return "", errors.New("test: no terminal") }
	waitForRestart = func(string, server.RunState, time.Duration) (server.RunState, bool) { return server.RunState{}, false }
}

func runCLI(args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = realMain(args, &o, &e)
	return code, o.String(), e.String()
}

// udpTrap listens on a UDP and a TCP port and counts what arrives.
type udpTrap struct {
	port int
	got  chan string
}

func newTrap(t *testing.T) *udpTrap {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := pc.LocalAddr().(*net.UDPAddr).Port
	tl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		pc.Close()
		t.Skipf("TCP port %d not free: %v", port, err)
	}
	tr := &udpTrap{port: port, got: make(chan string, 100)}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			tr.got <- string(buf[:n])
		}
	}()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			tr.got <- "tcp connection"
			c.Close()
		}
	}()
	t.Cleanup(func() { pc.Close(); tl.Close() })
	return tr
}

func (tr *udpTrap) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-tr.got:
		t.Fatalf("something was sent: %q", m)
	case <-time.After(d):
	}
}

func TestHelpNeverRunsTheCommand(t *testing.T) {
	tr := newTrap(t)
	port := fmt.Sprint(tr.port)
	for _, args := range [][]string{
		{"send", "--help"},
		{"send", "-h"},
		{"send", "--port", port, "--help"},
		{"send", "--port", port, "--count", "5", "--help"},
		{"send", "--port", port, "--proto", "tcp", "-h"},
		{"send", "--port", port, "--message", "--help"},
		{"send", "help"},
		{"help", "send"},
		{"bench", "--help"},
		{"bench", "--duration", "1h", "-h"},
		{"run", "--help"},
		{"install", "--help"},
		{"uninstall", "--help"},
		{"status", "--help"},
		{"reindex", "--help"},
		{"reset-password", "--help"},
		{"update-check", "--help"},
		{"update-check", "on", "--config", "/nonexistent/x.toml", "-h"},
		{"portable", "--help"},
		{"portable", "--port", port, "--no-browser", "-h"},
		{"version", "--help"},
	} {
		code, out, errOut := runCLI(args...)
		name := args[0]
		if name == "help" {
			name = args[1]
		}
		if code != 0 || !strings.HasPrefix(out, "usage: woodshed "+name) || errOut != "" {
			t.Errorf("%v: code %d, stdout %.60q, stderr %q", args, code, out, errOut)
		}
	}
	tr.quiet(t, 300*time.Millisecond)
}

// Every command is in the top-level help (flow and flows once weren't).
func TestUsageListsEveryCommand(t *testing.T) {
	for _, c := range commands {
		if !strings.Contains(usage, "\n  "+c.name+" ") {
			t.Errorf("woodshed --help doesn't list %q", c.name)
		}
	}
}

func TestTopLevel(t *testing.T) {
	if code, out, _ := runCLI("--help"); code != 0 || !strings.Contains(out, "reset-password") || !strings.Contains(out, "bench") {
		t.Errorf("--help: %d %q", code, out)
	}
	if code, _, errOut := runCLI("frobnicate"); code != 2 || !strings.Contains(errOut, `unknown command "frobnicate"`) {
		t.Errorf("unknown: %d %q", code, errOut)
	}
	// No arguments starts portable mode (stubbed here: it would bind 514).
	called := false
	orig := startPortable
	startPortable = func(stdout, stderr io.Writer) int { called = true; return 0 }
	defer func() { startPortable = orig }()
	if code, _, _ := runCLI(); code != 0 || !called {
		t.Errorf("no args didn't start portable mode: %d", code)
	}
	if code, out, _ := runCLI("help"); code != 0 || !strings.Contains(out, "portable") {
		t.Errorf("help: %d %q", code, out)
	}
	if code, out, _ := runCLI("version"); code != 0 || !strings.HasPrefix(out, "woodshed "+version) {
		t.Errorf("version: %d %q", code, out)
	}
	if code, _, errOut := runCLI("version", "extra"); code != 2 || !strings.Contains(errOut, "unexpected argument") {
		t.Errorf("version extra: %d %q", code, errOut)
	}
}

func TestSendUsageErrors(t *testing.T) {
	tr := newTrap(t)
	port := fmt.Sprint(tr.port)
	for _, args := range [][]string{
		{"send", "--port", port, "--proto", "sctp"},
		{"send", "--port", port, "--proto", "tcp", "--framing", "crlf"},
		{"send", "--port", "70000"},
		{"send", "--port", port, "--duration", "5s"},
		{"send", "--port", port, "--duration", "5s", "--rate", "10", "--count", "3"},
		{"send", "--port", port, "--bogus"},
	} {
		if code, _, errOut := runCLI(args...); code != 2 || !strings.Contains(errOut, "woodshed send:") {
			t.Errorf("%v: code %d, stderr %q", args, code, errOut)
		}
	}
	tr.quiet(t, 200*time.Millisecond)
}

func TestSendMessage(t *testing.T) {
	tr := newTrap(t)
	code, out, errOut := runCLI("send", "--port", fmt.Sprint(tr.port), "--message", "hello from the test")
	if code != 0 || !strings.Contains(out, "Sent 1 message to") {
		t.Fatalf("send: %d %q %q", code, out, errOut)
	}
	select {
	case m := <-tr.got:
		if !strings.HasPrefix(m, "<134>1 ") || !strings.HasSuffix(m, " hello from the test") || !strings.Contains(m, "seq=") {
			t.Errorf("message = %q", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("nothing arrived")
	}
}

func TestSendNothingListening(t *testing.T) {
	// Port 1 (tcpmux) is never served on a test machine; a just-closed ephemeral
	// port can be taken by a parallel test before the dial (as in 382e54a).
	code, _, errOut := runCLI("send", "--proto", "tcp", "--host", "127.0.0.1", "--port", "1")
	if code != 1 || !strings.Contains(errOut, "woodshed send:") || !strings.Contains(errOut, "refused") {
		t.Errorf("code %d, stderr %q", code, errOut)
	}
}

// testConfig writes a config whose data dir is dir/data.
func testConfig(t *testing.T, edit func(*config.Config)) (cfgPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	c := config.Default()
	c.Storage.DataDir = filepath.Join(dir, "data")
	c.Listeners.UDP.Addr, c.Listeners.UDP.Port = "127.0.0.1", 15599
	c.Listeners.TCP.Addr, c.Listeners.TCP.Port = "127.0.0.1", 15599
	c.UI.Port = 18599
	if edit != nil {
		edit(&c)
	}
	cfgPath = filepath.Join(dir, "woodshed.toml")
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(c.Storage.DataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	return cfgPath, c.Storage.DataDir
}

func TestResetPassword(t *testing.T) {
	cfgPath, dataDir := testConfig(t, func(c *config.Config) { c.UI.LANMode = true; c.Listeners.MaxMessageBytes = 8192 })
	hash := filepath.Join(dataDir, api.PasswordFile)
	if err := os.WriteFile(hash, []byte("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runCLI("reset-password", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Removed the UI password and turned LAN mode off") ||
		!strings.Contains(out, "http://localhost:18599/") {
		t.Fatalf("reset-password: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(hash); !os.IsNotExist(err) {
		t.Errorf("hash still there: %v", err)
	}
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if c.UI.LANMode || c.Listeners.MaxMessageBytes != 8192 || c.UI.Port != 18599 {
		t.Errorf("config after reset: %+v", c)
	}
	// Again: nothing to do.
	if code, out, _ := runCLI("reset-password", "--config", cfgPath); code != 0 || !strings.Contains(out, "nothing to change") {
		t.Errorf("second run: %d %q", code, out)
	}
}

func TestResetPasswordWhileRunningInForeground(t *testing.T) {
	cfgPath, dataDir := testConfig(t, func(c *config.Config) { c.UI.LANMode = true })
	lock, err := server.LockDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	code, out, errOut := runCLI("reset-password", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "stop it (Ctrl-C) and start it again") {
		t.Errorf("%d %q %q", code, out, errOut)
	}
}

func TestResetPasswordRestartsTheService(t *testing.T) {
	defer noService()
	restarts := 0
	serviceStatus = func() (service.State, error) { return service.StateRunning, nil }
	serviceRestart = func() error { restarts++; return nil }
	cfgPath, dataDir := testConfig(t, func(c *config.Config) { c.UI.LANMode = true })
	lock, err := server.LockDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	code, out, errOut := runCLI("reset-password", "--config", cfgPath)
	if code != 0 || restarts != 1 || !strings.Contains(out, "Restarted the service") {
		t.Errorf("%d restarts=%d %q %q", code, restarts, out, errOut)
	}

	// A restart the service manager refuses is reported, not hidden.
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c.UI.LANMode = true
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	serviceRestart = func() error { return errNoServiceManager }
	code, _, errOut = runCLI("reset-password", "--config", cfgPath)
	if code != 1 || !strings.Contains(errOut, "couldn't restart the service") {
		t.Errorf("refused restart: %d %q", code, errOut)
	}
}

func TestResetPasswordNeedsWriteAccess(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a non-root Unix user")
	}
	cfgPath, dataDir := testConfig(t, func(c *config.Config) { c.UI.LANMode = true })
	hash := filepath.Join(dataDir, api.PasswordFile)
	os.WriteFile(hash, []byte("x\n"), 0o600)
	if err := os.Chmod(dataDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dataDir, 0o750)
	code, _, errOut := runCLI("reset-password", "--config", cfgPath)
	if code != 1 || !strings.Contains(errOut, "sudo") {
		t.Errorf("%d %q", code, errOut)
	}
	if _, err := os.Stat(hash); err != nil {
		t.Errorf("the hash was touched: %v", err)
	}
	if c, _ := config.Load(cfgPath); !c.UI.LANMode {
		t.Error("LAN mode was turned off although the reset failed")
	}
}

func TestResetPasswordNoConfig(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope", "woodshed.toml")
	code, _, errOut := runCLI("reset-password", "--config", missing)
	if code != 1 || !strings.Contains(errOut, "no config file") {
		t.Errorf("%d %q", code, errOut)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Error("reset-password created a config")
	}
}

func TestReindex(t *testing.T) {
	cfgPath, dataDir := testConfig(t, nil)
	// One device's log file, written as the store writes it.
	dev := filepath.Join(dataDir, logfile.LogsDir, "192.0.2.1")
	os.MkdirAll(dev, 0o750)
	now := time.Now().UTC()
	var b []byte
	for i := range 10 {
		b = store.FormatLine(b, now.Add(time.Duration(i)*time.Millisecond), netip.MustParseAddr("192.0.2.1"), []byte(fmt.Sprintf("<134>hello %d", i)))
	}
	if err := os.WriteFile(filepath.Join(dev, logfile.DayOf(now)+".log"), b, 0o640); err != nil {
		t.Fatal(err)
	}

	lock, err := server.LockDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runCLI("reindex", "--config", cfgPath)
	if code != 1 || !strings.Contains(errOut, "Woodshed is running") || !strings.Contains(errOut, "stop it first") {
		t.Errorf("while locked: %d %q", code, errOut)
	}
	lock.Unlock()

	code, out, errOut := runCLI("reindex", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "files:   1") || !strings.Contains(out, "devices: 1") {
		t.Fatalf("reindex: %d %q %q", code, out, errOut)
	}
	idx, err := index.Open(filepath.Join(dataDir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	d, err := idx.Device(context.Background(), "192.0.2.1")
	if err != nil || d.TotalMsgs != 10 {
		t.Errorf("device after reindex: %+v %v", d, err)
	}
	evs, _ := idx.Events(context.Background(), time.Time{}, time.Time{}, 0)
	if len(evs) == 0 || !strings.Contains(evs[len(evs)-1].Text, "woodshed reindex") {
		t.Errorf("events = %+v", evs)
	}
}

// status points at what Woodpile, the old name, left: a service still installed
// (with the command that removes it) and data folders it can delete.
func TestStatusLegacy(t *testing.T) {
	cfgPath, _ := testConfig(t, func(c *config.Config) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		c.UI.Port = l.Addr().(*net.TCPAddr).Port
		l.Close()
	})
	t.Cleanup(noService)
	serviceLegacy = func() (service.Legacy, error) {
		return service.Legacy{Service: "/usr/lib/systemd/system/woodpile.service", Remove: "sudo apt remove woodpile",
			Data: []string{"/var/lib/woodpile", "/etc/woodpile"}}, nil
	}
	_, out, _ := runCLI("status", "--config", cfgPath)
	for _, want := range []string{
		"Woodpile:   the old Woodpile service is still installed (/usr/lib/systemd/system/woodpile.service); remove it with: sudo apt remove woodpile\n",
		"Woodpile:   the old Woodpile data in /var/lib/woodpile and /etc/woodpile isn't used by Woodshed; you can delete it\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status doesn't say %q:\n%s", want, out)
		}
	}
	serviceLegacy = func() (service.Legacy, error) { return service.Legacy{}, nil }
	if _, out, _ = runCLI("status", "--config", cfgPath); strings.Contains(out, "Woodpile") {
		t.Errorf("status mentions Woodpile with nothing left of it:\n%s", out)
	}
}

func TestStatusNotRunning(t *testing.T) {
	cfgPath, _ := testConfig(t, func(c *config.Config) {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		c.UI.Port = l.Addr().(*net.TCPAddr).Port
		l.Close()
	})
	code, out, _ := runCLI("status", "--config", cfgPath)
	if code != 1 || !strings.Contains(out, "not running") || !strings.Contains(out, "Service:") {
		t.Errorf("%d %q", code, out)
	}
}
