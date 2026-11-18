package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/pprofsrv"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/service"
)

// profiled is a test config whose data folder has a profiling listener, as a
// running server with debug.pprof on has.
func profiled(t *testing.T) (cfgPath, dataDir string, in pprofsrv.Info) {
	t.Helper()
	cfgPath, dataDir = testConfig(t, nil)
	p, err := pprofsrv.Start(dataDir, "config", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	in, err = pprofsrv.ReadInfo(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	return cfgPath, dataDir, in
}

func gunzipFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("%s isn't gzip: %v", path, err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestProfileCapturesEveryKind(t *testing.T) {
	cfgPath, _, _ := profiled(t)
	dir := t.TempDir()

	cpu := filepath.Join(dir, "cpu.pprof")
	code, out, errOut := runCLI("profile", "cpu", "--seconds", "1", "--out", cpu, "--config", cfgPath)
	if code != 0 || errOut != "" || !strings.Contains(out, "Capturing a 1 s CPU profile") || !strings.Contains(out, "go tool pprof -top") {
		t.Fatalf("cpu: %d %q %q", code, out, errOut)
	}
	if raw := gunzipFile(t, cpu); !bytes.Contains(raw, []byte("samples")) {
		t.Errorf("cpu profile without sample types (%d bytes)", len(raw))
	}
	if fi, _ := os.Stat(cpu); fi == nil || !isWindows() && fi.Mode().Perm() != 0o600 {
		t.Errorf("cpu file mode: %v", fi)
	}

	// cpu --trace: both files, the trace over the profile's start.
	cpu2 := filepath.Join(dir, "both.pprof")
	code, out, errOut = runCLI("profile", "cpu", "--seconds", "2", "--trace", "--trace-seconds", "1", "--out", cpu2, "--config", cfgPath)
	if code != 0 || errOut != "" || !strings.Contains(out, "go tool trace") {
		t.Fatalf("cpu --trace: %d %q %q", code, out, errOut)
	}
	gunzipFile(t, cpu2)
	if b, err := os.ReadFile(filepath.Join(dir, "both.trace")); err != nil || !bytes.HasPrefix(b, []byte("go 1.")) {
		t.Errorf("cpu --trace's trace: %v %.16q", err, b)
	}

	tr := filepath.Join(dir, "t.trace")
	code, out, errOut = runCLI("profile", "trace", "--seconds", "1", "--out", tr, "--config", cfgPath)
	if code != 0 || errOut != "" {
		t.Fatalf("trace: %d %q %q", code, out, errOut)
	}
	if b, _ := os.ReadFile(tr); !bytes.HasPrefix(b, []byte("go 1.")) {
		t.Errorf("not a trace: %.16q", b)
	}

	heap := filepath.Join(dir, "heap.pprof")
	code, out, errOut = runCLI("profile", "heap", "--out", heap, "--config", cfgPath)
	if code != 0 || errOut != "" || !strings.Contains(out, "privately") {
		t.Fatalf("heap: %d %q %q", code, out, errOut)
	}
	if raw := gunzipFile(t, heap); !bytes.Contains(raw, []byte("inuse_space")) {
		t.Error("heap profile without inuse_space")
	}

	g := filepath.Join(dir, "g.txt")
	code, out, errOut = runCLI("profile", "goroutine", "--out", g, "--config", cfgPath)
	if code != 0 || errOut != "" {
		t.Fatalf("goroutine: %d %q %q", code, out, errOut)
	}
	if b, _ := os.ReadFile(g); !bytes.Contains(b, []byte("goroutine ")) {
		t.Errorf("goroutine dump: %.200q", b)
	}
	// No .part files left behind.
	if m, _ := filepath.Glob(filepath.Join(dir, "*.part")); len(m) > 0 {
		t.Errorf("left %v", m)
	}
}

func TestProfileDefaultFileName(t *testing.T) {
	cfgPath, _, _ := profiled(t)
	dir := t.TempDir()
	t.Chdir(dir)
	old := profileNow
	profileNow = func() time.Time { return time.Date(2026, 11, 18, 9, 30, 5, 0, time.Local) }
	defer func() { profileNow = old }()
	if code, out, errOut := runCLI("profile", "goroutine", "--config", cfgPath); code != 0 ||
		!strings.Contains(out, "Wrote woodshed-goroutine-20261118-093005.txt") {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "woodshed-goroutine-20261118-093005.txt")); err != nil {
		t.Error(err)
	}
}

// Off by default: with no listener the command says why and exits 1, and
// writes nothing.
func TestProfileWhenOffOrNotRunning(t *testing.T) {
	cfgPath, dataDir := testConfig(t, nil)
	out := filepath.Join(t.TempDir(), "x.pprof")
	code, _, errOut := runCLI("profile", "cpu", "--seconds", "1", "--out", out, "--config", cfgPath)
	if code != 1 || !strings.Contains(errOut, "isn't running") {
		t.Errorf("not running: %d %q", code, errOut)
	}
	lock, err := server.LockDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	code, _, errOut = runCLI("profile", "heap", "--out", out, "--config", cfgPath)
	if code != 1 || !strings.Contains(errOut, "profiling is off") || !strings.Contains(errOut, "profile on") {
		t.Errorf("off: %d %q", code, errOut)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("wrote a file: %v", err)
	}
}

func writeInfoFile(t *testing.T, dataDir string, in pprofsrv.Info) {
	t.Helper()
	b, _ := json.Marshal(in)
	if err := os.WriteFile(filepath.Join(dataDir, pprofsrv.InfoFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestProfileRefusesABadInfoFile(t *testing.T) {
	cfgPath, dataDir, in := profiled(t)
	out := filepath.Join(t.TempDir(), "x.pprof")
	// The token never leaves the machine, whatever the file says.
	for _, addr := range []string{"192.0.2.1:8514", "[2001:db8::1]:8514", "example.com:80", "localhost:1"} {
		bad := in
		bad.Addr = addr
		writeInfoFile(t, dataDir, bad)
		code, _, errOut := runCLI("profile", "goroutine", "--out", out, "--config", cfgPath)
		if code != 1 || !strings.Contains(errOut, "not a loopback address") {
			t.Errorf("%s: %d %q", addr, code, errOut)
		}
	}
	// A wrong token: the server refuses it, and nothing is written.
	bad := in
	bad.Token = strings.Repeat("0", 64)
	writeInfoFile(t, dataDir, bad)
	code, _, errOut := runCLI("profile", "goroutine", "--out", out, "--config", cfgPath)
	if code != 1 || !strings.Contains(errOut, "401") {
		t.Errorf("wrong token: %d %q", code, errOut)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Errorf("wrote a file: %v", err)
	}
	if _, err := os.Stat(out + ".part"); !os.IsNotExist(err) {
		t.Errorf("left a .part: %v", err)
	}
	// Nothing listening at the address.
	gone := in
	gone.Addr = "127.0.0.1:1"
	writeInfoFile(t, dataDir, gone)
	if code, _, errOut := runCLI("profile", "goroutine", "--out", out, "--config", cfgPath); code != 1 || !strings.Contains(errOut, "didn't answer") {
		t.Errorf("nothing listening: %d %q", code, errOut)
	}
}

func TestProfileUsage(t *testing.T) {
	cfgPath, _ := testConfig(t, nil)
	for _, args := range [][]string{
		{"profile"},
		{"profile", "memory"},
		{"profile", "cpu", "extra"},
		{"profile", "cpu", "--seconds", "0"},
		{"profile", "cpu", "--seconds", "301"},
		{"profile", "trace", "--seconds", "61"},
		{"profile", "heap", "--seconds", "5"},
		{"profile", "goroutine", "--trace"},
		{"profile", "cpu", "--trace-seconds", "3"},
		{"profile", "cpu", "--seconds", "5", "--trace", "--trace-seconds", "10"},
		{"profile", "on", "--seconds", "5"},
		{"profile", "off", "--out", "x"},
	} {
		code, _, errOut := runCLI(append(args, "--config", cfgPath)...)
		if code != 2 || errOut == "" {
			t.Errorf("%v: %d %q", args, code, errOut)
		}
	}
	if code, out, _ := runCLI("profile", "--help"); code != 0 || !strings.HasPrefix(out, "usage: woodshed profile") ||
		!strings.Contains(out, "127.0.0.1") || !strings.Contains(out, "-trace-seconds") || !strings.Contains(out, "Exit status") {
		t.Errorf("help: %d %q", code, out)
	}
	if _, out, _ := runCLI("help"); !strings.Contains(out, "  profile ") {
		t.Error("profile isn't in the usage")
	}
}

func TestProfileOnOff(t *testing.T) {
	defer noService()
	cfgPath, dataDir := testConfig(t, nil)
	code, out, errOut := runCLI("profile", "on", "--config", cfgPath)
	if code != 0 || errOut != "" || !strings.Contains(out, "Turned profiling on") || !strings.Contains(out, "isn't running") {
		t.Errorf("on: %d %q %q", code, out, errOut)
	}
	if !loadCfg(t, cfgPath).Debug.PProf {
		t.Error("on didn't save debug.pprof")
	}
	if code, out, _ := runCLI("profile", "on", "--config", cfgPath); code != 0 || !strings.Contains(out, "already true") {
		t.Errorf("on again: %d %q", code, out)
	}
	// A running service is restarted to use it.
	lock, err := server.LockDataDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Unlock()
	restarts := 0
	serviceStatus = func() (service.State, error) { return service.StateRunning, nil }
	serviceRestart = func() error { restarts++; return nil }
	code, out, errOut = runCLI("profile", "off", "--config", cfgPath)
	if code != 0 || restarts != 1 || !strings.Contains(out, "Turned profiling off") || !strings.Contains(out, "Restarted the service") {
		t.Errorf("off: %d restarts=%d %q %q", code, restarts, out, errOut)
	}
	if loadCfg(t, cfgPath).Debug.PProf {
		t.Error("off didn't save")
	}
	// The file leaves the table out again once it's off.
	if b, _ := os.ReadFile(cfgPath); bytes.Contains(b, []byte("[debug]")) {
		t.Errorf("the config still has [debug]:\n%s", b)
	}
}

func isWindows() bool { return filepath.Separator == '\\' }
