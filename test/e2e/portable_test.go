package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/loadgen"
)

// syncBuf is a goroutine-safe buffer for a child's stdout.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// TestPortable runs `woodshed portable` (on high loopback ports, since tests never
// bind 514), with its UI port already taken so it falls back, checks the console
// banner and the UI, sends from two protocols, watches the new-device line, then
// stops it with SIGTERM (Ctrl-Break on Windows) and checks everything was flushed.
func TestPortable(t *testing.T) {
	if testingShort() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	// Something else (an installed Woodshed, say) has the UI port.
	hold, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", uiPort))
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()

	var out syncBuf
	cmd := exec.Command(binary, "portable", "--dir", dir, "--no-browser",
		"--port", fmt.Sprint(syslogPort), "--listen", "127.0.0.1", "--ui-port", fmt.Sprint(uiPort))
	cmd.Stdout, cmd.Stderr = &out, &out
	prepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	defer func() {
		select {
		case <-exited:
		default:
			_ = cmd.Process.Kill() // our own child, by PID
			<-exited
		}
		if t.Failed() {
			t.Logf("console:\n%s", out.String())
		}
	}()

	waitFor(t, "the banner", 20*time.Second, func() bool { return strings.Contains(out.String(), "Press Ctrl-C") })
	banner := out.String()
	for _, want := range []string{
		"portable mode",
		"Data folder:  " + dir,
		fmt.Sprintf("Listening on UDP %d and TCP %d on 127.0.0.1", syslogPort, syslogPort),
		"Send logs to: 127.0.0.1",
		fmt.Sprintf("port %d is in use", uiPort),
		"Your logs stay in " + dir,
	} {
		if !strings.Contains(banner, want) {
			t.Errorf("banner lacks %q", want)
		}
	}
	var ui int
	for p := uiPort + 1; p <= uiPort+16; p++ {
		if strings.Contains(banner, fmt.Sprintf("http://localhost:%d/", p)) {
			ui = p
		}
	}
	if ui == 0 {
		t.Fatalf("no fallback UI URL in the banner:\n%s", banner)
	}
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/healthz", ui))
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("UI on the fallback port: %v %v", resp, err)
	}
	resp.Body.Close()

	run := loadgen.NewRunID()
	// Each run's last message on the live tail means the server has read it and
	// handed it to the store (which still holds it in a buffer): the flush on stop
	// is what's tested, not how fast the sockets are read.
	base := fmt.Sprintf("http://127.0.0.1:%d", ui)
	lasts := []*liveStream{
		openLive(t, base, "q="+url.QueryEscape(loadgen.SeqTag(run)+"1999")),
		openLive(t, base, "q="+url.QueryEscape(loadgen.SeqTag(run)+"3999")),
	}
	for i, proto := range []string{"udp", "tcp"} {
		if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
			Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort), Proto: proto, Count: 2000, Rate: 4000, RunID: run, FirstSeq: i * 2000,
		}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the new-device line", 20*time.Second, func() bool { return strings.Contains(out.String(), "New device 127.0.0.1 (first message") })
	if n := strings.Count(out.String(), "New device"); n != 1 {
		t.Errorf("%d new-device lines for one device", n)
	}

	// A second copy on the same folder is refused, kindly.
	second, _ := exec.Command(binary, "portable", "--dir", dir, "--no-browser", "--port", fmt.Sprint(syslogPort),
		"--listen", "127.0.0.1", "--ui-port", fmt.Sprint(ui)).CombinedOutput()
	if !strings.Contains(string(second), "Woodshed is already running on "+dir) {
		t.Errorf("second copy: %s", second)
	}

	for _, ls := range lasts {
		ls.wait(t, 10*time.Second)
	}
	t0 := time.Now()
	if err := terminate(cmd); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		exited <- err
		if err != nil {
			t.Fatalf("portable exited with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("portable didn't stop within 10 s")
	}
	took := time.Since(t0)
	if !strings.Contains(out.String(), "Woodshed stopped; everything is saved in "+dir) {
		t.Errorf("no clean-stop line")
	}
	if took > 5*time.Second {
		t.Errorf("stopping took %v; Windows allows about 5 s after a console close", took)
	}
	v, err := loadgen.Verify(dir, run, 4000)
	if err != nil || v.Missing != 0 || v.Duplicates != 0 {
		t.Fatalf("on disk after stopping: %+v %v", v, err)
	}
	t.Logf("portable: UI fell back %d -> %d, 4000/4000 on disk, stopped in %v", uiPort, ui, took.Round(time.Millisecond))
}

// startPortable starts `woodshed portable` on loopback ports and waits for its banner.
func startPortable(t *testing.T, dir string, syslogPort, uiPort int) (*exec.Cmd, *syncBuf, chan error) {
	t.Helper()
	out := &syncBuf{}
	cmd := exec.Command(binary, "portable", "--dir", dir, "--no-browser",
		"--port", fmt.Sprint(syslogPort), "--listen", "127.0.0.1", "--ui-port", fmt.Sprint(uiPort))
	cmd.Stdout, cmd.Stderr = out, out
	prepareCmd(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case err := <-exited:
			exited <- err
		default:
			_ = cmd.Process.Kill() // our own child, by PID
			<-exited
		}
		if t.Failed() {
			t.Logf("console:\n%s", out.String())
		}
	})
	waitFor(t, "the banner", 30*time.Second, func() bool { return strings.Contains(out.String(), "Press Ctrl-C") })
	return cmd, out, exited
}

func stopPortable(t *testing.T, cmd *exec.Cmd, out *syncBuf, exited chan error) {
	t.Helper()
	if err := terminate(cmd); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		exited <- err
		if err != nil {
			t.Fatalf("portable exited with %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("portable didn't stop within 10 s")
	}
	if !strings.Contains(out.String(), "Woodshed stopped; everything is saved") {
		t.Error("no clean-stop line")
	}
}

// With ui.require_login_local on, the API needs a login even on localhost; the
// console's readiness check and new-device lines read the server in-process, so
// they keep working.
func TestPortableRequireLoginLocal(t *testing.T) {
	if testingShort() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	cmd, out, exited := startPortable(t, dir, syslogPort, uiPort)
	base := fmt.Sprintf("http://127.0.0.1:%d", uiPort)
	put := func(path string, body string) int {
		req, _ := http.NewRequest("PUT", base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := put("/api/password", `{"current":"","new":"correct horse battery"}`); code != 204 {
		t.Fatalf("set password: %d", code)
	}
	// The first password turns require_login_local on by itself (docs/api.md).
	if resp, err := http.Get(base + "/api/settings"); err != nil || resp.StatusCode != 401 {
		t.Fatalf("require_login_local didn't come on with the first password: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	stopPortable(t, cmd, out, exited)

	// Again, now with the login required.
	cmd, out, exited = startPortable(t, dir, syslogPort, uiPort)
	if !strings.Contains(out.String(), fmt.Sprintf("Listening on UDP %d and TCP %d", syslogPort, syslogPort)) {
		t.Errorf("banner without the listeners:\n%s", out.String())
	}
	if resp, err := http.Get(base + "/api/devices"); err != nil || resp.StatusCode != 401 {
		t.Fatalf("the API doesn't need a login: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	run := loadgen.NewRunID()
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort), Proto: "tcp", Count: 500, RunID: run}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the new-device line", 20*time.Second, func() bool { return strings.Contains(out.String(), "New device 127.0.0.1") })
	stopPortable(t, cmd, out, exited)
	if v, err := loadgen.Verify(dir, run, 500); err != nil || v.Missing != 0 || v.Duplicates != 0 {
		t.Fatalf("%+v %v", v, err)
	}
}
