package pprofsrv

import (
	"bytes"
	"compress/gzip"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var quiet = slog.New(slog.DiscardHandler)

func TestSourceIsOffByDefault(t *testing.T) {
	none := func(string) string { return "" }
	if got := Source(false, none); got != "" {
		t.Errorf("default: %q", got)
	}
	if got := Source(false, nil); got != "" {
		t.Errorf("nil getenv: %q", got)
	}
	if got := Source(true, none); got != "config" {
		t.Errorf("config: %q", got)
	}
	for v, want := range map[string]string{
		"1": "env", "true": "env", " ON ": "env", "yes": "env",
		"0": "", "false": "", "off": "", "": "", "2": "", "enabled": "",
	} {
		if got := Source(false, func(k string) string {
			if k == EnvVar {
				return v
			}
			return "1" // any other variable doesn't count
		}); got != want {
			t.Errorf("%s=%q: %q, want %q", EnvVar, v, got, want)
		}
	}
}

func start(t *testing.T) (*Server, Info) {
	t.Helper()
	dir := t.TempDir()
	s, err := Start(dir, "config", quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	in, err := ReadInfo(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, in
}

func get(t *testing.T, in Info, path, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+in.Addr+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, b
}

func TestStartBindsLoopbackAndWritesAPrivateInfoFile(t *testing.T) {
	dir := t.TempDir()
	s, err := Start(dir, "env", quiet)
	if err != nil {
		t.Fatal(err)
	}
	in, err := ReadInfo(dir)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := netip.ParseAddrPort(in.Addr)
	if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 || in.Addr != s.Addr() {
		t.Errorf("addr %q (server %q): %v", in.Addr, s.Addr(), err)
	}
	if in.PID != os.Getpid() || len(in.Token) != 64 || in.Source != "env" || in.StartedAt.IsZero() {
		t.Errorf("info %+v", in)
	}
	fi, err := os.Stat(filepath.Join(dir, InfoFile))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	// Nothing answers on the machine's other addresses: the socket is bound to
	// loopback, not the wildcard.
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err != nil || p.Addr().IsLoopback() || p.Addr().IsLinkLocalUnicast() {
				continue
			}
			c, err := net.DialTimeout("tcp", netip.AddrPortFrom(p.Addr(), ap.Port()).String(), time.Second)
			if err == nil {
				c.Close()
				t.Errorf("the listener answers on %s", p.Addr())
			}
		}
	}
	// A new start gets a new token.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, InfoFile)); !os.IsNotExist(err) {
		t.Errorf("the info file outlived Close: %v", err)
	}
	if c, err := net.DialTimeout("tcp", in.Addr, time.Second); err == nil {
		c.Close()
		t.Error("still listening after Close")
	}
	s2, err := Start(dir, "config", quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if in2, _ := ReadInfo(dir); in2.Token == in.Token {
		t.Error("the token was reused")
	}
}

func TestEveryRouteNeedsTheTokenAndLoopback(t *testing.T) {
	s, in := start(t)
	for _, p := range []string{PathCPU, PathTrace, PathHeap, PathGoroutine, "/", "/debug/pprof/", "/nope"} {
		for _, tok := range []string{"", "wrong", strings.ToUpper(in.Token), in.Token + "x"} {
			resp, body := get(t, in, p, tok)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s with token %q: %s %q", p, tok, resp.Status, body)
			}
		}
	}
	// Only GET.
	req, _ := http.NewRequest(http.MethodPost, "http://"+in.Addr+PathHeap, nil)
	req.Header.Set("Authorization", "Bearer "+in.Token)
	if resp, err := http.DefaultTransport.RoundTrip(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %v %v", resp, err)
	} else {
		resp.Body.Close()
	}
	// From another address (behind a proxy on this machine, say), even with the
	// token: refused.
	h := s.handler()
	for _, ra := range []string{"192.0.2.10:5555", "[2001:db8::1]:5555", "10.0.0.1:1", "garbage"} {
		r := httptest.NewRequest(http.MethodGet, PathGoroutine, nil)
		r.RemoteAddr = ra
		r.Header.Set("Authorization", "Bearer "+in.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("from %s: %d", ra, w.Code)
		}
	}
	for _, ra := range []string{"127.0.0.1:5555", "[::1]:5555", "[::ffff:127.0.0.1]:5555"} {
		r := httptest.NewRequest(http.MethodGet, PathGoroutine, nil)
		r.RemoteAddr = ra
		r.Header.Set("Authorization", "Bearer "+in.Token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("from %s: %d", ra, w.Code)
		}
	}
}

//go:noinline
func spin(n int) int {
	x := 0
	for i := range n {
		x += i * i % 7
	}
	return x
}

// busy keeps a goroutine on the CPU in pprofBusyLoop until stop closes.
func busy(t *testing.T) {
	t.Helper()
	stop := make(chan struct{})
	done := make(chan struct{})
	var sink atomic.Int64
	go func() {
		defer close(done)
		pprofBusyLoop(stop, &sink)
	}()
	t.Cleanup(func() { close(stop); <-done })
}

//go:noinline
func pprofBusyLoop(stop <-chan struct{}, sink *atomic.Int64) {
	for {
		select {
		case <-stop:
			return
		default:
			sink.Add(int64(spin(100000)))
		}
	}
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("not gzip (%d bytes): %v", len(b), err)
	}
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestCPUProfile(t *testing.T) {
	_, in := start(t)
	busy(t)
	t0 := time.Now()
	resp, body := get(t, in, PathCPU+"?seconds=1", in.Token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %q", resp.Status, body)
	}
	if d := time.Since(t0); d < time.Second {
		t.Errorf("a 1 s profile took %v", d)
	}
	// The pprof format: gzipped protobuf whose string table names the
	// functions (go tool pprof reads it without the binary).
	raw := gunzip(t, body)
	if !bytes.Contains(raw, []byte("pprofBusyLoop")) {
		t.Errorf("the profile doesn't name the busy function (%d bytes)", len(raw))
	}
}

// held waits until mu is held by someone else.
func held(t *testing.T, mu *sync.Mutex) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for mu.TryLock() {
		mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the capture never started")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOneCaptureOfAKindAtATime(t *testing.T) {
	s, in := start(t)
	first := make(chan int, 1)
	go func() {
		resp, _ := get(t, in, PathCPU+"?seconds=2", in.Token)
		first <- resp.StatusCode
	}()
	held(t, &s.cpuMu)
	resp, body := get(t, in, PathCPU+"?seconds=1", in.Token)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(string(body), "already") {
		t.Errorf("a second CPU profile: %s %q", resp.Status, body)
	}
	// A trace can overlap a CPU profile.
	if resp, body := get(t, in, PathTrace+"?seconds=1", in.Token); resp.StatusCode != http.StatusOK {
		t.Errorf("trace during a CPU profile: %s %q", resp.Status, body)
	}
	if code := <-first; code != http.StatusOK {
		t.Errorf("first profile: %d", code)
	}
	go func() {
		resp, _ := get(t, in, PathTrace+"?seconds=2", in.Token)
		first <- resp.StatusCode
	}()
	held(t, &s.traceMu)
	if resp, body := get(t, in, PathTrace+"?seconds=1", in.Token); resp.StatusCode != http.StatusConflict {
		t.Errorf("a second trace: %s %q", resp.Status, body)
	}
	if code := <-first; code != http.StatusOK {
		t.Errorf("first trace: %d", code)
	}
}

func TestTrace(t *testing.T) {
	_, in := start(t)
	resp, body := get(t, in, PathTrace+"?seconds=1", in.Token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s %q", resp.Status, body)
	}
	// A runtime trace starts with "go 1.NN trace".
	if !bytes.HasPrefix(body, []byte("go 1.")) || !bytes.Contains(body[:16], []byte(" trace")) {
		t.Errorf("not a runtime trace: %q", body[:min(len(body), 16)])
	}
}

func TestHeapAndGoroutine(t *testing.T) {
	_, in := start(t)
	resp, body := get(t, in, PathHeap, in.Token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("heap: %s %q", resp.Status, body)
	}
	if raw := gunzip(t, body); !bytes.Contains(raw, []byte("inuse_space")) {
		t.Errorf("heap profile without inuse_space (%d bytes)", len(raw))
	}
	resp, body = get(t, in, PathGoroutine, in.Token)
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("goroutine: %s %q", resp.Status, resp.Header.Get("Content-Type"))
	}
	if !bytes.Contains(body, []byte("goroutine ")) || !bytes.Contains(body, []byte("pprofsrv.(*Server).goroutine")) {
		t.Errorf("goroutine dump: %.300q", body)
	}
}

func TestBadSeconds(t *testing.T) {
	_, in := start(t)
	for _, q := range []string{"0", "-1", "x", "1.5", strconv.Itoa(MaxCPUSeconds + 1)} {
		if resp, _ := get(t, in, PathCPU+"?seconds="+q, in.Token); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("cpu seconds=%s: %s", q, resp.Status)
		}
	}
	if resp, _ := get(t, in, PathTrace+"?seconds="+strconv.Itoa(MaxTraceSeconds+1), in.Token); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("trace over the max: %s", resp.Status)
	}
}

// Close ends a capture in progress at once (the server's shutdown must not wait
// out a 5-minute profile).
func TestCloseEndsACapture(t *testing.T) {
	dir := t.TempDir()
	s, err := Start(dir, "config", quiet)
	if err != nil {
		t.Fatal(err)
	}
	in, _ := ReadInfo(dir)
	got := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest(http.MethodGet, "http://"+in.Addr+PathCPU+"?seconds=120", nil)
		req.Header.Set("Authorization", "Bearer "+in.Token)
		resp, err := (&http.Client{Transport: &http.Transport{}}).Do(req)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			resp.Body.Close()
		}
		got <- err
	}()
	held(t, &s.cpuMu)
	t0 := time.Now()
	s.Close()
	if d := time.Since(t0); d > time.Second {
		t.Errorf("Close took %v", d)
	}
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the capture didn't end")
	}
	// The profiler is free again.
	s2, err := Start(dir, "config", quiet)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	in2, _ := ReadInfo(dir)
	if resp, body := get(t, in2, PathCPU+"?seconds=1", in2.Token); resp.StatusCode != http.StatusOK {
		t.Errorf("after Close: %s %q", resp.Status, body)
	}
}

// No package imports net/http/pprof (its init registers handlers on
// http.DefaultServeMux, which any server with a nil handler would then serve)
// or expvar (the same, at /debug/vars).
func TestNoDefaultMuxDebugImports(t *testing.T) {
	dir, _ := filepath.Abs(".")
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		if filepath.Dir(dir) == dir {
			t.Fatal("no go.mod")
		}
		dir = filepath.Dir(dir)
	}
	fset := token.NewFileSet()
	checked := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "testdata", "vendor", ".git", "dist":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		checked++
		for _, imp := range f.Imports {
			if v, _ := strconv.Unquote(imp.Path.Value); v == "net/http/pprof" || v == "expvar" {
				t.Errorf("%s imports %s", p, v)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 100 {
		t.Fatalf("only %d Go files", checked)
	}
}
