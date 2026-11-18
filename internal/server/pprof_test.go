package server

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/peer"
	"github.com/gmccollu/woodshed/internal/pprofsrv"
)

// startEnv is start with a fake environment for WOODSHED_PPROF.
func startEnv(t *testing.T, cfgPath string, env map[string]string) *running {
	t.Helper()
	srv, err := Open(cfgPath, Options{Version: "1.2.3", Commit: "abc1234", Logger: testLogger(t),
		getenv: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	srv.be.peers.find = func(context.Context, peer.Options) (peer.Info, bool) { return peer.Info{}, false }
	srv.be.peers.readConfig = func(string) (config.Config, error) { return config.Config{}, os.ErrNotExist }
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{srv: srv, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- srv.Run(ctx) }()
	waitFor(t, "the UI", func() bool { return srv.UIState().Listening })
	r.base = "http://" + srv.UIState().Addr
	t.Cleanup(func() { r.stop(t) })
	return r
}

func profilingBanner(t *testing.T, r *running) *api.Banner {
	t.Helper()
	var st api.Status
	if code := r.do(t, "GET", "/api/status", nil, &st); code != 200 {
		t.Fatalf("status %d", code)
	}
	for _, b := range st.Banners {
		if b.Kind == "profiling_on" {
			return &b
		}
	}
	return nil
}

// The profiling listener is off by default, with no file, no banner and no
// route on the UI's API; a stale file from a crash is removed (SPEC §13.10
// decision 85).
func TestProfilingOffByDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeConfig(t, dir, freePort(t), 0, nil)
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dataDir, pprofsrv.InfoFile)
	if err := os.WriteFile(stale, []byte(`{"addr":"127.0.0.1:1","token":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// "0" isn't on, nor is any other variable.
	r := startEnv(t, cfgPath, map[string]string{pprofsrv.EnvVar: "0", "WOODSHED_DEBUG": "1"})
	if r.srv.prof != nil {
		t.Fatal("the profiling listener started")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the stale info file is still there: %v", err)
	}
	if b := profilingBanner(t, r); b != nil {
		t.Errorf("banner while off: %+v", b)
	}
	// The UI's own server has no profiling routes, on or off.
	for _, p := range []string{"/debug/pprof/", pprofsrv.PathCPU, pprofsrv.PathHeap, "/api/debug/pprof/heap"} {
		resp, err := http.Get(r.base + p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(b), "goroutine ") || resp.Header.Get("Content-Type") == "application/octet-stream" {
			t.Errorf("%s on the UI port: %s %.100q", p, resp.Status, b)
		}
	}
}

func TestProfilingOnWhenEnabled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		edit   func(*config.Config)
		env    map[string]string
		source string
	}{
		{"config", func(c *config.Config) { c.Debug.PProf = true }, nil, "config"},
		{"env", nil, map[string]string{pprofsrv.EnvVar: "1"}, "env"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := writeConfig(t, dir, freePort(t), 0, tc.edit)
			dataDir := filepath.Join(dir, "data")
			r := startEnv(t, cfgPath, tc.env)
			in, err := pprofsrv.ReadInfo(dataDir)
			if err != nil {
				t.Fatal(err)
			}
			if ap, err := netip.ParseAddrPort(in.Addr); err != nil || !ap.Addr().IsLoopback() || in.Source != tc.source {
				t.Errorf("info %+v %v", in, err)
			}
			b := profilingBanner(t, r)
			if b == nil || b.Level != api.LevelInfo || !strings.Contains(b.Text, "woodshed profile off") || !strings.Contains(b.Text, in.Addr) {
				t.Errorf("banner %+v", b)
			}
			req, _ := http.NewRequest("GET", "http://"+in.Addr+pprofsrv.PathGoroutine, nil)
			req.Header.Set("Authorization", "Bearer "+in.Token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			// The dump is of the running server: its store and listeners are in it.
			if resp.StatusCode != 200 || !strings.Contains(string(body), "woodshed/internal/") {
				t.Errorf("goroutine dump: %s %.200q", resp.Status, body)
			}
			// A capture in progress doesn't hold up the shutdown.
			go func() {
				req, _ := http.NewRequest("GET", "http://"+in.Addr+pprofsrv.PathCPU+"?seconds=120", nil)
				req.Header.Set("Authorization", "Bearer "+in.Token)
				if resp, err := http.DefaultClient.Do(req); err == nil {
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
				}
			}()
			time.Sleep(200 * time.Millisecond)
			t0 := time.Now()
			r.stop(t)
			if d := time.Since(t0); d > 10*time.Second {
				t.Errorf("shutdown took %v", d)
			}
			if _, err := os.Stat(filepath.Join(dataDir, pprofsrv.InfoFile)); !os.IsNotExist(err) {
				t.Errorf("the info file outlived the server: %v", err)
			}
		})
	}
}
