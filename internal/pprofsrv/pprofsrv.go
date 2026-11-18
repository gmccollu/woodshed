// Package pprofsrv is the opt-in profiling listener behind `woodshed profile`
// (SPEC §13.10 decision 85): CPU and heap profiles, goroutine dumps and runtime
// traces of the running server, for finding out where its CPU goes on a given
// machine.
//
// It is off unless debug.pprof is true in the config or WOODSHED_PPROF=1 is in
// the server's environment. When on, it listens on loopback only (127.0.0.1, or
// ::1 where there's no IPv4 loopback) on a port the OS picks, and answers only
// requests from a loopback address that carry the random token it writes into
// the data folder (InfoFile, mode 0600; on Windows the data folder's protected
// ACL). So only someone who can read the data folder on this machine, an
// administrator or the service account, can use it, and nothing on the network
// can reach it.
//
// It never uses net/http/pprof, whose import registers handlers on
// http.DefaultServeMux; the handlers here are written against runtime/pprof
// and runtime/trace directly.
package pprofsrv

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/atomicfile"
)

// InfoFile is the file in the data folder that says where the listener is and
// holds its token. It exists only while the listener runs.
const InfoFile = "woodshed.pprof.json"

// EnvVar turns the listener on from the server's environment, as debug.pprof
// does from the config.
const EnvVar = "WOODSHED_PPROF"

// Limits on a capture's length, in seconds.
const (
	DefaultCPUSeconds   = 30
	MaxCPUSeconds       = 300
	DefaultTraceSeconds = 5
	MaxTraceSeconds     = 60
)

// Paths served. Every one is GET only.
const (
	PathCPU       = "/debug/pprof/cpu"       // ?seconds=N: a CPU profile (pprof format, gzipped)
	PathTrace     = "/debug/pprof/trace"     // ?seconds=N: a runtime trace (go tool trace)
	PathHeap      = "/debug/pprof/heap"      // a heap profile after a GC (pprof format, gzipped)
	PathGoroutine = "/debug/pprof/goroutine" // every goroutine's stack, as text
)

// Info is InfoFile's content.
type Info struct {
	PID       int       `json:"pid"`
	Addr      string    `json:"addr"` // host:port, always a loopback address
	Token     string    `json:"token"`
	Source    string    `json:"source"` // "config" (debug.pprof) or "env" (WOODSHED_PPROF)
	StartedAt time.Time `json:"started_at"`
}

// Source is why the listener is on: "config", "env" or "" (it's off).
func Source(configOn bool, getenv func(string) string) string {
	if configOn {
		return "config"
	}
	if getenv != nil {
		switch strings.ToLower(strings.TrimSpace(getenv(EnvVar))) {
		case "1", "true", "on", "yes":
			return "env"
		}
	}
	return ""
}

// ReadInfo reads InfoFile in dataDir.
func ReadInfo(dataDir string) (Info, error) {
	var in Info
	b, err := atomicfile.ReadFile(filepath.Join(dataDir, InfoFile))
	if err != nil {
		return in, err
	}
	if err := json.Unmarshal(b, &in); err != nil {
		return in, fmt.Errorf("%s: %w", InfoFile, err)
	}
	if in.Addr == "" || in.Token == "" {
		return in, fmt.Errorf("%s has no address or token", InfoFile)
	}
	return in, nil
}

// Server is a running profiling listener.
type Server struct {
	dataDir string
	info    Info
	ln      net.Listener
	srv     *http.Server
	log     *slog.Logger
	done    chan struct{}
	// stop ends every request's context, so Close doesn't wait out a capture.
	ctx  context.Context
	stop context.CancelFunc

	// One capture of each kind at a time: the runtime allows a single CPU
	// profile and a single trace (a CPU profile and a trace may overlap).
	cpuMu, traceMu sync.Mutex

	closeOnce sync.Once
}

// listen is net.Listen, replaced by tests.
var listen = net.Listen

// Start listens on loopback, writes InfoFile into dataDir and serves until
// Close. source is what turned it on ("config" or "env").
func Start(dataDir, source string, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	ln, err := listen("tcp4", "127.0.0.1:0")
	if err != nil {
		var err6 error
		if ln, err6 = listen("tcp6", "[::1]:0"); err6 != nil {
			return nil, fmt.Errorf("pprof: listen on loopback: %w", errors.Join(err, err6))
		}
	}
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil || !ap.Addr().IsLoopback() {
		ln.Close()
		return nil, fmt.Errorf("pprof: bound %s, not a loopback address", ln.Addr())
	}
	tok := make([]byte, 32)
	if _, err := rand.Read(tok); err != nil {
		ln.Close()
		return nil, fmt.Errorf("pprof: token: %w", err)
	}
	s := &Server{
		dataDir: dataDir,
		info: Info{PID: os.Getpid(), Addr: ap.String(), Token: hex.EncodeToString(tok), Source: source,
			StartedAt: time.Now().UTC().Truncate(time.Second)},
		ln:   ln,
		log:  log,
		done: make(chan struct{}),
	}
	s.ctx, s.stop = context.WithCancel(context.Background())
	if err := writeInfo(dataDir, s.info); err != nil {
		ln.Close()
		s.stop()
		return nil, fmt.Errorf("pprof: write %s: %w", InfoFile, err)
	}
	s.srv = &http.Server{
		Handler: s.handler(),
		// No ReadTimeout: it would end the request's context, and the capture,
		// in the middle of a long CPU profile. A GET has no body to wait for.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      (MaxCPUSeconds + 60) * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
		BaseContext:       func(net.Listener) context.Context { return s.ctx },
	}
	go func() {
		defer close(s.done)
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("pprof: the profiling listener stopped", "err", err)
		}
	}()
	return s, nil
}

// Addr is the bound address (host:port, loopback).
func (s *Server) Addr() string { return s.info.Addr }

// Close stops the listener, ends captures in progress and removes InfoFile.
func (s *Server) Close() error {
	var err error
	s.closeOnce.Do(func() {
		// Captures in progress see their request context end and stop at once.
		s.stop()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err = s.srv.Shutdown(ctx); err != nil {
			err = s.srv.Close()
		}
		<-s.done
		// Remove the file only if it's still ours (a second server on the same
		// data folder can't run, but don't delete what isn't ours anyway).
		if in, rerr := ReadInfo(s.dataDir); rerr == nil && in.Token == s.info.Token {
			_ = os.Remove(filepath.Join(s.dataDir, InfoFile))
		}
	})
	return err
}

func writeInfo(dataDir string, in Info) error {
	b, err := json.MarshalIndent(in, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, InfoFile)
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return atomicfile.Rename(tmp, path)
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+PathCPU, s.cpu)
	mux.HandleFunc("GET "+PathTrace, s.trace)
	mux.HandleFunc("GET "+PathHeap, s.heap)
	mux.HandleFunc("GET "+PathGoroutine, s.goroutine)
	return s.guard(mux)
}

// guard lets through only a request from a loopback address with the token.
func (s *Server) guard(next http.Handler) http.Handler {
	want := []byte("Bearer " + s.info.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ap, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !ap.Addr().Unmap().IsLoopback() {
			http.Error(w, "only from this machine", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			http.Error(w, "no or wrong token (it's in "+InfoFile+" in the data folder)", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// seconds parses ?seconds=, def when absent.
func seconds(r *http.Request, def, max int) (time.Duration, error) {
	v := r.URL.Query().Get("seconds")
	if v == "" {
		return time.Duration(def) * time.Second, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > max {
		return 0, fmt.Errorf("seconds must be a whole number from 1 to %d", max)
	}
	return time.Duration(n) * time.Second, nil
}

// wait sleeps for d, or until the client goes away or the server closes.
func wait(r *http.Request, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-r.Context().Done():
	}
}

func (s *Server) cpu(w http.ResponseWriter, r *http.Request) {
	d, err := seconds(r, DefaultCPUSeconds, MaxCPUSeconds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.cpuMu.TryLock() {
		http.Error(w, "a CPU profile is already being captured", http.StatusConflict)
		return
	}
	defer s.cpuMu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="woodshed-cpu.pprof"`)
	// StartCPUProfile writes nothing until the profile ends, so a failure here
	// can still answer with an error status.
	if err := pprof.StartCPUProfile(w); err != nil {
		http.Error(w, "can't start a CPU profile: "+err.Error(), http.StatusConflict)
		return
	}
	s.log.Info("pprof: capturing a CPU profile", "seconds", d.Seconds())
	wait(r, d)
	pprof.StopCPUProfile()
}

func (s *Server) trace(w http.ResponseWriter, r *http.Request) {
	d, err := seconds(r, DefaultTraceSeconds, MaxTraceSeconds)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.traceMu.TryLock() {
		http.Error(w, "a trace is already being captured", http.StatusConflict)
		return
	}
	defer s.traceMu.Unlock()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="woodshed.trace"`)
	if err := trace.Start(w); err != nil {
		w.Header().Del("Content-Disposition")
		http.Error(w, "can't start a trace: "+err.Error(), http.StatusConflict)
		return
	}
	s.log.Info("pprof: capturing a runtime trace", "seconds", d.Seconds())
	wait(r, d)
	trace.Stop()
}

func (s *Server) heap(w http.ResponseWriter, r *http.Request) {
	// A GC first, so the in-use numbers are current (as net/http/pprof's gc=1).
	runtime.GC()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="woodshed-heap.pprof"`)
	s.log.Info("pprof: writing a heap profile")
	if err := pprof.Lookup("heap").WriteTo(w, 0); err != nil {
		s.log.Warn("pprof: heap profile", "err", err)
	}
}

func (s *Server) goroutine(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	s.log.Info("pprof: writing a goroutine dump")
	if err := pprof.Lookup("goroutine").WriteTo(w, 2); err != nil {
		s.log.Warn("pprof: goroutine dump", "err", err)
	}
}
