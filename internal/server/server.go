// Package server assembles Woodshed's parts into the running service: the config,
// the index, the store, the syslog listeners, the live hub and the HTTP API.
//
// Open loads (or creates) the config, validates it, takes the data dir's lock and
// opens the index and the store. Run starts the listeners and the UI and serves
// until its context ends, then shuts down in order: listeners, live hub, UI, store
// (flushed and fsynced), index.
//
// A syslog port that can't be bound never stops the service (SPEC §2, "Port 514 in
// use"): that listener stays down, the UI starts anyway and shows a banner, and
// Retry rebinds it.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/export"
	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/peer"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/updatecheck"
)

// DefaultShutdownTimeout bounds the whole shutdown. It stays under the 20 s the
// Windows service manager waits by default.
const DefaultShutdownTimeout = 15 * time.Second

// Options configures a Server. Zero fields take defaults.
type Options struct {
	Version     string // shown in /api/status and the About page
	Commit      string // the build (short commit hash)
	ReleasesURL string // build-time constant; empty until the project has a public home

	Logger          *slog.Logger  // default slog.Default()
	ShutdownTimeout time.Duration // default DefaultShutdownTimeout

	// Service says the OS service manager runs this server: a data folder that
	// Everyone, Users or Authenticated Users can open then stops it from starting
	// (re-test N2), unless AllowSharedDataDir is set.
	Service            bool
	AllowSharedDataDir bool

	// FindPeer looks for another running Woodshed (default peer.Find, which asks
	// the OS service manager). Tests replace it.
	FindPeer func(context.Context, peer.Options) (peer.Info, bool)

	// updateTesting points the update check at a test server, on a fake clock
	// (tests in this package only; nothing else can set it).
	updateTesting *updatecheck.TestHooks
}

// Server is an opened Woodshed service. Call Run once.
type Server struct {
	opts    Options
	log     *slog.Logger
	cfgPath string
	created bool // Open created the config file

	lock    *DirLock
	idx     *index.DB
	store   *store.Store
	search  *search.Engine
	exports *export.Manager
	hub     *hub.Hub
	api     *api.Server
	be      *backend

	ran bool
}

// Open loads the config at cfgPath (creating it with defaults if it's missing),
// validates it, takes the data dir's lock and opens the index and the store. The
// listeners and the UI start in Run. On error nothing is left open.
func Open(cfgPath string, opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.ShutdownTimeout <= 0 {
		opts.ShutdownTimeout = DefaultShutdownTimeout
	}
	if opts.Version == "" {
		opts.Version = "0.0.0-dev"
	}
	if opts.Commit == "" {
		opts.Commit = "none"
	}
	log := opts.Logger

	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("config path %q: %w", cfgPath, err)
	}
	// Folders this start creates are protected as they're created (re-test N2):
	// LoadConfig writes a new config, creating its folder, which on Windows would
	// otherwise inherit ProgramData's ACL (Users may read and create).
	createdHere := map[string]bool{}
	if cd := filepath.Dir(abs); !exists(cd) {
		if err := makeProtectedDir(cd); err != nil {
			return nil, fmt.Errorf("create the config folder: %w", err)
		}
		createdHere[filepath.Clean(cd)] = true
	}
	cfg, created, err := LoadConfig(abs)
	if err != nil {
		return nil, err
	}
	if created {
		log.Info("created a default config", "path", abs, "data_dir", cfg.Storage.DataDir)
	}
	if errs := cfg.Validate(nil); len(errs) > 0 {
		return nil, fmt.Errorf("%s has invalid settings: %w", abs, errs)
	}
	dataDir := cfg.Storage.DataDir
	if !exists(dataDir) {
		// A folder created here (not by an installer) gets, on Windows, a protected
		// ACL for this account, SYSTEM and Administrators (security review M3).
		if err := makeProtectedDir(dataDir); err != nil {
			return nil, fmt.Errorf("create the data folder: %w", err)
		}
		createdHere[filepath.Clean(dataDir)] = true
	}
	sharedBanner, err := checkSharedDataDir(dataDir, createdHere[filepath.Clean(dataDir)], opts, log)
	if err != nil {
		return nil, err
	}

	s := &Server{opts: opts, log: log, cfgPath: abs, created: created}
	ok := false
	defer func() {
		if !ok {
			s.closeOpened()
		}
	}()

	if s.lock, err = LockDataDir(dataDir); err != nil {
		if errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("%w: stop it first (`woodshed status` shows what's running)", err)
		}
		return nil, fmt.Errorf("data folder %s: %w", dataDir, err)
	}
	if s.idx, err = index.Open(filepath.Join(dataDir, index.FileName)); err != nil {
		return nil, fmt.Errorf("open the index: %w", err)
	}
	// Search and exports read the files through the index. The export queue
	// opens before the store so the store's low-disk guard can delete exports
	// before any log.
	s.search = search.New(search.Options{DataDir: dataDir, Index: s.idx, Logger: log})
	if s.exports, err = export.Open(export.Options{DataDir: dataDir, Index: s.idx, Search: s.search, Version: opts.Version, Logger: log}); err != nil {
		return nil, fmt.Errorf("open the exports folder: %w", err)
	}
	// store.Open repairs the data dir after a crash and reconciles the index with
	// the files on disk.
	t0 := time.Now()
	if s.store, err = store.Open(store.Options{
		DataDir:             dataDir,
		Index:               s.idx,
		PartBytes:           cfg.Storage.PartBytes,
		RetentionDays:       cfg.Storage.RetentionDays,
		RetentionBytes:      cfg.Storage.RetentionBytes,
		MaxDevices:          cfg.Listeners.MaxDevices,
		NewDeviceBurst:      cfg.Listeners.NewDeviceBurst,
		NewDevicesPerMinute: float64(cfg.Listeners.NewDevicesPerMinute),
		Reclaim:             s.exports.Reclaim,
		Logger:              log,
	}); err != nil {
		return nil, fmt.Errorf("open the log store: %w", err)
	}
	log.Info("store open", "data_dir", dataDir, "took", time.Since(t0).Round(time.Millisecond))

	s.be = newBackend(backendDeps{
		cfgPath: abs,
		cfg:     cfg,
		idx:     s.idx,
		store:   s.store,
		log:     log,
		version: opts.Version,
		commit:  opts.Commit,
		release: opts.ReleasesURL,
		search:  s.search,
		exports: s.exports,
	})
	s.be.peers.find = opts.FindPeer
	// The update check: nothing touches the network unless updates.check is "on"
	// in a release build (SPEC §10.2).
	s.be.updates = updatecheck.New(updatecheck.Options{
		Version: opts.Version, ReleasesURL: opts.ReleasesURL, DataDir: dataDir,
		Check: cfg.Updates.Check, Logger: log, Testing: opts.updateTesting,
	})
	s.be.tlsc = newTLSSide(dataDir, cfg.Listeners.TLS, time.Now, func() []string { return s.be.config().UI.ExtraHostnames })
	// Turned on in the config (by `woodshed tls on`, or by hand) while stopped:
	// the CA and the certificate are made now. A failure shows on the listener.
	_ = s.be.prepareTLS(cfg.Listeners.TLS)
	s.be.applyTLSRenewRequest(dataDir)
	if sharedBanner != nil {
		s.be.startupBanners = append(s.be.startupBanners, *sharedBanner)
		s.be.serviceEvent(index.LevelError, index.KindError, sharedBanner.Text)
	}
	s.hub = hub.New(hub.Options{GroupOf: s.be.groupOf, HiddenOf: s.be.hiddenOf})
	s.be.hub = s.hub
	if err := s.be.refreshGroups(context.Background()); err != nil {
		return nil, fmt.Errorf("read devices from the index: %w", err)
	}

	if s.api, err = api.New(api.Options{
		Backend: s.be,
		DataDir: dataDir,
		UI:      uiConfig(cfg.UI),
		Logger:  log,
		// When the UI port is taken, say who holds it (as the service, it can see).
		PortHolder: func(port int) string { return listen.PortHolder("tcp", port) },
	}); err != nil {
		return nil, fmt.Errorf("prepare the UI server: %w", err)
	}
	s.be.isService = opts.Service
	s.be.uiListening = func() bool { return s.api.State().Listening }
	ok = true
	return s, nil
}

// LoadConfig reads the config at path, creating it with defaults when it's
// missing, and reports whether it did. A new config at the OS's default path
// gets the OS's default data dir; one anywhere else keeps its data next to it
// (woodshed-data in the config file's folder), so `woodshed run --config
// ./x/woodshed.toml` is self-contained. LoadConfig doesn't validate.
func LoadConfig(path string) (config.Config, bool, error) {
	c, created, err := config.LoadOrCreate(path, NewConfigFor(path))
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return c, false, fmt.Errorf("%w (run as the service's user or an administrator, or pass --config)", err)
		}
		return c, false, err
	}
	return c, created, nil
}

// NewConfigFor is the config LoadConfig creates at a missing path (it writes
// nothing).
func NewConfigFor(path string) config.Config {
	def := config.Default()
	if !samePath(path, config.DefaultConfigPath()) {
		// woodshed-data next to the config, never the config's folder itself:
		// `--config /etc/woodshed.toml` must not make /etc the data folder (review M2).
		def.Storage.DataDir = filepath.Join(filepath.Dir(path), "woodshed-data")
	}
	return def
}

func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		return equalFold(a, b)
	}
	return a == b
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func uiConfig(u config.UI) api.UIConfig {
	return api.UIConfig{LANMode: u.LANMode, Port: u.Port, CertFile: u.CertFile, KeyFile: u.KeyFile, RequireLoginLocal: u.RequireLoginLocal,
		ExtraHostnames: u.ExtraHostnames, TrustedHosts: u.TrustedHosts}
}

// ConfigPath returns the absolute config path.
func (s *Server) ConfigPath() string { return s.cfgPath }

// DataDir returns the data dir in use.
func (s *Server) DataDir() string { return s.be.config().Storage.DataDir }

// UIState reports what the UI server is doing.
func (s *Server) UIState() api.State { return s.api.State() }

// Run starts the listeners and the UI and serves until ctx is done, then shuts
// down cleanly. It returns nil after a clean shutdown, or an error if the
// shutdown didn't finish within the timeout (the store may then have lost up to
// its last few seconds of data).
func (s *Server) Run(ctx context.Context) error {
	if s.ran {
		return errors.New("server: Run called twice")
	}
	s.ran = true
	log := s.log
	cfg := s.be.config()
	started := time.Now().UTC()
	s.be.startedAt = started
	s.be.serviceEvent(index.LevelInfo, index.KindStart,
		fmt.Sprintf("Woodshed %s (%s) started on %s/%s; data folder %s.", s.opts.Version, s.opts.Commit, runtime.GOOS, runtime.GOARCH, cfg.Storage.DataDir))

	ln, err := listen.Start(cfg.Listeners, listen.Options{
		Sink:        s.be.sink,
		OnQueueDrop: s.be.store.DropQueued,
		// A third of the shutdown for draining the UDP queue, leaving the rest
		// for the store's flush and the index.
		DrainTimeout:   s.opts.ShutdownTimeout / 3,
		OnEvent:        s.be.listenEvent,
		Logger:         log,
		TLSCertificate: s.be.tlsc.certs.Certificate,
	})
	if err != nil {
		// Only an invalid allowlist gets here, and Validate already checked it.
		s.shutdown(nil, nil, nil)
		return fmt.Errorf("start the listeners: %w", err)
	}
	s.be.setListeners(ln)
	s.exports.Start()
	// The listeners log what they bound and the UDP buffer the OS granted; a
	// buffer too small for bursts is a warning (and a banner).
	lst := ln.Status()
	if udpBufferBanner(runtime.GOOS, lst.UDPRcvbufBytes, lst.UDPRcvbufRequestedBytes) != nil {
		log.Warn("UDP receive buffer is smaller than requested: "+udpBufferText(lst.UDPRcvbufBytes, lst.UDPRcvbufRequestedBytes),
			"rcvbuf_granted", lst.UDPRcvbufBytes, "rcvbuf_requested", lst.UDPRcvbufRequestedBytes)
	}
	for _, l := range lst.Listeners {
		if !l.OK {
			log.Error("listener didn't start; the UI shows a banner with Retry", "proto", l.Proto, "addr", l.Addr,
				"port", l.Port, "err", l.Error, "holder", l.Holder)
		}
	}

	apiCtx, apiCancel := context.WithCancel(context.Background())
	apiDone := make(chan error, 1)
	go func() { apiDone <- s.api.Run(apiCtx) }()

	stateDone := make(chan struct{})
	stateStop := make(chan struct{})
	go func() {
		defer close(stateDone)
		s.watchState(started, stateStop)
	}()

	retentionDone := make(chan struct{})
	go func() {
		defer close(retentionDone)
		s.be.watchRetention(stateStop)
	}()

	updCtx, updCancel := context.WithCancel(context.Background())
	updDone := make(chan struct{})
	go func() {
		defer close(updDone)
		s.be.updates.Run(updCtx)
	}()

	select {
	case <-ctx.Done():
	case err := <-apiDone:
		// api.Run returns only when its context ends; treat anything else as fatal.
		log.Error("UI server stopped unexpectedly", "err", err)
		apiDone <- err
	}
	log.Info("shutting down")
	updCancel() // a check in flight is cancelled
	close(stateStop)
	<-stateDone
	<-retentionDone
	<-updDone
	return s.shutdown(ln, apiCancel, apiDone)
}

// shutdown stops everything in order within the timeout: the listeners (no more
// messages), the live hub (ends live tails), the UI server, the store (flush,
// fsync, index update) and the index. ln and the api parts may be nil when Run
// failed early.
func (s *Server) shutdown(ln *listen.Server, apiCancel context.CancelFunc, apiDone chan error) error {
	timeout := s.opts.ShutdownTimeout
	var mu sync.Mutex
	step, stepStart := "starting", time.Now()
	setStep := func(v string) {
		mu.Lock()
		if d := time.Since(stepStart); d > time.Second {
			s.log.Warn("shutdown step was slow", "step", step, "took", d.Round(time.Millisecond))
		}
		step, stepStart = v, time.Now()
		mu.Unlock()
	}

	done := make(chan error, 1)
	go func() {
		var errs []error
		if ln != nil {
			setStep("stopping the listeners")
			// Close drains the UDP queue into the store first (bounded).
			if err := ln.Close(); err != nil {
				errs = append(errs, fmt.Errorf("listeners: %w", err))
			}
			st := ln.Status()
			var queueDropped int64
			for _, q := range st.UDPQueues {
				queueDropped += q.Dropped
			}
			s.log.Info("listeners stopped", "received", st.Received, "truncated", st.Truncated, "rejected", st.Rejected,
				"udp_queue_dropped", queueDropped)
		}
		setStep("closing the live hub")
		s.hub.Close()
		if apiCancel != nil {
			setStep("stopping the UI server")
			apiCancel()
			<-apiDone
		}
		setStep("stopping the export queue")
		s.exports.Close() // a build in progress is cancelled (marked failed)
		setStep("flushing and closing the store")
		before := s.store.Usage().Written
		if err := s.store.Close(); err != nil {
			errs = append(errs, fmt.Errorf("store: %w", err))
		}
		u := s.store.Usage()
		s.log.Info("store closed", "written", u.Written, "dropped", u.Dropped, "flushed_at_stop", u.Written-before)
		level := index.LevelInfo
		text := "Woodshed stopped."
		if len(errs) > 0 {
			level, text = index.LevelError, "Woodshed stopped with errors: "+errors.Join(errs...).Error()
		}
		s.be.serviceEvent(level, index.KindStop, text)
		setStep("closing the index")
		if err := s.idx.Close(); err != nil {
			errs = append(errs, fmt.Errorf("index: %w", err))
		}
		setStep("done")
		removeState(s.be.config().Storage.DataDir)
		if err := s.lock.Unlock(); err != nil {
			errs = append(errs, fmt.Errorf("unlock: %w", err))
		}
		done <- errors.Join(errs...)
	}()

	select {
	case err := <-done:
		if err != nil {
			s.log.Error("shutdown finished with errors", "err", err)
			return err
		}
		s.log.Info("stopped cleanly")
		return nil
	case <-time.After(timeout):
		mu.Lock()
		at := step
		mu.Unlock()
		err := fmt.Errorf("shutdown didn't finish within %v (stuck %s)", timeout, at)
		s.log.Error("shutdown timed out", "err", err)
		return err
	}
}

// closeOpened closes what Open managed to open, after an Open error.
func (s *Server) closeOpened() {
	if s.store != nil {
		_ = s.store.Close()
	}
	if s.exports != nil {
		s.exports.Close()
	}
	if s.hub != nil {
		s.hub.Close()
	}
	if s.idx != nil {
		_ = s.idx.Close()
	}
	if s.lock != nil {
		_ = s.lock.Unlock()
	}
}

// Close releases everything Open opened, for a Server that never ran.
func (s *Server) Close() error {
	if s.ran {
		return nil
	}
	s.ran = true
	s.closeOpened()
	return nil
}

// watchState keeps the run-state file (read by `woodshed status`) current until
// stop closes.
func (s *Server) watchState(started time.Time, stop <-chan struct{}) {
	dataDir := s.be.config().Storage.DataDir
	var last RunState
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for first := true; ; first = false {
		ui := s.api.State()
		rs := RunState{
			PID:       os.Getpid(),
			Version:   s.opts.Version,
			StartedAt: started,
			Config:    s.cfgPath,
			DataDir:   dataDir,
			UI:        RunStateUI{Listening: ui.Listening, URL: ui.URL, LANMode: ui.LANMode, CertFingerprint: ui.CertFingerprint},
		}
		if ui.Err != nil {
			rs.UI.Error = ui.Err.Error()
		}
		s.be.fillRunState(&rs)
		if first || !reflect.DeepEqual(rs, last) {
			if err := writeState(dataDir, rs); err != nil {
				// Try again on the next tick (on Windows a reader or a virus scanner
				// holding the file makes the rename fail): last stays as it was.
				s.log.Warn("couldn't write the run-state file", "err", err)
			} else {
				if rs.UI != last.UI {
					if rs.UI.Listening {
						s.log.Info("UI ready", "url", rs.UI.URL)
					} else if rs.UI.Error != "" {
						s.log.Error("UI isn't listening", "err", rs.UI.Error)
					}
				}
				last = rs
			}
		}
		// The UI's state changes are written at once (woodshed status reads the
		// file); the tick retries failed writes.
		select {
		case <-stop:
			return
		case <-t.C:
		case <-s.api.StateChanged():
		}
	}
}
