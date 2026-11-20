package api

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/web"
)

// DefaultPort is the UI port (SPEC §5).
const DefaultPort = 8514

// UIConfig is how the UI server listens.
type UIConfig struct {
	// LANMode serves HTTPS on all interfaces with login. Off: plain HTTP on
	// 127.0.0.1 with no login.
	LANMode bool
	// Port is the UI port (0 picks a free one, for tests).
	Port int
	// CertFile and KeyFile optionally replace the self-signed certificate in
	// LAN mode. Both or neither.
	CertFile, KeyFile string
	// RequireLoginLocal makes localhost mode require the password too (once
	// one is set). It applies without a restart.
	RequireLoginLocal bool
	// ExtraHostnames (DNS names or IPs) are added to the self-signed
	// certificate; TrustedHosts are extra Host values accepted in localhost mode
	// (and as redirect targets in LAN mode). Both validated by config, and both
	// apply without a restart.
	ExtraHostnames, TrustedHosts []string
}

// Options configure a Server.
type Options struct {
	Backend Backend
	// DataDir holds the password hash and the self-signed certificate.
	DataDir string
	UI      UIConfig
	// Static is the UI to serve; nil means the embedded web.Dist.
	Static fs.FS
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// PortHolder, if set, names the process holding a TCP port ("" if unknown),
	// for the error when the UI port is taken.
	PortHolder func(port int) string

	// Test hooks (zero values are the real thing).
	now        func() time.Time
	argon      argonParams
	identity   func() (hostIdentity, error)
	lanAddr    string // host to bind in LAN mode ("" = all interfaces)
	retryAfter time.Duration
}

// ErrNoPassword is the reason LAN mode didn't start: no password is set.
var ErrNoPassword = errors.New("LAN mode needs a UI password; set one first")

// State describes what the UI server is doing, for `woodshed status`.
type State struct {
	Listening bool
	Addr      string // the bound address, e.g. "127.0.0.1:8514"
	URL       string // where to open the UI
	LANMode   bool   // serving LAN mode right now (not just configured)
	Err       error  // the last start error, if the server isn't listening or fell back
	// CertFingerprint is the SHA-256 of the certificate served in LAN mode
	// (AB:CD:…), "" in localhost mode.
	CertFingerprint string
}

// Server is the HTTP server for the API and the UI. Create it with New and run it
// with Run.
type Server struct {
	backend Backend
	dataDir string
	log     *slog.Logger
	now     func() time.Time
	auth    *auth
	static  *staticUI
	opts    Options
	handler http.Handler

	reconf chan struct{}

	mu      sync.Mutex
	want    UIConfig // the configured UI
	state   State
	changed chan struct{} // signalled (without blocking) when state changes

	lan          atomic.Bool                // the running server is in LAN mode
	requireLocal atomic.Bool                // ui.require_login_local
	certSrc      atomic.Pointer[certSource] // the LAN-mode certificate in use (nil in localhost mode)
	port         atomic.Int64               // the running server's port
	extraHosts   atomic.Pointer[[]string]   // ui.extra_hostnames
	trustedHosts atomic.Pointer[[]config.TrustedHost]
	// settingsMu serializes PUT /api/settings (the If-Match check and the save).
	settingsMu sync.Mutex

	addrMu    sync.Mutex // guards the two below: /api/status's ui_addrs, cached
	addrCache []string
	addrAt    time.Time
}

// uiAddrs is ui_addrs in /api/status: this machine's stable addresses (the
// certificate's, without loopback), IPv4 first. Cached for 30 s, since the
// status is polled.
func (s *Server) uiAddrs() []string {
	s.addrMu.Lock()
	defer s.addrMu.Unlock()
	if s.addrCache != nil && s.now().Sub(s.addrAt) < 30*time.Second {
		return slices.Clone(s.addrCache)
	}
	out := []string{}
	if id, err := s.opts.identity(); err == nil {
		for _, ip := range id.stableAddrs() {
			out = append(out, ip.String())
		}
	}
	s.addrCache, s.addrAt = out, s.now()
	return slices.Clone(out)
}

// New prepares a Server. It reads the password hash and the UI files but doesn't
// listen; call Run.
func New(opts Options) (*Server, error) {
	if opts.Backend == nil {
		return nil, errors.New("api: no backend")
	}
	if opts.DataDir == "" {
		return nil, errors.New("api: no data dir")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.now == nil {
		opts.now = time.Now
	}
	if opts.argon == (argonParams{}) {
		opts.argon = defaultArgon
	}
	if opts.identity == nil {
		opts.identity = localIdentity
	}
	if opts.retryAfter == 0 {
		opts.retryAfter = 10 * time.Second
	}
	if opts.Static == nil {
		sub, err := fs.Sub(web.Dist, "dist")
		if err != nil {
			return nil, err
		}
		opts.Static = sub
	}
	st, err := newStaticUI(opts.Static)
	if err != nil {
		return nil, fmt.Errorf("api: load the UI: %w", err)
	}
	s := &Server{
		backend: opts.Backend,
		dataDir: opts.DataDir,
		log:     opts.Logger,
		now:     opts.now,
		static:  st,
		opts:    opts,
		reconf:  make(chan struct{}, 1),
		changed: make(chan struct{}, 1),
		want:    opts.UI,
	}
	s.requireLocal.Store(opts.UI.RequireLoginLocal)
	s.setHosts(opts.UI.ExtraHostnames, opts.UI.TrustedHosts)
	s.auth, err = newAuth(opts.DataDir, opts.argon, opts.now, func(e Event) { s.event(e.Level, e.Kind, e.Text) })
	if err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	s.handler = s.buildHandler()
	return s, nil
}

// setHosts applies ui.extra_hostnames and ui.trusted_hosts. A new extra name
// makes the running LAN-mode certificate source re-check at once (it regenerates,
// keeping the key, if the name isn't covered).
func (s *Server) setHosts(extra, trusted []string) {
	extra = slices.Clone(extra)
	old := s.extraHosts.Swap(&extra)
	th := config.UI{TrustedHosts: trusted}.TrustedHostList()
	s.trustedHosts.Store(&th)
	if old != nil && !slices.Equal(*old, extra) {
		if cs := s.certSrc.Load(); cs != nil {
			cs.recheck()
			if _, err := cs.load(); err != nil {
				s.log.Warn("api: couldn't regenerate the UI certificate", "err", err)
			}
		}
	}
}

// identity is the host identity plus ui.extra_hostnames.
func (s *Server) identity() (hostIdentity, error) {
	id, err := s.opts.identity()
	if err != nil {
		return id, err
	}
	if p := s.extraHosts.Load(); p != nil {
		id = id.withExtras(*p)
	}
	return id, nil
}

// Handler is the full handler chain (headers, guards, auth, routes, UI), for
// tests and embedding.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) buildHandler() http.Handler {
	api := s.apiRoutes()
	root := http.NewServeMux()
	root.Handle("/api/", api)
	root.Handle("/api", api)
	root.Handle("/healthz", api)
	root.Handle("/", s.static)
	var h http.Handler = root
	h = s.requireSession(h)
	h = crossOriginGuard(h)
	h = s.hostGuard(h)
	h = recoverer(s.log, h)
	h = securityHeaders(h)
	return h
}

func (s *Server) lanActive() bool { return s.lan.Load() }
func (s *Server) boundPort() int  { return int(s.port.Load()) }

func (s *Server) currentUI() UIConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.want
}

// StateChanged is signalled whenever State changes (it holds at most one
// pending signal; read State after receiving).
func (s *Server) StateChanged() <-chan struct{} { return s.changed }

// setState sets the state and signals StateChanged.
func (s *Server) setState(st State) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
	s.signalChanged()
}

// State returns what the UI server is doing now.
func (s *Server) State() State {
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	if cs := s.certSrc.Load(); st.LANMode && cs != nil {
		st.CertFingerprint = cs.fingerprint()
	}
	return st
}

func (s *Server) signalChanged() {
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Reconfigure applies a new UI config: the server stops listening, ends open
// requests (live tails included) and starts again with cfg. It returns at once.
func (s *Server) Reconfigure(cfg UIConfig) {
	s.mu.Lock()
	s.want = cfg
	s.mu.Unlock()
	s.setHosts(cfg.ExtraHostnames, cfg.TrustedHosts)
	select {
	case s.reconf <- struct{}{}:
	default:
	}
}

func (s *Server) event(level, kind, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.backend.RecordEvent(ctx, Event{Level: level, Kind: kind, Text: text}); err != nil {
		s.log.Warn("api: could not record an event", "err", err)
	}
	switch level {
	case LevelError:
		s.log.Error("api: " + text)
	case LevelWarn:
		s.log.Warn("api: " + text)
	default:
		s.log.Info("api: " + text)
	}
}

// Run serves until ctx is done, restarting on Reconfigure. If the port can't be
// bound it logs the error, records an event, reports it in State, and retries.
// LAN mode without a password falls back to localhost mode (and says so).
func (s *Server) Run(ctx context.Context) error {
	var lastErr, lastLANErr string // repeated failures are recorded once
	for {
		cfg := s.currentUI()
		inst, err := s.start(cfg)
		var lanErr error
		if err != nil && cfg.LANMode && !isListenError(err) {
			// Don't leave the machine without a UI: serve on localhost and say why.
			lanErr = err
			if msg := "LAN mode didn't start: " + err.Error() + ". Serving the UI on localhost only."; msg != lastLANErr {
				s.event(LevelError, EventKindUI, msg)
				lastLANErr = msg
			}
			fallback := cfg
			fallback.LANMode = false
			inst, err = s.start(fallback)
		}
		if err != nil {
			msg := fmt.Sprintf("UI server can't listen on port %d: %v", cfg.Port, err)
			if s.opts.PortHolder != nil && isListenError(err) {
				if h := s.opts.PortHolder(cfg.Port); h != "" {
					msg += " (held by " + h + ")"
				}
			}
			if msg != lastErr {
				s.event(LevelError, EventKindUI, msg)
				lastErr = msg
			}
			s.setState(State{Err: err})
			select {
			case <-ctx.Done():
				return nil
			case <-s.reconf:
			case <-time.After(s.opts.retryAfter):
			}
			continue
		}
		lastErr = ""
		if lanErr == nil {
			lastLANErr = ""
		}
		s.setState(State{Listening: true, Addr: inst.addr, URL: inst.url, LANMode: inst.lan, Err: lanErr})
		mode := "localhost mode"
		if inst.lan {
			mode = "LAN mode"
		}
		s.event(LevelInfo, EventKindUI, fmt.Sprintf("UI serving at %s (%s).", inst.url, mode))

		select {
		case <-ctx.Done():
			inst.stop()
			s.setState(State{})
			return nil
		case <-s.reconf:
			inst.stop()
		case err := <-inst.done:
			// The listener failed underneath us; start again.
			s.log.Error("api: UI server stopped", "err", err)
			inst.stop()
		}
	}
}

// isListenError reports whether err came from binding the port (as opposed to
// LAN-mode setup such as the password or certificate).
func isListenError(err error) bool {
	var oe *net.OpError
	return errors.As(err, &oe) && oe.Op == "listen"
}

// instance is one running HTTP server.
type instance struct {
	lan      bool
	addr     string
	url      string
	ln       net.Listener
	servers  []*http.Server
	conns    connTracker
	cancel   context.CancelFunc
	done     chan error
	stopOnce sync.Once
}

// connTracker follows the servers' connections, so stop can close the ones
// with no request in flight at once. http.Server.Shutdown closes idle
// keep-alive connections itself, but treats a new connection that hasn't sent
// a request yet (a browser's preconnect) as busy for its first 5 s, which held
// every shutdown and UI restart that long.
type connTracker struct {
	mu    sync.Mutex
	conns map[net.Conn]http.ConnState
}

func (t *connTracker) hook(c net.Conn, st http.ConnState) {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch st {
	case http.StateHijacked, http.StateClosed:
		delete(t.conns, c)
	default:
		if t.conns == nil {
			t.conns = map[net.Conn]http.ConnState{}
		}
		t.conns[c] = st
	}
}

// closeQuiet closes every connection that is new (no request yet) or idle.
func (t *connTracker) closeQuiet() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for c, st := range t.conns {
		if st == http.StateNew || st == http.StateIdle {
			c.Close()
			delete(t.conns, c)
		}
	}
}

// start binds and serves cfg.
func (s *Server) start(cfg UIConfig) (*instance, error) {
	inst := &instance{lan: cfg.LANMode, done: make(chan error, 2)}
	var tlsCfg *tls.Config
	host := "127.0.0.1"
	if cfg.LANMode {
		if !s.auth.passwordSet() {
			return nil, ErrNoPassword
		}
		cs := &certSource{
			dataDir:  s.dataDir,
			userCert: cfg.CertFile,
			userKey:  cfg.KeyFile,
			now:      s.now,
			identity: s.identity,
			onGenerate: func(reason string) {
				s.event(LevelInfo, EventKindUI, "Generated a self-signed UI certificate ("+reason+").")
				s.signalChanged() // the fingerprint in State changed
			},
		}
		if _, err := cs.load(); err != nil { // fail now, not on the first handshake
			return nil, err
		}
		s.certSrc.Store(cs)
		tlsCfg = cs.tlsConfig()
		host = s.opts.lanAddr
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(cfg.Port)))
	if err != nil {
		return nil, err
	}
	inst.ln = ln
	port := ln.Addr().(*net.TCPAddr).Port
	inst.addr = ln.Addr().String()
	baseCtx, cancel := context.WithCancel(context.Background())
	inst.cancel = cancel

	// Switch modes before the first request arrives on the new listener.
	s.lan.Store(cfg.LANMode)
	s.port.Store(int64(port))

	newServer := func(h http.Handler) *http.Server {
		return &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
			BaseContext:       func(net.Listener) context.Context { return baseCtx },
			ConnState:         inst.conns.hook,
			ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		}
	}
	serve := func(srv *http.Server, l net.Listener) {
		inst.servers = append(inst.servers, srv)
		go func() {
			if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
				inst.done <- err
			}
		}()
	}
	if !cfg.LANMode {
		s.certSrc.Store(nil)
		inst.url = fmt.Sprintf("http://localhost:%d/", port)
		serve(newServer(s.handler), ln)
		return inst, nil
	}
	// LAN mode: TLS and plain HTTP share the port. TLS connections get the UI;
	// plain HTTP ones get a redirect to https, so an open http:// tab finds its
	// way after the switch.
	inst.url = fmt.Sprintf("https://%s/", net.JoinHostPort(displayHost(s.identity), strconv.Itoa(port)))
	sp := newSplitListener(ln)
	serve(newServer(s.handler), tls.NewListener(sp.tls, tlsCfg))
	serve(newServer(securityHeaders(http.HandlerFunc(s.redirectToHTTPS))), sp.plain)
	return inst, nil
}

// displayHost is the host name for the UI URL in LAN mode.
func displayHost(identity func() (hostIdentity, error)) string {
	if id, err := identity(); err == nil {
		if id.Host != "" {
			return id.Host
		}
		for _, n := range id.Names {
			if n != "localhost" {
				return n
			}
		}
	}
	return "localhost"
}

// stop closes the listener, cancels every request context (ending live tails),
// closes connections with no request in flight, and waits briefly for handlers
// to finish.
func (inst *instance) stop() {
	inst.stopOnce.Do(func() {
		inst.cancel()
		for _, srv := range inst.servers {
			srv.SetKeepAlivesEnabled(false) // active connections close after their response
		}
		_ = inst.ln.Close() // no new connections
		inst.conns.closeQuiet()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// A connection accepted just before the listener closed may reach the
		// tracker (StateNew) only after the closeQuiet above, and Shutdown would
		// then wait its 5 s for it: keep closing quiet ones until Shutdown is done.
		sweepDone := make(chan struct{})
		defer close(sweepDone)
		go func() {
			t := time.NewTicker(20 * time.Millisecond)
			defer t.Stop()
			for {
				select {
				case <-sweepDone:
					return
				case <-t.C:
					inst.conns.closeQuiet()
				}
			}
		}()
		var wg sync.WaitGroup
		for _, srv := range inst.servers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := srv.Shutdown(ctx); err != nil {
					_ = srv.Close()
				}
			}()
		}
		wg.Wait()
		_ = inst.ln.Close()
	})
}

// redirectToHTTPS sends plain-HTTP requests in LAN mode to https on the
// listening port, path only (no query). The host is the one the client used
// when it's one of this machine's names or addresses, and the machine's own
// name otherwise, so the redirect never points at a host the client made up.
func (s *Server) redirectToHTTPS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeError(w, http.StatusBadRequest, "This server uses HTTPS in LAN mode.")
		return
	}
	host := displayHost(s.identity)
	h := r.Host
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.ToLower(strings.TrimSuffix(strings.Trim(h, "[]"), "."))
	if id, err := s.identity(); err == nil && h != "" {
		ip, ipErr := netip.ParseAddr(h)
		if slices.Contains(id.Names, h) || (ipErr == nil && slices.Contains(id.IPs, ip.Unmap().WithZone(""))) {
			host = h
		}
	}
	if s.trustedHost(r.Host) {
		host = h
	}
	target := "https://" + net.JoinHostPort(host, strconv.Itoa(s.boundPort())) + r.URL.EscapedPath()
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// splitListener sorts accepted connections into TLS and plain by their first
// byte (0x16 starts a TLS handshake).
type splitListener struct {
	tls, plain *chanListener

	mu      sync.Mutex
	pending map[net.Conn]bool // accepted, first byte not seen yet
	closed  bool
}

func newSplitListener(ln net.Listener) *splitListener {
	closed := make(chan struct{})
	sp := &splitListener{
		tls:     &chanListener{addr: ln.Addr(), conns: make(chan net.Conn), closed: closed, parent: ln},
		plain:   &chanListener{addr: ln.Addr(), conns: make(chan net.Conn), closed: closed, parent: ln},
		pending: map[net.Conn]bool{},
	}
	var once sync.Once
	sp.tls.closeAll = func() {
		once.Do(func() {
			close(closed)
			// Connections still waiting for their first byte belong to no server
			// yet, so no Shutdown would close them.
			sp.mu.Lock()
			sp.closed = true
			for c := range sp.pending {
				c.Close()
			}
			sp.pending = nil
			sp.mu.Unlock()
		})
	}
	sp.plain.closeAll = sp.tls.closeAll
	go func() {
		defer sp.tls.closeAll()
		for {
			c, err := ln.Accept()
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				return
			}
			go sp.route(c)
		}
	}()
	return sp
}

func (sp *splitListener) route(c net.Conn) {
	sp.mu.Lock()
	if sp.closed {
		sp.mu.Unlock()
		c.Close()
		return
	}
	sp.pending[c] = true
	sp.mu.Unlock()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var b [1]byte
	_, err := io.ReadFull(c, b[:])
	sp.mu.Lock()
	delete(sp.pending, c)
	sp.mu.Unlock()
	if err != nil {
		c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	pc := &peekedConn{Conn: c, first: b[0], has: true}
	target := sp.plain
	if b[0] == 0x16 {
		target = sp.tls
	}
	select {
	case target.conns <- pc:
	case <-target.closed:
		c.Close()
	}
}

// peekedConn replays one byte already read.
type peekedConn struct {
	net.Conn
	first byte
	has   bool
}

func (c *peekedConn) Read(p []byte) (int, error) {
	if c.has && len(p) > 0 {
		p[0] = c.first
		c.has = false
		if len(p) == 1 {
			return 1, nil
		}
		n, err := c.Conn.Read(p[1:])
		return n + 1, err
	}
	return c.Conn.Read(p)
}

// chanListener is a net.Listener fed by splitListener.
type chanListener struct {
	addr     net.Addr
	conns    chan net.Conn
	closed   chan struct{}
	closeAll func()
	parent   net.Listener
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.closeAll()
	return l.parent.Close()
}

func (l *chanListener) Addr() net.Addr { return l.addr }
