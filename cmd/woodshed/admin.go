package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/peer"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/service"
)

// The service manager, through these so tests never reach the real one
// (launchctl, systemctl, the SCM). TestMain replaces them.
var (
	serviceInstall   = service.Install
	serviceUninstall = service.Uninstall
	serviceStatus    = service.Status
	serviceRestart   = service.Restart
	serviceLegacy    = service.DetectLegacy // what Woodpile, the old name, left behind
	findPeer         = peer.Find            // passed to server.Open: the server's own lookup of the service
	// What status assumes when it can't read the config, so tests never reach a real
	// server on the default UI port.
	defaultConfig = config.Default
)

// ---- install / uninstall ----

func cmdInstall(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("install", "", `
Install Woodshed as a system service (`+service.Name(runtime.GOOS)+`) and start it, set up
the way Woodshed's installer package does it: the same service definition, the
same unprivileged account (`+installAccount()+`), the same folders and
permissions. The binary is copied to `+installedExe()+`.
Needs administrator rights (sudo, or an administrator prompt on Windows).

This is for machines without the package. If the package already installed the
service, install refuses, so there's never a second one.`, stderr)
	cfg := configFlag(fs)
	dataDir := fs.String("data-dir", config.DefaultDataDir(), "data `folder` (logs, index); the config must name the same one")
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	res, err := serviceInstall(service.InstallOptions{ConfigPath: *cfg, DataDir: *dataDir, Version: version,
		Out: &headed{w: stdout, head: "Installing the Woodshed service:"}})
	if err != nil {
		return fail(stderr, "install", err)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(stdout, "  note: %s\n", n)
	}
	fmt.Fprintf(stdout, "Installed and started %s, running as %s.\n", res.Where, res.Account)
	fmt.Fprintf(stdout, "Config: %s\nData:   %s\nUI:     %s (run `woodshed status` to check the listeners)\n",
		res.Config, res.DataDir, uiURL(readConfigOrDefault(res.Config)))
	return 0
}

// headed prints head before the first progress line, so a refusal (which
// happens before any) prints only the error.
type headed struct {
	w    io.Writer
	head string
	done bool
}

func (h *headed) Write(p []byte) (int, error) {
	if !h.done {
		h.done = true
		fmt.Fprintln(h.w, h.head)
	}
	return h.w.Write(p)
}

func installAccount() string {
	switch runtime.GOOS {
	case "windows":
		return service.WindowsAccount
	case "darwin":
		return service.DarwinUser
	}
	return service.LinuxUser
}

func installedExe() string {
	if runtime.GOOS == "windows" {
		return `%ProgramFiles%\Woodshed\woodshed.exe`
	}
	return "/usr/local/bin/woodshed"
}

func cmdUninstall(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("uninstall", "", `
Stop and remove the system service installed by "woodshed install", and the
binary it copied. The config and the received logs are kept unless you pass
--delete-logs. Needs administrator rights.

A service installed by Woodshed's package is left alone: remove the package
instead (the error says how).`, stderr)
	deleteLogs := fs.Bool("delete-logs", false, "also delete the data folder (logs, index, config)"+map[bool]string{true: " and the _woodshed account"}[runtime.GOOS == "darwin"])
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	res, err := serviceUninstall(service.UninstallOptions{DeleteLogs: *deleteLogs, Out: &headed{w: stdout, head: "Removing the Woodshed service:"}})
	if err != nil {
		return fail(stderr, "uninstall", err)
	}
	for _, n := range res.Notes {
		fmt.Fprintf(stdout, "  note: %s\n", n)
	}
	if *deleteLogs {
		fmt.Fprintln(stdout, "Woodshed is uninstalled, and its logs and config are deleted.")
	} else {
		fmt.Fprintln(stdout, "Woodshed is uninstalled. The logs and config are kept.")
	}
	return 0
}

// ---- status ----

func cmdStatus(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("status", "", `
Show the service's state, the syslog listeners and the UI address. It asks the
running server over its local API; if nothing answers, it says so. Without root
(administrator rights on Windows) it can't read the config: it says so and
assumes the defaults.

Exit status: 0 when the server answers, 1 when it isn't running or can't be
reached.`, stderr)
	cfgPath := configFlag(fs)
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	cfg, cfgErr := readConfig(*cfgPath)
	if cfgErr != nil {
		cfg = defaultConfig()
	}
	fullStatus := "status"
	if *cfgPath != config.DefaultConfigPath() {
		fullStatus += " --config " + shellQuote(*cfgPath)
	}

	w := &tabw{w: stdout}
	st, stErr := serviceStatus()
	svc := string(st)
	if stErr != nil {
		svc += " (" + stErr.Error() + ")"
	}
	w.row("Service", fmt.Sprintf("%s (%s, %s)", svc, service.Name(runtime.GOOS), service.Platform()))
	switch {
	case errors.Is(cfgErr, os.ErrPermission):
		// The installers keep the config folder private to the service. A normal user
		// still gets the service state, and the server's own answer when its UI is on
		// the default port.
		w.row("Config", fmt.Sprintf("%s can't be read without %s; assuming the defaults", *cfgPath, adminWord()))
		w.row("", "for the full status, run: "+asAdmin(fullStatus))
	case cfgErr != nil:
		w.row("Config", fmt.Sprintf("%s: %v; assuming the defaults", *cfgPath, cfgErr))
	default:
		w.row("Config", *cfgPath)
	}
	if old, err := serviceLegacy(); err == nil {
		for _, n := range []string{old.ServiceNote(), old.DataNote()} {
			if n != "" {
				w.row("Woodpile", n)
			}
		}
	}

	status, apiErr := fetchStatus(cfg)
	if cfgErr != nil && apiErr != nil && !errors.Is(apiErr, errNeedsLogin) && !cfg.UI.LANMode {
		// Without the config, the scheme is a guess: in LAN mode the UI is HTTPS.
		lan := cfg
		lan.UI.LANMode = true
		if st, err := fetchStatus(lan); err == nil || errors.Is(err, errNeedsLogin) {
			cfg, status, apiErr = lan, st, err
		}
	}
	switch {
	case apiErr == nil:
		w.row("Server", fmt.Sprintf("running, version %s (%s), up since %s", status.Version, status.Build,
			status.StartedAt.Local().Format("2006-01-02 15:04:05")))
		listenerRows(w, status.Listeners)
		uiRows(w, cfg, status.UICertFingerprint)
		statusTLSRows(w, cfg, nil)
		statusSNMPRows(w, cfg, nil)
		statusPollRows(w, cfg, nil, time.Now())
		w.row("Data", status.DataDir)
		if cfgErr == nil {
			updateRows(w, cfg, status.Version)
		}
		bannerRows(w, status.Banners)
		return 0
	case errors.Is(apiErr, errNeedsLogin):
		// The run-state file has what /api/status would say. Whoever can read the
		// data folder (root, or the service account) can read the logs anyway.
		rs, err := server.ReadState(cfg.Storage.DataDir)
		if err != nil {
			w.row("Server", "running; the UI needs a login")
			w.row("Listeners", "log in to the UI to see them, or run "+asAdmin(fullStatus))
			uiRows(w, cfg, "")
			return 0
		}
		w.row("Server", fmt.Sprintf("running (pid %d), version %s, up since %s; the UI needs a login", rs.PID, rs.Version,
			rs.StartedAt.Local().Format("2006-01-02 15:04:05")))
		if rs.Listeners == nil {
			w.row("Listeners", "not started yet")
		} else {
			listenerRows(w, rs.Listeners)
		}
		uiRows(w, cfg, rs.UI.CertFingerprint)
		statusTLSRows(w, cfg, &rs)
		statusSNMPRows(w, cfg, &rs)
		statusPollRows(w, cfg, &rs, time.Now())
		w.row("Data", cfg.Storage.DataDir)
		if cfgErr == nil {
			updateRows(w, cfg, rs.Version)
		}
		bannerRows(w, rs.Banners)
		return 0
	}

	// Nothing (or something else) answers on the UI port. The data dir's lock
	// says whether a server is running anyway.
	inUse, lockErr := server.DataDirInUse(cfg.Storage.DataDir)
	switch {
	case inUse:
		msg := "running, but its UI doesn't answer on " + uiURL(cfg)
		if rs, err := server.ReadState(cfg.Storage.DataDir); err == nil {
			msg = fmt.Sprintf("running (pid %d), but its UI doesn't answer on %s", rs.PID, uiURL(cfg))
			if rs.UI.Error != "" {
				msg += ": " + rs.UI.Error
			}
		}
		w.row("Server", msg)
		w.row("", "("+apiErr.Error()+")")
	case errors.Is(lockErr, os.ErrPermission):
		w.row("Server", fmt.Sprintf("not answering on %s (%v)", uiURL(cfg), apiErr))
		w.row("", fmt.Sprintf("the data folder can't be checked without %s: run %s", adminWord(), asAdmin(fullStatus)))
	case lockErr != nil:
		w.row("Server", fmt.Sprintf("not answering on %s (%v)", uiURL(cfg), apiErr))
		w.row("", fmt.Sprintf("couldn't check the data folder either: %v (try as administrator)", lockErr))
	default:
		w.row("Server", "not running (nothing answers on "+uiURL(cfg)+")")
	}
	return 1
}

// statusTLSRows adds the TLS listener's certificate to `woodshed status`, from
// the run-state file (or the files), when TLS is on or was ever turned on.
func statusTLSRows(w *tabw, cfg config.Config, rs *server.RunState) {
	if rs == nil {
		if got, err := server.ReadState(cfg.Storage.DataDir); err == nil {
			rs = &got
		}
	}
	var t *server.RunStateTLS
	if rs != nil {
		t = rs.TLS
	}
	if t == nil && cfg.Listeners.TLS.Enabled {
		t = tlsFromFiles(cfg.Listeners.TLS, cfg.Storage.DataDir)
		t.Enabled, t.Port = true, cfg.Listeners.TLS.Port
	}
	if t != nil {
		tlsRows(w, t)
	}
}

func listenerRows(w *tabw, ls []api.Listener) {
	if len(ls) == 0 {
		w.row("Listeners", "none enabled")
	}
	for i, l := range ls {
		label := ""
		if i == 0 {
			label = "Listeners"
		}
		w.row(label, describeListener(l))
	}
}

// uiRows prints the UI's address(es): in LAN mode, also each stable address
// other machines use, and the certificate's SHA-256 when known.
func uiRows(w *tabw, cfg config.Config, fingerprint string) {
	w.row("UI", uiURL(cfg))
	if cfg.UI.LANMode {
		addrs, _ := api.StableAddrs()
		for _, ip := range addrs {
			w.row("", "https://"+net.JoinHostPort(ip.String(), strconv.Itoa(cfg.UI.Port))+"/")
		}
	}
	if fingerprint != "" {
		w.row("TLS cert", "SHA-256 "+fingerprint)
	}
}

func bannerRows(w *tabw, bs []api.Banner) {
	for i, b := range bs {
		label := ""
		if i == 0 {
			label = "Attention"
		}
		w.row(label, fmt.Sprintf("[%s] %s", b.Level, b.Text))
	}
}

func describeListener(l api.Listener) string {
	s := fmt.Sprintf("%s %s: ", strings.ToUpper(l.Proto), net.JoinHostPort(l.Addr, strconv.Itoa(l.Port)))
	if l.OK {
		return s + "listening"
	}
	s += "NOT listening: " + l.Error
	if l.Holder != "" {
		s += " (held by " + l.Holder + ")"
	}
	return s
}

var errNeedsLogin = errors.New("the API needs a login (LAN mode, or require_login_local)")

// fetchStatus reads /api/status from the local server.
func fetchStatus(cfg config.Config) (api.Status, error) {
	var st api.Status
	scheme := "http"
	client := &http.Client{Timeout: 3 * time.Second}
	if cfg.UI.LANMode {
		// Our own server on loopback with its self-signed certificate: there is
		// nothing to verify against, and nothing leaves the machine.
		scheme = "https"
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	url := fmt.Sprintf("%s://127.0.0.1:%d/api/status", scheme, cfg.UI.Port)
	resp, err := client.Get(url)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return st, errNeedsLogin
	}
	if resp.StatusCode != http.StatusOK {
		return st, fmt.Errorf("%s answered %s", url, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st); err != nil || st.Version == "" {
		return st, fmt.Errorf("%s isn't Woodshed's API", url)
	}
	return st, nil
}

// uiURL is where the UI is, from the config.
func uiURL(cfg config.Config) string {
	if cfg.UI.LANMode {
		return fmt.Sprintf("https://localhost:%d/ (LAN mode)", cfg.UI.Port)
	}
	return fmt.Sprintf("http://localhost:%d/", cfg.UI.Port)
}

// tabw prints aligned "Label:  value" rows.
type tabw struct{ w io.Writer }

func (t *tabw) row(label, value string) {
	if label != "" {
		label += ":"
	}
	fmt.Fprintf(t.w, "%-11s %s\n", label, value)
}

// readConfig reads an existing config without creating one.
func readConfig(path string) (config.Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return config.Config{}, err
	}
	if _, err := os.Stat(abs); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return config.Config{}, fmt.Errorf("no config file at %s", abs)
		}
		return config.Config{}, adminErr(err)
	}
	c, _, err := server.LoadConfig(abs)
	if err != nil {
		return c, adminErr(err)
	}
	return c, nil
}

func readConfigOrDefault(path string) config.Config {
	c, err := readConfig(path)
	if err != nil {
		return config.Default()
	}
	return c
}

// adminWord is what a permission error needs: "root", or administrator rights on Windows.
func adminWord() string {
	if runtime.GOOS == "windows" {
		return "administrator rights"
	}
	return "root"
}

// adminErr adds the "run as administrator" hint to a permission error.
func adminErr(err error) error {
	if err == nil || !errors.Is(err, os.ErrPermission) {
		return err
	}
	if runtime.GOOS == "windows" {
		return fmt.Errorf("%w\nThis needs administrator rights: run it from an administrator prompt", err)
	}
	return fmt.Errorf("%w\nThis needs root: run it with sudo", err)
}

// ---- reindex ----

func cmdReindex(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("reindex", "", `
Rebuild the index (index.db) from the log files, which are always the source of
truth. Device names, groups and hidden flags are kept.

The server must be stopped: reindex refuses while Woodshed is running on the
data folder.`, stderr)
	cfgPath := configFlag(fs)
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		return fail(stderr, "reindex", err)
	}
	if errs := cfg.Validate(nil); len(errs) > 0 {
		return fail(stderr, "reindex", fmt.Errorf("%s: %w", *cfgPath, errs))
	}
	dataDir := cfg.Storage.DataDir
	// Hold the data dir's lock for the whole rebuild, so the server can't start
	// in the middle of it.
	// As root on a folder the service account owns, nothing may be opened or
	// created there (re-test N1, N10): the index refuses it, so say how first,
	// before even the lock file is created.
	if err := runAsOwnerFirst(dataDir); err != nil {
		return fail(stderr, "reindex", err)
	}
	lock, err := server.LockDataDir(dataDir)
	if errors.Is(err, server.ErrLocked) {
		return fail(stderr, "reindex", fmt.Errorf("Woodshed is running on %s; stop it first (%s, or Ctrl-C a foreground `woodshed run`), then run reindex again",
			dataDir, stopHint()))
	}
	if err != nil {
		return fail(stderr, "reindex", adminErr(err))
	}
	defer lock.Unlock()
	// Run as root, the lock it just created would be root's (re-test N10).
	if err := lock.MatchOwner(dataDir); err != nil {
		return fail(stderr, "reindex", fmt.Errorf("give the lock file the data folder's owner: %w", err))
	}

	idx, err := index.Open(filepath.Join(dataDir, index.FileName))
	if errors.Is(err, index.ErrRunAsOwner) {
		return fail(stderr, "reindex", fmt.Errorf("%v\n%s", err, runAsOwnerHint(dataDir)))
	}
	if err != nil {
		return fail(stderr, "reindex", adminErr(err))
	}
	defer idx.Close()
	t0 := time.Now()
	ctx := context.Background()
	res, err := idx.Reindex(ctx, dataDir)
	if err != nil {
		return fail(stderr, "reindex", err)
	}
	took := time.Since(t0).Round(time.Millisecond)
	text := fmt.Sprintf("Index rebuilt from the log files by `woodshed reindex`: %d files (%d read), %d devices, %d stale rows removed, "+
		"%d bad lines, %d bytes in torn last lines, in %v.", len(res.Files), res.Scanned, res.Devices, res.Removed, res.BadLines, res.TornBytes, took)
	if err := idx.AddEvent(ctx, index.Event{Level: index.LevelInfo, Kind: index.KindRecover, Text: text}); err != nil {
		fmt.Fprintf(stderr, "woodshed reindex: couldn't record the event: %v\n", err)
	}
	fmt.Fprintf(stdout, "Reindexed %s in %v\n  files:   %d (%d read)\n  devices: %d\n  removed: %d stale rows\n",
		dataDir, took, len(res.Files), res.Scanned, res.Devices, res.Removed)
	if res.BadLines > 0 || res.TornBytes > 0 {
		fmt.Fprintf(stdout, "  skipped: %d lines that didn't parse, %d bytes of torn last lines\n", res.BadLines, res.TornBytes)
	}
	for _, s := range res.Skipped {
		fmt.Fprintf(stdout, "  not indexed: %s\n", s)
	}
	return 0
}

func stopHint() string {
	switch runtime.GOOS {
	case "windows":
		return "`sc stop Woodshed` from an administrator prompt"
	case "darwin":
		return "`sudo launchctl bootout system/" + service.DarwinName + "`"
	}
	return "`sudo systemctl stop woodshed`"
}

// ---- reset-password ----

func cmdResetPassword(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("reset-password", "", `
Forgot the UI password? On the Woodshed machine, run this as an administrator.
It deletes the password hash, turns LAN mode off in the config and restarts the
service, so the UI is back on http://localhost:<port>/ (this machine only, no
login). Set a new password in Settings to turn LAN mode on again. There is no
way to do this over the network, by design.`, stderr)
	cfgPath := configFlag(fs)
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		return fail(stderr, "reset-password", err)
	}
	abs, _ := filepath.Abs(*cfgPath)
	dataDir := cfg.Storage.DataDir
	hashPath := filepath.Join(dataDir, api.PasswordFile)

	// Check both folders are writable before changing anything.
	for _, dir := range []string{dataDir, filepath.Dir(abs)} {
		if err := checkWritable(dir); err != nil {
			return fail(stderr, "reset-password", adminErr(err))
		}
	}
	removed := true
	if err := os.Remove(hashPath); errors.Is(err, os.ErrNotExist) {
		removed = false
	} else if err != nil {
		return fail(stderr, "reset-password", adminErr(err))
	}
	wasLAN := cfg.UI.LANMode
	if wasLAN {
		cfg.UI.LANMode = false
		// Run as root, Save would leave the config root-owned, and the service
		// couldn't read it (security review L3): keep its owner and mode.
		if err := saveConfigKeepingOwner(abs, cfg); err != nil {
			return fail(stderr, "reset-password", adminErr(err))
		}
	}
	switch {
	case removed && wasLAN:
		fmt.Fprintln(stdout, "Removed the UI password and turned LAN mode off.")
	case removed:
		fmt.Fprintln(stdout, "Removed the UI password (LAN mode was already off).")
	case wasLAN:
		fmt.Fprintln(stdout, "No UI password was set; turned LAN mode off.")
	default:
		fmt.Fprintln(stdout, "No UI password was set and LAN mode was already off; nothing to change.")
	}
	url := fmt.Sprintf("http://localhost:%d/", cfg.UI.Port)

	if !removed && !wasLAN {
		fmt.Fprintf(stdout, "The UI is at %s\n", url)
		return 0
	}
	// The running server still has the old password and mode in memory.
	switch a := applyToRunning("reset-password", dataDir, stderr); a {
	case restarted:
		fmt.Fprintf(stdout, "Restarted the service. The UI is back on %s\n", url)
		return 0
	case notRunning:
		fmt.Fprintf(stdout, "The UI will be at %s when Woodshed starts.\n", url)
		return 0
	default:
		return applyHint(stdout, a, "the UI will be on "+url)
	}
}

// checkWritable reports whether a file can be created in dir.
func checkWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".woodshed-write-check-*")
	if err != nil {
		return fmt.Errorf("can't write in %s: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
