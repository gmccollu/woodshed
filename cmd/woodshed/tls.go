package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

// `woodshed tls on|off|renew [--new-ca]|status` (SPEC §10.3.6). Like lan-mode,
// they need administrator rights, edit the config (or leave a renewal request
// in the data folder), and restart a running service to apply it. The
// certificate itself is always made by the service, as the service's account,
// so its files have the right owner.

// fwRun runs the host firewall's commands (faked in tests).
var fwRun fwrule.Runner = fwrule.Exec

// fwOS is the OS whose firewall `tls on|off` changes (tests set it).
var fwOS = runtime.GOOS

func cmdTLS(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("tls", "on|off|renew|status", `
Syslog over TLS (TCP 6514 by default), for servers without a browser.

  on      turn the TLS listener on. The service makes Woodshed's own CA and
          certificate the first time. On Windows it also enables the firewall
          rule "Woodshed syslog (TLS 6514)"; on Linux it opens the port in ufw
          or firewalld when one is active (and records what it added).
  off     turn it off (the certificate is kept) and undo the firewall change.
  renew   make a new certificate signed by the same CA: devices need nothing.
          With --new-ca, a new CA too: every device must import it again.
  status  the listener, the fingerprints, the expiry and the last failures.

Run it as an administrator (sudo): it saves the config, and a running service
is restarted to use it.`, stderr)
	cfgPath := configFlag(fs)
	port := fs.Int("port", 0, "with on: the TLS `port` (default: keep the current one, 6514)")
	newCA := fs.Bool("new-ca", false, "with renew: replace the CA too (every device must import the new one)")
	var mode string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	if mode == "" && fs.NArg() == 1 {
		mode = fs.Arg(0)
	} else if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "woodshed tls: unexpected argument %q\n\n%s", fs.Arg(0), fs.help())
		return 2
	}
	switch mode {
	case "on", "off", "renew", "status":
	default:
		fmt.Fprintf(stderr, "woodshed tls: say on, off, renew or status\n\n%s", fs.help())
		return 2
	}
	if *port != 0 && mode != "on" {
		fmt.Fprintln(stderr, "woodshed tls: --port goes with on")
		return 2
	}
	if *newCA && mode != "renew" {
		fmt.Fprintln(stderr, "woodshed tls: --new-ca goes with renew")
		return 2
	}

	cfg, err := readConfig(*cfgPath)
	if err != nil {
		return fail(stderr, "tls", err)
	}
	abs, _ := filepath.Abs(*cfgPath)
	dataDir := cfg.Storage.DataDir
	if mode == "status" {
		tlsStatus(stdout, cfg)
		return 0
	}
	if err := checkWritable(filepath.Dir(abs)); err != nil {
		return fail(stderr, "tls", adminErr(err))
	}

	switch mode {
	case "on", "off":
		next := cfg.Clone()
		next.Listeners.TLS.Enabled = mode == "on"
		if *port != 0 {
			next.Listeners.TLS.Port = *port
		}
		if errs := next.Validate(&cfg); len(errs) > 0 {
			for _, k := range []string{"listeners.tls.port", "listeners.tls.addr", "listeners.tls.cert_file", "listeners.tls.key_file"} {
				if msg, ok := errs[k]; ok {
					return fail(stderr, "tls", fmt.Errorf("%s %s", k, msg))
				}
			}
			return fail(stderr, "tls", fmt.Errorf("%s: %w", abs, errs))
		}
		changed := next.Listeners.TLS != cfg.Listeners.TLS
		if changed {
			if err := saveConfigKeepingOwner(abs, next); err != nil {
				return fail(stderr, "tls", adminErr(err))
			}
			fmt.Fprintf(stdout, "Turned syslog over TLS %s (TCP port %d).\n", mode, next.Listeners.TLS.Port)
		} else {
			fmt.Fprintf(stdout, "Syslog over TLS is already %s (TCP port %d).\n", mode, next.Listeners.TLS.Port)
		}
		firewall(stdout, stderr, mode == "on", next.Listeners.TLS.Port, dataDir)
		if !changed {
			if mode == "on" {
				printTLSFromState(stdout, dataDir, nil)
			}
			return 0
		}
		return applyTLS(stdout, stderr, dataDir, "the TLS change", mode == "on")
	}

	// renew
	if cfg.Listeners.TLS.UsesOwnCert() {
		return fail(stderr, "tls", errors.New("this server uses your own certificate (listeners.tls.cert_file); replace those files instead"))
	}
	if _, err := os.Stat(filepath.Join(dataDir, tlscert.CAFile)); err != nil && !*newCA {
		if errors.Is(err, os.ErrNotExist) {
			return fail(stderr, "tls", errors.New("there's no TLS certificate yet: turn TLS on first ("+asAdmin("tls on")+")"))
		}
		return fail(stderr, "tls", adminErr(err))
	}
	if err := server.WriteTLSRenewRequest(dataDir, *newCA); err != nil {
		return fail(stderr, "tls", adminErr(err))
	}
	if *newCA {
		fmt.Fprintln(stdout, "Asked for a new CA and certificate. Every device that sends over TLS must import the new CA certificate.")
	} else {
		fmt.Fprintln(stdout, "Asked for a new certificate signed by the same CA; devices need no change.")
	}
	return applyTLS(stdout, stderr, dataDir, "the renewal", true)
}

// applyTLS restarts a running service (or says how the change applies) and
// prints the certificate it then reports.
func applyTLS(stdout, stderr io.Writer, dataDir, what string, show bool) int {
	before, _ := server.ReadState(dataDir)
	a := applyToRunning("tls", dataDir, stderr)
	switch a {
	case restarted:
		fmt.Fprintln(stdout, "Restarted the service to use it.")
		if rs, ok := waitForRestart(dataDir, before, 20*time.Second); ok && show {
			printTLSFromState(stdout, dataDir, &rs)
		}
	case applyFailed:
		return 1
	default:
		applyHint(stdout, a, what+" applies")
		if show {
			fmt.Fprintln(stdout, "The service makes the certificate when it starts; then "+asAdmin("tls status")+" shows its fingerprints.")
		}
	}
	return 0
}

// firewall opens (on) or closes the TLS port in the host firewall.
func firewall(stdout, stderr io.Writer, on bool, port int, dataDir string) {
	switch fwOS {
	case "windows":
		exe, err := os.Executable()
		if err != nil {
			exe = installedExe()
		}
		if on {
			err = fwrule.WindowsEnable(fwRun, exe, port)
		} else {
			err = fwrule.WindowsDisable(fwRun)
		}
		if err != nil {
			fmt.Fprintf(stderr, "woodshed tls: couldn't change the firewall rule %q: %v\n", fwrule.RuleName, err)
			return
		}
		if on {
			fmt.Fprintf(stdout, "Enabled the Windows firewall rule %q for TCP %d.\n", fwrule.RuleName, port)
		} else {
			fmt.Fprintf(stdout, "Disabled the Windows firewall rule %q.\n", fwrule.RuleName)
		}
	case "linux":
		var msg string
		var err error
		if on {
			msg, err = fwrule.LinuxOpen(fwRun, dataDir, port)
		} else {
			msg, err = fwrule.LinuxClose(fwRun, dataDir)
		}
		if msg != "" {
			fmt.Fprintln(stdout, msg)
		}
		if err != nil {
			fmt.Fprintf(stderr, "woodshed tls: firewall: %v\n", err)
		}
	default:
		// macOS: the application firewall allows the program on every port.
	}
}

// printTLSFromState prints the certificate fingerprints from the run-state file
// (rs, or read now), or from the files when the server isn't running.
func printTLSFromState(stdout io.Writer, dataDir string, rs *server.RunState) {
	if rs == nil {
		if got, err := server.ReadState(dataDir); err == nil {
			rs = &got
		}
	}
	w := &tabw{w: stdout}
	if rs != nil && rs.TLS != nil {
		tlsRows(w, rs.TLS)
		return
	}
	if t := tlsFromFiles(config.TLSListener{}, dataDir); t != nil && t.CertSHA256 != "" {
		tlsRows(w, t)
	}
}

// tlsFromFiles reads the certificate files directly (needs the rights to read
// the data folder), for when no server is running.
func tlsFromFiles(l config.TLSListener, dataDir string) *server.RunStateTLS {
	m := tlscert.New(tlscert.Options{DataDir: dataDir, CertFile: l.CertFile, KeyFile: l.KeyFile})
	st := m.Status()
	rs := &server.RunStateTLS{Enabled: l.Enabled, Port: l.Port, Source: st.Source, Error: st.Err}
	if st.CA != nil {
		at := st.CA.NotAfter
		rs.CASHA256, rs.CASHA1, rs.CANotAfter = st.CA.SHA256, st.CA.SHA1, &at
	}
	if st.Cert != nil {
		at := st.Cert.NotAfter
		rs.CertSHA256, rs.CertNotAfter = st.Cert.SHA256, &at
	}
	return rs
}

// tlsStatus is `woodshed tls status`.
func tlsStatus(stdout io.Writer, cfg config.Config) {
	w := &tabw{w: stdout}
	l := cfg.Listeners.TLS
	var t *server.RunStateTLS
	running := false
	if rs, err := server.ReadState(cfg.Storage.DataDir); err == nil {
		if inUse, _ := server.DataDirInUse(cfg.Storage.DataDir); inUse {
			running = true
			t = rs.TLS
			for _, ln := range rs.Listeners {
				if ln.Proto == "tls" {
					w.row("Listener", describeListener(ln))
				}
			}
		}
	}
	if t == nil {
		t = tlsFromFiles(l, cfg.Storage.DataDir)
	}
	t.Enabled, t.Port = l.Enabled, l.Port
	if !running {
		w.row("Server", "not running (or this account can't see it)")
	}
	tlsRows(w, t)
	if fwOS == "linux" {
		if rec, err := fwrule.LinuxOpened(cfg.Storage.DataDir); err == nil && (len(rec.Ufw) > 0 || len(rec.Firewalld) > 0) {
			var opened []string
			for _, e := range rec.Ufw {
				opened = append(opened, "ufw "+e)
			}
			for _, e := range rec.Firewalld {
				opened = append(opened, "firewalld "+e)
			}
			w.row("Firewall", "opened by woodshed tls on: "+strings.Join(opened, ", "))
		} else {
			w.row("Firewall", "if devices can't connect, open the port:")
			for _, line := range strings.Split(strings.TrimRight(fwrule.LinuxCommands(l.Port), "\n"), "\n") {
				w.row("", strings.TrimSpace(line))
			}
		}
	}
	if fwOS == "windows" {
		w.row("Firewall", "rule "+fmt.Sprintf("%q", fwrule.RuleName)+": "+fwrule.WindowsState(fwRun, l.Port))
	}
}

// tlsRows prints the TLS listener's certificate rows (also in `woodshed status`).
func tlsRows(w *tabw, t *server.RunStateTLS) {
	state := "off"
	if t.Enabled {
		state = "on"
	}
	src := "Woodshed's own CA"
	if t.Source == tlscert.SourceFile {
		src = "your own certificate (listeners.tls.cert_file)"
	}
	w.row("Syslog TLS", fmt.Sprintf("%s, TCP %d, %s", state, t.Port, src))
	if t.CASHA256 != "" {
		w.row("TLS CA", "SHA-256 "+t.CASHA256)
		w.row("", "SHA-1   "+t.CASHA1)
		if t.CANotAfter != nil {
			w.row("", "expires "+t.CANotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
	}
	if t.CertSHA256 != "" {
		w.row("TLS leaf", "SHA-256 "+t.CertSHA256)
		if t.CertNotAfter != nil {
			w.row("", "expires "+t.CertNotAfter.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
	} else if t.Enabled && t.Error == "" {
		w.row("TLS leaf", "not made yet (the service makes it when it starts with TLS on)")
	}
	if t.Error != "" {
		w.row("TLS error", t.Error)
	}
	for i, f := range t.Failures {
		label := ""
		if i == 0 {
			label = "TLS fails"
		}
		w.row(label, fmt.Sprintf("%s: %s, %d in 24 h, last %s", f.IP, f.Reason, f.Count24h, f.LastSeen.UTC().Format("2006-01-02 15:04 UTC")))
	}
}
