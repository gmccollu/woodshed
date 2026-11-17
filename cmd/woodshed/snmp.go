package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gmccollu/woodshed/internal/atomicfile"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// `woodshed snmp on|off|status` (SPEC §11.2.7), like `woodshed tls`: they need
// administrator rights, edit the config, and restart a running service to
// apply it. v3 users and communities are secrets, managed only in Settings (an
// admin command can't encrypt for the service account's key store, and
// passphrases never go on a command line, SPEC §11.2.6), so there's no flag
// for them here.

func cmdSNMP(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("snmp", "on|off|status", `
The SNMP trap receiver (UDP 162 by default), for servers without a browser.

  on      turn the SNMP listener on. On Windows it also enables the firewall
          rule "Woodshed SNMP traps (UDP 162)"; on Linux it opens the port in
          ufw or firewalld when one is active (and records what it added).
  off     turn it off and undo the firewall change.
  status  the listener, Woodshed's v3 engine ID, the last 24 h counts and the
          senders whose traps fail.

v3 users and the v1/v2c community list are set in the web UI (Settings → SNMP
traps), never on the command line: passphrases on a command line show in the
process list.

Run it as an administrator (sudo): it saves the config, and a running service
is restarted to use it.`, stderr)
	cfgPath := configFlag(fs)
	port := fs.Int("port", 0, "with on: the UDP `port` for traps and informs (default: keep the current one, 162)")
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
		fmt.Fprintf(stderr, "woodshed snmp: unexpected argument %q\n\n%s", fs.Arg(0), fs.help())
		return 2
	}
	switch mode {
	case "on", "off", "status":
	default:
		fmt.Fprintf(stderr, "woodshed snmp: say on, off or status\n\n%s", fs.help())
		return 2
	}
	if *port != 0 && mode != "on" {
		fmt.Fprintln(stderr, "woodshed snmp: --port goes with on")
		return 2
	}

	cfg, err := readConfig(*cfgPath)
	if err != nil {
		return fail(stderr, "snmp", err)
	}
	abs, _ := filepath.Abs(*cfgPath)
	dataDir := cfg.Storage.DataDir
	if mode == "status" {
		// As run, reindex and flow status do: a config the server would refuse
		// to start with is an error, not a status.
		if errs := cfg.Validate(nil); len(errs) > 0 {
			return configErr(stderr, "snmp", abs, errs, snmpConfigKeys...)
		}
		snmpStatus(stdout, cfg)
		return 0
	}
	if err := checkWritable(filepath.Dir(abs)); err != nil {
		return fail(stderr, "snmp", adminErr(err))
	}

	next := cfg.Clone()
	next.Listeners.SNMP.Enabled = mode == "on"
	if *port != 0 {
		next.Listeners.SNMP.Port = *port
	}
	if errs := next.Validate(&cfg); len(errs) > 0 {
		return configErr(stderr, "snmp", abs, errs, snmpConfigKeys...)
	}
	was, now := cfg.Listeners.SNMP, next.Listeners.SNMP
	changed := was.Enabled != now.Enabled || was.Port != now.Port
	if changed {
		if err := saveConfigKeepingOwner(abs, next); err != nil {
			return fail(stderr, "snmp", adminErr(err))
		}
		fmt.Fprintf(stdout, "Turned the SNMP trap receiver %s (UDP port %d).\n", mode, now.Port)
	} else {
		fmt.Fprintf(stdout, "The SNMP trap receiver is already %s (UDP port %d).\n", mode, now.Port)
	}
	snmpFirewall(stdout, stderr, mode == "on", now.Port, dataDir)
	if !changed {
		return 0
	}
	a := applyToRunning("snmp", dataDir, stderr)
	switch a {
	case restarted:
		fmt.Fprintln(stdout, "Restarted the service to use it.")
	case applyFailed:
		return 1
	default:
		applyHint(stdout, a, "the change applies")
	}
	if mode == "on" {
		fmt.Fprintln(stdout, "Add v3 users and communities in Settings → SNMP traps; "+asAdmin("snmp status")+" shows the engine ID for devices.")
	}
	return 0
}

// snmpFirewall opens (on) or closes the SNMP port in the host firewall.
func snmpFirewall(stdout, stderr io.Writer, on bool, port int, dataDir string) {
	switch fwOS {
	case "windows":
		exe, err := os.Executable()
		if err != nil {
			exe = installedExe()
		}
		if on {
			err = fwrule.SNMPWindowsEnable(fwRun, exe, port)
		} else {
			err = fwrule.SNMPWindowsDisable(fwRun)
		}
		if err != nil {
			fmt.Fprintf(stderr, "woodshed snmp: couldn't change the firewall rule %q: %v\n", fwrule.SNMPRuleName, err)
			return
		}
		if on {
			fmt.Fprintf(stdout, "Enabled the Windows firewall rule %q for UDP %d.\n", fwrule.SNMPRuleName, port)
		} else {
			fmt.Fprintf(stdout, "Disabled the Windows firewall rule %q.\n", fwrule.SNMPRuleName)
		}
	case "linux":
		var msg string
		var err error
		if on {
			msg, err = fwrule.SNMPLinuxOpen(fwRun, dataDir, port)
		} else {
			msg, err = fwrule.SNMPLinuxClose(fwRun, dataDir)
		}
		if msg != "" {
			fmt.Fprintln(stdout, msg)
		}
		if err != nil {
			fmt.Fprintf(stderr, "woodshed snmp: firewall: %v\n", err)
		}
	default:
		// macOS: the application firewall allows the program on every port.
	}
}

// snmpEngineFromFile reads <data>/snmp-engine.json without changing it (the
// server adds one to the boots at each start; this only looks), for when no
// server is running.
func snmpEngineFromFile(dataDir string) (id string, boots int64, ok bool) {
	b, err := atomicfile.ReadFile(filepath.Join(dataDir, snmp.EngineFile))
	if err != nil {
		return "", 0, false
	}
	var f struct {
		EngineID    string `json:"engine_id"`
		EngineBoots int64  `json:"engine_boots"`
	}
	if json.Unmarshal(b, &f) != nil || f.EngineID == "" {
		return "", 0, false
	}
	return f.EngineID, f.EngineBoots, true
}

// snmpFromFiles is the SNMP part of the status when no server is running: the
// config and the engine file.
func snmpFromFiles(l config.SNMPListener, dataDir string) *server.RunStateSNMP {
	rs := &server.RunStateSNMP{Enabled: l.Enabled, Port: l.Port, AnswerInforms: l.AnswerInforms}
	if id, boots, ok := snmpEngineFromFile(dataDir); ok {
		rs.EngineID, rs.EngineBoots = id, boots
	}
	return rs
}

// snmpConfigKeys are the trap listener's keys, reported first when a config
// doesn't validate.
var snmpConfigKeys = []string{"listeners.snmp.port", "listeners.snmp.addr", "listeners.snmp.mib_dir", "listeners.snmp.engine_id"}

// snmpStatus is `woodshed snmp status`.
func snmpStatus(stdout io.Writer, cfg config.Config) {
	w := &tabw{w: stdout}
	l := cfg.Listeners.SNMP
	var s *server.RunStateSNMP
	running := false
	if rs, err := server.ReadState(cfg.Storage.DataDir); err == nil {
		if inUse, _ := server.DataDirInUse(cfg.Storage.DataDir); inUse {
			running = true
			s = rs.SNMP
			for _, ln := range rs.Listeners {
				if ln.Proto == "snmp" {
					w.row("Listener", describeListener(ln))
				}
			}
		}
	}
	if s == nil {
		s = snmpFromFiles(l, cfg.Storage.DataDir)
	}
	if !running {
		w.row("Server", "not running (or this account can't see it)")
		s.Enabled, s.Port, s.AnswerInforms = l.Enabled, l.Port, l.AnswerInforms
	}
	snmpRows(w, s, running)
	if fwOS == "linux" {
		w.row("Firewall", "if devices' traps don't arrive, open the port:")
		for _, line := range strings.Split(strings.TrimRight(fwrule.SNMPLinuxCommands(l.Port), "\n"), "\n") {
			w.row("", strings.TrimSpace(line))
		}
	}
	if fwOS == "windows" {
		w.row("Firewall", "rule "+fmt.Sprintf("%q", fwrule.SNMPRuleName)+": "+fwrule.SNMPWindowsState(fwRun, l.Port))
	}
}

// snmpRows prints the SNMP receiver's rows (also in `woodshed status`); counts
// only with a running server's numbers.
func snmpRows(w *tabw, s *server.RunStateSNMP, counts bool) {
	state := "off"
	if s.Enabled {
		state = "on"
	}
	informs := "informs answered"
	if !s.AnswerInforms {
		informs = "informs stored, not answered"
	}
	w.row("SNMP traps", fmt.Sprintf("%s, UDP %d, %s", state, s.Port, informs))
	switch {
	case s.EngineID != "":
		w.row("SNMP engine", fmt.Sprintf("%s (boots %d)", s.EngineID, s.EngineBoots))
	case s.Enabled:
		w.row("SNMP engine", "not made yet (the service makes it when it starts with SNMP on)")
	}
	if s.Error != "" {
		w.row("SNMP error", s.Error)
	}
	if counts {
		line := fmt.Sprintf("%d received, %d informs answered, %d replies rate-limited, %d time resyncs",
			s.Received24h, s.InformsAnswered24h, s.RateLimited24h, s.TimeResyncs24h)
		w.row("SNMP 24 h", line)
		if len(s.ByStatus24h) > 0 {
			keys := make([]string, 0, len(s.ByStatus24h))
			for k := range s.ByStatus24h {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool {
				if s.ByStatus24h[keys[i]] != s.ByStatus24h[keys[j]] {
					return s.ByStatus24h[keys[i]] > s.ByStatus24h[keys[j]]
				}
				return keys[i] < keys[j]
			})
			parts := make([]string, len(keys))
			for i, k := range keys {
				parts[i] = fmt.Sprintf("%s %d", k, s.ByStatus24h[k])
			}
			w.row("", "by status: "+strings.Join(parts, ", "))
		}
		users := fmt.Sprintf("%d v3 users", s.Users)
		if s.UnreadableUsers > 0 {
			users += fmt.Sprintf(" (%d need their passphrases again in Settings)", s.UnreadableUsers)
		}
		mibs := fmt.Sprintf("%d MIB names", s.MIBNames)
		if s.MIBErrors > 0 {
			mibs += fmt.Sprintf(", %d MIB files didn't load (see Settings)", s.MIBErrors)
		}
		w.row("SNMP setup", users+", "+mibs)
	}
	for i, f := range s.Failures {
		label := ""
		if i == 0 {
			label = "SNMP fails"
		}
		detail := f.Status
		if f.Detail != "" {
			detail += " (" + f.Detail + ")"
		}
		w.row(label, fmt.Sprintf("%s: %s, %d in 24 h, last %s", f.IP, detail, f.Count24h, f.LastSeen.Local().Format("2006-01-02 15:04")))
	}
}

// statusSNMPRows adds the SNMP receiver to `woodshed status`, from the
// run-state file, when it's on or the server reports it.
func statusSNMPRows(w *tabw, cfg config.Config, rs *server.RunState) {
	if rs == nil {
		if got, err := server.ReadState(cfg.Storage.DataDir); err == nil {
			rs = &got
		}
	}
	if rs != nil && rs.SNMP != nil {
		snmpRows(w, rs.SNMP, true)
		return
	}
	if cfg.Listeners.SNMP.Enabled {
		snmpRows(w, snmpFromFiles(cfg.Listeners.SNMP, cfg.Storage.DataDir), false)
	}
}
