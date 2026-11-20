package main

import (
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/server"
)

// ---- severity-filter ----

// cmdSeverityFilter shows or sets the syslog severity filter (SPEC §13.10
// decision 86) from the machine itself: the default (syslog.min_severity) or
// one device's own (syslog.min_severity_by_device). Like update-check it
// saves the config and restarts a running service to use it; the device
// page and Settings change it without a restart.
func cmdSeverityFilter(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("severity-filter", "[--device <address>] [<severity>|default]", `
Show or set which syslog messages Woodshed stores. A severity stores that
severity and more severe ones: emerg, alert, crit, err, warning, notice, info
or debug (the default: everything), or 0 to 7. For example, "info" leaves out
debug messages, for a device that sends debug and can't be told not to.
Messages without a severity (no PRI) are always stored, and SNMP traps, polls
and flows aren't affected. What's left out isn't stored anywhere (search, the
live tail and exports don't have it), but it's counted per device and
severity: woodshed status, the device's page and incident bundles show the
counts.

With no argument it shows the default and every device's own setting. With a
severity it sets the default, for every device without its own. With --device
it sets that device's own ("default": follow the default again).

Run it as an administrator (sudo): it saves the config, and a running service
is restarted to use it (a second or two without listeners). The device's page
and Settings in the web UI change it without a restart.`, stderr)
	cfgPath := configFlag(fs)
	device := fs.String("device", "", "set this device's own filter instead of the default (its IP `address`, as on the Devices page)")
	noRestart := fs.Bool("no-restart", false, "don't restart a running service (it uses the change when it next starts)")
	// The severity may come before, between or after the flags.
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" || a == "-?" {
			fmt.Fprint(stdout, fs.help())
			return 0
		}
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			fmt.Fprintf(stderr, "woodshed severity-filter: %v\n\n%s", err, fs.help())
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos, args = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	if len(pos) > 1 {
		fmt.Fprintf(stderr, "woodshed severity-filter: unexpected argument %q\n\n%s", pos[1], fs.help())
		return 2
	}
	var value string
	if len(pos) == 1 {
		value = pos[0]
	}
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "woodshed severity-filter: "+format+"\n\n%s", append(a, fs.help())...)
		return 2
	}
	abs, err := filepath.Abs(*cfgPath)
	if err != nil {
		return fail(stderr, "severity-filter", err)
	}
	var ip netip.Addr
	if *device != "" {
		a, err := netip.ParseAddr(strings.TrimSpace(strings.ReplaceAll(*device, "_", ":")))
		if err != nil || a.Zone() != "" {
			return usage("--device %q isn't an IP address", *device)
		}
		ip = a.Unmap()
	}
	value = strings.TrimSpace(value)
	if value == "" {
		if *device != "" {
			return usage("say the severity for %s, or default", ip)
		}
		cfg, err := readConfig(abs)
		if err != nil {
			return fail(stderr, "severity-filter", err)
		}
		showSeverityFilter(stdout, cfg.Syslog)
		return 0
	}
	level := -1
	if n, ok := config.ParseSeverity(value); ok {
		level = n
	} else if !strings.EqualFold(value, config.SeverityDefault) || *device == "" {
		return usage("%q isn't a severity (emerg, alert, crit, err, warning, notice, info or debug, or 0 to 7)%s; nothing changed", value,
			map[bool]string{true: " or default", false: ""}[*device != ""])
	}

	cfg, err := readConfig(abs)
	if err != nil {
		return fail(stderr, "severity-filter", err)
	}
	if err := checkWritable(filepath.Dir(abs)); err != nil {
		return fail(stderr, "severity-filter", adminErr(err))
	}
	next := cfg.Clone()
	var done string
	if *device == "" {
		if cfg.Syslog.Level() == level {
			fmt.Fprintf(stdout, "The default severity filter already stores %s; nothing to change.\n", config.SeverityPhrase(level))
			return 0
		}
		next.Syslog.MinSeverity = config.SeverityText(config.SeverityName(level))
		done = fmt.Sprintf("Set the default severity filter to store %s (was %s).", config.SeverityPhrase(level), config.SeverityPhrase(cfg.Syslog.Level()))
		switch n := len(next.Syslog.DeviceLevels()); n {
		case 0:
		case 1:
			done += " The 1 device with its own setting keeps it."
		default:
			done += fmt.Sprintf(" The %d devices with their own setting keep it.", n)
		}
	} else {
		if !next.Syslog.SetDevice(ip, level) {
			fmt.Fprintf(stdout, "%s already has that setting; nothing to change.\n", ip)
			return 0
		}
		if level < 0 {
			done = fmt.Sprintf("%s follows the default again: it stores %s.", ip, config.SeverityPhrase(next.Syslog.Level()))
		} else {
			done = fmt.Sprintf("%s now stores %s (its own setting).", ip, config.SeverityPhrase(level))
		}
	}
	if errs := next.Validate(&cfg); len(errs) > 0 {
		return fail(stderr, "severity-filter", fmt.Errorf("%s: %w", abs, errs))
	}
	if err := saveConfigKeepingOwner(abs, next); err != nil {
		return fail(stderr, "severity-filter", adminErr(err))
	}
	fmt.Fprintln(stdout, done)
	dataDir := next.Storage.DataDir
	if *noRestart {
		if inUse, _ := server.DataDirInUse(dataDir); inUse {
			fmt.Fprintln(stdout, "Woodshed is running; it uses the change when it next starts.")
		}
		return 0
	}
	before, _ := server.ReadState(dataDir)
	switch a := applyToRunning("severity-filter", dataDir, stderr); a {
	case restarted:
		fmt.Fprintln(stdout, "Restarted the service to use it.")
		waitForRestart(dataDir, before, 20*time.Second)
	case applyFailed:
		return 1
	default:
		applyHint(stdout, a, "it uses the change")
	}
	return 0
}

// showSeverityFilter prints the default and the devices' own settings.
func showSeverityFilter(w io.Writer, s config.Syslog) {
	fmt.Fprintf(w, "Default: store %s (syslog.min_severity = %s).\n", config.SeverityPhrase(s.Level()), config.SeverityName(s.Level()))
	own := s.DeviceLevels()
	if len(own) == 0 {
		fmt.Fprintln(w, "No device has its own setting.")
		return
	}
	addrs := make([]netip.Addr, 0, len(own))
	for a := range own {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	fmt.Fprintln(w, "Devices with their own setting:")
	for _, a := range addrs {
		fmt.Fprintf(w, "  %-39s %s\n", a, config.SeverityPhrase(own[a]))
	}
}

// statusSeverityRows is `woodshed status`'s line for the severity filter:
// the setting from the config, and the last 24 hours from the run-state
// file when it can be read. Nothing while it stores everything and left
// nothing out.
func statusSeverityRows(w *tabw, cfg config.Config, rs *server.RunState) {
	if rs == nil {
		if got, err := server.ReadState(cfg.Storage.DataDir); err == nil {
			rs = &got
		}
	}
	filtering := cfg.Syslog.Filtering()
	if !filtering && (rs == nil || rs.SeverityFilter == nil || rs.SeverityFilter.Filtered24h == 0) {
		return
	}
	text := "stores " + config.SeverityPhrase(cfg.Syslog.Level()) + " by default"
	if n := len(cfg.Syslog.DeviceLevels()); n > 0 {
		text += fmt.Sprintf(", %d %s with %s own", n, map[bool]string{true: "device", false: "devices"}[n == 1],
			map[bool]string{true: "its", false: "their"}[n == 1])
	}
	if rs != nil && rs.SeverityFilter != nil {
		f := rs.SeverityFilter
		if f.Filtered24h == 0 {
			text += "; nothing left out in the last 24 h"
		} else {
			var parts []string
			for i := 7; i >= 0; i-- {
				if n := f.BySeverity24h[config.SeverityNames[i]]; n > 0 {
					parts = append(parts, datatype.Thousands(n)+" "+config.SeverityNames[i])
				}
			}
			text += fmt.Sprintf("; not stored in the last 24 h: %s (%s from %d %s)", datatype.Thousands(f.Filtered24h), strings.Join(parts, ", "),
				f.Devices24h, map[bool]string{true: "device", false: "devices"}[f.Devices24h == 1])
		}
	}
	w.row("Severity", text)
}
