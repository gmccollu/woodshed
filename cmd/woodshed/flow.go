package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/server"
)

// `woodshed flow on|off|status` (SPEC §13.7), like `woodshed snmp`: on and
// off edit the config, change the firewall rules and restart a running
// service; status shows each exporter's rate, templates, sampling, sequence
// gaps and pending data from the run-state file.

func cmdFlow(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("flow", "on|off|status", `
The flow listener: flows (v5, v9) on UDP 2055 and IPFIX on UDP 4739 by default
(both ports read every version), for servers without a browser.

  on      turn the flow listener on. On Windows it also enables the firewall
          rules "Woodshed flows (UDP 2055)" and "(UDP 4739)"; on Linux it opens
          the ports in ufw or firewalld when one is active (and records what it
          added).
  off     turn it off and undo the firewall change.
  status  the listener and each exporter: records a second, templates,
          sampling, sequence gaps and data waiting for a template.

Run on and off as an administrator (sudo): they save the config, and a running
service is restarted to use it.`, stderr)
	cfgPath := configFlag(fs)
	nfPort := fs.Int("flow-port", -1, "with on: the UDP `port` for flows, v5 and v9 (0 turns it off; default: keep the current one, 2055)")
	ixPort := fs.Int("ipfix-port", -1, "with on: the UDP `port` for IPFIX (0 turns it off; default: keep the current one, 4739)")
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
		fmt.Fprintf(stderr, "woodshed flow: unexpected argument %q\n\n%s", fs.Arg(0), fs.help())
		return 2
	}
	switch mode {
	case "on", "off", "status":
	default:
		fmt.Fprintf(stderr, "woodshed flow: say on, off or status\n\n%s", fs.help())
		return 2
	}
	if (*nfPort >= 0 || *ixPort >= 0) && mode != "on" {
		fmt.Fprintln(stderr, "woodshed flow: --flow-port and --ipfix-port go with on")
		return 2
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		return fail(stderr, "flow", err)
	}
	abs, _ := filepath.Abs(*cfgPath)
	dataDir := cfg.Storage.DataDir
	if mode == "status" {
		// As reindex and run do (and on and off, for the config they save): a
		// config the server would refuse to start with is an error, not a status.
		if errs := cfg.Validate(nil); len(errs) > 0 {
			return flowConfigErr(stderr, abs, errs)
		}
		flowStatus(stdout, cfg)
		return 0
	}
	if err := checkWritable(filepath.Dir(abs)); err != nil {
		return fail(stderr, "flow", adminErr(err))
	}
	next := cfg.Clone()
	next.Listeners.Flow.Enabled = mode == "on"
	if *nfPort >= 0 {
		next.Listeners.Flow.FlowPort = *nfPort
	}
	if *ixPort >= 0 {
		next.Listeners.Flow.IPFIXPort = *ixPort
	}
	if errs := next.Validate(&cfg); len(errs) > 0 {
		return flowConfigErr(stderr, abs, errs)
	}
	was, now := cfg.Listeners.Flow, next.Listeners.Flow
	ports := flowPortsText(now)
	changed := was.Enabled != now.Enabled || was.FlowPort != now.FlowPort || was.IPFIXPort != now.IPFIXPort
	if changed {
		if err := saveConfigKeepingOwner(abs, next); err != nil {
			return fail(stderr, "flow", adminErr(err))
		}
		fmt.Fprintf(stdout, "Turned the flow listener %s (%s).\n", mode, ports)
	} else {
		fmt.Fprintf(stdout, "The flow listener is already %s (%s).\n", mode, ports)
	}
	flowFirewall(stdout, stderr, mode == "on", now, dataDir)
	if !changed {
		return 0
	}
	a := applyToRunning("flow", dataDir, stderr)
	switch a {
	case restarted:
		fmt.Fprintln(stdout, "Restarted the service to use it.")
	case applyFailed:
		return 1
	default:
		applyHint(stdout, a, "the change applies")
	}
	return 0
}

// flowConfigErr reports a config that doesn't validate: the listener's own
// ports and address first, else every error.
func flowConfigErr(stderr io.Writer, abs string, errs config.Errors) int {
	return configErr(stderr, "flow", abs, errs, "listeners.flow.flow_port", "listeners.flow.ipfix_port", "listeners.flow.addr")
}

// configErr reports a config that doesn't validate for command cmd: the first
// of the command's own keys that has an error, else every error.
func configErr(stderr io.Writer, cmd, abs string, errs config.Errors, keys ...string) int {
	for _, k := range keys {
		if msg, ok := errs[k]; ok {
			return fail(stderr, cmd, fmt.Errorf("%s %s", k, msg))
		}
	}
	return fail(stderr, cmd, fmt.Errorf("%s: %w", abs, errs))
}

func flowPortsText(l config.FlowListener) string {
	var parts []string
	if l.FlowPort != 0 {
		parts = append(parts, fmt.Sprintf("flow UDP %d", l.FlowPort))
	}
	if l.IPFIXPort != 0 {
		parts = append(parts, fmt.Sprintf("IPFIX UDP %d", l.IPFIXPort))
	}
	return strings.Join(parts, ", ")
}

// flowFirewall opens (on) or closes the flow ports in the host firewall.
func flowFirewall(stdout, stderr io.Writer, on bool, l config.FlowListener, dataDir string) {
	switch fwOS {
	case "windows":
		exe, err := os.Executable()
		if err != nil {
			exe = installedExe()
		}
		if on {
			err = fwrule.FlowWindowsEnable(fwRun, exe, l.FlowPort, l.IPFIXPort)
		} else {
			err = fwrule.FlowWindowsDisable(fwRun)
		}
		if err != nil {
			fmt.Fprintf(stderr, "woodshed flow: couldn't change the flow firewall rules: %v\n", err)
			return
		}
		if on {
			fmt.Fprintf(stdout, "Enabled the Windows firewall rules %q and %q for %s.\n", fwrule.FlowPortRuleName,
				fwrule.FlowIPFIXRuleName, flowPortsText(l))
		} else {
			fmt.Fprintf(stdout, "Disabled the Windows firewall rules %q and %q.\n", fwrule.FlowPortRuleName, fwrule.FlowIPFIXRuleName)
		}
	case "linux":
		var msg string
		var err error
		if on {
			msg, err = fwrule.FlowLinuxOpen(fwRun, dataDir, l.FlowPort, l.IPFIXPort)
		} else {
			msg, err = fwrule.FlowLinuxClose(fwRun, dataDir)
		}
		if msg != "" {
			fmt.Fprintln(stdout, msg)
		}
		if err != nil {
			fmt.Fprintf(stderr, "woodshed flow: firewall: %v\n", err)
		}
	}
}

// flowStatus is `woodshed flow status`.
func flowStatus(stdout io.Writer, cfg config.Config) {
	w := &tabw{w: stdout}
	l := cfg.Listeners.Flow
	state := "off"
	if l.Enabled {
		state = "on"
	}
	w.row("Flows", fmt.Sprintf("%s, %s; template timeout %s", state, flowPortsText(l), config.ShortDuration(time.Duration(l.TemplateTimeout))))
	var fs *api.FlowState
	running := false
	if rs, err := server.ReadState(cfg.Storage.DataDir); err == nil {
		if inUse, _ := server.DataDirInUse(cfg.Storage.DataDir); inUse {
			running = true
			fs = rs.Flows
			for _, ln := range rs.Listeners {
				if ln.Proto == "flow" || ln.Proto == "ipfix" {
					w.row("Listener", describeListener(ln))
				}
			}
		}
	}
	if !running {
		w.row("Server", "not running (or this account can't see it)")
	}
	if fs != nil {
		flowStateRows(w, fs)
	}
	if fwOS == "linux" && l.Enabled {
		w.row("Firewall", "if exporters' flows don't arrive, open the ports:")
		for _, line := range strings.Split(strings.TrimRight(fwrule.FlowLinuxCommands(l.FlowPort, l.IPFIXPort), "\n"), "\n") {
			w.row("", strings.TrimSpace(line))
		}
	}
	if fwOS == "windows" {
		bad := fwrule.FlowWindowsStates(fwRun, l.FlowPort, l.IPFIXPort)
		if len(bad) == 0 {
			w.row("Firewall", fmt.Sprintf("rules %q and %q: %s", fwrule.FlowPortRuleName, fwrule.FlowIPFIXRuleName, fwrule.StateOK))
		}
		label := "Firewall"
		for _, r := range bad {
			w.row(label, fmt.Sprintf("rule %q: %s", r.Rule, r.State))
			label = ""
		}
	}
}

// flowStateRows prints the budget and each exporter.
func flowStateRows(w *tabw, fs *api.FlowState) {
	budget := fmt.Sprintf("%s of %s used", formatSize(fs.Budget.UsedBytes), formatSize(fs.Budget.Bytes))
	if fs.Budget.EstimatedDays != nil {
		budget += fmt.Sprintf("; holds about %.1f days at the current rate", *fs.Budget.EstimatedDays)
	}
	w.row("Flow budget", budget)
	for _, e := range fs.Exporters {
		var doms []string
		for _, d := range e.Domains {
			s := "sampling unknown"
			switch {
			case d.Sampling == 1:
				s = "unsampled"
			case d.Sampling > 1:
				s = fmt.Sprintf("1 in %d", d.Sampling)
			}
			doms = append(doms, fmt.Sprintf("domain %d: %d templates, %s", d.ID, d.Templates, s))
		}
		c := e.Counts24h
		w.row("Exporter", fmt.Sprintf("%s: %.1f records/s; %s", e.DeviceID, e.RecordsPerSec, strings.Join(doms, "; ")))
		w.row("", fmt.Sprintf("24 h: %d records, %d late, %d without a template, %d malformed, %d sequence gaps, %d duplicates; "+
			"%d bytes waiting for a template", c.Records, c.Late, c.NoTemplate, c.Malformed, c.SequenceGaps, c.Duplicates, e.PendingBytes))
		if e.TimeSource == "received" {
			w.row("", fmt.Sprintf("its clock is %d ms off: its flows use the received time", e.ClockSkewMS))
		}
		if o := e.TimeOffsets24h; o.Ahead > 0 || o.Behind > 0 {
			var ws []string
			if o.Ahead > 0 {
				ws = append(ws, fmt.Sprintf("%d records more than 1 h ahead of when they arrived (up to %s)", o.Ahead, flow.OffsetText(o.MaxAheadMS)))
			}
			if o.Behind > 0 {
				ws = append(ws, fmt.Sprintf("%d more than 24 h behind (up to %s)", o.Behind, flow.OffsetText(o.MaxBehindMS)))
			}
			w.row("", "24 h: "+strings.Join(ws, ", ")+"; kept at their own times: its clock or uptime is probably wrong")
		}
	}
}

// statusFlowRows adds the Flows row to `woodshed status`: exporters, records
// a second, budget used.
func statusFlowRows(w *tabw, rs *server.RunState) {
	if rs == nil || rs.Flows == nil {
		return
	}
	fs := rs.Flows
	var rate float64
	for _, e := range fs.Exporters {
		rate += e.RecordsPerSec
	}
	state := "off"
	if fs.Enabled {
		state = "on"
	}
	n := len(fs.Exporters)
	exp := "exporters"
	if n == 1 {
		exp = "exporter"
	}
	pct := 0.0
	if fs.Budget.Bytes > 0 {
		pct = 100 * float64(fs.Budget.UsedBytes) / float64(fs.Budget.Bytes)
	}
	w.row("Flows", fmt.Sprintf("%s; %d %s, %.0f records/s; budget %.0f %% used (%s of %s)", state, n, exp, rate, pct,
		formatSize(fs.Budget.UsedBytes), formatSize(fs.Budget.Bytes)))
}

func formatSize(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// ---- woodshed flows top ----

func cmdFlows(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "top" {
		if len(args) > 0 && (args[0] == "-h" || args[0] == "--help" || args[0] == "help") {
			fmt.Fprintln(stdout, "usage: woodshed flows top [flags]   (woodshed flows top --help for the flags)")
			return 0
		}
		fmt.Fprintln(stderr, "woodshed flows: say top (woodshed flows top --help)")
		return exitUsage
	}
	args = args[1:]
	fs := newFlagSet("flows top", "", `
The top-N of stored flows for a window, from the data folder (read-only), as
the Events Top panel and /api/flows/top: exported and scaled counts, each
row's share of the window.

Examples:
  woodshed flows top --by src --last 1h                         top talkers by bytes
  woodshed flows top --by dst-port --metric flows --fw-event denied --last 24h
  woodshed flows top --by conversation --src 10.20.0.0/16 --json`, stderr)
	by := fs.String("by", "src", "`key`: src, dst, conversation, dst-port, src-port, proto, in-if, out-if, post-nat-src, post-nat-dst, fw-event, rule-id")
	metric := fs.String("metric", "", "`metric`: bytes (default), packets, flows or connections (flows with --fw-event denied)")
	top := fs.Int("top", 10, "rows (`1-100`)")
	from := fs.String("from", "", "start `time` (default: --to minus 24h)")
	to := fs.String("to", "", "end `time` (default: now)")
	last := fs.String("last", "", "the last `duration` (15m, 1h, 24h, 7d)")
	devices := fs.String("devices", "", "only these `devices`")
	asJSON := fs.Bool("json", false, "the /api/flows/top response as JSON")
	cfgFlag := fs.String("config", config.DefaultConfigPath(), "config `file` that names the data folder")
	data := fs.String("data", "", "data `folder` (instead of the config's)")
	flow := flowFilterFlags(fs.FlagSet)
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	v := url.Values{"by": {strings.ReplaceAll(*by, "-", "_")}, "top": {fmt.Sprint(*top)}}
	if *metric != "" {
		v.Set("metric", *metric)
	}
	for p, val := range flow {
		if *val != "" {
			v.Set(p, *val)
		}
	}
	if *devices != "" {
		v.Set("devices", *devices)
	}
	now := searchNow()
	switch {
	case *last != "" && (*from != "" || *to != ""):
		fmt.Fprintln(stderr, "woodshed flows top: --last is instead of --from and --to")
		return exitUsage
	case *last != "":
		d, err := parseDurationArg(*last)
		if err != nil {
			fmt.Fprintf(stderr, "woodshed flows top: --last: %v\n", err)
			return exitUsage
		}
		v.Set("from", now.Add(-d).UTC().Format(time.RFC3339Nano))
		v.Set("to", now.UTC().Format(time.RFC3339Nano))
	default:
		t1 := now
		var err error
		if *to != "" {
			if t1, err = parseTimeArg(*to, now, searchLocation()); err != nil {
				fmt.Fprintf(stderr, "woodshed flows top: --to: %v\n", err)
				return exitUsage
			}
		}
		t0 := t1.Add(-search.DefaultRange)
		if *from != "" {
			if t0, err = parseTimeArg(*from, now, searchLocation()); err != nil {
				fmt.Fprintf(stderr, "woodshed flows top: --from: %v\n", err)
				return exitUsage
			}
		}
		v.Set("from", t0.UTC().Format(time.RFC3339Nano))
		v.Set("to", t1.UTC().Format(time.RFC3339Nano))
	}
	req, err := api.ParseFlowTop(v)
	if err != nil {
		fmt.Fprintf(stderr, "woodshed flows top: %v\n", err)
		return exitUsage
	}
	sf := &searchFlags{config: *cfgFlag, data: *data, set: set}
	dataDir, code, msg := searchDataDir(sf, "woodshed flows top")
	if code != 0 {
		fmt.Fprintf(stderr, "woodshed flows top: %s\n", msg)
		return code
	}
	idx, code, msg := openSearchIndex(dataDir, "woodshed flows top")
	if code != 0 {
		fmt.Fprintf(stderr, "woodshed flows top: %s\n", msg)
		return code
	}
	defer idx.Close()
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	eng := search.New(search.Options{DataDir: dataDir, Index: idx, Now: searchNow, Logger: logger})
	ctx, stop := searchSignals(context.Background())
	defer stop()
	devs, err := eng.ResolveDevices(ctx, req.Devices, req.Group, req.Ungrouped, req.ExcludeDevices)
	if err != nil {
		fmt.Fprintf(stderr, "woodshed flows top: %v\n", err)
		return exitUsage
	}
	if devs == nil {
		devs = []string{}
	}
	filter, err := req.Flow.Filter()
	if err != nil {
		fmt.Fprintf(stderr, "woodshed flows top: %v\n", err)
		return exitUsage
	}
	q := flowquery.Query{DeviceIDs: devs, From: req.From, To: req.To, Filter: filter}
	start := time.Now()
	res, err := flowEngine(dataDir, idx, logger, searchRuleIEs(sf, dataDir)).Top(ctx, q, req.By, req.Metric, req.Top, 24*time.Hour, "")
	if err != nil {
		if ctx.Err() != nil {
			return exitInterrupted
		}
		fmt.Fprintf(stderr, "woodshed flows top: %v\n", err)
		return exitUsage
	}
	page := server.ToAPITop(req.By, req.Metric, q, res, time.Since(start))
	if *asJSON {
		b, _ := json.Marshal(page)
		fmt.Fprintf(stdout, "%s\n", b)
	} else {
		printTop(stdout, page)
	}
	if len(page.Rows) == 0 {
		return exitNoMatch
	}
	return exitMatch
}

func printTop(w io.Writer, p api.FlowTopPage) {
	tw := tabwriter.NewWriter(w, 2, 8, 2, ' ', 0)
	// Scaled columns only when some rate above 1 is known (records of unknown
	// sampling add nothing to the scaled sums).
	sampled := p.Total.BytesScaled > p.Total.Bytes || p.Total.PacketsScaled > p.Total.Packets
	head := []string{strings.ToUpper(strings.ReplaceAll(p.By, "_", " ")), "FLOWS", "BYTES", "PACKETS"}
	if sampled {
		head = append(head, "BYTES SCALED", "PACKETS SCALED")
	}
	head = append(head, "SHARE")
	fmt.Fprintln(tw, strings.Join(head, "\t"))
	for _, r := range p.Rows {
		label := r.Label
		if r.Approx {
			label = "~ " + label
		}
		row := []string{label, fmt.Sprint(r.Flows), fmt.Sprint(r.Bytes), fmt.Sprint(r.Packets)}
		if sampled {
			ge := ""
			if r.ScaledLowerBound {
				ge = ">= "
			}
			row = append(row, ge+fmt.Sprint(r.BytesScaled), ge+fmt.Sprint(r.PacketsScaled))
		}
		row = append(row, fmt.Sprintf("%.1f %%", 100*r.Share))
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	tw.Flush()
	note := fmt.Sprintf("%d flows, %d bytes, %d packets in the window", p.Total.Flows, p.Total.Bytes, p.Total.Packets)
	if p.Approx {
		note += fmt.Sprintf(" (too many keys to count exactly: approximate; a key not listed has at most %d %s, and a row marked ~ is at most its error over)",
			p.ErrorBound, p.Metric)
	}
	fmt.Fprintln(w, note)
}
