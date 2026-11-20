package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/export"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
)

// `woodshed bundle` (SPEC §11.3): the incident bundle without the service,
// built from the data folder directly and read-only, with the access rules
// of `woodshed search`. It writes the zip the API builds for the same
// request (export.Prepare and Plan.Write are the queue's own code).

// Hooks for tests.
var bundleHostname = os.Hostname

const bundleDesc = `
Build an incident bundle: every record Woodshed stored around a moment, from
every device that sent anything then (or the devices you name), in one zip
with a summary per device (counts by severity and by trap, the polls' traffic,
errors and cycles, first and last, reboots from traps and polls, gaps when
Woodshed wasn't running, drops), the manifest with SHA-256s and Woodshed's own
events. SNMP polls go in as CSV files (poll/<device>/*.csv), flows as CSV and
IPFIX files (flows/<device>/; --flow-formats). It's the zip the UI's "Bundle around this" builds,
made from the data folder directly: the service can be stopped, the UI off or
in LAN mode. It reads the data folder and never writes to it.

The window is [--at minus --before, --at plus --after), cut at now. Times:
RFC 3339 (2026-11-14T09:42:00Z), local time (2026-11-14 09:42, or UTC with
--utc), now, or a time back from now (-15m). Spans: 15m, 1h, 1h30m, 7d, 0s
(each 0s to 7d, not both 0s).

It prints the zip's path, size and SHA-256, and one line per device, so a
remote helper can ask for one command and one zip.

It needs the rights to read the data folder: run it as root (sudo woodshed
bundle ...), as the service account (sudo -u woodshed woodshed bundle ...;
_woodshed on macOS), or on Windows in an administrator prompt.

Examples:
  woodshed bundle --at "2026-11-14 09:42"                  30 min before, 10 after, every active device
  woodshed bundle --at -15m --before 1h --after 15m --group HQ
  woodshed bundle --at 2026-11-14T09:42:00Z --devices 192.0.2.10,192.0.2.11 --types syslog
  woodshed bundle --at now --before 4h --after 0s --out edge-reboot.zip

Exit status: 0 when the zip was written, 1 when the window held nothing (no zip
is written), 2 for a usage error or when --out already exists, 3 when the data
folder can't be read, 4 when there's no data folder or index, 130 when
interrupted (Ctrl-C; the partial zip is removed).`

func cmdBundle(args []string, stdout, stderr io.Writer) int {
	fset := newFlagSet("bundle", "", bundleDesc, stderr)
	var at, before, after, devices, group, types, out, flowFormats string
	var ungrouped, active, utc bool
	sf := searchFlags{}
	fset.StringVar(&at, "at", "", "the `time` the bundle is around (required)")
	fset.StringVar(&before, "before", "30m", "`span` before --at")
	fset.StringVar(&after, "after", "10m", "`span` after --at")
	fset.StringVar(&devices, "devices", "", "only these `devices` (comma-separated IDs or addresses; hidden or silent ones too)")
	fset.StringVar(&group, "group", "", "the devices of this `group`")
	fset.BoolVar(&ungrouped, "ungrouped", false, "the devices in no group")
	fset.BoolVar(&active, "active", false, "every device that sent anything in the window (the default)")
	fset.StringVar(&types, "types", "", "the data `types` (comma-separated: syslog, trap, poll, flow; default: every type with data in the window)")
	fset.StringVar(&flowFormats, "flow-formats", "csv,ipfix", "the flow `files` in the zip: csv, ipfix or both (flows/<device>/flows.csv, flows.ipfix)")
	fset.StringVar(&out, "out", "", "the zip `file` to write (default woodshed-bundle-<host>-<at, UTC>.zip here); never overwritten")
	fset.BoolVar(&utc, "utc", false, "read --at in the local form as UTC")
	fset.StringVar(&sf.config, "config", config.DefaultConfigPath(), "config `file` that names the data folder")
	fset.StringVar(&sf.data, "data", "", "data `folder` to read (instead of the config's)")
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "woodshed bundle: "+format+"\n", a...)
		return exitUsage
	}
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" || a == "-?" {
			fmt.Fprint(stdout, fset.help())
			return 0
		}
	}
	if err := fset.Parse(args); err != nil {
		fmt.Fprintf(stderr, "woodshed bundle: %v\n\n%s", err, fset.help())
		return exitUsage
	}
	if fset.NArg() > 0 {
		return usageErr("unexpected argument %q (every option is a flag: woodshed bundle --at <time>)", fset.Arg(0))
	}
	sf.set = map[string]bool{}
	fset.Visit(func(fl *flag.Flag) { sf.set[fl.Name] = true })

	// The request, each flag checked on its own.
	now := searchNow()
	zone := searchLocation()
	if utc {
		zone = time.UTC
	}
	if at == "" {
		return usageErr("--at is required: the moment the bundle is around (2026-11-14T09:42:00Z, \"2026-11-14 09:42\", now or -15m)")
	}
	atT, err := parseTimeArg(at, now, zone)
	if err != nil {
		return usageErr("--at: %v", err)
	}
	b, err := model.ParseSpan(before)
	if err != nil {
		return usageErr("--before: %v", err)
	}
	a, err := model.ParseSpan(after)
	if err != nil {
		return usageErr("--after: %v", err)
	}
	picks := 0
	for _, p := range []bool{active, devices != "", group != "", ungrouped} {
		if p {
			picks++
		}
	}
	if picks > 1 {
		return usageErr("--active, --devices, --group and --ungrouped are alternatives: pick one")
	}
	atU := atT.UTC()
	req := export.Request{Filters: export.Filters{Kind: export.KindBundle, At: &atU, Before: b, After: a, Group: group,
		Ungrouped: ungrouped, ActiveDevices: picks == 0 || active}}
	for _, d := range strings.Split(devices, ",") {
		if d = strings.TrimSpace(d); d == "" {
			continue
		}
		if ad, err := netip.ParseAddr(d); err == nil {
			d = model.DeviceID(ad) // 2001:db8::5 is the device 2001_db8__5
		}
		req.Devices = append(req.Devices, d)
	}
	if devices != "" && len(req.Devices) == 0 {
		return usageErr("--devices: name at least one device")
	}
	for _, t := range strings.Split(types, ",") {
		if t = strings.ToLower(strings.TrimSpace(t)); t == "" {
			continue
		}
		if datatype.Get(t) == nil {
			return usageErr("--types: unknown data type %q (this build has %s)", t, strings.Join(datatype.Names(), ", "))
		}
		if !slices.Contains(req.Types, t) {
			req.Types = append(req.Types, t)
		}
	}
	if types != "" && len(req.Types) == 0 {
		return usageErr("--types: name at least one type (%s)", strings.Join(datatype.Names(), ", "))
	}
	for _, ff := range strings.Split(flowFormats, ",") {
		if ff = strings.ToLower(strings.TrimSpace(ff)); ff == "" {
			continue
		}
		if ff != export.FlowCSV && ff != export.FlowIPFIX {
			return usageErr("--flow-formats: %q isn't csv or ipfix", ff)
		}
		if !slices.Contains(req.FlowFormats, ff) {
			req.FlowFormats = append(req.FlowFormats, ff)
		}
	}
	if len(req.FlowFormats) == 0 {
		return usageErr("--flow-formats: name csv, ipfix or both")
	}
	if len(req.FlowFormats) == 2 {
		req.FlowFormats = nil // both, the default, as the API's bundle
	}

	// The data folder, as for woodshed search.
	cmdline := "woodshed bundle"
	for _, x := range args {
		cmdline += " " + shellQuote(x)
	}
	dataDir, code, msg := searchDataDir(&sf, cmdline)
	if code != 0 {
		fmt.Fprintf(stderr, "woodshed bundle: %s\n", msg)
		return code
	}
	if out == "" {
		host, _ := bundleHostname()
		out = export.BundleFileName(host, atU)
	}
	outAbs, err := filepath.Abs(out)
	if err != nil {
		return usageErr("--out: %v", err)
	}
	if inside(dataDir, outAbs) {
		return usageErr("--out: %s is inside the data folder, which woodshed bundle never writes to; write the zip elsewhere", outAbs)
	}
	if _, err := os.Lstat(outAbs); err == nil {
		return usageErr("--out: %s already exists; woodshed bundle never overwrites a file (pass --out with another name)", outAbs)
	}
	idx, code, msg := openSearchIndex(dataDir, cmdline)
	if code != 0 {
		fmt.Fprintf(stderr, "woodshed bundle: %s\n", msg)
		return code
	}
	defer idx.Close()
	indexPath := filepath.Join(dataDir, index.FileName)
	stateBefore := index.StateOf(indexPath)
	loadSearchMIBs(&sf) // trap names in the summary, as the service names them

	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}}))
	eng := search.New(search.Options{DataDir: dataDir, Index: idx, Now: searchNow, Logger: logger})
	ctx, stop := searchSignals(context.Background())
	defer stop()

	// Flows are read from the closed segments (a segment the service is still
	// writing has no footer yet, so the current hour of a running service's
	// exporters isn't in the zip; the API's bundle has it).
	flows := flowEngine(dataDir, idx, logger, searchRuleIEs(&sf, dataDir))
	opts := export.Options{Index: idx, Search: eng, Flows: flows, Version: version, Now: searchNow, Location: searchLocation(), Logger: logger,
		SeverityFilter: searchSeverity(&sf, dataDir)}
	plan, err := export.Prepare(ctx, opts, req)
	var re *export.RequestError
	switch {
	case errors.As(err, &re) && re.Empty:
		fmt.Fprintf(stderr, "woodshed bundle: %s No zip written.\n", re.Msg)
		return exitNoMatch
	case errors.As(err, &re):
		return usageErr("%s", re.Msg)
	case ctx.Err() != nil:
		return exitInterrupted
	case err != nil:
		fmt.Fprintf(stderr, "woodshed bundle: %s\n", strings.TrimPrefix(err.Error(), "index: "))
		return exitUsage
	}
	nothing := func() int {
		fmt.Fprintf(stderr, "woodshed bundle: nothing was stored from %s between %s and %s. No zip written.\n",
			deviceWords(plan.Info), plan.Info.From.Format("2006-01-02T15:04:05.000Z07:00"), plan.Info.To.Format("2006-01-02T15:04:05.000Z07:00"))
		return exitNoMatch
	}
	if est, err := plan.Estimate(ctx); err == nil && est.Lines == 0 {
		return nothing()
	}

	f, err := os.OpenFile(outAbs, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, fs.ErrExist) {
		return usageErr("--out: %s already exists; woodshed bundle never overwrites a file (pass --out with another name)", outAbs)
	}
	if err != nil {
		return usageErr("--out: can't create the zip: %v", err)
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(outAbs)
		}
	}()
	res, err := plan.Write(ctx, f, nil)
	switch {
	case ctx.Err() != nil:
		fmt.Fprintln(stderr, "woodshed bundle: interrupted; the partial zip was removed.")
		return exitInterrupted
	case err != nil:
		fmt.Fprintf(stderr, "woodshed bundle: %s\n", strings.TrimPrefix(err.Error(), "index: "))
		return exitUsage
	case res.Lines == 0:
		return nothing()
	}
	sum := sha256.New()
	if _, err := f.Seek(0, io.SeekStart); err == nil {
		_, err = io.Copy(sum, f)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		fmt.Fprintf(stderr, "woodshed bundle: can't write the zip: %v\n", err)
		return exitUsage
	}
	ok = true

	ts := plan.Info.Filters.TypesOrSyslog()
	var tw []string
	for _, t := range ts {
		if t == datatype.Syslog {
			tw = append(tw, "syslog")
		} else {
			tw = append(tw, datatype.Get(t).Label())
		}
	}
	fmt.Fprintln(stdout, outAbs)
	fmt.Fprintf(stdout, "  %s, SHA-256 %s\n", sizeWords(res.Size), hex.EncodeToString(sum.Sum(nil)))
	fmt.Fprintf(stdout, "  %s to %s UTC: %s from %d %s (%s)\n", plan.Info.From.Format("2006-01-02 15:04:05"),
		plan.Info.To.Format("2006-01-02 15:04:05"), recordWords(res.Lines), len(res.Summary), plural(int64(len(res.Summary)), "device", "devices"),
		strings.Join(tw, ", "))
	for _, d := range res.Summary {
		fmt.Fprintf(stdout, "  %s: %s\n", d.Heading(), d.Line(ts))
	}
	if len(res.Gaps) == 0 {
		fmt.Fprintln(stdout, "  gaps: none of 1 s or more (Woodshed and its listeners were up the whole window)")
	} else {
		fmt.Fprintf(stdout, "  gaps: %d (Woodshed or a listener was down; see README.txt)\n", len(res.Gaps))
	}
	if idx.Immutable() && index.StateOf(indexPath) != stateBefore {
		fmt.Fprintln(stderr, "warning: Woodshed started writing while this bundle was built; it may miss records. Run it again.")
	}
	return 0
}

// inside reports whether path is dir or inside it (after resolving links in
// the parts that exist).
func inside(dir, path string) bool {
	resolve := func(p string) string {
		p = filepath.Clean(p)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return r
		}
		if r, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
			return filepath.Join(r, filepath.Base(p))
		}
		return p
	}
	d, p := resolve(dir), resolve(path)
	rel, err := filepath.Rel(d, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func deviceWords(info export.Info) string {
	if len(info.Devices) == 1 {
		return info.Devices[0]
	}
	return fmt.Sprintf("the %d devices", len(info.Devices))
}

func recordWords(n int64) string {
	if n == 1 {
		return "1 record"
	}
	return datatype.Thousands(n) + " records"
}

func sizeWords(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB (%s bytes)", float64(n)/(1<<30), datatype.Thousands(n))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB (%s bytes)", float64(n)/(1<<20), datatype.Thousands(n))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB (%s bytes)", float64(n)/(1<<10), datatype.Thousands(n))
	}
	return datatype.Thousands(n) + " bytes"
}
