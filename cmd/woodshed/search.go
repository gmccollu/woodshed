package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/server"
)

// `woodshed search` (SPEC §11.4): the Events search engine on the command line,
// reading the data folder directly and read-only, beside the running service
// or without it.

// Exit codes (SPEC §11.4), grep-style.
const (
	exitMatch       = 0
	exitNoMatch     = 1
	exitUsage       = 2
	exitAccess      = 3
	exitNoData      = 4
	exitInterrupted = 130
)

// Hooks for tests.
var (
	searchNow      = time.Now
	searchLocation = func() *time.Location { return time.Local }
	searchExe      = os.Executable
	// searchSignals is the context Ctrl-C (or SIGTERM) cancels.
	searchSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
	// searchFlushEvery is how often buffered output is flushed while a search
	// runs, so a match shows at once even when the next one is far away.
	searchFlushEvery = 200 * time.Millisecond
)

// listFlag is a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, " ") }
func (l *listFlag) Set(v string) error { *l = append(*l, v); return nil }

// searchFlags are the parsed flags of one run.
type searchFlags struct {
	query                              string
	terms, regex, caseSens             bool
	exclude, typ                       string
	from, to, last                     string
	utc                                bool
	devices, group                     string
	ungrouped                          bool
	excludeDevices                     string
	severities, facilities             string
	app, excludeApp, host, excludeHost string
	fields, notFields                  listFlag
	order                              string
	limit, context                     int
	count, json, raw                   bool
	config, data                       string
	set                                map[string]bool // flags given on the command line
}

const searchDesc = `
Search the stored logs from the command line, with the same engine and filters as
the Events page, compressed days included. It reads the data folder directly and
never writes to it, so it works with the UI off, in LAN mode, beside the running
service or with the service stopped.

QUERY is text to find (ignoring case unless --case), or with --terms the boolean
terms Events takes ("deny AND NOT 10.0.0.1"), or with --regex an RE2 regular
expression. With no QUERY every line in the range matches.

Output: one stored line per match, "<received> <device> <message>" as in the file
(escaped, so always one line per match); --raw prints only the message, as
received; --json prints one JSON object per match (the /api/search result plus
"type" and "device_name"). With --context N, N lines before and after each match
from the same file, "--" between groups and "> " before each match. A summary
("N matches, M MiB read from F files in Ts") goes to standard error.

Fields: --field KEY=V1,V2 keeps lines whose field KEY is one of the values, and
--not-field KEY=V1,V2 drops them; KEY is any field of the type (syslog: device,
severity, facility, host, app). --devices, --severities, --app and the others are
shortcuts for the same filters.

Times: RFC 3339 (2026-11-14T09:30:00Z), local time (2026-11-14 09:30, or UTC with
--utc), now, or a time back from now (-15m). The default range is --last 24h.

It needs the rights to read the data folder: run it as root (sudo woodshed search
...), as the service account (sudo -u woodshed woodshed search ...; _woodshed on
macOS), or on Windows in an administrator prompt. A portable copy searches its own
woodshed-data folder.

Examples:
  woodshed search "link down"                            the last 24 hours, oldest first
  woodshed search --last 1h --devices 192.0.2.10 --severities 0,1,2,3
  woodshed search --terms 'deny AND NOT 203.0.113.7' --app '%FW-*' --context 3
  woodshed search --from "2026-11-14 08:00" --to "2026-11-14 09:00" --json | jq .raw
  woodshed search --field host=edge-fw-01 --not-field severity=7 --count

Exit status: 0 when something matched, 1 when nothing did, 2 for a usage or query
error, 3 when the data folder can't be read, 4 when there's no data folder or
index, 130 when interrupted (Ctrl-C).`

func cmdSearch(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("search", "[QUERY]", searchDesc, stderr)
	var f searchFlags
	fs.BoolVar(&f.terms, "terms", false, "QUERY and --exclude are boolean terms (AND, OR, NOT, parentheses, \"quotes\")")
	fs.BoolVar(&f.regex, "regex", false, "QUERY and --exclude are RE2 regular expressions")
	fs.BoolVar(&f.caseSens, "case", false, "match case (QUERY and --exclude)")
	fs.StringVar(&f.exclude, "exclude", "", "drop lines matching this `text` (like QUERY, with --terms, --regex and --case)")
	fs.StringVar(&f.typ, "type", search.TypeSyslog, "data `type` to search")
	fs.StringVar(&f.from, "from", "", "start `time` (default: --to minus 24h)")
	fs.StringVar(&f.to, "to", "", "end `time`, not included (default: now)")
	fs.StringVar(&f.last, "last", "", "the last `duration` (15m, 1h, 24h, 7d), instead of --from and --to (default 24h)")
	fs.BoolVar(&f.utc, "utc", false, "read --from and --to local-form times as UTC")
	fs.StringVar(&f.devices, "devices", "", "only these `devices` (comma-separated IDs or addresses; hidden devices too)")
	fs.StringVar(&f.group, "group", "", "only the devices of this `group`")
	fs.BoolVar(&f.ungrouped, "ungrouped", false, "only devices in no group")
	fs.StringVar(&f.excludeDevices, "exclude-devices", "", "leave out these `devices`")
	fs.StringVar(&f.severities, "severities", "", "only these `severities` (0-7 and unknown, comma-separated)")
	fs.StringVar(&f.facilities, "facilities", "", "only these `facilities` (0-23 and unknown, comma-separated)")
	fs.StringVar(&f.app, "app", "", "only these program/tag `values` (a trailing * is a prefix)")
	fs.StringVar(&f.excludeApp, "exclude-app", "", "drop these program/tag `values`")
	fs.StringVar(&f.host, "host", "", "only these header `hostnames`")
	fs.StringVar(&f.excludeHost, "exclude-host", "", "drop these header `hostnames`")
	fs.Var(&f.fields, "field", "keep lines whose field is one of the values: `KEY=V1,V2` (repeatable)")
	fs.Var(&f.notFields, "not-field", "drop lines whose field is one of the values: `KEY=V1,V2` (repeatable)")
	fs.StringVar(&f.order, "order", "asc", "`order`: asc (oldest first) or desc (newest first)")
	fs.IntVar(&f.limit, "limit", 0, "stop after this many `matches` (0: all)")
	fs.IntVar(&f.context, "context", 0, fmt.Sprintf("`lines` before and after each match, from the same file (at most %d)", search.MaxContext))
	fs.BoolVar(&f.count, "count", false, "print only the number of matches")
	fs.BoolVar(&f.json, "json", false, "one JSON object per match (NDJSON)")
	fs.BoolVar(&f.raw, "raw", false, "print only each message, unescaped")
	fs.StringVar(&f.config, "config", config.DefaultConfigPath(), "config `file` that names the data folder")
	fs.StringVar(&f.data, "data", "", "data `folder` to search (instead of the config's)")
	usageErr := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "woodshed search: "+format+"\n", a...)
		return exitUsage
	}
	// Any other error (an unreadable index, say) is 2 as well, as for grep.
	otherErr := func(err error) int {
		fmt.Fprintf(stderr, "woodshed search: %s\n", strings.TrimPrefix(err.Error(), "index: "))
		return exitUsage
	}
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" || a == "-?" {
			fmt.Fprint(stdout, fs.help())
			return 0
		}
		if a == "--" {
			break
		}
	}
	if err := parseInterleaved(fs.FlagSet, args, &f.query); err != nil {
		fmt.Fprintf(stderr, "woodshed search: %v\n\n%s", err, fs.help())
		return exitUsage
	}
	f.set = map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })

	values, err := f.values(searchNow(), searchLocation())
	if err != nil {
		return usageErr("%v", err)
	}
	req, err := api.ParseSearch(values)
	if err != nil {
		return usageErr("%v", err)
	}
	q := server.SearchQuery(req)

	cmdline := "woodshed search"
	for _, a := range args {
		cmdline += " " + shellQuote(a)
	}
	dataDir, code, msg := searchDataDir(&f, cmdline)
	if code != 0 {
		fmt.Fprintf(stderr, "woodshed search: %s\n", msg)
		return code
	}
	idx, code, msg := openSearchIndex(dataDir, cmdline)
	if code != 0 {
		fmt.Fprintf(stderr, "woodshed search: %s\n", msg)
		return code
	}
	defer idx.Close()

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

	out := newSearchOut(stdout, &f, q.Asc)
	if f.json {
		devs, err := idx.ListDevices(ctx)
		if err != nil {
			return otherErr(err)
		}
		for _, d := range devs {
			out.names[d.ID] = d.Name
		}
	}
	if f.context > 0 {
		out.around = eng.NewAround(ctx, !q.Asc)
		defer out.around.Close()
	}
	stopFlush := out.flushEvery(searchFlushEvery)
	errLimit := errors.New("limit reached")
	st, err := eng.Each(ctx, q, func(r *search.Result) error {
		if f.count {
			out.matches++
		} else if err := out.match(r); err != nil {
			return err
		}
		if f.limit > 0 && out.matches >= int64(f.limit) {
			return errLimit
		}
		return nil
	})
	stopFlush()
	interrupted := ctx.Err() != nil && errors.Is(err, ctx.Err())
	var qe *search.QueryError
	switch {
	case errors.As(err, &qe):
		msg := qe.Msg
		if rest, ok := strings.CutPrefix(msg, "exclude: "); ok {
			return usageErr("--exclude: %s", rest)
		}
		return usageErr("QUERY: %s", msg)
	case err == nil, errors.Is(err, errLimit), interrupted:
	case out.err != nil:
		fmt.Fprintf(stderr, "woodshed search: can't write the output: %v\n", out.err)
		return exitUsage
	default:
		out.finish()
		return otherErr(err)
	}
	out.finish()
	if f.count {
		if f.json {
			fmt.Fprintf(stdout, "{\"count\":%d}\n", out.matches)
		} else {
			fmt.Fprintln(stdout, out.matches)
		}
	}
	if out.err != nil {
		fmt.Fprintf(stderr, "woodshed search: can't write the output: %v\n", out.err)
		return exitUsage
	}
	writeSummary(stderr, f.json, out.matches, st, interrupted)
	switch {
	case interrupted:
		return exitInterrupted
	case out.matches > 0:
		return exitMatch
	}
	return exitNoMatch
}

// parseInterleaved parses flags and the one positional QUERY in any order
// (flag stops at the first non-flag). Everything after "--" is positional.
func parseInterleaved(fs *flag.FlagSet, args []string, query *string) error {
	var rest []string
	if i := slices.Index(args, "--"); i >= 0 {
		args, rest = args[:i], args[i+1:]
	}
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	pos = append(pos, rest...)
	switch {
	case len(pos) > 1:
		return fmt.Errorf("unexpected argument %q (quote a QUERY with spaces: woodshed search \"link down\")", pos[1])
	case len(pos) == 1:
		*query = pos[0]
	}
	return nil
}

// paramFlags names the flag behind each /api/search parameter, for messages.
var paramFlags = map[string]string{
	"devices": "--devices", "exclude_devices": "--exclude-devices", "group": "--group", "ungrouped": "--ungrouped",
	"severities": "--severities", "facilities": "--facilities", "app": "--app", "exclude_app": "--exclude-app",
	"host": "--host", "exclude_host": "--exclude-host", "from": "--from", "to": "--to", "order": "--order",
	"type": "--type", "q": "QUERY", "exclude": "--exclude", "syntax": "--terms", "regex": "--regex", "case": "--case",
}

// values builds the /api/search parameters of the flags (SPEC §11.4: they mean
// exactly what those parameters mean), checking each one so a message names
// the flag it came from.
func (f *searchFlags) values(now time.Time, loc *time.Location) (url.Values, error) {
	switch {
	case f.terms && f.regex:
		return nil, errors.New("--terms and --regex can't be combined: pick one")
	case f.group != "" && f.ungrouped:
		return nil, errors.New("--group and --ungrouped are alternatives: pick one")
	case f.json && f.raw:
		return nil, errors.New("--json and --raw are alternatives: pick one")
	case f.count && (f.raw || f.context > 0):
		return nil, errors.New("--count prints only the number of matches: drop --raw and --context")
	case f.last != "" && (f.from != "" || f.to != ""):
		return nil, errors.New("--last is instead of --from and --to: use one or the other")
	case f.limit < 0:
		return nil, fmt.Errorf("--limit must be 0 (all) or more, not %d", f.limit)
	case f.context < 0 || f.context > search.MaxContext:
		return nil, fmt.Errorf("--context must be from 0 to %d, not %d", search.MaxContext, f.context)
	}
	ts := findType(f.typ)
	if ts == nil {
		var known []string
		for _, t := range search.Schema() {
			known = append(known, t.Type)
		}
		return nil, fmt.Errorf("--type: unknown data type %q (this build searches %s)", f.typ, strings.Join(known, ", "))
	}
	f.typ = ts.Type

	v := url.Values{}
	origin := map[string]string{}
	add := func(param, from string, vals ...string) {
		for _, x := range vals {
			if x = strings.TrimSpace(x); x == "" {
				continue
			}
			if a, err := netip.ParseAddr(x); err == nil && (param == "devices" || param == "exclude_devices") {
				x = model.DeviceID(a) // an address as typed: 2001:db8::5 is the device 2001_db8__5
			}
			v.Add(param, x)
		}
		if _, ok := origin[param]; !ok {
			origin[param] = from
		}
	}
	set := func(param, val string) {
		if val != "" {
			add(param, paramFlags[param], val)
		}
	}
	set("q", f.query)
	set("exclude", f.exclude)
	set("type", ts.Type)
	if f.terms {
		set("syntax", "terms")
	}
	if f.regex {
		set("regex", "true")
	}
	if f.caseSens {
		set("case", "true")
	}
	if f.ungrouped {
		set("ungrouped", "true")
	}
	set("group", f.group)
	set("order", f.order)
	for param, val := range map[string]string{"devices": f.devices, "exclude_devices": f.excludeDevices, "severities": f.severities,
		"facilities": f.facilities, "app": f.app, "exclude_app": f.excludeApp, "host": f.host, "exclude_host": f.excludeHost} {
		if val != "" {
			add(param, paramFlags[param], strings.Split(val, ",")...)
		}
	}

	// --field and --not-field, from the type's schema.
	excluded := map[string][]string{} // closed fields: the values to take out of the domain
	for _, neg := range []bool{false, true} {
		list, name := f.fields, "--field"
		if neg {
			list, name = f.notFields, "--not-field"
		}
		for _, kv := range list {
			key, vals, ok := strings.Cut(kv, "=")
			key = strings.TrimSpace(key)
			if !ok || key == "" || strings.TrimSpace(vals) == "" {
				return nil, fmt.Errorf("%s %q: use KEY=V1,V2", name, kv)
			}
			fd := findField(ts, key)
			if fd == nil {
				var keys []string
				for _, x := range ts.Fields {
					keys = append(keys, x.Key)
				}
				return nil, fmt.Errorf("%s %q: %s has no field %q (fields: %s)", name, kv, ts.Type, key, strings.Join(keys, ", "))
			}
			from := name + " " + key
			switch {
			case !neg:
				add(fd.Param, from, strings.Split(vals, ",")...)
			case fd.ExcludeParam != "":
				add(fd.ExcludeParam, from, strings.Split(vals, ",")...)
			default:
				for _, x := range strings.Split(vals, ",") {
					x = strings.TrimSpace(x)
					if !slices.ContainsFunc(fd.Domain, func(d search.DomainValue) bool { return strings.EqualFold(d.Value, x) }) {
						return nil, fmt.Errorf("%s %q: %q isn't a %s (%s)", name, kv, x, key, domainList(fd.Domain))
					}
					excluded[fd.Param] = append(excluded[fd.Param], strings.ToLower(x))
				}
				if _, ok := origin[fd.Param]; !ok {
					origin[fd.Param] = from
				}
			}
		}
	}
	for _, fd := range ts.Fields {
		ex := excluded[fd.Param]
		if len(ex) == 0 {
			continue
		}
		// A closed field's exclusion is the rest of its domain (within what
		// was asked for, if anything was).
		keep := v[fd.Param]
		if len(keep) == 0 {
			for _, d := range fd.Domain {
				keep = append(keep, d.Value)
			}
		}
		var rest []string
		for _, x := range keep {
			if !slices.Contains(ex, strings.ToLower(x)) {
				rest = append(rest, x)
			}
		}
		if len(rest) == 0 {
			rest = []string{"none"}
		}
		v.Del(fd.Param)
		v[fd.Param] = rest
	}

	// Time.
	switch {
	case f.last != "":
		d, err := parseDurationArg(f.last)
		if err != nil {
			return nil, fmt.Errorf("--last: %v", err)
		}
		set("from", now.Add(-d).UTC().Format(time.RFC3339Nano))
		set("to", now.UTC().Format(time.RFC3339Nano))
	default:
		zone := loc
		if f.utc {
			zone = time.UTC
		}
		var from, to time.Time
		var err error
		if f.to != "" {
			if to, err = parseTimeArg(f.to, now, zone); err != nil {
				return nil, fmt.Errorf("--to: %v", err)
			}
		} else {
			to = now
		}
		if f.from != "" {
			if from, err = parseTimeArg(f.from, now, zone); err != nil {
				return nil, fmt.Errorf("--from: %v", err)
			}
		} else {
			from = to.Add(-search.DefaultRange)
		}
		set("from", from.UTC().Format(time.RFC3339Nano))
		set("to", to.UTC().Format(time.RFC3339Nano))
	}

	// Each parameter on its own first, so its message names its flag.
	params := make([]string, 0, len(v))
	for p := range v {
		params = append(params, p)
	}
	slices.Sort(params)
	for _, p := range params {
		one := url.Values{p: {strings.Join(v[p], ",")}}
		if _, err := api.ParseSearch(one); err != nil {
			msg := strings.TrimPrefix(err.Error(), p+": ")
			return nil, fmt.Errorf("%s: %s", origin[p], msg)
		}
	}
	for p, vals := range v {
		v[p] = []string{strings.Join(vals, ",")}
	}
	if _, err := api.ParseSearch(v); err != nil {
		if strings.Contains(err.Error(), `"from" must be before "to"`) {
			return nil, errors.New("--from must be before --to")
		}
		return nil, err
	}
	return v, nil
}

func findType(name string) *search.TypeSchema {
	for _, t := range search.Schema() {
		if strings.EqualFold(t.Type, name) {
			return &t
		}
	}
	return nil
}

func findField(t *search.TypeSchema, key string) *search.FieldSchema {
	for i := range t.Fields {
		if strings.EqualFold(t.Fields[i].Key, key) {
			return &t.Fields[i]
		}
	}
	return nil
}

func domainList(d []search.DomainValue) string {
	var vs []string
	for _, x := range d {
		vs = append(vs, x.Value)
	}
	return strings.Join(vs, ", ")
}

// ---- the data folder ----

// searchDataDir finds the data folder: --data, the --config file's, a portable
// copy's woodshed-data next to the binary, or the installed service's. A
// non-zero code comes with the message to print.
func searchDataDir(f *searchFlags, cmdline string) (dir string, code int, msg string) {
	if f.data != "" {
		abs, err := filepath.Abs(f.data)
		if err != nil {
			return "", exitUsage, fmt.Sprintf("--data: %v", err)
		}
		return abs, 0, ""
	}
	if !f.set["config"] {
		if exe, err := searchExe(); err == nil {
			next := filepath.Join(filepath.Dir(exe), portableDirName)
			if _, err := os.Stat(filepath.Join(next, index.FileName)); err == nil {
				return next, 0, ""
			}
		}
	}
	abs, err := filepath.Abs(f.config)
	if err != nil {
		return "", exitUsage, fmt.Sprintf("--config: %v", err)
	}
	c, err := config.Read(abs) // never creates it
	if errors.Is(err, fs.ErrNotExist) {
		if f.set["config"] {
			return "", exitNoData, fmt.Sprintf("there's no config file at %s.", abs)
		}
		return config.DefaultDataDir(), 0, "" // installed with the default folder, or not installed
	}
	if errors.Is(err, fs.ErrPermission) {
		return "", exitAccess, accessDenied(abs, cmdline)
	}
	if err != nil {
		return "", exitNoData, strings.TrimPrefix(err.Error(), "config: ")
	}
	return c.Storage.DataDir, 0, ""
}

// openSearchIndex checks that the data folder can be read and opens its index
// read-only. A non-zero code comes with the message to print.
func openSearchIndex(dir, cmdline string) (*index.DB, int, string) {
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, exitNoData, fmt.Sprintf("there's no data folder at %s. Pass --data DIR (or --config FILE) to search another one.", dir)
	case errors.Is(err, fs.ErrPermission):
		return nil, exitAccess, accessDenied(dir, cmdline)
	case err != nil:
		return nil, exitNoData, err.Error()
	case !fi.IsDir():
		return nil, exitNoData, fmt.Sprintf("%s isn't a folder.", dir)
	}
	for _, d := range []string{dir, filepath.Join(dir, "logs")} {
		h, err := os.Open(d)
		if err == nil {
			_, err = h.Readdirnames(1)
			h.Close()
		}
		if errors.Is(err, fs.ErrPermission) {
			return nil, exitAccess, accessDenied(d, cmdline)
		}
	}
	path := filepath.Join(dir, index.FileName)
	idx, err := index.OpenReadOnly(path)
	switch {
	case errors.Is(err, index.ErrNoIndex):
		return nil, exitNoData, fmt.Sprintf("there's no index (%s) in %s, so it isn't a Woodshed data folder, or Woodshed hasn't run there yet. "+
			"Pass --data DIR (or --config FILE) to search another one.", index.FileName, dir)
	case errors.Is(err, fs.ErrPermission):
		return nil, exitAccess, accessDenied(path, cmdline)
	case errors.Is(err, index.ErrUnsafeFile):
		return nil, exitAccess, strings.TrimPrefix(err.Error(), "index: ")
	case err != nil:
		return nil, exitNoData, strings.TrimPrefix(err.Error(), "index: ")
	}
	return idx, 0, ""
}

// ---- output ----

// searchOut writes matches (and their context) to standard output, buffered
// and flushed at least every searchFlushEvery.
type searchOut struct {
	mu      sync.Mutex
	w       *bufio.Writer
	f       *searchFlags
	desc    bool
	names   map[string]string
	around  *search.Around
	matches int64
	err     error // the first write error

	// --context: the open group of lines (one file's, in output order).
	grp struct {
		open    bool
		file    int64
		last    int64           // offset of the last line printed in it
		pending []search.Result // lines after the last match, not printed yet
	}
	printed bool // something has been printed (a "--" goes before the next group)
}

func newSearchOut(w io.Writer, f *searchFlags, asc bool) *searchOut {
	return &searchOut{w: bufio.NewWriterSize(w, 64<<10), f: f, desc: !asc, names: map[string]string{}}
}

// flushEvery flushes the output every d until the returned func is called.
func (o *searchOut) flushEvery(d time.Duration) func() {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(d)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				o.mu.Lock()
				if o.w.Buffered() > 0 && o.err == nil {
					o.err = o.w.Flush()
				}
				o.mu.Unlock()
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

// match prints one match (with its context).
func (o *searchOut) match(r *search.Result) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.matches++
	if o.f.context == 0 {
		o.line(r, true)
		return o.err
	}
	n := o.f.context
	var pre, post []search.Result
	var err error
	// One more line on the preceding side (in output order): it shows whether
	// this group touches the previous one.
	if o.desc {
		var older, newer []search.Result
		older, newer, err = o.around.Lines(r.FileID, r.Offset, n, n+1)
		pre, post = reversed(newer), reversed(older)
	} else {
		pre, post, err = o.around.Lines(r.FileID, r.Offset, n+1, n)
	}
	if err != nil {
		pre, post = nil, nil // the file went away: the match alone
	}
	// after reports whether a comes after b in the output order.
	after := func(a, b int64) bool {
		if o.desc {
			return a < b
		}
		return a > b
	}
	g := &o.grp
	frontier := g.last
	if len(g.pending) > 0 {
		frontier = g.pending[len(g.pending)-1].Offset
	}
	first := r.Offset
	if len(pre) > 0 {
		first = pre[0].Offset
	}
	if g.open && g.file == r.FileID && !after(first, frontier) {
		// It touches or overlaps the open group: carry on without a "--".
		for i := range g.pending {
			if p := &g.pending[i]; after(r.Offset, p.Offset) {
				o.line(p, false)
				g.last = p.Offset
			}
		}
		for i := range pre {
			if after(pre[i].Offset, g.last) {
				o.line(&pre[i], false)
			}
		}
	} else {
		o.closeGroup()
		if o.printed && !o.f.json {
			o.write([]byte("--\n"))
		}
		if len(pre) > n {
			pre = pre[1:]
		}
		for i := range pre {
			o.line(&pre[i], false)
		}
		g.open, g.file = true, r.FileID
	}
	o.line(r, true)
	g.last, g.pending = r.Offset, post
	return o.err
}

// closeGroup prints the open group's remaining lines.
func (o *searchOut) closeGroup() {
	g := &o.grp
	for i := range g.pending {
		o.line(&g.pending[i], false)
	}
	g.open, g.pending = false, nil
}

// finish prints what's left and flushes.
func (o *searchOut) finish() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.closeGroup()
	if o.err == nil {
		o.err = o.w.Flush()
	}
}

func reversed(rs []search.Result) []search.Result {
	slices.Reverse(rs)
	return rs
}

func (o *searchOut) write(b []byte) {
	if o.err == nil {
		_, o.err = o.w.Write(b)
	}
}

// line prints one stored line, a match or a context line.
func (o *searchOut) line(r *search.Result, isMatch bool) {
	o.printed = true
	if o.f.json {
		b, err := api.SearchLine{Received: r.Received, DeviceID: r.DeviceID, Severity: r.Severity, Raw: r.Raw, Ref: r.Ref,
			App: r.App, Host: r.Host}.MarshalJSON()
		if err != nil {
			o.err = err
			return
		}
		name, _ := json.Marshal(strings.ToValidUTF8(o.names[r.DeviceID], "�"))
		typ, _ := json.Marshal(o.f.typ)
		b = append(b[:len(b)-1], `,"type":`...)
		b = append(b, typ...)
		b = append(b, `,"device_name":`...)
		b = append(b, name...)
		if o.f.context > 0 {
			b = append(b, `,"context":`...)
			b = strconv.AppendBool(b, !isMatch)
		}
		o.write(append(b, "}\n"...))
		return
	}
	if o.f.context > 0 {
		if isMatch {
			o.write([]byte("> "))
		} else {
			o.write([]byte("  "))
		}
	}
	if o.f.raw {
		o.write(r.Raw)
	} else {
		o.write(r.Stored)
	}
	o.write([]byte("\n"))
}

// writeSummary prints the summary line on standard error.
func writeSummary(w io.Writer, asJSON bool, matches int64, st search.EachStats, interrupted bool) {
	if asJSON {
		b, _ := json.Marshal(struct {
			Matches      int64 `json:"matches"`
			ScannedBytes int64 `json:"scanned_bytes"`
			ScannedFiles int   `json:"scanned_files"`
			GoneFiles    int   `json:"gone_files"`
			ElapsedMS    int64 `json:"elapsed_ms"`
			Interrupted  bool  `json:"interrupted"`
		}{matches, st.ScannedBytes, st.ScannedFiles, st.GoneFiles, st.Elapsed.Milliseconds(), interrupted})
		fmt.Fprintf(w, "%s\n", b)
		return
	}
	s := fmt.Sprintf("%d %s, %.1f MiB read from %d %s in %.2fs", matches, plural(matches, "match", "matches"),
		float64(st.ScannedBytes)/(1<<20), st.ScannedFiles, plural(int64(st.ScannedFiles), "file", "files"), st.Elapsed.Seconds())
	if st.GoneFiles > 0 {
		s += fmt.Sprintf("; %d %s skipped (deleted or unreadable during the search)", st.GoneFiles,
			plural(int64(st.GoneFiles), "file", "files"))
	}
	if interrupted {
		s += " (interrupted)"
	}
	fmt.Fprintln(w, s)
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
