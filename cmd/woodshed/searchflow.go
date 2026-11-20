package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/export"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/search"
)

// `woodshed search --type flow` (SPEC §13.7): the flow engine over the data
// folder, read-only. Beside the running service, the hour it's still writing
// is read up to its last complete block (about a second behind).

// flowEngine is the flow query engine over a data folder, without a store
// (no open segments). rules are the config's listeners.flow.rule_id_ies, so
// raw sets decoded on read fill rule_id as the service does.
func flowEngine(dataDir string, idx *index.DB, log *slog.Logger, rules []flow.IEKey) *flowquery.Engine {
	return flowquery.New(flowquery.Options{DataDir: dataDir, Index: idx, Logger: log, RuleIDIEs: rules})
}

// ruleIEsOf is a config's listeners.flow.rule_id_ies as IE keys (entries that
// don't parse are left out; validation reports them).
func ruleIEsOf(c config.Config) []flow.IEKey {
	var out []flow.IEKey
	for _, s := range c.Listeners.Flow.RuleIDIEs {
		if pen, id, ok := config.ParseRuleIDIE(s); ok {
			out = append(out, flow.IEKey{PEN: pen, ID: id})
		}
	}
	return out
}

// searchRuleIEs is the rule_id_ies of the config behind a data folder, best
// effort and read-only: --config when given, else the folder's own
// woodshed.toml (a portable copy), else the installed config unless --data
// named another folder. Nil when none can be read.
func searchRuleIEs(f *searchFlags, dataDir string) []flow.IEKey {
	c, ok := searchConfig(f, dataDir)
	if !ok {
		return nil
	}
	return ruleIEsOf(c)
}

// searchSeverity is the syslog severity filter in effect for a device, from
// the same config as searchRuleIEs, for a bundle's summary (nil: the config
// can't be read, so the README gives the counts without the setting).
func searchSeverity(f *searchFlags, dataDir string) func(id string) (int, bool) {
	c, ok := searchConfig(f, dataDir)
	if !ok {
		return nil
	}
	return func(id string) (int, bool) {
		a, err := netip.ParseAddr(strings.ReplaceAll(id, "_", ":"))
		if err != nil {
			return c.Syslog.Level(), false
		}
		return c.Syslog.DeviceLevel(a)
	}
}

// searchConfig reads the config that goes with the data folder: --config
// when given, the data folder's own woodshed.toml, or the default config
// when --data isn't given. It never creates one.
func searchConfig(f *searchFlags, dataDir string) (config.Config, bool) {
	var path string
	switch own := filepath.Join(dataDir, config.FileName); {
	case f.set["config"]:
		path = f.config
	case fileExists(own):
		path = own
	case !f.set["data"]:
		path = f.config
	default:
		return config.Config{}, false
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return config.Config{}, false
	}
	c, err := config.Read(abs) // never creates it
	return c, err == nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// flowRange applies search's defaults to a request's range.
func flowRange(r api.SearchRequest) (time.Time, time.Time) {
	to := r.To
	if to.IsZero() {
		to = searchNow().UTC()
	}
	from := r.From
	if from.IsZero() {
		from = to.Add(-search.DefaultRange)
	}
	return from, to
}

// errFlowStop ends a flow listing early (the limit, or a write error).
var errFlowStop = errors.New("stop")

func flowSearch(stdout, stderr io.Writer, f *searchFlags, req api.SearchRequest, dataDir string, idx *index.DB, indexPath string,
	before index.FileState) int {
	if f.context > 0 {
		fmt.Fprintln(stderr, "woodshed search: --context: flows have no neighbouring lines")
		return exitUsage
	}
	if f.raw {
		fmt.Fprintln(stderr, "woodshed search: --raw: a flow record isn't a message; use the default rows or --json")
		return exitUsage
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	eng := search.New(search.Options{DataDir: dataDir, Index: idx, Now: searchNow, Logger: logger})
	ctx, stop := searchSignals(context.Background())
	defer stop()
	devs, err := eng.ResolveDevices(ctx, req.Devices, req.Group, req.Ungrouped, req.ExcludeDevices)
	if err != nil {
		fmt.Fprintf(stderr, "woodshed search: %v\n", err)
		return exitUsage
	}
	if devs == nil {
		devs = []string{}
	}
	filter, err := req.Flow.Filter()
	if err != nil {
		fmt.Fprintf(stderr, "woodshed search: %v\n", err)
		return exitUsage
	}
	from, to := flowRange(req)
	q := flowquery.Query{DeviceIDs: devs, From: from, To: to, Filter: filter}
	fe := flowEngine(dataDir, idx, logger, searchRuleIEs(f, dataDir))
	w := bufio.NewWriterSize(stdout, 64<<10)
	start := time.Now()
	var n int64
	headerDone := f.json || f.count
	interrupted := false
	writeErr := error(nil)
	var line []byte
	// Every record in order, each block decoded once (Engine.Stream gives
	// what Search's pages would, one after another).
	err = fe.Stream(ctx, q, req.Asc, func(h *flowquery.Hit) error {
		n++
		if !f.count {
			line = line[:0]
			if !headerDone {
				line = append(line, "device,"+strings.Join(export.FlowCSVHeader(), ",")+"\r\n"...)
				headerDone = true
			}
			if f.json {
				rec := &h.Record
				line = api.AppendFlowLineJSON(line, &api.SearchLine{Received: time.UnixMilli(rec.Received).UTC(),
					DeviceID: h.DeviceID, Type: datatype.Flow, Ref: h.Ref(), Flow: rec})
				line = append(line, '\n')
			} else {
				line = append(line, h.DeviceID...)
				line = append(line, ',')
				line = export.AppendFlowCSVRow(line, &h.Record)
			}
			if _, err := w.Write(line); err != nil {
				writeErr = err
				return errFlowStop
			}
		}
		if f.limit > 0 && n >= int64(f.limit) {
			return errFlowStop
		}
		return nil
	})
	switch {
	case err == nil, errors.Is(err, errFlowStop):
	case ctx.Err() != nil:
		interrupted = true
	default:
		fmt.Fprintf(stderr, "woodshed search: %v\n", err)
		return exitUsage
	}
	if err := w.Flush(); err != nil && writeErr == nil {
		writeErr = err
	}
	if writeErr != nil {
		fmt.Fprintf(stderr, "woodshed search: can't write the output: %v\n", writeErr)
		return exitUsage
	}
	if f.count {
		if f.json {
			fmt.Fprintf(stdout, "{\"count\":%d}\n", n)
		} else {
			fmt.Fprintln(stdout, n)
		}
	}
	took := time.Since(start)
	if f.json {
		b, _ := json.Marshal(struct {
			Matches     int64 `json:"matches"`
			ElapsedMS   int64 `json:"elapsed_ms"`
			Interrupted bool  `json:"interrupted"`
		}{n, took.Milliseconds(), interrupted})
		fmt.Fprintf(stderr, "%s\n", b)
	} else {
		s := fmt.Sprintf("%d flow %s in %.2fs", n, plural(n, "record", "records"), took.Seconds())
		if interrupted {
			s += " (interrupted)"
		}
		fmt.Fprintln(stderr, s)
	}
	if idx.Immutable() && index.StateOf(indexPath) != before {
		fmt.Fprintln(stderr, "warning: Woodshed started writing while this search ran; results may be incomplete. Run it again.")
	}
	switch {
	case interrupted:
		return exitInterrupted
	case n > 0:
		return exitMatch
	}
	return exitNoMatch
}
