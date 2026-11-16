package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/export"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/search"
)

// `woodshed search --type flow` (SPEC §13.7): the flow engine over the data
// folder, read-only. The open hour's segment has no footer until it closes,
// so a search beside the running service sees closed segments only; it says
// so when the window reaches into the current hour.

// flowEngine is the flow query engine over a data folder, without a store
// (no open segments).
func flowEngine(dataDir string, idx *index.DB, log *slog.Logger) *flowquery.Engine {
	return flowquery.New(flowquery.Options{DataDir: dataDir, Index: idx, Logger: log})
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
	fe := flowEngine(dataDir, idx, logger)
	w := bufio.NewWriterSize(stdout, 64<<10)
	start := time.Now()
	var n int64
	headerDone := f.json || f.count
	cursor := ""
	interrupted := false
	writeErr := error(nil)
	for {
		res, err := fe.Search(ctx, q, 5000, req.Asc, cursor, time.Minute)
		if err != nil {
			if ctx.Err() != nil {
				interrupted = true
				break
			}
			fmt.Fprintf(stderr, "woodshed search: %v\n", err)
			return exitUsage
		}
		for i := range res.Hits {
			h := &res.Hits[i]
			n++
			if f.count {
				continue
			}
			if !headerDone {
				w.WriteString("device," + strings.Join(export.FlowCSVHeader(), ",") + "\r\n")
				headerDone = true
			}
			if f.json {
				rec := h.Record
				b, err := json.Marshal(api.SearchLine{Received: time.UnixMilli(rec.Received).UTC(), DeviceID: h.DeviceID,
					Type: datatype.Flow, Ref: h.Ref(), Flow: &rec})
				if err != nil {
					writeErr = err
					break
				}
				w.Write(b)
				w.WriteByte('\n')
			} else {
				w.WriteString(h.DeviceID)
				w.WriteByte(',')
				w.Write(export.AppendFlowCSVRow(nil, &h.Record))
			}
			if f.limit > 0 && n >= int64(f.limit) {
				break
			}
		}
		if res.Cursor == "" || (f.limit > 0 && n >= int64(f.limit)) || writeErr != nil {
			break
		}
		cursor = res.Cursor
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
	if to.After(searchNow().Truncate(time.Hour)) {
		fmt.Fprintln(stderr, "note: the current hour's flows are in a segment the service is still writing; they're searchable "+
			"from the UI or the API now, and here once the hour ends.")
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
