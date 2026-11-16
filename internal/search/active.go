package search

import (
	"context"
	"errors"
	"path/filepath"
	"sort"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
)

// Active answers "which devices stored anything in [from, to)?" for the
// incident bundle's active_devices and GET /api/devices?active_from&active_to
// (SPEC §11.3). It is exact, and reads as little as it can:
//
//  1. the index's file rows of each type that may hold a line in the range
//     (widened back by the index's lag, as a search is);
//  2. a file whose first or last received time is in the range proves it:
//     both are times of stored lines;
//  3. so does a checkpoint received in the range: a checkpoint's time is the
//     highest received time of the lines up to it, so a line with that time
//     is stored;
//  4. otherwise (a file that spans the whole range, with no checkpoint in it)
//     one scan of the range, which stops at the first line it finds and
//     starts at the checkpoint before from.
//
// The per-minute stats aren't used: a minute bucket only roughly matches the
// range's edges, and the stats outlive the files retention deletes.
//
// It returns, for each active device, the types it stored records of in the
// range, in the order of types. Hidden devices are included; callers apply
// their own selection rules.
func (e *Engine) Active(ctx context.Context, types []string, from, to time.Time) (map[string][]string, error) {
	fromMs, toMs := ceilMs(from), ceilMs(to)
	out := map[string][]string{}
	if fromMs >= toMs {
		return out, nil
	}
	in := func(t time.Time) bool { ms := t.UnixMilli(); return ms >= fromMs && ms < toMs }
	for _, typ := range types {
		if err := CheckType(typ); err != nil {
			return nil, &QueryError{Msg: err.Error()}
		}
		spans, err := e.idx.FilesInRangeOf(ctx, typ, nil, time.UnixMilli(fromMs).Add(-maxSkew), time.UnixMilli(toMs))
		if err != nil {
			return nil, err
		}
		found := map[string]bool{}
		if datatype.IsSegments(typ) {
			// Flow segments have no checkpoints and aren't lines: each
			// candidate segment's blocks (and raw sets) are checked by their
			// received times, decoding only a block that straddles the range.
			for _, sp := range spans {
				f := sp.File
				if found[f.DeviceID] || f.Lines == 0 || f.FirstReceived.UnixMilli() >= toMs || f.LastReceived.UnixMilli() < fromMs {
					continue
				}
				ok, err := e.flowActive(filepath.Join(e.dataDir, filepath.FromSlash(f.Path)), fromMs, toMs)
				if err != nil {
					e.log.Warn("search: a flow segment couldn't be read for the active devices", "file", f.Path, "err", err)
					continue
				}
				found[f.DeviceID] = ok
			}
			for d, ok := range found {
				if ok {
					out[d] = append(out[d], typ)
				}
			}
			continue
		}
		var unsure []int64 // file IDs that need their checkpoints
		unsureDev := map[int64]string{}
		for _, sp := range spans {
			f := sp.File
			if found[f.DeviceID] {
				continue
			}
			if in(f.FirstReceived) || in(f.LastReceived) {
				found[f.DeviceID] = true
				continue
			}
			unsure = append(unsure, f.ID)
			unsureDev[f.ID] = f.DeviceID
		}
		if len(unsure) > 0 {
			cps, err := e.idx.CheckpointsFor(ctx, unsure)
			if err != nil {
				return nil, err
			}
			for id, cs := range cps {
				for _, c := range cs {
					if in(c.Received) {
						found[unsureDev[id]] = true
						break
					}
				}
			}
		}
		// The rest are read: devices with a candidate file and no proof yet.
		var scan []string
		seen := map[string]bool{}
		for _, id := range unsure {
			if d := unsureDev[id]; !found[d] && !seen[d] {
				seen[d] = true
				scan = append(scan, d)
			}
		}
		sort.Strings(scan)
		for _, d := range scan {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			sc, err := e.NewScanner(ctx, d, Filter{From: time.UnixMilli(fromMs), To: time.UnixMilli(toMs), Type: typ})
			if err != nil {
				return nil, err
			}
			_, ok := sc.Next()
			sc.Close()
			if err := sc.Err(); err != nil {
				return nil, err
			}
			if ok {
				found[d] = true
			}
		}
		for d, ok := range found {
			if ok {
				out[d] = append(out[d], typ)
			}
		}
	}
	return out, nil
}

// flowActive reports whether a flow segment holds a record or a raw set
// received in [fromMs, toMs): a block wholly inside the range proves it, a
// block that straddles it is decoded (the received column only).
func (e *Engine) flowActive(path string, fromMs, toMs int64) (bool, error) {
	r, err := flowseg.Open(path)
	if errors.Is(err, flowseg.ErrNoFooter) {
		r, err = flowseg.OpenLive(path) // the segment the store is writing
	}
	if err != nil {
		return false, err
	}
	defer r.Close()
	f := r.Footer()
	var blk flowseg.Block
	for i := range f.Blocks {
		b := &f.Blocks[i]
		switch {
		case b.Rows == 0 || b.MaxReceived < fromMs || b.MinReceived >= toMs:
			continue
		case b.MinReceived >= fromMs && b.MaxReceived < toMs:
			return true, nil
		}
		if err := r.Decode(i, flowseg.ColReceived, &blk); err != nil {
			return false, err
		}
		for _, ms := range blk.Received() {
			if ms >= fromMs && ms < toMs {
				return true, nil
			}
		}
	}
	found := false
	err = r.Raw(func(rs *flow.RawSet) bool {
		found = rs.Received >= fromMs && rs.Received < toMs
		return !found
	})
	return found, err
}
