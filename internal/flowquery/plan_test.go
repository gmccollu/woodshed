package flowquery

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// The plan's open segments while the store changes their index rows (each
// flush moves a row's end; a new segment gets its first row): every open
// segment is read once, whatever its row does during the plan.

// planEnv is writeHours' segments, each listed as open (its snapshot a fresh
// copy of its directory, as Writer.Snapshot makes); onSnap runs inside every
// snapshot, as the store's flushes would run between a plan's batches.
type planEnv struct {
	e      *Engine
	segs   []index.FlowSegment // by device ID
	onSnap func(rel string)
}

func newPlanEnv(t *testing.T, exporters, blocks int) *planEnv {
	t.Helper()
	pe := &planEnv{e: writeHours(t, hour0, 1, exporters, blocks)}
	segs, err := pe.e.o.Index.FlowSegments(bg, nil, time.Time{}, time.Time{})
	if err != nil || len(segs) != exporters {
		t.Fatalf("%d segments: %v", len(segs), err)
	}
	slices.SortFunc(segs, func(a, b index.FlowSegment) int { return cmpStr(a.DeviceID, b.DeviceID) })
	pe.segs = segs
	pe.e.o.Open = func([]string) []OpenSegment {
		out := make([]OpenSegment, len(pe.segs))
		for i, sg := range pe.segs {
			rel, path := sg.Path, filepath.Join(pe.e.o.DataDir, sg.Path)
			out[i] = OpenSegment{DeviceID: sg.DeviceID, Rel: rel, Path: path, Snap: func() *flowseg.Footer {
				if pe.onSnap != nil {
					pe.onSnap(rel)
				}
				r, err := flowseg.Open(path)
				if err != nil {
					return nil
				}
				defer r.Close()
				f := *r.Footer()
				f.Blocks = slices.Clone(f.Blocks)
				return &f
			}}
		}
		return out
	}
	pe.e.page, pe.e.batch = 1, 2 // one row a page; a batch a segment
	return pe
}

func cmpStr(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// setRow rewrites segment i's index row with its end moved by d (as a flush
// would), or deletes it (del).
func (pe *planEnv) setRow(t *testing.T, i int, d time.Duration, del bool) {
	t.Helper()
	sg := pe.segs[i]
	if del {
		if err := pe.e.o.Index.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpDelete,
			File: index.File{DeviceID: sg.DeviceID, Type: index.TypeFlow, Path: sg.Path}}}}); err != nil {
			t.Fatal(err)
		}
		return
	}
	path := filepath.Join(pe.e.o.DataDir, sg.Path)
	r, err := flowseg.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	foot := r.Footer()
	r.Close()
	fi, _ := os.Stat(path)
	name, _ := flowseg.ParseName(filepath.Base(path))
	rows := index.FlowRowsOf(index.FlowFile{DeviceID: sg.DeviceID, Name: name, Rel: sg.Path, Path: path}, foot, fi.Size(), false)
	rows.Segment.End += d.Milliseconds()
	if err := pe.e.o.Index.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment}}}); err != nil {
		t.Fatal(err)
	}
}

func (pe *planEnv) check(t *testing.T, what string, want int64) {
	t.Helper()
	q := hourQuery()
	c, err := pe.e.Count(bg, q)
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range pe.segs {
		if c[sg.DeviceID] != want {
			t.Fatalf("%s: count %v, want %d each", what, c, want)
		}
	}
	for _, asc := range []bool{false, true} {
		res, err := pe.e.Search(bg, q, 100_000, asc, "", time.Hour)
		if err != nil || res.Partial || res.Cursor != "" || len(res.Hits) != int(want)*len(pe.segs) {
			t.Fatalf("%s: search asc %v: %d hits, partial %v, cursor %q (want %d): %v", what, asc, len(res.Hits),
				res.Partial, res.Cursor, want*int64(len(pe.segs)), err)
		}
		seen := map[[3]any]bool{}
		for _, h := range res.Hits {
			k := [3]any{h.Rel, h.Block, h.Row}
			if seen[k] {
				t.Fatalf("%s: search asc %v read %v twice", what, asc, k)
			}
			seen[k] = true
		}
	}
	top, err := pe.e.Top(bg, q, "src", "flows", 10, time.Hour, "")
	if err != nil || top.Partial || top.Total.Flows != want*int64(len(pe.segs)) || !top.Progress.CompleteFrom.Equal(q.From) {
		t.Fatalf("%s: top flows %d partial %v complete_from %v: %v", what, top.Total.Flows, top.Partial,
			top.Progress.CompleteFrom, err)
	}
	if u := pe.e.pool.Used(); u != 0 {
		t.Fatalf("%s: pool used %d after the queries", what, u)
	}
}

// An open segment whose row moves ahead of the plan's page cursor while the
// plan runs is still read (it used to come only from the pages, and its row
// jumped past them).
func TestPlanOpenRowMoves(t *testing.T) {
	pe := newPlanEnv(t, 3, 10)
	moved := 0
	pe.onSnap = func(rel string) {
		// Each segment loaded moves every other's row ahead, a minute
		// further each time.
		moved++
		for i, sg := range pe.segs {
			if sg.Path != rel {
				pe.setRow(t, i, time.Duration(moved)*time.Minute, false)
			}
		}
	}
	pe.check(t, "rows moving", 20)
	if moved == 0 {
		t.Fatal("no snapshot moved a row")
	}
}

// An open segment unindexed when the plan starts and indexed during it is
// read once (it used to be read first as unindexed, then again from its row).
func TestPlanOpenIndexedDuring(t *testing.T) {
	pe := newPlanEnv(t, 3, 10)
	pe.setRow(t, 2, 0, true)
	pe.onSnap = func(rel string) {
		if rel == pe.segs[2].Path {
			pe.setRow(t, 2, 0, false) // its first row lands
		}
	}
	for i := 0; i < 3; i++ {
		pe.check(t, "indexed during the plan", 20)
		pe.setRow(t, 2, 0, true)
	}
}

// A search page whose cursor is behind many segments skips them in a loop:
// the stack doesn't grow with the segments skipped (nextSeg recursed once a
// segment, about 1 KB each: 1,000 here would pass a 512 KiB stack limit).
func TestPlanSkipsWithoutRecursion(t *testing.T) {
	if testing.Short() {
		t.Skip("short: writes 1,000 segments")
	}
	const hours = 1000
	start := hour0.Add(-hours * time.Hour)
	e := writeHours(t, start, hours, 1, 1) // one block of 2 records an hour
	q := Query{From: start, To: start.Add(hours * time.Hour)}
	first, err := e.Search(bg, q, 2*hours-1, false, "", time.Hour) // all but the oldest, newest first
	if err != nil || len(first.Hits) != 2*hours-1 || first.Cursor == "" {
		t.Fatalf("first page: %v, %d hits, cursor %q", err, len(first.Hits), first.Cursor)
	}
	old := debug.SetMaxStack(512 << 10)
	defer debug.SetMaxStack(old)
	last, err := e.Search(bg, q, 10, false, first.Cursor, time.Hour) // skips every newer segment
	if err != nil || len(last.Hits) != 1 || last.Cursor != "" || last.Partial {
		t.Fatalf("last page: %v, %d hits, cursor %q, partial %v", err, len(last.Hits), last.Cursor, last.Partial)
	}
}
