package store

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

var restartHour = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

// flowDerived renders what the index derives from the segments' footers:
// every flow_segments row and the per-device, per-minute flow_minute sums.
// A full Reindex of the same files must give the same.
func flowDerived(t *testing.T, idx *index.DB) string {
	t.Helper()
	var b strings.Builder
	segs, err := idx.AllFlowSegments(bg)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range segs {
		fmt.Fprintf(&b, "seg %+v\n", s)
	}
	from, to := restartHour.Add(-2*time.Hour).UnixMilli(), restartHour.Add(8*time.Hour).UnixMilli()
	m, err := idx.FlowMinuteBuckets(bg, nil, from, to, 0, time.Minute.Milliseconds(), true)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&b, "minutes %+v\n", m)
	return b.String()
}

// flowStored renders the rest of the store's flow state in the index: the
// files rows (with their IDs: a row kept as is keeps its ID), the devices
// and the collector's counts in type_stats.
func flowStored(t *testing.T, idx *index.DB) string {
	t.Helper()
	var b strings.Builder
	files, err := idx.Files(bg, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Type == index.TypeFlow {
			fmt.Fprintf(&b, "file %+v\n", f)
		}
	}
	devs, err := idx.ListDevices(bg)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		fmt.Fprintf(&b, "dev %s %s %s %s %d %d\n", d.ID, d.IP, d.FirstSeen.Format(time.RFC3339Nano),
			d.LastHeard.Format(time.RFC3339Nano), d.TotalMsgs, d.TotalBytes)
	}
	counts, err := idx.FlowCountBuckets(bg, restartHour.Add(-2*time.Hour), restartHour.Add(8*time.Hour), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range counts {
		fmt.Fprintf(&b, "count %s %s %d %+v\n", c.DeviceID, c.Start.Format(time.RFC3339), c.Records, c.FlowCounts)
	}
	return b.String()
}

// reindexed is flowDerived of a fresh index rebuilt from dir's footers.
func reindexed(t *testing.T, dir string) string {
	t.Helper()
	idx, err := index.Open(filepath.Join(t.TempDir(), index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	if _, err := idx.Reindex(bg, dir); err != nil {
		t.Fatal(err)
	}
	return flowDerived(t, idx)
}

// checkFlowCatalog compares the store's closed-segment catalog with the
// segments on disk, as their footers say (what recovery used to read for
// every one).
func checkFlowCatalog(t *testing.T, s *Store, wantRels []string) {
	t.Helper()
	s.fl.mu.Lock()
	defer s.fl.mu.Unlock()
	var rels []string
	var bytes int64
	for rel, seg := range s.fl.cat {
		rels = append(rels, rel)
		bytes += seg.size
		r, err := flowseg.Open(seg.abs)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		f := r.Footer()
		r.Close()
		fi, err := os.Stat(seg.abs)
		if err != nil {
			t.Fatal(err)
		}
		if seg.size != fi.Size() || seg.records != f.Totals.Records || !seg.first.Equal(time.UnixMilli(f.MinReceived).UTC()) ||
			!seg.last.Equal(time.UnixMilli(f.MaxReceived).UTC()) || seg.deviceID != f.DeviceID {
			t.Fatalf("%s: catalog %+v, footer %d records %d..%d, size %d", rel, *seg, f.Totals.Records, f.MinReceived, f.MaxReceived, fi.Size())
		}
	}
	sort.Strings(rels)
	wantRels = append([]string(nil), wantRels...)
	sort.Strings(wantRels)
	if fmt.Sprint(rels) != fmt.Sprint(wantRels) {
		t.Fatalf("catalog %v, want %v", rels, wantRels)
	}
	if s.fl.catBytes != bytes {
		t.Fatalf("catalog bytes %d, segments %d", s.fl.catBytes, bytes)
	}
}

// writeFlowsAt stores n records received at the clock's time.
func (e *env) writeFlowsAt(addr netip.Addr, n int, seq *int) {
	e.t.Helper()
	e.writeFlows(addr, n, *seq)
	*seq += 100
}

// A clean restart reads no flow segment: their rows are kept as the close
// wrote them (identical to what a rebuild from the footers gives), so there's
// no recovery event, and the catalog, flow counts and minutes are the same.
// After a crash-cut segment, a deleted one and one added by hand, the
// recovery covers exactly those three.
func TestFlowCleanRestartReadsNoSegments(t *testing.T) {
	e := newEnv(t, nil)
	a, b := ip(7), ip(8)
	seq := 0
	var rels []string
	for i := 0; i < 4; i++ {
		e.clock.Set(restartHour.Add(time.Duration(i)*time.Hour + 10*time.Minute))
		e.writeFlowsAt(a, 20+i, &seq)
		e.writeFlowsAt(b, 5+i, &seq)
		e.clock.Add(time.Minute)
		e.writeFlowsAt(a, 3, &seq)
		raws := []*flow.RawSet{{Received: e.clock.Now().UnixMilli(), Exporter: b, Status: flow.StatusNoTemplate, Data: []byte{1}}}
		if err := e.s.WriteFlows(b, FlowBatch{Received: e.clock.Now(), Size: 100, Records: flowRecs(e.clock.Now(), 2, seq), Raw: raws,
			SeqGaps: 1, SeqLost: 7}); err != nil {
			t.Fatal(err)
		}
		seq += 100
		e.maintain()
		name := flowseg.NameFor(restartHour.Add(time.Duration(i) * time.Hour)).String()
		rels = append(rels, "logs/192.0.2.7/flows/"+name, "logs/192.0.2.8/flows/"+name)
	}
	// Three hours' segments closed by the hour, the fourth by Close.
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	if evs := eventsOf(t, e.idx, index.KindRecover); len(evs) != 0 {
		t.Fatalf("recover events before the restart %+v", evs)
	}
	derived, stored := flowDerived(t, e.idx), flowStored(t, e.idx)
	if !strings.Contains(derived, "Closed:true") || strings.Contains(derived, "Closed:false") || strings.Count(derived, "seg ") != 8 {
		t.Fatalf("segments before the restart\n%s", derived)
	}
	// What the store wrote as it went is what the footers say: keeping the
	// rows loses nothing a rebuild would restore.
	if want := reindexed(t, e.dir); derived != want {
		t.Fatalf("the store's rows differ from a rebuild\nstore:\n%s\nrebuild:\n%s", derived, want)
	}

	e.open()
	if evs := eventsOf(t, e.idx, index.KindRecover); len(evs) != 0 {
		t.Fatalf("a clean restart logged recovery %+v", evs)
	}
	if got := flowDerived(t, e.idx); got != derived {
		t.Fatalf("flow rows changed over a clean restart\ngot:\n%s\nwant:\n%s", got, derived)
	}
	if got := flowStored(t, e.idx); got != stored {
		t.Fatalf("flow files, devices or counts changed over a clean restart\ngot:\n%s\nwant:\n%s", got, stored)
	}
	checkFlowCatalog(t, e.s, rels)
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	if res, err := e.idx.Reconcile(bg, e.dir); err != nil || res.Scanned != 0 || res.Removed != 0 || len(res.Skipped) != 0 {
		t.Fatalf("reconcile after a clean restart %+v %v", res, err)
	}

	// Out of band, with the store stopped: a segment cut by a crash (its
	// footer gone), one deleted, and one added.
	cut := filepath.Join(e.dir, filepath.FromSlash(rels[2])) // a, hour 1
	segsBefore, _ := e.idx.FlowSegmentsByPath(bg, []string{rels[2]})
	if len(segsBefore) != 1 {
		t.Fatalf("segment %s: %+v", rels[2], segsBefore)
	}
	fi, err := os.Stat(cut)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(cut, fi.Size()-5); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(e.dir, filepath.FromSlash(rels[5]))); err != nil { // b, hour 2
		t.Fatal(err)
	}
	added := "logs/192.0.2.9/flows/" + flowseg.NameFor(restartHour).String()
	addedAbs := filepath.Join(e.dir, filepath.FromSlash(added))
	if err := os.MkdirAll(filepath.Dir(addedAbs), 0o750); err != nil {
		t.Fatal(err)
	}
	w, err := flowseg.Create(addedAbs, "192.0.2.9", restartHour, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range flowRecs(restartHour.Add(30*time.Minute), 11, 5000) {
		if err := w.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}

	e.open()
	evs := eventsOf(t, e.idx, index.KindRecover)
	if len(evs) != 2 {
		t.Fatalf("recover events %+v", evs)
	}
	var texts []string
	for _, ev := range evs {
		texts = append(texts, ev.DeviceID+": "+ev.Text)
	}
	sort.Strings(texts)
	if !strings.HasPrefix(texts[0], "192.0.2.7: "+rels[2]+" was left open by an unclean stop") ||
		texts[1] != ": startup recovery: index: re-read 2 files, dropped 1 rows for missing files" {
		t.Fatalf("recover events %q", texts)
	}
	want := append(append([]string(nil), rels[:5]...), rels[6:]...)
	checkFlowCatalog(t, e.s, append(want, added))
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := flowDerived(t, e.idx), reindexed(t, e.dir); got != want {
		t.Fatalf("after recovery the rows differ from a rebuild\ngot:\n%s\nrebuild:\n%s", got, want)
	}
	segs, _ := e.idx.FlowSegmentsByPath(bg, []string{rels[2], rels[5], added})
	if len(segs) != 2 || segs[0].Path != rels[2] || segs[0].Records != segsBefore[0].Records || !segs[0].Closed ||
		segs[1].Path != added || segs[1].Records != 11 {
		t.Fatalf("segments after recovery %+v (before %+v)", segs, segsBefore)
	}
	// The collector's counts in type_stats aren't derived from segments:
	// recovery leaves them as they were.
	if got := flowStored(t, e.idx); !strings.Contains(got, "count 192.0.2.8 ") || typeStatsLines(got) != typeStatsLines(stored) {
		t.Fatalf("counts after recovery\ngot:\n%s\nwant:\n%s", got, stored)
	}
	if res, err := e.idx.Reconcile(bg, e.dir); err != nil || res.Scanned != 0 || res.Removed != 0 {
		t.Fatalf("reconcile after recovery %+v %v", res, err)
	}
}

// typeStatsLines keeps a flowStored dump's type_stats lines.
func typeStatsLines(dump string) string {
	var out []string
	for _, l := range strings.Split(dump, "\n") {
		if strings.HasPrefix(l, "count ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// Flow minutes dropped from the index queue (the index failing until the
// queue overflowed) leave the stale marker, and the next start re-reads
// every footer, restoring them, and removes it.
func TestFlowMinutesDroppedMarkStale(t *testing.T) {
	old := maxQueued
	maxQueued = 2
	t.Cleanup(func() { maxQueued = old })
	idxPath := filepath.Join(t.TempDir(), index.FileName)
	idx, err := index.Open(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnv(t, func(o *Options) { o.Index = idx })
	a := ip(7)
	seq := 0
	e.clock.Set(restartHour.Add(10 * time.Minute))
	e.writeFlowsAt(a, 5, &seq)
	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	e.clock.Set(restartHour.Add(time.Hour + 10*time.Minute)) // closes hour 0
	e.writeFlowsAt(a, 4, &seq)
	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(e.dir, index.FlowRowsStaleFile)
	if _, err := os.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("marker without a loss: %v", err)
	}
	// The index fails from here on: three minutes later the queue holds more
	// flow minutes than it keeps.
	idx.Close()
	for i := 0; i < 3; i++ {
		e.clock.Add(time.Minute)
		e.writeFlowsAt(a, 2, &seq)
		if err := e.s.Flush(); err == nil {
			t.Fatal("flush with a closed index succeeded")
		}
	}
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("no marker after dropping flow minutes: %v", err)
	}
	if err := e.s.Close(); err == nil {
		t.Fatal("close with a closed index succeeded")
	}

	idx2, err := index.Open(idxPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx2.Close() })
	e.idx, e.opts.Index = idx2, idx2
	e.open()
	if _, err := os.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("marker after the restart: %v", err)
	}
	evs := eventsOf(t, idx2, index.KindRecover)
	if len(evs) != 1 || !strings.HasPrefix(evs[0].Text, "startup recovery: index: re-read 2 files, dropped 0 rows") {
		t.Fatalf("recover events %+v", evs)
	}
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	if got, want := flowDerived(t, idx2), reindexed(t, e.dir); got != want {
		t.Fatalf("after the restart\ngot:\n%s\nrebuild:\n%s", got, want)
	}
}

// flowRecordsInIndex is a device's flow_minute records over the test hours.
func flowRecordsInIndex(t *testing.T, idx *index.DB, dev string) int64 {
	t.Helper()
	tot, err := idx.FlowDeviceTotals(bg, nil, restartHour.Add(-2*time.Hour).UnixMilli(), restartHour.Add(8*time.Hour).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	return tot[dev].Records
}

// The low-disk guard can delete the current hour's closed part before the
// index has its close: the exporter's next part takes a new number, and,
// even in one index batch with the close and the delete, the path's
// minutes are the new segment's only.
func TestFlowPartDeletedBeforeIndexNotReused(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(7)
	seq := 0
	e.clock.Set(restartHour.Add(10 * time.Minute))
	e.writeFlowsAt(a, 50, &seq)
	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	// Closed early (as the directory budget does) and deleted (as the
	// low-disk guard may, the current hour included), then the exporter
	// writes on, all before the next index update.
	st := e.s.flowStream("192.0.2.7")
	st.mu.Lock()
	e.s.closeFlowLocked(st, "")
	st.mu.Unlock()
	e.s.flowLowDisk(e.clock.Now(), func(uint64) bool { return false })
	e.clock.Add(time.Minute)
	e.writeFlowsAt(a, 30, &seq)
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	if got := e.flowFiles(a); len(got) != 1 || got[0] != "2026-11-10T12.001.wsf" {
		t.Fatalf("files %v", got)
	}
	if n := flowRecordsInIndex(t, e.idx, "192.0.2.7"); n != 30 {
		t.Fatalf("minutes count %d records, want 30", n)
	}
	if got, want := flowDerived(t, e.idx), reindexed(t, e.dir); got != want {
		t.Fatalf("rows differ from a rebuild\ngot:\n%s\nrebuild:\n%s", got, want)
	}
	e.open()
	if evs := eventsOf(t, e.idx, index.KindRecover); len(evs) != 0 {
		t.Fatalf("recover events %+v", evs)
	}
}

// badOp makes every index update fail while it's queued.
var badOp = index.FileOp{Kind: index.FileOpKind(99)}

// Flow minutes dropped from the index queue while their segment is open
// (the index failing), then the index recovers and the segment's close row
// commits: closed rows of the right size, minutes short. The stale marker,
// or without it the sum check on kept rows, makes the next start read the
// segment and the minutes come right.
func TestFlowMinutesDroppedWhileOpenHealed(t *testing.T) {
	for _, keepMarker := range []bool{true, false} {
		t.Run(fmt.Sprintf("marker=%v", keepMarker), func(t *testing.T) {
			old := maxQueued
			maxQueued = 2
			t.Cleanup(func() { maxQueued = old })
			e := newEnv(t, nil)
			a := ip(7)
			seq := 0
			e.clock.Set(restartHour.Add(10 * time.Minute))
			e.writeFlowsAt(a, 5, &seq)
			if err := e.s.Flush(); err != nil {
				t.Fatal(err)
			}
			// The index fails: the next block's op waits behind the bad op,
			// then the one after pushes it out of the queue.
			e.clock.Add(time.Minute)
			e.writeFlowsAt(a, 7, &seq)
			if err := e.s.flushFlows(e.clock.Now(), false); err != nil {
				t.Fatal(err)
			}
			e.s.pushOps(badOp)
			if err := e.s.applyIndex(); err == nil {
				t.Fatal("index update with the bad op succeeded")
			}
			e.clock.Add(time.Minute)
			e.writeFlowsAt(a, 3, &seq)
			if err := e.s.flushFlows(e.clock.Now(), false); err != nil {
				t.Fatal(err)
			}
			if err := e.s.applyIndex(); err == nil {
				t.Fatal("index update with the bad op succeeded")
			}
			marker := filepath.Join(e.dir, index.FlowRowsStaleFile)
			if _, err := os.Lstat(marker); err != nil {
				t.Fatalf("no marker: %v", err)
			}
			// The index recovers; the hour ends and the close row commits.
			e.s.qMu.Lock()
			var keep []index.FileOp
			for _, op := range e.s.qOps {
				if op.Kind != badOp.Kind {
					keep = append(keep, op)
				}
			}
			e.s.qOps = keep
			e.s.qMu.Unlock()
			e.clock.Set(restartHour.Add(time.Hour + time.Second))
			e.maintain()
			segs, _ := e.idx.AllFlowSegments(bg)
			if len(segs) != 1 || !segs[0].Closed || segs[0].Records != 15 {
				t.Fatalf("segments %+v", segs)
			}
			if n := flowRecordsInIndex(t, e.idx, "192.0.2.7"); n != 8 {
				t.Fatalf("minutes before the restart: %d records, want 8 (the 7 dropped)", n)
			}
			if err := e.s.Close(); err != nil {
				t.Fatal(err)
			}
			if !keepMarker {
				if err := os.Remove(marker); err != nil {
					t.Fatal(err)
				}
			}
			e.open()
			if n := flowRecordsInIndex(t, e.idx, "192.0.2.7"); n != 15 {
				t.Fatalf("minutes after the restart: %d records, want 15", n)
			}
			if _, err := os.Lstat(marker); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("marker after the restart: %v", err)
			}
			evs := eventsOf(t, e.idx, index.KindRecover)
			if len(evs) != 1 || evs[0].Text != "startup recovery: index: re-read 1 files, dropped 0 rows for missing files" {
				t.Fatalf("recover events %+v", evs)
			}
			if err := e.s.Close(); err != nil {
				t.Fatal(err)
			}
			if got, want := flowDerived(t, e.idx), reindexed(t, e.dir); got != want {
				t.Fatalf("rows differ from a rebuild\ngot:\n%s\nrebuild:\n%s", got, want)
			}
		})
	}
}

// syncBuffer is a log destination safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *syncBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *syncBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// A failed marker write is logged once per Open, not on every pass.
func TestFlowStaleMarkerErrorLoggedOnce(t *testing.T) {
	old := maxQueued
	maxQueued = 1
	t.Cleanup(func() { maxQueued = old })
	var buf syncBuffer
	e := newEnv(t, func(o *Options) { o.Logger = slog.New(slog.NewTextHandler(&buf, nil)) })
	// A folder where the marker goes: creating the file fails.
	if err := os.Mkdir(filepath.Join(e.dir, index.FlowRowsStaleFile), 0o750); err != nil {
		t.Fatal(err)
	}
	a := ip(7)
	seq := 0
	for i := 0; i < 5; i++ {
		e.clock.Add(time.Minute)
		e.writeFlowsAt(a, 2, &seq)
		if err := e.s.flushFlows(e.clock.Now(), false); err != nil {
			t.Fatal(err)
		}
		e.s.qMu.Lock()
		e.s.qOps = append([]index.FileOp{badOp}, e.s.qOps...) // the index keeps failing
		e.s.qMu.Unlock()
		e.s.applyIndex()
	}
	if n := strings.Count(buf.String(), "marker for the next start couldn't be written"); n != 1 {
		t.Fatalf("logged %d times:\n%s", n, buf.String())
	}
	e.s.qMu.Lock()
	e.s.qOps = nil
	e.s.qMu.Unlock()
}
