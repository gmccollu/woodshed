package flowquery

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// A page of selective hits, each from a different block whose every record
// carries an extra, holds about its hits' own bytes: their extras are
// copied out of the blocks' shared column copies, which pinned about 230
// KiB a hit (48 MiB for a 200-hit page; found by the independent review).
func TestSearchPageExtrasNotPinned(t *testing.T) {
	const blocks, rows = 40, 20000
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	dev := "192.0.2.10"
	fdir := filepath.Join(dir, "logs", dev, "flows")
	if err := os.MkdirAll(fdir, 0o750); err != nil {
		t.Fatal(err)
	}
	h0 := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	name := flowseg.NameFor(h0)
	path := filepath.Join(fdir, name.String())
	w, err := flowseg.Create(path, dev, h0, "t")
	if err != nil {
		t.Fatal(err)
	}
	for b := 0; b < blocks; b++ {
		for i := 0; i < rows; i++ {
			ms := h0.UnixMilli() + int64(b*rows+i)/10
			src := netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
			if i == 777 {
				src = netip.MustParseAddr("10.9.9.9")
			}
			r := flow.Record{Has: flow.HasEnd | flow.HasSrc, End: ms, Received: ms, Src: src,
				Extras: []flow.Extra{{PEN: 9, ID: 12, Value: []byte{1, 2, 3, 4, 5, 6, 7, byte(i)}}}}
			if err := w.Append(&r); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	foot, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	ff := index.FlowFile{DeviceID: dev, Name: name, Rel: "logs/" + dev + "/flows/" + name.String(), Path: path}
	fr := index.FlowRowsOf(ff, foot, w.Size(), true)
	if err := idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: fr.File, Flow: &fr.Segment}},
		FlowMinutes: fr.Minutes}); err != nil {
		t.Fatal(err)
	}
	q := Query{From: h0.Add(-time.Hour), To: h0.Add(3 * time.Hour), Filter: mustFilter(t, "src=10.9.9.9")}
	// The stateless page's second pass, and a page's stream (Search's).
	for _, stateless := range []bool{true, false} {
		e := New(Options{DataDir: dir, Index: idx, Workers: 2})
		e.statelessPages = stateless
		extrasNotPinned(t, e, q, blocks)
	}
}

func extrasNotPinned(t *testing.T, e *Engine, q Query, blocks int) {
	heapNow := func() uint64 {
		for range 3 {
			runtime.GC()
		}
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	if _, err := e.Search(bg, q, 500, false, "", time.Minute); err != nil { // warm the workers' buffers
		t.Fatal(err)
	}
	res, err := e.Search(bg, q, 500, false, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) != blocks {
		t.Fatalf("%d hits, want %d", len(res.Hits), blocks)
	}
	for i := range res.Hits {
		if x := res.Hits[i].Record.Extras; len(x) != 1 || x[0].PEN != 9 || len(x[0].Value) != 8 || x[0].Value[7] != byte(777%256) {
			t.Fatalf("hit %d extras %+v", i, x)
		}
	}
	with := heapNow()
	runtime.KeepAlive(res)
	res = SearchResult{}
	without := heapNow()
	runtime.KeepAlive(e)
	pinned := int64(with) - int64(without)
	const ceiling = 512 << 10 // the hits' records are about 25 KiB
	t.Logf("stateless %v: %d hits pin %d bytes", e.statelessPages, blocks, pinned)
	if pinned > ceiling {
		t.Fatalf("a %d-hit page holds %d KiB (ceiling %d KiB)", blocks, pinned>>10, ceiling>>10)
	}
}

// A segment deleted between a page's two passes (retention) doesn't cost
// the page its hits: it's read again without the segment, as a page read
// after the deletion is.
func TestSearchPageRereadsAfterDeletion(t *testing.T) {
	fx := newFixture(t, 2000)
	fx.eng.statelessPages = true // the two passes are the stateless page's (pages.go: a stream reads each block once)
	q := Query{DeviceIDs: []string{"10.1.0.1", "10.1.0.2"}, From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	gone := filepath.Join(fx.dir, "logs", "10.1.0.2", "flows", flowseg.NameFor(fx.h.Add(time.Hour)).String())
	calls := 0
	fx.eng.fillHook = func() {
		if calls++; calls == 1 {
			if err := os.Remove(gone); err != nil {
				t.Error(err)
			}
		}
	}
	got, err := fx.eng.Search(bg, q, 300, false, "", time.Minute)
	fx.eng.fillHook = nil
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("second pass ran %d times", calls)
	}
	want, err := fx.eng.Search(bg, q, 300, false, "", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Hits) != 300 {
		t.Fatalf("%d hits", len(got.Hits))
	}
	sameHits(t, "after deletion", got.Hits, want.Hits)
	if got.Cursor != want.Cursor {
		t.Fatalf("cursor %q, want %q", got.Cursor, want.Cursor)
	}
}
