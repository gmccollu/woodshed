package flowquery

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// searchAll is every hit of Search's pages, one after another.
func searchAll(t testing.TB, e *Engine, q Query, asc bool, limit int) []Hit {
	t.Helper()
	var out []Hit
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 100000 {
			t.Fatal("no end")
		}
		res, err := e.Search(bg, q, limit, asc, cursor, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, res.Hits...)
		if res.Cursor == "" {
			return out
		}
		cursor = res.Cursor
	}
}

// streamAll is every hit Stream gives.
func streamAll(t testing.TB, e *Engine, q Query, asc bool) []Hit {
	t.Helper()
	var out []Hit
	if err := e.Stream(bg, q, asc, func(h *Hit) error {
		out = append(out, *h)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

func sameHits(t *testing.T, what string, got, want []Hit) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d hits, want %d", what, len(got), len(want))
	}
	for i := range got {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Fatalf("%s: hit %d:\n got %+v\nwant %+v", what, i, got[i], want[i])
		}
	}
}

// Stream gives exactly what Search's pages give one after another, in order,
// over open and closed segments, plan pages and batches, filters and device
// selections; and holds nothing in the pool after.
func TestStreamMatchesSearchPages(t *testing.T) {
	fx := newFixture(t, 2000)
	for _, asc := range []bool{false, true} {
		for _, fq := range []string{"", "proto=udp&dst_port=53", "src=10.20.0.7", "fw_event=denied"} {
			for _, devs := range [][]string{nil, {"10.1.0.3"}, {"10.1.0.1", "10.1.0.2"}} {
				q := Query{DeviceIDs: devs, From: fx.h.Add(10 * time.Minute), To: fx.h.Add(110 * time.Minute), Filter: mustFilter(t, fq)}
				what := fmt.Sprintf("asc %v %q %v", asc, fq, devs)
				want := searchAll(t, fx.eng, q, asc, 137)
				if len(want) != len(fx.brute(q)) {
					t.Fatalf("%s: the pages gave %d of %d", what, len(want), len(fx.brute(q)))
				}
				before := fx.eng.pool.Used()
				fb := fx.eng.streamFallbacks.Load()
				sameHits(t, what, streamAll(t, fx.eng, q, asc), want)
				if fx.eng.streamFallbacks.Load() != fb {
					t.Fatalf("%s: fell back to pages", what)
				}
				if u := fx.eng.pool.Used(); u != before {
					t.Fatalf("%s: pool %d after, %d before", what, u, before)
				}
			}
		}
	}
	// The whole fixture, newest first, against one-hit pages too.
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	sameHits(t, "everything", streamAll(t, fx.eng, q, false), searchAll(t, fx.eng, q, false, 3))
}

// A pool that can't hold the overlapping blocks makes Stream carry on with
// Search's pages from the last record it gave, with the same result.
func TestStreamFallsBackToPages(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	for _, asc := range []bool{false, true} {
		want := searchAll(t, fx.eng, q, asc, 500)
		for _, pool := range []int64{1, 20_000, 60_000} {
			e := New(Options{DataDir: fx.dir, Index: fx.idx, Open: fx.eng.o.Open, Workers: 3, PoolBytes: pool})
			e.page, e.batch = fx.eng.page, fx.eng.batch
			sameHits(t, fmt.Sprintf("asc %v pool %d", asc, pool), streamAll(t, e, q, asc), want)
			if e.streamFallbacks.Load() != 1 {
				t.Fatalf("pool %d: %d fallbacks", pool, e.streamFallbacks.Load())
			}
			if e.pool.Used() != 0 {
				t.Fatalf("pool %d: %d bytes left charged", pool, e.pool.Used())
			}
		}
	}
}

// An error from fn, or a cancelled context, stops the stream and returns the
// pool's bytes and the workers.
func TestStreamStops(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	stop := errors.New("enough")
	n := 0
	err := fx.eng.Stream(bg, q, false, func(*Hit) error {
		if n++; n == 10 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || n != 10 {
		t.Fatalf("err %v after %d", err, n)
	}
	ctx, cancel := context.WithCancel(bg)
	n = 0
	err = fx.eng.Stream(ctx, q, true, func(*Hit) error {
		if n++; n == 25 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v after %d", err, n)
	}
	if fx.eng.pool.Used() != 0 || len(fx.eng.slots) != cap(fx.eng.slots) {
		t.Fatalf("pool %d, %d of %d slots back", fx.eng.pool.Used(), len(fx.eng.slots), cap(fx.eng.slots))
	}
}

// Stream decodes each block of the window once (a listing used to decode
// each block once per page that overlapped it).
func TestStreamDecodesEachBlockOnce(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	p, err := fx.eng.planFor(bg, &q, false)
	if err != nil {
		t.Fatal(err)
	}
	rd := newReaders(p)
	blocks := 0
	for {
		bs := p.take(bg, rd, 100)
		if len(bs) == 0 {
			break
		}
		for _, b := range bs {
			rd.done(b.seg)
			if !b.raw {
				blocks++
			}
		}
	}
	rd.close()
	p.release()
	d := fx.eng.streamDecodes.Load()
	if got := len(streamAll(t, fx.eng, q, false)); got == 0 {
		t.Fatal("nothing")
	}
	if n := fx.eng.streamDecodes.Load() - d; n != int64(blocks) {
		t.Fatalf("decoded %d blocks, the window has %d", n, blocks)
	}
}

// Raw sets decoded on read stream like the rest, in Search's order.
func TestStreamRawSets(t *testing.T) {
	eng, h := rawFixture(t)
	for _, fq := range []string{"", "status=late"} {
		for _, asc := range []bool{false, true} {
			q := Query{From: h, To: h.Add(time.Hour), Filter: mustFilter(t, fq)}
			want := searchAll(t, eng, q, asc, 2)
			if len(want) == 0 {
				t.Fatal("no hits")
			}
			sameHits(t, fmt.Sprintf("%q asc %v", fq, asc), streamAll(t, eng, q, asc), want)
		}
	}
}

// ---- the flow listing bench (SPEC §13.6) ----

// benchStore writes n records for one exporter at rate records a second as
// the collector stores them (blocks of at most 65,536 rows or a second
// received; flow ends up to 2 s before received, starts up to 30 s before
// the end, as loadgen sends), and indexes the segments.
func benchStore(t testing.TB, n int, rate float64) (*Engine, Query) {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	dev := "192.0.2.10"
	fdir := filepath.Join(dir, "logs", dev, "flows")
	if err := os.MkdirAll(fdir, 0o750); err != nil {
		t.Fatal(err)
	}
	h0 := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	rng := rand.New(rand.NewPCG(4, 2))
	var w *flowseg.Writer
	var hour time.Time
	var path string
	closeSeg := func() {
		foot, err := w.Close()
		if err != nil {
			t.Fatal(err)
		}
		name := flowseg.NameFor(hour)
		ff := index.FlowFile{DeviceID: dev, Name: name, Rel: "logs/" + dev + "/flows/" + name.String(), Path: path}
		rows := index.FlowRowsOf(ff, foot, w.Size(), true)
		if err := idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment}},
			FlowMinutes: rows.Minutes}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		recv := h0.Add(time.Duration(float64(i) / rate * float64(time.Second)))
		if hh := recv.Truncate(time.Hour); w == nil || !hh.Equal(hour) {
			if w != nil {
				closeSeg()
			}
			hour = hh
			path = filepath.Join(fdir, flowseg.NameFor(hour).String())
			if w, err = flowseg.Create(path, dev, hour, "bench"); err != nil {
				t.Fatal(err)
			}
		}
		ms := recv.UnixMilli()
		end := ms - rng.Int64N(2000)
		r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto |
			flow.HasTCPFlags | flow.HasBytes | flow.HasPackets | flow.HasInIf | flow.HasOutIf,
			Received: ms, End: end, Start: end - rng.Int64N(30000),
			Src: netip.AddrFrom4([4]byte{10, byte(rng.IntN(4)), byte(rng.IntN(256)), byte(rng.IntN(256))}),
			Dst: netip.AddrFrom4([4]byte{198, 51, 100, byte(rng.IntN(256))}), SrcPort: uint16(1024 + rng.IntN(60000)),
			DstPort: []uint16{443, 53, 22, 80}[rng.IntN(4)], Proto: []uint8{6, 17}[rng.IntN(2)], TCPFlags: uint16(rng.IntN(64)),
			Bytes: uint64(rng.IntN(1 << 20)), Packets: uint64(1 + rng.IntN(1000)), InIf: uint32(rng.IntN(8)), OutIf: uint32(rng.IntN(8)),
			Sampling: 1, Domain: 1, Version: flow.IPFIX}
		if err := w.Append(&r); err != nil {
			t.Fatal(err)
		}
	}
	closeSeg()
	e := New(Options{DataDir: dir, Index: idx})
	return e, Query{From: h0.Add(-time.Hour), To: h0.Add(24 * time.Hour)}
}

// BenchmarkFlowListing lists 1,000,000 records at 100,000 a second: the
// CLI's path (Stream) and the API's (Search pages of 5,000 and 500, each
// continuing the stream the page before saved; and stateless, as when it's
// gone), in records a second. On the build machine (SPEC §13.6): Stream
// 4.4–4.7 M/s (the CLI's pages of 5,000 were 69 k/s before it); pages of
// 5,000 and 500 1.4–1.5 M/s; stateless pages of 5,000 206 k/s (69 k/s before
// the two-pass pages) and of 500 30 k/s (8.2 k/s): each reads again every
// block overlapping it.
func BenchmarkFlowListing(b *testing.B) {
	const n = 1_000_000
	e, q := benchStore(b, n, 100_000)
	b.Run("stream", func(b *testing.B) {
		for b.Loop() {
			got := 0
			if err := e.Stream(bg, q, false, func(*Hit) error { got++; return nil }); err != nil || got != n {
				b.Fatalf("%d records, %v", got, err)
			}
		}
		b.ReportMetric(float64(n)*float64(b.N)/b.Elapsed().Seconds(), "records/s")
	})
	for _, c := range []struct {
		limit     int
		stateless bool
	}{{5000, false}, {500, false}, {5000, true}, {500, true}} {
		name := fmt.Sprintf("pages-%d", c.limit)
		if c.stateless {
			name += "-stateless"
		}
		limit := c.limit
		b.Run(name, func(b *testing.B) {
			e.statelessPages = c.stateless
			defer func() { e.statelessPages = false }()
			const max = 200_000 // the newest; every page costs about the same
			for b.Loop() {
				got, cursor := 0, ""
				for got < max {
					res, err := e.Search(bg, q, limit, false, cursor, 10*time.Second)
					if err != nil {
						b.Fatal(err)
					}
					got += len(res.Hits)
					cursor = res.Cursor
				}
			}
			b.ReportMetric(float64(max)*float64(b.N)/b.Elapsed().Seconds(), "records/s")
		})
	}
}

// outlierStore writes hours one-exporter segments of blocks of rows records
// (one a second, received 1 ms apart), a hundredth of them ending up to
// spanSec before they were received (an idle flow exported late), the rest
// within 2 s: every block's end range reaches far back, so a merge reads
// most blocks long before the bound reaches most of their rows. It returns
// the engine (pool poolBytes), the window, the record count, and the
// segments' bytes.
func outlierStore(t *testing.T, hours, blocks, rows, spanSec int, poolBytes int64) (*Engine, Query, int, int64) {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	dev := "192.0.2.20"
	fdir := filepath.Join(dir, "logs", dev, "flows")
	if err := os.MkdirAll(fdir, 0o750); err != nil {
		t.Fatal(err)
	}
	h0 := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	rng := rand.New(rand.NewPCG(8, 9))
	var size int64
	n := 0
	for hr := 0; hr < hours; hr++ {
		hour := h0.Add(time.Duration(hr) * time.Hour)
		name := flowseg.NameFor(hour)
		path := filepath.Join(fdir, name.String())
		w, err := flowseg.Create(path, dev, hour, "test")
		if err != nil {
			t.Fatal(err)
		}
		for b := 0; b < blocks; b++ {
			for i := 0; i < rows; i++ {
				ms := hour.UnixMilli() + int64(b)*1000 + int64(i)*1000/int64(rows)
				end := ms - rng.Int64N(2000)
				if rng.IntN(100) == 0 {
					end = ms - rng.Int64N(int64(spanSec)*1000)
				}
				r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasSrcAS,
					Received: ms, End: end, Start: end - rng.Int64N(30000), Src: netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}),
					Dst: netip.MustParseAddr("198.51.100.7"), Bytes: uint64(i), SrcAS: uint32(n)}
				if err := w.Append(&r); err != nil {
					t.Fatal(err)
				}
				n++
			}
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
		}
		foot, err := w.Close()
		if err != nil {
			t.Fatal(err)
		}
		size += w.Size()
		ff := index.FlowFile{DeviceID: dev, Name: name, Rel: "logs/" + dev + "/flows/" + name.String(), Path: path}
		fr := index.FlowRowsOf(ff, foot, w.Size(), true)
		if err := idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: fr.File, Flow: &fr.Segment}},
			FlowMinutes: fr.Minutes}); err != nil {
			t.Fatal(err)
		}
	}
	e := New(Options{DataDir: dir, Index: idx, Workers: 4, PoolBytes: poolBytes})
	return e, Query{From: h0.Add(-time.Hour), To: h0.Add(time.Duration(hours+1) * time.Hour)}, n, size
}

// A full listing reads each block about once whatever the window's length,
// the segments' size or how far a few rows end from the rest (the lab's
// 250 M-record listing read 140 times its data and slowed as it went: blocks
// with a few rows ending far back filled the pool, and the fall back to
// Search's pages read every such block again for every page). With a pool
// too small for the rows waiting (about 7 MiB here, ascending; the pool 4
// MiB, so the stream's budget 2 MiB), Stream trims instead (keeping the few rows, dropping the dense run, reading it again
// once): every record once and in order, the same records as with a big
// pool, at most about twice the segments' bytes read, and no fall back.
func TestStreamReadsEachBlockAboutOnce(t *testing.T) {
	const hours, blocks, rows, span = 2, 300, 1000, 120
	small, q, n, size := outlierStore(t, hours, blocks, rows, span, 4<<20)
	big := New(Options{DataDir: small.o.DataDir, Index: small.o.Index, Workers: 4})
	for _, asc := range []bool{true, false} {
		what := fmt.Sprintf("asc %v", asc)
		read0, dec0, tr0, rr0 := flowseg.ReadBytes(), small.streamDecodes.Load(), small.streamTrims.Load(), small.streamRereads.Load()
		got := streamAll(t, small, q, asc)
		read, dec := flowseg.ReadBytes()-read0, small.streamDecodes.Load()-dec0
		if len(got) != n {
			t.Fatalf("%s: %d of %d records", what, len(got), n)
		}
		seen := make([]bool, n)
		for i := range got {
			if as := got[i].Record.SrcAS; seen[as] {
				t.Fatalf("%s: record %d twice", what, as)
			} else {
				seen[as] = true
			}
			if i > 0 && !keyOfHit(&got[i-1]).before(keyOfHit(&got[i]), asc) {
				t.Fatalf("%s: out of order at %d", what, i)
			}
		}
		t.Logf("%s: read %.2f× the segments' bytes, %d decodes of %d blocks, %d trims, %d read again", what, float64(read)/float64(size),
			dec, hours*blocks, small.streamTrims.Load()-tr0, small.streamRereads.Load()-rr0)
		if small.streamFallbacks.Load() != 0 {
			t.Fatalf("%s: fell back to pages", what)
		}
		if asc && small.streamTrims.Load() == tr0 {
			t.Fatalf("%s: never trimmed (the pool should be too small)", what)
		}
		if read > size*22/10 || dec > int64(hours*blocks)*22/10 {
			t.Fatalf("%s: read %d bytes of %d (%.2f×), %d decodes of %d blocks", what, read, size, float64(read)/float64(size), dec, hours*blocks)
		}
		sameHits(t, what+" against a big pool", got, streamAll(t, big, q, asc))
		if small.pool.Used() != 0 {
			t.Fatalf("%s: %d bytes left charged", what, small.pool.Used())
		}
	}
}
