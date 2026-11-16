package flowquery

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// heapInuse is the heap's in-use spans (objects and the free room in their
// spans), as runtime.MemStats.HeapInuse, read without stopping the world.
func heapInuse() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/memory/classes/heap/unused:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64() + s[1].Value.Uint64()
}

// peakDuring samples heapInuse every millisecond while fn runs and returns
// the peak above the heap before it (after a GC).
func peakDuring(fn func()) (peak, base uint64) {
	runtime.GC()
	base = heapInuse()
	var top atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Millisecond)
		defer t.Stop()
		for {
			if h := heapInuse(); h > top.Load() {
				top.Store(h)
			}
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}()
	fn()
	close(stop)
	wg.Wait()
	if h := heapInuse(); h > top.Load() {
		top.Store(h)
	}
	if top.Load() < base {
		return 0, base
	}
	return top.Load() - base, base
}

func addrN(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
}

// A key's pool cost covers what the exact table really takes on the heap,
// for every key kind, at several table sizes (a map's size just after it
// grows is its worst).
func TestAggKeyCostCoversHeap(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	cases := []struct {
		by  string
		set func(r *flow.Record, i int)
	}{
		{"src", func(r *flow.Record, i int) { r.Src = addrN(i) }},
		{"conversation", func(r *flow.Record, i int) { r.Src, r.Dst = addrN(i), addrN(i+1<<23) }},
		{"dst_port", func(r *flow.Record, i int) { r.Proto, r.DstPort = uint8(i>>16), uint16(i) }},
		{"rule_id", func(r *flow.Record, i int) { r.RuleID = fmt.Sprintf("rule-%07d", i) }},
	}
	for _, c := range cases {
		for _, n := range []int{30_000, 70_000, 140_000, 1_000_000} {
			pool := NewPool(1 << 40)
			var top *Top
			r := flow.Record{Has: flow.HasSrc | flow.HasDst | flow.HasDstPort | flow.HasProto | flow.HasRuleID | flow.HasBytes,
				Bytes: 1, Sampling: 1}
			var recs []flow.Record
			for i := 0; i < n; i++ {
				c.set(&r, i)
				recs = append(recs, r)
			}
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)
			top, _ = NewTopWith(c.by, "bytes", TopOptions{Pool: pool})
			top.Add(&recs[0]) // the fixed part: a worker's cache and batches
			top.Keys()
			runtime.GC()
			runtime.ReadMemStats(&before)
			for i := range recs {
				top.Add(&recs[i])
			}
			top.Keys() // flush
			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)
			heap := int64(after.HeapAlloc) - int64(before.HeapAlloc) + pool.Used()/int64(n) // the first key's
			if top.Keys() != n || top.Approx() {
				t.Fatalf("%s %d: keys %d approx %v", c.by, n, top.Keys(), top.Approx())
			}
			t.Logf("%s %d keys: heap %.0f B/key, pool %.0f B/key", c.by, n, float64(heap)/float64(n), float64(pool.Used())/float64(n))
			if heap > pool.Used() {
				t.Errorf("%s %d keys: the table takes %d bytes of heap, the pool counted %d", c.by, n, heap, pool.Used())
			}
			runtime.KeepAlive(top)
			runtime.KeepAlive(recs)
		}
	}
}

// writeFlows writes n records over one hour for one device, keyed by key(i),
// and indexes them; it returns an engine over them.
func writeFlows(t testing.TB, n int, o Options, set func(r *flow.Record, i int)) *Engine {
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	dev := "10.1.0.1"
	hour := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	fdir := filepath.Join(dir, "logs", dev, "flows")
	os.MkdirAll(fdir, 0o750)
	name := flowseg.NameFor(hour)
	path := filepath.Join(fdir, name.String())
	w, err := flowseg.Create(path, dev, hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort |
		flow.HasProto | flow.HasBytes | flow.HasPackets, Proto: 6, Sampling: 1, Domain: 1}
	for i := 0; i < n; i++ {
		ms := hour.UnixMilli() + int64(i)*3_600_000/int64(n)
		r.Received, r.End, r.Start = ms, ms, ms-1000
		r.SrcPort, r.DstPort = uint16(1024+i%5000), 443
		r.Bytes, r.Packets = uint64(100+i%900), 1
		set(&r, i)
		if err := w.Append(&r); err != nil {
			t.Fatal(err)
		}
	}
	foot, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	ff := index.FlowFile{DeviceID: dev, Name: name, Rel: "logs/" + dev + "/flows/" + name.String(), Path: path}
	rows := index.FlowRowsOf(ff, foot, w.Size(), true)
	if err := idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment}},
		FlowMinutes: rows.Minutes}); err != nil {
		t.Fatal(err)
	}
	o.DataDir, o.Index = dir, idx
	return New(o)
}

// Top by conversation over more distinct keys than the exact limit: the
// heap stays under a fixed ceiling while it runs, the same for 1.6 and 4.5
// million distinct keys, and the answer says it's approximate with its
// error bound. The engine's defaults: 4 workers, the 128 MiB pool.
func TestTopConversationsPeakHeap(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("short or race: the heap ceiling is for the real build")
	}
	const ceiling = 192 << 20
	var peaks []uint64
	for _, n := range []int{3_000_000, 6_000_000} {
		rng := rand.New(rand.NewPCG(7, 8))
		e := writeFlows(t, n, Options{}, func(r *flow.Record, i int) {
			k := i
			if i%4 == 0 {
				k = rng.IntN(100_000) // repeats
			}
			r.Src, r.Dst = addrN(k), addrN(k+1<<23)
		})
		q := Query{From: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
		var res TopResult
		var err error
		peak, base := peakDuring(func() {
			res, err = e.Top(context.Background(), q, "conversation", "bytes", 100, time.Hour, "") // complete even on a starved CPU
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%d records: peak heap %.1f MiB above %.1f MiB; %d workers; approx %v, error bound %d",
			n, float64(peak)/(1<<20), float64(base)/(1<<20), e.o.Workers, res.Approx, res.ErrorBound)
		if peak > ceiling {
			t.Fatalf("%d records: peak heap %.1f MiB, over the %d MiB ceiling", n, float64(peak)/(1<<20), ceiling>>20)
		}
		if !res.Approx || res.ErrorBound <= 0 || res.Partial || res.Total.Flows != int64(n) || len(res.Rows) != 100 {
			t.Fatalf("approx %v bound %d partial %v flows %d rows %d", res.Approx, res.ErrorBound, res.Partial, res.Total.Flows, len(res.Rows))
		}
		if e.pool.Used() != 0 {
			t.Fatalf("pool used %d after a complete query", e.pool.Used())
		}
		peaks = append(peaks, peak)
	}
	// The same table, buffers and sketch either way; what's left is garbage
	// between collections (gcNudgeBytes, and a wave's).
	if d := int64(peaks[1]) - int64(peaks[0]); d > 24<<20 {
		t.Fatalf("the peak grew %.1f MiB with the key count", float64(d)/(1<<20))
	}
}

// On a skewed distribution, the approximate top 10 is the exact top 10, in
// order, and every approximate row's true value is within its error.
func TestApproxTopMatchesExact(t *testing.T) {
	for _, by := range []string{"conversation", "src"} {
		for _, metric := range []string{"bytes", "flows"} {
			rng := rand.New(rand.NewPCG(3, 4))
			z := rand.NewZipf(rng, 1.2, 1, 499_999)
			exact, _ := NewTopWith(by, metric, TopOptions{MaxKeys: 10_000_000})
			approx, _ := NewTopWith(by, metric, TopOptions{MaxKeys: 20_000})
			truth := map[string]int64{}
			r := flow.Record{Has: flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasPackets, Sampling: 1}
			for i := 0; i < 2_000_000; i++ {
				k := int(z.Uint64()) // a few heavy keys and a long tail
				// The key order shuffled, so heavy keys arrive late too.
				k = int((uint64(k) * 2654435761) % 500_000)
				r.Src, r.Dst = addrN(k), addrN(k+1<<23)
				r.Bytes = uint64(1 + rng.IntN(1000))
				exact.Add(&r)
				approx.Add(&r)
			}
			want := exact.Rows(10)
			got := approx.Rows(10)
			if exact.Approx() || !approx.Approx() {
				t.Fatalf("%s/%s: exact approx %v, approx approx %v", by, metric, exact.Approx(), approx.Approx())
			}
			for _, row := range exact.Rows(1 << 20) {
				truth[row.Key] = row.Metric(metric)
			}
			for i := range want {
				if got[i].Key != want[i].Key {
					t.Fatalf("%s/%s row %d: %s, want %s\ngot  %v\nwant %v", by, metric, i, got[i].Key, want[i].Key, keys(got), keys(want))
				}
				tv, est := truth[got[i].Key], got[i].Metric(metric)
				if est < tv || est-got[i].Err > tv {
					t.Fatalf("%s/%s %s: estimate %d err %d, true %d", by, metric, got[i].Key, est, got[i].Err, tv)
				}
			}
			// A key not listed has at most the error bound beyond… nothing: it
			// isn't in the tables at all, so the bound caps its true value.
			b := approx.ErrorBound()
			listed := map[string]bool{}
			for _, row := range approx.Rows(1 << 20) {
				listed[row.Key] = true
			}
			for k, v := range truth {
				if !listed[k] && v > b {
					t.Fatalf("%s/%s: %s has %d, not listed, over the bound %d", by, metric, k, v, b)
				}
			}
			t.Logf("%s/%s: error bound %d (top row %d)", by, metric, b, want[0].Metric(metric))
		}
	}
}

func keys(rows []Row) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Key)
	}
	return out
}

var hour0 = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

func hourQuery() Query { return Query{From: hour0, To: hour0.Add(time.Hour)} }

// Many keys spread over every shard and four workers: the shared table is
// exact (the same rows as one goroutine counting alone) below the limit.
func TestTopExactAcrossWorkers(t *testing.T) {
	const n = 300_000
	e := writeFlows(t, n, Options{Workers: 4}, func(r *flow.Record, i int) {
		r.Src, r.Dst = addrN(i%120_000), addrN(i%7)
		r.Bytes = uint64(1 + i%997)
	})
	want, _ := NewTop("src", "bytes")
	ref := writeFlowsRecords(n, func(r *flow.Record, i int) {
		r.Src, r.Dst = addrN(i%120_000), addrN(i%7)
		r.Bytes = uint64(1 + i%997)
	})
	for i := range ref {
		want.Add(&ref[i])
	}
	res, err := e.Top(bg, hourQuery(), "src", "bytes", 50, time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	w := want.Rows(50)
	if res.Approx || res.ErrorBound != 0 || len(res.Rows) != 50 || res.Total != want.Total {
		t.Fatalf("approx %v bound %d rows %d total %+v want %+v", res.Approx, res.ErrorBound, len(res.Rows), res.Total, want.Total)
	}
	for i := range w {
		if res.Rows[i].Key != w[i].Key || res.Rows[i].Sums != w[i].Sums || res.Rows[i].Approx {
			t.Fatalf("row %d: %+v, want %+v", i, res.Rows[i], w[i])
		}
	}
}

// writeFlowsRecords builds the records writeFlows writes, in memory.
func writeFlowsRecords(n int, set func(r *flow.Record, i int)) []flow.Record {
	out := make([]flow.Record, n)
	r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort |
		flow.HasProto | flow.HasBytes | flow.HasPackets, Proto: 6, Sampling: 1, Domain: 1}
	for i := 0; i < n; i++ {
		ms := hour0.UnixMilli() + int64(i)*3_600_000/int64(n)
		r.Received, r.End, r.Start = ms, ms, ms-1000
		r.SrcPort, r.DstPort = uint16(1024+i%5000), 443
		r.Bytes, r.Packets = uint64(100+i%900), 1
		set(&r, i)
		out[i] = r
	}
	return out
}

// The pool is shared: a partial query's saved state holds its table; a new
// query that needs the room drops it (its cursor then expires), and every
// byte goes back when queries finish.
func TestPoolSharedAndSavedStatesEvicted(t *testing.T) {
	const n = 400_000
	e := writeFlows(t, n, Options{Workers: 2, PoolBytes: 24 << 20}, func(r *flow.Record, i int) {
		r.Src, r.Dst = addrN(i), addrN(i%3)
	})
	// A budget so short the first request stops after one wave, holding its
	// table in a saved state.
	first, err := e.Top(bg, hourQuery(), "src", "flows", 10, time.Nanosecond, "")
	if err != nil || !first.Partial || first.Cursor == "" {
		t.Fatalf("first: %v partial %v", err, first.Partial)
	}
	held := e.pool.Used()
	if held == 0 {
		t.Fatal("the saved state holds no pool bytes")
	}
	// A second query over every key fills the pool: the saved state goes.
	second, err := e.Top(bg, hourQuery(), "conversation", "flows", 10, time.Hour, "")
	if err != nil || second.Partial {
		t.Fatalf("second: %v partial %v", err, second.Partial)
	}
	if !second.Approx || second.ErrorBound <= 0 {
		t.Fatalf("second: a 24 MiB pool can't hold 400,000 conversations exactly; approx %v bound %d", second.Approx, second.ErrorBound)
	}
	if _, err := e.Top(bg, hourQuery(), "src", "flows", 10, time.Hour, first.Cursor); err != ErrExpired {
		t.Fatalf("the evicted cursor: %v, want ErrExpired", err)
	}
	if u := e.pool.Used(); u != 0 {
		t.Fatalf("pool used %d with no query running or saved", u)
	}
	// A summary's values come from the same pool: capped, flagged, returned.
	sum, err := e.Summary(bg, hourQuery(), SummaryQuery{Fields: []string{"src", "dst"}, Top: 5}, time.Hour, "")
	if err != nil || sum.Partial {
		t.Fatalf("summary: %v partial %v", err, sum.Partial)
	}
	if !sum.Fields[0].DistinctCapped || sum.Fields[0].Distinct > MaxDistinct || sum.Fields[1].Distinct != 3 {
		t.Fatalf("summary src %d capped %v, dst %d", sum.Fields[0].Distinct, sum.Fields[0].DistinctCapped, sum.Fields[1].Distinct)
	}
	if u := e.pool.Used(); u != 0 {
		t.Fatalf("pool used %d after the summary", u)
	}
}

// Concurrent queries share the engine's workers and pool without races,
// and each answer is right.
func TestConcurrentTopsShareWorkers(t *testing.T) {
	const n = 200_000
	e := writeFlows(t, n, Options{Workers: 3, PoolBytes: 8 << 20}, func(r *flow.Record, i int) {
		r.Src, r.Dst = addrN(i%50_000), addrN(i%11)
	})
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			by := []string{"src", "dst", "conversation", "dst_port"}[g%4]
			res, err := e.Top(bg, hourQuery(), by, "flows", 5, time.Hour, "")
			if err == nil && (res.Total.Flows != n || len(res.Rows) == 0) {
				err = fmt.Errorf("%s: total %d rows %d", by, res.Total.Flows, len(res.Rows))
			}
			if err == nil && by == "dst" && (res.Approx || res.Rows[0].Flows < n/11) {
				err = fmt.Errorf("dst: %+v", res.Rows[0])
			}
			errs <- err
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if u := e.pool.Used(); u != 0 {
		t.Fatalf("pool used %d after", u)
	}
}

// A key that enters a full approximate table after records that added
// nothing to the ranked metric (flow creates, for connections) isn't shown
// as exact: its other counts may miss those records.
func TestLateRowsAreApprox(t *testing.T) {
	top, _ := NewTopWith("src", "connections", TopOptions{MaxKeys: 1, Small: true})
	created := func(i int) *flow.Record {
		return &flow.Record{Has: flow.HasSrc | flow.HasFwEvent, Src: addrN(i), FwEvent: flow.FwCreated, Sampling: 1}
	}
	// Fill every shard's table with keys of 0 connections.
	for i := 0; i < 20_000; i++ {
		top.Add(created(i))
	}
	late := 1 << 20
	for j := 0; j < 50; j++ {
		top.Add(created(late)) // 50 flows, no connection: turned away
	}
	top.Keys() // past the worker's combining cache
	r := created(late)
	r.FwEvent = flow.FwDeleted
	top.Add(r) // its first connection: admitted
	for _, row := range top.Rows(1 << 20) {
		if row.Key == addrN(late).String() {
			if !row.Approx || row.Flows != 1 { // the 50 earlier are missing, and the row says so
				t.Fatalf("late row %+v: approx %v", row, row.Approx)
			}
			return
		}
	}
	t.Fatal("the late key isn't listed")
}

// writeWeek writes a week of hourly segments for exporters exporters, each
// with blocks blocks of 2 records (one segment per hour, written once and
// copied to every exporter's path), indexes them, and returns an engine with
// the defaults.
func writeWeek(t *testing.T, exporters, blocks int) (*Engine, time.Time) {
	t.Helper()
	week := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	return writeHours(t, week, 7*24, exporters, blocks), week
}

// writeHours is writeWeek over hours hours from start.
func writeHours(t *testing.T, start time.Time, hours, exporters, blocks int) *Engine {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	tmpl := filepath.Join(dir, "tmpl")
	os.MkdirAll(tmpl, 0o750)
	var batch index.Batch
	apply := func() {
		if err := idx.Apply(bg, batch); err != nil {
			t.Fatal(err)
		}
		batch = index.Batch{}
	}
	for h := 0; h < hours; h++ {
		hour := start.Add(time.Duration(h) * time.Hour)
		name := flowseg.NameFor(hour)
		src := filepath.Join(tmpl, name.String())
		w, err := flowseg.Create(src, "tmpl", hour, "test")
		if err != nil {
			t.Fatal(err)
		}
		r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasPackets, Sampling: 1,
			Bytes: 100, Packets: 1}
		for b := 0; b < blocks; b++ {
			ms := hour.UnixMilli() + int64(b)*3_600_000/int64(blocks)
			for i := 0; i < 2; i++ {
				r.Received, r.End, r.Start = ms+int64(i), ms+int64(i), ms-500
				r.Src, r.Dst = addrN(b%50), addrN(1<<20+i)
				if err := w.Append(&r); err != nil {
					t.Fatal(err)
				}
			}
			w.Flush()
		}
		foot, err := w.Close()
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		for x := 0; x < exporters; x++ {
			dev := fmt.Sprintf("10.9.%d.%d", x/250, x%250+1)
			fdir := filepath.Join(dir, "logs", dev, "flows")
			os.MkdirAll(fdir, 0o750)
			path := filepath.Join(fdir, name.String())
			if err := os.WriteFile(path, data, 0o640); err != nil {
				t.Fatal(err)
			}
			ff := index.FlowFile{DeviceID: dev, Name: name, Rel: "logs/" + dev + "/flows/" + name.String(), Path: path}
			rows := index.FlowRowsOf(ff, foot, int64(len(data)), true)
			batch.Files = append(batch.Files, index.FileOp{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment})
			if len(batch.Files) >= 2000 {
				apply()
			}
		}
	}
	apply()
	return New(Options{DataDir: dir, Index: idx})
}

// A week over 50 exporters (8,400 segments): the plan streams the window, so
// a top-N's and a search's peak heap is the same with 4 times the blocks,
// and far under the query ceiling (SPEC §13.10 decision 56). At one block a
// second a real week is 30 million blocks: the old plan's 64 bytes each
// would have been 1.9 GB, before the segments' directories.
func TestWeekPlanBounded(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("short or race: writes 8,400 segments")
	}
	const exporters = 50
	var peaks []uint64
	for _, blocks := range []int{15, 60} {
		e, week := writeWeek(t, exporters, blocks)
		q := Query{From: week, To: week.Add(7 * 24 * time.Hour)}
		var top TopResult
		var err error
		peak, _ := peakDuring(func() { top, err = e.Top(bg, q, "src", "flows", 10, time.Hour, "") })
		if err != nil {
			t.Fatal(err)
		}
		want := int64(exporters * 7 * 24 * blocks * 2)
		if top.Partial || top.Total.Flows != want || top.Progress.RecordsDone != want || top.Progress.BlocksDone != int64(exporters*7*24*blocks) {
			t.Fatalf("%d blocks: partial %v flows %d (want %d) progress %+v", blocks, top.Partial, top.Total.Flows, want, top.Progress)
		}
		// A search's pages walk the week newest first; the first and a later one.
		var sres SearchResult
		speak, _ := peakDuring(func() { sres, err = e.Search(bg, q, 500, false, "", time.Hour) })
		if err != nil || len(sres.Hits) != 500 || sres.Cursor == "" {
			t.Fatalf("search: %v hits %d", err, len(sres.Hits))
		}
		if _, err := e.Search(bg, q, 500, false, sres.Cursor, time.Hour); err != nil {
			t.Fatal(err)
		}
		n, err := e.Count(bg, q)
		var c int64
		for _, v := range n {
			c += v
		}
		if err != nil || c != want || len(n) != exporters {
			t.Fatalf("count %d (want %d) devices %d: %v", c, want, len(n), err)
		}
		t.Logf("%d exporters, a week, %d blocks a segment (%d blocks): top peak %.1f MiB, search peak %.1f MiB",
			exporters, blocks, exporters*7*24*blocks, float64(peak)/(1<<20), float64(speak)/(1<<20))
		peaks = append(peaks, max(peak, speak))
		if p := max(peak, speak); p > 192<<20 {
			t.Fatalf("peak %.1f MiB over the ceiling", float64(p)/(1<<20))
		}
	}
	if d := int64(peaks[1]) - int64(peaks[0]); d > 16<<20 {
		t.Fatalf("4 times the blocks grew the peak by %.1f MiB", float64(d)/(1<<20))
	}
}

// An open segment that closed between the listing and the plan reaching it
// (its Snap gives nil) is read from its file, once.
func TestOpenSegmentClosedSinceListing(t *testing.T) {
	const n = 50_000
	e := writeFlows(t, n, Options{}, func(r *flow.Record, i int) { r.Src, r.Dst = addrN(i%100), addrN(7) })
	segs, _ := e.o.Index.FlowSegments(bg, nil, time.Time{}, time.Time{})
	if len(segs) != 1 {
		t.Fatalf("%d segments", len(segs))
	}
	calls := 0
	e.o.Open = func([]string) []OpenSegment {
		return []OpenSegment{{DeviceID: segs[0].DeviceID, Rel: segs[0].Path, Path: filepath.Join(e.o.DataDir, segs[0].Path),
			Snap: func() *flowseg.Footer { calls++; return nil }}}
	}
	res, err := e.Top(bg, hourQuery(), "src", "flows", 5, time.Hour, "")
	if err != nil || res.Total.Flows != n || res.Partial || calls != 1 {
		t.Fatalf("flows %d partial %v snaps %d: %v", res.Total.Flows, res.Partial, calls, err)
	}
	c, err := e.Count(bg, hourQuery())
	if err != nil || c[segs[0].DeviceID] != n {
		t.Fatalf("count %v %v", c, err)
	}
}

// A minute's window over 300 exporters' hour-long segments of 3,600 blocks
// (one a second): each segment gives the plan 60 blocks but holds its whole
// directory (472 bytes a block, its footer's or an open segment's snapshot),
// so a batch is bounded by the directory entries it loads, not only by the
// blocks it plans. Before, a batch of 16,384 planned blocks loaded 273 such
// segments: about 460 MiB. Closed segments, then the same as open ones.
func TestNarrowWindowPlanBounded(t *testing.T) {
	if testing.Short() || raceEnabled {
		t.Skip("short or race: writes 300 segments of 3,600 blocks")
	}
	const exporters, blocks = 300, 3600
	hour := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	e := writeHours(t, hour, 1, exporters, blocks)
	segs, err := e.o.Index.FlowSegments(bg, nil, time.Time{}, time.Time{})
	if err != nil || len(segs) != exporters {
		t.Fatalf("%d segments: %v", len(segs), err)
	}
	q := Query{From: hour.Add(30 * time.Minute), To: hour.Add(31 * time.Minute)}
	want := int64(exporters * 61 * 2) // blocks 1,800 to 1,860: the last one's flows start 500 ms before its end
	for _, open := range []bool{false, true} {
		if open {
			// Every segment as an open one, its snapshot a fresh copy of
			// the directory per call, as Writer.Snapshot makes.
			e.o.Open = func([]string) []OpenSegment {
				out := make([]OpenSegment, len(segs))
				for i, sg := range segs {
					path := filepath.Join(e.o.DataDir, sg.Path)
					out[i] = OpenSegment{DeviceID: sg.DeviceID, Rel: sg.Path, Path: path, Snap: func() *flowseg.Footer {
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
		}
		var top TopResult
		peak, _ := peakDuring(func() { top, err = e.Top(bg, q, "src", "flows", 10, time.Hour, "") })
		if err != nil {
			t.Fatal(err)
		}
		if top.Partial || top.Total.Flows != want {
			t.Fatalf("open %v: partial %v flows %d, want %d", open, top.Partial, top.Total.Flows, want)
		}
		t.Logf("open %v: a minute over %d exporters' %d-block segments: peak %.1f MiB", open, exporters, blocks,
			float64(peak)/(1<<20))
		if peak > 64<<20 {
			t.Errorf("open %v: peak %.1f MiB, over the 64 MiB ceiling", open, float64(peak)/(1<<20))
		}
	}
}

// Many small segments: a batch loads at most planBatchSegs of them, so a
// plan never holds more footers and open files than that, and a segment
// with nothing in the window keeps no file open; every segment still loads
// once, and a count over the window finds every record.
func TestPlanBatchSegmentsBounded(t *testing.T) {
	const exporters = 700
	hour := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	e := writeHours(t, hour, 1, exporters, 2) // blocks at 09:00 and 09:30
	q := Query{From: hour.Add(20 * time.Minute), To: hour.Add(time.Hour)}
	p, err := e.planFor(bg, &q, false)
	if err != nil {
		t.Fatal(err)
	}
	rd := newReaders(p)
	defer rd.close()
	segs, batches := 0, 0
	for p.more(bg) {
		p.load(bg, rd)
		if len(p.segs) == 0 {
			break
		}
		batches++
		segs += len(p.segs)
		rd.mu.Lock()
		open := len(rd.rds)
		rd.mu.Unlock()
		if len(p.segs) > planBatchSegs || open > len(p.segs) || len(p.blocks) != len(p.segs) {
			t.Fatalf("batch %d: %d segments, %d files open, %d blocks", batches, len(p.segs), open, len(p.blocks))
		}
		p.done = len(p.blocks)
		for _, b := range p.blocks {
			rd.done(b.seg)
		}
	}
	if p.err != nil || segs != exporters || batches != (exporters+planBatchSegs-1)/planBatchSegs {
		t.Fatalf("%d segments in %d batches: %v", segs, batches, p.err)
	}
	// Outside the window's blocks: the 09:00 one; a whole-window count.
	n, err := e.Count(bg, q)
	var c int64
	for _, v := range n {
		c += v
	}
	if err != nil || c != exporters*2 {
		t.Fatalf("count %d, want %d: %v", c, exporters*2, err)
	}
	// A window inside the segments' index ranges with no block in it
	// (09:10 to 09:11): they load, and no file is held at all.
	q = Query{From: hour.Add(10 * time.Minute), To: hour.Add(11 * time.Minute)}
	p, err = e.planFor(bg, &q, false)
	if err != nil {
		t.Fatal(err)
	}
	rd2 := newReaders(p)
	defer rd2.close()
	p.load(bg, rd2)
	if len(p.segs) == 0 || len(p.blocks) != 0 || len(rd2.rds) != 0 {
		t.Fatalf("an empty window: %d segments, %d blocks, %d files open", len(p.segs), len(p.blocks), len(rd2.rds))
	}
}
