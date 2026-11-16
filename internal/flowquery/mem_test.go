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
			res, err = e.Top(context.Background(), q, "conversation", "bytes", 100, time.Minute, "")
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
	res, err := e.Top(bg, hourQuery(), "src", "bytes", 50, time.Minute, "")
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
	second, err := e.Top(bg, hourQuery(), "conversation", "flows", 10, time.Minute, "")
	if err != nil || second.Partial {
		t.Fatalf("second: %v partial %v", err, second.Partial)
	}
	if !second.Approx || second.ErrorBound <= 0 {
		t.Fatalf("second: a 24 MiB pool can't hold 400,000 conversations exactly; approx %v bound %d", second.Approx, second.ErrorBound)
	}
	if _, err := e.Top(bg, hourQuery(), "src", "flows", 10, time.Minute, first.Cursor); err != ErrExpired {
		t.Fatalf("the evicted cursor: %v, want ErrExpired", err)
	}
	if u := e.pool.Used(); u != 0 {
		t.Fatalf("pool used %d with no query running or saved", u)
	}
	// A summary's values come from the same pool: capped, flagged, returned.
	sum, err := e.Summary(bg, hourQuery(), SummaryQuery{Fields: []string{"src", "dst"}, Top: 5}, time.Minute, "")
	if err != nil {
		t.Fatal(err)
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
			res, err := e.Top(bg, hourQuery(), by, "flows", 5, time.Minute, "")
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
