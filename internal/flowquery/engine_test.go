package flowquery

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

var bg = context.Background()

type fixture struct {
	dir  string
	idx  *index.DB
	eng  *Engine
	recs map[string][]flow.Record // by device, every record written
	h    time.Time
}

// newFixture writes segments for 3 devices over 2 hours (several blocks
// each) and indexes them; one device's second hour stays open (a snapshot).
func newFixture(t *testing.T, n int) *fixture {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	fx := &fixture{dir: dir, idx: idx, recs: map[string][]flow.Record{}, h: time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)}
	rng := rand.New(rand.NewPCG(1, 2))
	var open []OpenSegment
	seq := 0
	for d := 1; d <= 3; d++ {
		dev := fmt.Sprintf("10.1.0.%d", d)
		for hr := 0; hr < 2; hr++ {
			hour := fx.h.Add(time.Duration(hr) * time.Hour)
			fdir := filepath.Join(dir, "logs", dev, "flows")
			os.MkdirAll(fdir, 0o750)
			name := flowseg.NameFor(hour)
			path := filepath.Join(fdir, name.String())
			w, err := flowseg.Create(path, dev, hour, "test")
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < n; i++ {
				seq++
				// Received a millisecond apart (blocks split on flushes, not on the
				// writer's 1 s rule); flow times spread over the hour.
				rec := hour.UnixMilli() + int64(i)
				end := hour.Add(time.Duration(i)*time.Hour/time.Duration(n)).UnixMilli() - rng.Int64N(60000)
				r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort |
					flow.HasProto | flow.HasBytes | flow.HasPackets | flow.HasSrcAS,
					Received: rec, End: end, Start: end - rng.Int64N(300000),
					Src: netip.AddrFrom4([4]byte{10, 20, 0, byte(rng.IntN(20))}), Dst: netip.AddrFrom4([4]byte{198, 51, 100, byte(rng.IntN(5))}),
					SrcPort: uint16(1024 + rng.IntN(100)), DstPort: []uint16{443, 53, 22, 80}[rng.IntN(4)], Proto: []uint8{6, 17}[rng.IntN(2)],
					Bytes: uint64(rng.IntN(100000)), Packets: uint64(1 + rng.IntN(100)), Sampling: []uint32{1, 1000, 0}[d-1], Domain: uint32(d),
					SrcAS: uint32(seq)}
				if i%7 == 0 {
					r.Has |= flow.HasFwEvent
					r.FwEvent = flow.FwDenied
				}
				if err := w.Append(&r); err != nil {
					t.Fatal(err)
				}
				fx.recs[dev] = append(fx.recs[dev], r)
				if i%500 == 499 {
					w.Flush()
				}
			}
			w.Flush()
			ff := index.FlowFile{DeviceID: dev, Name: name, Rel: "logs/" + dev + "/flows/" + name.String(), Path: path}
			var rows index.FlowRows
			if d == 3 && hr == 1 {
				snap := w.Snapshot()
				rows = index.FlowRowsOf(ff, snap, w.Size(), false)
				open = append(open, OpenSegment{DeviceID: dev, Rel: ff.Rel, Path: path, Footer: snap})
				t.Cleanup(func() { w.Close() })
			} else {
				foot, err := w.Close()
				if err != nil {
					t.Fatal(err)
				}
				rows = index.FlowRowsOf(ff, foot, w.Size(), true)
			}
			if err := idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment}},
				FlowMinutes: rows.Minutes}); err != nil {
				t.Fatal(err)
			}
		}
	}
	fx.eng = New(Options{DataDir: dir, Index: idx, Open: func([]string) []OpenSegment { return open }, Workers: 3})
	// Tiny plan pages and batches, so every query here crosses both (the
	// defaults run in mem_test.go and the other packages).
	fx.eng.page, fx.eng.batch = 2, 7
	return fx
}

func (fx *fixture) brute(q Query) []flow.Record {
	var out []flow.Record
	f := q.filter()
	want := map[string]bool{}
	for _, d := range q.DeviceIDs {
		want[d] = true
	}
	for dev, rs := range fx.recs {
		if q.DeviceIDs != nil && !want[dev] {
			continue
		}
		for i := range rs {
			r := rs[i]
			s, e := flowseg.EffectiveTimes(&r)
			if e >= q.From.UnixMilli() && s < q.To.UnixMilli() && f.Match(&r) {
				out = append(out, r)
			}
		}
	}
	return out
}

func mustFilter(t *testing.T, q string) *Filter {
	v, _ := url.ParseQuery(q)
	f, err := Parse(v.Get)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestEngineTopMatchesBruteForce(t *testing.T) {
	fx := newFixture(t, 3000)
	for _, fq := range []string{"", "proto=tcp", "dst_port=443,22&src=10.20.0.0/28", "fw_event=denied", "dst=198.51.100.3"} {
		q := Query{From: fx.h.Add(20 * time.Minute), To: fx.h.Add(100 * time.Minute), Filter: mustFilter(t, fq)}
		for _, by := range []string{"src", "dst_port", "conversation"} {
			res, err := fx.eng.Top(bg, q, by, "bytes", 5, time.Minute, "")
			if err != nil {
				t.Fatal(err)
			}
			want, _ := NewTop(by, "bytes")
			for _, r := range fx.brute(q) {
				want.Add(&r)
			}
			wr, wz := want.RowsZero(5)
			if res.Partial || res.Total != want.Total || len(res.Rows) != len(wr) || res.ZeroOmitted != wz {
				t.Fatalf("%s by %s: total %+v want %+v (partial %v, zero %d want %d)", fq, by, res.Total, want.Total, res.Partial,
					res.ZeroOmitted, wz)
			}
			for _, row := range res.Rows {
				if row.Bytes == 0 {
					t.Fatalf("%s by %s: a row with 0 bytes: %+v", fq, by, row)
				}
			}
			for i := range wr {
				if res.Rows[i].Key != wr[i].Key || res.Rows[i].Sums != wr[i].Sums {
					t.Fatalf("%s by %s row %d: %+v want %+v", fq, by, i, res.Rows[i], wr[i])
				}
			}
			if res.Progress.BlocksDone != res.Progress.BlocksTotal || !res.Progress.CompleteFrom.Equal(q.From) {
				t.Fatalf("progress %+v", res.Progress)
			}
		}
	}
}

// With no budget each request reads one wave; the cursor continues the same
// counts until they're complete, and they equal one full answer.
func TestEngineTopPartialContinues(t *testing.T) {
	fx := newFixture(t, 3000)
	fx.eng.o.Workers = 1
	q := Query{From: fx.h, To: fx.h.Add(2 * time.Hour)}
	full, _ := fx.eng.Top(bg, q, "src", "flows", 10, time.Minute, "")
	res, err := fx.eng.Top(bg, q, "src", "flows", 10, 0, "")
	if err != nil || !res.Partial || res.Cursor == "" {
		t.Fatalf("first %+v %v", res.Progress, err)
	}
	last := res.Progress.CompleteFrom
	for steps := 0; res.Partial; steps++ {
		if steps > 1000 {
			t.Fatal("no end")
		}
		if res, err = fx.eng.Top(bg, q, "src", "flows", 10, 0, res.Cursor); err != nil {
			t.Fatal(err)
		}
		if res.Progress.CompleteFrom.After(last) {
			t.Fatalf("complete_from went forward: %v after %v", res.Progress.CompleteFrom, last)
		}
		last = res.Progress.CompleteFrom
	}
	if res.Total != full.Total || res.Rows[0] != full.Rows[0] {
		t.Fatalf("continued %+v, full %+v", res.Total, full.Total)
	}
	if _, err := fx.eng.Top(bg, q, "src", "flows", 10, 0, "fq_nope"); err != ErrExpired {
		t.Fatalf("unknown cursor: %v", err)
	}
	r2, _ := fx.eng.Top(bg, q, "src", "flows", 10, 0, "")
	if _, err := fx.eng.Top(bg, q, "dst", "flows", 10, 0, r2.Cursor); err != ErrCursor {
		t.Fatalf("another query's cursor: %v", err)
	}
}

// Paging through a search with any budget returns every match once, in order
// by flow end, newest first (or oldest first), the open segment included.
func TestEngineSearchPages(t *testing.T) {
	fx := newFixture(t, 2000)
	for _, asc := range []bool{false, true} {
		for _, budget := range []time.Duration{time.Minute, 0} {
			for _, fq := range []string{"", "proto=udp&dst_port=53", "src=10.20.0.7"} {
				q := Query{From: fx.h.Add(10 * time.Minute), To: fx.h.Add(110 * time.Minute), Filter: mustFilter(t, fq)}
				want := fx.brute(q)
				var got []flow.Record
				cursor := ""
				for pages := 0; ; pages++ {
					if pages > 10000 {
						t.Fatal("no end")
					}
					res, err := fx.eng.Search(bg, q, 137, asc, cursor, budget)
					if err != nil {
						t.Fatal(err)
					}
					for _, h := range res.Hits {
						got = append(got, h.Record)
					}
					if res.Cursor == "" {
						break
					}
					cursor = res.Cursor
				}
				if len(got) != len(want) {
					t.Fatalf("asc %v budget %v %q: %d hits, want %d", asc, budget, fq, len(got), len(want))
				}
				seen := map[uint32]bool{}
				for i := range got {
					if seen[got[i].SrcAS] {
						t.Fatalf("record %d twice", got[i].SrcAS)
					}
					seen[got[i].SrcAS] = true
					if i > 0 {
						_, a := flowseg.EffectiveTimes(&got[i-1])
						_, b := flowseg.EffectiveTimes(&got[i])
						if (!asc && a < b) || (asc && a > b) {
							t.Fatalf("out of order at %d: %d then %d", i, a, b)
						}
					}
				}
			}
		}
	}
}

func TestEngineSummaryEachCount(t *testing.T) {
	fx := newFixture(t, 1500)
	q := Query{From: fx.h.Add(5 * time.Minute), To: fx.h.Add(90 * time.Minute), Filter: mustFilter(t, "proto=tcp")}
	want := fx.brute(q)
	res, err := fx.eng.Summary(bg, q, SummaryQuery{Fields: FieldKeys, Top: 5, Histogram: true, Bucket: 10 * time.Minute, Origin: time.Unix(0, 0)},
		time.Minute, "")
	if err != nil || res.Partial {
		t.Fatal(err)
	}
	if res.Matched != int64(len(want)) {
		t.Fatalf("matched %d want %d", res.Matched, len(want))
	}
	var flows, bytes int64
	for _, b := range res.Buckets {
		flows += b.Flows
		bytes += b.Bytes
	}
	var wb int64
	for _, r := range want {
		wb += int64(r.SumBytes())
	}
	if flows != int64(len(want)) || bytes != wb {
		t.Fatalf("histogram flows %d bytes %d, want %d %d", flows, bytes, len(want), wb)
	}
	for _, fc := range res.Fields {
		if fc.Key == "proto" && (len(fc.Values) != 1 || fc.Values[0].Value != "tcp" || fc.Values[0].Count != int64(len(want))) {
			t.Fatalf("proto %+v", fc)
		}
		if fc.Key == "fw_event" && fc.None == 0 {
			t.Fatalf("fw_event none %+v", fc)
		}
	}
	n := 0
	if err := fx.eng.Each(bg, q, func(string, *flow.Record) error { n++; return nil }); err != nil || n != len(want) {
		t.Fatalf("each %d want %d %v", n, len(want), err)
	}
	q.Filter = nil
	all := fx.brute(q)
	c, err := fx.eng.Count(bg, q)
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, v := range c {
		total += v
	}
	if total != int64(len(all)) {
		t.Fatalf("count %d want %d", total, len(all))
	}
	_ = sort.Strings
}

// A search continued with the default range keeps the first page's range.
func TestEngineSearchCursorKeepsDefaultRange(t *testing.T) {
	fx := newFixture(t, 500)
	q := Query{From: fx.h, To: fx.h.Add(2 * time.Hour), DefaultRange: true}
	res, err := fx.eng.Search(bg, q, 10, false, "", time.Minute)
	if err != nil || res.Cursor == "" {
		t.Fatal(err)
	}
	q2 := Query{From: fx.h.Add(time.Hour), To: fx.h.Add(90 * time.Minute), DefaultRange: true} // "now" moved on
	res2, err := fx.eng.Search(bg, q2, 10, false, res.Cursor, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, last := flowseg.EffectiveTimes(&res.Hits[len(res.Hits)-1].Record)
	for _, h := range res2.Hits {
		if _, e := flowseg.EffectiveTimes(&h.Record); e > last || e < fx.h.UnixMilli() {
			t.Fatalf("hit outside the first page's range: %d (last %d)", e, last)
		}
	}
	// The next page follows straight on: newer than the second request's own
	// (later) range would allow.
	if _, e := flowseg.EffectiveTimes(&res2.Hits[0].Record); len(res2.Hits) != 10 || e <= fx.h.Add(90*time.Minute).UnixMilli() {
		t.Fatalf("second page %d hits, first end %d", len(res2.Hits), e)
	}
}
