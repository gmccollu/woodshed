package flowquery

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// Data kept raw for lack of its template is decoded on read when the
// segment holds the template (SPEC §13.1.3): searches, counts, top-N and
// Each see its records, marked late.
func TestEngineDecodesRawOnRead(t *testing.T) {
	eng, h := rawFixture(t)
	q := Query{From: h, To: h.Add(time.Hour)}
	c, err := eng.Count(bg, q)
	if err != nil || c["192.0.2.9"] != 5 {
		t.Fatalf("count %v %v", c, err)
	}
	late := 0
	eng.Each(bg, q, func(_ string, r *flow.Record) error {
		if r.Status == flow.StatusLate {
			late++
		}
		return nil
	})
	if late != 3 {
		t.Fatalf("late %d", late)
	}
	top, err := eng.Top(bg, q, "src", "flows", 5, time.Minute, "")
	if err != nil || top.Rows[0].Key != "10.0.0.7" || top.Rows[0].Flows != 3 {
		t.Fatalf("top %+v %v", top.Rows, err)
	}
	res, err := eng.Search(bg, Query{From: h, To: h.Add(time.Hour), Filter: mustFilter(t, "status=late")}, 10, false, "", time.Minute)
	if err != nil || len(res.Hits) != 3 {
		t.Fatalf("search %d %v", len(res.Hits), err)
	}
}

// rawFixture is a segment of one exporter: 2 records decoded on arrival and
// a raw set of 3 kept for lack of its template, which the segment holds.
func rawFixture(t *testing.T) (*Engine, time.Time) {
	t.Helper()
	dataDir := t.TempDir()
	idx, err := index.Open(filepath.Join(dataDir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	h := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	from := netip.MustParseAddrPort("192.0.2.9:40000")
	fields := []flow.TemplateField{{ID: 8, Length: 4}, {ID: 12, Length: 4}, {ID: 1, Length: 8}, {ID: 2, Length: 8}, {ID: 153, Length: 8}}
	data := func(n int, src string) []byte {
		b := flow.NewBuilder(flow.IPFIX)
		for i := 0; i < n; i++ {
			b.Data(300, flow.Values(nil).Addr(netip.MustParseAddr(src)).Addr(netip.MustParseAddr("10.0.0.2")).U64(100).U64(1).
				U64(uint64(h.Add(time.Minute).UnixMilli())))
		}
		return b.Message(flow.Header{ExportTime: uint32(h.Unix()), Domain: 1})
	}
	now := h
	coll := flow.NewCollector(flow.Options{TemplateTimeout: time.Minute, Clock: func() time.Time { return now }})
	var recs []flow.Record
	var raws []*flow.RawSet
	emit := func(r *flow.Record) { recs = append(recs, *r) }
	keep := func(rs *flow.RawSet) { raws = append(raws, rs) }
	coll.Decode(flow.Packet{Data: data(3, "10.0.0.7"), From: from, Received: h.Add(time.Minute)}, emit, keep)
	now = h.Add(3 * time.Minute)
	coll.Expire(now, keep)
	tb := flow.NewBuilder(flow.IPFIX)
	tb.Template(300, fields)
	coll.Decode(flow.Packet{Data: tb.Message(flow.Header{ExportTime: uint32(now.Unix()), Domain: 1}), From: from, Received: now}, emit, keep)
	coll.Decode(flow.Packet{Data: data(2, "10.0.0.1"), From: from, Received: now}, emit, keep)
	if len(raws) != 1 || len(recs) != 2 {
		t.Fatalf("raws %d recs %d", len(raws), len(recs))
	}
	dir := filepath.Join(dataDir, "logs", "192.0.2.9", "flows")
	os.MkdirAll(dir, 0o750)
	name := flowseg.NameFor(h)
	path := filepath.Join(dir, name.String())
	w, _ := flowseg.Create(path, "192.0.2.9", h, "test")
	for i := range recs {
		w.Append(&recs[i])
	}
	w.AppendRaw(raws[0])
	foot, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	ff := index.FlowFile{DeviceID: "192.0.2.9", Name: name, Rel: "logs/192.0.2.9/flows/" + name.String(), Path: path}
	rows := index.FlowRowsOf(ff, foot, w.Size(), true)
	if err := idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment}}}); err != nil {
		t.Fatal(err)
	}
	return New(Options{DataDir: dataDir, Index: idx}), h
}

// rawSetsEnding is n records' raw set (kept for lack of a template,
// received a minute into hour h) whose records end at end, and the template
// that decodes them.
func rawSetsEnding(t *testing.T, h time.Time, n int, end time.Time) ([]*flow.RawSet, *flow.Template) {
	t.Helper()
	from := netip.MustParseAddrPort("192.0.2.9:40000")
	fields := []flow.TemplateField{{ID: 8, Length: 4}, {ID: 12, Length: 4}, {ID: 1, Length: 8}, {ID: 2, Length: 8}, {ID: 153, Length: 8}}
	data := func(n int, src string) []byte {
		b := flow.NewBuilder(flow.IPFIX)
		for i := 0; i < n; i++ {
			b.Data(300, flow.Values(nil).Addr(netip.MustParseAddr(src)).Addr(netip.MustParseAddr("10.0.0.2")).U64(100).U64(1).
				U64(uint64(end.UnixMilli())))
		}
		return b.Message(flow.Header{ExportTime: uint32(h.Unix()), Domain: 1})
	}
	now := h
	coll := flow.NewCollector(flow.Options{TemplateTimeout: time.Minute, Clock: func() time.Time { return now }})
	var raws []*flow.RawSet
	var recs []flow.Record
	keep := func(rs *flow.RawSet) { raws = append(raws, rs) }
	coll.Decode(flow.Packet{Data: data(n, "10.0.0.7"), From: from, Received: h.Add(time.Minute)}, func(*flow.Record) {}, keep)
	now = h.Add(3 * time.Minute)
	coll.Expire(now, keep)
	tb := flow.NewBuilder(flow.IPFIX)
	tb.Template(300, fields)
	emit := func(r *flow.Record) { recs = append(recs, *r) }
	coll.Decode(flow.Packet{Data: tb.Message(flow.Header{ExportTime: uint32(now.Unix()), Domain: 1}), From: from, Received: now}, emit, keep)
	coll.Decode(flow.Packet{Data: data(1, "10.0.0.1"), From: from, Received: now}, emit, keep)
	if len(raws) == 0 || len(recs) != 1 || recs[0].Template == nil {
		t.Fatalf("raw sets %d, records %d", len(raws), len(recs))
	}
	return raws, recs[0].Template
}

// Raw sets whose records end long after they were received (an exporter's
// clock ahead of Woodshed's) are found and placed by every page size and by
// Stream: nothing lost, every record once, in order, the pages and Stream
// alike. Their blocks used to be bounded by the received times, so a page's
// cursor passed them (pages of 137 lost all 40 with the clock 29 min ahead).
func TestRawSetsAheadOfReceived(t *testing.T) {
	for _, ahead := range []time.Duration{30 * time.Second, 29 * time.Minute, -50 * time.Minute} {
		fx := newFixture(t, 600)
		h := fx.h
		dev := "10.1.0.2"
		name := flowseg.NameFor(h)
		name.Part = 1 // a second part of the hour
		path := filepath.Join(fx.dir, "logs", dev, "flows", name.String())
		w, err := flowseg.Create(path, dev, h, "test")
		if err != nil {
			t.Fatal(err)
		}
		// A few records of its own, so the index has its row; the raw sets
		// end ahead of their received time (h + 1 min).
		for i := 0; i < 50; i++ {
			ms := h.Add(time.Minute).UnixMilli() + int64(i)
			r := flow.Record{Has: flow.HasEnd | flow.HasSrc, Received: ms, End: ms, Src: netip.MustParseAddr("10.20.0.99"), SrcAS: uint32(900000 + i)}
			if err := w.Append(&r); err != nil {
				t.Fatal(err)
			}
		}
		raws, tmpl := rawSetsEnding(t, h, 40, h.Add(time.Minute+ahead))
		w.AddTemplate(tmpl)
		for _, rs := range raws {
			if err := w.AppendRaw(rs); err != nil {
				t.Fatal(err)
			}
		}
		foot, err := w.Close()
		if err != nil {
			t.Fatal(err)
		}
		ff := index.FlowFile{DeviceID: dev, Name: name, Rel: "logs/" + dev + "/flows/" + name.String(), Path: path}
		rows := index.FlowRowsOf(ff, foot, w.Size(), true)
		if err := fx.idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment}},
			FlowMinutes: rows.Minutes}); err != nil {
			t.Fatal(err)
		}
		q := Query{From: h.Add(-2 * time.Hour), To: h.Add(4 * time.Hour)}
		c, err := fx.eng.Count(bg, q)
		if err != nil {
			t.Fatal(err)
		}
		total := 0
		for _, n := range c {
			total += int(n)
		}
		if total != 6*600+50+40 {
			t.Fatalf("ahead %v: count %d", ahead, total)
		}
		for _, asc := range []bool{false, true} {
			stream := streamAll(t, fx.eng, q, asc)
			what := fmt.Sprintf("ahead %v asc %v", ahead, asc)
			if len(stream) != total {
				t.Fatalf("%s: stream %d of %d", what, len(stream), total)
			}
			late := 0
			for i := range stream {
				if stream[i].Record.Status == flow.StatusLate {
					late++
				}
				if i > 0 {
					a, b := keyOfHit(&stream[i-1]), keyOfHit(&stream[i])
					if !a.before(b, asc) {
						t.Fatalf("%s: out of order at %d: %+v then %+v", what, i, a, b)
					}
				}
			}
			if late != 40 {
				t.Fatalf("%s: %d late records", what, late)
			}
			for _, limit := range []int{7, 137, 5000} {
				sameHits(t, fmt.Sprintf("%s limit %d", what, limit), searchAll(t, fx.eng, q, asc, limit), stream)
			}
		}
	}
}
