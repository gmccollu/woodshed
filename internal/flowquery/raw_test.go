package flowquery

import (
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
	dataDir := t.TempDir()
	idx, err := index.Open(filepath.Join(dataDir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
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
	eng := New(Options{DataDir: dataDir, Index: idx})
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
