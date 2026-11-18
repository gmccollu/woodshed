package index

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
)

// A data set kept raw because its template came only after the wait gives up
// is decoded by RedecodeFlows with the template the segment holds, and the
// rows Reindex rebuilds count it.
func TestRedecodeFlows(t *testing.T) {
	dataDir := t.TempDir()
	h := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	from := netip.MustParseAddrPort("192.0.2.9:40000")
	fields := []flow.TemplateField{{ID: 8, Length: 4}, {ID: 12, Length: 4}, {ID: 1, Length: 8}, {ID: 2, Length: 8}, {ID: 153, Length: 8}}
	data := func(n int) []byte {
		b := flow.NewBuilder(flow.IPFIX)
		for i := 0; i < n; i++ {
			v := flow.Values(nil).Addr(netip.MustParseAddr("10.0.0.1")).Addr(netip.MustParseAddr("10.0.0.2")).U64(100).U64(1).
				U64(uint64(h.Add(time.Minute).UnixMilli()))
			b.Data(300, v)
		}
		return b.Message(flow.Header{ExportTime: uint32(h.Unix()), Domain: 1})
	}
	now := h
	coll := flow.NewCollector(flow.Options{TemplateTimeout: time.Minute, Clock: func() time.Time { return now }})
	var recs []flow.Record
	var raws []*flow.RawSet
	emit := func(r *flow.Record) { recs = append(recs, *r) }
	keep := func(rs *flow.RawSet) { raws = append(raws, rs) }
	coll.Decode(flow.Packet{Data: data(3), From: from, Received: h}, emit, keep)
	now = h.Add(2 * time.Minute) // the wait is over: the data is kept raw
	coll.Expire(now, keep)
	if len(raws) != 1 || raws[0].Status != flow.StatusNoTemplate || len(recs) != 0 {
		t.Fatalf("raws %d recs %d", len(raws), len(recs))
	}
	tb := flow.NewBuilder(flow.IPFIX)
	tb.Template(300, fields)
	coll.Decode(flow.Packet{Data: tb.Message(flow.Header{ExportTime: uint32(now.Unix()), Domain: 1}), From: from, Received: now}, emit, keep)
	coll.Decode(flow.Packet{Data: data(2), From: from, Received: now}, emit, keep)
	if len(recs) != 2 {
		t.Fatalf("records after the template: %d", len(recs))
	}

	dir := filepath.Join(dataDir, "logs", "192.0.2.9", "flows")
	os.MkdirAll(dir, 0o750)
	path := filepath.Join(dir, flowseg.NameFor(h).String())
	w, err := flowseg.Create(path, "192.0.2.9", h, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i := range recs {
		w.Append(&recs[i])
	}
	w.AppendRaw(raws[0])
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := RedecodeFlows(dataDir, "test", nil)
	if err != nil || res.Segments != 1 || res.Decoded != 1 || res.Records != 3 || res.StillRaw != 0 {
		t.Fatalf("redecode %+v %v", res, err)
	}
	r, err := flowseg.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f := r.Footer()
	if f.Totals.Records != 5 || f.Raw != 0 || f.Totals.Status[flow.StatusLate] != 3 {
		t.Fatalf("footer %+v raw %d", f.Totals, f.Raw)
	}
	// Until Reindex has run, the rows are marked stale (a start reads
	// every footer); Reindex clears the mark.
	marker := filepath.Join(dataDir, FlowRowsStaleFile)
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("no stale mark after a redecode: %v", err)
	}
	d := openIn(t, t.TempDir())
	if _, err := d.Reindex(ctx, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(marker); !os.IsNotExist(err) {
		t.Fatalf("stale mark after Reindex: %v", err)
	}
	segs, _ := d.AllFlowSegments(ctx)
	if len(segs) != 1 || segs[0].Records != 5 || segs[0].Late != 3 {
		t.Fatalf("index %+v", segs)
	}
	// Running it again finds nothing to do.
	if res, _ := RedecodeFlows(dataDir, "test", nil); res.Segments != 0 {
		t.Fatalf("again %+v", res)
	}
}
