package index

import (
	"testing"
	"time"
)

// A 1.3 index (schema 7) migrates once to 8, keeping everything.
func TestMigrate13ToFlows(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV8 + `PRAGMA user_version = 7`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != 8 || CurrentSchema != 8 {
		t.Fatalf("schema %d", v)
	}
	if segs, err := d2.AllFlowSegments(ctx); err != nil || len(segs) != 0 {
		t.Fatalf("segments %v %v", segs, err)
	}
}

func TestFlowSegmentsAndMinutes(t *testing.T) {
	d := openIn(t, t.TempDir())
	h := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	seg := func(path, dev string, start, end time.Time, recs int64) FileOp {
		return FileOp{Kind: OpUpsert, File: File{DeviceID: dev, Type: TypeFlow, Path: path, Day: "2026-11-16",
			FirstReceived: start, LastReceived: end, Size: 100, RawSize: 100, Lines: recs},
			Flow: &FlowSegment{Path: path, DeviceID: dev, Start: start.UnixMilli(), End: end.UnixMilli(), Records: recs,
				Bytes: recs * 10, Samplings: []uint32{1, 1000}, Domains: []uint32{1, 2}, ScaledComplete: true}}
	}
	a := "logs/10.1.0.1/flows/2026-11-16T09.wsf"
	b := "logs/10.1.0.2/flows/2026-11-16T09.wsf"
	m := func(path, dev string, minute time.Time, recs, bytes int64, unknown bool) FlowMinute {
		return FlowMinute{Path: path, DeviceID: dev, Minute: minute.UnixMilli(), Records: recs, Bytes: bytes, BytesScaled: bytes * 2, Unknown: unknown}
	}
	if err := d.Apply(ctx, Batch{Files: []FileOp{seg(a, "10.1.0.1", h, h.Add(30*time.Minute), 5), seg(b, "10.1.0.2", h.Add(40*time.Minute), h.Add(50*time.Minute), 3)},
		FlowMinutes: []FlowMinute{m(a, "10.1.0.1", h, 2, 20, false), m(a, "10.1.0.1", h.Add(time.Minute), 3, 30, false), m(b, "10.1.0.2", h.Add(40*time.Minute), 3, 30, true)}}); err != nil {
		t.Fatal(err)
	}
	// Deltas add up.
	if err := d.Apply(ctx, Batch{FlowMinutes: []FlowMinute{m(a, "10.1.0.1", h, 1, 5, false)}}); err != nil {
		t.Fatal(err)
	}
	segs, err := d.FlowSegments(ctx, nil, h.Add(35*time.Minute), h.Add(time.Hour))
	if err != nil || len(segs) != 1 || segs[0].Path != b {
		t.Fatalf("overlap: %+v %v", segs, err)
	}
	segs, _ = d.FlowSegments(ctx, nil, time.Time{}, time.Time{})
	if len(segs) != 2 || segs[0].Path != b || segs[1].Samplings[1] != 1000 || segs[1].Domains[1] != 2 {
		t.Fatalf("all, newest end first: %+v", segs)
	}
	bk, err := d.FlowMinuteBuckets(ctx, nil, h.UnixMilli(), h.Add(time.Hour).UnixMilli(), h.UnixMilli(), (10 * time.Minute).Milliseconds(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got := bk[""][h.UnixMilli()]; got.Records != 6 || got.Bytes != 55 || got.Unknown {
		t.Errorf("bucket 0: %+v", got)
	}
	if got := bk[""][h.Add(40*time.Minute).UnixMilli()]; got.Records != 3 || !got.Unknown || got.BytesScaled != 60 {
		t.Errorf("bucket 40: %+v", got)
	}
	tot, _ := d.FlowDeviceTotals(ctx, []string{"10.1.0.1"}, h.UnixMilli(), h.Add(time.Hour).UnixMilli())
	if tot["10.1.0.1"].Records != 6 || len(tot) != 1 {
		t.Errorf("totals %+v", tot)
	}
	// Deleting the segment's files row removes its derived rows.
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpDelete, File: File{DeviceID: "10.1.0.1", Type: TypeFlow, Path: a},
		Deletion: &Deletion{Time: h, File: a, DeviceID: "10.1.0.1", Type: TypeFlow, Bytes: 100, Reason: ReasonCap}}}}); err != nil {
		t.Fatal(err)
	}
	segs, _ = d.AllFlowSegments(ctx)
	bk, _ = d.FlowMinuteBuckets(ctx, nil, h.UnixMilli(), h.Add(time.Hour).UnixMilli(), h.UnixMilli(), 60000, true)
	if len(segs) != 1 || len(bk["10.1.0.1"]) != 0 || len(bk["10.1.0.2"]) != 1 {
		t.Errorf("after delete: %+v %+v", segs, bk)
	}
	on, _ := d.FlowBytesOnDisk(ctx)
	if on["10.1.0.2"] != 100 || on["10.1.0.1"] != 0 {
		t.Errorf("bytes on disk %v", on)
	}
}

func TestFloorDiv(t *testing.T) {
	for _, c := range [][3]int64{{7, 2, 3}, {-7, 2, -4}, {-6, 2, -3}, {0, 5, 0}} {
		if got := floorDiv(c[0], c[1]); got != c[2] {
			t.Errorf("%d/%d = %d", c[0], c[1], got)
		}
	}
}
