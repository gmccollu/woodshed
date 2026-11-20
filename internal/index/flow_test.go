package index

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A 1.3 index (schema 7) migrates to 8, 9 and 10, keeping everything.
func TestMigrate13ToFlows(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV8 + `PRAGMA user_version = 7`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != CurrentSchema || CurrentSchema != 10 {
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

// FlowSegmentsPage walks FlowSegments' rows in pages either way, ties by
// path, with the same filter; the count and the devices agree.
func TestFlowSegmentsPage(t *testing.T) {
	d := openIn(t, t.TempDir())
	h := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	var ops []FileOp
	for i := 0; i < 23; i++ {
		dev := []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"}[i%3]
		path := "logs/" + dev + "/flows/" + h.Add(time.Duration(i/3)*time.Hour).Format("2006-01-02T15") + ".wsf"
		start, end := h.Add(time.Duration(i/3)*time.Hour), h.Add(time.Duration(i/3+1)*time.Hour) // ties of 3
		ops = append(ops, FileOp{Kind: OpUpsert, File: File{DeviceID: dev, Type: TypeFlow, Path: path, Day: "2026-11-16",
			FirstReceived: start, LastReceived: end, Size: 1, RawSize: 1, Lines: int64(i + 1)},
			Flow: &FlowSegment{Path: path, DeviceID: dev, Start: start.UnixMilli(), End: end.UnixMilli(), Records: int64(i + 1)}})
	}
	if err := d.Apply(ctx, Batch{Files: ops}); err != nil {
		t.Fatal(err)
	}
	from, to := h.Add(90*time.Minute), h.Add(6*time.Hour)
	for _, devs := range [][]string{nil, {"10.1.0.2", "10.1.0.3"}} {
		all, _ := d.FlowSegments(ctx, devs, from, to)
		for _, asc := range []bool{false, true} {
			var got []FlowSegment
			var c *FlowSegCursor
			for {
				page, err := d.FlowSegmentsPage(ctx, devs, from, to, asc, c, 4)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, page...)
				if len(page) < 4 {
					break
				}
				last := page[len(page)-1]
				c = &FlowSegCursor{Key: last.End, Path: last.Path}
				if asc {
					c.Key = last.Start
				}
			}
			if len(got) != len(all) || len(all) == 0 {
				t.Fatalf("devs %v asc %v: %d rows paged, %d in all", devs, asc, len(got), len(all))
			}
			for i := 1; i < len(got); i++ {
				a, b := got[i-1], got[i]
				if (!asc && (a.End < b.End || a.End == b.End && a.Path <= b.Path)) || (asc && (a.Start > b.Start || a.Start == b.Start && a.Path >= b.Path)) {
					t.Fatalf("asc %v: out of order at %d: %s %s", asc, i, a.Path, b.Path)
				}
			}
		}
		n, recs, err := d.FlowSegmentsCount(ctx, devs, from, to)
		var want int64
		for _, s := range all {
			want += s.Records
		}
		if err != nil || n != int64(len(all)) || recs != want {
			t.Fatalf("count %d %d (want %d %d) %v", n, recs, len(all), want, err)
		}
		ids, _ := d.FlowDevices(ctx, devs, from, to)
		if (devs == nil && len(ids) != 3) || (devs != nil && len(ids) != 2) || ids[0] > ids[len(ids)-1] {
			t.Fatalf("devices %v", ids)
		}
	}
	if rows, _ := d.FlowSegmentsPage(ctx, []string{}, from, to, false, nil, 4); rows != nil {
		t.Fatal("an empty device list has rows")
	}
}

// A plan's pages (no device list, either direction, from the first or a
// cursor) walk an order index: no scan and sort of flow_segments a page.
func TestFlowSegmentsPageUsesIndex(t *testing.T) {
	d := openIn(t, t.TempDir())
	from, to := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	for _, asc := range []bool{false, true} {
		for _, c := range []*FlowSegCursor{nil, {Key: from.UnixMilli() + 1, Path: "logs/x/flows/a.wsf"}} {
			q, args, ok := flowSegPageSQL(nil, from, to, asc, c, 256)
			if !ok {
				t.Fatal("no query")
			}
			rows, err := d.db.QueryContext(ctx, `EXPLAIN QUERY PLAN `+q, args...)
			if err != nil {
				t.Fatal(err)
			}
			var plan []string
			for rows.Next() {
				var id, parent, notused int
				var detail string
				if err := rows.Scan(&id, &parent, &notused, &detail); err != nil {
					t.Fatal(err)
				}
				plan = append(plan, detail)
			}
			rows.Close()
			got := strings.Join(plan, "; ")
			want := "flow_segments_end"
			if asc {
				want = "flow_segments_start"
			}
			if !strings.Contains(got, want) || strings.Contains(got, "TEMP B-TREE") {
				t.Errorf("asc %v cursor %v: %s", asc, c != nil, got)
			}
		}
	}
}

// FlowSegmentsWithRaw lists only the window's raw-holding segments (by their
// files rows' received times), a page at a time by path.
func TestFlowSegmentsWithRawWindowed(t *testing.T) {
	d := openIn(t, t.TempDir())
	h := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	var ops []FileOp
	for i := 0; i < 6; i++ {
		path := "logs/10.1.0.1/flows/" + h.Add(time.Duration(i)*time.Hour).Format("2006-01-02T15") + ".wsf"
		recv := h.Add(time.Duration(i) * time.Hour)
		ops = append(ops, FileOp{Kind: OpUpsert, File: File{DeviceID: "10.1.0.1", Type: TypeFlow, Path: path, Day: "2026-11-16",
			FirstReceived: recv, LastReceived: recv.Add(59 * time.Minute), Size: 1, RawSize: 1, Lines: 1},
			Flow: &FlowSegment{Path: path, DeviceID: "10.1.0.1", Start: recv.UnixMilli(), End: recv.UnixMilli(), Raw: int64(i % 3)}})
	}
	if err := d.Apply(ctx, Batch{Files: ops}); err != nil {
		t.Fatal(err)
	}
	var got []string
	for after := ""; ; {
		rows, err := d.FlowSegmentsWithRaw(ctx, nil, h.Add(90*time.Minute), h.Add(5*time.Hour), after, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		got = append(got, rows[0].Path[len("logs/10.1.0.1/flows/"):])
		after = rows[0].Path
	}
	// Hours 1 to 4 overlap; of those, 1, 2 and 4 hold raw sets.
	if want := "[2026-11-16T01.wsf 2026-11-16T02.wsf 2026-11-16T04.wsf]"; fmt.Sprint(got) != want {
		t.Fatalf("got %v, want %s", got, want)
	}
	all, _ := d.FlowSegmentsWithRaw(ctx, nil, time.Time{}, time.Time{}, "", 100)
	if len(all) != 4 {
		t.Fatalf("%d with open bounds, want 4", len(all))
	}
}
