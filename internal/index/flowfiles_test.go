package index

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
)

func writeSegment(t *testing.T, dataDir, dev string, hour time.Time, n int, closeIt bool) string {
	t.Helper()
	dir := filepath.Join(dataDir, "logs", dev, "flows")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, flowseg.NameFor(hour).String())
	w, err := flowseg.Create(p, dev, hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		at := hour.Add(time.Duration(i) * time.Second).UnixMilli()
		r := &flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasPackets,
			Received: at, Start: at - 1000, End: at, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"),
			Bytes: 100, Packets: 1, Sampling: 1}
		if err := w.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if closeIt {
		if _, err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// A crash: the file as it is now (its blocks, no footer), and the
	// writer's handle gone with the process. A handle left open would keep
	// the file from being removed on Windows (CI run 44032327415: "being used
	// by another process"), which a crashed server's never does.
	if err := w.Sync(); err != nil {
		t.Fatal(err)
	}
	img, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, img, 0o640); err != nil {
		t.Fatal(err)
	}
	return p
}

// Reindex rebuilds files, flow_segments and flow_minute from the footers,
// closing a segment a crash left open; Reconcile drops the rows of a deleted
// segment and keeps the others.
func TestReindexFlows(t *testing.T) {
	dataDir := t.TempDir()
	h := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	writeSegment(t, dataDir, "10.1.0.1", h, 50, true)
	open := writeSegment(t, dataDir, "10.1.0.2", h, 30, false)
	d := openIn(t, t.TempDir())
	res, err := d.Reindex(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if res.FlowRecovered != 1 || res.Devices != 2 {
		t.Fatalf("result %+v", res)
	}
	segs, _ := d.AllFlowSegments(ctx)
	if len(segs) != 2 || segs[0].Records != 50 || segs[1].Records != 30 || !segs[1].Closed || segs[0].Bytes != 5000 {
		t.Fatalf("segments %+v", segs)
	}
	tot, _ := d.FlowDeviceTotals(ctx, nil, h.Add(-time.Hour).UnixMilli(), h.Add(2*time.Hour).UnixMilli())
	if tot["10.1.0.1"].Records != 50 || tot["10.1.0.1"].Bytes != 5000 || tot["10.1.0.2"].Records != 30 {
		t.Fatalf("minutes %+v", tot)
	}
	files, _ := d.Files(ctx, "10.1.0.1")
	if len(files) != 1 || files[0].Type != TypeFlow || files[0].Lines != 50 || !files[0].Compressed {
		t.Fatalf("files %+v", files)
	}
	devs, _ := d.ListDevices(ctx)
	if len(devs) != 2 {
		t.Fatalf("devices %+v", devs)
	}
	// Reconcile: a segment gone from disk loses its rows; the other stays.
	if err := os.Remove(open); err != nil {
		t.Fatal(err)
	}
	if res, err = d.Reconcile(ctx, dataDir); err != nil || res.Removed != 1 {
		t.Fatalf("reconcile %+v %v", res, err)
	}
	segs, _ = d.AllFlowSegments(ctx)
	tot, _ = d.FlowDeviceTotals(ctx, nil, h.Add(-time.Hour).UnixMilli(), h.Add(2*time.Hour).UnixMilli())
	if len(segs) != 1 || tot["10.1.0.2"].Records != 0 || tot["10.1.0.1"].Records != 50 {
		t.Fatalf("after reconcile %+v %+v", segs, tot)
	}
	// Running it again changes nothing (minutes aren't added twice).
	if _, err = d.Reconcile(ctx, dataDir); err != nil {
		t.Fatal(err)
	}
	tot, _ = d.FlowDeviceTotals(ctx, nil, h.Add(-time.Hour).UnixMilli(), h.Add(2*time.Hour).UnixMilli())
	if tot["10.1.0.1"].Records != 50 {
		t.Fatalf("reconcile twice %+v", tot)
	}
}

// flowRowsDump renders every flow files, flow_segments and flow_minute row
// (with the files row IDs: a row kept as is keeps its ID).
func flowRowsDump(t *testing.T, d *DB) string {
	t.Helper()
	var b strings.Builder
	files, err := d.Files(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.Type == TypeFlow {
			fmt.Fprintf(&b, "file %+v\n", f)
		}
	}
	segs, err := d.AllFlowSegments(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range segs {
		fmt.Fprintf(&b, "seg %+v\n", s)
	}
	rows, err := d.db.QueryContext(ctx, `SELECT device_id, minute, path, records, bytes, packets, bytes_scaled, packets_scaled, unknown
		FROM flow_minute ORDER BY path, device_id, minute`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var m FlowMinute
		var unknown int
		if err := rows.Scan(&m.DeviceID, &m.Minute, &m.Path, &m.Records, &m.Bytes, &m.Packets, &m.BytesScaled, &m.PacketsScaled, &unknown); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "min %+v %d\n", m, unknown)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// Reconcile keeps a closed segment's rows when the file still matches them
// (path and size) without opening it: nothing is read or counted, and the
// rows stay as they were. New segments, segments whose rows aren't closed
// and missing ones are read or dropped, and only they count. Reindex reads
// every footer. A stale-minutes marker makes Reconcile read every footer
// once, and is removed.
func TestReconcileKeepsCurrentFlowRows(t *testing.T) {
	dataDir := t.TempDir()
	h := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	segA := writeSegment(t, dataDir, "10.1.0.1", h, 50, true)
	writeSegment(t, dataDir, "10.1.0.1", h.Add(time.Hour), 40, true)
	segC := writeSegment(t, dataDir, "10.1.0.2", h, 30, true)
	d := openIn(t, t.TempDir())
	res, err := d.Reindex(ctx, dataDir)
	if err != nil || res.Scanned != 3 || res.Removed != 0 || res.FlowRecovered != 0 || len(res.Skipped) != 0 {
		t.Fatalf("reindex %+v %v", res, err)
	}
	want := flowRowsDump(t, d)
	devsBefore, _ := d.ListDevices(ctx)

	// Nothing changed: nothing read, nothing counted, rows untouched.
	res, err = d.Reconcile(ctx, dataDir)
	if err != nil || res.Scanned != 0 || res.Removed != 0 || res.FlowRecovered != 0 || len(res.Skipped) != 0 || res.Devices != 2 {
		t.Fatalf("idle reconcile %+v %v", res, err)
	}
	if got := flowRowsDump(t, d); got != want {
		t.Fatalf("idle reconcile changed the rows\ngot:\n%s\nwant:\n%s", got, want)
	}
	if devs, _ := d.ListDevices(ctx); fmt.Sprint(devs) != fmt.Sprint(devsBefore) {
		t.Fatalf("devices %+v, were %+v", devs, devsBefore)
	}

	// The proof that a matching segment isn't opened: same size, footer
	// garbled. Reconcile keeps the rows; Reindex reads it and can't.
	orig, err := os.ReadFile(segA)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), orig...)
	for i := len(bad) - 64; i < len(bad); i++ {
		bad[i] ^= 0xff
	}
	if err := os.WriteFile(segA, bad, 0o640); err != nil {
		t.Fatal(err)
	}
	if res, err = d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 0 || len(res.Skipped) != 0 {
		t.Fatalf("reconcile opened a matching segment: %+v %v", res, err)
	}
	if got := flowRowsDump(t, d); got != want {
		t.Fatalf("rows changed\ngot:\n%s\nwant:\n%s", got, want)
	}
	if err := os.WriteFile(segA, orig, 0o640); err != nil {
		t.Fatal(err)
	}

	// Reindex (full) reads every footer again, and rebuilds the same rows
	// (new IDs: the files table is rebuilt).
	res, err = d.Reindex(ctx, dataDir)
	if err != nil || res.Scanned != 3 || len(res.Skipped) != 0 {
		t.Fatalf("second reindex %+v %v", res, err)
	}
	want = flowRowsDump(t, d)

	// A segment whose rows aren't closed (the close's index update lost in
	// a crash: the rows are a flush's), at the same size, is read.
	fileC, err := d.FileByPath(ctx, "logs/10.1.0.2/flows/"+flowseg.NameFor(h).String())
	if err != nil {
		t.Fatal(err)
	}
	segs, _ := d.FlowSegmentsByPath(ctx, []string{fileC.Path})
	if len(segs) != 1 {
		t.Fatalf("segment C %+v", segs)
	}
	open := segs[0]
	open.Closed, open.Records = false, 20
	openFile := fileC
	openFile.Compressed = false
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpUpsert, File: openFile, Flow: &open}}}); err != nil {
		t.Fatal(err)
	}
	if res, err = d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 1 || res.Removed != 0 {
		t.Fatalf("reconcile of an unclosed row %+v %v", res, err)
	}
	if got := flowRowsDump(t, d); got != want {
		t.Fatalf("after reading the unclosed segment\ngot:\n%s\nwant:\n%s", got, want)
	}

	// A new segment is read, a missing one dropped; only they count.
	writeSegment(t, dataDir, "10.1.0.3", h, 10, true)
	if err := os.Remove(segC); err != nil {
		t.Fatal(err)
	}
	if res, err = d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 1 || res.Removed != 1 || res.Devices != 2 {
		t.Fatalf("reconcile of new and missing %+v %v", res, err)
	}
	tot, _ := d.FlowDeviceTotals(ctx, nil, h.Add(-time.Hour).UnixMilli(), h.Add(3*time.Hour).UnixMilli())
	if tot["10.1.0.1"].Records != 90 || tot["10.1.0.2"].Records != 0 || tot["10.1.0.3"].Records != 10 {
		t.Fatalf("totals %+v", tot)
	}
	fresh := openIn(t, t.TempDir())
	if _, err := fresh.Reindex(ctx, dataDir); err != nil {
		t.Fatal(err)
	}
	if got, want := flowMinutesOnly(flowRowsDump(t, d)), flowMinutesOnly(flowRowsDump(t, fresh)); got != want {
		t.Fatalf("incremental rows differ from a full rebuild\ngot:\n%s\nwant:\n%s", got, want)
	}

	// Lost minutes: the store's marker makes Reconcile read every footer
	// once (restoring them), then it's gone and the next one reads nothing.
	if _, err := d.db.ExecContext(ctx, `DELETE FROM flow_minute WHERE path = ?`, "logs/10.1.0.1/flows/"+flowseg.NameFor(h).String()); err != nil {
		t.Fatal(err)
	}
	if err := MarkFlowRowsStale(dataDir); err != nil {
		t.Fatal(err)
	}
	if res, err = d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 3 || res.Removed != 0 {
		t.Fatalf("reconcile with the marker %+v %v", res, err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, FlowRowsStaleFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("marker still there: %v", err)
	}
	if got, want := flowMinutesOnly(flowRowsDump(t, d)), flowMinutesOnly(flowRowsDump(t, fresh)); got != want {
		t.Fatalf("minutes not restored\ngot:\n%s\nwant:\n%s", got, want)
	}
	if res, err = d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 0 || res.Removed != 0 {
		t.Fatalf("reconcile after the marker %+v %v", res, err)
	}
	// Reindex clears a marker too.
	if err := MarkFlowRowsStale(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Reindex(ctx, dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, FlowRowsStaleFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("marker after reindex: %v", err)
	}
}

// flowMinutesOnly keeps a dump's seg and min lines (files rows carry IDs,
// which differ between two indexes).
func flowMinutesOnly(dump string) string {
	var out []string
	for _, l := range strings.Split(dump, "\n") {
		if strings.HasPrefix(l, "seg ") || strings.HasPrefix(l, "min ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// segmentRows are a segment file's rows as the store queues them at close.
func segmentRows(t *testing.T, dataDir, path string) FlowRows {
	t.Helper()
	r, err := flowseg.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(dataDir, path)
	if err != nil {
		t.Fatal(err)
	}
	rel = filepath.ToSlash(rel)
	dev := strings.Split(rel, "/")[1]
	n, _ := flowseg.ParseName(filepath.Base(path))
	return FlowRowsOf(FlowFile{DeviceID: dev, Name: n, Rel: rel, Path: path, Size: fi.Size()}, r.Footer(), fi.Size(), true)
}

// One batch with a segment's close (rows and last minutes), its delete, and
// a new segment at the same path: the minutes travel with their ops, so the
// path ends with the new segment's minutes only. Minutes sent the old way
// (Batch.FlowMinutes, after every op) land on the new segment; Reconcile's
// sum check sees that and reads it.
func TestApplyFlowCloseDeleteCreateSamePath(t *testing.T) {
	dataDir := t.TempDir()
	h := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	path := writeSegment(t, dataDir, "10.1.0.1", h, 50, true)
	old := segmentRows(t, dataDir, path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	writeSegment(t, dataDir, "10.1.0.1", h, 30, true)
	cur := segmentRows(t, dataDir, path)
	if old.File.Path != cur.File.Path || old.Segment.Records != 50 || cur.Segment.Records != 30 {
		t.Fatalf("setup %+v %+v", old.Segment, cur.Segment)
	}
	del := FileOp{Kind: OpDelete, File: File{DeviceID: "10.1.0.1", Type: TypeFlow, Path: old.File.Path}}
	total := func(d *DB) int64 {
		tot, err := d.FlowDeviceTotals(ctx, nil, h.Add(-3*time.Hour).UnixMilli(), h.Add(3*time.Hour).UnixMilli())
		if err != nil {
			t.Fatal(err)
		}
		return tot["10.1.0.1"].Records
	}

	d := openIn(t, t.TempDir())
	if err := d.Apply(ctx, Batch{Files: []FileOp{
		{Kind: OpUpsert, File: old.File, Flow: &old.Segment, FlowMinutes: old.Minutes},
		del,
		{Kind: OpUpsert, File: cur.File, Flow: &cur.Segment, FlowMinutes: cur.Minutes},
	}}); err != nil {
		t.Fatal(err)
	}
	if n := total(d); n != 30 {
		t.Fatalf("minutes %d, want 30", n)
	}
	setRowsVersion(t, d)
	if res, err := d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 0 || total(d) != 30 {
		t.Fatalf("reconcile %+v %v, minutes %d", res, err, total(d))
	}

	// The old shape: every minute after every op.
	d2 := openIn(t, t.TempDir())
	if err := d2.Apply(ctx, Batch{Files: []FileOp{
		{Kind: OpUpsert, File: old.File, Flow: &old.Segment},
		del,
		{Kind: OpUpsert, File: cur.File, Flow: &cur.Segment},
	}, FlowMinutes: append(append([]FlowMinute(nil), old.Minutes...), cur.Minutes...)}); err != nil {
		t.Fatal(err)
	}
	if n := total(d2); n != 80 {
		t.Fatalf("old-shape minutes %d, want 80 (the drift this guards against)", n)
	}
	setRowsVersion(t, d2)
	res, err := d2.Reconcile(ctx, dataDir)
	if err != nil || res.Scanned != 1 || res.FlowRead != 1 || total(d2) != 30 {
		t.Fatalf("reconcile of drifted minutes %+v %v, minutes %d", res, err, total(d2))
	}
	if res, err := d2.Reconcile(ctx, dataDir); err != nil || res.Scanned != 0 {
		t.Fatalf("second reconcile %+v %v", res, err)
	}
}

// setRowsVersion marks d's flow rows as derived by this version's rules,
// as a Reconcile or Reindex under it leaves them.
func setRowsVersion(t *testing.T, d *DB) {
	t.Helper()
	if _, err := d.db.ExecContext(ctx, `INSERT INTO index_meta (key, value) VALUES (?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value`, metaFlowRowsVersion, FlowRowsVersion); err != nil {
		t.Fatal(err)
	}
}

// Kept rows are checked against their minutes: a closed segment whose
// flow_minute rows don't add up to its records or bytes is read. Rows
// without a files row are dropped. A different rows version (an upgrade, or
// a downgrade from a newer one) reads every footer once.
func TestReconcileChecksKeptFlowRows(t *testing.T) {
	dataDir := t.TempDir()
	h := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	writeSegment(t, dataDir, "10.1.0.1", h, 50, true)
	writeSegment(t, dataDir, "10.1.0.2", h, 30, true)
	d := openIn(t, t.TempDir())
	if _, err := d.Reindex(ctx, dataDir); err != nil {
		t.Fatal(err)
	}
	want := flowRowsDump(t, d)
	a := "logs/10.1.0.1/flows/" + flowseg.NameFor(h).String()

	// Records off (a minute doubled), then bytes off alone.
	for _, q := range []string{
		`UPDATE flow_minute SET records = records + 1 WHERE path = ? AND minute = (SELECT min(minute) FROM flow_minute WHERE path = ?)`,
		`UPDATE flow_minute SET bytes = bytes + 7 WHERE path = ? AND minute = (SELECT min(minute) FROM flow_minute WHERE path = ?)`,
		`DELETE FROM flow_minute WHERE path = ? AND minute = (SELECT max(minute) FROM flow_minute WHERE path = ?)`,
	} {
		if _, err := d.db.ExecContext(ctx, q, a, a); err != nil {
			t.Fatal(err)
		}
		if res, err := d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 1 || res.FlowRead != 1 || res.FlowRowsRebuilt {
			t.Fatalf("%s: reconcile %+v %v", q, res, err)
		}
		if got := flowRowsDump(t, d); got != want {
			t.Fatalf("%s: rows not restored\ngot:\n%s\nwant:\n%s", q, got, want)
		}
	}

	// Orphans: derived rows for a path with no files row.
	gone := "logs/10.1.0.9/flows/" + flowseg.NameFor(h).String()
	if err := d.Apply(ctx, Batch{FlowMinutes: []FlowMinute{{Path: gone, DeviceID: "10.1.0.9", Minute: h.UnixMilli(), Records: 4}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.ExecContext(ctx, `INSERT INTO flow_segments (path, device_id, start, end, records, bytes, packets, bytes_scaled,
		packets_scaled, scaled_complete, closed) VALUES (?, '10.1.0.8', 0, 0, 1, 1, 1, 1, 1, 1, 1)`, "logs/10.1.0.8/flows/x.wsf"); err != nil {
		t.Fatal(err)
	}
	res, err := d.Reconcile(ctx, dataDir)
	if err != nil || res.Scanned != 0 || res.FlowOrphans != 2 {
		t.Fatalf("orphans %+v %v", res, err)
	}
	if got := flowRowsDump(t, d); got != want {
		t.Fatalf("after dropping orphans\ngot:\n%s\nwant:\n%s", got, want)
	}

	// The rows version: unset (an index from a release candidate), older
	// or newer than this build's reads every footer once.
	for _, v := range []string{`DELETE FROM index_meta`, `UPDATE index_meta SET value = value + 1`} {
		if _, err := d.db.ExecContext(ctx, v); err != nil {
			t.Fatal(err)
		}
		res, err := d.Reconcile(ctx, dataDir)
		if err != nil || res.Scanned != 2 || res.FlowRead != 2 || !res.FlowRowsRebuilt {
			t.Fatalf("%s: reconcile %+v %v", v, res, err)
		}
		if got, err := d.metaInt(ctx, metaFlowRowsVersion); err != nil || got != FlowRowsVersion {
			t.Fatalf("version %d %v", got, err)
		}
		if res, err := d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 0 || res.FlowRowsRebuilt {
			t.Fatalf("%s: second reconcile %+v %v", v, res, err)
		}
		if got := flowRowsDump(t, d); got != want {
			t.Fatalf("%s: rows\ngot:\n%s\nwant:\n%s", v, got, want)
		}
	}
	// The covering index replaced flow_minute_path.
	var n int
	d.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name IN ('flow_minute_path_sums', 'flow_minute_path')`).Scan(&n)
	if n != 1 {
		t.Fatalf("indexes %d", n)
	}
	if v, _ := d.SchemaVersion(ctx); v != 9 {
		t.Fatalf("schema %d", v)
	}
}
