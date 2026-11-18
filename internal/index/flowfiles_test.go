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
