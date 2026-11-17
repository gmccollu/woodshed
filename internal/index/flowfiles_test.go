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
