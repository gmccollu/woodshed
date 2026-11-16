package store

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

func flowRecs(at time.Time, n, seq int) []*flow.Record {
	out := make([]*flow.Record, n)
	for i := range out {
		ms := at.UnixMilli()
		out[i] = &flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasPackets | flow.HasProto,
			Received: ms, Start: ms - 2000, End: ms, Src: netip.AddrFrom4([4]byte{10, 0, byte(seq >> 8), byte(seq)}),
			Dst: netip.MustParseAddr("198.51.100.7"), Bytes: uint64(100 + i), Packets: 1, Proto: 6, Sampling: 1,
			SrcAS: uint32(seq + i)}
	}
	return out
}

func (e *env) writeFlows(addr netip.Addr, n, seq int) {
	e.t.Helper()
	if err := e.s.WriteFlows(addr, FlowBatch{Received: e.clock.Now(), Size: 1400, Records: flowRecs(e.clock.Now(), n, seq)}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) flowFiles(addr netip.Addr) []string {
	ents, _ := os.ReadDir(filepath.Join(e.dir, logfile.LogsDir, addr.String(), logfile.FlowDir))
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	sort.Strings(out)
	return out
}

// Flows go to one segment per device per received hour; the index gets the
// files, flow_segments and flow_minute rows as blocks are written, and the
// device row and type_stats like any type.
func TestWriteFlowsSegmentsAndIndex(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(7)
	h := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	e.clock.Set(h.Add(10 * time.Minute))
	e.writeFlows(a, 30, 0)
	e.clock.Add(time.Second)
	e.writeFlows(a, 20, 100)
	e.maintain()
	if got := e.flowFiles(a); len(got) != 1 || got[0] != "2026-11-10T12.wsf" {
		t.Fatalf("files %v", got)
	}
	segs, err := e.idx.AllFlowSegments(bg)
	if err != nil || len(segs) != 1 || segs[0].Records != 50 || segs[0].Closed {
		t.Fatalf("segments %+v %v", segs, err)
	}
	tot, _ := e.idx.FlowDeviceTotals(bg, nil, h.UnixMilli(), h.Add(time.Hour).UnixMilli())
	if tot["192.0.2.7"].Records != 50 {
		t.Fatalf("minutes %+v", tot)
	}
	dev, err := e.idx.Device(bg, "192.0.2.7")
	if err != nil || dev.TotalMsgs != 50 {
		t.Fatalf("device %+v %v", dev, err)
	}
	// The hour ends: the segment closes, and the next records start the next hour's.
	e.clock.Set(h.Add(time.Hour + time.Second))
	e.maintain()
	segs, _ = e.idx.AllFlowSegments(bg)
	if len(segs) != 1 || !segs[0].Closed {
		t.Fatalf("closed %+v", segs)
	}
	e.writeFlows(a, 5, 200)
	e.maintain()
	if got := e.flowFiles(a); len(got) != 2 || got[1] != "2026-11-10T13.wsf" {
		t.Fatalf("files %v", got)
	}
	r, err := flowseg.Open(filepath.Join(e.dir, "logs/192.0.2.7/flows/2026-11-10T12.wsf"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Footer().Totals.Records != 50 || r.Footer().DeviceID != "192.0.2.7" {
		t.Fatalf("footer %+v", r.Footer().Totals)
	}
	// Close writes the open segment's footer; a reopen starts a new part.
	e.reopen()
	e.writeFlows(a, 1, 300)
	e.maintain()
	if got := e.flowFiles(a); len(got) != 3 || got[1] != "2026-11-10T13.001.wsf" {
		t.Fatalf("after reopen %v", got)
	}
	if err := e.s.WriteFlows(netip.Addr{}, FlowBatch{}); err != ErrInvalidSender {
		t.Fatalf("invalid sender: %v", err)
	}
}

// A crash leaves the open segment without a footer: the next start keeps its
// complete blocks, writes the footer, records the cut, and indexes it.
func TestFlowCrashRecovery(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(8)
	e.writeFlows(a, 40, 0)
	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	e.writeFlows(a, 10, 50) // in the open block only: lost in the crash
	seg := filepath.Join(e.dir, "logs/192.0.2.8/flows/2026-11-10T12.wsf")
	// Simulate the crash on a copy of the data folder: the process's open
	// writer can't be stopped without writing its footer.
	crashed := t.TempDir()
	b, err := os.ReadFile(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(crashed, "logs/192.0.2.8/flows"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(crashed, "logs/192.0.2.8/flows/2026-11-10T12.wsf"), append(b, 1, 2, 3), 0o640); err != nil {
		t.Fatal(err)
	}
	idx, err := index.Open(filepath.Join(crashed, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	s2, err := Open(Options{DataDir: crashed, Index: idx, Clock: e.clock.Now, DiskUsage: e.disk.usage, Manual: true, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if err := s2.Maintain(); err != nil {
		t.Fatal(err)
	}
	segs, _ := idx.AllFlowSegments(bg)
	if len(segs) != 1 || segs[0].Records != 40 || !segs[0].Closed {
		t.Fatalf("recovered %+v", segs)
	}
	evs, _ := idx.Events(bg, time.Time{}, time.Time{}, 100)
	found := false
	for _, ev := range evs {
		found = found || (ev.Kind == index.KindRecover && ev.DeviceID == "192.0.2.8")
	}
	if !found {
		t.Fatalf("no recover event: %+v", evs)
	}
	// The exporter writes on: a new part, the recovered segment untouched.
	if err := s2.WriteFlows(a, FlowBatch{Received: e.clock.Now(), Records: flowRecs(e.clock.Now(), 3, 900)}); err != nil {
		t.Fatal(err)
	}
	s2.Maintain()
	segs, _ = idx.AllFlowSegments(bg)
	if len(segs) != 2 {
		t.Fatalf("after recovery %+v", segs)
	}
}

// The flow budget: past it the oldest flow segments go, never the current or
// previous hour, and syslog is untouched; the other types share the cap less
// what flows hold.
func TestFlowBudget(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RetentionBytes = 50 << 20; o.FlowBudgetBytes = 1 })
	a := ip(9)
	start := time.Date(2026, 11, 10, 0, 30, 0, 0, time.UTC)
	for h := 0; h < 6; h++ {
		e.clock.Set(start.Add(time.Duration(h) * time.Hour))
		e.write(a, fmt.Sprintf("syslog %d", h))
		e.writeFlows(a, 200, h*1000)
		e.maintain()
	}
	// The budget is 1 byte: everything but this hour and the last goes.
	got := e.flowFiles(a)
	if len(got) != 2 || got[0] != "2026-11-10T04.wsf" || got[1] != "2026-11-10T05.wsf" {
		t.Fatalf("flow files %v", got)
	}
	if lines := readLines(t, e.dir, "192.0.2.9"); len(lines) != 6 {
		t.Fatalf("syslog touched: %d lines", len(lines))
	}
	segs, _ := e.idx.AllFlowSegments(bg)
	if len(segs) != 2 {
		t.Fatalf("index %+v", segs)
	}
	dels, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 100)
	n := 0
	for _, d := range dels {
		if d.Type == index.TypeFlow && d.Reason == index.ReasonCap {
			n++
		}
	}
	if n != 4 {
		t.Fatalf("flow deletions %d: %+v", n, dels)
	}
	if b := e.s.FlowBudget(); b != 1 {
		t.Fatalf("budget %d", b)
	}
	e.s.SetLimits(Limits{FlowBudgetBytes: -1})
	if b := e.s.FlowBudget(); b != (50<<20)*40/100 {
		t.Fatalf("default budget %d", b)
	}
}

// Low disk: closed flow segments go first, before any other type.
func TestFlowLowDiskFirst(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(10)
	start := time.Date(2026, 11, 10, 0, 30, 0, 0, time.UTC)
	for h := 0; h < 3; h++ {
		e.clock.Set(start.Add(time.Duration(h) * time.Hour))
		e.write(a, fmt.Sprintf("syslog %d", h))
		e.writeFlows(a, 500, h*1000)
		e.maintain()
	}
	free := e.disk.total - uint64(duLogs(e.dir))
	// Leave the disk a little short of the reserve: deleting flows is enough.
	e.disk.setOther(free - (1 << 30) + 1000)
	e.maintain()
	if got := e.flowFiles(a); len(got) != 1 || got[0] != "2026-11-10T02.wsf" {
		t.Fatalf("flow files %v", got)
	}
	if lines := readLines(t, e.dir, "192.0.2.10"); len(lines) != 3 {
		t.Fatalf("syslog touched: %d lines", len(lines))
	}
}

// The exporter's metadata blob goes into every segment it writes: the one
// open when it changed, and the next hour's, without being sent again.
func TestFlowMetadataInEverySegment(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(11)
	h := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	e.clock.Set(h.Add(10 * time.Minute))
	meta := []byte(`{"scopes":[{"domain":1,"sampling":100}]}`)
	if err := e.s.WriteFlows(a, FlowBatch{Received: e.clock.Now(), Records: flowRecs(e.clock.Now(), 3, 0), Meta: meta}); err != nil {
		t.Fatal(err)
	}
	e.clock.Set(h.Add(time.Hour + time.Minute))
	e.maintain() // the hour ends: the first segment closes
	e.writeFlows(a, 2, 100)
	e.reopen() // closes the second
	for _, name := range []string{"2026-11-10T12.wsf", "2026-11-10T13.wsf"} {
		r, err := flowseg.Open(filepath.Join(e.dir, "logs/192.0.2.11/flows", name))
		if err != nil {
			t.Fatal(err)
		}
		got := string(r.Meta())
		r.Close()
		if got != string(meta) {
			t.Fatalf("%s: meta %q", name, got)
		}
	}
}
