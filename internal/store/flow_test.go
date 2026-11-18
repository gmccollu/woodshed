package store

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
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

// The collector's counts go to type_stats with the batch they came with
// (SPEC §13.10 decision 82): sequence gaps, duplicates, late records, raw
// sets by status and times off arrival, also from a batch with nothing to
// store (which opens no segment); they survive
// a restart of the store.
func TestFlowCountsStored(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(8)
	h := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	e.clock.Set(h.Add(10 * time.Minute))
	recs := flowRecs(e.clock.Now(), 3, 0)
	recs[0].Status = flow.StatusLate
	recs[1].End = recs[1].Received + 2*time.Hour.Milliseconds() // ahead
	raws := []*flow.RawSet{{Received: recs[0].Received, Exporter: a, Status: flow.StatusNoTemplate, Data: []byte{1}},
		{Received: recs[0].Received, Exporter: a, Status: flow.StatusMalformed, Data: []byte{2}}}
	if err := e.s.WriteFlows(a, FlowBatch{Received: e.clock.Now(), Size: 900, Records: recs, Raw: raws, SeqGaps: 2, SeqLost: 60, Duplicates: 1}); err != nil {
		t.Fatal(err)
	}
	e.clock.Add(time.Minute)
	if err := e.s.WriteFlows(ip(9), FlowBatch{Received: e.clock.Now(), SeqGaps: 1, SeqLost: 30}); err != nil {
		t.Fatal(err)
	}
	e.maintain()
	if got := e.flowFiles(ip(9)); len(got) != 0 {
		t.Fatalf("a counts-only batch opened %v", got)
	}
	e.reopen()
	w, err := e.idx.FlowCountsIn(bg, "192.0.2.8", h, h.Add(time.Hour), time.Time{})
	if err != nil || !w.Known || w.SeqGaps != 2 || w.SeqLost != 60 || w.Duplicates != 1 || w.Late != 1 || w.NoTemplate != 1 ||
		w.Malformed != 1 || w.Ahead != 1 || w.MaxAheadMs != 2*time.Hour.Milliseconds() || w.Records != 3 {
		t.Fatalf("counts %+v %v", w, err)
	}
	if w, _ := e.idx.FlowCountsIn(bg, "192.0.2.9", h, h.Add(time.Hour), time.Time{}); !w.Known || w.SeqGaps != 1 || w.Records != 0 {
		t.Fatalf("counts only %+v", w)
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
		if d.Type != index.TypeFlow || d.Reason != index.ReasonFlowBudget {
			t.Fatalf("deletion %+v: want a flow-budget flow deletion", d)
		}
		n++
	}
	if n != 4 {
		t.Fatalf("flow deletions %d: %+v", n, dels)
	}
	// The events name the flow budget, never the storage cap: one per segment
	// and one per budget pass that deleted any.
	size := `(?:\d+ B|\d+\.\d [KMGTPE]iB)`
	passRe := regexp.MustCompile(`^flows over their budget \(` + size + ` of 1 B\): deleted (\d+) oldest flow segments? \(` + size + `\)$`)
	perSeg, inPasses := 0, 0
	for _, ev := range eventsOf(t, e.idx, index.KindDelete) {
		switch {
		case strings.Contains(ev.Text, "storage cap"):
			t.Fatalf("flow budget event says storage cap: %q", ev.Text)
		case strings.HasPrefix(ev.Text, "deleted logs/192.0.2.9/flows/") && strings.Contains(ev.Text, "(flows over their budget, "):
			perSeg++
		case passRe.MatchString(ev.Text):
			k, _ := strconv.Atoi(passRe.FindStringSubmatch(ev.Text)[1])
			inPasses += k
		default:
			t.Fatalf("unexpected delete event %q", ev.Text)
		}
	}
	if perSeg != 4 || inPasses != 4 {
		t.Fatalf("per-segment events %d, segments in pass events %d", perSeg, inPasses)
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

// A segment starts a numbered part at the block limit, and every record is
// still found: once in the parts' blocks, and in the index rows, kept and
// rebuilt by a reindex.
func TestFlowPartAtBlockLimit(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.FlowPartBlocks = 10 })
	a := ip(9)
	h := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	e.clock.Set(h.Add(time.Minute))
	const batches, per = 35, 4 // one block each
	for i := 0; i < batches; i++ {
		e.writeFlows(a, per, i*per)
		if err := e.s.Flush(); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Second)
	}
	e.maintain()
	got := e.flowFiles(a)
	want := []string{"2026-11-10T12.001.wsf", "2026-11-10T12.002.wsf", "2026-11-10T12.003.wsf", "2026-11-10T12.wsf"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("files %v, want %v", got, want)
	}
	seen := map[string]int{} // a record's batch is in its source address, its place in the batch in its bytes
	for _, name := range got {
		path := filepath.Join(e.dir, "logs/192.0.2.9/flows", name)
		r, err := flowseg.Open(path)
		if name == "2026-11-10T12.003.wsf" {
			// The open part: read as the CLI would, beside the writer.
			if err == nil {
				t.Fatal("the open part has a footer")
			}
			r, err = flowseg.OpenLive(path)
		}
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if wantBlocks := map[bool]int{true: 5, false: 10}[name == "2026-11-10T12.003.wsf"]; r.Blocks() != wantBlocks {
			t.Fatalf("%s: %d blocks, want %d", name, r.Blocks(), wantBlocks)
		}
		for i := 0; i < r.Blocks(); i++ {
			recs, err := r.ReadBlock(i, flowseg.ColAll, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, rec := range recs {
				seen[fmt.Sprint(rec.Src, rec.Bytes)]++
			}
		}
		r.Close()
	}
	for i := 0; i < batches*per; i++ {
		seq := i / per * per
		k := fmt.Sprint(netip.AddrFrom4([4]byte{10, 0, byte(seq >> 8), byte(seq)}), 100+i%per)
		if seen[k] != 1 {
			t.Fatalf("record %d (%s) read %d times", i, k, seen[k])
		}
	}
	if len(seen) != batches*per {
		t.Fatalf("%d records, want %d", len(seen), batches*per)
	}
	segs, err := e.idx.AllFlowSegments(bg)
	if err != nil {
		t.Fatal(err)
	}
	var recs int64
	closed := 0
	for _, sg := range segs {
		recs += sg.Records
		if sg.Closed {
			closed++
		}
	}
	if len(segs) != 4 || closed != 3 || recs != batches*per {
		t.Fatalf("index: %d segments (%d closed), %d records", len(segs), closed, recs)
	}
	tot, _ := e.idx.FlowDeviceTotals(bg, nil, h.UnixMilli(), h.Add(time.Hour).UnixMilli())
	if tot["192.0.2.9"].Records != batches*per {
		t.Fatalf("minutes %+v", tot)
	}
	// A reindex after the store has closed (the open part with it) lists
	// every part again.
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	e.s = nil
	if _, err := e.idx.Reindex(bg, e.dir); err != nil {
		t.Fatal(err)
	}
	segs, err = e.idx.AllFlowSegments(bg)
	if err != nil {
		t.Fatal(err)
	}
	recs, closed = 0, 0
	for _, sg := range segs {
		recs += sg.Records
		if sg.Closed {
			closed++
		}
	}
	if len(segs) != 4 || closed != 4 || recs != batches*per {
		t.Fatalf("after a reindex: %d segments (%d closed), %d records", len(segs), closed, recs)
	}
}

// At the real limit, an hour of one-second blocks (and some early flushes)
// stays one segment. (The flushes skip the index's commit, which only costs
// time here.)
func TestFlowHourOfBlocksIsOnePart(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(10)
	h := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	e.clock.Set(h)
	n := 0
	for sec := 0; sec < 3600; sec++ {
		e.writeFlows(a, 2, n)
		n += 2
		if sec%4 == 0 { // an extra block every few seconds
			if err := e.s.flushFlows(e.clock.Now(), false); err != nil {
				t.Fatal(err)
			}
			e.writeFlows(a, 1, n)
			n++
		}
		if err := e.s.flushFlows(e.clock.Now(), false); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Second)
	}
	e.maintain() // the hour has ended: the segment closes
	if got := e.flowFiles(a); len(got) != 1 || got[0] != "2026-11-10T12.wsf" {
		t.Fatalf("files %v", got)
	}
	r, err := flowseg.Open(filepath.Join(e.dir, "logs/192.0.2.10/flows/2026-11-10T12.wsf"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.Blocks() != 4500 || r.Footer().Totals.Records != int64(n) {
		t.Fatalf("%d blocks, %d records (want 4,500, %d)", r.Blocks(), r.Footer().Totals.Records, n)
	}
}

// Over many exporters the writers' directories stay under FlowDirBudget:
// the maintenance pass closes the segments keeping the most, so their
// exporters go on in new parts, and every record is still read exactly
// once (in the parts' blocks, the index, a reindex and a query). The
// budget here is a third of what the run's directories would take
// uncapped, so every exporter rolls at least once. Under the race detector
// (where the heap ceiling doesn't apply) it runs at the short size unless
// WOODSHED_LONG_TESTS=1: the full 180,000 flushes took 222 s of the
// package's 370 there on a laptop, and CI's -race run of the package
// passed its 20-minute timeout (run 44038809604).
func TestFlowDirBudget(t *testing.T) {
	exporters, seconds := 300, 600
	if testing.Short() || (raceEnabled && os.Getenv("WOODSHED_LONG_TESTS") != "1") {
		exporters, seconds = 60, 240
	}
	budget := int64(exporters) * int64(seconds/3) * flowseg.DirEntryBytes
	e := newEnv(t, func(o *Options) { o.FlowDirBudget = budget })
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 18, byte(i / 250), byte(i%250 + 1)}) }
	h := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	e.clock.Set(h)
	seq := make([]int, exporters)
	live0 := heapLiveStore()
	maxDir := int64(0)
	for sec := 0; sec < seconds; sec++ {
		for i := 0; i < exporters; i++ {
			e.writeFlows(addr(i), 2, seq[i])
			seq[i] += 2
		}
		if err := e.s.flushFlows(e.clock.Now(), false); err != nil {
			t.Fatal(err)
		}
		// One block an exporter past the budget at most, between passes.
		maxDir = max(maxDir, e.s.FlowDirBytes())
		if d := e.s.FlowDirBytes(); d > budget+int64(exporters)*flowseg.DirEntryBytes {
			t.Fatalf("second %d: the writers keep %d bytes, budget %d", sec, d, budget)
		}
		if sec%60 == 59 {
			e.maintain()
		}
		e.clock.Add(time.Second)
	}
	e.maintain()
	grown := int64(heapLiveStore()) - int64(live0)
	early := e.s.Usage().FlowPartsEarly
	t.Logf("%d exporters, %d s: %d early parts (%.1f an exporter), the writers kept at most %.2f MiB (budget %.2f MiB), "+
		"live heap grew %.1f MiB", exporters, seconds, early, float64(early)/float64(exporters), float64(maxDir)/(1<<20),
		float64(budget)/(1<<20), float64(grown)/(1<<20))
	if early < int64(exporters) || early > int64(4*exporters) {
		t.Fatalf("%d early parts for %d exporters", early, exporters)
	}
	// Live: the capped directories and every stream's writer and open
	// block, under the uncapped directories' 3 times the budget (the race
	// detector's build allocates differently).
	if lim := budget + int64(exporters)*24<<10 + 16<<20; !raceEnabled && grown > lim {
		t.Fatalf("live heap grew %d bytes, ceiling %d", grown, lim)
	}

	want := exporters * seconds * 2
	nfiles := 0
	count := func(what string, files func(i int) []string) {
		t.Helper()
		got := 0
		for i := 0; i < exporters; i++ {
			nfiles += len(files(i))
			seen := map[string]int{} // a record's batch is in its source address, its place in the batch in its bytes
			for _, name := range files(i) {
				path := filepath.Join(e.dir, "logs", addr(i).String(), "flows", name)
				r, err := flowseg.Open(path)
				if errors.Is(err, flowseg.ErrNoFooter) {
					r, err = flowseg.OpenLive(path) // the open part
				}
				if err != nil {
					t.Fatalf("%s: %s: %v", what, name, err)
				}
				for b := 0; b < r.Blocks(); b++ {
					recs, err := r.ReadBlock(b, flowseg.ColAll, nil)
					if err != nil {
						t.Fatal(err)
					}
					for _, rec := range recs {
						seen[fmt.Sprint(rec.Src, rec.Bytes)]++
					}
				}
				r.Close()
			}
			for k, n := range seen {
				if n != 1 {
					t.Fatalf("%s: exporter %d's record %s read %d times", what, i, k, n)
				}
			}
			if len(seen) != seconds*2 {
				t.Fatalf("%s: exporter %d: %d records, want %d", what, i, len(seen), seconds*2)
			}
			got += len(seen)
		}
		if got != want {
			t.Fatalf("%s: %d records, want %d", what, got, want)
		}
	}
	count("the files", func(i int) []string { return e.flowFiles(addr(i)) })
	indexed := func(what string) {
		t.Helper()
		segs, err := e.idx.AllFlowSegments(bg)
		if err != nil {
			t.Fatal(err)
		}
		var recs int64
		for _, sg := range segs {
			recs += sg.Records
		}
		if recs != int64(want) || len(segs) != nfiles || int64(nfiles) < int64(exporters)+early-1 {
			t.Fatalf("%s: %d segments, %d files (early parts %d), %d records", what, len(segs), nfiles, early, recs)
		}
	}
	indexed("the index")
	q := flowquery.Query{From: h.Add(-time.Minute), To: h.Add(time.Hour)}
	eng := flowquery.New(flowquery.Options{DataDir: e.dir, Index: e.idx, Open: func(ids []string) []flowquery.OpenSegment {
		var out []flowquery.OpenSegment
		for _, s := range e.s.OpenFlowList(ids) {
			out = append(out, flowquery.OpenSegment{DeviceID: s.DeviceID, Rel: s.Rel, Path: s.Path, Snap: s.Snap})
		}
		return out
	}})
	n, err := eng.Count(bg, q)
	var c int64
	for _, v := range n {
		c += v
	}
	if err != nil || c != int64(want) || len(n) != exporters {
		t.Fatalf("query: %d records over %d exporters (want %d): %v", c, len(n), want, err)
	}
	// A reindex after the store has closed finds the same parts.
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	e.s = nil
	if _, err := e.idx.Reindex(bg, e.dir); err != nil {
		t.Fatal(err)
	}
	indexed("after a reindex")
}

// heapLiveStore is the live heap: objects after two collections (the second
// frees sync.Pool's victims, which vary with the number of Ps).
func heapLiveStore() uint64 {
	runtime.GC()
	runtime.GC()
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}
