package flowseg

import (
	"errors"
	"math/bits"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

func genRecords(seed uint64, n int, full bool) []flow.Record {
	r := rand.New(rand.NewPCG(seed, 1))
	out := make([]flow.Record, n)
	recv := testHour.UnixMilli() + 1000
	for i := range out {
		recv += int64(r.IntN(3))
		out[i] = randRecord(r, recv, full)
	}
	return out
}

func TestRoundTripEveryColumn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		full  bool
		n     int
		flush int
	}{{"full", true, 500, 97}, {"sparse", false, 3000, 0}, {"one", true, 1, 0}, {"big", false, MaxBlockRows + 10, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			recs := genRecords(7, tc.n, tc.full)
			// Every Has bit set somewhere.
			var has uint64
			for i := range recs {
				has |= recs[i].Has
			}
			if tc.full && has != uint64(ColOptional) {
				t.Fatalf("generator misses columns: %b", uint64(ColOptional)&^has)
			}
			path, wf := writeSegment(t, t.TempDir(), recs, nil, tc.flush)
			r, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got := readAll(t, r)
			if len(got) != len(recs) {
				t.Fatalf("read %d records, wrote %d", len(got), len(recs))
			}
			for i := range recs {
				sameRecord(t, recs[i], got[i], "record "+string(rune('0'+i%10)))
			}
			if !reflect.DeepEqual(wf.Totals, r.Footer().Totals) || wf.Totals.Records != int64(len(recs)) {
				t.Fatalf("totals: close %+v, open %+v", wf.Totals, r.Footer().Totals)
			}
			if r.Footer().DeviceID != "10.1.0.1" || !r.Footer().Hour.Equal(testHour) || r.Footer().WriterVersion != "2.0.0-test" {
				t.Fatalf("footer identity %+v", r.Footer())
			}
			if string(r.Meta()) != "meta-1" {
				t.Fatalf("meta %q", r.Meta())
			}
			if tc.name == "big" && r.Blocks() < 2 {
				t.Fatalf("%d blocks for %d rows", r.Blocks(), tc.n)
			}
		})
	}
}

func TestSelectedColumnsOnly(t *testing.T) {
	recs := genRecords(3, 2000, false)
	path, _ := writeSegment(t, t.TempDir(), recs, nil, 0)
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	cols := Cols(flow.HasSrc|flow.HasBytes) | ColSampling
	var b Block
	if err := r.Decode(0, cols, &b); err != nil {
		t.Fatal(err)
	}
	src, byt := b.Addr(flow.HasSrc), b.Uint(flow.HasBytes)
	for i := 0; i < b.Rows; i++ {
		w := normalize(recs[i])
		if b.Present(flow.HasSrc, i) != w.Is(flow.HasSrc) || src[i] != w.Src {
			t.Fatalf("row %d src %v/%v want %v", i, b.Present(flow.HasSrc, i), src[i], w.Src)
		}
		if b.Present(flow.HasBytes, i) != w.Is(flow.HasBytes) || byt[i] != w.Bytes {
			t.Fatalf("row %d bytes", i)
		}
		if b.Sampling()[i] != w.Sampling {
			t.Fatalf("row %d sampling", i)
		}
		var rec flow.Record
		b.Record(i, &rec)
		if rec.Has&^(flow.HasSrc|flow.HasBytes) != 0 || rec.Dst.IsValid() || rec.Received != 0 {
			t.Fatalf("row %d decoded more than asked: %+v", i, rec)
		}
	}
	// Reusing the Block for another block and column set.
	if err := r.Decode(0, ColReceived, &b); err != nil {
		t.Fatal(err)
	}
	if b.Present(flow.HasSrc, 0) || b.Received()[5] != recs[5].Received {
		t.Fatal("reused block kept old columns")
	}
}

// Totals and minutes recomputed from the records match the footer, and the
// writer's TakeMinutes deltas sum to the footer's minutes.
func TestTotalsAndMinutes(t *testing.T) {
	recs := genRecords(11, 5000, false)
	path := filepath.Join(t.TempDir(), "x.wsf")
	w, err := Create(path, "d", testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	taken := minuteAcc{}
	for i := range recs {
		if err := w.Append(&recs[i]); err != nil {
			t.Fatal(err)
		}
		if i%700 == 0 {
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			taken.merge(w.TakeMinutes())
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	taken.merge(w.TakeMinutes())
	f, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if len(w.TakeMinutes()) != 0 {
		t.Fatal("minutes left after the last take")
	}
	var want Totals
	wantMin := minuteAcc{}
	minS, maxE := int64(1<<62), int64(-1<<62)
	for i := range recs {
		addRecordTotals(&want, &recs[i])
		wantMin.addRecord(&recs[i])
		s, e := EffectiveTimes(&recs[i])
		minS, maxE = min(minS, s), max(maxE, e)
	}
	if want != f.Totals {
		t.Fatalf("totals %+v, want %+v", f.Totals, want)
	}
	if !reflect.DeepEqual(f.Minutes, wantMin.sorted()) || !reflect.DeepEqual(taken.sorted(), f.Minutes) {
		t.Fatal("minutes differ from a recount or from TakeMinutes")
	}
	if f.MinStart != minS || f.MaxEnd != maxE {
		t.Fatalf("flow range %d..%d, want %d..%d", f.MinStart, f.MaxEnd, minS, maxE)
	}
	var recSum int64
	for _, m := range f.Minutes {
		recSum += m.Records
	}
	if recSum != int64(len(recs)) {
		t.Fatalf("minutes count %d records", recSum)
	}
}

func TestMinuteSpread(t *testing.T) {
	m := minuteAcc{}
	base := testHour.UnixMilli()
	r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasBytes | flow.HasPackets, Start: base + 30000,
		End: base + 2*minuteMs + 1, Bytes: 10, Packets: 3, Sampling: 100}
	m.addRecord(&r)
	got := m.sorted()
	if len(got) != 3 {
		t.Fatalf("%d minutes", len(got))
	}
	if got[0].Bytes != 3 || got[1].Bytes != 3 || got[2].Bytes != 4 || got[2].Records != 1 || got[0].Records != 0 {
		t.Fatalf("spread %+v", got)
	}
	if got[2].ScaledBytes != 334 || got[0].ScaledBytes != 333 || got[2].Packets != 1 {
		t.Fatalf("scaled %+v", got)
	}
	// A denied event with only totals adds no bytes; an over-long flow is clamped.
	m = minuteAcc{}
	r = flow.Record{Has: flow.HasEnd | flow.HasStart | flow.HasBytes | flow.HasTotals | flow.HasFwEvent,
		FwEvent: flow.FwCreated, Start: base - 10*3600000, End: base, Bytes: 99}
	m.addRecord(&r)
	if got := m.sorted(); len(got) != 1 || got[0].Bytes != 0 || got[0].Records != 1 || got[0].UnknownSampling != 1 {
		t.Fatalf("created event %+v", got)
	}
	m = minuteAcc{}
	r.FwEvent = flow.FwDeleted
	m.addRecord(&r)
	if got := m.sorted(); len(got) != MaxSpreadMinutes || got[len(got)-1].Minute != base {
		t.Fatalf("clamp: %d minutes", len(got))
	}
}

func TestEffectiveTimes(t *testing.T) {
	for _, tc := range []struct {
		r          flow.Record
		start, end int64
	}{
		{flow.Record{Received: 9}, 9, 9},
		{flow.Record{Has: flow.HasEventTime, EventTime: 5, Received: 9}, 5, 5},
		{flow.Record{Has: flow.HasEnd | flow.HasStart, Start: 1, End: 4, Received: 9}, 1, 4},
		{flow.Record{Has: flow.HasEnd | flow.HasStart, Start: 7, End: 4}, 4, 4},
		{flow.Record{Has: flow.HasStart, Start: 3, Received: 9}, 3, 9},
	} {
		if s, e := EffectiveTimes(&tc.r); s != tc.start || e != tc.end {
			t.Errorf("%+v: %d..%d, want %d..%d", tc.r, s, e, tc.start, tc.end)
		}
	}
}

func TestRawSetsAndTemplates(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 5))
	recs := genRecords(5, 50, true)
	raws := make([]flow.RawSet, 30)
	for i := range raws {
		raws[i] = randRaw(r, testHour.UnixMilli()+int64(i))
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "s.wsf")
	w, err := Create(path, "d", testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	extra := &flow.Template{Version: flow.IPFIX, ID: 999, Domain: 1, ExporterPort: 40000,
		Fields: []flow.TemplateField{{ID: 7, Length: 2}}}
	w.AddTemplate(extra)
	w.AddTemplate(extra)
	// A copy of a template already in the table interns to the same entry.
	cp := *testTemplates[0]
	recs[0].Template = &cp
	for i := range recs {
		w.Append(&recs[i])
		if i < len(raws) {
			w.AppendRaw(&raws[i])
		}
		if i == 10 {
			w.Flush()
		}
	}
	f, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if f.Raw != 30 || f.RawStatus[flow.StatusNoTemplate]+f.RawStatus[flow.StatusMalformed] != 30 {
		t.Fatalf("raw counts %d %v", f.Raw, f.RawStatus)
	}
	rd, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	var got []flow.RawSet
	if err := rd.Raw(func(rs *flow.RawSet) bool { got = append(got, *rs); return true }); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(raws) {
		t.Fatalf("%d raw sets", len(got))
	}
	for i := range raws {
		if !sameRaw(raws[i], got[i]) {
			t.Fatalf("raw %d: %+v, want %+v", i, got[i], raws[i])
		}
	}
	n := 0
	rd.Raw(func(*flow.RawSet) bool { n++; return n < 3 })
	if n != 3 {
		t.Fatalf("Raw didn't stop: %d", n)
	}
	keys := map[string]bool{}
	for _, tm := range rd.Templates() {
		keys[templateKey(tm)] = true
	}
	if len(rd.Templates()) != 3 || !keys[templateKey(extra)] || !keys[templateKey(testTemplates[1])] {
		t.Fatalf("templates %d", len(rd.Templates()))
	}
}

// A writer's snapshot reads the blocks written so far, while it keeps
// writing.
func TestSnapshotReadsLiveSegment(t *testing.T) {
	recs := genRecords(9, 3000, false)
	path := filepath.Join(t.TempDir(), "live.wsf")
	w, err := Create(path, "d", testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		w.Append(&recs[i])
	}
	w.Flush()
	for i := 1000; i < 1500; i++ {
		w.Append(&recs[i]) // open block: not in the snapshot
	}
	snap := w.Snapshot()
	if _, err := Open(path); !errors.Is(err, ErrNoFooter) {
		t.Fatalf("Open of a live segment: %v", err)
	}
	r, err := OpenSnapshot(path, snap)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if snap.Totals.Records != 1000 || r.Blocks() != 1 {
		t.Fatalf("snapshot %d records, %d blocks", snap.Totals.Records, r.Blocks())
	}
	bi, err := r.Block(0)
	if err != nil {
		t.Fatal(err)
	}
	if !bi.MayHaveAddr(normalize(recs[0]).Src) && recs[0].Is(flow.HasSrc) {
		t.Fatal("lazy index misses a source")
	}
	for i := 1500; i < 3000; i++ {
		w.Append(&recs[i])
		if i%300 == 0 {
			w.Flush()
		}
	}
	got := readAll(t, r)
	for i := range got {
		sameRecord(t, recs[i], got[i], "live")
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, r); len(got) != 1000 {
		t.Fatalf("after close the snapshot reader still reads its own blocks: %d", len(got))
	}
}

func TestWriterErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "e.wsf")
	w, err := Create(path, "d", testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, "d", testHour, "v"); err == nil {
		t.Fatal("Create over an existing segment")
	}
	f, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !f.Empty() || len(f.Blocks) != 0 {
		t.Fatalf("empty segment footer %+v", f)
	}
	if err := w.Append(&flow.Record{}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := w.Close(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	os.WriteFile(filepath.Join(dir, "junk.wsf"), []byte("not a segment at all, no"), 0o600)
	if _, err := Open(filepath.Join(dir, "junk.wsf")); !errors.Is(err, ErrBadHeader) {
		t.Fatal(err)
	}
	if _, err := Recover(filepath.Join(dir, "junk.wsf")); !errors.Is(err, ErrBadHeader) {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "junk.wsf")); len(b) == 0 {
		t.Fatal("recover changed a non-segment")
	}
}

// An invalid address with its bit set is stored as absent; a long device ID
// is kept whole.
func TestInvalidAddressAndLongID(t *testing.T) {
	id := ""
	for len(id) < 300 {
		id += "2001_db8__1_"
	}
	path := filepath.Join(t.TempDir(), "a.wsf")
	w, err := Create(path, id, testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	rec := flow.Record{Has: flow.HasSrc | flow.HasDst, Dst: netip.MustParseAddr("::ffff:192.0.2.1"), Received: 5}
	w.Append(&rec)
	w.Close()
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got := readAll(t, r)
	if got[0].Has != flow.HasDst || got[0].Dst != netip.MustParseAddr("192.0.2.1") || r.Footer().DeviceID != id {
		t.Fatalf("%+v %q", got[0], r.Footer().DeviceID)
	}
}

func TestNames(t *testing.T) {
	for _, s := range []string{"2026-11-16T09.wsf", "2026-11-16T00.001.wsf", "2026-11-16T23.999.wsf", "2026-11-16T23.1000.wsf"} {
		n, ok := ParseName(s)
		if !ok || n.String() != s {
			t.Errorf("%s: %+v %v", s, n, ok)
		}
	}
	for _, s := range []string{"2026-11-16T24.wsf", "2026-11-16.log", "2026-11-16T09.000.wsf", "2026-11-16T09.1.wsf",
		"2026-13-16T09.wsf", "2026-11-16T9.wsf", "2026-11-16T09.wsf.tmp", "2026-11-16T-1.wsf", "2026-11-16T09.0001.wsf", "2026-11-16T09.+12.wsf"} {
		if _, ok := ParseName(s); ok {
			t.Errorf("%s parsed", s)
		}
	}
	n := NameFor(time.Date(2026, 11, 16, 9, 59, 0, 0, time.UTC))
	if n.String() != "2026-11-16T09.wsf" || !n.Time().Equal(testHour) {
		t.Fatal(n)
	}
	a, b := Name{Day: "2026-11-16", Hour: 9, Part: 1}, Name{Day: "2026-11-16", Hour: 10}
	if !a.Less(b) || b.Less(a) {
		t.Fatal("order")
	}
}

func TestBlockSplitsOnOneSecond(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wsf")
	w, _ := Create(path, "d", testHour, "v")
	base := testHour.UnixMilli()
	for _, at := range []int64{0, 500, 999, 1000, 400 /* late: older received, same block */, 2500} {
		w.Append(&flow.Record{Received: base + at})
	}
	f, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	var rows []int
	for _, b := range f.Blocks {
		rows = append(rows, b.Rows)
	}
	if !slices.Equal(rows, []int{3, 2, 1}) {
		t.Fatalf("blocks %v", rows)
	}
}

// Size grows with appends, and OpenBytes falls to 0 on flush.
func TestSizeAndOpenBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.wsf")
	w, _ := Create(path, "d", testHour, "v")
	s0 := w.Size()
	recs := genRecords(1, 100, true)
	for i := range recs {
		recs[i].Received = testHour.UnixMilli()
		w.Append(&recs[i])
	}
	if w.Size() <= s0 || w.OpenBytes() < 100*recordSize || w.Rows() != 100 {
		t.Fatalf("size %d open %d rows %d", w.Size(), w.OpenBytes(), w.Rows())
	}
	w.Flush()
	st, _ := os.Stat(path)
	if w.OpenBytes() != 0 || w.Size() != st.Size() {
		t.Fatalf("after flush: open %d size %d file %d", w.OpenBytes(), w.Size(), st.Size())
	}
	w.Close()
}

func TestColsCover(t *testing.T) {
	if bits.OnesCount64(uint64(ColOptional)) != bits.TrailingZeros64(flow.HasTotals)+1 {
		t.Fatal("ColOptional")
	}
	if ColOptional&(ColReceived|ColExtras) != 0 || bitID(ColExtras) >= colDict {
		t.Fatal("bits overlap")
	}
}
