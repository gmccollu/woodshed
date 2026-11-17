package flow

import (
	"testing"
	"time"
)

func TestTimeOffsetLimits(t *testing.T) {
	rec := t0.UnixMilli()
	h := time.Hour.Milliseconds()
	for _, tc := range []struct {
		name          string
		start, end    int64
		src           TimeSource
		ahead, behind int64
	}{
		{"normal", rec - 60_000, rec - 1000, TimeExporter, 0, 0},
		{"just ahead, within the limit", rec, rec + h, TimeExporter, 0, 0},
		{"ahead", rec, rec + h + 1, TimeExporter, h + 1, 0},
		{"49.7 days ahead", rec + 4294967296 - 5000, rec + 4294967296, TimeExporter, 4294967296, 0},
		{"a day behind, within the limit", rec - 25*h, rec - 24*h, TimeExporter, 0, 0},
		{"behind", rec - 30*h, rec - 24*h - 1, TimeExporter, 0, 24*h + 1},
		{"a long connection: the start days back, the end now", rec - 72*h, rec - 1000, TimeExporter, 0, 0},
		{"on received time", rec + 5*h, rec + 5*h, TimeReceived, 0, 0},
	} {
		r := Record{Received: rec, Start: tc.start, End: tc.end, TimeSource: tc.src}
		if a, b := TimeOffset(&r); a != tc.ahead || b != tc.behind {
			t.Errorf("%s: ahead %d behind %d, want %d %d", tc.name, a, b, tc.ahead, tc.behind)
		}
	}
}

// Records ahead, behind and normal in one message: all three are emitted as
// sent (nothing dropped, no time changed), and the exporter's counts and
// largest offsets cover the last hour and the last 24 hours.
func TestTimeOffsetsCountedNeverDropped(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	b.Template(256, []TemplateField{{ID: ieStartMs, Length: 8}, {ID: ieEndMs, Length: 8}, {ID: ieOctetDelta, Length: 8}})
	at := t0.Add(time.Second)
	wrap := int64(1) << 32 // 49.7 days in ms: the uptime wrap
	times := [][2]int64{
		{t0.UnixMilli() - 30_000, t0.UnixMilli() - 1000},                           // normal
		{t0.UnixMilli() + wrap - 20_000, t0.UnixMilli() + wrap},                    // ahead
		{t0.Add(-50 * time.Hour).UnixMilli(), t0.Add(-49 * time.Hour).UnixMilli()}, // behind
	}
	for i, tt := range times {
		b.Data(256, Values{}.U64(uint64(tt[0])).U64(uint64(tt[1])).U64(uint64(100+i)))
	}
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, at)
	if len(s.recs) != 3 || len(s.raws) != 0 {
		t.Fatalf("%d records, %d raw sets", len(s.recs), len(s.raws))
	}
	for i, r := range s.recs {
		if r.Start != times[i][0] || r.End != times[i][1] || r.TimeSource != TimeExporter || r.Bytes != uint64(100+i) || r.Status != StatusOK {
			t.Errorf("record %d changed: %+v", i, r)
		}
	}
	wantAhead := t0.UnixMilli() + wrap - at.UnixMilli()
	wantBehind := at.UnixMilli() - t0.Add(-49*time.Hour).UnixMilli()
	want := TimeOffsets{Ahead: 1, Behind: 1, MaxAheadMs: wantAhead, MaxBehindMs: wantBehind}
	sum := func(now time.Time) ExporterStats {
		for _, st := range c.Stats(now) {
			if st.Addr == exp1.Addr() {
				return st
			}
		}
		t.Fatal("no stats")
		return ExporterStats{}
	}
	if st := sum(at); st.TimeOffsets1h != want || st.TimeOffsets24h != want || st.Counts.Records != 3 {
		t.Errorf("now: 1h %+v 24h %+v records %d, want %+v", st.TimeOffsets1h, st.TimeOffsets24h, st.Counts.Records, want)
	}
	if st := sum(at.Add(61 * time.Minute)); st.TimeOffsets1h.Any() || st.TimeOffsets24h != want {
		t.Errorf("an hour on: 1h %+v 24h %+v", st.TimeOffsets1h, st.TimeOffsets24h)
	}
	if st := sum(at.Add(25 * time.Hour)); st.TimeOffsets24h.Any() {
		t.Errorf("a day on: 24h %+v", st.TimeOffsets24h)
	}
	// More in the same 5 minutes add up; the largest offset stays the largest.
	b2 := NewBuilder(IPFIX)
	b2.Template(256, []TemplateField{{ID: ieStartMs, Length: 8}, {ID: ieEndMs, Length: 8}, {ID: ieOctetDelta, Length: 8}})
	for i := 0; i < 4; i++ {
		e := at.Add(2 * time.Hour).UnixMilli()
		b2.Data(256, Values{}.U64(uint64(e-1000)).U64(uint64(e)).U64(1))
	}
	s.decode(c, b2.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, at.Add(time.Minute))
	if st := sum(at.Add(time.Minute)); st.TimeOffsets1h.Ahead != 5 || st.TimeOffsets1h.MaxAheadMs != wantAhead || st.TimeOffsets1h.Behind != 1 {
		t.Errorf("after 4 more ahead: %+v", st.TimeOffsets1h)
	}
	if len(s.recs) != 7 {
		t.Errorf("%d records stored, want 7", len(s.recs))
	}
}

// v5 records (uptime-relative) are checked too, and a normal exporter never
// gets offset state; an exporter whose header clock is off is the clock
// rule's (its records go on received time), not this one's.
func TestTimeOffsetsV5AndClockRule(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	h := V5Header{SysUptime: 100000, UnixSecs: uint32(t0.Unix())}
	ahead := uint32(100000 + 3*3600*1000) // three hours past the header's uptime
	s.decode(c, EncodeV5(h, []V5Record{{Src: ip("10.0.0.1"), First: 90000, Last: 99000},
		{Src: ip("10.0.0.2"), First: ahead - 1000, Last: ahead}}), exp1, t0)
	if len(s.recs) != 2 || s.recs[1].End != t0.UnixMilli()+3*3600*1000 {
		t.Fatalf("records %+v", s.recs)
	}
	st := stats(t, c, exp1.Addr())
	if st.TimeOffsets24h.Ahead != 1 || st.TimeOffsets24h.MaxAheadMs != 3*3600*1000 || st.TimeOffsets24h.Behind != 0 {
		t.Errorf("v5 offsets %+v", st.TimeOffsets24h)
	}
	// exp2's header clock is three hours behind: received time, no offsets.
	h2 := V5Header{SysUptime: 100000, UnixSecs: uint32(t0.Add(-3 * time.Hour).Unix())}
	s.decode(c, EncodeV5(h2, []V5Record{{Src: ip("10.0.0.3"), First: 90000, Last: 99000}}), exp2, t0)
	st2 := stats(t, c, exp2.Addr())
	if st2.TimeSource != "received" || st2.TimeOffsets24h.Any() {
		t.Errorf("clock-rule exporter: %s %+v", st2.TimeSource, st2.TimeOffsets24h)
	}
	c.mu.RLock()
	off := c.exporters[exp2.Addr()].off
	c.mu.RUnlock()
	if off != nil {
		t.Error("offset state allocated for an exporter with none")
	}
}

// Data that waited for its template is checked against its own arrival time
// when it's decoded.
func TestTimeOffsetsLateRecords(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	fields := []TemplateField{{ID: ieStartMs, Length: 8}, {ID: ieEndMs, Length: 8}}
	e := t0.Add(5 * time.Hour).UnixMilli()
	b.Data(256, Values{}.U64(uint64(e-1000)).U64(uint64(e)))
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, t0)
	if len(s.recs) != 0 {
		t.Fatal("decoded without a template")
	}
	tb := NewBuilder(IPFIX)
	tb.Template(256, fields)
	s.decode(c, tb.Message(Header{ExportTime: uint32(t0.Unix()) + 30, Domain: 1, Seq: 1}), exp1, t0.Add(30*time.Second))
	if len(s.recs) != 1 || s.recs[0].Status != StatusLate || s.recs[0].End != e {
		t.Fatalf("late records %+v", s.recs)
	}
	st := stats(t, c, exp1.Addr())
	if st.TimeOffsets24h.Ahead != 1 || st.TimeOffsets24h.MaxAheadMs != 5*3600*1000 {
		t.Errorf("late offsets %+v", st.TimeOffsets24h)
	}
}
