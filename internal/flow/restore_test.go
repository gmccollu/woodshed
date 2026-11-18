package flow

import (
	"math"
	"testing"
	"time"
)

// Restore (SPEC §13.10 decision 83): a restarted collector gets an exporter's
// 24-hour counts and times off arrival into its rings (not its since-start
// counts), and nothing that shapes a record: data after the restart waits
// for the exporter's template, so a layout changed while Woodshed was down
// decodes with the new layout, and says sampling unknown until the
// exporter's own options data comes, so a rate changed meanwhile is never
// applied (the old one is only shown, as last known); interface names
// aren't applied either.
func TestRestore(t *testing.T) {
	// The "before" collector: a template, a sampling rate, an interface name.
	before := NewCollector(Options{TemplateTimeout: 30 * time.Minute})
	var s0 sink
	b := NewBuilder(IPFIX)
	b.OptionsTemplate(256, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieSamplingProbability, Length: 8}})
	b.Data(256, Values{}.U32(1).U64(math.Float64bits(0.001)))
	b.OptionsTemplate(301, 1, []TemplateField{{ID: ieInIf, Length: 4}, {ID: ieIfName, Length: 4}})
	b.Data(301, Values{}.U32(3).Bytes([]byte("eth3")))
	b.Template(300, []TemplateField{{ID: ieOctetDelta, Length: 4}})
	b.Data(300, Values{}.U32(5))
	s0.decode(before, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0)
	meta, _ := before.Metadata(exp1.Addr())
	tpls := before.Templates(exp1.Addr())
	if len(s0.recs) != 1 || s0.recs[0].Sampling != 1000 || len(tpls) != 3 {
		t.Fatalf("before: %+v %d templates", s0.recs, len(tpls))
	}

	now := t0.Add(10 * time.Minute)
	c := NewCollector(Options{TemplateTimeout: 30 * time.Minute, Clock: func() time.Time { return now }})
	hour := t0.Truncate(time.Hour).UnixMilli()
	c.Restore([]Restored{{Addr: exp1.Addr(), LastHeard: t0.UnixMilli(), Meta: meta,
		// The hour 24 h back shares the current hour's ring slot, and comes last (from the hourly table): it mustn't
		// replace it.
		Hours: []RestoreBucket{{At: hour - 3*3600000, Counts: Counts{Records: 100, SequenceGaps: 849, LostEstimate: 37498}},
			{At: hour, Counts: Counts{Records: 1, SequenceGaps: 1, NoTemplate: 2}, Off: TimeOffsets{Ahead: 1, MaxAheadMs: 7200000}},
			{At: hour - 24*3600000, Counts: Counts{Records: 7, SequenceGaps: 5}, Off: TimeOffsets{Behind: 1, MaxBehindMs: 1}}},
		Fives: []RestoreBucket{{At: t0.Truncate(5 * time.Minute).UnixMilli(), Off: TimeOffsets{Ahead: 1, MaxAheadMs: 7200000}}}}})
	st := c.Stats(now)
	if len(st) != 1 || st[0].Counts24h.SequenceGaps != 850 || st[0].Counts24h.Records != 101 || st[0].Counts24h.NoTemplate != 2 ||
		st[0].Counts != (Counts{}) || st[0].TimeOffsets24h.Ahead != 1 || st[0].TimeOffsets24h.Behind != 0 || st[0].TimeOffsets1h.Ahead != 1 {
		t.Fatalf("stats %+v", st)
	}
	if len(st[0].Domains) != 1 || st[0].Domains[0].Sampling != 0 || st[0].Domains[0].LastKnownSampling != 1000 ||
		st[0].Domains[0].Templates != 0 || !st[0].Domains[0].LastTemplate.IsZero() {
		t.Fatalf("domains %+v", st[0].Domains)
	}
	if len(c.Templates(exp1.Addr())) != 0 {
		t.Fatal("templates restored into the decoder")
	}
	// The exporter changed template 300 while Woodshed was down (bytes, now
	// packets, with the input interface) and its sampling (1 in 1,000, now 1
	// in 100). Data right after the restart waits; when the new template comes
	// it decodes with the new layout, sampling unknown, no interface name.
	var s sink
	b2 := NewBuilder(IPFIX)
	b2.Data(300, Values{}.U16(9).U32(3))
	s.decode(c, b2.Message(Header{Domain: 1, ExportTime: uint32(now.Unix()), Seq: 99}), exp1, now)
	if len(s.recs) != 0 || c.PendingBytes() == 0 {
		t.Fatalf("decoded without the exporter's template: %+v", s.recs)
	}
	b2.Template(300, []TemplateField{{ID: iePacketDelta, Length: 2}, {ID: ieInIf, Length: 4}})
	b2.Data(300, Values{}.U16(10).U32(3))
	s.decode(c, b2.Message(Header{Domain: 1, ExportTime: uint32(now.Unix()), Seq: 100}), exp1, now.Add(time.Second))
	if len(s.recs) != 2 || c.PendingBytes() != 0 {
		t.Fatalf("after the template: %+v pending %d", s.recs, c.PendingBytes())
	}
	for i, want := range []uint64{9, 10} {
		if r := s.recs[i]; r.Is(HasBytes) || r.Packets != want || r.Sampling != 0 || r.Is(HasInIfName) {
			t.Fatalf("record %d with the old layout, a restored rate or a restored name: %+v", i, r)
		}
	}
	// Its options data: the new rate from then on, and "last known" goes.
	b2.OptionsTemplate(256, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieSamplingProbability, Length: 8}})
	b2.Data(256, Values{}.U32(1).U64(math.Float64bits(0.01)))
	b2.Data(300, Values{}.U16(11).U32(3))
	s.decode(c, b2.Message(Header{Domain: 1, ExportTime: uint32(now.Unix()), Seq: 102}), exp1, now.Add(2*time.Second))
	if r := s.recs[len(s.recs)-1]; r.Packets != 11 || r.Sampling != 100 {
		t.Fatalf("after the options data: %+v", r)
	}
	if d := c.Stats(now)[0].Domains; d[0].Sampling != 100 || d[0].LastKnownSampling != 0 {
		t.Fatalf("domains after the options data %+v", d)
	}
	if s.recs[0].Status != StatusLate {
		t.Fatalf("the waiting record isn't late: %+v", s.recs[0])
	}
	if st := c.Stats(now); st[0].Counts.Records != 3 || st[0].Counts24h.Records != 104 || st[0].Counts.SequenceGaps != 0 {
		t.Fatalf("counts after restore %+v", st[0])
	}
	// Bad input is ignored.
	c.Restore([]Restored{{}, {Addr: exp2.Addr(), Meta: []byte("{not json")}})
	if n := len(c.Stats(now)); n != 2 {
		t.Fatalf("%d exporters", n)
	}
}
