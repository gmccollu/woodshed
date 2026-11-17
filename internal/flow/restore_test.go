package flow

import (
	"math"
	"testing"
	"time"
)

// Restore (SPEC §13.10 decision 83): a restarted collector gets an exporter's
// 24-hour counts and times off arrival into its rings (not its since-start
// counts), decodes data right away with the stored templates and sampling,
// lets a template the exporter sends again win, and times restored templates
// out from when their segment last stored data.
func TestRestore(t *testing.T) {
	// The "before" collector: a template, a sampling rate, an interface name.
	before := NewCollector(Options{TemplateTimeout: 30 * time.Minute})
	var s0 sink
	b := NewBuilder(IPFIX)
	b.OptionsTemplate(256, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieSamplingProbability, Length: 8}})
	b.Data(256, Values{}.U32(1).U64(math.Float64bits(0.001)))
	b.Template(300, []TemplateField{{ID: ieOctetDelta, Length: 4}})
	b.Data(300, Values{}.U32(5))
	s0.decode(before, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0)
	meta, _ := before.Metadata(exp1.Addr())
	tpls := before.Templates(exp1.Addr())
	if len(s0.recs) != 1 || s0.recs[0].Sampling != 1000 || len(tpls) != 2 {
		t.Fatalf("before: %+v %d templates", s0.recs, len(tpls))
	}
	defs := []*Template{s0.recs[0].Template}

	now := t0.Add(10 * time.Minute)
	c := NewCollector(Options{TemplateTimeout: 30 * time.Minute, Clock: func() time.Time { return now }})
	hour := t0.Truncate(time.Hour).UnixMilli()
	c.Restore([]Restored{{Addr: exp1.Addr(), LastHeard: t0.UnixMilli(), TemplatesAt: t0.UnixMilli(), Templates: defs, Meta: meta,
		Hours: []RestoreBucket{{At: hour - 3*3600000, Counts: Counts{Records: 100, SequenceGaps: 849, LostEstimate: 37498}},
			{At: hour, Counts: Counts{Records: 1, SequenceGaps: 1, NoTemplate: 2}, Off: TimeOffsets{Ahead: 1, MaxAheadMs: 7200000}}},
		Fives: []RestoreBucket{{At: t0.Truncate(5 * time.Minute).UnixMilli(), Off: TimeOffsets{Ahead: 1, MaxAheadMs: 7200000}}}}})
	st := c.Stats(now)
	if len(st) != 1 || st[0].Counts24h.SequenceGaps != 850 || st[0].Counts24h.Records != 101 || st[0].Counts24h.NoTemplate != 2 ||
		st[0].Counts != (Counts{}) || st[0].TimeOffsets24h.Ahead != 1 || st[0].TimeOffsets1h.Ahead != 1 {
		t.Fatalf("stats %+v", st)
	}
	if len(st[0].Domains) != 1 || st[0].Domains[0].Sampling != 1000 || st[0].Domains[0].Templates != 1 {
		t.Fatalf("domains %+v", st[0].Domains)
	}
	// Data right after the restart, no template in the packet: decoded, sampled.
	var s sink
	b2 := NewBuilder(IPFIX)
	b2.Data(300, Values{}.U32(6))
	s.decode(c, b2.Message(Header{Domain: 1, ExportTime: uint32(now.Unix()), Seq: 99}), exp1, now)
	if len(s.recs) != 1 || s.recs[0].Bytes != 6 || s.recs[0].Sampling != 1000 || len(s.raws) != 0 || c.PendingBytes() != 0 {
		t.Fatalf("after restore: %+v raws %d pending %d", s.recs, len(s.raws), c.PendingBytes())
	}
	if st := c.Stats(now); st[0].Counts.Records != 1 || st[0].Counts24h.Records != 102 || st[0].Counts.SequenceGaps != 0 {
		t.Fatalf("counts after restore %+v", st[0])
	}
	// The exporter sends the ID again with another definition: it wins.
	b2.Template(300, []TemplateField{{ID: iePacketDelta, Length: 2}})
	b2.Data(300, Values{}.U16(9))
	s.decode(c, b2.Message(Header{Domain: 1, ExportTime: uint32(now.Unix()), Seq: 100}), exp1, now.Add(time.Second))
	if r := s.recs[1]; r.Is(HasBytes) || r.Packets != 9 {
		t.Fatalf("the exporter's template didn't win: %+v", r)
	}
	// Templates are per source port: another port of the exporter has none.
	b3 := NewBuilder(IPFIX)
	b3.Data(300, Values{}.U32(1))
	n := len(s.recs)
	s.decode(c, b3.Message(Header{Domain: 1}), exp1b, now.Add(2*time.Second))
	if len(s.recs) != n {
		t.Fatalf("another source port is another scope: %+v", s.recs[n:])
	}
	// Restored templates time out from their segment's last data.
	stale := NewCollector(Options{TemplateTimeout: 30 * time.Minute})
	stale.Restore([]Restored{{Addr: exp1.Addr(), LastHeard: t0.UnixMilli(), TemplatesAt: t0.UnixMilli(), Templates: defs}})
	var s4 sink
	b3.Data(300, Values{}.U32(1))
	s4.decode(stale, b3.Message(Header{Domain: 1}), exp1, t0.Add(31*time.Minute))
	if len(s4.recs) != 0 || stale.PendingBytes() == 0 {
		t.Fatalf("a restored template past its timeout still decodes: %+v raws %+v pending %d", s4.recs, s4.raws, stale.PendingBytes())
	}
	// Bad input is ignored.
	c.Restore([]Restored{{}, {Addr: exp2.Addr(), Meta: []byte("{not json")}})
	if n := len(c.Stats(now)); n != 2 {
		t.Fatalf("%d exporters", n)
	}
}
