package flow

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

var (
	exp1  = netip.MustParseAddrPort("192.0.2.1:40000")
	exp1b = netip.MustParseAddrPort("192.0.2.1:40001")
	exp2  = netip.MustParseAddrPort("198.51.100.2:50000")
	t0    = time.Date(2026, 11, 16, 9, 30, 0, 0, time.UTC)
)

type sink struct {
	recs []Record
	raws []RawSet
}

func (s *sink) emit(r *Record) { s.recs = append(s.recs, *r) }
func (s *sink) raw(r *RawSet)  { s.raws = append(s.raws, *r) }

func (s *sink) decode(c *Collector, data []byte, from netip.AddrPort, at time.Time) {
	c.Decode(Packet{Data: data, From: from, Received: at}, s.emit, s.raw)
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func stats(t *testing.T, c *Collector, a netip.Addr) ExporterStats {
	t.Helper()
	for _, s := range c.Stats(t0.Add(time.Hour)) {
		if s.Addr == a {
			return s
		}
	}
	t.Fatalf("no stats for %v", a)
	return ExporterStats{}
}

func TestV5(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	secs := uint32(t0.Unix())
	h := V5Header{SysUptime: 100000, UnixSecs: secs, Nsecs: 250e6, Seq: 1000, EngineType: 1, EngineID: 7,
		SamplingInterval: 1<<14 | 100}
	pkt := EncodeV5(h, []V5Record{{Src: ip("10.20.0.5"), Dst: ip("198.51.100.7"), NextHop: ip("10.0.0.1"), In: 3, Out: 1,
		Packets: 12, Bytes: 9000, First: 90000, Last: 99000, SrcPort: 51544, DstPort: 443, TCPFlags: 0x1b, Proto: 6,
		ToS: 0x10, SrcAS: 64500, DstAS: 64501, SrcMask: 24}})
	s.decode(c, pkt, exp1, t0)
	if len(s.recs) != 1 || len(s.raws) != 0 {
		t.Fatalf("got %d records, %d raw", len(s.recs), len(s.raws))
	}
	r := s.recs[0]
	exportMs := t0.UnixMilli() + 250
	if r.Start != exportMs-10000 || r.End != exportMs-1000 {
		t.Errorf("times %d..%d, want %d..%d", r.Start, r.End, exportMs-10000, exportMs-1000)
	}
	if r.Src != ip("10.20.0.5") || r.Dst != ip("198.51.100.7") || r.SrcPort != 51544 || r.DstPort != 443 ||
		r.Proto != 6 || r.Bytes != 9000 || r.Packets != 12 || r.InIf != 3 || r.OutIf != 1 || r.SrcAS != 64500 ||
		r.DstAS != 64501 || r.ToS != 0x10 || r.TCPFlags != 0x1b || r.NextHop != ip("10.0.0.1") {
		t.Errorf("columns wrong: %+v", r)
	}
	if r.Sampling != 100 || r.Version != V5 || r.Domain != 0 || r.ExporterPort != 40000 || r.Status != StatusOK {
		t.Errorf("sampling %d version %d domain %d port %d status %v", r.Sampling, r.Version, r.Domain, r.ExporterPort, r.Status)
	}
	want := []Extra{{0, ieEngineType, []byte{1}}, {0, ieEngineID, []byte{7}}, {0, ieSrcMaskV4, []byte{24}}}
	if !extrasEqual(r.Extras, want) {
		t.Errorf("extras %v, want %v", r.Extras, want)
	}
	if !r.Countable() || r.SumBytes() != 9000 {
		t.Error("a v5 record adds to sums")
	}
	// Sequence: v5 counts records. The next packet should be 1001.
	h.Seq = 1005 // 4 records lost
	s.decode(c, EncodeV5(h, []V5Record{{Src: ip("10.0.0.1"), Dst: ip("10.0.0.2")}}), exp1, t0.Add(time.Second))
	h.Seq = 1005 // the same again: a duplicate
	s.decode(c, EncodeV5(h, []V5Record{{Src: ip("10.0.0.1"), Dst: ip("10.0.0.2")}}), exp1, t0.Add(2*time.Second))
	st := stats(t, c, exp1.Addr())
	if st.Counts.SequenceGaps != 1 || st.Counts.LostEstimate != 4 || st.Counts.Duplicates != 1 || st.Counts.Records != 3 {
		t.Errorf("counts %+v", st.Counts)
	}
	if st.Counts24h != st.Counts {
		t.Errorf("24h counts %+v != %+v", st.Counts24h, st.Counts)
	}
	// Unsampled header: interval 0 is every packet.
	h.SamplingInterval, h.Seq = 0, 1006
	s.recs = nil
	s.decode(c, EncodeV5(h, []V5Record{{Src: ip("10.0.0.1"), Dst: ip("10.0.0.2")}}), exp1, t0.Add(3*time.Second))
	if s.recs[0].Sampling != 1 {
		t.Errorf("sampling %d, want 1", s.recs[0].Sampling)
	}
	// A count past the packet: what fits is decoded, the packet kept raw.
	s.recs = nil
	bad := EncodeV5(h, []V5Record{{Src: ip("10.0.0.1")}, {Src: ip("10.0.0.3")}})
	binary.BigEndian.PutUint16(bad[2:], 3)
	s.decode(c, bad, exp1, t0.Add(4*time.Second))
	if len(s.recs) != 2 || len(s.raws) != 1 || s.raws[0].Status != StatusMalformed || !bytes.Equal(s.raws[0].Data, bad) {
		t.Errorf("records %d raws %v", len(s.recs), s.raws)
	}
}

func extrasEqual(a, b []Extra) bool {
	return slices.EqualFunc(a, b, func(x, y Extra) bool { return x.PEN == y.PEN && x.ID == y.ID && bytes.Equal(x.Value, y.Value) })
}

func TestV9TemplatesOptionsAndUptime(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(V9)
	tmpl := []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: ieDstV4, Length: 4}, {ID: ieSrcPort, Length: 2},
		{ID: ieDstPort, Length: 2}, {ID: ieProto, Length: 1}, {ID: ieOctetDelta, Length: 4}, {ID: iePacketDelta, Length: 4},
		{ID: ieStartUptime, Length: 4}, {ID: ieEndUptime, Length: 4}, {ID: ieInIf, Length: 2}, {ID: ieOutIf, Length: 2},
		{ID: 40001, Length: 3}, {ID: ieSamplerID, Length: 1}}
	b.Template(256, tmpl)
	// Options: the sampler table (scope System) and interface names (scope Interface).
	b.OptionsTemplate(257, 1, []TemplateField{{ID: 1, Length: 4}, {ID: ieSamplerID, Length: 1},
		{ID: ieSamplerRandomInterval, Length: 4}})
	b.OptionsTemplate(258, 1, []TemplateField{{ID: 2, Length: 4}, {ID: ieIfName, Length: 8}})
	b.Data(257, Values{}.U32(0).U8(5).U32(1000))
	b.Data(258, Values{}.U32(3).Bytes([]byte("eth3\x00\x00\x00\x00")))
	b.Data(258, Values{}.U32(1).Bytes([]byte("eth1\x00\x00\x00\x00")))
	rec := Values{}.Addr(ip("10.1.1.1")).Addr(ip("203.0.113.9")).U16(1234).U16(53).U8(17).U32(500).U32(5).
		U32(4000000000).U32(4000001000).U16(3).U16(1).Bytes([]byte{1, 2, 3}).U8(5)
	b.Data(256, rec)
	// sysUptime wrapped past 2^32 since the flow started.
	up := uint32(500)
	pkt := b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 7, Domain: 9, SysUptime: up})
	s.decode(c, pkt, exp1, t0.Add(300*time.Millisecond))
	if len(s.recs) != 1 || len(s.raws) != 0 {
		t.Fatalf("records %d raws %d", len(s.recs), len(s.raws))
	}
	r := s.recs[0]
	exportMs := t0.UnixMilli()
	wantStart := exportMs - int64(uint32(up)-4000000000) - 0
	wantStart = exportMs - int64(int32(up-4000000000))
	if r.Start != wantStart || r.End != wantStart+1000 {
		t.Errorf("times %d..%d want %d..", r.Start, r.End, wantStart)
	}
	if r.Sampling != 1000 {
		t.Errorf("sampling %d, want the sampler's 1000", r.Sampling)
	}
	if r.InIfName != "eth3" || r.OutIfName != "eth1" || !r.Is(HasInIfName|HasOutIfName) {
		t.Errorf("names %q %q", r.InIfName, r.OutIfName)
	}
	if !extrasEqual(r.Extras, []Extra{{0, 40001, []byte{1, 2, 3}}}) {
		t.Errorf("extras %v", r.Extras)
	}
	if r.Domain != 9 || r.TemplateID != 256 || r.Template == nil || r.Version != V9 {
		t.Errorf("domain %d template %d", r.Domain, r.TemplateID)
	}
	ti := c.Templates(exp1.Addr())
	if len(ti) != 3 || ti[0].ID != 256 || ti[0].Fields[0].Name != "sourceIPv4Address" || ti[1].Fields[0].Name != "scopeSystem" ||
		!ti[1].Fields[0].Scope || ti[0].Fields[11].Name != "0:40001" {
		t.Errorf("templates %+v", ti)
	}
	st := stats(t, c, exp1.Addr())
	if len(st.Domains) != 1 || st.Domains[0].ID != 9 || st.Domains[0].Templates != 3 || st.Domains[0].Sampling != 1000 {
		t.Errorf("domains %+v", st.Domains)
	}
	// v9 sequence counts packets: 8 then 11 is a gap of 2 packets.
	b.Data(256, rec)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 8, Domain: 9, SysUptime: up + 1000}), exp1, t0.Add(time.Second))
	b.Data(256, rec)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 11, Domain: 9, SysUptime: up + 2000}), exp1, t0.Add(2*time.Second))
	st = stats(t, c, exp1.Addr())
	if st.Counts.SequenceGaps != 1 || st.Counts.LostEstimate < 2 || st.Counts.Records != 3 {
		t.Errorf("counts %+v", st.Counts)
	}
}

// ipfixAll is a template with one field of every column kind.
func ipfixAll() ([]TemplateField, Values) {
	f := []TemplateField{
		{ID: ieSrcV6, Length: 16}, {ID: ieDstV4, Length: 4}, {ID: ieSrcPort, Length: 2}, {ID: ieDstPort, Length: 2},
		{ID: ieProto, Length: 1}, {ID: ieTCPFlags, Length: 2}, {ID: ieToS, Length: 1},
		{ID: ieOctetDelta, Length: 8}, {ID: iePacketDelta, Length: 2}, // reduced-size
		{ID: ieInIf, Length: 4}, {ID: ieOutIf, Length: 4}, {ID: ieSrcAS, Length: 4}, {ID: ieDstAS, Length: 2},
		{ID: ieNextHopV6, Length: 16}, {ID: ieVLAN, Length: 2}, {ID: ieDirection, Length: 1}, {ID: ieEndReason, Length: 1},
		{ID: ieFwEvent, Length: 1}, {ID: ieNatEvent, Length: 1}, {ID: iePostNATSrcV4, Length: 4}, {ID: iePostNATDstV6, Length: 16},
		{ID: iePostNAPTSrcPort, Length: 2}, {ID: iePostNAPTDstPort, Length: 2},
		{ID: ieInitiatorOctets, Length: 8}, {ID: ieResponderOctets, Length: 4}, {ID: ieInitiatorPackets, Length: 8},
		{ID: ieResponderPackets, Length: 8}, {PEN: PENReverse, ID: ieOctetDelta, Length: 8},
		{PEN: PENReverse, ID: iePacketDelta, Length: 4},
		{ID: ieStartMs, Length: 8}, {ID: ieEndUs, Length: 8}, {ID: ieObsTimeNs, Length: 8},
		{ID: ieSamplingPacketInterval, Length: 4}, {ID: ieSamplingPacketSpace, Length: 4},
		{PEN: 32473, ID: 1, Length: Varlen}, {PEN: 32473, ID: 2, Length: 4}, {ID: 96, Length: Varlen},
	}
	ms := t0.UnixMilli()
	v := Values{}.Addr(ip("2001:db8::5")).Addr(ip("198.51.100.7")).U16(51544).U16(443).U8(6).U16(0x112).U8(0x20).
		U64(2210444).U16(1840).U32(3).U32(1).U32(64500).U16(64501).Addr(ip("2001:db8::1")).U16(100).U8(1).U8(3).
		U8(FwDeleted).U8(5).Addr(ip("192.0.2.10")).Addr(ip("2001:db8::7")).U16(40112).U16(443).
		U64(1000).U32(2000).U64(10).U64(20).U64(3000).U32(30).
		U64(uint64(ms - 50000)).U64(msToNTP(ms - 10)).U64(msToNTP(ms - 5)).
		U32(1).U32(99).
		Var([]byte("abc")).U32(77).Var(bytes.Repeat([]byte{'x'}, 300))
	return f, v
}

func TestIPFIXEveryColumn(t *testing.T) {
	c := NewCollector(Options{RuleIDIEs: []IEKey{{32473, 9}, {32473, 2}}})
	var s sink
	b := NewBuilder(IPFIX)
	f, v := ipfixAll()
	b.Template(300, f)
	b.Data(300, v)
	b.Data(300, v)
	pkt := b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 0, Domain: 4})
	pkt = append(pkt[:len(pkt)], 0, 0, 0) // trailing bytes past the length field are ignored
	s.decode(c, pkt, exp2, t0.Add(time.Second))
	if len(s.recs) != 2 || len(s.raws) != 0 {
		t.Fatalf("records %d raws %v", len(s.recs), s.raws)
	}
	r := s.recs[0]
	ms := t0.UnixMilli()
	checks := []struct {
		name string
		ok   bool
	}{
		{"src", r.Src == ip("2001:db8::5")}, {"dst", r.Dst == ip("198.51.100.7")}, {"ports", r.SrcPort == 51544 && r.DstPort == 443},
		{"proto", r.Proto == 6}, {"flags", r.TCPFlags == 0x112}, {"tos", r.ToS == 0x20},
		{"bytes", r.Bytes == 2210444 && r.Packets == 1840 && !r.Is(HasTotals)},
		{"ifs", r.InIf == 3 && r.OutIf == 1}, {"as", r.SrcAS == 64500 && r.DstAS == 64501},
		{"nexthop", r.NextHop == ip("2001:db8::1")}, {"vlan", r.VLAN == 100}, {"dir", r.Direction == 1 && r.EndReason == 3},
		{"fw", r.FwEvent == FwDeleted && r.NatEvent == 5}, {"postnat", r.PostNATSrc == ip("192.0.2.10") && r.PostNATDst == ip("2001:db8::7")},
		{"postnat ports", r.PostNATSrcPort == 40112 && r.PostNATDstPort == 443},
		{"init/resp", r.InitiatorBytes == 1000 && r.ResponderBytes == 2000 && r.InitiatorPackets == 10 && r.ResponderPackets == 20},
		{"rev", r.RevBytes == 3000 && r.RevPackets == 30},
		{"start", r.Start == ms-50000}, {"end", r.End == ms-10}, {"event", r.EventTime == ms-5 && r.Is(HasEventTime)},
		{"sampling", r.Sampling == 100}, {"rule", r.RuleID == "77" && r.Is(HasRuleID)},
		{"source", r.TimeSource == TimeExporter}, {"domain", r.Domain == 4},
	}
	for _, ch := range checks {
		if !ch.ok {
			t.Errorf("%s wrong: %+v", ch.name, r)
		}
	}
	want := []Extra{{32473, 1, []byte("abc")}, {32473, 2, []byte{0, 0, 0, 77}}, {0, 96, bytes.Repeat([]byte{'x'}, 300)}}
	if !extrasEqual(r.Extras, want) {
		t.Errorf("extras %v", r.Extras)
	}
	if r.Extras[0].String() != "32473:1=616263" {
		t.Errorf("extra string %q", r.Extras[0].String())
	}
	if r.ConvBytes() != 2210444+3000 {
		t.Errorf("conversation bytes %d", r.ConvBytes())
	}
	// IPFIX sequence counts records: next is 2.
	b.Data(300, v)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 2, Domain: 4}), exp2, t0.Add(2*time.Second))
	b.Data(300, v)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 10, Domain: 4}), exp2, t0.Add(3*time.Second))
	st := stats(t, c, exp2.Addr())
	if st.Counts.SequenceGaps != 1 || st.Counts.LostEstimate != 7 {
		t.Errorf("counts %+v", st.Counts)
	}
}

func TestIPFIXTimesAndEvents(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	ms := t0.UnixMilli()
	// systemInitTimeMilliseconds from options data, then sysUpTime-relative times.
	b.OptionsTemplate(400, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieSysInitMs, Length: 8}})
	b.Data(400, Values{}.U32(1).U64(uint64(ms-3600000)))
	b.Template(401, []TemplateField{{ID: ieStartUptime, Length: 4}, {ID: ieEndUptime, Length: 4}})
	b.Data(401, Values{}.U32(1000).U32(2000))
	// Seconds, and a start delta from the export time.
	b.Template(402, []TemplateField{{ID: ieStartDeltaUs, Length: 4}, {ID: ieEndSec, Length: 4}})
	b.Data(402, Values{}.U32(7000000).U32(uint32(t0.Unix())))
	// An event with only an event time.
	b.Template(403, []TemplateField{{ID: ieFwEvent, Length: 1}, {ID: ieObsTimeMs, Length: 8}, {ID: ieSrcV4, Length: 4}})
	b.Data(403, Values{}.U8(FwDenied).U64(uint64(ms-123)).Addr(ip("203.0.113.50")))
	// No time at all, and a start with a duration.
	b.Template(404, []TemplateField{{ID: ieSrcV4, Length: 4}})
	b.Data(404, Values{}.Addr(ip("10.0.0.1")))
	b.Template(405, []TemplateField{{ID: ieStartMs, Length: 8}, {ID: ieDurationMs, Length: 4}, {ID: ieStartSec, Length: 4}})
	b.Data(405, Values{}.U64(uint64(ms-9000)).U32(4000).U32(1))
	at := t0.Add(2 * time.Second)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, at)
	if len(s.recs) != 5 {
		t.Fatalf("got %d records: %+v", len(s.recs), s.raws)
	}
	base := ms - 3600000
	if r := s.recs[0]; r.Start != base+1000 || r.End != base+2000 {
		t.Errorf("uptime times %d %d", r.Start-base, r.End-base)
	}
	if r := s.recs[1]; r.Start != ms-7000 || r.End != ms {
		t.Errorf("delta/seconds %d %d", r.Start-ms, r.End-ms)
	}
	if r := s.recs[2]; r.Start != ms-123 || r.End != ms-123 || r.EventTime != ms-123 || r.FwEvent != FwDenied || r.IsConnection() != true {
		t.Errorf("event %+v", r)
	}
	if r := s.recs[3]; r.Start != at.UnixMilli() || r.End != at.UnixMilli() || r.TimeSource != TimeReceived {
		t.Errorf("no time: %+v", r)
	}
	// The most precise start wins; the seconds form is dropped as redundant.
	if r := s.recs[4]; r.Start != ms-9000 || r.End != ms-5000 || len(r.Extras) != 0 {
		t.Errorf("duration %d %d %v", r.Start-ms, r.End-ms, r.Extras)
	}
}

func TestEventCountingRule(t *testing.T) {
	mk := func(ev uint8, has uint64) Record {
		return Record{Has: HasFwEvent | has, FwEvent: ev, Bytes: 10, Packets: 1, InitiatorBytes: 7, ResponderBytes: 5,
			InitiatorPackets: 1, ResponderPackets: 2}
	}
	cases := []struct {
		r          Record
		sum, conv  uint64
		connection bool
	}{
		{mk(FwCreated, HasInitiatorBytes|HasResponderBytes), 0, 0, false},
		{mk(FwUpdate, HasInitiatorBytes|HasResponderBytes), 0, 0, false},
		{mk(FwDeleted, HasInitiatorBytes|HasResponderBytes), 7, 12, true},
		{mk(FwDenied, 0), 0, 0, true},
		{mk(FwCreated, HasBytes|HasPackets), 10, 10, false},          // deltas add regardless
		{mk(FwCreated, HasBytes|HasPackets|HasTotals), 0, 0, false},  // totals only on the final record
		{mk(FwDeleted, HasBytes|HasPackets|HasTotals), 10, 10, true}, //
		{Record{Has: HasBytes | HasTotals, Bytes: 4}, 4, 4, true},    // a non-event record
	}
	for i, c := range cases {
		if got := c.r.SumBytes(); got != c.sum {
			t.Errorf("%d: SumBytes %d, want %d", i, got, c.sum)
		}
		if got := c.r.ConvBytes(); got != c.conv {
			t.Errorf("%d: ConvBytes %d, want %d", i, got, c.conv)
		}
		if c.r.IsConnection() != c.connection {
			t.Errorf("%d: IsConnection", i)
		}
	}
}

func TestTotalsAndClockSkew(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	b.Template(256, []TemplateField{{ID: ieOctetTotal, Length: 8}, {ID: iePacketTotal, Length: 8}, {ID: ieStartMs, Length: 8},
		{ID: ieEndMs, Length: 8}, {ID: ieObsTimeMs, Length: 8}})
	old := t0.Add(-3 * time.Hour).UnixMilli()
	b.Data(256, Values{}.U64(500).U64(5).U64(uint64(old-1000)).U64(uint64(old)).U64(uint64(old)))
	// The exporter's clock says three hours ago.
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Add(-3 * time.Hour).Unix()), Domain: 1}), exp1, t0)
	r := s.recs[0]
	if !r.Is(HasTotals) || r.Bytes != 500 || r.Packets != 5 {
		t.Errorf("totals %+v", r)
	}
	if r.TimeSource != TimeReceived || r.End != t0.UnixMilli() || r.Start != t0.UnixMilli()-1000 || r.EventTime != t0.UnixMilli() {
		t.Errorf("skewed record not on received time: %+v", r)
	}
	if len(r.Extras) != 3 || binary.BigEndian.Uint64(r.Extras[0].Value) != uint64(old-1000) || r.Extras[2].ID != ieObsTimeMs {
		t.Errorf("exporter times not kept: %v", r.Extras)
	}
	st := stats(t, c, exp1.Addr())
	if st.TimeSource != "received" || st.ClockSkewMs != 3*3600*1000 {
		t.Errorf("stats %+v", st)
	}
}

func TestPendingLateExpireAndFull(t *testing.T) {
	c := NewCollector(Options{TemplateTimeout: 10 * time.Minute, PendingPerExporter: 600})
	var s sink
	b := NewBuilder(IPFIX)
	f := []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: ieOctetDelta, Length: 4}}
	b.Data(256, Values{}.Addr(ip("10.0.0.1")).U32(1))
	b.Data(256, Values{}.Addr(ip("10.0.0.2")).U32(2))
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, t0)
	if len(s.recs) != 0 || len(s.raws) != 0 || c.PendingBytes() == 0 {
		t.Fatalf("data before its template should wait: %d %d %d", len(s.recs), len(s.raws), c.PendingBytes())
	}
	// Another exporter's data with the same template ID doesn't match.
	b.Template(256, f)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp2, t0.Add(time.Second))
	if len(s.recs) != 0 {
		t.Fatal("another exporter's template resolved the data")
	}
	b.Template(256, f)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, t0.Add(5*time.Second))
	if len(s.recs) != 2 || s.recs[0].Status != StatusLate || s.recs[0].Received != t0.UnixMilli() || s.recs[1].Bytes != 2 {
		t.Fatalf("late decode: %+v", s.recs)
	}
	if c.PendingBytes() != 0 {
		t.Errorf("pending %d after the template", c.PendingBytes())
	}
	st := stats(t, c, exp1.Addr())
	if st.Counts.Late != 2 || st.Counts.Records != 2 {
		t.Errorf("counts %+v", st.Counts)
	}
	// Data for an unknown template on another port (another key) waits, then expires.
	s.recs = nil
	b.Data(256, Values{}.Addr(ip("10.0.0.3")).U32(3))
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1b, t0.Add(time.Minute))
	if len(s.recs) != 0 {
		t.Fatal("decoded with another port's template")
	}
	c.Expire(t0.Add(time.Minute+9*time.Minute), s.raw)
	if len(s.raws) != 0 {
		t.Fatal("expired before the timeout")
	}
	c.Expire(t0.Add(time.Minute+10*time.Minute+time.Millisecond), s.raw)
	if len(s.raws) != 1 || s.raws[0].Status != StatusNoTemplate || s.raws[0].TemplateID != 256 || s.raws[0].Received != t0.Add(time.Minute).UnixMilli() ||
		s.raws[0].Exporter != exp1.Addr() || s.raws[0].ExporterPort != exp1b.Port() {
		t.Fatalf("raws %+v", s.raws)
	}
	// The per-exporter limit: a set too big goes raw at once.
	s.raws = nil
	b.Data(999, bytes.Repeat([]byte{1}, 500))
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, t0.Add(20*time.Minute))
	if len(s.raws) != 1 || s.raws[0].Status != StatusNoTemplate {
		t.Fatalf("over the limit: raws %+v pending %d", s.raws, c.PendingBytes())
	}
	if st := stats(t, c, exp1.Addr()); st.Counts.NoTemplate != 2 {
		t.Errorf("no_template %d", st.Counts.NoTemplate)
	}
	// DecodeRawSet with the template.
	recs, err := DecodeRawSet(&Template{Version: IPFIX, ID: 999, Fields: []TemplateField{{ID: ieOctetDelta, Length: 4}}}, &s.raws[0], RedecodeOptions{Sampling: 10})
	if err != nil || len(recs) != 125 || recs[0].Bytes != 0x01010101 || recs[0].Status != StatusLate || recs[0].Sampling != 10 {
		t.Errorf("redecode: %d records, %v", len(recs), err)
	}
}

func TestTemplateReplacementWithdrawalTimeout(t *testing.T) {
	c := NewCollector(Options{TemplateTimeout: time.Minute})
	var s sink
	b := NewBuilder(IPFIX)
	b.Template(256, []TemplateField{{ID: ieOctetDelta, Length: 4}})
	b.Data(256, Values{}.U32(7))
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0)
	first := s.recs[0].Template
	// Same ID, new definition: from this packet on.
	b.Template(256, []TemplateField{{ID: iePacketDelta, Length: 2}})
	b.Data(256, Values{}.U16(9))
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0.Add(time.Second))
	r := s.recs[1]
	if r.Is(HasBytes) || r.Packets != 9 || r.Template == first || first.Fields[0].ID != ieOctetDelta {
		t.Errorf("replacement: %+v, old %+v", r, first)
	}
	// An identical copy keeps the pointer.
	b.Template(256, []TemplateField{{ID: iePacketDelta, Length: 2}})
	b.Data(256, Values{}.U16(10))
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0.Add(2*time.Second))
	if s.recs[2].Template != r.Template {
		t.Error("an identical template got a new definition")
	}
	// Withdrawal: the data waits again.
	b.Withdraw(256, false)
	b.Data(256, Values{}.U16(11))
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0.Add(3*time.Second))
	if len(s.recs) != 3 || c.PendingBytes() == 0 {
		t.Errorf("withdrawn template still decodes: %d", len(s.recs))
	}
	// The all-templates form.
	b.Template(260, []TemplateField{{ID: iePacketDelta, Length: 2}})
	b.Template(261, []TemplateField{{ID: iePacketDelta, Length: 2}})
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0.Add(4*time.Second))
	if n := len(c.Templates(exp1.Addr())); n != 2 {
		t.Fatalf("%d templates", n)
	}
	b.Withdraw(2, false)
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0.Add(5*time.Second))
	if n := len(c.Templates(exp1.Addr())); n != 0 {
		t.Errorf("%d templates after withdraw-all", n)
	}
	// Timeout: a template not refreshed in time is gone.
	b.Template(262, []TemplateField{{ID: iePacketDelta, Length: 2}})
	b.Data(262, Values{}.U16(1))
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0.Add(6*time.Second))
	n := len(s.recs)
	b.Data(262, Values{}.U16(1))
	s.decode(c, b.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), exp1, t0.Add(6*time.Second+time.Minute+time.Millisecond))
	if len(s.recs) != n {
		t.Error("an expired template still decodes")
	}
}

func TestTemplateCacheLimits(t *testing.T) {
	c := NewCollector(Options{MaxTemplatesPerKey: 4, MaxTemplates: 6})
	var s sink
	b := NewBuilder(IPFIX)
	for i := range 6 {
		b.Template(uint16(256+i), []TemplateField{{ID: ieOctetDelta, Length: 4}})
		s.decode(c, b.Message(Header{Domain: 1}), exp1, t0.Add(time.Duration(i)*time.Second))
	}
	if n := len(c.Templates(exp1.Addr())); n != 4 {
		t.Errorf("per-key cap: %d", n)
	}
	for i := range 4 {
		b.Template(uint16(256+i), []TemplateField{{ID: ieOctetDelta, Length: 4}})
		s.decode(c, b.Message(Header{Domain: 1}), exp2, t0.Add(time.Duration(10+i)*time.Second))
	}
	if n1, n2 := len(c.Templates(exp1.Addr())), len(c.Templates(exp2.Addr())); n1+n2 != 6 || n2 != 4 {
		t.Errorf("total cap: %d + %d", n1, n2)
	}
}

func TestMalformed(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	b.Template(256, []TemplateField{{ID: ieOctetDelta, Length: 4}, {ID: 96, Length: Varlen}})
	b.Data(256, Values{}.U32(1).Var([]byte("ok")))
	good := b.Message(Header{Domain: 1})
	// A record whose variable-length field runs past the set.
	bad := append([]byte(nil), good...)
	bad = append(bad, 1, 0, 0, 9, 0, 0, 0, 2, 50)
	binary.BigEndian.PutUint16(bad[2:], uint16(len(bad)))
	cases := [][]byte{
		{0},                              // too short
		{0, 7, 1, 2, 3, 4},               // wrong version
		good[:len(good)-3],               // the length field says more than came
		append(good[:16:16], 1, 0, 0, 2), // a set shorter than its header
		bad,
	}
	for i, p := range cases {
		s.recs, s.raws = nil, nil
		s.decode(c, p, exp1, t0.Add(time.Duration(i)*time.Second))
		if len(s.raws) != 1 || s.raws[0].Status != StatusMalformed || s.raws[0].Exporter != exp1.Addr() {
			t.Errorf("case %d: raws %+v", i, s.raws)
		}
	}
	if len(s.recs) != 1 || s.recs[0].Bytes != 1 {
		t.Errorf("the record before the break: %+v", s.recs)
	}
	if st := stats(t, c, exp1.Addr()); st.Counts.Malformed != int64(len(cases)) {
		t.Errorf("malformed %d", st.Counts.Malformed)
	}
	// A template with an impossible field length.
	tb := NewBuilder(V9)
	tb.Template(256, []TemplateField{{ID: 1, Length: 0}})
	s.raws = nil
	s.decode(c, tb.Message(Header{Domain: 1}), exp1, t0.Add(time.Minute))
	if len(s.raws) != 1 {
		t.Error("zero-length field accepted")
	}
}

func TestPaddingAndRuleRendering(t *testing.T) {
	c := NewCollector(Options{RuleIDIEs: []IEKey{{32473, 5}}})
	var s sink
	b := NewBuilder(V9)
	b.Template(256, []TemplateField{{ID: ieOctetDelta, Length: 4}, {ID: ieProto, Length: 1}})
	b.Data(256, Values{}.U32(5).U8(6))
	b.Data(256, Values{}.U32(6).U8(17)) // the flowset is then padded to 4 bytes
	s.decode(c, b.Message(Header{Domain: 1}), exp1, t0)
	if len(s.recs) != 2 || len(s.raws) != 0 {
		t.Fatalf("padding: %d records, %v", len(s.recs), s.raws)
	}
	for _, x := range []struct {
		v      []byte
		varlen bool
		want   string
	}{{[]byte{0, 1, 0, 0}, false, "65536"}, {[]byte("acl-outside-in\x00\x00\x00"), false, "acl-outside-in"},
		{[]byte("rule-7"), true, "rule-7"}, {[]byte{1, 2}, true, "0102"},
		{[]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}, false, "010203040506070809"}} {
		if got := RuleIDText(x.v, x.varlen); got != x.want {
			t.Errorf("RuleIDText(%v) = %q, want %q", x.v, got, x.want)
		}
	}
	// A rule IE fills rule_id (and stays in extras); a live change applies.
	bi := NewBuilder(IPFIX)
	bi.Template(256, []TemplateField{{PEN: 32473, ID: 5, Length: Varlen}, {PEN: 32473, ID: 6, Length: 2}})
	bi.Data(256, Values{}.Var([]byte("rule-7")).U16(8))
	s.recs = nil
	s.decode(c, bi.Message(Header{Domain: 1}), exp2, t0)
	if s.recs[0].RuleID != "rule-7" || len(s.recs[0].Extras) != 2 {
		t.Errorf("rule %q extras %v", s.recs[0].RuleID, s.recs[0].Extras)
	}
	c.SetOptions(0, []IEKey{{32473, 6}, {32473, 5}})
	bi.Data(256, Values{}.Var([]byte("rule-7")).U16(8))
	s.decode(c, bi.Message(Header{Domain: 1}), exp2, t0.Add(time.Second))
	if s.recs[1].RuleID != "8" {
		t.Errorf("after SetOptions rule %q", s.recs[1].RuleID)
	}
}

func TestSamplingSources(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	// The domain's own sampling (options without a sampler), then a selector table.
	b.OptionsTemplate(256, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieSamplingProbability, Length: 8}})
	b.Data(256, Values{}.U32(1).U64(math.Float64bits(0.001)))
	b.OptionsTemplate(257, 1, []TemplateField{{ID: ieSelectorID, Length: 4}, {ID: ieSamplingPacketInterval, Length: 4},
		{ID: ieSamplingPacketSpace, Length: 4}})
	b.Data(257, Values{}.U32(9).U32(1).U32(63))
	b.Template(258, []TemplateField{{ID: ieOctetDelta, Length: 4}})
	b.Template(259, []TemplateField{{ID: ieOctetDelta, Length: 4}, {ID: ieSelectorID, Length: 4}})
	b.Template(260, []TemplateField{{ID: ieOctetDelta, Length: 4}, {ID: ieSamplingSize, Length: 4}, {ID: ieSamplingPopulation, Length: 4}})
	b.Data(258, Values{}.U32(1))
	b.Data(259, Values{}.U32(1).U32(9))
	b.Data(260, Values{}.U32(1).U32(1).U32(50))
	s.decode(c, b.Message(Header{Domain: 1}), exp1, t0)
	got := []uint32{s.recs[0].Sampling, s.recs[1].Sampling, s.recs[2].Sampling}
	if !slices.Equal(got, []uint32{1000, 64, 50}) {
		t.Errorf("sampling %v", got)
	}
	// A domain that says nothing: unknown.
	b.Template(258, []TemplateField{{ID: ieOctetDelta, Length: 4}})
	b.Data(258, Values{}.U32(1))
	s.decode(c, b.Message(Header{Domain: 2}), exp1, t0)
	if s.recs[3].Sampling != 0 {
		t.Errorf("unknown sampling %d", s.recs[3].Sampling)
	}
}

// TestStatsConcurrent reads Stats and Templates while Decode runs (-race).
func TestStatsConcurrent(t *testing.T) {
	c := NewCollector(Options{})
	b := NewBuilder(IPFIX)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.Stats(t0)
			c.Templates(exp1.Addr())
		}
	}()
	for i := range 2000 {
		b.Template(uint16(256+i%300), []TemplateField{{ID: ieOctetDelta, Length: 4}})
		b.OptionsTemplate(999, 1, []TemplateField{{ID: ieInIf, Length: 4}, {ID: ieIfName, Length: Varlen}})
		b.Data(999, Values{}.U32(uint32(i%7)).Var([]byte("if")))
		b.Data(uint16(256+i%300), Values{}.U32(1))
		c.Decode(Packet{Data: b.Message(Header{Domain: uint32(i % 3)}), From: exp1, Received: t0.Add(time.Duration(i) * time.Millisecond)}, nil, nil)
	}
	close(stop)
	wg.Wait()
	if st := stats(t, c, exp1.Addr()); st.Counts.Records != 2000 {
		t.Errorf("records %d", st.Counts.Records)
	}
}

// softflowdIPFIX is one message laid out byte for byte as softflowd 1.1
// writes IPFIX by default (ipfix.c): each template in its own set (IPv4,
// template 1024: addresses, flowStartSysUpTime/flowEndSysUpTime, counters,
// interfaces, direction, end reason, ports, protocol, TCP flags, IP version,
// class of service), an options template 256 scoped by meteringProcessId with
// systemInitTimeMilliseconds, its 82-byte options data set, then one data set
// padded to 4 bytes. start and end are sysUpTime values, as softflowd
// computes them: (u_int32_t)(flow time - init time).
func softflowdIPFIX(export, sysInit time.Time, start, end uint32) []byte {
	be := binary.BigEndian
	p := be.AppendUint16(nil, IPFIX)
	p = be.AppendUint16(p, 0) // length, below
	p = be.AppendUint32(p, uint32(export.Unix()))
	p = be.AppendUint32(p, 0) // sequence
	p = be.AppendUint32(p, 0) // observation domain
	tmpl := [][2]uint16{{ieSrcV4, 4}, {ieDstV4, 4}, {ieStartUptime, 4}, {ieEndUptime, 4}, {1, 4}, {2, 4}, {10, 4}, {14, 4},
		{61, 1}, {136, 1}, {7, 2}, {11, 2}, {4, 1}, {6, 1}, {60, 1}, {5, 1}}
	p = be.AppendUint16(p, 2)
	p = be.AppendUint16(p, uint16(8+4*len(tmpl)))
	p = be.AppendUint16(p, 1024)
	p = be.AppendUint16(p, uint16(len(tmpl)))
	for _, f := range tmpl {
		p = be.AppendUint16(be.AppendUint16(p, f[0]), f[1])
	}
	opt := [][2]uint16{{143, 4}, {ieSysInitMs, 8}, {305, 4}, {306, 4}, {304, 2}, {ieIfName, 16}, {130, 4}, {131, 16}, {403, 4}, {404, 16}}
	p = be.AppendUint16(p, 3)
	p = be.AppendUint16(p, uint16(10+4*len(opt)))
	p = be.AppendUint16(p, 256)
	p = be.AppendUint16(p, uint16(len(opt)))
	p = be.AppendUint16(p, 1) // scope count
	for _, f := range opt {
		p = be.AppendUint16(be.AppendUint16(p, f[0]), f[1])
	}
	p = be.AppendUint16(p, 256)
	p = be.AppendUint16(p, 82)
	p = be.AppendUint32(p, 4242) // meteringProcessId
	p = be.AppendUint64(p, uint64(sysInit.UnixMilli()))
	p = be.AppendUint32(p, 1) // samplingPacketInterval
	p = be.AppendUint32(p, 0) // samplingPacketSpace
	p = be.AppendUint16(p, 3) // selectorAlgorithm
	p = append(p, []byte("synthetic.pcap\x00\x00")...)
	p = append(p, make([]byte, 4+16+4+16)...)
	p = be.AppendUint16(p, 1024)
	p = be.AppendUint16(p, 4+42+2)
	p = append(p, 10, 10, 0, 1, 192, 0, 2, 1)
	p = be.AppendUint32(p, start)
	p = be.AppendUint32(p, end)
	p = be.AppendUint32(p, 420) // octets
	p = be.AppendUint32(p, 3)   // packets
	p = be.AppendUint32(p, 0)
	p = be.AppendUint32(p, 0)
	p = append(p, 0, 1) // direction, end reason
	p = be.AppendUint16(p, 40000)
	p = be.AppendUint16(p, 443)
	p = append(p, 6, 0x18, 4, 0, 0, 0) // protocol, TCP flags, IP version, class of service; padding
	be.PutUint16(p[2:], uint16(len(p)))
	return p
}

// IPFIX sysUpTime times are resolved modulo 2^32 ms against the export time,
// as v9's are: a flow that predates the exporter's init time (softflowd
// reading a capture file sends (u_int32_t)(flow time - init time), just
// below 2^32), and one after the 49.7-day wrap, land at their real times,
// not 49.7 days away.
func TestIPFIXUptimeModulo(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sysInit    time.Time
		start, end time.Time
	}{
		{"before init", t0, t0.Add(-10 * time.Minute), t0.Add(-10*time.Minute + 20*time.Millisecond)},
		{"after the wrap", t0.Add(-60 * 24 * time.Hour), t0.Add(-2 * time.Minute), t0.Add(-time.Minute)},
		{"no wrap", t0.Add(-30 * 24 * time.Hour), t0.Add(-2 * time.Minute), t0.Add(-time.Minute)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := func(at time.Time) uint32 { return uint32(at.Sub(tc.sysInit).Milliseconds()) }
			c := NewCollector(Options{})
			var s sink
			s.decode(c, softflowdIPFIX(t0, tc.sysInit, up(tc.start), up(tc.end)), exp1, t0.Add(time.Second))
			if len(s.recs) != 1 || len(s.raws) != 0 {
				t.Fatalf("%d records, %d raw sets: %+v", len(s.recs), len(s.raws), stats(t, c, exp1.Addr()).Counts)
			}
			r := s.recs[0]
			if r.Start != tc.start.UnixMilli() || r.End != tc.end.UnixMilli() || r.TimeSource != TimeExporter {
				t.Errorf("start %v end %v (%v), want %v %v", time.UnixMilli(r.Start).UTC(), time.UnixMilli(r.End).UTC(), r.TimeSource,
					tc.start, tc.end)
			}
			if r.Src != ip("10.10.0.1") || r.Dst != ip("192.0.2.1") || r.SrcPort != 40000 || r.DstPort != 443 || r.Proto != 6 ||
				r.Packets != 3 || r.Bytes != 420 {
				t.Errorf("record %+v", r)
			}
		})
	}
}
