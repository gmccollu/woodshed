package flow

import (
	"testing"
	"time"
)

// BenchmarkDecodeIPFIX decodes IPFIX packets of 30 records each (a plain
// flow template with two enterprise IEs, as `woodshed send` sends):
// records/s per core is b.N*30 over the time.
func BenchmarkDecodeIPFIX(b *testing.B) {
	bl := NewBuilder(IPFIX)
	f := []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: ieDstV4, Length: 4}, {ID: ieSrcPort, Length: 2}, {ID: ieDstPort, Length: 2},
		{ID: ieProto, Length: 1}, {ID: ieTCPFlags, Length: 1}, {ID: ieToS, Length: 1}, {ID: ieOctetDelta, Length: 8},
		{ID: iePacketDelta, Length: 8}, {ID: ieStartMs, Length: 8}, {ID: ieEndMs, Length: 8}, {ID: ieInIf, Length: 4},
		{ID: ieOutIf, Length: 4}, {PEN: PENDocumentation, ID: 1, Length: 4}, {PEN: PENDocumentation, ID: 2, Length: 8}}
	bl.Template(256, f)
	c := NewCollector(Options{})
	c.Decode(Packet{Data: bl.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())}), From: exp1, Received: t0}, nil, nil)
	ms := uint64(t0.UnixMilli())
	for i := range 30 {
		bl.Data(256, Values{}.Addr(ip("10.20.0.5")).Addr(ip("198.51.100.7")).U16(uint16(40000+i)).U16(443).U8(6).U8(0x1b).U8(0).
			U64(123456).U64(100).U64(ms-1000).U64(ms).U32(1).U32(3).U32(0xabcdef01).U64(uint64(i)))
	}
	pkt := bl.Message(Header{Domain: 1, ExportTime: uint32(t0.Unix())})
	var n int
	emit := func(*Record) { n++ }
	b.SetBytes(int64(len(pkt)))
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		c.Decode(Packet{Data: pkt, From: exp1, Received: t0.Add(time.Duration(i) * time.Microsecond)}, emit, nil)
	}
	b.ReportMetric(float64(n)/b.Elapsed().Seconds(), "records/s")
}
