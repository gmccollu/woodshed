package export

import (
	"bytes"
	"encoding/csv"
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// refFlowCSVRow is the row as encoding/csv writes FlowCSVRow (the encoder
// AppendFlowCSVRow replaced).
func refFlowCSVRow(r *flow.Record) []byte {
	var b bytes.Buffer
	cw := csv.NewWriter(&b)
	cw.UseCRLF = true
	_ = cw.Write(FlowCSVRow(r))
	cw.Flush()
	return b.Bytes()
}

var csvStrings = []string{"", "Gi0/1", "rule-7", "a,b", `q"uote`, " lead", "\tlead", "\u00a0nbsp", "\u3000wide", `\.`, `\.x`,
	"cr\rlf\n", "trail ", "ünï", "bad\xffutf8", "x<y>&z", "\x00ctl"}

func randCSVAddr(rng *rand.Rand) netip.Addr {
	switch rng.IntN(5) {
	case 0:
		return netip.AddrFrom4([4]byte{byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
	case 1:
		var b [16]byte
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		return netip.AddrFrom16(b)
	case 2:
		return netip.MustParseAddr("::ffff:192.0.2.1")
	case 3:
		return netip.MustParseAddr("fe80::1").WithZone([]string{"eth0", "a,b", " z"}[rng.IntN(3)])
	}
	return netip.Addr{}
}

func randCSVRecord(rng *rand.Rand) flow.Record {
	u64 := func() uint64 {
		switch rng.IntN(4) {
		case 0:
			return 0
		case 1:
			return ^uint64(0) - uint64(rng.IntN(3))
		}
		return rng.Uint64() >> rng.IntN(64)
	}
	ms := func() int64 {
		switch rng.IntN(6) {
		case 0:
			return 0
		case 1:
			return -int64(rng.IntN(1 << 40))
		case 2:
			return 253402300799999 + int64(rng.IntN(1000))
		}
		return 1794930766130 + int64(rng.IntN(1<<30))
	}
	str := func() string { return csvStrings[rng.IntN(len(csvStrings))] }
	return flow.Record{Has: rng.Uint64(), Received: ms(), Start: ms(), End: ms(), EventTime: ms(), Src: randCSVAddr(rng),
		Dst: randCSVAddr(rng), SrcPort: uint16(u64()), DstPort: uint16(u64()), Proto: uint8(u64()), TCPFlags: uint16(u64()),
		ToS: uint8(u64()), Packets: u64(), Bytes: u64(), InIf: uint32(u64()), OutIf: uint32(u64()), InIfName: str(), OutIfName: str(),
		SrcAS: uint32(u64()), DstAS: uint32(u64()), NextHop: randCSVAddr(rng), FwEvent: uint8(rng.IntN(8)), NatEvent: uint8(rng.IntN(20)),
		PostNATSrc: randCSVAddr(rng), PostNATDst: randCSVAddr(rng), PostNATSrcPort: uint16(u64()), PostNATDstPort: uint16(u64()),
		InitiatorBytes: u64(), ResponderBytes: u64(), InitiatorPackets: u64(), ResponderPackets: u64(), RevBytes: u64(),
		RevPackets: u64(), RuleID: str(), Sampling: []uint32{0, 1, 1000, ^uint32(0)}[rng.IntN(4)], Domain: uint32(u64()),
		Status: flow.Status(rng.IntN(6)), TimeSource: flow.TimeSource(rng.IntN(3))}
}

func TestAppendFlowCSVRowMatchesEncodingCSV(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 5))
	plain := 0
	for i := 0; i < 30000; i++ {
		rec := randCSVRecord(rng)
		if i < 2 {
			rec.Has = []uint64{0, ^uint64(0)}[i]
		}
		if i%3 == 0 { // most rows in a store need no quoting: exercise the plain path
			rec.InIfName, rec.OutIfName, rec.RuleID = "Gi0/1", "", "r1"
			rec.Src, rec.Dst, rec.NextHop = netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8::7"), netip.Addr{}
			rec.PostNATSrc, rec.PostNATDst = netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("::ffff:192.0.2.1")
		}
		want := refFlowCSVRow(&rec)
		got := AppendFlowCSVRow([]byte("prefix"), &rec)
		if string(got[:6]) != "prefix" || !bytes.Equal(got[6:], want) {
			t.Fatalf("record %d:\n got %q\nwant %q", i, got[6:], want)
		}
		if _, ok := appendFlowCSVPlain(nil, &rec); ok {
			plain++
		}
	}
	if plain < 5000 {
		t.Fatalf("only %d rows took the plain path", plain)
	}
}

func BenchmarkAppendFlowCSVRow(b *testing.B) {
	rec := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto |
		flow.HasTCPFlags | flow.HasBytes | flow.HasPackets | flow.HasInIf | flow.HasOutIf, Received: 1794930766130, Start: 1794930736268,
		End: 1794930766130, Src: netip.MustParseAddr("10.20.1.2"), Dst: netip.MustParseAddr("198.51.100.7"), SrcPort: 40000, DstPort: 443,
		Proto: 6, TCPFlags: 0x1b, Bytes: 123456, Packets: 99, InIf: 3, OutIf: 4, Sampling: 1, Domain: 1}
	b.Run("append", func(b *testing.B) {
		var buf []byte
		for b.Loop() {
			buf = AppendFlowCSVRow(buf[:0], &rec)
		}
	})
	b.Run("encoding-csv", func(b *testing.B) {
		for b.Loop() {
			_ = refFlowCSVRow(&rec)
		}
	})
}
