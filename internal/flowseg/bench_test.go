package flowseg

import (
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// realistic is plausible traffic for one exporter: about 300 inside hosts
// talking to a few thousand outside ones, port skew (443, 53, 80, …),
// mostly IPv4 and TCP, and a share of event-style records (created, deleted,
// denied with NAT and initiator/responder totals), arriving at rate a second.
func realistic(seed uint64, n, rate int) []flow.Record {
	r := rand.New(rand.NewPCG(seed, 99))
	tmpl := testTemplates[0]
	out := make([]flow.Record, n)
	recv := testHour.UnixMilli()
	ports := []uint16{443, 443, 443, 443, 443, 53, 53, 80, 22, 123, 445, 3389, 8080}
	for i := range out {
		recv = testHour.UnixMilli() + int64(i)*1000/int64(rate)
		in := netip.AddrFrom4([4]byte{10, 20, byte(r.IntN(2)), byte(r.IntN(150))})
		ext := netip.AddrFrom4([4]byte{198, 51, byte(r.IntN(16)), byte(r.IntN(200))})
		if r.IntN(20) == 0 {
			ext = netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, byte(r.IntN(4)), 15: byte(r.IntN(200))})
		}
		rec := flow.Record{Received: recv, Sampling: 1, Domain: 1, Version: flow.IPFIX, ExporterPort: 40000,
			Template: tmpl, TemplateID: tmpl.ID}
		rec.Has = flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort |
			flow.HasProto | flow.HasPackets | flow.HasBytes | flow.HasInIf | flow.HasOutIf | flow.HasTCPFlags
		rec.Src, rec.Dst = in, ext
		rec.SrcPort = uint16(32768 + r.IntN(28000))
		rec.DstPort = ports[r.IntN(len(ports))]
		rec.Proto = 6
		if rec.DstPort == 53 || rec.DstPort == 123 {
			rec.Proto = 17
		}
		if r.IntN(2) == 0 { // the reply direction
			rec.Src, rec.Dst, rec.SrcPort, rec.DstPort = rec.Dst, rec.Src, rec.DstPort, rec.SrcPort
		}
		rec.End = recv - int64(r.IntN(2000))
		rec.Start = rec.End - int64(r.ExpFloat64()*20000)
		rec.Packets = 1 + uint64(r.ExpFloat64()*30)
		rec.Bytes = rec.Packets * uint64(60+r.IntN(1400))
		rec.InIf, rec.OutIf = uint32(1+r.IntN(4)), uint32(1+r.IntN(4))
		rec.TCPFlags = []uint16{0x1b, 0x1b, 0x12, 0x02, 0x11, 0x14}[r.IntN(6)]
		if r.IntN(5) == 0 { // event style
			rec.Has |= flow.HasFwEvent | flow.HasEventTime | flow.HasPostNATSrc | flow.HasPostNATSrcPort | flow.HasNatEvent
			rec.FwEvent = []uint8{flow.FwCreated, flow.FwDeleted, flow.FwDeleted, flow.FwDenied}[r.IntN(4)]
			rec.EventTime = rec.End
			rec.PostNATSrc = netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + r.IntN(4))})
			rec.PostNATSrcPort = uint16(1024 + r.IntN(60000))
			rec.NatEvent = 4
			if rec.FwEvent == flow.FwDenied {
				rec.Has &^= flow.HasPackets | flow.HasBytes | flow.HasStart | flow.HasEnd | flow.HasPostNATSrc |
					flow.HasPostNATSrcPort | flow.HasNatEvent
			} else {
				rec.Has |= flow.HasInitiatorBytes | flow.HasResponderBytes | flow.HasTotals
				rec.InitiatorBytes, rec.ResponderBytes = rec.Bytes, rec.Bytes*3
			}
		}
		out[i] = rec
	}
	return out
}

const benchRate = 50000

// BenchmarkEncodeBlock encodes one second of a 50,000 records/s exporter as a
// block; ns/rec × 50,000 is the encode CPU per second at that rate.
func BenchmarkEncodeBlock(b *testing.B) {
	recs := realistic(1, benchRate, benchRate)
	meta := make([]rowMeta, len(recs))
	for i := range meta {
		meta[i].tmpl = 1
	}
	var e encoder
	var size int
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		body, _ := e.encodeBlock(recs, meta)
		size = len(body) + prefixLen
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(recs)), "ns/rec")
	b.ReportMetric(float64(size)/float64(len(recs)), "B/rec")
}

// BenchmarkWriter is the whole write path: Append and a Flush a second into
// a file, 60 s of a 50,000 records/s exporter; B/rec is the closed file's
// size (footer included) per record.
func BenchmarkWriter(b *testing.B) {
	recs := realistic(2, 60*benchRate, benchRate)
	var bytesPer float64
	for i := 0; i < b.N; i++ {
		path := filepath.Join(b.TempDir(), "w.wsf")
		w, err := Create(path, "10.1.0.1", testHour, "bench")
		if err != nil {
			b.Fatal(err)
		}
		for j := range recs {
			w.Append(&recs[j])
			if (j+1)%benchRate == 0 {
				w.Flush()
				w.TakeMinutes()
			}
		}
		f, err := w.Close()
		if err != nil {
			b.Fatal(err)
		}
		_ = f
		st, err := os.Stat(path)
		if err != nil {
			b.Fatal(err)
		}
		bytesPer = float64(st.Size()) / float64(len(recs)) // footer included
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(len(recs)), "ns/rec")
	b.ReportMetric(bytesPer, "B/rec")
}

func benchDecode(b *testing.B, cols Cols) {
	recs := realistic(3, benchRate, benchRate)
	path, _ := writeSegment(b, b.TempDir(), recs, nil, 0)
	r, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	var blk Block
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := r.Decode(0, cols, &blk); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)*float64(len(recs))/b.Elapsed().Seconds()/1e6, "Mrec/s")
}

// BenchmarkDecodeSrcBytes is top talkers' read: the source and bytes columns.
func BenchmarkDecodeSrcBytes(b *testing.B) { benchDecode(b, Cols(flow.HasSrc|flow.HasBytes)) }

// BenchmarkDecodeAll decodes every column (a search page, an export).
func BenchmarkDecodeAll(b *testing.B) { benchDecode(b, ColAll) }

// BenchmarkReadBlockRecords is ReadBlock's record form of every column.
func BenchmarkReadBlockRecords(b *testing.B) {
	recs := realistic(4, benchRate, benchRate)
	path, _ := writeSegment(b, b.TempDir(), recs, nil, 0)
	r, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	var buf []flow.Record
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf, err = r.ReadBlock(0, ColAll, buf)
		if err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(b.N)*float64(len(recs))/b.Elapsed().Seconds()/1e6, "Mrec/s")
}

// The realistic mix stores within the contract's 12–20 bytes a record or
// close to it; a regression that doubles it fails here.
func TestBytesPerRecordRealistic(t *testing.T) {
	recs := realistic(5, 5*benchRate/10, benchRate/10)
	path, f := writeSegment(t, t.TempDir(), recs, nil, benchRate/10)
	_ = path
	var on int64
	for _, b := range f.Blocks {
		on += b.Length
	}
	per := float64(on) / float64(len(recs))
	t.Logf("%.1f bytes/record in blocks (%d records at 5,000/s)", per, len(recs))
	if per > 30 {
		t.Fatalf("%.1f bytes/record", per)
	}
}
