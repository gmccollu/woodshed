package flow

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

var fileRules = []IEKey{{PENDocumentation, 3}, {0, 40003}}

// randRecord makes a record as the collector could have decoded it (the
// presence rules hold: start and end together, names only with their
// interface, totals only as the counters).
func randRecord(rnd *rand.Rand, names map[uint32]string) Record {
	r := Record{Received: 1_790_000_000_000 + rnd.Int64N(1e9), Domain: uint32(rnd.IntN(3))}
	pick := func() bool { return rnd.IntN(2) == 0 }
	addr := func() netip.Addr {
		if pick() {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], rnd.Uint32())
			return netip.AddrFrom4(b)
		}
		var b [16]byte
		binary.BigEndian.PutUint64(b[:], 0x20010db8_00000000|rnd.Uint64()>>32)
		binary.BigEndian.PutUint64(b[8:], rnd.Uint64())
		return netip.AddrFrom16(b)
	}
	set := func(bit uint64, f func()) {
		if pick() {
			r.Has |= bit
			f()
		}
	}
	set(HasSrc, func() { r.Src = addr() })
	set(HasDst, func() { r.Dst = addr() })
	set(HasSrcPort, func() { r.SrcPort = uint16(rnd.Uint32()) })
	set(HasDstPort, func() { r.DstPort = uint16(rnd.Uint32()) })
	set(HasProto, func() { r.Proto = uint8(rnd.Uint32()) })
	set(HasTCPFlags, func() { r.TCPFlags = uint16(rnd.Uint32() & 0x1ff) })
	set(HasToS, func() { r.ToS = uint8(rnd.Uint32()) })
	set(HasBytes, func() { r.Bytes = rnd.Uint64() })
	set(HasPackets, func() { r.Packets = rnd.Uint64() })
	if r.Has&(HasBytes|HasPackets) != 0 && pick() {
		r.Has |= HasTotals
	}
	set(HasInIf, func() { r.InIf = uint32(rnd.IntN(4)) })
	set(HasOutIf, func() { r.OutIf = uint32(rnd.IntN(4)) })
	set(HasSrcAS, func() { r.SrcAS = rnd.Uint32() })
	set(HasDstAS, func() { r.DstAS = rnd.Uint32() })
	set(HasNextHop, func() { r.NextHop = addr() })
	set(HasVLAN, func() { r.VLAN = uint16(rnd.Uint32()) })
	set(HasDirection, func() { r.Direction = uint8(rnd.Uint32()) })
	set(HasEndReason, func() { r.EndReason = uint8(rnd.Uint32()) })
	set(HasFwEvent, func() { r.FwEvent = uint8(rnd.IntN(6)) })
	set(HasNatEvent, func() { r.NatEvent = uint8(rnd.IntN(19)) })
	set(HasPostNATSrc, func() { r.PostNATSrc = addr() })
	set(HasPostNATDst, func() { r.PostNATDst = addr() })
	set(HasPostNATSrcPort, func() { r.PostNATSrcPort = uint16(rnd.Uint32()) })
	set(HasPostNATDstPort, func() { r.PostNATDstPort = uint16(rnd.Uint32()) })
	set(HasInitiatorBytes, func() { r.InitiatorBytes = rnd.Uint64() })
	set(HasResponderBytes, func() { r.ResponderBytes = rnd.Uint64() })
	set(HasInitiatorPackets, func() { r.InitiatorPackets = rnd.Uint64() })
	set(HasResponderPackets, func() { r.ResponderPackets = rnd.Uint64() })
	set(HasRevBytes, func() { r.RevBytes = rnd.Uint64() })
	set(HasRevPackets, func() { r.RevPackets = rnd.Uint64() })
	switch rnd.IntN(4) {
	case 1:
		r.Sampling = 1
	case 2:
		r.Sampling = uint32(rnd.IntN(10000) + 2)
	}
	// Interface names, the same table for both sides; sometimes renamed.
	for _, x := range []struct {
		bit, nameBit uint64
		ifx          uint32
		name         *string
	}{{HasInIf, HasInIfName, r.InIf, &r.InIfName}, {HasOutIf, HasOutIfName, r.OutIf, &r.OutIfName}} {
		if !r.Is(x.bit) {
			continue
		}
		if rnd.IntN(8) == 0 {
			if pick() {
				names[x.ifx] = "if" + string(rune('a'+rnd.IntN(26)))
			} else {
				delete(names, x.ifx)
			}
		}
	}
	for _, x := range []struct {
		bit, nameBit uint64
		ifx          uint32
		name         *string
	}{{HasInIf, HasInIfName, r.InIf, &r.InIfName}, {HasOutIf, HasOutIfName, r.OutIf, &r.OutIfName}} {
		if n, ok := names[x.ifx]; ok && r.Is(x.bit) {
			*x.name = n
			r.Has |= x.nameBit
		}
	}
	// Extras: enterprise, IANA (not the time forms) and reverse IEs.
	for range rnd.IntN(4) {
		e := Extra{Value: make([]byte, rnd.IntN(12))}
		for i := range e.Value {
			e.Value[i] = byte(rnd.Uint32())
		}
		switch rnd.IntN(4) {
		case 0:
			e.PEN, e.ID = 0, uint16(400+rnd.IntN(100))
		case 1:
			e.PEN, e.ID = PENReverse, uint16(1+rnd.IntN(300))
		case 2:
			// A flow v9 vendor-range type (PEN 0, 32768–65535).
			e.PEN, e.ID = 0, uint16(32768+rnd.IntN(32768))
			if e.ID == 40003 {
				e.ID = 40004
			}
		default:
			e.PEN, e.ID = uint32(1+rnd.IntN(40000)), uint16(rnd.IntN(32768))
			if e.PEN == PENDocumentation && e.ID == 3 {
				e.ID = 4
			}
		}
		r.Extras = append(r.Extras, e)
	}
	if pick() {
		v := []byte("deny-telnet")
		if pick() {
			v = []byte{0, 0, byte(rnd.Uint32()), byte(rnd.Uint32())}
		}
		k := fileRules[rnd.IntN(len(fileRules))] // the IPFIX form or the v9 one
		r.Extras = append(r.Extras, Extra{PEN: k.PEN, ID: k.ID, Value: v})
		r.RuleID, r.Has = RuleIDText(v, pick()), r.Has|HasRuleID
	}
	// Times: the exporter's, none (received), or a skewed exporter's.
	r.Start = r.Received - rnd.Int64N(600000)
	r.End = r.Start + rnd.Int64N(600000)
	r.Has |= HasStart | HasEnd
	if pick() {
		r.EventTime, r.Has = r.End-rnd.Int64N(1000), r.Has|HasEventTime
	}
	switch rnd.IntN(4) {
	case 0:
		r.Start, r.End, r.TimeSource = r.Received, r.Received, TimeReceived
		r.Has &^= HasEventTime
		r.EventTime = 0
	case 1:
		skewToReceived(&r, r.Received)
	}
	return r
}

func recordsEqual(a, b *Record) bool {
	x, y := *a, *b
	for _, r := range []*Record{&x, &y} {
		r.Status, r.ExporterPort, r.Version, r.TemplateID, r.Template, r.Extras = 0, 0, 0, 0, nil, nil
	}
	return reflect.DeepEqual(x, y) && extrasEqual(a.Extras, b.Extras)
}

func roundTrip(t testing.TB, recs []Record) {
	var buf bytes.Buffer
	fw := NewFileWriter(&buf, FileOptions{Version: "2.0.0-test", ExportTime: t0})
	for i := range recs {
		if err := fw.Write(&recs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	byDom := map[uint32][]Record{}
	for _, r := range recs {
		byDom[r.Domain] = append(byDom[r.Domain], r)
	}
	got := map[uint32][]Record{}
	if err := ReadFile(bytes.NewReader(buf.Bytes()), FileReadOptions{RuleIDIEs: fileRules}, func(r *Record) {
		got[r.Domain] = append(got[r.Domain], *r)
	}); err != nil {
		t.Fatal(err)
	}
	for d, want := range byDom {
		g := got[d]
		if len(g) != len(want) {
			t.Fatalf("domain %d: %d records back, wrote %d", d, len(g), len(want))
		}
		for i := range want {
			if !recordsEqual(&g[i], &want[i]) {
				t.Fatalf("domain %d record %d:\n got %+v\nwant %+v", d, i, g[i], want[i])
			}
		}
	}
}

func TestIPFIXFileRoundTrip(t *testing.T) {
	// Records decoded off the wire: v5, v9 with names and sampling, every IPFIX column, a skewed exporter.
	c := NewCollector(Options{RuleIDIEs: fileRules})
	var s sink
	s.decode(c, EncodeV5(V5Header{SysUptime: 5000, UnixSecs: uint32(t0.Unix()), SamplingInterval: 10},
		[]V5Record{{Src: ip("10.0.0.1"), Dst: ip("10.0.0.2"), Packets: 1, Bytes: 60, First: 1000, Last: 4000, Proto: 17}}), exp1, t0)
	b := NewBuilder(IPFIX)
	f, v := ipfixAll()
	f = append(f, TemplateField{PEN: PENDocumentation, ID: 3, Length: 4})
	v = v.U32(1234)
	b.OptionsTemplate(299, 1, []TemplateField{{ID: ieInIf, Length: 4}, {ID: ieIfName, Length: Varlen}})
	b.Data(299, Values{}.U32(3).Var([]byte("outside")))
	b.Template(300, f)
	b.Data(300, v)
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 4}), exp2, t0)
	b.Template(301, []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: ieEndMs, Length: 8}})
	b.Data(301, Values{}.Addr(ip("10.9.9.9")).U64(uint64(t0.Add(-5*time.Hour).UnixMilli())))
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Add(-5 * time.Hour).Unix()), Domain: 5}), exp1b, t0)
	if len(s.recs) != 3 || s.recs[1].InIfName != "outside" || s.recs[1].RuleID != "1234" || s.recs[2].TimeSource != TimeReceived {
		t.Fatalf("setup: %d records %+v", len(s.recs), s.recs)
	}
	roundTrip(t, s.recs)

	rnd := rand.New(rand.NewPCG(1, 2))
	names := map[uint32]string{}
	var recs []Record
	for range 3000 {
		recs = append(recs, randRecord(rnd, names))
	}
	roundTrip(t, recs)
}

// walkIPFIX reads an IPFIX file as an independent reader would, strictly by
// RFC 7011 and nothing of Woodshed's: every enterprise-bit field is followed by
// its enterprise number, every data set is consumed exactly by its template's
// records (with less than one record of padding), and every message adds up.
// It returns the data records per template, options included.
func walkIPFIX(t *testing.T, b []byte) (records int, enterprise map[[2]uint32]int) {
	t.Helper()
	type tf struct{ length uint16 }
	tmpls := map[[2]uint32][]tf{}
	enterprise = map[[2]uint32]int{}
	for len(b) > 0 {
		if len(b) < 16 || binary.BigEndian.Uint16(b) != 10 {
			t.Fatalf("not an IPFIX message header: % x", b[:min(len(b), 16)])
		}
		ml := int(binary.BigEndian.Uint16(b[2:]))
		if ml < 16 || ml > len(b) {
			t.Fatalf("message length %d of %d", ml, len(b))
		}
		dom := binary.BigEndian.Uint32(b[12:])
		m := b[16:ml]
		for len(m) > 0 {
			if len(m) < 4 {
				t.Fatalf("%d bytes left in a message", len(m))
			}
			sid, sl := binary.BigEndian.Uint16(m), int(binary.BigEndian.Uint16(m[2:]))
			if sl < 4 || sl > len(m) {
				t.Fatalf("set %d length %d of %d", sid, sl, len(m))
			}
			body := m[4:sl]
			switch {
			case sid == 2 || sid == 3:
				for len(body) >= 4 {
					tid, n := binary.BigEndian.Uint16(body), int(binary.BigEndian.Uint16(body[2:]))
					body = body[4:]
					if sid == 3 {
						body = body[2:] // scope field count
					}
					var fs []tf
					for range n {
						if len(body) < 4 {
							t.Fatalf("template %d cut short", tid)
						}
						id, l := binary.BigEndian.Uint16(body), binary.BigEndian.Uint16(body[2:])
						body = body[4:]
						if id&0x8000 != 0 {
							if len(body) < 4 {
								t.Fatalf("template %d: enterprise bit without an enterprise number", tid)
							}
							enterprise[[2]uint32{binary.BigEndian.Uint32(body), uint32(id & 0x7fff)}]++
							body = body[4:]
						}
						fs = append(fs, tf{l})
					}
					tmpls[[2]uint32{dom, uint32(tid)}] = fs
				}
				if len(body) != 0 {
					t.Fatalf("%d bytes after the templates", len(body))
				}
			case sid >= 256:
				fs, ok := tmpls[[2]uint32{dom, uint32(sid)}]
				if !ok {
					t.Fatalf("data set %d before its template", sid)
				}
				minLen := 0
				for _, f := range fs {
					if f.length == 65535 {
						minLen++
					} else {
						minLen += int(f.length)
					}
				}
				for len(body) >= max(minLen, 1) {
					for _, f := range fs {
						l := int(f.length)
						if f.length == 65535 {
							if len(body) < 1 {
								t.Fatalf("set %d: a variable-length field cut short", sid)
							}
							l, body = int(body[0]), body[1:]
							if l == 255 {
								if len(body) < 2 {
									t.Fatalf("set %d: a long variable-length field cut short", sid)
								}
								l, body = int(binary.BigEndian.Uint16(body)), body[2:]
							}
						}
						if len(body) < l {
							t.Fatalf("set %d: a record runs past its set (field of %d, %d left)", sid, l, len(body))
						}
						body = body[l:]
					}
					records++
				}
				if len(body) != 0 {
					t.Fatalf("set %d: %d bytes left over", sid, len(body))
				}
			default:
				t.Fatalf("set ID %d", sid)
			}
			m = m[sl:]
		}
		b = b[ml:]
	}
	return records, enterprise
}

// Flow v9 records with vendor-range field types (the generator's 40001–40003)
// written to the IPFIX file: every enterprise-bit field has its enterprise
// number (0, VendorRangePEN), an independent strict reader reads every record,
// and our reader gives back every record and field, rule_id included.
func TestIPFIXFileV9VendorFields(t *testing.T) {
	c := NewCollector(Options{RuleIDIEs: fileRules})
	var s sink
	b := NewBuilder(V9)
	b.Template(256, []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: ieDstV4, Length: 4}, {ID: ieSrcPort, Length: 2},
		{ID: ieDstPort, Length: 2}, {ID: ieProto, Length: 1}, {ID: ieFwEvent, Length: 1}, {ID: ieObsTimeMs, Length: 8},
		{ID: 40001, Length: 4}, {ID: 40002, Length: 8}, {ID: 40003, Length: 4}, {ID: 65535, Length: 2}, {ID: 32768, Length: 1}})
	const n = 2000
	for i := range n {
		b.Data(256, Values{}.Addr(ip("10.0.0.1")).Addr(ip("192.0.2.9")).U16(uint16(1024+i)).U16(443).U8(6).U8(uint8(1+i%5)).
			U64(uint64(t0.UnixMilli())-uint64(i)).U32(0x0badc0de).U64(uint64(i)).U32(uint32(7+i%3)).U16(uint16(i)).U8(9))
		if b.Records() == 30 || i == n-1 {
			s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: uint32(i), Domain: 3, SysUptime: 1000}), exp1, t0)
		}
	}
	if len(s.recs) != n || len(s.raws) != 0 {
		t.Fatalf("setup: %d records, %d raw", len(s.recs), len(s.raws))
	}
	if r := s.recs[0]; r.RuleID != "7" || len(r.Extras) != 5 || r.Extras[0].PEN != 0 || r.Extras[0].ID != 40001 {
		t.Fatalf("setup: %+v", r)
	}
	var buf bytes.Buffer
	fw := NewFileWriter(&buf, FileOptions{Version: "2.0.0-test", ExportTime: t0})
	for i := range s.recs {
		if err := fw.Write(&s.recs[i]); err != nil {
			t.Fatal(err)
		}
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	// The bug: "9c43 ffff" with no enterprise number after it.
	if !bytes.Contains(buf.Bytes(), []byte{0x9c, 0x43, 0, 4, 0, 0, 0, 0}) {
		t.Fatal("type 40003 isn't written as the enterprise bit, 7235, length 4 and enterprise number 0")
	}
	recs, ent := walkIPFIX(t, buf.Bytes())
	if recs != n+1 { // + the note
		t.Fatalf("an independent reader read %d records, want %d", recs, n+1)
	}
	for _, id := range []uint32{40001, 40002, 40003, 65535, 32768} {
		if ent[[2]uint32{VendorRangePEN, id & 0x7fff}] == 0 {
			t.Errorf("type %d isn't in a template as enterprise number 0", id)
		}
	}
	roundTrip(t, s.recs)
	// The reader fills rule_id from the v9 form of rule_id_ies.
	var got []Record
	if err := ReadFile(bytes.NewReader(buf.Bytes()), FileReadOptions{RuleIDIEs: []IEKey{{0, 40003}}}, func(r *Record) { got = append(got, *r) }); err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if got[i].RuleID != s.recs[i].RuleID || got[i].RuleID == "" {
			t.Fatalf("record %d: rule_id %q, want %q", i, got[i].RuleID, s.recs[i].RuleID)
		}
	}
}

// An IPFIX template field with the enterprise bit and enterprise number 0 is
// a v9 vendor-range type: the same key as flow v9's, so a rule_id_ies entry
// "0:40003" names it either way, and the builder writes it that way.
func TestIPFIXEnterpriseZeroIsV9Type(t *testing.T) {
	c := NewCollector(Options{RuleIDIEs: []IEKey{{0, 40003}}})
	var s sink
	b := NewBuilder(IPFIX)
	b.Template(300, []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: 40003, Length: 4}, {PEN: PENDocumentation, ID: 40003 & 0x7fff, Length: 4}})
	b.Data(300, Values{}.Addr(ip("10.1.1.1")).U32(42).U32(43))
	msg := b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1})
	if !bytes.Contains(msg, []byte{0x9c, 0x43, 0, 4, 0, 0, 0, 0}) || !bytes.Contains(msg, []byte{0x9c, 0x43, 0, 4, 0, 0, 0x7e, 0xd9}) {
		t.Fatalf("template % x", msg)
	}
	s.decode(c, msg, exp2, t0)
	if len(s.recs) != 1 {
		t.Fatalf("%d records, %d raw", len(s.recs), len(s.raws))
	}
	r := s.recs[0]
	if r.RuleID != "42" || !extrasEqual(r.Extras, []Extra{{0, 40003, []byte{0, 0, 0, 42}}, {PENDocumentation, 7235, []byte{0, 0, 0, 43}}}) {
		t.Fatalf("record %+v", r)
	}
}

func TestIPFIXFileNoteAndLimits(t *testing.T) {
	var buf bytes.Buffer
	fw := NewFileWriter(&buf, FileOptions{Version: "2.0.0", ExportTime: t0})
	big := Record{Has: HasStart | HasEnd, Start: 1, End: 2, Received: 3}
	for range 40 {
		big.Extras = append(big.Extras, Extra{PEN: 9, ID: 1, Value: bytes.Repeat([]byte{7}, 2000)})
	}
	if err := fw.Write(&big); err != nil {
		t.Fatal(err)
	}
	for range 5000 {
		r := Record{Has: HasStart | HasEnd | HasBytes, Start: 1, End: 2, Bytes: 9, Received: 3}
		if err := fw.Write(&r); err != nil {
			t.Fatal(err)
		}
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	if fw.Truncated != 1 || fw.Records != 5001 {
		t.Errorf("truncated %d records %d", fw.Truncated, fw.Records)
	}
	if !bytes.Contains(buf.Bytes(), []byte(FileNote("2.0.0"))) || !strings.Contains(FileNote("2.0.0"), "not captured off the wire") {
		t.Error("the note is missing")
	}
	// Every message is within the limit and the sequence counts records.
	b := buf.Bytes()
	var seq uint32
	n := 0
	for len(b) > 0 {
		l := int(binary.BigEndian.Uint16(b[2:]))
		if l > maxMessage || l < ipfixHeader {
			t.Fatalf("message of %d bytes", l)
		}
		if got := binary.BigEndian.Uint32(b[8:]); got < seq {
			t.Fatalf("sequence went back: %d < %d", got, seq)
		} else {
			seq = got
		}
		b = b[l:]
		n++
	}
	if n < 2 {
		t.Errorf("%d messages", n)
	}
	count := 0
	if err := ReadFile(bytes.NewReader(buf.Bytes()), FileReadOptions{}, func(*Record) { count++ }); err != nil || count != 5001 {
		t.Errorf("read back %d, %v", count, err)
	}
	// Garbage is an error, not a panic.
	if err := ReadFile(bytes.NewReader([]byte{0, 10, 0, 20, 1, 2}), FileReadOptions{}, func(*Record) {}); err == nil {
		t.Error("a truncated file read without error")
	}
}

// FuzzIPFIXFile re-reads what the IPFIX file writer wrote: every column
// equal. It also reads the input itself as a file (no panic).
func FuzzIPFIXFile(f *testing.F) {
	f.Add([]byte("seed"), uint16(10))
	f.Add([]byte{0, 10, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, uint16(1))
	f.Fuzz(func(t *testing.T, data []byte, n uint16) {
		_ = ReadFile(bytes.NewReader(data), FileReadOptions{RuleIDIEs: fileRules}, func(*Record) {})
		h := fnv.New64a()
		h.Write(data)
		rnd := rand.New(rand.NewPCG(h.Sum64(), uint64(n)))
		names := map[uint32]string{}
		recs := make([]Record, int(n%300)+1)
		for i := range recs {
			recs[i] = randRecord(rnd, names)
		}
		roundTrip(t, recs)
	})
}
