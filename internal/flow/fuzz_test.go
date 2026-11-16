package flow

import (
	"encoding/binary"
	"slices"
	"testing"
	"time"
)

// checkDecode decodes one datagram and checks the accounting: every record
// and raw set is counted, raw data is kept, and the buffer stays within its
// limits.
func checkDecode(t *testing.T, c *Collector, data []byte, at time.Time) {
	var recs, raws, malformed, noTmpl int
	before := c.Stats(at)
	c.Decode(Packet{Data: data, From: exp1, Received: at}, func(r *Record) {
		recs++
		if !r.Is(HasStart|HasEnd) || r.End < r.Start {
			t.Fatalf("record without a time span: %+v", r)
		}
	}, func(r *RawSet) {
		raws++
		switch r.Status {
		case StatusMalformed:
			malformed++
		case StatusNoTemplate:
			noTmpl++
		default:
			t.Fatalf("raw set with status %v", r.Status)
		}
	})
	after := c.Stats(at)
	var b, a Counts
	for _, s := range before {
		b.add(s.Counts)
	}
	for _, s := range after {
		a.add(s.Counts)
	}
	if a.Records-b.Records != int64(recs) || a.Malformed-b.Malformed != int64(malformed) || a.NoTemplate-b.NoTemplate != int64(noTmpl) {
		t.Fatalf("counts moved %+v -> %+v for %d records, %d malformed, %d no_template", b, a, recs, malformed, noTmpl)
	}
	if c.PendingBytes() > c.opts.PendingBytes {
		t.Fatalf("pending %d over %d", c.PendingBytes(), c.opts.PendingBytes)
	}
	if c.nTmpl > c.opts.MaxTemplates || c.tmplBytes > maxTemplateBytes || c.metaBytes > maxMetaBytes {
		t.Fatalf("cache over its bounds: %d templates, %d bytes, %d meta", c.nTmpl, c.tmplBytes, c.metaBytes)
	}
}

func fuzzCollector() *Collector {
	return NewCollector(Options{PendingBytes: 64 << 10, PendingPerExporter: 16 << 10, MaxTemplates: 64, MaxTemplatesPerKey: 16})
}

func FuzzFlowV5(f *testing.F) {
	f.Add(EncodeV5(V5Header{SysUptime: 9, UnixSecs: 1e9, SamplingInterval: 0x4064},
		[]V5Record{{Src: ip("10.0.0.1"), Dst: ip("10.0.0.2"), First: 1, Last: 5}}))
	f.Add([]byte{0, 5, 0, 30})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) >= 2 {
			data[0], data[1] = 0, 5
		}
		checkDecode(t, fuzzCollector(), data, t0)
	})
}

func seedV9() [][]byte {
	b := NewBuilder(V9)
	b.Template(256, []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: ieStartUptime, Length: 4}, {ID: ieOctetDelta, Length: 4}})
	b.OptionsTemplate(257, 1, []TemplateField{{ID: 2, Length: 4}, {ID: ieIfName, Length: 6}})
	b.Data(257, Values{}.U32(1).Bytes([]byte("eth0\x00\x00")))
	b.Data(256, Values{}.Addr(ip("10.0.0.1")).U32(5).U32(100))
	return [][]byte{b.Message(Header{SysUptime: 10, ExportTime: 1e9, Seq: 1, Domain: 2})}
}

func FuzzFlowV9(f *testing.F) {
	for _, s := range seedV9() {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b []byte) {
		c := fuzzCollector()
		for i, d := range [][]byte{a, b} {
			if len(d) >= 2 {
				d[0], d[1] = 0, 9
			}
			checkDecode(t, c, d, t0.Add(time.Duration(i)*time.Second))
		}
		c.Expire(t0.Add(time.Hour), func(*RawSet) {})
		if c.PendingBytes() != 0 {
			t.Fatal("pending data left after the timeout")
		}
	})
}

func seedIPFIX() []byte {
	b := NewBuilder(IPFIX)
	f, v := ipfixAll()
	b.Template(300, f)
	b.OptionsTemplate(301, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieSysInitMs, Length: 8}})
	b.Data(301, Values{}.U32(1).U64(1))
	b.Data(300, v)
	b.Withdraw(300, false)
	return b.Message(Header{ExportTime: 1e9, Domain: 1})
}

func FuzzIPFIX(f *testing.F) {
	s := seedIPFIX()
	f.Add(s, s[:len(s)/2])
	f.Fuzz(func(t *testing.T, a, b []byte) {
		c := fuzzCollector()
		for i, d := range [][]byte{a, b} {
			if len(d) >= 4 {
				d[0], d[1] = 0, 10
				binary.BigEndian.PutUint16(d[2:], uint16(len(d)))
			}
			checkDecode(t, c, d, t0.Add(time.Duration(i)*time.Second))
		}
	})
}

// FuzzTemplates runs random sequences of template definitions, withdrawals
// and data against one cache: every record must be decoded with the
// definition in force for its template ID (no stale decode after a
// replacement), data for a defined ID decodes at once, and no definition is
// ever changed after the fact.
func FuzzTemplates(f *testing.F) {
	f.Add([]byte{0, 1, 3, 2, 0, 1, 2, 0, 4, 1, 1, 3, 0, 2, 1, 3, 0})
	f.Add([]byte{3, 0, 0, 1, 2, 1, 0, 2, 3, 0})
	kinds := []TemplateField{{ID: ieOctetDelta, Length: 4}, {ID: ieOctetDelta, Length: 8}, {ID: ieSrcV4, Length: 4},
		{ID: iePacketDelta, Length: 2}, {ID: ieProto, Length: 1}, {PEN: 32473, ID: 1, Length: Varlen}, {ID: 96, Length: Varlen}}
	f.Fuzz(func(t *testing.T, prog []byte) {
		c := NewCollector(Options{TemplateTimeout: time.Hour})
		b := NewBuilder(IPFIX)
		model := map[uint16][]TemplateField{}
		type seen struct {
			t      *Template
			fields []TemplateField
		}
		var defs []seen
		at := t0
		next := func() byte {
			if len(prog) == 0 {
				return 0
			}
			x := prog[0]
			prog = prog[1:]
			return x
		}
		for steps := 0; len(prog) > 0 && steps < 200; steps++ {
			op := next() % 4
			id := 256 + uint16(next()%6)
			at = at.Add(time.Millisecond)
			var want []TemplateField
			switch op {
			case 0: // define (or replace)
				n := int(next()%5) + 1
				fs := make([]TemplateField, n)
				for i := range fs {
					fs[i] = kinds[int(next())%len(kinds)]
				}
				b.Template(id, fs)
				model[id] = fs
			case 1: // withdraw
				b.Withdraw(id, false)
				delete(model, id)
			case 2: // withdraw all
				b.Withdraw(2, false)
				clear(model)
			case 3: // data
				fs, ok := model[id]
				if !ok {
					fs = []TemplateField{kinds[int(next())%len(kinds)]}
				}
				var v Values
				for _, f := range fs {
					if f.Length == Varlen {
						v = v.Var([]byte{next()})
					} else {
						v = append(v, make([]byte, f.Length)...)
					}
				}
				b.Data(id, v)
				if ok {
					want = fs
				}
			}
			got := 0
			c.Decode(Packet{Data: b.Message(Header{Domain: 1, ExportTime: uint32(at.Unix())}), From: exp1, Received: at},
				func(r *Record) {
					fs, ok := model[r.TemplateID]
					if !ok || !slices.Equal(r.Template.Fields, fs) {
						t.Fatalf("record of template %d decoded with %v, in force %v (%v)", r.TemplateID, r.Template.Fields, fs, ok)
					}
					defs = append(defs, seen{r.Template, slices.Clone(r.Template.Fields)})
					got++
				}, func(r *RawSet) {
					// Parked data that doesn't fit the definition that came may
					// break off; data for a defined template never does.
					if want != nil {
						t.Fatalf("raw set %+v", r)
					}
				})
			if want != nil && got != 1 {
				t.Fatalf("data for a defined template decoded %d records", got)
			}
		}
		for _, d := range defs {
			if !slices.Equal(d.t.Fields, d.fields) {
				t.Fatal("a template definition changed after records used it")
			}
		}
	})
}
