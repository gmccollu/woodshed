package flowseg

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

var testHour = time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)

var testTemplates = []*flow.Template{
	{Version: flow.IPFIX, ExporterPort: 40000, Domain: 1, ID: 256, Received: testHour.UnixMilli(),
		Fields: []flow.TemplateField{{ID: 8, Length: 4}, {ID: 12, Length: 4}, {ID: 1, Length: 8}, {PEN: 32473, ID: 1, Length: 65535}}},
	{Version: flow.V9, ExporterPort: 2001, Domain: 7, ID: 300, Options: true, ScopeCount: 1,
		Received: testHour.UnixMilli() + 5, Fields: []flow.TemplateField{{ID: 10, Length: 4}, {ID: 82, Length: 16}}},
}

// randAddr returns an IPv4 address from a small pool (realistic reuse) or,
// sometimes, an IPv6 one.
func randAddr(r *rand.Rand, hosts int) netip.Addr {
	if r.IntN(10) == 0 {
		var b [16]byte
		b[0], b[1], b[2], b[3] = 0x20, 0x01, 0x0d, 0xb8
		b[15] = byte(r.IntN(hosts))
		b[14] = byte(r.IntN(4))
		return netip.AddrFrom16(b)
	}
	h := r.IntN(hosts)
	return netip.AddrFrom4([4]byte{10, 20, byte(h >> 8), byte(h)})
}

// randRecord is a record with a random subset of every column (all of them
// when full).
func randRecord(r *rand.Rand, recv int64, full bool) flow.Record {
	pick := func() bool { return full || r.IntN(3) > 0 }
	rec := flow.Record{Received: recv, Sampling: uint32([]int{0, 1, 1000}[r.IntN(3)]), Domain: uint32(r.IntN(3)),
		ExporterPort: uint16(40000 + r.IntN(2)), Version: []uint8{flow.V5, flow.V9, flow.IPFIX}[r.IntN(3)],
		Status: flow.Status(r.IntN(2)), TimeSource: flow.TimeSource(r.IntN(2))}
	if pick() {
		rec.Template = testTemplates[r.IntN(len(testTemplates))]
		rec.TemplateID = rec.Template.ID
	}
	set := func(bit uint64) bool {
		if pick() {
			rec.Has |= bit
			return true
		}
		return false
	}
	end := recv - int64(r.IntN(30000))
	if set(flow.HasEnd) {
		rec.End = end
	}
	if set(flow.HasStart) {
		rec.Start = end - int64(r.IntN(600000))
	}
	if set(flow.HasEventTime) {
		rec.EventTime = end - int64(r.IntN(100))
	}
	addrs := []struct {
		bit uint64
		p   *netip.Addr
	}{{flow.HasSrc, &rec.Src}, {flow.HasDst, &rec.Dst}, {flow.HasNextHop, &rec.NextHop},
		{flow.HasPostNATSrc, &rec.PostNATSrc}, {flow.HasPostNATDst, &rec.PostNATDst}}
	for _, a := range addrs {
		if set(a.bit) {
			*a.p = randAddr(r, 300)
		}
	}
	for id := 0; id < 48; id++ {
		bit := uint64(1) << id
		switch kindOf[id] {
		case kindUint, kindByte:
			if set(bit) {
				mx := uintMax(id)
				v := r.Uint64() % (min(mx, 1<<40) + 1)
				if r.IntN(4) == 0 {
					v = mx
				}
				setUint(&rec, id, v)
			}
		case kindString:
			if set(bit) {
				setString(&rec, id, fmt.Sprintf("s%d", r.IntN(5)))
			}
		case kindFlag:
			set(bit)
		}
	}
	if pick() {
		n := 1 + r.IntN(3)
		for i := 0; i < n; i++ {
			v := make([]byte, r.IntN(6))
			for j := range v {
				v[j] = byte(r.IntN(256))
			}
			rec.Extras = append(rec.Extras, flow.Extra{PEN: uint32(r.IntN(2)) * 32473, ID: uint16(r.IntN(70000)), Value: v})
		}
	}
	return rec
}

// normalize is what a record reads back as.
func normalize(r flow.Record) flow.Record {
	for _, id := range []uint64{flow.HasSrc, flow.HasDst, flow.HasNextHop, flow.HasPostNATSrc, flow.HasPostNATDst} {
		i := bitID(Cols(id))
		a := addrOf(&r, i)
		if r.Has&id != 0 && !a.IsValid() {
			r.Has &^= id
		}
		if r.Has&id != 0 {
			setAddr(&r, i, a.Unmap().WithZone(""))
		} else {
			setAddr(&r, i, netip.Addr{})
		}
	}
	// Columns without their bit read back as zero.
	for id := 0; id < 48; id++ {
		if r.Has&(1<<id) != 0 {
			continue
		}
		switch kindOf[id] {
		case kindTime:
			setTime(&r, id, 0)
		case kindUint, kindByte:
			setUint(&r, id, 0)
		case kindString:
			setString(&r, id, "")
		}
	}
	if len(r.Extras) == 0 {
		r.Extras = nil
	}
	for i := range r.Extras {
		if r.Extras[i].Value == nil {
			r.Extras[i].Value = []byte{}
		}
	}
	return r
}

// sameRecord compares records, templates by content.
func sameRecord(t *testing.T, want, got flow.Record, where string) {
	t.Helper()
	want = normalize(want)
	wt, gt := want.Template, got.Template
	want.Template, got.Template = nil, nil
	for i := range got.Extras {
		if got.Extras[i].Value == nil {
			got.Extras[i].Value = []byte{}
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("%s:\nwant %+v\n got %+v", where, want, got)
	}
	if (wt == nil) != (gt == nil) || wt != nil && templateKey(wt) != templateKey(gt) {
		t.Fatalf("%s: template %+v, got %+v", where, wt, gt)
	}
}

// writeSegment writes recs (flushing every flushEvery records) and closes it.
func writeSegment(t testing.TB, dir string, recs []flow.Record, raws []flow.RawSet, flushEvery int) (string, *Footer) {
	t.Helper()
	return writeSegmentWith(t, dir, recs, raws, flushEvery, (*Writer).Close)
}

// writeSegmentWith is writeSegment closing with closeFn.
func writeSegmentWith(t testing.TB, dir string, recs []flow.Record, raws []flow.RawSet, flushEvery int,
	closeFn func(*Writer) (*Footer, error)) (string, *Footer) {
	t.Helper()
	path := filepath.Join(dir, NameFor(testHour).String())
	w, err := Create(path, "10.1.0.1", testHour, "2.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	w.SetMeta([]byte("meta-1"))
	for i := range recs {
		if err := w.Append(&recs[i]); err != nil {
			t.Fatal(err)
		}
		if flushEvery > 0 && (i+1)%flushEvery == 0 {
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
		}
		if i < len(raws) {
			if err := w.AppendRaw(&raws[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	f, err := closeFn(w)
	if err != nil {
		t.Fatal(err)
	}
	return path, f
}

// readAll reads every record of a segment with ColAll.
func readAll(t testing.TB, r *Reader) []flow.Record {
	t.Helper()
	var out []flow.Record
	for i := 0; i < r.Blocks(); i++ {
		recs, err := r.ReadBlock(i, ColAll, nil)
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		out = append(out, recs...)
	}
	return out
}

func randRaw(r *rand.Rand, recv int64) flow.RawSet {
	d := make([]byte, 1+r.IntN(40))
	for i := range d {
		d[i] = byte(r.IntN(256))
	}
	st := flow.StatusNoTemplate
	if r.IntN(3) == 0 {
		st = flow.StatusMalformed
	}
	return flow.RawSet{Received: recv, ExporterPort: 40000, Domain: 1, Version: flow.IPFIX, TemplateID: 999, Status: st,
		Header: []byte{0, 10, 0, 16}, Data: d}
}

func sameRaw(a, b flow.RawSet) bool {
	return a.Received == b.Received && a.ExporterPort == b.ExporterPort && a.Domain == b.Domain &&
		a.Version == b.Version && a.TemplateID == b.TemplateID && a.Status == b.Status &&
		bytes.Equal(a.Header, b.Header) && bytes.Equal(a.Data, b.Data)
}
