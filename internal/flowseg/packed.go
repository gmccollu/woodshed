package flowseg

import (
	"encoding/binary"
	"math/bits"
	"net/netip"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Packed keeps some of a decoded block's rows, in the order they were added,
// as compact bytes (60 to 110 bytes a flow record in the tests, where a
// decoded block holds about 300 a row), for a caller that must keep rows of
// many blocks at once (flowquery's Stream, merging the blocks that overlap
// in flow time). Next gives each row back as Block.Record gave it.
type Packed struct {
	cols      Cols
	base      int64 // times are stored as zigzag deltas from it
	data      []byte
	pos       int
	n, read   int
	templates []*flow.Template
	strs      []string
	strIdx    map[string]uint64
	hasExt    bool // the block has extras: each row stores its own (count, then PEN, ID and value each)
}

// Reset empties p for rows of b (p's buffers are kept).
func (p *Packed) Reset(b *Block) {
	p.cols, p.data, p.pos, p.n, p.read = b.cols, p.data[:0], 0, 0, 0
	p.base = 0
	if b.Info != nil {
		p.base = b.Info.MinReceived
	}
	p.templates = b.templates
	clear(p.strs)
	p.strs = p.strs[:0]
	clear(p.strIdx)
	p.hasExt = b.cols&ColExtras != 0 && len(b.extras) > 0
}

// Len is the rows added.
func (p *Packed) Len() int { return p.n }

// Bytes is about how much memory p holds.
func (p *Packed) Bytes() int64 {
	return int64(cap(p.data)) + int64(cap(p.strs))*16 + int64(len(p.strIdx))*32
}

// Add appends b's row (b is the block p was Reset for, still decoded).
func (p *Packed) Add(b *Block, row int) {
	d := p.data
	var has uint64
	for o := uint64(b.cols & ColOptional); o != 0; {
		id := bits.TrailingZeros64(o)
		o &^= 1 << id
		if pr := b.pres[id]; len(pr) > 0 && pr[row] {
			has |= 1 << id
		}
	}
	d = binary.AppendUvarint(d, has)
	for o := has; o != 0; {
		id := bits.TrailingZeros64(o)
		o &^= 1 << id
		switch kindOf[id] {
		case kindTime:
			d = binary.AppendUvarint(d, zigzag(b.t[id][row]-p.base))
		case kindAddr:
			d = appendAddr(d, b.a[id][row])
		case kindUint:
			d = binary.AppendUvarint(d, b.u[id][row])
		case kindByte:
			d = append(d, byte(b.u[id][row]))
		case kindString:
			d = binary.AppendUvarint(d, p.str(b.s[id][row]))
		}
	}
	c := p.cols
	if c&ColReceived != 0 {
		d = binary.AppendUvarint(d, zigzag(b.received[row]-p.base))
	}
	if c&ColSampling != 0 {
		d = binary.AppendUvarint(d, uint64(b.sampling[row]))
	}
	if c&ColDomain != 0 {
		d = binary.AppendUvarint(d, uint64(b.domain[row]))
	}
	if c&ColMeta != 0 {
		d = append(d, b.version[row])
		d = binary.AppendUvarint(d, uint64(b.port[row]))
	}
	if c&ColTemplate != 0 {
		d = binary.AppendUvarint(d, uint64(b.tid[row]))
		d = binary.AppendUvarint(d, uint64(b.tmpl[row]))
	}
	if c&ColStatus != 0 {
		d = append(d, b.status[row])
	}
	if c&ColTimeSource != 0 {
		d = append(d, b.tsrc[row])
	}
	if p.hasExt {
		var xs []flow.Extra
		if row < len(b.extras) {
			xs = b.extras[row]
		}
		switch {
		case xs == nil:
			d = append(d, 0)
		default:
			d = binary.AppendUvarint(d, uint64(len(xs))+1) // 1: an empty list, not nil
			for _, x := range xs {
				d = binary.AppendUvarint(d, uint64(x.PEN))
				d = binary.AppendUvarint(d, uint64(x.ID))
				d = binary.AppendUvarint(d, uint64(len(x.Value)))
				d = append(d, x.Value...)
			}
		}
	}
	p.data = d
	p.n++
}

func (p *Packed) str(s string) uint64 {
	if i, ok := p.strIdx[s]; ok {
		return i
	}
	if p.strIdx == nil {
		p.strIdx = map[string]uint64{}
	}
	i := uint64(len(p.strs))
	p.strs = append(p.strs, s)
	p.strIdx[s] = i
	return i
}

// appendAddr writes a: a length byte (0, 4 or 16) and its bytes. A block's
// addresses come from its dictionary, so they have no zone.
func appendAddr(d []byte, a netip.Addr) []byte {
	switch {
	case !a.IsValid():
		return append(d, 0)
	case a.Is4():
		v := a.As4()
		return append(append(d, 4), v[:]...)
	}
	v := a.As16()
	return append(append(d, 16), v[:]...)
}

// Next fills r with the next row (in Add order), as Block.Record filled it.
// It must not be called more than Len times since Reset.
func (p *Packed) Next(r *flow.Record) {
	*r = flow.Record{}
	d := p.data[p.pos:]
	uv := func() uint64 {
		v, n := binary.Uvarint(d)
		d = d[n:]
		return v
	}
	has := uv()
	r.Has = has
	for o := has; o != 0; {
		id := bits.TrailingZeros64(o)
		o &^= 1 << id
		switch kindOf[id] {
		case kindTime:
			setTime(r, id, unzigzag(uv())+p.base)
		case kindAddr:
			var a netip.Addr
			switch d[0] {
			case 4:
				a = netip.AddrFrom4([4]byte(d[1:5]))
			case 16:
				a = netip.AddrFrom16([16]byte(d[1:17]))
			}
			d = d[1+int(d[0]):]
			setAddr(r, id, a)
		case kindUint:
			setUint(r, id, uv())
		case kindByte:
			setUint(r, id, uint64(d[0]))
			d = d[1:]
		case kindString:
			setString(r, id, p.strs[uv()])
		}
	}
	c := p.cols
	if c&ColReceived != 0 {
		r.Received = unzigzag(uv()) + p.base
	}
	if c&ColSampling != 0 {
		r.Sampling = uint32(uv())
	}
	if c&ColDomain != 0 {
		r.Domain = uint32(uv())
	}
	if c&ColMeta != 0 {
		r.Version = d[0]
		d = d[1:]
		r.ExporterPort = uint16(uv())
	}
	if c&ColTemplate != 0 {
		r.TemplateID = uint16(uv())
		if i := uv(); i > 0 && int(i) <= len(p.templates) {
			r.Template = p.templates[i-1]
		}
	}
	if c&ColStatus != 0 {
		r.Status = flow.Status(d[0])
		d = d[1:]
	}
	if c&ColTimeSource != 0 {
		r.TimeSource = flow.TimeSource(d[0])
		d = d[1:]
	}
	if p.hasExt {
		if k := uv(); k > 0 {
			xs := make([]flow.Extra, k-1) // the record's own, as Record's are
			for i := range xs {
				xs[i].PEN, xs[i].ID = uint32(uv()), uint16(uv())
				if n := int(uv()); n > 0 {
					xs[i].Value = append([]byte(nil), d[:n]...)
					d = d[n:]
				}
			}
			r.Extras = xs
		}
	}
	p.pos = len(p.data) - len(d)
	p.read++
}
