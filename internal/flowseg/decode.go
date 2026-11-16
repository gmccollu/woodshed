package flowseg

import (
	"math"
	"math/bits"
	"net/netip"
	"slices"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Block is one block's decoded columns, reusable across Reader.Decode calls
// (its slices are overwritten). Column slices have one entry per row; a row
// without a value holds the zero value and Present reports false.
type Block struct {
	Rows int
	Info *BlockInfo
	cols Cols // decoded

	pres [64][]bool
	u    [64][]uint64
	t    [64][]int64
	a    [64][]netip.Addr
	s    [64][]string

	received []int64
	sampling []uint32
	domain   []uint32
	version  []uint8
	port     []uint16
	tmpl     []uint32 // template table index + 1
	tid      []uint16
	status   []uint8
	tsrc     []uint8
	extras   [][]flow.Extra
	xpres    []bool

	templates []*flow.Template
	dict      []netip.Addr
	buf       []byte
	inf       [64][]byte // inflated columns, reused from block to block
}

// Decoded reports which columns the last Decode filled.
func (b *Block) Decoded() Cols { return b.cols }

// Present reports whether row has a value in optional column col (a flow.Has*
// bit).
func (b *Block) Present(col uint64, row int) bool {
	p := b.pres[bits.TrailingZeros64(col)]
	return row < len(p) && p[row]
}

// Uint is an integer or one-byte optional column's values (ports, counters,
// interfaces, proto, events, …).
func (b *Block) Uint(col uint64) []uint64 { return b.u[bits.TrailingZeros64(col)] }

// Time is a time column's values (unix ms).
func (b *Block) Time(col uint64) []int64 { return b.t[bits.TrailingZeros64(col)] }

// Addr is an address column's values (IPv4 in its 4-byte form).
func (b *Block) Addr(col uint64) []netip.Addr { return b.a[bits.TrailingZeros64(col)] }

// String is a string column's values (rule_id, the interface names).
func (b *Block) String(col uint64) []string { return b.s[bits.TrailingZeros64(col)] }

// Received, Sampling and Domain are always-present columns.
func (b *Block) Received() []int64  { return b.received }
func (b *Block) Sampling() []uint32 { return b.sampling }
func (b *Block) Domain() []uint32   { return b.domain }

// Record fills r with row's decoded columns (Has bits only for decoded
// optional columns that have a value). Its strings and extras are its own: r
// may keep them after the next Decode.
func (b *Block) Record(row int, r *flow.Record) {
	*r = flow.Record{}
	for o := uint64(b.cols & ColOptional); o != 0; {
		id := bits.TrailingZeros64(o)
		o &^= 1 << id
		p := b.pres[id]
		if len(p) == 0 || !p[row] {
			continue
		}
		r.Has |= 1 << id
		switch kindOf[id] {
		case kindTime:
			setTime(r, id, b.t[id][row])
		case kindAddr:
			setAddr(r, id, b.a[id][row])
		case kindUint, kindByte:
			setUint(r, id, b.u[id][row])
		case kindString:
			setString(r, id, b.s[id][row])
		}
	}
	if b.cols&ColReceived != 0 {
		r.Received = b.received[row]
	}
	if b.cols&ColSampling != 0 {
		r.Sampling = b.sampling[row]
	}
	if b.cols&ColDomain != 0 {
		r.Domain = b.domain[row]
	}
	if b.cols&ColMeta != 0 {
		r.Version, r.ExporterPort = b.version[row], b.port[row]
	}
	if b.cols&ColTemplate != 0 {
		r.TemplateID = b.tid[row]
		if i := b.tmpl[row]; i > 0 && int(i) <= len(b.templates) {
			r.Template = b.templates[i-1]
		}
	}
	if b.cols&ColStatus != 0 {
		r.Status = flow.Status(b.status[row])
	}
	if b.cols&ColTimeSource != 0 {
		r.TimeSource = flow.TimeSource(b.tsrc[row])
	}
	if b.cols&ColExtras != 0 && row < len(b.extras) {
		r.Extras = b.extras[row]
	}
}

type colEntry struct {
	id       int
	flags    byte
	raw, sto int
	data     []byte // stored bytes
}

// decodeBody parses a verified block body into b, decoding cols. templates is
// the segment's table (for Record.Template).
func decodeBody(body []byte, cols Cols, templates []*flow.Template, b *Block) error {
	d := &dec{b: body}
	hl := d.limit(uint64(len(body)))
	hdr := slices.Clone(d.next(int(hl))) // the body buffer is reused; the index must outlive it
	bi := &BlockInfo{}
	hd := &dec{b: hdr}
	readHeader(hd, bi)
	if hd.err != nil || len(hd.b) != 0 {
		return errCorrupt
	}
	bi.hdr = hdr
	ncols := d.count(4)
	ents := make([]colEntry, 0, ncols)
	for i := 0; i < ncols && d.err == nil; i++ {
		e := colEntry{id: int(d.byte1()), flags: d.byte1()}
		e.raw = int(d.limit(maxColumnRaw))
		e.sto = int(d.limit(uint64(len(body))))
		if e.id >= 64 || e.flags&^colDeflated != 0 || (e.flags == 0 && e.raw != e.sto) {
			d.fail()
		}
		ents = append(ents, e)
	}
	if d.err != nil {
		return errCorrupt
	}
	for i := range ents {
		ents[i].data = d.next(ents[i].sto)
	}
	if d.err != nil || len(d.b) != 0 {
		return errCorrupt
	}
	*b = Block{pres: b.pres, u: b.u, t: b.t, a: b.a, s: b.s, received: b.received, sampling: b.sampling,
		domain: b.domain, version: b.version, port: b.port, tmpl: b.tmpl, tid: b.tid, status: b.status, tsrc: b.tsrc,
		xpres: b.xpres, buf: b.buf, dict: b.dict, inf: b.inf}
	b.Rows, b.Info, b.templates = bi.Rows, bi, templates
	n := bi.Rows
	for i := range b.pres {
		b.pres[i] = b.pres[i][:0]
	}
	// Zeroed always-present columns, filled below where stored.
	b.received = zeroed(b.received, n)
	b.sampling = zeroed(b.sampling, n)
	b.domain = zeroed(b.domain, n)
	b.version = zeroed(b.version, n)
	b.port = zeroed(b.port, n)
	b.tmpl = zeroed(b.tmpl, n)
	b.tid = zeroed(b.tid, n)
	b.status = zeroed(b.status, n)
	b.tsrc = zeroed(b.tsrc, n)
	b.extras = nil

	want := uint64(cols)
	if want&uint64(ColMeta) != 0 {
		want |= uint64(ColDomain)
	}
	needDict := want & (flow.HasSrc | flow.HasDst | flow.HasNextHop | flow.HasPostNATSrc | flow.HasPostNATDst)
	stored := uint64(0)
	raw := func(e *colEntry) ([]byte, error) {
		if e.flags&colDeflated == 0 {
			return e.data, nil
		}
		if uint64(e.raw) > uint64(e.sto)*1100+1024 {
			return nil, errCorrupt
		}
		out, err := inflate(e.data, e.raw, b.inf[e.id])
		if err == nil {
			b.inf[e.id] = out
		}
		return out, err
	}
	// The dictionary first.
	b.dict = b.dict[:0]
	for i := range ents {
		e := &ents[i]
		if e.id != colDict {
			continue
		}
		if needDict == 0 {
			break
		}
		r, err := raw(e)
		if err != nil {
			return err
		}
		dd := &dec{b: r}
		k := dd.count(16)
		dict := b.dict[:0]
		if cap(dict) < k {
			dict = make([]netip.Addr, 0, k)
		}
		for j := 0; j < k; j++ {
			x := dd.next(16)
			if x == nil {
				break
			}
			dict = append(dict, netip.AddrFrom16([16]byte(x)).Unmap())
		}
		if dd.err != nil || len(dd.b) != 0 {
			return errCorrupt
		}
		b.dict = dict
	}
	for i := range ents {
		e := &ents[i]
		if e.id == colDict {
			continue
		}
		if stored&(1<<e.id) != 0 {
			return errCorrupt // a column twice
		}
		stored |= 1 << e.id
		if want&(1<<e.id) == 0 {
			continue
		}
		r, err := raw(e)
		if err != nil {
			return err
		}
		if err := b.decodeCol(e.id, r, n); err != nil {
			return err
		}
	}
	b.cols = Cols(want) & (ColAll)
	// Optional columns not stored decode as absent everywhere.
	for o := uint64(b.cols & ColOptional); o != 0; {
		id := bits.TrailingZeros64(o)
		o &^= 1 << id
		if stored&(1<<id) == 0 {
			b.pres[id] = zeroed(b.pres[id], n)
		}
	}
	return nil
}

func zeroed[T any](s []T, n int) []T {
	if cap(s) < n {
		return make([]T, n)
	}
	s = s[:n]
	clear(s)
	return s
}

func (b *Block) decodeCol(id int, r []byte, n int) error {
	d := &dec{b: r}
	if id < 48 {
		k := kindOf[id]
		if k == kindNone {
			return errCorrupt
		}
		var present int
		b.pres[id], present = readPresence(d, n, b.pres[id])
		if d.err != nil {
			return errCorrupt
		}
		p := b.pres[id]
		switch k {
		case kindTime:
			mn := d.varint()
			t := zeroed(b.t[id], n)
			for i := 0; i < n && d.err == nil; i++ {
				if p[i] {
					t[i] = mn + unzigzag(d.uvarint())
				}
			}
			b.t[id] = t
		case kindAddr:
			a := zeroed(b.a[id], n)
			for i := 0; i < n && d.err == nil; i++ {
				if p[i] {
					j := d.uvarint()
					if j >= uint64(len(b.dict)) {
						d.fail()
						break
					}
					a[i] = b.dict[j]
				}
			}
			b.a[id] = a
		case kindUint:
			u := zeroed(b.u[id], n)
			mx := uintMax(id)
			for i := 0; i < n && d.err == nil; i++ {
				if p[i] {
					u[i] = d.limit(mx)
				}
			}
			b.u[id] = u
		case kindByte:
			u := zeroed(b.u[id], n)
			vals := d.next(present)
			if vals != nil {
				j := 0
				for i := 0; i < n; i++ {
					if p[i] {
						u[i] = uint64(vals[j])
						j++
					}
				}
			}
			b.u[id] = u
		case kindString:
			k := d.count(1)
			list := make([]string, 0, k)
			for j := 0; j < k && d.err == nil; j++ {
				list = append(list, string(d.bytes()))
			}
			s := zeroed(b.s[id], n)
			for i := 0; i < n && d.err == nil; i++ {
				if p[i] {
					j := d.uvarint()
					if j >= uint64(len(list)) {
						d.fail()
						break
					}
					s[i] = list[j]
				}
			}
			b.s[id] = s
		case kindFlag:
		}
		if d.err != nil || len(d.b) != 0 {
			return errCorrupt
		}
		return nil
	}
	switch Cols(1) << id {
	case ColReceived:
		mn := d.varint()
		for i := 0; i < n && d.err == nil; i++ {
			b.received[i] = mn + unzigzag(d.uvarint())
		}
	case ColSampling, ColDomain, ColTemplate, ColStatus, ColTimeSource:
		width := 1
		switch Cols(1) << id {
		case ColDomain:
			width = 3
		case ColTemplate:
			width = 2
		}
		for i := 0; i < n && d.err == nil; {
			run := d.uvarint()
			if run == 0 || run > uint64(n-i) {
				d.fail()
				break
			}
			var v [3]uint64
			for k := 0; k < width; k++ {
				v[k] = d.uvarint()
			}
			for j := 0; j < int(run); j++ {
				switch Cols(1) << id {
				case ColSampling:
					b.sampling[i+j] = uint32(min(v[0], math.MaxUint32))
				case ColDomain:
					b.version[i+j], b.port[i+j], b.domain[i+j] = uint8(min(v[0], 255)), uint16(min(v[1], 65535)),
						uint32(min(v[2], math.MaxUint32))
				case ColTemplate:
					b.tmpl[i+j], b.tid[i+j] = uint32(min(v[0], math.MaxUint32)), uint16(min(v[1], 65535))
				case ColStatus:
					b.status[i+j] = uint8(min(v[0], 255))
				case ColTimeSource:
					b.tsrc[i+j] = uint8(min(v[0], 255))
				}
			}
			i += int(run)
		}
	case ColExtras:
		b.xpres, _ = readPresence(d, n, b.xpres)
		b.extras = make([][]flow.Extra, n)
		for i := 0; i < n && d.err == nil; i++ {
			if !b.xpres[i] {
				continue
			}
			k := d.count(3)
			xs := make([]flow.Extra, 0, k)
			for j := 0; j < k && d.err == nil; j++ {
				x := flow.Extra{PEN: uint32(d.limit(math.MaxUint32)), ID: uint16(d.limit(65535))}
				x.Value = append([]byte(nil), d.bytes()...)
				xs = append(xs, x)
			}
			b.extras[i] = xs
		}
	default:
		return errCorrupt
	}
	if d.err != nil || len(d.b) != 0 {
		return errCorrupt
	}
	return nil
}
