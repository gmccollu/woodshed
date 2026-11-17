package flow

import (
	"encoding/binary"
	"net/netip"
)

// Builder assembles flow v9 and IPFIX messages, for `woodshed send` and
// tests: templates, options templates, withdrawals and data records, in the
// order they're added, each run of one kind in one set.
type Builder struct {
	version  uint8
	buf      []byte
	setStart int
	setID    uint16
	count    int // v9: records in the message (templates and data)
	records  int // data records
}

// NewBuilder returns a builder for version V9 or IPFIX.
func NewBuilder(version uint8) *Builder {
	b := &Builder{version: version}
	b.Reset()
	return b
}

func (b *Builder) hdrLen() int {
	if b.version == V9 {
		return v9Header
	}
	return ipfixHeader
}

// Reset empties the message.
func (b *Builder) Reset() {
	b.buf = append(b.buf[:0], make([]byte, b.hdrLen())...)
	b.setStart, b.setID, b.count, b.records = -1, 0, 0, 0
}

// Len is the message's length so far.
func (b *Builder) Len() int { return len(b.buf) }

// Records is the number of data records added.
func (b *Builder) Records() int { return b.records }

func (b *Builder) closeSet() {
	if b.setStart < 0 {
		return
	}
	for (len(b.buf)-b.setStart)%4 != 0 && b.version == V9 {
		b.buf = append(b.buf, 0) // v9 flowsets are padded to 4 bytes
	}
	binary.BigEndian.PutUint16(b.buf[b.setStart+2:], uint16(len(b.buf)-b.setStart))
	b.setStart = -1
}

func (b *Builder) set(id uint16) {
	if b.setStart >= 0 && b.setID == id {
		return
	}
	b.closeSet()
	b.setStart, b.setID = len(b.buf), id
	b.buf = binary.BigEndian.AppendUint16(b.buf, id)
	b.buf = append(b.buf, 0, 0)
}

func (b *Builder) field(f TemplateField) {
	id := f.ID
	if f.enterprise() {
		id |= 0x8000
	}
	b.buf = binary.BigEndian.AppendUint16(b.buf, id)
	b.buf = binary.BigEndian.AppendUint16(b.buf, f.Length)
	if f.enterprise() && b.version == IPFIX {
		b.buf = binary.BigEndian.AppendUint32(b.buf, f.PEN) // VendorRangePEN for a v9 vendor-range type
	}
}

// Template adds a template record.
func (b *Builder) Template(id uint16, fields []TemplateField) {
	sid := uint16(2)
	if b.version == V9 {
		sid = 0
	}
	b.set(sid)
	b.buf = binary.BigEndian.AppendUint16(b.buf, id)
	b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(len(fields)))
	for _, f := range fields {
		b.field(f)
	}
	b.count++
}

// OptionsTemplate adds an options template whose first scope fields are its
// scope (v9: scope field types, RFC 3954 §6.1).
func (b *Builder) OptionsTemplate(id uint16, scope int, fields []TemplateField) {
	if b.version == V9 {
		b.set(1)
		b.buf = binary.BigEndian.AppendUint16(b.buf, id)
		b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(4*scope))
		b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(4*(len(fields)-scope)))
	} else {
		b.set(3)
		b.buf = binary.BigEndian.AppendUint16(b.buf, id)
		b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(len(fields)))
		b.buf = binary.BigEndian.AppendUint16(b.buf, uint16(scope))
	}
	for _, f := range fields {
		b.field(f)
	}
	b.count++
}

// Withdraw adds an IPFIX template withdrawal (id 2 or 3 withdraws every
// template or options template).
func (b *Builder) Withdraw(id uint16, options bool) {
	sid := uint16(2)
	if options {
		sid = 3
	}
	b.set(sid)
	b.buf = binary.BigEndian.AppendUint16(b.buf, id)
	b.buf = append(b.buf, 0, 0)
}

// Data adds one data record of template id (its encoded fields).
func (b *Builder) Data(id uint16, rec []byte) {
	b.set(id)
	b.buf = append(b.buf, rec...)
	b.count++
	b.records++
}

// Header is a message header's values.
type Header struct {
	ExportTime uint32 // unix seconds
	Seq        uint32
	Domain     uint32 // observation domain (v9 source ID)
	SysUptime  uint32 // v9 only: ms since the exporter booted
}

// Message finishes the message and returns a copy of it; the builder is
// then reset.
func (b *Builder) Message(h Header) []byte {
	b.closeSet()
	m := append([]byte(nil), b.buf...)
	binary.BigEndian.PutUint16(m, uint16(b.version))
	if b.version == V9 {
		binary.BigEndian.PutUint16(m[2:], uint16(b.count))
		binary.BigEndian.PutUint32(m[4:], h.SysUptime)
		binary.BigEndian.PutUint32(m[8:], h.ExportTime)
		binary.BigEndian.PutUint32(m[12:], h.Seq)
		binary.BigEndian.PutUint32(m[16:], h.Domain)
	} else {
		binary.BigEndian.PutUint16(m[2:], uint16(len(m)))
		binary.BigEndian.PutUint32(m[4:], h.ExportTime)
		binary.BigEndian.PutUint32(m[8:], h.Seq)
		binary.BigEndian.PutUint32(m[12:], h.Domain)
	}
	b.Reset()
	return m
}

// V5Header is a flow v5 header's values.
type V5Header struct {
	SysUptime        uint32
	UnixSecs, Nsecs  uint32
	Seq              uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16 // mode in the top 2 bits, interval below
}

// V5Record is one flow v5 record's values.
type V5Record struct {
	Src, Dst, NextHop netip.Addr // IPv4
	In, Out           uint16
	Packets, Bytes    uint32
	First, Last       uint32 // sysUptime ms
	SrcPort, DstPort  uint16
	TCPFlags, Proto   uint8
	ToS               uint8
	SrcAS, DstAS      uint16
	SrcMask, DstMask  uint8
}

// EncodeV5 builds a flow v5 packet.
func EncodeV5(h V5Header, recs []V5Record) []byte {
	b := make([]byte, v5Header, v5Header+len(recs)*v5Record)
	binary.BigEndian.PutUint16(b, V5)
	binary.BigEndian.PutUint16(b[2:], uint16(len(recs)))
	binary.BigEndian.PutUint32(b[4:], h.SysUptime)
	binary.BigEndian.PutUint32(b[8:], h.UnixSecs)
	binary.BigEndian.PutUint32(b[12:], h.Nsecs)
	binary.BigEndian.PutUint32(b[16:], h.Seq)
	b[20], b[21] = h.EngineType, h.EngineID
	binary.BigEndian.PutUint16(b[22:], h.SamplingInterval)
	v4 := func(a netip.Addr) []byte {
		if !a.Is4() {
			return make([]byte, 4)
		}
		x := a.As4()
		return x[:]
	}
	for _, r := range recs {
		x := make([]byte, v5Record)
		copy(x[0:], v4(r.Src))
		copy(x[4:], v4(r.Dst))
		copy(x[8:], v4(r.NextHop))
		binary.BigEndian.PutUint16(x[12:], r.In)
		binary.BigEndian.PutUint16(x[14:], r.Out)
		binary.BigEndian.PutUint32(x[16:], r.Packets)
		binary.BigEndian.PutUint32(x[20:], r.Bytes)
		binary.BigEndian.PutUint32(x[24:], r.First)
		binary.BigEndian.PutUint32(x[28:], r.Last)
		binary.BigEndian.PutUint16(x[32:], r.SrcPort)
		binary.BigEndian.PutUint16(x[34:], r.DstPort)
		x[37], x[38], x[39] = r.TCPFlags, r.Proto, r.ToS
		binary.BigEndian.PutUint16(x[40:], r.SrcAS)
		binary.BigEndian.PutUint16(x[42:], r.DstAS)
		x[44], x[45] = r.SrcMask, r.DstMask
		b = append(b, x...)
	}
	return b
}

// Values appends field values in network order, for building data records.
type Values []byte

func (v Values) U8(x uint8) Values   { return append(v, x) }
func (v Values) U16(x uint16) Values { return binary.BigEndian.AppendUint16(v, x) }
func (v Values) U32(x uint32) Values { return binary.BigEndian.AppendUint32(v, x) }
func (v Values) U64(x uint64) Values { return binary.BigEndian.AppendUint64(v, x) }

// Addr appends an address in its 4- or 16-byte form.
func (v Values) Addr(a netip.Addr) Values {
	if a.Is4() {
		b := a.As4()
		return append(v, b[:]...)
	}
	b := a.As16()
	return append(v, b[:]...)
}

// Var appends a variable-length value (IPFIX).
func (v Values) Var(b []byte) Values { return putVarlen(v, b) }

// Bytes appends raw bytes.
func (v Values) Bytes(b []byte) Values { return append(v, b...) }
