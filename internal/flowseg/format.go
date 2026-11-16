package flowseg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// File layout (see doc.go for the full description).
const (
	Magic         = "WSFLOW01"
	FormatVersion = 1
	headerFixed   = 32
	prefixLen     = 12 // section magic, body length, body CRC
	trailerLen    = 16 // footer body length, footer CRC, end magic
	endMagic      = "WSFLOWEN"

	maxSectionBody = 1 << 30
	maxDeviceID    = 1024
	maxVersion     = 256
	maxMeta        = 16 << 20
	maxRawEntry    = 1 << 20
	maxTemplates   = 1 << 20
	maxFields      = 1 << 12
)

// Section magics.
var (
	magicBlock = [4]byte{'W', 'S', 'B', '1'} // a block of records
	magicRaw   = [4]byte{'W', 'S', 'R', '1'} // a chunk of raw sets
	magicTmpl  = [4]byte{'W', 'S', 'C', '1'} // templates (and metadata) first used since the last chunk
	magicTable = [4]byte{'W', 'S', 'T', '1'} // the whole template table, at close
	magicFoot  = [4]byte{'W', 'S', 'F', '1'} // the footer
)

// Errors.
var (
	// ErrNoFooter: the segment is still open, or the writer crashed; Recover
	// closes it.
	ErrNoFooter = errors.New("flowseg: segment has no footer (open, or not closed cleanly)")
	// ErrBadHeader: not a segment, or its header doesn't check.
	ErrBadHeader = errors.New("flowseg: not a flow segment (bad header)")
	// ErrCorrupt: a section fails its CRC or doesn't parse.
	ErrCorrupt = fmt.Errorf("flowseg: corrupt segment: %w", errCorrupt)
	// ErrClosed: the writer is closed.
	ErrClosed = errors.New("flowseg: writer closed")
)

// header is a segment's header.
type header struct {
	deviceID string
	hour     int64 // unix ms of the hour's start
	version  string
	created  int64
	length   int
}

func encodeHeader(h header) []byte {
	b := make([]byte, 0, headerFixed+len(h.deviceID)+len(h.version))
	b = append(b, Magic...)
	b = putU16(b, FormatVersion)
	b = putU16(b, uint16(headerFixed+len(h.deviceID)+len(h.version)))
	b = putU32(b, uint32(h.hour/3600000))
	b = putU16(b, uint16(len(h.deviceID)))
	b = putU16(b, uint16(len(h.version)))
	b = putU64(b, uint64(h.created))
	b = putU32(b, 0) // CRC, below
	b = append(b, h.deviceID...)
	b = append(b, h.version...)
	c := crc(append(append([]byte(nil), b[:28]...), b[headerFixed:]...))
	binary.LittleEndian.PutUint32(b[28:], c)
	return b
}

func readHeaderAt(f io.ReaderAt, size int64) (header, error) {
	if size < headerFixed {
		return header{}, ErrBadHeader
	}
	var fx [headerFixed]byte
	if _, err := f.ReadAt(fx[:], 0); err != nil {
		return header{}, ErrBadHeader
	}
	if string(fx[:8]) != Magic || binary.LittleEndian.Uint16(fx[8:]) != FormatVersion {
		return header{}, ErrBadHeader
	}
	hl := int(binary.LittleEndian.Uint16(fx[10:]))
	dl := int(binary.LittleEndian.Uint16(fx[16:]))
	vl := int(binary.LittleEndian.Uint16(fx[18:]))
	if hl != headerFixed+dl+vl || dl > maxDeviceID || vl > maxVersion || int64(hl) > size {
		return header{}, ErrBadHeader
	}
	all := make([]byte, hl)
	if _, err := f.ReadAt(all, 0); err != nil {
		return header{}, ErrBadHeader
	}
	if crc(append(append([]byte(nil), all[:28]...), all[headerFixed:]...)) != binary.LittleEndian.Uint32(all[28:]) {
		return header{}, ErrBadHeader
	}
	return header{
		deviceID: string(all[headerFixed : headerFixed+dl]),
		hour:     int64(binary.LittleEndian.Uint32(fx[12:])) * 3600000,
		version:  string(all[headerFixed+dl:]),
		created:  int64(binary.LittleEndian.Uint64(fx[20:])),
		length:   hl,
	}, nil
}

// section frames body with its magic, length and CRC.
func section(magic [4]byte, body []byte) []byte {
	b := make([]byte, 0, prefixLen+len(body))
	b = append(b, magic[:]...)
	b = putU32(b, uint32(len(body)))
	b = putU32(b, crc(body))
	return append(b, body...)
}

// readSection reads the section at off: its magic and verified body. ok is
// false for a section that's cut short, too long or fails its CRC.
func readSection(f io.ReaderAt, off, size int64, buf []byte) (magic [4]byte, body []byte, ok bool) {
	if off < 0 || size-off < prefixLen {
		return magic, nil, false
	}
	var p [prefixLen]byte
	if _, err := f.ReadAt(p[:], off); err != nil {
		return magic, nil, false
	}
	copy(magic[:], p[:4])
	n := int64(binary.LittleEndian.Uint32(p[4:]))
	if n > maxSectionBody || n > size-off-prefixLen {
		return magic, nil, false
	}
	if int64(cap(buf)) < n {
		buf = make([]byte, n)
	}
	body = buf[:n]
	if _, err := f.ReadAt(body, off+prefixLen); err != nil {
		return magic, nil, false
	}
	if crc(body) != binary.LittleEndian.Uint32(p[8:]) {
		return magic, nil, false
	}
	return magic, body, true
}

// ---- templates ----

func appendTemplate(b []byte, t *flow.Template) []byte {
	b = append(b, t.Version)
	b = putUvarint(b, uint64(t.ExporterPort))
	b = putUvarint(b, uint64(t.Domain))
	b = putUvarint(b, uint64(t.ID))
	opt := byte(0)
	if t.Options {
		opt = 1
	}
	b = append(b, opt)
	b = putUvarint(b, uint64(max(t.ScopeCount, 0)))
	b = putVarint(b, t.Received)
	b = putUvarint(b, uint64(len(t.Fields)))
	for _, f := range t.Fields {
		b = putUvarint(b, uint64(f.PEN))
		b = putUvarint(b, uint64(f.ID))
		b = putUvarint(b, uint64(f.Length))
	}
	return b
}

func readTemplate(d *dec) *flow.Template {
	t := &flow.Template{Version: d.byte1()}
	t.ExporterPort = uint16(d.limit(65535))
	t.Domain = uint32(d.limit(math.MaxUint32))
	t.ID = uint16(d.limit(65535))
	switch d.byte1() {
	case 0:
	case 1:
		t.Options = true
	default:
		d.fail()
	}
	t.ScopeCount = int(d.limit(maxFields))
	t.Received = d.varint()
	n := d.count(3)
	if n > maxFields {
		d.fail()
	}
	if d.err != nil {
		return nil
	}
	t.Fields = make([]flow.TemplateField, 0, n)
	for i := 0; i < n && d.err == nil; i++ {
		t.Fields = append(t.Fields, flow.TemplateField{PEN: uint32(d.limit(math.MaxUint32)),
			ID: uint16(d.limit(65535)), Length: uint16(d.limit(65535))})
	}
	if d.err != nil {
		return nil
	}
	return t
}

// templateKey is a template's content, for interning.
func templateKey(t *flow.Template) string { return string(appendTemplate(nil, t)) }

// tmplChunk is a template chunk (or the table): templates from index first,
// and the metadata when it changed.
type tmplChunk struct {
	first     int
	templates []*flow.Template
	meta      []byte
	hasMeta   bool
}

func encodeTmplChunk(c tmplChunk) []byte {
	b := putUvarint(nil, uint64(c.first))
	b = putUvarint(b, uint64(len(c.templates)))
	for _, t := range c.templates {
		b = appendTemplate(b, t)
	}
	if c.hasMeta {
		b = append(b, 1)
		b = putBytes(b, c.meta)
	} else {
		b = append(b, 0)
	}
	return b
}

func decodeTmplChunk(body []byte) (tmplChunk, bool) {
	d := &dec{b: body}
	c := tmplChunk{first: int(d.limit(maxTemplates))}
	n := d.count(8)
	if n > maxTemplates {
		return c, false
	}
	for i := 0; i < n && d.err == nil; i++ {
		if t := readTemplate(d); t != nil {
			c.templates = append(c.templates, t)
		}
	}
	switch d.byte1() {
	case 0:
	case 1:
		c.hasMeta = true
		m := d.bytes()
		if len(m) > maxMeta {
			d.fail()
		}
		c.meta = append([]byte{}, m...)
	default:
		d.fail()
	}
	return c, d.err == nil && len(d.b) == 0
}

// ---- raw sets ----

// RawChunk is a raw section chunk's directory entry.
type RawChunk struct {
	Offset, Length int64
	Count          int
	MinReceived    int64
	MaxReceived    int64
	Status         [4]int64 // raw sets by flow.Status
}

func encodeRawChunk(raws []flow.RawSet) []byte {
	var b []byte
	b = putUvarint(b, uint64(len(raws)))
	for i := range raws {
		r := &raws[i]
		b = putVarint(b, r.Received)
		b = putUvarint(b, uint64(r.ExporterPort))
		b = putUvarint(b, uint64(r.Domain))
		b = append(b, r.Version)
		b = putUvarint(b, uint64(r.TemplateID))
		b = append(b, byte(r.Status))
		b = putBytes(b, r.Header)
		b = putBytes(b, r.Data)
	}
	return b
}

// decodeRawChunk parses a raw chunk; with fn nil it only checks and counts.
func decodeRawChunk(body []byte, fn func(*flow.RawSet) bool) (RawChunk, bool) {
	d := &dec{b: body}
	n := d.count(7)
	var c RawChunk
	c.Count = n
	for i := 0; i < n && d.err == nil; i++ {
		r := flow.RawSet{Received: d.varint()}
		r.ExporterPort = uint16(d.limit(65535))
		r.Domain = uint32(d.limit(math.MaxUint32))
		r.Version = d.byte1()
		r.TemplateID = uint16(d.limit(65535))
		r.Status = flow.Status(d.byte1())
		h, data := d.bytes(), d.bytes()
		if d.err != nil || len(h) > maxRawEntry || len(data) > maxRawEntry || int(r.Status) >= len(c.Status) {
			d.fail()
			break
		}
		if i == 0 || r.Received < c.MinReceived {
			c.MinReceived = r.Received
		}
		if i == 0 || r.Received > c.MaxReceived {
			c.MaxReceived = r.Received
		}
		c.Status[r.Status]++
		if fn != nil {
			r.Header, r.Data = append([]byte(nil), h...), append([]byte(nil), data...)
			if !fn(&r) {
				return c, true
			}
		}
	}
	return c, d.err == nil && len(d.b) == 0
}

// ---- the footer ----

// Footer is a segment's directory and totals (SPEC §13.2). A Writer's
// Snapshot returns the same for the part written so far.
type Footer struct {
	DeviceID      string
	Hour          time.Time
	WriterVersion string

	Totals    Totals
	Raw       int64    // raw sets
	RawStatus [4]int64 // raw sets by flow.Status

	// MinReceived and MaxReceived cover records and raw sets; MinStart and
	// MaxEnd are the records' effective flow time (EffectiveTimes). All zero
	// in an empty segment.
	MinReceived, MaxReceived int64
	MinStart, MaxEnd         int64

	Samplings []uint32 // distinct, sorted (at most 256)
	Domains   []uint32
	Minutes   []Minute // sorted by minute

	Blocks    []BlockInfo
	RawChunks []RawChunk
	Templates []*flow.Template
	Meta      []byte

	tableOff int64 // the template table section (closed segments)
}

// Empty reports whether the segment holds neither records nor raw sets.
func (f *Footer) Empty() bool { return f.Totals.Records == 0 && f.Raw == 0 }

func encodeFooter(f *Footer, hdrs [][]byte) []byte {
	b := putUvarint(nil, 1)
	b = putBytes(b, []byte(f.DeviceID))
	b = putVarint(b, f.Hour.UnixMilli())
	b = putBytes(b, []byte(f.WriterVersion))
	b = appendTotals(b, &f.Totals)
	b = putUvarint(b, uint64(f.Raw))
	for _, v := range f.RawStatus {
		b = putUvarint(b, uint64(v))
	}
	b = putVarint(b, f.MinReceived)
	b = putUvarint(b, uint64(f.MaxReceived-f.MinReceived))
	b = putVarint(b, f.MinStart)
	b = putUvarint(b, uint64(f.MaxEnd-f.MinStart))
	b = appendU32s(b, f.Samplings)
	b = appendU32s(b, f.Domains)
	b = appendMinutes(b, f.Minutes)
	b = putUvarint(b, uint64(f.tableOff))
	b = putUvarint(b, uint64(len(f.Blocks)))
	for i := range f.Blocks {
		bi := &f.Blocks[i]
		b = putUvarint(b, uint64(bi.Offset))
		b = putUvarint(b, uint64(bi.Length))
		b = putBytes(b, hdrs[i])
	}
	b = putUvarint(b, uint64(len(f.RawChunks)))
	for _, c := range f.RawChunks {
		b = putUvarint(b, uint64(c.Offset))
		b = putUvarint(b, uint64(c.Length))
		b = putUvarint(b, uint64(c.Count))
		b = putVarint(b, c.MinReceived)
		b = putUvarint(b, uint64(c.MaxReceived-c.MinReceived))
		for _, v := range c.Status {
			b = putUvarint(b, uint64(v))
		}
	}
	return b
}

// decodeFooter parses a footer body; blocks' index fields are loaded from the
// footer's copies of their headers. Templates come from the table section.
func decodeFooter(body []byte, size int64) (*Footer, bool) {
	d := &dec{b: body}
	if d.uvarint() != 1 {
		return nil, false
	}
	f := &Footer{}
	id := d.bytes()
	if len(id) > maxDeviceID {
		return nil, false
	}
	f.DeviceID = string(id)
	f.Hour = time.UnixMilli(d.varint()).UTC()
	v := d.bytes()
	if len(v) > maxVersion {
		return nil, false
	}
	f.WriterVersion = string(v)
	f.Totals = readTotals(d)
	f.Raw = int64(d.limit(math.MaxInt64))
	for i := range f.RawStatus {
		f.RawStatus[i] = int64(d.limit(math.MaxInt64))
	}
	f.MinReceived = d.varint()
	f.MaxReceived = addSpan(d, f.MinReceived)
	f.MinStart = d.varint()
	f.MaxEnd = addSpan(d, f.MinStart)
	f.Samplings = readU32s(d)
	f.Domains = readU32s(d)
	f.Minutes = readMinutes(d)
	f.tableOff = int64(d.limit(uint64(size)))
	n := d.count(3)
	f.Blocks = make([]BlockInfo, 0, n)
	prevEnd := int64(0)
	for i := 0; i < n && d.err == nil; i++ {
		bi := BlockInfo{Offset: int64(d.limit(uint64(size))), Length: int64(d.limit(uint64(size)))}
		hdr := d.bytes()
		hd := &dec{b: hdr}
		readHeader(hd, &bi)
		if hd.err != nil || len(hd.b) != 0 || bi.Offset < prevEnd || bi.Length < prefixLen ||
			bi.Offset+bi.Length > size {
			d.fail()
			break
		}
		prevEnd = bi.Offset + bi.Length
		bi.hdr = hdr
		f.Blocks = append(f.Blocks, bi)
	}
	n = d.count(5)
	for i := 0; i < n && d.err == nil; i++ {
		c := RawChunk{Offset: int64(d.limit(uint64(size))), Length: int64(d.limit(uint64(size)))}
		c.Count = int(d.limit(math.MaxInt32))
		c.MinReceived = d.varint()
		c.MaxReceived = addSpan(d, c.MinReceived)
		for j := range c.Status {
			c.Status[j] = int64(d.limit(math.MaxInt64))
		}
		if c.Offset+c.Length > size {
			d.fail()
		}
		f.RawChunks = append(f.RawChunks, c)
	}
	if d.err != nil || len(d.b) != 0 {
		return nil, false
	}
	return f, true
}

// readFooter reads a closed segment's footer and template table.
func readFooter(fl io.ReaderAt, size int64, hl int) (*Footer, error) {
	if size < int64(hl)+trailerLen {
		return nil, ErrNoFooter
	}
	var tr [trailerLen]byte
	if _, err := fl.ReadAt(tr[:], size-trailerLen); err != nil {
		return nil, ErrNoFooter
	}
	if string(tr[8:]) != endMagic {
		return nil, ErrNoFooter
	}
	n := int64(binary.LittleEndian.Uint32(tr[:4]))
	off := size - trailerLen - n - prefixLen
	if off < int64(hl) {
		return nil, ErrCorrupt
	}
	magic, body, ok := readSection(fl, off, size-trailerLen, nil)
	if !ok || magic != magicFoot || int64(len(body)) != n || crc(body) != binary.LittleEndian.Uint32(tr[4:]) {
		return nil, ErrCorrupt
	}
	f, ok := decodeFooter(body, off)
	if !ok {
		return nil, ErrCorrupt
	}
	// The template table sits right before the footer.
	m, tb, ok := readSection(fl, f.tableOff, off, nil)
	if !ok || m != magicTable || f.tableOff+prefixLen+int64(len(tb)) != off {
		return nil, ErrCorrupt
	}
	c, ok := decodeTmplChunk(tb)
	if !ok || c.first != 0 {
		return nil, ErrCorrupt
	}
	f.Templates, f.Meta = c.templates, c.meta
	return f, nil
}

// sortedU32 returns a set's members, sorted.
func sortedU32(m map[uint32]struct{}) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// syncFile fsyncs f (a separate func so tests could slow it).
var syncFile = func(f *os.File) error { return f.Sync() }
