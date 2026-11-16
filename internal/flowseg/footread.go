package flowseg

import (
	"bufio"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"time"
)

// Reading a closed segment's footer in bounded memory (SPEC §13.10 decision
// 51). The footer repeats every block's header, Bloom filters included,
// which is a few bytes a record: a reader that kept it, or read it whole,
// would hold memory in proportion to the segment. readFooterStream reads the
// footer body once, in order, checking its CRC as it goes, and keeps each
// block's directory fields only, with where its header copy sits in the file
// (Reader.Block loads the index from there when asked, without keeping it).

// footHeadMax bounds the footer's fields before its block list (device ID,
// version, totals, sampling and domain lists, minutes: far less in practice).
const footHeadMax = 1 << 20

type footStream struct {
	r   *bufio.Reader
	crc uint32
	pos int64 // file offset of the next byte
	end int64 // file offset past the body
	err bool
}

func (s *footStream) take(b []byte) {
	s.crc = crc32.Update(s.crc, castagnoli, b)
	s.pos += int64(len(b))
}

func (s *footStream) uvarint() uint64 {
	if s.err {
		return 0
	}
	var buf [binary.MaxVarintLen64]byte
	for i := 0; i < len(buf); i++ {
		if s.pos >= s.end {
			s.err = true
			return 0
		}
		c, err := s.r.ReadByte()
		if err != nil {
			s.err = true
			return 0
		}
		buf[i] = c
		s.take(buf[i : i+1])
		if c < 0x80 {
			v, n := binary.Uvarint(buf[:i+1])
			if n <= 0 {
				s.err = true
				return 0
			}
			return v
		}
	}
	s.err = true
	return 0
}

func (s *footStream) read(dst []byte) bool {
	if s.err || int64(len(dst)) > s.end-s.pos {
		s.err = true
		return false
	}
	if _, err := io.ReadFull(s.r, dst); err != nil {
		s.err = true
		return false
	}
	s.take(dst)
	return true
}

// readFooterStream reads the footer section at off (its body n bytes, whose
// CRC is want) of a segment of size bytes.
func readFooterStream(fl io.ReaderAt, off, n int64, want uint32, size int64) (*Footer, bool) {
	var p [prefixLen]byte
	if _, err := fl.ReadAt(p[:], off); err != nil || string(p[:4]) != string(magicFoot[:]) ||
		int64(binary.LittleEndian.Uint32(p[4:])) != n || binary.LittleEndian.Uint32(p[8:]) != want {
		return nil, false
	}
	start := off + prefixLen
	headLen := int(min(n, footHeadMax))
	hr := bufio.NewReaderSize(io.NewSectionReader(fl, start, n), max(headLen, 64<<10))
	s := &footStream{r: hr, pos: start, end: start + n}
	// The head, parsed from a bounded peek.
	head, err := hr.Peek(headLen)
	if err != nil {
		return nil, false
	}
	d := &dec{b: head}
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
	nb := d.uvarint()
	if d.err != nil {
		return nil, false
	}
	used := len(head) - len(d.b)
	s.take(head[:used])
	hr.Discard(used)
	if nb > uint64(s.end-s.pos)/3 {
		return nil, false
	}
	// The blocks, one at a time.
	f.Blocks = make([]BlockInfo, 0, min(nb, 4096)) // the count isn't CRC-checked yet
	prevEnd := int64(0)
	var hdr []byte
	for i := uint64(0); i < nb; i++ {
		bi := BlockInfo{Offset: int64(s.uvarint()), Length: int64(s.uvarint())}
		hl := s.uvarint()
		if s.err || hl > uint64(s.end-s.pos) || bi.Offset < prevEnd || bi.Length < prefixLen ||
			bi.Offset > size || bi.Length > size-bi.Offset {
			return nil, false
		}
		bi.hdrOff, bi.hdrLen = s.pos, int64(hl)
		if cap(hdr) < int(hl) {
			hdr = make([]byte, hl)
		}
		hdr = hdr[:hl]
		if !s.read(hdr) {
			return nil, false
		}
		hd := &dec{b: hdr}
		readHeader(hd, &bi)
		if hd.err != nil || len(hd.b) != 0 {
			return nil, false
		}
		bi.lighten()
		prevEnd = bi.Offset + bi.Length
		f.Blocks = append(f.Blocks, bi)
	}
	// The raw chunks: the rest (kept whole in the footer anyway).
	tail := make([]byte, s.end-s.pos)
	if !s.read(tail) || s.crc != want {
		return nil, false
	}
	d = &dec{b: tail}
	nr := d.count(5)
	for i := 0; i < nr && d.err == nil; i++ {
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

// lighten drops a directory entry's index fields (the Bloom filter, the
// protocol and interface sets) and its per-block minutes, keeping what a
// plan needs; Reader.Block reloads the index from hdrOff.
func (b *BlockInfo) lighten() {
	b.Minutes, b.hdr = nil, nil
	b.inIfs, b.outIfs, b.keys = ifSet{}, ifSet{}, bloom{}
	b.protos = [4]uint64{}
	b.loaded = false
}
