package flowseg

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"math"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func crc(b []byte) uint32 { return crc32.Checksum(b, castagnoli) }

// errCorrupt is what every decoder returns for bytes that don't parse; the
// public errors wrap it.
var errCorrupt = errors.New("flowseg: corrupt data")

// ---- appending ----

func putUvarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

func putVarint(b []byte, v int64) []byte { return binary.AppendVarint(b, v) }

func putU16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }

func putU32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }

func putU64(b []byte, v uint64) []byte { return binary.LittleEndian.AppendUint64(b, v) }

func putBytes(b, v []byte) []byte {
	b = putUvarint(b, uint64(len(v)))
	return append(b, v...)
}

func zigzag(v int64) uint64 { return uint64(v<<1) ^ uint64(v>>63) }

func unzigzag(u uint64) int64 { return int64(u>>1) ^ -int64(u&1) }

// ---- reading ----

// dec reads from a byte slice; the first error sticks (err) and every later
// read returns zero, so a parser checks err once at the end of a section.
type dec struct {
	b   []byte
	err error
}

func (d *dec) fail() {
	if d.err == nil {
		d.err = errCorrupt
	}
	d.b = nil
}

func (d *dec) uvarint() uint64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.fail()
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *dec) varint() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.fail()
		return 0
	}
	d.b = d.b[n:]
	return v
}

// count reads a uvarint that counts items of at least minSize bytes each
// still to come, refusing one that can't fit (so a corrupt count can't make a
// parser allocate a huge slice).
func (d *dec) count(minSize int) int {
	v := d.uvarint()
	if d.err != nil {
		return 0
	}
	if minSize < 1 {
		minSize = 1
	}
	if v > uint64(len(d.b)/minSize) {
		d.fail()
		return 0
	}
	return int(v)
}

// limit reads a uvarint and refuses one above max.
func (d *dec) limit(max uint64) uint64 {
	v := d.uvarint()
	if v > max {
		d.fail()
		return 0
	}
	return v
}

func (d *dec) byte1() byte {
	if d.err != nil {
		return 0
	}
	if len(d.b) < 1 {
		d.fail()
		return 0
	}
	v := d.b[0]
	d.b = d.b[1:]
	return v
}

func (d *dec) next(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.fail()
		return nil
	}
	v := d.b[:n:n]
	d.b = d.b[n:]
	return v
}

func (d *dec) bytes() []byte {
	n := d.uvarint()
	if n > uint64(len(d.b)) {
		d.fail()
		return nil
	}
	return d.next(int(n))
}

func (d *dec) u32() uint32 {
	b := d.next(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// ---- arithmetic ----

// satAdd adds without wrapping (sums of hostile counters saturate).
func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return math.MaxUint64
}

func satMul(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > math.MaxUint64/b {
		return math.MaxUint64
	}
	return a * b
}

// toI64 caps a count at the largest int64 (the index stores INTEGER).
func toI64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

// ---- presence bitmaps ----

// appendPresence writes a presence bitmap as runs: absent, present, absent, …
// (uvarints summing to len(p)), so a column present in every row costs two
// bytes.
func appendPresence(b []byte, p []bool) []byte {
	want := false
	run := uint64(0)
	nruns := 0
	start := len(b)
	b = putUvarint(b, 0) // placeholder replaced below
	var runs []byte
	for _, v := range p {
		if v == want {
			run++
			continue
		}
		runs = putUvarint(runs, run)
		nruns++
		want = !want
		run = 1
	}
	runs = putUvarint(runs, run)
	nruns++
	b = b[:start]
	b = putUvarint(b, uint64(nruns))
	return append(b, runs...)
}

// readPresence decodes a presence bitmap of rows rows into out (reused).
func readPresence(d *dec, rows int, out []bool) ([]bool, int) {
	n := d.count(1)
	out = out[:0]
	if cap(out) < rows {
		out = make([]bool, 0, rows)
	}
	present := 0
	v := false
	for i := 0; i < n && d.err == nil; i++ {
		run := d.uvarint()
		if run > uint64(rows-len(out)) {
			d.fail()
			break
		}
		for j := uint64(0); j < run; j++ {
			out = append(out, v)
		}
		if v {
			present += int(run)
		}
		v = !v
	}
	if d.err == nil && len(out) != rows {
		d.fail()
	}
	return out, present
}
