package flowseg

import (
	"os"
)

// RecoverResult is what Recover did.
type RecoverResult struct {
	// Clean: the segment already had a valid footer; nothing changed.
	Clean bool
	// KeptBlocks is the number of blocks the closed segment holds.
	KeptBlocks int
	// CutBytes were removed after the last complete section (a block cut
	// short or failing its CRC, and everything after it).
	CutBytes int64
	Footer   *Footer
}

// Recover closes a segment a crash left open (SPEC §13.2): it reads the
// sections in order, keeps every one whose CRC checks up to the first that
// doesn't (or is cut short), cuts the file there, and writes the template
// table and the footer, then fsyncs. A segment with a valid footer is left as
// it is (Clean), so Recover is idempotent. A file too short for a header, or
// whose header doesn't check, returns ErrBadHeader and is left alone.
func Recover(path string) (RecoverResult, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return RecoverResult{}, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return RecoverResult{}, err
	}
	size := st.Size()
	h, err := readHeaderAt(f, size)
	if err != nil {
		return RecoverResult{}, err
	}
	if foot, err := readFooter(f, size, h.length); err == nil && foot.DeviceID == h.deviceID &&
		foot.Hour.UnixMilli() == h.hour && blocksCheck(f, size, foot) {
		return RecoverResult{Clean: true, KeptBlocks: len(foot.Blocks), Footer: foot}, nil
	}
	s := scan(f, size, h)
	foot, err := s.writeTail(f, true)
	if err != nil {
		return RecoverResult{}, err
	}
	return RecoverResult{KeptBlocks: len(foot.Blocks), CutBytes: size - s.off, Footer: foot}, nil
}

// blocksCheck verifies every section a footer lists (a footer can be intact
// over a block that a crash or a disk error damaged).
func blocksCheck(f *os.File, size int64, foot *Footer) bool {
	var buf []byte
	for _, b := range foot.Blocks {
		m, body, ok := readSection(f, b.Offset, size, buf)
		if !ok || m != magicBlock || int64(len(body))+prefixLen != b.Length {
			return false
		}
		buf = body
	}
	for _, c := range foot.RawChunks {
		m, body, ok := readSection(f, c.Offset, size, buf)
		if !ok || m != magicRaw || int64(len(body))+prefixLen != c.Length {
			return false
		}
		buf = body
	}
	return true
}

// scan reads the complete sections after the header, stopping at the first
// that's cut short, fails its CRC or doesn't parse, or at a template table or
// footer (written only at close: a valid footer would have been used).
func scan(f *os.File, size int64, h header) *segState {
	s := newSegState(h)
	var buf []byte
	for {
		off := s.off
		magic, body, ok := readSection(f, off, size, buf)
		if !ok {
			return s
		}
		buf = body
		length := prefixLen + int64(len(body))
		switch magic {
		case magicBlock:
			d := &dec{b: body}
			hl := d.limit(uint64(len(body)))
			hdrStart := len(body) - len(d.b)
			hdr := d.next(int(hl))
			bi := BlockInfo{}
			hd := &dec{b: hdr}
			readHeader(hd, &bi)
			if d.err != nil || hd.err != nil || len(hd.b) != 0 || decodeBody(body, 0, nil, &Block{}) != nil {
				return s
			}
			s.addBlock(&bi, off, length, off+prefixLen+int64(hdrStart), int64(hl))
		case magicRaw:
			c, ok := decodeRawChunk(body, nil)
			if !ok {
				return s
			}
			c.Offset, c.Length = off, length
			s.addRaw(c)
		case magicTmpl:
			c, ok := decodeTmplChunk(body)
			if !ok || c.first != len(s.templates) {
				return s
			}
			s.templates = append(s.templates, c.templates...)
			if c.hasMeta {
				s.meta = c.meta
			}
			s.off = off + length
		default:
			return s
		}
	}
}
