package flowseg

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"slices"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// segState is what a writer (or a recovery) knows about the sections written
// so far, enough to write the template table and the footer.
type segState struct {
	h         header
	off       int64 // the end of the last complete section
	blocks    []dirEntry
	rawChunks []RawChunk
	templates []*flow.Template
	meta      []byte

	totals             Totals
	raw                int64
	rawStatus          [4]int64
	minRecv, maxRecv   int64
	minStart, maxEnd   int64
	haveRecv, haveFlow bool
	samplings          map[uint32]struct{}
	domains            map[uint32]struct{}
	minutes            minuteAcc
}

// dirEntry is a written block's directory entry as a writer keeps it for
// the segment's life: BlockInfo's directory fields without its index (the
// footer's copy of the header is read back from the block itself), 216
// bytes instead of BlockInfo's 472. A block's sampling and domain lists
// share the previous block's when they're equal (they usually are).
type dirEntry struct {
	off, length, hdrOff                int64
	hdrLen, rows                       int32
	minRecv, maxRecv                   int64
	minStart, maxStart, minEnd, maxEnd int64
	cols                               Cols
	totals                             Totals
	samplings, domains                 []uint32
}

// info is the entry as a directory BlockInfo (its index not loaded).
func (e *dirEntry) info() BlockInfo {
	return BlockInfo{Offset: e.off, Length: e.length, Rows: int(e.rows), MinReceived: e.minRecv, MaxReceived: e.maxRecv,
		MinStart: e.minStart, MaxStart: e.maxStart, MinEnd: e.minEnd, MaxEnd: e.maxEnd, Columns: e.cols, Totals: e.totals,
		Samplings: e.samplings, Domains: e.domains, hdrOff: e.hdrOff, hdrLen: int64(e.hdrLen)}
}

func newSegState(h header) *segState {
	return &segState{h: h, off: int64(h.length), samplings: map[uint32]struct{}{}, domains: map[uint32]struct{}{},
		minutes: minuteAcc{}}
}

func (s *segState) recv(lo, hi int64) {
	if !s.haveRecv {
		s.minRecv, s.maxRecv, s.haveRecv = lo, hi, true
		return
	}
	s.minRecv, s.maxRecv = min(s.minRecv, lo), max(s.maxRecv, hi)
}

// shareList returns v, or prev when it holds the same values.
func shareList(prev, v []uint32) []uint32 {
	if len(v) > 0 && slices.Equal(prev, v) {
		return prev
	}
	return v
}

// addBlock records a block written at off (its section is length bytes; its
// header bytes at hdrOff, hdrLen). bi has its index loaded.
func (s *segState) addBlock(bi *BlockInfo, off, length, hdrOff, hdrLen int64) {
	e := dirEntry{off: off, length: length, hdrOff: hdrOff, hdrLen: int32(hdrLen), rows: int32(bi.Rows),
		minRecv: bi.MinReceived, maxRecv: bi.MaxReceived, minStart: bi.MinStart, maxStart: bi.MaxStart, minEnd: bi.MinEnd,
		maxEnd: bi.MaxEnd, cols: bi.Columns, totals: bi.Totals, samplings: bi.Samplings, domains: bi.Domains}
	if n := len(s.blocks); n > 0 {
		e.samplings = shareList(s.blocks[n-1].samplings, e.samplings)
		e.domains = shareList(s.blocks[n-1].domains, e.domains)
	}
	s.blocks = append(s.blocks, e)
	s.totals.add(&bi.Totals)
	s.recv(bi.MinReceived, bi.MaxReceived)
	if !s.haveFlow {
		s.minStart, s.maxEnd, s.haveFlow = bi.MinStart, bi.MaxEnd, true
	} else {
		s.minStart, s.maxEnd = min(s.minStart, bi.MinStart), max(s.maxEnd, bi.MaxEnd)
	}
	for _, v := range bi.Samplings {
		if len(s.samplings) < maxDistinct {
			s.samplings[v] = struct{}{}
		}
	}
	for _, v := range bi.Domains {
		if len(s.domains) < maxDistinct {
			s.domains[v] = struct{}{}
		}
	}
	s.minutes.merge(bi.Minutes)
	s.off = off + length
}

func (s *segState) addRaw(c RawChunk) {
	s.rawChunks = append(s.rawChunks, c)
	s.raw += int64(c.Count)
	for i := range c.Status {
		s.rawStatus[i] += c.Status[i]
	}
	if c.Count > 0 {
		s.recv(c.MinReceived, c.MaxReceived)
	}
	s.off = c.Offset + c.Length
}

// summary is the footer's segment-level fields only: no blocks, raw chunks,
// templates or metadata.
func (s *segState) summary() *Footer {
	f := &Footer{
		DeviceID: s.h.deviceID, Hour: time.UnixMilli(s.h.hour).UTC(), WriterVersion: s.h.version,
		Totals: s.totals, Raw: s.raw, RawStatus: s.rawStatus,
		Samplings: sortedU32(s.samplings), Domains: sortedU32(s.domains), Minutes: s.minutes.sorted(),
	}
	if s.haveRecv {
		f.MinReceived, f.MaxReceived = s.minRecv, s.maxRecv
	}
	if s.haveFlow {
		f.MinStart, f.MaxEnd = s.minStart, s.maxEnd
	}
	return f
}

// footer builds the footer (blocks as stored: their index not loaded, their
// header at the block's own copy).
func (s *segState) footer() *Footer {
	f := s.summary()
	if len(s.blocks) > 0 { // nil for none, as slices.Clone gave
		f.Blocks = make([]BlockInfo, len(s.blocks))
		for i := range s.blocks {
			f.Blocks[i] = s.blocks[i].info()
		}
	}
	f.RawChunks, f.Templates, f.Meta = slices.Clone(s.rawChunks), slices.Clip(s.templates), s.meta
	return f
}

// tailBufSize bounds the buffer a segment's tail is written through (a var
// so tests can make its writes many and small).
var tailBufSize = 256 << 10

// errFooterTooLarge: a footer over a section's maximum body (readers would
// refuse it); the store's block-count part limit keeps footers far below it.
var errFooterTooLarge = errors.New("flowseg: footer too large")

// tailWriter writes a section body at a file offset through a bounded
// buffer, computing its CRC as it goes. The first error sticks.
type tailWriter struct {
	f   segFile
	buf []byte
	off int64 // the file offset of buf[0]
	n   int64 // body bytes so far
	crc uint32
	err error
}

// pos is the file offset of the next byte.
func (w *tailWriter) pos() int64 { return w.off + int64(len(w.buf)) }

func (w *tailWriter) flush() {
	if w.err != nil || len(w.buf) == 0 {
		return
	}
	if _, err := w.f.WriteAt(w.buf, w.off); err != nil {
		w.err = err
		return
	}
	w.off += int64(len(w.buf))
	w.buf = w.buf[:0]
}

// room returns the buffer's free space, flushing it first when it's full
// (empty after a failed flush).
func (w *tailWriter) room() []byte {
	if len(w.buf) == cap(w.buf) {
		w.flush()
	}
	return w.buf[len(w.buf):cap(w.buf)]
}

// took counts k bytes just put in the buffer's free space.
func (w *tailWriter) took(k int) {
	w.crc = crc32.Update(w.crc, castagnoli, w.buf[len(w.buf):len(w.buf)+k])
	w.buf = w.buf[:len(w.buf)+k]
	w.n += int64(k)
}

func (w *tailWriter) write(p []byte) {
	for len(p) > 0 && w.err == nil {
		r := w.room()
		if w.err != nil {
			return
		}
		k := copy(r, p)
		w.took(k)
		p = p[k:]
	}
}

// copyFrom appends n bytes of src at off.
func (w *tailWriter) copyFrom(src io.ReaderAt, off, n int64) {
	for n > 0 && w.err == nil {
		r := w.room()
		if w.err != nil {
			return
		}
		r = r[:min(int64(len(r)), n)]
		if k, err := src.ReadAt(r, off); k < len(r) {
			if err == nil || err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			w.err = err
			return
		}
		w.took(len(r))
		off += int64(len(r))
		n -= int64(len(r))
	}
}

// writeTail writes the template table, the footer and the trailer at s.off,
// cutting the file there first, then fsyncs. The footer goes out streamed:
// each block's header is copied from its span in the file through a bounded
// buffer, so memory doesn't grow with the footer (SPEC §13.10 decision 56).
// It returns the footer as Open reads it: directory entries only, each
// pointing at its header's copy in the footer; with dir false, the
// segment-level fields only (summary's, no directory to build). On an error
// the file is cut back to s.off.
func (s *segState) writeTail(fl segFile, dir bool) (*Footer, error) {
	if err := fl.Truncate(s.off); err != nil {
		return nil, err
	}
	f, err := s.writeTailAt(fl, dir)
	if err != nil {
		fl.Truncate(s.off)
		return nil, err
	}
	if err := syncSeg(fl); err != nil {
		return nil, err
	}
	return f, nil
}

// tailBufs are the tail writers' buffers, so the store closing every
// exporter's segment at the hour mark reuses a few instead of leaving one
// each for the collector.
var tailBufs sync.Pool

func (s *segState) writeTailAt(fl segFile, dir bool) (*Footer, error) {
	f := s.summary()
	f.tableOff = s.off
	table := section(magicTable, encodeTmplChunk(tmplChunk{templates: s.templates, meta: s.meta, hasMeta: true}))
	if _, err := fl.WriteAt(table, s.off); err != nil {
		return nil, err
	}
	// The footer's body goes after room for its prefix (its length and CRC
	// are known only at the end).
	start := s.off + int64(len(table)) + prefixLen
	buf, _ := tailBufs.Get().(*[]byte)
	if buf == nil || cap(*buf) != tailBufSize {
		b := make([]byte, 0, tailBufSize)
		buf = &b
	}
	defer tailBufs.Put(buf)
	w := &tailWriter{f: fl, buf: (*buf)[:0], off: start}
	b := appendFooterHead(nil, f, len(s.blocks))
	w.write(b)
	if dir {
		f.Blocks = make([]BlockInfo, len(s.blocks))
	}
	for i := range s.blocks {
		e := &s.blocks[i]
		b = putUvarint(b[:0], uint64(e.off))
		b = putUvarint(b, uint64(e.length))
		b = putUvarint(b, uint64(e.hdrLen))
		w.write(b)
		if dir {
			f.Blocks[i] = e.info()
			f.Blocks[i].hdrOff = w.pos()
		}
		w.copyFrom(fl, e.hdrOff, int64(e.hdrLen))
	}
	b = putUvarint(b[:0], uint64(len(s.rawChunks)))
	w.write(b)
	for i := range s.rawChunks {
		w.write(appendRawDirEntry(b[:0], &s.rawChunks[i]))
	}
	w.flush()
	if w.err != nil {
		return nil, w.err
	}
	if w.n > maxSectionBody {
		return nil, errFooterTooLarge
	}
	p := make([]byte, 0, prefixLen)
	p = append(p, magicFoot[:]...)
	p = putU32(p, uint32(w.n))
	p = putU32(p, w.crc)
	if _, err := fl.WriteAt(p, start-prefixLen); err != nil {
		return nil, err
	}
	// The trailer goes last, after an fsync: the tail is several writes, and
	// without it a crash could keep the trailer and lose a page of the body.
	// Open calls that segment corrupt, not unfinished, so recovery would
	// leave it out; this way it's only ever unfinished (no trailer).
	if err := syncSeg(fl); err != nil {
		return nil, err
	}
	var tr [trailerLen]byte
	binary.LittleEndian.PutUint32(tr[:], uint32(w.n))
	binary.LittleEndian.PutUint32(tr[4:], w.crc)
	copy(tr[8:], endMagic)
	if _, err := fl.WriteAt(tr[:], start+w.n); err != nil {
		return nil, err
	}
	if dir {
		f.RawChunks, f.Templates, f.Meta = slices.Clone(s.rawChunks), slices.Clip(s.templates), s.meta
	}
	return f, nil
}
