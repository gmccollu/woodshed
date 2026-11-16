package flowseg

import (
	"io"
	"slices"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// segState is what a writer (or a recovery) knows about the sections written
// so far, enough to write the template table and the footer.
type segState struct {
	h         header
	off       int64       // the end of the last complete section
	blocks    []BlockInfo // without their index (it's re-read from the file for the footer)
	hdrSpans  [][2]int64  // each block's header bytes in the file (offset, length)
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

// addBlock records a block written at off (its section is length bytes; its
// header bytes at hdrOff, hdrLen). bi has its index loaded.
func (s *segState) addBlock(bi *BlockInfo, off, length, hdrOff, hdrLen int64) {
	lite := *bi
	lite.Offset, lite.Length = off, length
	lite.Minutes, lite.hdr = nil, nil
	lite.inIfs, lite.outIfs, lite.keys = ifSet{}, ifSet{}, bloom{}
	lite.protos = [4]uint64{}
	lite.loaded = false
	s.blocks = append(s.blocks, lite)
	s.hdrSpans = append(s.hdrSpans, [2]int64{hdrOff, hdrLen})
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

// footer builds the footer (blocks as stored: their index not loaded).
func (s *segState) footer() *Footer {
	f := &Footer{
		DeviceID: s.h.deviceID, Hour: time.UnixMilli(s.h.hour).UTC(), WriterVersion: s.h.version,
		Totals: s.totals, Raw: s.raw, RawStatus: s.rawStatus,
		Samplings: sortedU32(s.samplings), Domains: sortedU32(s.domains), Minutes: s.minutes.sorted(),
		Blocks: slices.Clone(s.blocks), RawChunks: slices.Clone(s.rawChunks),
		Templates: slices.Clip(s.templates), Meta: s.meta,
	}
	if s.haveRecv {
		f.MinReceived, f.MaxReceived = s.minRecv, s.maxRecv
	}
	if s.haveFlow {
		f.MinStart, f.MaxEnd = s.minStart, s.maxEnd
	}
	return f
}

// writeTail writes the template table, the footer and the trailer at s.off,
// cutting the file there first, then fsyncs. It returns the footer, with
// the blocks' index loaded.
func (s *segState) writeTail(fl segFile) (*Footer, error) {
	if err := fl.Truncate(s.off); err != nil {
		return nil, err
	}
	hdrs := make([][]byte, len(s.blocks))
	for i, sp := range s.hdrSpans {
		h := make([]byte, sp[1])
		if _, err := fl.ReadAt(h, sp[0]); err != nil && err != io.EOF {
			return nil, err
		}
		hdrs[i] = h
	}
	f := s.footer()
	table := section(magicTable, encodeTmplChunk(tmplChunk{templates: s.templates, meta: s.meta, hasMeta: true}))
	f.tableOff = s.off
	body := encodeFooter(f, hdrs)
	out := append(table, section(magicFoot, body)...)
	out = putU32(out, uint32(len(body)))
	out = putU32(out, crc(body))
	out = append(out, endMagic...)
	if _, err := fl.WriteAt(out, s.off); err != nil {
		fl.Truncate(s.off)
		return nil, err
	}
	if err := syncSeg(fl); err != nil {
		return nil, err
	}
	size := s.off + int64(len(out))
	full, ok := decodeFooter(body, size)
	if !ok {
		return nil, ErrCorrupt // can't happen: we just encoded it
	}
	full.Templates, full.Meta, full.tableOff = f.Templates, f.Meta, f.tableOff
	return full, nil
}
