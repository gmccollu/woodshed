package flowseg

import (
	"os"
	"slices"
	"sync"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Reader reads a segment: its footer (or a writer's snapshot) and blocks.
// Safe for concurrent use: queries decode different blocks in parallel.
type Reader struct {
	f    *os.File
	size int64
	h    header
	foot *Footer
	mu   sync.Mutex // guards lazy loading of blocks' index
}

// Open opens a closed segment. It returns ErrNoFooter for one still being
// written or left by a crash (Recover closes it), ErrBadHeader for a file that
// isn't a segment.
func Open(path string) (*Reader, error) {
	f, err := logfile.OpenFile(path) // shared: the store may delete it while it's read (Windows)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	h, err := readHeaderAt(f, st.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	foot, err := readFooter(f, st.Size(), h.length)
	if err != nil {
		f.Close()
		return nil, err
	}
	if foot.DeviceID != h.deviceID || foot.Hour.UnixMilli() != h.hour {
		f.Close()
		return nil, ErrCorrupt
	}
	return &Reader{f: f, size: st.Size(), h: h, foot: foot}, nil
}

// OpenSnapshot opens a segment that's still being written, through its
// writer's Snapshot: only the sections the snapshot lists are read (a
// snapshot never lists a section that isn't complete on disk). Its blocks'
// index is loaded on first use (Block).
func OpenSnapshot(path string, snap *Footer) (*Reader, error) {
	f, err := logfile.OpenFile(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	h, err := readHeaderAt(f, st.Size())
	if err != nil {
		f.Close()
		return nil, err
	}
	foot := *snap
	foot.Blocks = slices.Clone(snap.Blocks)
	return &Reader{f: f, size: st.Size(), h: h, foot: &foot}, nil
}

// Close closes the file.
func (r *Reader) Close() error { return r.f.Close() }

// Footer returns the segment's footer (shared; don't modify it). Its blocks
// carry their directory fields only; Block loads one's index.
func (r *Reader) Footer() *Footer { return r.foot }

// Templates is the segment's template table; Meta its exporter metadata.
func (r *Reader) Templates() []*flow.Template { return r.foot.Templates }
func (r *Reader) Meta() []byte                { return r.foot.Meta }

// Blocks is the number of blocks.
func (r *Reader) Blocks() int { return len(r.foot.Blocks) }

// Block returns block i's directory entry with its index loaded, read from
// the file (the footer's copy of its header, or the block itself) and not
// kept, so a scan's memory doesn't grow with the blocks it checks.
func (r *Reader) Block(i int) (*BlockInfo, error) {
	if i < 0 || i >= len(r.foot.Blocks) {
		return nil, ErrCorrupt
	}
	bi := &r.foot.Blocks[i]
	if bi.loaded {
		return bi, nil
	}
	full := BlockInfo{Offset: bi.Offset, Length: bi.Length}
	if bi.hdrLen > 0 && bi.hdrLen <= bi.Length && bi.hdrOff > 0 && bi.hdrOff+bi.hdrLen <= r.size {
		hdr := make([]byte, bi.hdrLen)
		if _, err := r.f.ReadAt(hdr, bi.hdrOff); err == nil {
			hd := &dec{b: hdr}
			readHeader(hd, &full)
			if hd.err == nil && len(hd.b) == 0 && full.Rows == bi.Rows && full.MinReceived == bi.MinReceived {
				full.hdrOff, full.hdrLen = bi.hdrOff, bi.hdrLen
				return &full, nil
			}
		}
		full = BlockInfo{Offset: bi.Offset, Length: bi.Length}
	}
	magic, body, ok := readSection(r.f, bi.Offset, min(r.size, bi.Offset+bi.Length), nil)
	if !ok || magic != magicBlock {
		return nil, ErrCorrupt
	}
	d := &dec{b: body}
	hl := d.limit(uint64(len(body)))
	hdr := d.next(int(hl))
	hd := &dec{b: hdr}
	readHeader(hd, &full)
	if d.err != nil || hd.err != nil || len(hd.b) != 0 {
		return nil, ErrCorrupt
	}
	full.hdr = slices.Clone(hdr)
	return &full, nil
}

// Decode decodes block i's columns cols into b (reused). The block's CRC is
// checked on every read.
func (r *Reader) Decode(i int, cols Cols, b *Block) error {
	if i < 0 || i >= len(r.foot.Blocks) {
		return ErrCorrupt
	}
	bi := &r.foot.Blocks[i]
	magic, body, ok := readSection(r.f, bi.Offset, min(r.size, bi.Offset+bi.Length), b.buf)
	if !ok || magic != magicBlock || int64(len(body))+prefixLen != bi.Length {
		return ErrCorrupt
	}
	b.buf = body
	if err := decodeBody(body, cols, r.foot.Templates, b); err != nil {
		return ErrCorrupt
	}
	b.buf = body
	if b.Info.Rows != bi.Rows {
		return ErrCorrupt
	}
	b.Info.Offset, b.Info.Length = bi.Offset, bi.Length
	return nil
}

// ReadBlock decodes block i's columns cols as records, appended to buf[:0].
func (r *Reader) ReadBlock(i int, cols Cols, buf []flow.Record) ([]flow.Record, error) {
	var b Block
	if err := r.Decode(i, cols, &b); err != nil {
		return buf[:0], err
	}
	out := buf[:0]
	for row := 0; row < b.Rows; row++ {
		out = append(out, flow.Record{})
		b.Record(row, &out[len(out)-1])
	}
	return out, nil
}

// Raw calls fn with each raw set, in order, until it returns false.
func (r *Reader) Raw(fn func(*flow.RawSet) bool) error {
	for _, c := range r.foot.RawChunks {
		magic, body, ok := readSection(r.f, c.Offset, min(r.size, c.Offset+c.Length), nil)
		if !ok || magic != magicRaw {
			return ErrCorrupt
		}
		stop := false
		if _, ok := decodeRawChunk(body, func(rs *flow.RawSet) bool {
			if !fn(rs) {
				stop = true
				return false
			}
			return true
		}); !ok {
			return ErrCorrupt
		}
		if stop {
			return nil
		}
	}
	return nil
}

// OpenLive opens a segment without changing it, footer or not: a closed one
// as Open does, and one still being written (or left by a crash) by scanning
// its sections from the start, as Recover would, up to the first that's cut
// short or fails its CRC (a block the writer is writing just ends the scan).
// The footer is built in memory from the blocks, raw chunks and template
// chunks found; nothing is cut or written. Use it from another process (the
// CLI beside the service); inside the writer's process, OpenSnapshot is
// cheaper. Blocks' index loads on first use (Block).
func OpenLive(path string) (*Reader, error) {
	f, err := logfile.OpenFile(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	size := st.Size()
	h, err := readHeaderAt(f, size)
	if err != nil {
		f.Close()
		return nil, err
	}
	if foot, err := readFooter(f, size, h.length); err == nil && foot.DeviceID == h.deviceID && foot.Hour.UnixMilli() == h.hour {
		return &Reader{f: f, size: size, h: h, foot: foot}, nil
	}
	s := scan(f, size, h)
	return &Reader{f: f, size: s.off, h: h, foot: s.footer()}, nil
}
