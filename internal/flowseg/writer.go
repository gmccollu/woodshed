package flowseg

import (
	"encoding/binary"
	"io"
	"math/bits"
	"os"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Writer appends records and raw sets to one segment. Its methods are safe
// for concurrent use (queries call Snapshot while the store appends).
//
// Records collect in the open block, which is written as one section when it
// reaches MaxBlockRows, when a record arrives 1 s or more after the block's
// first, and on Flush (the store calls it every second). A failed write
// drops what it was writing (the open block with the template chunk before
// it, or the waiting raw sets) and returns the error; the file is cut back to
// the last complete section, so later writes still land after good data, and
// a cut that fails only leaves torn bytes the next write overwrites (and
// readers and Recover stop at). An Append whose flush fails drops its own
// record too. TakeMinutes never counts a dropped block (fault_test.go).
type Writer struct {
	mu     sync.Mutex
	f      segFile
	path   string
	st     *segState
	enc    encoder
	closed bool

	rows      []flow.Record
	meta      []rowMeta
	firstRecv int64
	maxRecv   int64
	openBytes int64

	raws     []flow.RawSet
	rawBytes int64

	tmplPtr     map[*flow.Template]uint32 // index + 1
	tmplKey     map[string]uint32
	tmplWritten int
	metaDirty   bool

	pending   minuteAcc // flushed since the last TakeMinutes
	perRow    float64   // stored bytes per record so far, for Size's estimate
	written   int64     // records in flushed blocks
	writtenSz int64     // their blocks' bytes
}

// recordSize is what one buffered record costs in memory, besides its extras
// and strings.
const recordSize = int64(unsafe.Sizeof(flow.Record{}) + unsafe.Sizeof(rowMeta{}))

// rawFlushBytes: raw sets are written once this many bytes wait (or on Flush).
const rawFlushBytes = 1 << 20

// Create starts a new segment at path (which must not exist) for deviceID and
// the hour holding hour, stamped with the writer's Woodshed version.
func Create(path, deviceID string, hour time.Time, version string) (*Writer, error) {
	if len(deviceID) > maxDeviceID {
		deviceID = deviceID[:maxDeviceID]
	}
	if len(version) > maxVersion {
		version = version[:maxVersion]
	}
	h := header{deviceID: deviceID, hour: hour.UTC().Truncate(time.Hour).UnixMilli(), version: version,
		created: time.Now().UnixMilli()}
	hb := encodeHeader(h)
	h.length = len(hb)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteAt(hb, 0); err != nil {
		f.Close()
		os.Remove(path)
		return nil, err
	}
	return &Writer{f: wrapFile(f), path: path, st: newSegState(h), tmplPtr: map[*flow.Template]uint32{},
		tmplKey: map[string]uint32{}, pending: minuteAcc{}, perRow: 20}, nil
}

// segFile is what a Writer needs of its file (an *os.File; tests wrap it to
// inject failures).
type segFile interface {
	io.ReaderAt
	io.WriterAt
	Truncate(size int64) error
	Close() error
	Sync() error
}

// wrapFile is the seam tests use to put a failing file under a Writer.
var wrapFile = func(f *os.File) segFile { return f }

// syncSeg fsyncs a segment file through syncFile when it's a real file.
func syncSeg(f segFile) error {
	if of, ok := f.(*os.File); ok {
		return syncFile(of)
	}
	return f.Sync()
}

// Path returns the segment's path.
func (w *Writer) Path() string { return w.path }

// intern returns a template's table index + 1, adding it if new.
func (w *Writer) intern(t *flow.Template) uint32 {
	if t == nil {
		return 0
	}
	if i, ok := w.tmplPtr[t]; ok {
		return i
	}
	k := templateKey(t)
	i, ok := w.tmplKey[k]
	if !ok {
		w.st.templates = append(w.st.templates, t)
		i = uint32(len(w.st.templates))
		w.tmplKey[k] = i
	}
	w.tmplPtr[t] = i
	return i
}

// AddTemplate puts a template in the segment's table even if no record uses
// it, so raw sets that needed it can be decoded from the segment later.
func (w *Writer) AddTemplate(t *flow.Template) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.closed {
		w.intern(t)
	}
}

// SetMeta sets the exporter metadata blob the template table carries (the
// latest wins).
func (w *Writer) SetMeta(m []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || len(m) > maxMeta {
		return
	}
	w.st.meta = slices.Clone(m)
	w.metaDirty = true
}

// Append adds a record to the open block (copying it). An invalid address
// with its Has bit set is stored as absent.
func (w *Writer) Append(r *flow.Record) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	if n := len(w.rows); n > 0 && (n >= MaxBlockRows || r.Received > w.maxRecv && r.Received-w.firstRecv >= 1000) {
		if err := w.flushBlock(); err != nil {
			return err
		}
	}
	if len(w.rows) == 0 {
		w.firstRecv, w.maxRecv = r.Received, r.Received
	}
	w.maxRecv = max(w.maxRecv, r.Received)
	w.rows = append(w.rows, *r)
	c := &w.rows[len(w.rows)-1]
	for _, bit := range [...]uint64{flow.HasSrc, flow.HasDst, flow.HasNextHop, flow.HasPostNATSrc, flow.HasPostNATDst} {
		if c.Has&bit != 0 && !addrOf(c, bits.TrailingZeros64(bit)).IsValid() {
			c.Has &^= bit
		}
	}
	sz := recordSize + int64(len(c.RuleID)+len(c.InIfName)+len(c.OutIfName))
	if len(r.Extras) > 0 {
		xs := make([]flow.Extra, len(r.Extras))
		n := 0
		for _, x := range r.Extras {
			n += len(x.Value)
		}
		arena := make([]byte, 0, n)
		for i, x := range r.Extras {
			s := len(arena)
			arena = append(arena, x.Value...)
			xs[i] = flow.Extra{PEN: x.PEN, ID: x.ID, Value: arena[s:len(arena):len(arena)]}
		}
		c.Extras = xs
		sz += int64(n) + int64(len(xs))*int64(unsafe.Sizeof(flow.Extra{}))
	}
	w.meta = append(w.meta, rowMeta{tmpl: w.intern(r.Template)})
	w.openBytes += sz
	return nil
}

// AppendRaw adds a raw set (copying it); it's written with the next flush.
func (w *Writer) AppendRaw(r *flow.RawSet) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	c := *r
	c.Header, c.Data = slices.Clone(r.Header), slices.Clone(r.Data)
	if len(c.Header) > maxRawEntry {
		c.Header = c.Header[:maxRawEntry]
	}
	if len(c.Data) > maxRawEntry {
		c.Data = c.Data[:maxRawEntry]
	}
	if c.Status != flow.StatusMalformed {
		c.Status = flow.StatusNoTemplate
	}
	w.raws = append(w.raws, c)
	w.rawBytes += int64(len(c.Header)+len(c.Data)) + int64(unsafe.Sizeof(c))
	if w.rawBytes >= rawFlushBytes {
		return w.flushRaw()
	}
	return nil
}

// Flush writes the open block and the waiting raw sets (no fsync).
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	return w.flushLocked()
}

func (w *Writer) flushLocked() error {
	err := w.flushBlock()
	if e := w.flushRaw(); err == nil {
		err = e
	}
	return err
}

// writeSection writes sec at the end; on failure the file is cut back.
func (w *Writer) writeSection(sec []byte) error {
	if _, err := w.f.WriteAt(sec, w.st.off); err != nil {
		w.f.Truncate(w.st.off)
		return err
	}
	return nil
}

// flushTemplates writes a template chunk with the templates and metadata new
// since the last one, before a block that may use them.
func (w *Writer) flushTemplates() error {
	if w.tmplWritten == len(w.st.templates) && !w.metaDirty {
		return nil
	}
	c := tmplChunk{first: w.tmplWritten, templates: w.st.templates[w.tmplWritten:], meta: w.st.meta, hasMeta: w.metaDirty}
	sec := section(magicTmpl, encodeTmplChunk(c))
	if err := w.writeSection(sec); err != nil {
		return err
	}
	w.st.off += int64(len(sec))
	w.tmplWritten = len(w.st.templates)
	w.metaDirty = false
	return nil
}

func (w *Writer) flushBlock() error {
	if len(w.rows) == 0 {
		return nil
	}
	rows, meta := w.rows, w.meta
	w.rows, w.meta, w.openBytes = w.rows[:0], w.meta[:0], 0
	defer func() {
		clear(rows) // drop references to strings, extras and templates
	}()
	if err := w.flushTemplates(); err != nil {
		return err
	}
	body, bi := w.enc.encodeBlock(rows, meta)
	sec := section(magicBlock, body)
	if err := w.writeSection(sec); err != nil {
		return err
	}
	off := w.st.off
	hl, n := binary.Uvarint(body)
	w.st.addBlock(bi, off, int64(len(sec)), off+prefixLen+int64(n), int64(hl))
	w.pending.merge(bi.Minutes)
	w.written += int64(bi.Rows)
	w.writtenSz += int64(len(sec))
	w.perRow = float64(w.writtenSz) / float64(w.written)
	return nil
}

func (w *Writer) flushRaw() error {
	if len(w.raws) == 0 {
		return nil
	}
	raws := w.raws
	w.raws, w.rawBytes = nil, 0
	body := encodeRawChunk(raws)
	sec := section(magicRaw, body)
	if err := w.writeSection(sec); err != nil {
		return err
	}
	c, _ := decodeRawChunk(body, nil)
	c.Offset, c.Length = w.st.off, int64(len(sec))
	w.st.addRaw(c)
	return nil
}

// Sync fsyncs what's been flushed.
func (w *Writer) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrClosed
	}
	return syncSeg(w.f)
}

// Close flushes, writes the template table, the footer and the trailer,
// fsyncs and closes the file. The footer is written through a bounded
// buffer, so Close's memory doesn't grow with it. It returns the footer as
// Open would read it: blocks' directory entries only, their index not
// loaded (Reader.Block loads one from the footer's copy). After an error the
// file is closed anyway; Recover can finish it.
func (w *Writer) Close() (*Footer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	w.closed = true
	err := w.flushLocked()
	if err == nil {
		err = w.flushTemplates()
	}
	var f *Footer
	if err == nil {
		f, err = w.st.writeTail(w.f)
	}
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Size is the segment's size on disk plus an estimate for the open block and
// waiting raw sets (the store starts a new part at 256 MiB).
func (w *Writer) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st.off + int64(float64(len(w.rows))*w.perRow) + w.rawBytes
}

// Rows is the number of records appended (flushed or not).
func (w *Writer) Rows() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.written + int64(len(w.rows))
}

// OpenBytes is the memory the open block and waiting raw sets hold (the store
// flushes early to keep every writer's together under its cap).
func (w *Writer) OpenBytes() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.openBytes + w.rawBytes
}

// TakeMinutes returns the per-minute counts of the blocks written since the
// last call, sorted (records still in the open block aren't in them yet, so
// the index never counts what a crash would lose). Their sum over a segment's
// life equals its footer's Minutes.
func (w *Writer) TakeMinutes() []Minute {
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.pending.sorted()
	w.pending = minuteAcc{}
	return m
}

// Snapshot returns the footer of what's been written so far (complete
// sections only), for OpenSnapshot; its blocks' index isn't loaded. It
// copies the whole block directory (472 bytes a block): callers that only
// need the totals use Summary.
func (w *Writer) Snapshot() *Footer {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st.footer()
}

// Summary returns the segment-level fields of what's been written so far
// (identity, totals, raw counts, time ranges, samplings, domains, minutes),
// as Snapshot would, without the block directory, raw chunks, templates or
// metadata (Blocks, RawChunks, Templates and Meta are nil). Its cost doesn't
// grow with the blocks written: the store calls it on every flush for the
// index rows (index.FlowRowsOf).
func (w *Writer) Summary() *Footer {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.st.summary()
}

// Blocks is the number of blocks written (the store starts a new part at
// its block limit, which bounds the writer's directory and the footer).
func (w *Writer) Blocks() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.st.blocks)
}

// Footer is Snapshot's running totals (an alias kept for callers that only
// want the counts).
func (w *Writer) Footer() *Footer { return w.Snapshot() }
