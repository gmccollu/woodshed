package search

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
)

// Each and Around are the engine behind `woodshed search` (SPEC §11.4): one
// search run to the end of its range with no time budget, its results handed
// over as they're found, and the stored lines around each result for
// --context.

// Result is one line of Each or Around: a search result with its place in its
// file and the line as stored.
type Result struct {
	Line
	FileID, Offset int64
	// Stored is the line as it is in the file, without its '\n': "<received>
	// <sender> <escaped record>". Each's is valid only until fn returns;
	// Around's stays valid.
	Stored []byte
}

// EachStats describes one Each run.
type EachStats struct {
	Matches      int64
	ScannedBytes int64
	ScannedFiles int
	// GoneFiles are the files skipped because they disappeared (retention) or
	// couldn't be read during the run.
	GoneFiles int
	Elapsed   time.Duration
}

// Ring budget for a desc Each: a compressed file read backwards is read
// forwards in passes that each keep this many bytes of the latest matches.
const (
	eachRingTotal = 256 << 20
	eachRingMin   = 4 << 20
	eachRingMax   = 64 << 20
)

// Each runs q to the end of its time range in the merge order of Search (q's
// Limit and Cursor aren't used), calling fn with each result as soon as the
// merge can place it, so a caller can stream them. There is no time budget:
// cancelling ctx stops it, with ctx's error. An error from fn stops it too and
// is returned as it is. A bad query is a *QueryError, before any reading.
func (e *Engine) Each(ctx context.Context, q Query, fn func(*Result) error) (EachStats, error) {
	start := time.Now()
	var st EachStats
	if q.Cursor != "" {
		return st, &QueryError{Msg: "Each doesn't take a cursor."}
	}
	c, err := e.compile(q.Filter)
	if err != nil {
		return st, err
	}
	r := &run{e: e, ctx: ctx, now: e.now(), desc: !q.Asc, m: c.m, ex: c.ex, fields: c.fields, sevs: q.Severities,
		facs: q.Facilities, need: 1 << 30, files: map[int64]struct{}{}, gone: map[int64]struct{}{}}
	if r.fromMs, r.toMs, err = e.resolveRange(q.Filter); err != nil {
		return st, err
	}
	finish := func(err error) (EachStats, error) {
		st.ScannedBytes, st.ScannedFiles, st.GoneFiles, st.Elapsed = r.scanned, len(r.files), len(r.gone), time.Since(start)
		return st, err
	}
	if q.Severities == hub.SeverityNone || q.Facilities == FacilityNone {
		return finish(nil)
	}
	devs, err := e.devices(ctx, q.Devices, q.Group, q.Ungrouped, q.ExcludeDevices)
	if err != nil {
		return finish(err)
	}
	files, err := e.filesByDevice(ctx, devs, r.fromMs, r.toMs)
	if err != nil {
		return finish(err)
	}
	streams := make([]*stream, 0, len(devs))
	for _, d := range devs {
		s := newStream(d, files[d])
		if r.desc {
			s.fi = len(s.files) - 1
		}
		streams = append(streams, s)
	}
	r.streams = streams
	r.ringBytes = min(max(eachRingTotal/max(len(streams), 1), eachRingMin), eachRingMax)
	defer func() {
		for _, s := range streams {
			s.close()
		}
	}()
	if !r.desc {
		for _, s := range streams {
			s.warm(r)
		}
	}
	var res Result
	for {
		s := r.pick(streams)
		if s == nil {
			break
		}
		if s.head() == nil {
			if r.expired() {
				break
			}
			s.step(r)
			if r.err != nil {
				break
			}
			continue
		}
		h := s.pop()
		res = Result{Line: e.line(s.dev, h), FileID: h.file.ID, Offset: h.off, Stored: h.line}
		st.Matches++
		if err := fn(&res); err != nil {
			return finish(err)
		}
	}
	return finish(r.err)
}

// Around reads the stored lines around results, each from the result's own
// file only, like grep -C (woodshed search --context). It keeps a reader per
// file for the last few files it was asked about, so results of several
// devices interleaved by the merge don't make it start again each time:
//
//   - In file order (an asc search) each file is read forwards once.
//   - Backwards (desc), a compressed file is decompressed once and kept whole
//     in memory, up to aroundWholeCap for all files together. A plain file (or
//     a compressed one past the cap) starts again at a checkpoint a window
//     before the line and keeps the window's lines, so the next results within
//     it need no new reading; past the cap, each such restart decompresses
//     from the start of the file.
//
// It is not safe for concurrent use.
type Around struct {
	e     *Engine
	ctx   context.Context
	desc  bool
	r     *run // matches every line
	files []*aroundFile
	tick  int64
	whole int64 // bytes of the files kept whole

	window, wholeCap int64 // aroundWindow and aroundWholeCap (tests change them)
}

// aroundFile is Around's reader of one file.
type aroundFile struct {
	fi      *fileInfo
	o       *opened
	fw      *fwd
	ring    []hit // lines read and kept, in file order
	trimmed bool  // lines before ring[0] exist (dropped, or before the reader's start)
	done    bool  // fw has returned every complete line
	used    int64
	whole   int64 // > 0: the whole file is in ring (its uncompressed size)
}

const (
	aroundFiles  = 16      // readers kept
	aroundWindow = 4 << 20 // desc: bytes of lines kept behind a restart's target
	// aroundWholeCap bounds the compressed files a desc Around keeps whole.
	aroundWholeCap = 256 << 20
)

// NewAround returns an Around for the results of a search in the given
// order. Close it when done.
func (e *Engine) NewAround(ctx context.Context, desc bool) *Around {
	return &Around{e: e, ctx: ctx, desc: desc, window: aroundWindow, wholeCap: aroundWholeCap, r: &run{e: e, ctx: ctx, m: &matcher{kind: matchAll}, fromMs: -1 << 62,
		toMs: 1 << 62, files: map[int64]struct{}{}}}
}

// Close closes the open files.
func (a *Around) Close() {
	for _, f := range a.files {
		a.release(f)
	}
	a.files = nil
}

// release closes f and returns its memory to the whole-file budget.
func (a *Around) release(f *aroundFile) {
	a.whole -= f.whole
	f.whole = 0
	f.close()
}

func (f *aroundFile) close() {
	if f.o != nil {
		f.o.Close()
		f.o = nil
	}
	f.fw, f.ring = nil, nil
}

// file returns the reader of a file, opening it (and closing the least
// recently used one) if needed.
func (a *Around) file(fileID int64) (*aroundFile, error) {
	a.tick++
	for _, f := range a.files {
		if f.fi.ID == fileID {
			f.used = a.tick
			return f, nil
		}
	}
	fi := &fileInfo{File: index.File{ID: fileID}}
	o, err := a.e.open(a.ctx, fi)
	if errors.Is(err, errGone) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	f := &aroundFile{fi: fi, o: o, used: a.tick}
	if len(a.files) >= aroundFiles {
		lru := 0
		for i, g := range a.files {
			if g.used < a.files[lru].used {
				lru = i
			}
		}
		a.release(a.files[lru])
		a.files[lru] = f
	} else {
		a.files = append(a.files, f)
	}
	return f, nil
}

// Lines returns up to before stored lines before the line at offset off of the
// file with ID fileID, oldest first, and up to after lines after it, from that
// file only. Lines that don't parse are left out, as in a search. A file that's
// gone gives ErrNotFound; a line that isn't there (any more) gives no lines.
func (a *Around) Lines(fileID, off int64, before, after int) (pre, post []Result, err error) {
	before, after = max(before, 0), max(after, 0)
	f, err := a.file(fileID)
	if err != nil {
		return nil, nil, err
	}
	if f.mustRestart(off, before) {
		if err := a.restart(f, off, before); err != nil {
			return nil, nil, err
		}
	}
	// Read up to the target, keeping the lines that may be wanted again.
	i, ok := f.find(off)
	for !ok && !f.done && (len(f.ring) == 0 || f.lastOff() < off) {
		a.trim(f, before)
		if err := a.read(f); err != nil {
			return nil, nil, err
		}
		i, ok = f.find(off)
	}
	if !ok {
		return nil, nil, nil
	}
	for _, h := range f.ring[max(0, i-before):i] {
		pre = append(pre, a.result(f, h))
	}
	for j := i + 1; len(post) < after; {
		if j < len(f.ring) {
			post = append(post, a.result(f, f.ring[j]))
			j++
			continue
		}
		if f.done {
			break
		}
		if err := a.read(f); err != nil {
			return nil, nil, err
		}
	}
	return pre, post, nil
}

// trim drops the lines no later request can want: for asc everything but the
// last before lines (later targets come after them), for desc whatever is more
// than the window behind the newest line.
func (a *Around) trim(f *aroundFile, before int) {
	if f.whole > 0 {
		return
	}
	k := len(f.ring) - before
	if a.desc {
		k = 0
		for k < len(f.ring)-before && f.lastOff()-f.ring[k].off > a.window {
			k++
		}
	}
	if k <= 0 {
		return
	}
	f.ring = f.ring[k:]
	f.trimmed = true
	if cap(f.ring) > 4096 && len(f.ring) < cap(f.ring)/4 {
		f.ring = append([]hit(nil), f.ring...)
	}
}

func (a *Around) result(f *aroundFile, h hit) Result {
	return Result{Line: a.e.line(f.fi.DeviceID, h), FileID: f.fi.ID, Offset: h.off, Stored: append([]byte(nil), h.line...)}
}

// mustRestart reports whether the reader can't give the line at off and the
// before lines ahead of it by reading on: it has passed them (or dropped
// them), or it reached the end of a file that may have grown since.
func (f *aroundFile) mustRestart(off int64, before int) bool {
	if f.whole > 0 {
		return false // every line is in the ring
	}
	if f.fw == nil {
		return true
	}
	if i, ok := f.find(off); ok {
		return i < before && f.trimmed
	}
	return off < f.fw.off || f.done
}

// find returns the index of the ring line at off.
func (f *aroundFile) find(off int64) (int, bool) {
	i := sort.Search(len(f.ring), func(i int) bool { return f.ring[i].off >= off })
	return i, i < len(f.ring) && f.ring[i].off == off
}

func (f *aroundFile) lastOff() int64 {
	if len(f.ring) == 0 {
		return -1
	}
	return f.ring[len(f.ring)-1].off
}

// restart positions the reader at a checkpoint with at least before lines
// before off (or the start of the file); for desc, also a window before off.
func (a *Around) restart(f *aroundFile, off int64, before int) error {
	if size := f.fi.RawSize; a.desc && f.o.file.Compressed && size > 0 && a.whole+size <= a.wholeCap {
		// gzip reads only forwards: decompress it once and keep it.
		rd, err := f.o.reader(0)
		if err != nil {
			return err
		}
		f.fw, f.ring, f.trimmed, f.done = newFwd(rd, 0, a.e.block), nil, false, false
		for !f.done {
			if err := a.read(f); err != nil {
				return err
			}
		}
		f.whole = size
		a.whole += size
		return nil
	}
	cps := f.fi.cps
	k := sort.Search(len(cps), func(i int) bool { return cps[i].Offset > off }) - 1
	var start int64
	if k >= 0 {
		wantLine, wantOff := cps[k].Line-int64(before), off
		if a.desc {
			wantOff = off - a.window/2
		}
		for j := k; j >= 0; j-- {
			if cps[j].Line <= wantLine && cps[j].Offset <= wantOff {
				start = cps[j].Offset
				break
			}
		}
	}
	rd, err := f.o.reader(start)
	if err != nil {
		return err
	}
	f.fw, f.ring, f.trimmed, f.done = newFwd(rd, start, a.e.block), nil, start > 0, false
	return nil
}

// read appends the next block of lines to the ring.
func (a *Around) read(f *aroundFile) error {
	buf, boff, err := f.fw.next()
	if err != nil || buf == nil {
		f.done = true
		return err
	}
	f.ring = a.r.lines(buf, boff, -1, f.fi, f.ring)
	return nil
}
