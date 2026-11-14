package search

import (
	"bytes"
	"context"
	"errors"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// run is the state of one scan (one search request, or one export device).
type run struct {
	e        *Engine
	ctx      context.Context
	deadline time.Time // zero: no budget
	now      time.Time

	fromMs, toMs int64 // lines with fromMs <= received < toMs
	desc         bool
	m            *matcher
	ex           *matcher        // nil: no exclude
	fields       *fieldMatcher   // nil: no app or host filter
	sevs         hub.SeveritySet // 0: all
	facs         FacilitySet     // 0: all

	need int // results still wanted (bounds the compressed-file ring)
	// cacheKey is the search's parameters and range, for the caches ("": don't cache).
	cacheKey string
	// ringBytes is how many bytes of matches a compressed-file pass keeps.
	ringBytes int
	// streams are the request's streams (for prefetch); prefetched is set once
	// prefetch has run.
	streams    []*stream
	prefetched bool
	// noDeadline is set while re-reading a stream's known next line: that
	// is part of returning a result the previous page found, not new reading.
	noDeadline bool
	// steps counts the reads a request has made (re-reading a pending line
	// excluded); with maxSteps > 0 (tests) the budget is that many reads instead
	// of a time, so budget tests don't depend on the OS timer's resolution.
	steps, maxSteps int
	scanned         int64 // bytes of uncompressed stream read for matching
	files           map[int64]struct{}
	// gone, when set (Each), collects the files skipped because they were
	// gone or couldn't be read.
	gone     map[int64]struct{}
	timedOut bool
	err      error // a context error

	unesc []byte
	msg   model.Message // fields' scratch parse

	// sum is set for a summary scan (sumscan.go): every match goes to it as
	// it's found, and a compressed-file pass that runs out of budget keeps its
	// reader for the next request instead of starting again from the top.
	sum *sumCollect
}

// expired reports whether the budget or the request is over.
func (r *run) expired() bool {
	if r.timedOut || r.err != nil {
		return true
	}
	if err := r.ctx.Err(); err != nil {
		r.err = err
		return true
	}
	if r.noDeadline {
		return false
	}
	if (r.maxSteps > 0 && r.steps >= r.maxSteps) || (!r.deadline.IsZero() && time.Now().After(r.deadline)) {
		r.timedOut = true
		return true
	}
	return false
}

// hit is a matching line.
type hit struct {
	ms       int64
	off, end int64  // the line's offset, and the offset after its '\n'
	line     []byte // the stored line without '\n'
	esc      []byte // the escaped raw message, within line
	file     *fileInfo
}

// check applies the time range, severity, q, exclude and then the app and
// host filters to one stored line: the cheap checks first, so the header is
// parsed only for lines that passed them.
func (r *run) check(line []byte) (int64, []byte, bool) {
	ms, esc, ok := splitLine(line)
	if !ok || ms < r.fromMs || ms >= r.toMs {
		return 0, nil, false
	}
	if r.sevs != 0 || r.facs != 0 || r.m.kind != matchAll || r.ex != nil || r.fields != nil {
		raw := esc
		if bytes.IndexByte(esc, '\\') >= 0 {
			r.unesc = logfile.Unescape(r.unesc[:0], esc)
			raw = r.unesc
		}
		if r.sevs != 0 || r.facs != 0 {
			p := PRI(raw)
			sev, fac := model.Unknown, model.Unknown
			if p >= 0 {
				sev, fac = p&7, p>>3
			}
			if r.sevs != 0 && !r.sevs.Has(sev) {
				return 0, nil, false
			}
			if r.facs != 0 && !r.facs.Has(fac) {
				return 0, nil, false
			}
		}
		if !r.m.match(raw) {
			return 0, nil, false
		}
		if r.ex != nil && r.ex.match(raw) {
			return 0, nil, false
		}
		if r.fields != nil && !r.fields.match(raw, &r.msg) {
			return 0, nil, false
		}
	}
	return ms, esc, true
}

// lines appends the matching lines of buf (complete lines; buf[0] is at offset
// base) to out, in file order. Lines starting at or after limit (if >= 0) are
// left out. With a prefilter it only looks at lines holding a candidate.
func (r *run) lines(buf []byte, base, limit int64, f *fileInfo, out []hit) []hit {
	add := func(ls, le int) {
		if ms, esc, ok := r.check(buf[ls:le]); ok {
			out = append(out, hit{ms: ms, off: base + int64(ls), end: base + int64(le) + 1, line: buf[ls:le], esc: esc, file: f})
		}
	}
	if r.m.prefilter {
		for i := 0; i < len(buf); {
			j := r.m.next(buf, i)
			if j < 0 {
				break
			}
			ls := bytes.LastIndexByte(buf[:j], '\n') + 1
			if limit >= 0 && base+int64(ls) >= limit {
				break
			}
			le := j + bytes.IndexByte(buf[j:], '\n')
			add(ls, le)
			i = le + 1
		}
		return out
	}
	for ls := 0; ls < len(buf); {
		if limit >= 0 && base+int64(ls) >= limit {
			break
		}
		le := ls + bytes.IndexByte(buf[ls:], '\n')
		add(ls, le)
		ls = le + 1
	}
	return out
}

// stream is one device's matching lines in file order (newest first for desc),
// read lazily a block at a time.
//
// Position: in files[fi], the unread region is [rs, pos) for desc and [pos, re)
// for asc, where [rs, re) is the file's region for the time range (re = -1: the
// end of the file). pos = -1 means the file hasn't been started. For a
// compressed file read desc, hint > 0 means a pass that ran out of time had
// read [rs, hint): the next pass covers [hint, pos) first.
type stream struct {
	dev   string
	files []*fileInfo
	fi    int
	pos   int64
	hint  int64
	done  bool // no files left
	// pending: the previous page found this stream's next line (received at
	// pendingMs) at pos but didn't return it. The merge treats it as the head
	// until the stream reads it again.
	pending   bool
	pendingMs int64

	cur      *opened
	rs, re   int64
	fileDone bool // asc: reached the end of the region
	rd       *fwd
	last     []byte // asc: the last block rd returned, at lastOff
	lastOff  int64
	queue    []hit
	qi       int

	// bound caches key's bound until the stream reads again.
	bound      int64
	boundValid bool

	// maxLastBefore[i] is the highest LastReceived (ms) of files[:i];
	// minFirstAfter[i] the lowest FirstReceived of files[i:].
	maxLastBefore, minFirstAfter []int64
}

func newStream(dev string, files []*fileInfo) *stream {
	s := &stream{dev: dev, files: files, pos: -1}
	n := len(files)
	s.maxLastBefore = make([]int64, n+1)
	s.minFirstAfter = make([]int64, n+1)
	s.maxLastBefore[0] = math.MinInt64
	for i, f := range files {
		s.maxLastBefore[i+1] = max(s.maxLastBefore[i], f.LastReceived.UnixMilli())
	}
	s.minFirstAfter[n] = math.MaxInt64
	for i := n - 1; i >= 0; i-- {
		s.minFirstAfter[i] = min(s.minFirstAfter[i+1], files[i].FirstReceived.UnixMilli())
	}
	if n == 0 {
		s.done = true
	}
	return s
}

func (s *stream) head() *hit {
	if s.qi < len(s.queue) {
		return &s.queue[s.qi]
	}
	return nil
}

func (s *stream) pop() hit {
	h := s.queue[s.qi]
	s.queue[s.qi] = hit{}
	s.qi++
	return h
}

func (s *stream) close() {
	if s.cur != nil {
		_ = s.cur.Close()
		s.cur = nil
	}
	s.rd, s.last = nil, nil
}

// park ends the stream at the end of a request: an asc reader of a compressed
// file is kept for the next page, anything else is closed.
func (s *stream) park(r *run) {
	if r.cacheKey != "" && !r.desc && s.cur != nil && s.cur.file.Compressed && s.rd != nil && !s.fileDone {
		r.e.readers.park(s.cur.file.ID, &parked{o: s.cur, rd: s.rd, last: s.last, lastOff: s.lastOff})
		s.cur, s.rd, s.last = nil, nil, nil
		return
	}
	s.close()
}

// nextFile moves to the next file in scan order.
func (s *stream) nextFile(desc bool) {
	s.close()
	s.pos, s.hint, s.fileDone = -1, 0, false
	if desc {
		s.fi--
	} else {
		s.fi++
	}
	if s.fi < 0 || s.fi >= len(s.files) {
		s.done = true
	}
}

// finished reports whether the current file's region has been read.
func (s *stream) finished(desc bool) bool {
	if s.cur == nil {
		return false
	}
	if desc {
		return s.pos >= 0 && s.pos <= s.rs && s.hint == 0
	}
	return s.fileDone
}

// key is the stream's merge key: its head's received time, or a bound on any
// line it hasn't read yet (an upper bound for desc, from the checkpoints; a
// lower bound for asc).
func (s *stream) key(r *run) (int64, bool) {
	if h := s.head(); h != nil {
		return h.ms, true
	}
	if s.pending {
		return s.pendingMs, true
	}
	if !s.boundValid {
		s.bound, s.boundValid = s.computeBound(r), true
	}
	return s.bound, false
}

func (s *stream) computeBound(r *run) int64 {
	fi := s.files[s.fi]
	if r.desc {
		var b int64
		switch {
		case s.pos < 0 || !fi.loaded:
			b = fi.LastReceived.UnixMilli()
			if fi.mayLag(r.now) {
				b = math.MaxInt64
			}
		default:
			b = math.MaxInt64
			if !fi.mayLag(r.now) {
				b = fi.LastReceived.UnixMilli()
			}
			for _, c := range fi.cps {
				if c.Offset >= s.pos {
					b = c.Received.UnixMilli()
					break
				}
			}
		}
		b = max(b, s.maxLastBefore[s.fi])
		return min(b, r.toMs-1)
	}
	b := fi.FirstReceived.UnixMilli()
	if s.pos >= 0 && fi.loaded {
		for _, c := range fi.cps {
			if c.Offset > s.pos {
				break
			}
			b = max(b, c.Received.UnixMilli()-maxSkew.Milliseconds())
		}
	}
	b = min(b, s.minFirstAfter[s.fi+1])
	return max(b, r.fromMs)
}

// step does one unit of reading: it opens the next file or reads one block (a
// whole pass for a compressed file read desc), leaving any matches in the queue.
// It does nothing while the queue holds hits.
func (s *stream) step(r *run) {
	if s.head() != nil || s.done {
		return
	}
	s.boundValid = false
	if s.pending {
		// One read finds the line again (or finds it gone); after that the
		// stream is ordinary.
		r.noDeadline = true
		defer func() { r.noDeadline, s.pending = false, false }()
	}
	s.queue, s.qi = s.queue[:0], 0
	if s.finished(r.desc) {
		s.nextFile(r.desc)
		return
	}
	fi := s.files[s.fi]
	if !s.openCur(r) {
		return
	}
	var err error
	switch {
	case !r.desc:
		err = s.stepAsc(r, fi)
	case s.cur.file.Compressed:
		err = s.passDesc(r, fi)
	default:
		err = s.stepDescPlain(r, fi)
	}
	if err != nil {
		// A file that can't be read (truncated, corrupt, or deleted on an OS that
		// doesn't keep open files readable): keep what was found, skip the rest.
		r.e.log.Warn("search: stopped reading a log file", "file", s.cur.file.Path, "err", err)
		if r.gone != nil {
			r.gone[fi.ID] = struct{}{}
		}
		s.nextFileKeepQueue(r.desc)
	}
}

// openCur opens the current file if it isn't open, and sets its region. It
// reports false (having moved to the next file) when the file is gone.
func (s *stream) openCur(r *run) bool {
	if s.cur != nil {
		return true
	}
	fi := s.files[s.fi]
	o, err := r.e.open(r.ctx, fi)
	if err != nil {
		if !errors.Is(err, errGone) {
			r.e.log.Warn("search: skipping a log file", "file", fi.Path, "err", err)
		}
		if r.gone != nil {
			r.gone[fi.ID] = struct{}{}
		}
		s.nextFile(r.desc)
		return false
	}
	s.cur = o
	r.files[fi.ID] = struct{}{}
	s.rs, s.re = regionStart(fi.cps, r.fromMs), regionEnd(fi.cps, r.toMs)
	if s.pos >= 0 && (s.pos < s.rs || (s.re >= 0 && s.pos > s.re)) {
		// A position outside the region (a hand-made cursor): clamp it.
		s.pos = min(max(s.pos, s.rs), max(s.re, s.rs))
	}
	return true
}

// warm opens an asc stream's first file and starts its read-ahead, so every
// device's compressed file is positioned (decompressed up to the range) at
// once rather than one after another as the merge reaches them.
func (s *stream) warm(r *run) {
	if r.desc || s.done || s.head() != nil || s.finished(false) || !s.openCur(r) {
		return
	}
	if s.cur.file.Compressed && s.rd == nil {
		if err := s.ensureReader(r, s.files[s.fi]); err != nil {
			s.close() // step opens it again and reports the error
		}
	}
}

// nextFileKeepQueue skips the rest of the current file once the queue drains.
func (s *stream) nextFileKeepQueue(desc bool) {
	if s.head() == nil {
		s.nextFile(desc)
		return
	}
	if desc {
		s.pos, s.hint = s.rs, 0
	} else {
		s.fileDone = true
	}
}

func (s *stream) stepDescPlain(r *run, fi *fileInfo) error {
	end, tail := s.pos, false
	if end < 0 {
		if s.re >= 0 {
			end = s.re
		} else {
			size, err := s.cur.size()
			if err != nil {
				return err
			}
			end, tail = size, true
		}
	}
	buf, start, err := readBack(s.cur.f, s.rs, end, r.e.block, tail)
	if err != nil {
		return err
	}
	r.scanned += int64(len(buf))
	hits := r.lines(buf, start, -1, fi, s.queue[:0])
	for i, j := 0, len(hits)-1; i < j; i, j = i+1, j-1 {
		hits[i], hits[j] = hits[j], hits[i]
	}
	s.queue, s.pos = hits, start
	return nil
}

// ensureReader sets up the asc reader at the stream's position: a reader the
// previous page parked, or a new one.
func (s *stream) ensureReader(r *run, fi *fileInfo) error {
	if s.rd != nil {
		return nil
	}
	start := s.pos
	if start < 0 {
		start = s.rs
	}
	if s.cur.file.Compressed && r.cacheKey != "" {
		if p := r.e.readers.take(fi.ID, s.cur.file.Path, start); p != nil {
			s.cur.Close()
			s.cur, s.rd, s.pos = p.o, p.rd, start
			s.rd.prepend(p.last[start-p.lastOff:], start)
			s.last, s.lastOff = nil, start // the prefix is in rd's buffer now
			return nil
		}
	}
	rd, err := s.cur.readAhead(start, r.e.block, r.e.decodeSem)
	if err != nil {
		return err
	}
	s.rd, s.pos = newFwd(rd, start, r.e.block), start
	s.last, s.lastOff = nil, start
	return nil
}

func (s *stream) stepAsc(r *run, fi *fileInfo) error {
	if err := s.ensureReader(r, fi); err != nil {
		return err
	}
	buf, off, err := s.rd.next()
	if err != nil {
		return err
	}
	if buf == nil {
		s.fileDone = true
		return nil
	}
	r.scanned += int64(len(buf))
	s.last, s.lastOff = buf, off
	s.queue = r.lines(buf, off, s.re, fi, s.queue[:0])
	s.pos = off + int64(len(buf))
	if s.re >= 0 && s.pos >= s.re {
		s.pos, s.fileDone = s.re, true
	}
	return nil
}

// passDesc reads [max(rs, hint), pos) of a compressed file forward in one pass
// (gzip can't be read backwards) and queues its last matches, newest first. It
// keeps at most need matches and ringBytes of lines; when it had to drop older
// ones, the next pass covers the region before the oldest it kept.
func (s *stream) passDesc(r *run, fi *fileInfo) error {
	lo := max(s.rs, s.hint)
	hi := s.pos
	if hi < 0 {
		hi = s.re
	}
	if r.sum != nil {
		return s.sumPass(r, fi, lo, hi)
	}
	key := passKey{fi.ID, r.cacheKey}
	if r.cacheKey != "" && s.hint == 0 {
		ent := r.e.passes.get(key, lo, hi)
		if ent == nil && r.prefetch() {
			ent = r.e.passes.get(key, lo, hi)
		}
		if ent != nil {
			q := s.queue[:0]
			for i := len(ent.hits) - 1; i >= 0; i-- {
				if h := ent.hits[i]; hi < 0 || h.end <= hi {
					q = append(q, h)
				}
			}
			s.queue, s.pos, s.hint = q, ent.frontier, 0
			return nil
		}
	}
	kept, frontier, reached, done, err := r.pass(s.cur, fi, lo, hi)
	if err != nil {
		return err
	}
	if !done {
		// Out of time: everything in [lo, reached) has been seen but nothing can
		// be returned before the rest of the pass. Resume the pass from there.
		s.pos, s.hint = hi, reached
		if hi < 0 {
			s.pos = -1
		}
		return nil
	}
	if r.cacheKey != "" && s.hint == 0 {
		r.e.passes.put(&passEntry{key: key, lo: lo, frontier: frontier, end: reached, eof: hi < 0, hits: kept})
	}
	q := s.queue[:0]
	for i := len(kept) - 1; i >= 0; i-- {
		q = append(q, kept[i])
	}
	// Without a drop the pass covered [lo, hi): what's left is [rs, lo), which is
	// empty unless the pass resumed at a hint.
	s.queue, s.pos, s.hint = q, frontier, 0
	return nil
}

// pass reads [lo, hi) of a compressed file (hi -1: to the end) forward and
// returns its last matches in offset order: at most need of them (or as many
// as ringBytes holds, when caching). frontier is where the kept matches
// start being complete (lo unless older ones were dropped); reached is where
// the pass got to. done is false when the budget ran out first.
func (r *run) pass(o *opened, fi *fileInfo, lo, hi int64) (kept []hit, frontier, reached int64, done bool, err error) {
	rd, err := o.readAhead(lo, r.e.block, r.e.decodeSem)
	if err != nil {
		return nil, 0, 0, false, err
	}
	fr := newFwd(rd, lo, r.e.block)
	// Keep more than this page needs when caching: the next pages use it.
	keep := max(r.need, 1)
	if r.cacheKey != "" {
		keep = 1 << 30
	}
	ring := newRing(keep, r.ringBytes)
	var tmp []hit
	for blocks := 0; ; blocks++ {
		if blocks > 0 && r.expired() {
			return nil, 0, fr.off, false, nil
		}
		buf, off, err := fr.next()
		if err != nil {
			return nil, 0, 0, false, err
		}
		if buf == nil || (hi >= 0 && off >= hi) {
			break
		}
		r.scanned += int64(len(buf))
		tmp = r.lines(buf, off, hi, fi, tmp[:0])
		for _, h := range tmp {
			h.line = bytes.Clone(h.line)
			_, h.esc, _ = splitLine(h.line)
			ring.push(h)
		}
		if hi >= 0 && off+int64(len(buf)) >= hi {
			break
		}
	}
	reached = fr.off
	if hi >= 0 {
		reached = min(reached, hi) // matches past hi were left out
	}
	items, dropped := ring.items()
	frontier = lo
	if dropped {
		frontier = items[0].off
	}
	return append([]hit(nil), items...), frontier, reached, true, nil
}

// prefetch runs, in parallel, the compressed-file passes the other desc
// streams will need next (a stream at a compressed file with no next line and
// no cached pass), so the merge doesn't decompress them one after another. It
// reports whether it ran any.
func (r *run) prefetch() bool {
	if r.cacheKey == "" || r.prefetched {
		return false
	}
	type job struct {
		fi  fileInfo
		pos int64
	}
	var jobs []job
	for _, s := range r.streams {
		if s.head() != nil || s.done || s.pending || s.hint > 0 || s.finished(true) {
			continue
		}
		if fi := s.files[s.fi]; fi.Compressed {
			jobs = append(jobs, job{fi: *fi, pos: s.pos})
		}
	}
	if len(jobs) < 2 {
		return false
	}
	r.prefetched = true // once per request: later misses are rare and run inline
	r.e.prefetches.Add(1)
	var mu sync.Mutex
	work := make(chan job)
	var wg sync.WaitGroup
	for w := 0; w < min(len(jobs), max(1, runtime.NumCPU()/2)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				c := &run{e: r.e, ctx: r.ctx, deadline: r.deadline, now: r.now, fromMs: r.fromMs, toMs: r.toMs, desc: true,
					m: r.m, ex: r.ex, fields: r.fields, sevs: r.sevs, facs: r.facs, need: r.need, cacheKey: r.cacheKey, ringBytes: r.ringBytes}
				fi := &j.fi
				o, err := r.e.open(r.ctx, fi)
				if err != nil {
					continue
				}
				lo, hi := regionStart(fi.cps, r.fromMs), j.pos
				if hi < 0 {
					hi = regionEnd(fi.cps, r.toMs)
				}
				key := passKey{fi.ID, r.cacheKey}
				if r.e.passes.get(key, lo, hi) == nil {
					if kept, frontier, reached, done, err := c.pass(o, fi, lo, hi); err == nil && done {
						r.e.passes.put(&passEntry{key: key, lo: lo, frontier: frontier, end: reached, eof: hi < 0, hits: kept})
					}
				}
				o.Close()
				mu.Lock()
				r.scanned += c.scanned
				r.files[fi.ID] = struct{}{}
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		work <- j
	}
	close(work)
	wg.Wait()
	return true
}

// ring keeps the newest n hits within a byte budget.
type ring struct {
	buf      []hit
	head     int
	bytes    int
	max      int
	maxBytes int
	dropped  bool
}

func newRing(n, maxBytes int) *ring { return &ring{max: n, maxBytes: maxBytes} }

func (g *ring) push(h hit) {
	g.buf = append(g.buf, h)
	g.bytes += len(h.line)
	for len(g.buf)-g.head > g.max || (g.bytes > g.maxBytes && len(g.buf)-g.head > 1) {
		g.bytes -= len(g.buf[g.head].line)
		g.buf[g.head] = hit{}
		g.head++
		g.dropped = true
	}
	if g.head > 4096 && g.head*2 > len(g.buf) {
		g.buf = append(g.buf[:0], g.buf[g.head:]...)
		g.head = 0
	}
}

func (g *ring) items() ([]hit, bool) { return g.buf[g.head:], g.dropped }
