package flowquery

import (
	"container/heap"
	"context"
	"errors"
	"math"
	"time"

	"github.com/gmccollu/woodshed/internal/flowseg"
)

// ---- search pages that continue (SPEC §13.6) ----
//
// A search page (the API's, the UI's Flows tab) is read by a stream like
// Stream's: the plan read once, each block decoded once, its matching rows
// held packed while an unread block could still come before them. A page
// that ends with a cursor keeps its stream (plan, merge and held rows,
// their bytes charged to the engine's pool) under that cursor's own
// string, so the next page carries on where it stopped, without planning
// again or reading again the blocks it has read. The cursor is the same
// bytes a stateless page gives (the key of its last record), so a page
// whose stream is gone (dropped for room, expired, the engine restarted, or
// taken by another request with the same cursor) is read from the cursor's
// values alone: a new stream started at the cursor, which skips what the
// stateless page skips and gives the same records.
//
// The store changes between pages, and a continued page gives what a
// stateless page would then. A saved stream that resumes checks what it
// was planned against (refresh): if the index has another segment count
// for the window, another set of segments holding raw sets to decode, or
// the open segments changed (one started, closed or was deleted), or a
// segment it still reads or holds rows of was deleted or written again
// under its name, it's dropped and the page read from the cursor. Blocks
// written since to the open segments it has loaded (a live store's every
// page) are read as it resumes. And a stream never gives a record that
// isn't after the last one it gave: one that comes up behind it (an index
// row its plan's bounds didn't cover) is left out, as a page from the
// cursor leaves it out. Saved streams hold no open files.

// MaxPageStates caps the saved page streams (least recently used dropped
// first, and after StateTTL unused); the pool drops them before top-N and
// summary states, since a page can always be read from its cursor.
const MaxPageStates = 8

// pageBudgetShare is the pool's share one page's stream may hold in rows
// before it trims (as Stream does with half the pool), and is saved within.
// Its plan's loaded batch is charged besides (as a saved top-N's plan is);
// the saved streams' charges together, rows and batches, stay under half
// the pool (the least recently used dropped past it).
const pageBudgetShare = 16

// errPageFull stops a page's drain at its limit.
var errPageFull = errors.New("flows: page full")

// pageState is a saved page stream.
type pageState struct {
	qk    string
	used  time.Time // for StateTTL
	seq   uint64    // e.saves when saved: the LRU order (the clock ties)
	s     *stream
	bytes int64 // its pool charge when saved: rows, bookkeeping and the plan's batch
}

// Search returns up to limit records, newest first by flow end (asc: oldest
// first), after cursor: the page a stateless reading of the cursor gives
// (searchStateless), from the stream the previous page saved under cursor
// when it's still there (see above).
func (e *Engine) Search(ctx context.Context, q Query, limit int, asc bool, cursor string, budget time.Duration) (SearchResult, error) {
	if e.statelessPages || limit <= 0 {
		return e.searchStateless(ctx, q, limit, asc, cursor, budget)
	}
	qk := q.key("search", asc)
	after, err := parseCursor(&q, qk, cursor)
	if err != nil {
		return SearchResult{}, err
	}
	e.sweepPages()
	var s *stream
	if cursor != "" {
		s = e.takePage(cursor, qk)
	}
	if s != nil {
		stale, err := s.refresh(ctx)
		if err != nil {
			s.discard()
			return SearchResult{}, err
		}
		if stale {
			s.discard()
			s = nil
			e.pageRebuilds.Add(1)
		}
	}
	if s != nil {
		e.pageResumes.Add(1)
	} else {
		if s, err = e.startPage(ctx, &q, asc, after); err != nil {
			return SearchResult{}, err
		}
		e.pageStarts.Add(1)
	}
	deadline := time.Now().Add(budget)
	res, exhausted, err := s.page(ctx, &q, qk, limit, after, deadline)
	switch {
	case errors.Is(err, errStreamFull):
		// Over its budget even trimmed (its bookkeeping alone): the rest of
		// the page from the last record given, stateless.
		e.pageFallbacks.Add(1)
		got := s.out
		s.discard()
		return e.finishStateless(ctx, q, qk, limit, asc, cursor, got, max(time.Until(deadline), 0))
	case err != nil:
		s.discard()
		return SearchResult{}, err
	}
	// Saved within its budget (trimmed if the last wave took it over), or
	// not at all.
	if res.Cursor != "" && !exhausted && (s.used.Load() <= s.budget || s.trim(s.h) == nil) {
		e.savePage(res.Cursor, qk, s)
	} else {
		s.discard()
	}
	return res, nil
}

// finishStateless completes a page that has got of its limit hits with a
// stateless page after the last of them (after cursor if none).
func (e *Engine) finishStateless(ctx context.Context, q Query, qk string, limit int, asc bool, cursor string, got []Hit,
	budget time.Duration) (SearchResult, error) {
	if len(got) == 0 {
		return e.searchStateless(ctx, q, limit, asc, cursor, budget)
	}
	from := encodeCursor(keyOfHit(&got[len(got)-1]), qk, &q)
	res, err := e.searchStateless(ctx, q, limit-len(got), asc, from, budget)
	if err != nil {
		return SearchResult{}, err
	}
	if len(res.Hits) == 0 && res.Cursor != "" {
		res.Cursor = from // partial: the last record given, as a stateless page's
	}
	res.Hits = append(got, res.Hits...)
	return res, nil
}

// startPage is a page stream over q from after (nil: the window's start).
func (e *Engine) startPage(ctx context.Context, q *Query, asc bool, after *hitKey) (*stream, error) {
	p, err := e.planOrdered(ctx, q, asc)
	if err != nil {
		return nil, err
	}
	p.skipBefore(after)
	s := &stream{e: e, asc: asc, p: p, h: &heldHeap{asc: asc}, more: true, after: after, budget: e.pool.cap / pageBudgetShare}
	s.f, s.from, s.to = q.filter(), p.from, p.to
	return s, nil
}

// setSkip makes the blocks read next keep only rows after both the cursor
// the stream started at and the last record it gave.
func (s *stream) setSkip() {
	s.skipTo = s.after
	if s.emitted && (s.skipTo == nil || s.skipTo.before(s.last, s.asc)) {
		k := s.last
		s.skipTo = &k
	}
}

// page fills a page of limit hits from the stream, within the deadline
// (one wave at least, as searchStateless reads), and gives the page as
// searchStateless would: its cursor, whether partial. exhausted: nothing is
// left to give.
func (s *stream) page(ctx context.Context, q *Query, qk string, limit int, start *hitKey, deadline time.Time) (SearchResult, bool, error) {
	e := s.e
	if s.rd == nil {
		s.rd = newReaders(s.p)
	}
	s.out, s.limit = nil, limit // grown as hits come, as a stateless page's (a page's cap of Hits would stay pinned)
	s.fn = func(h *Hit) error {
		s.out = append(s.out, *h)
		if len(s.out) >= s.limit {
			return errPageFull
		}
		return nil
	}
	// As searchStateless: past the deadline a page still reads until the
	// bound of what's unread passes the cursor it started from, so a
	// partial page's cursor (that bound, when it has no hits) moves on.
	progressed := func() bool {
		b, more := s.p.bound(ctx)
		switch {
		case !more:
			return true
		case start == nil && s.asc:
			return b > math.MinInt64
		case start == nil:
			return b < math.MaxInt64
		case s.asc:
			return b > start.End+1
		}
		return b < start.End-1
	}
	for first := true; ; first = false {
		err := s.drain(ctx, s.h, s.bound, s.more)
		if errors.Is(err, errPageFull) {
			break
		}
		if err != nil {
			return SearchResult{}, false, err
		}
		if !s.more && s.h.Len() == 0 {
			break
		}
		if !first && !time.Now().Before(deadline) && progressed() {
			break
		}
		if s.used.Load() > s.budget {
			if err := s.trim(s.h); err != nil {
				return SearchResult{}, false, err
			}
		}
		e.gcNudge()
		s.setSkip()
		w, ok := s.nextWave(ctx, s.p, s.rd, e.o.Workers)
		if w.err != nil {
			return SearchResult{}, false, w.err
		}
		for _, x := range w.held {
			if len(x.rows) == 0 {
				s.put(x)
				continue
			}
			heap.Push(s.h, x)
		}
		s.bound, s.more = w.bound, w.more && ok
		s.blocksDone += int64(w.blocks)
		s.recsDone += w.rows
	}
	if err := ctx.Err(); err != nil {
		return SearchResult{}, false, err
	}
	exhausted := !s.more && s.h.Len() == 0
	res := SearchResult{Hits: s.out, Progress: s.p.progress(ctx, s.blocksDone, s.recsDone)}
	s.out, s.fn = nil, nil
	switch {
	case exhausted && len(res.Hits) < limit:
		// The window is exhausted.
	case len(res.Hits) == limit:
		res.Cursor = encodeCursor(keyOfHit(&res.Hits[len(res.Hits)-1]), qk, q)
	default:
		// Out of budget: what's certain (every row past the bound has been
		// given), and a cursor past every block read.
		res.Partial = true
		bound, _ := s.p.bound(ctx)
		var k hitKey
		switch {
		case len(res.Hits) > 0:
			k = keyOfHit(&res.Hits[len(res.Hits)-1])
		case s.asc:
			k = hitKey{End: max(bound, math.MinInt64+1) - 1, Dev: "\U0010ffff"}
		default:
			k = hitKey{End: min(bound, math.MaxInt64-1) + 1, Dev: "\U0010ffff"}
		}
		res.Cursor = encodeCursor(k, qk, q)
	}
	if err := s.p.err; err != nil { // an index read failed as the page went on: its bounds, and its end, aren't true
		return SearchResult{}, false, err
	}
	ownExtras(res.Hits)
	return res, exhausted, nil
}

// refresh checks, as a saved page stream resumes, that the store is still
// what it was planned against, and reads the blocks written since to the
// open segments it has loaded (see the top of this file). stale: it can't
// give what a stateless page would now; read the page from the cursor.
func (s *stream) refresh(ctx context.Context) (stale bool, err error) {
	p, e := s.p, s.e
	from, to := time.UnixMilli(p.from).UTC(), time.UnixMilli(p.to).UTC()
	n, _, err := e.o.Index.FlowSegmentsCount(ctx, p.devs, from, to)
	if err != nil {
		return false, err
	}
	if n != p.segCount {
		return true, nil
	}
	nt, err := e.o.Index.FlowSegmentsNoTemplate(ctx, p.devs, from, to)
	if err != nil {
		return false, err
	}
	if len(nt) != len(p.ntSet) {
		return true, nil
	}
	for i := range nt {
		if !p.ntSet[nt[i].Path] {
			return true, nil
		}
	}
	cur := p.openNow()
	if len(cur) != len(p.openSet) {
		return true, nil
	}
	for rel := range cur {
		if !p.openSet[rel] {
			return true, nil
		}
	}
	// The files it still reads or holds rows of are the ones it read.
	ids := map[string]flowseg.Identity{}
	add := func(path string, id flowseg.Identity) bool {
		if old, ok := ids[path]; ok && old != id {
			return false
		}
		ids[path] = id
		return true
	}
	for _, x := range s.h.h {
		if x.src != nil && !add(x.src.Path, x.src.id) {
			return true, nil
		}
	}
	for _, b := range p.blocks[p.done:] {
		if sg := &p.segs[b.seg]; !add(sg.Path, sg.id) {
			return true, nil
		}
	}
	for _, ol := range p.openLoaded {
		if !add(ol.ref.Path, ol.ref.id) {
			return true, nil
		}
	}
	for path, id := range ids {
		if got, err := flowseg.ReadIdentity(path); err != nil || got != id {
			return true, nil
		}
	}
	// The open segments it has loaded: what's been written to them since.
	type grown struct {
		ol   *openLoad
		foot *flowseg.Footer
	}
	var gs []grown
	for rel, ol := range p.openLoaded {
		os := cur[rel]
		f := os.Footer
		if f == nil && os.Snap != nil {
			f = os.Snap()
		}
		if f == nil || len(f.RawChunks) != ol.raw || len(f.Blocks) < ol.blocks {
			return true, nil // closed since, or its raw sets changed (they're read as one)
		}
		if len(f.Blocks) > ol.blocks {
			gs = append(gs, grown{ol, f})
		}
	}
	s.setSkip()
	for _, g := range gs {
		if err := s.catchUp(ctx, g.ol, g.foot); errors.Is(err, errStreamFull) {
			return true, nil // what was written since doesn't fit even trimmed: read from the cursor
		} else if err != nil {
			return false, err
		}
	}
	return false, nil
}

// catchUp reads the blocks written to an open segment the stream has loaded
// since it planned them (foot is its snapshot now), keeping their rows after
// skipTo. The stream's blocks of the segment share the newest snapshot
// (what they had is a prefix of it), charged while it's kept. It reads them
// a wave (streamWave) at a time and trims after any wave that takes the
// stream over its budget, as a wave of the plan's does, so a busy segment
// after a long pause holds at most the budget and a wave; errStreamFull if
// trimming can't get it back under (the caller reads from the cursor).
func (s *stream) catchUp(ctx context.Context, ol *openLoad, foot *flowseg.Footer) error {
	p := s.p
	ref := ol.ref
	ref.snap = foot
	cp := &plan{e: s.e, asc: p.asc, from: p.from, to: p.to, segs: []segRef{ref}}
	var blocks []planned
	for i := ol.blocks; i < len(foot.Blocks); i++ {
		b := &foot.Blocks[i]
		if b.Rows == 0 || !b.Overlaps(p.from, p.to-1) {
			continue
		}
		blocks = append(blocks, planned{block: i, rows: b.Rows, minStart: b.MinStart, maxStart: b.MaxStart, minEnd: b.MinEnd, maxEnd: b.MaxEnd})
	}
	ol.blocks = len(foot.Blocks)
	shared := &segRef{DeviceID: ref.DeviceID, Rel: ref.Rel, Path: ref.Path, snap: foot, id: ref.id, open: true}
	cost := int64(len(foot.Blocks))*entryCost + int64(len(foot.RawChunks))*rawCost
	s.release(ol.cost)
	s.reserve(cost)
	ol.ref.snap, ol.cost = foot, cost
	for _, x := range s.h.h { // the blocks it holds of the segment: the newest snapshot (a superset)
		if x.src != nil && x.src.snap != nil && x.src.Path == ref.Path {
			x.src = shared
		}
	}
	if len(blocks) == 0 {
		return nil
	}
	rd := &readers{p: cp}
	rd.track(blocks)
	defer rd.close()
	for n := s.e.streamWave(); len(blocks) > 0; {
		wv := blocks[:min(n, len(blocks))]
		blocks = blocks[len(wv):]
		held, err := s.decode(ctx, cp, rd, wv, s.f)
		if err != nil {
			for _, x := range held {
				s.put(x)
			}
			return err
		}
		for _, x := range held {
			if len(x.rows) == 0 {
				s.put(x)
				continue
			}
			if x.src != nil && x.src.snap != nil {
				x.src = shared
			}
			heap.Push(s.h, x)
		}
		s.blocksDone += int64(len(wv))
		s.e.pageCatchUps.Add(int64(len(wv)))
		if s.used.Load() > s.budget {
			if err := s.trim(s.h); err != nil {
				return err
			}
		}
	}
	return nil
}

// openNow is the open segments of the plan's devices now, by rel (as
// newPlan lists them).
func (p *plan) openNow() map[string]OpenSegment {
	out := map[string]OpenSegment{}
	if p.e.o.Open == nil {
		return out
	}
	want := map[string]bool{}
	for _, d := range p.devs {
		want[d] = true
	}
	for _, os := range p.e.o.Open(p.devs) {
		if p.devs == nil || want[os.DeviceID] {
			out[os.Rel] = os
		}
	}
	return out
}

// park readies a page stream to be saved: it gives back its spare packed
// buffers and closes its files (a reader is opened again from the footer
// it read, so only the blocks are read again, and its file is checked to
// be the one it read).
func (s *stream) park() {
	s.mu.Lock()
	for _, f := range s.free {
		s.release(f.cost)
	}
	s.free = nil
	s.mu.Unlock()
	for _, a := range s.again {
		if a.r != nil {
			a.r.Close()
			a.r = nil
		}
	}
	p := s.p
	if s.rd != nil {
		s.rd.mu.Lock()
		for si, r := range s.rd.rds {
			if p.segs[si].snap == nil {
				p.segs[si].snap = r.Footer() // the batch's charge counts its entries
			}
			p.segs[si].id = r.Identity()
		}
		s.rd.mu.Unlock()
		s.rd.close()
		s.rd = nil
	}
	// Segments it reads from a snapshot without having opened their file
	// yet (open ones): which file it is now (unreadable: none, so stale on
	// resume).
	for _, b := range p.blocks[p.done:] {
		if sg := &p.segs[b.seg]; sg.id == (flowseg.Identity{}) {
			sg.id, _ = flowseg.ReadIdentity(sg.Path)
		}
	}
	held := map[string]bool{}
	for _, x := range s.h.h {
		if x.src != nil {
			held[x.src.Path] = true
		}
	}
	for _, ol := range p.openLoaded {
		if ol.ref.id == (flowseg.Identity{}) {
			ol.ref.id, _ = flowseg.ReadIdentity(ol.ref.Path)
		}
		if ol.cost != 0 && !held[ol.ref.Path] { // no rows of it held: its snapshot isn't needed
			s.release(ol.cost)
			ol.ref.snap, ol.cost = nil, 0
		}
	}
}

// discard gives back everything a page stream holds.
func (s *stream) discard() {
	if s.h != nil {
		for _, x := range s.h.h {
			s.put(x)
		}
		s.h.h = nil
	}
	s.close()
	if s.rd != nil {
		s.rd.close()
		s.rd = nil
	}
	if s.p != nil {
		for _, ol := range s.p.openLoaded {
			s.release(ol.cost)
			ol.ref.snap, ol.cost = nil, 0
		}
		s.p.release()
		s.p = nil
	}
	s.out, s.fn = nil, nil
}

// pageBytes is a stream's pool charge: its own and its plan's batch.
func (s *stream) pageBytes() int64 { return s.used.Load() + s.p.charged }

// savePage keeps s under cursor, dropping expired ones and, past
// MaxPageStates or half the pool between them, the least recently used.
func (e *Engine) savePage(cursor, qk string, s *stream) {
	s.park()
	var gone []*pageState
	defer func() {
		for _, g := range gone {
			g.s.discard()
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.o.Clock()
	gone = e.expiredPagesLocked(now)
	if old := e.pages[cursor]; old != nil { // two requests continued from one cursor
		delete(e.pages, cursor)
		e.savedPageBytes.Add(-old.bytes)
		gone = append(gone, old)
	}
	e.saves++
	ps := &pageState{qk: qk, used: now, seq: e.saves, s: s, bytes: s.pageBytes()}
	e.pages[cursor] = ps
	e.savedPageBytes.Add(ps.bytes)
	for len(e.pages) > MaxPageStates || (len(e.pages) > 0 && e.savedPageBytes.Load() > e.pool.cap/2) {
		gone = append(gone, e.oldestPageLocked())
	}
	if e.pageTimer == nil && len(e.pages) > 0 {
		e.pageTimer = time.AfterFunc(StateTTL, e.pageTimerFired)
	}
}

// takePage removes and returns the stream saved under cursor for query
// qk, or nil.
func (e *Engine) takePage(cursor, qk string) *stream {
	e.mu.Lock()
	ps := e.pages[cursor]
	if ps != nil {
		delete(e.pages, cursor)
		e.savedPageBytes.Add(-ps.bytes)
	}
	e.mu.Unlock()
	switch {
	case ps == nil:
		return nil
	case ps.qk != qk || e.o.Clock().Sub(ps.used) > StateTTL:
		ps.s.discard()
		return nil
	}
	return ps.s
}

// expiredPagesLocked removes and returns the saved page streams unused for
// StateTTL. e.mu is held.
func (e *Engine) expiredPagesLocked(now time.Time) []*pageState {
	var gone []*pageState
	for c, ps := range e.pages {
		if now.Sub(ps.used) > StateTTL {
			delete(e.pages, c)
			e.savedPageBytes.Add(-ps.bytes)
			gone = append(gone, ps)
		}
	}
	return gone
}

// sweepPages drops the saved page streams unused for StateTTL (abandoned
// listings'): on every search page, when the pool is full, and from a
// timer while any are saved.
func (e *Engine) sweepPages() {
	e.mu.Lock()
	gone := e.expiredPagesLocked(e.o.Clock())
	e.mu.Unlock()
	for _, g := range gone {
		g.s.discard()
	}
}

// pageTimerFired sweeps, and runs again while page streams are saved.
func (e *Engine) pageTimerFired() {
	e.sweepPages()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pageTimer = nil
	if len(e.pages) > 0 {
		e.pageTimer = time.AfterFunc(StateTTL/2, e.pageTimerFired)
	}
}

// evictPage drops the saved page streams that expired, or else the least
// recently used one, and reports whether there was one.
func (e *Engine) evictPage() bool {
	e.mu.Lock()
	gone := e.expiredPagesLocked(e.o.Clock())
	if len(gone) == 0 {
		if old := e.oldestPageLocked(); old != nil {
			gone = append(gone, old)
		}
	}
	e.mu.Unlock()
	for _, g := range gone {
		g.s.discard()
	}
	return len(gone) > 0
}

// oldestPageLocked removes and returns the least recently used saved page
// stream (nil: none). e.mu is held.
func (e *Engine) oldestPageLocked() *pageState {
	var oc string
	var old *pageState
	for c, ps := range e.pages {
		if old == nil || ps.seq < old.seq {
			oc, old = c, ps
		}
	}
	if old != nil {
		delete(e.pages, oc)
		e.savedPageBytes.Add(-old.bytes)
	}
	return old
}

// savedPages is how many page streams are saved (tests).
func (e *Engine) savedPages() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pages)
}
