package flowquery

import (
	"container/heap"
	"context"
	"errors"
	"math"
	"time"
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
// stateless page skips and gives the same records. Saved streams hold no
// open files (a file retention deletes is then just gone, as for any page).

// MaxPageStates caps the saved page streams (least recently used dropped
// first, and after StateTTL unused); the pool drops them before top-N and
// summary states, since a page can always be read from its cursor.
const MaxPageStates = 8

// pageBudgetShare is the pool's share one page's stream may hold before it
// trims (as Stream does with half the pool), and is saved within: eight
// saved streams take half the pool at most, besides their plans' batches.
const pageBudgetShare = 16

// errPageFull stops a page's drain at its limit.
var errPageFull = errors.New("flows: page full")

// pageState is a saved page stream.
type pageState struct {
	qk   string
	used time.Time
	s    *stream
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
	var s *stream
	if cursor != "" {
		s = e.takePage(cursor, qk)
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
	ownExtras(res.Hits)
	return res, exhausted, nil
}

// park readies a page stream to be saved: it gives back its spare packed
// buffers and closes its files (a reader is opened again from the footer
// it read, so only the blocks are read again).
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
	if s.rd != nil {
		s.rd.mu.Lock()
		for si, r := range s.rd.rds {
			if s.p.segs[si].snap == nil {
				s.p.segs[si].snap = r.Footer() // the batch's charge counts its entries
			}
		}
		s.rd.mu.Unlock()
		s.rd.close()
		s.rd = nil
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
		s.p.release()
		s.p = nil
	}
	s.out, s.fn = nil, nil
}

// savePage keeps s under cursor, dropping expired ones and, past
// MaxPageStates, the least recently used.
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
	for c, ps := range e.pages {
		if now.Sub(ps.used) > StateTTL {
			delete(e.pages, c)
			gone = append(gone, ps)
		}
	}
	if old := e.pages[cursor]; old != nil { // two requests continued from one cursor
		gone = append(gone, old)
	}
	e.pages[cursor] = &pageState{qk: qk, used: now, s: s}
	for len(e.pages) > MaxPageStates {
		gone = append(gone, e.oldestPageLocked())
	}
}

// takePage removes and returns the stream saved under cursor for query
// qk, or nil.
func (e *Engine) takePage(cursor, qk string) *stream {
	e.mu.Lock()
	ps := e.pages[cursor]
	if ps != nil {
		delete(e.pages, cursor)
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

// evictPage drops the least recently used saved page stream and reports
// whether there was one.
func (e *Engine) evictPage() bool {
	e.mu.Lock()
	old := e.oldestPageLocked()
	e.mu.Unlock()
	if old == nil {
		return false
	}
	old.s.discard()
	return true
}

// oldestPageLocked removes and returns the least recently used saved page
// stream (nil: none). e.mu is held.
func (e *Engine) oldestPageLocked() *pageState {
	var oc string
	var old *pageState
	for c, ps := range e.pages {
		if old == nil || ps.used.Before(old.used) {
			oc, old = c, ps
		}
	}
	if old != nil {
		delete(e.pages, oc)
	}
	return old
}

// savedPages is how many page streams are saved (tests).
func (e *Engine) savedPages() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.pages)
}
