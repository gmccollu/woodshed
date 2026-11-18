package flowquery

import (
	"container/heap"
	"context"
	"errors"
	"math"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
)

// ---- every record, in Search's order (woodshed search --type flow) ----

// Stream calls fn with every record of the window that passes the filter, in
// Search's order (newest first by flow end, or with asc oldest first; then
// by device, file, block and row): exactly what Search's pages give one after
// another, without a budget. The hit (and its record) is fn's only for the
// call. An error from fn stops the stream and is returned.
//
// Search pages: each page plans the window again and decodes every block
// that overlaps the page's end-time span, so a listing of the whole window
// decodes each block about as many times as pages fit in its span (with a
// few seconds of end-time spread per block and 5,000 hits a page, 30 to 50
// times). Stream decodes each block once: it keeps each block's matching
// rows, sorted and packed (flowseg.Packed, about a sixth of a decoded
// block), while they aren't certain yet (an unread block could still come
// before them), merges the blocks it keeps and gives a row once it's beyond
// the bound of everything unread. A reader decodes the next wave (half the
// workers' blocks) while the caller writes the current one.
//
// What it keeps is bounded: the rows it holds are charged to the engine's
// pool (decision 51's shared budget), and it decodes in the workers' own
// buffers. Past half the pool (a block holding a few rows that end far from
// the rest, so it can't be given back until the bound reaches them, while
// every later block comes in) it trims: it keeps each block's rows up to an
// end-time horizon chosen to fit a quarter of the pool, drops the rest with
// the key to resume at, and reads such a block again when the merge reaches
// that key, keeping only its rows from there on. So a block is read about
// twice at most when a few of its rows end far from the others, not once per
// page as a fall back to Search's pages read it. Only when the blocks waiting
// to be read again can't fit (their bookkeeping alone) does it carry on from
// the last record it gave with Search's pages.
func (e *Engine) Stream(ctx context.Context, q Query, asc bool, fn func(h *Hit) error) error {
	s := &stream{e: e, asc: asc, fn: fn}
	err := s.run(ctx, q)
	if errors.Is(err, errStreamFull) {
		e.streamFallbacks.Add(1)
		return s.pages(ctx, q)
	}
	return err
}

// streamPage is the page size Stream falls back to (the CLI's).
const streamPage = 5000

// errStreamFull is the stream still over its budget after trimming.
var errStreamFull = errors.New("flows: stream: pool full")

// heldBlock is one block's matching rows, sorted in result order and packed.
type heldBlock struct {
	dev, rel string
	block    int
	pk       *flowseg.Packed // the rows, in order (nil for raw sets)
	pkCost   int64           // pk's pool bytes
	raw      []flow.Record   // raw sets: the records, raw[i] for rows[i]
	rows     []int           // row numbers (raw sets: -1-i), in result order
	ends     []int64         // their effective ends
	next     int
	cost     int64 // pool bytes for rows, ends and raw

	// A trimmed block's rows past rows[len-1] were dropped: when the merge
	// reaches resume (its first dropped row's end and row), the block is read
	// again from src. Not for raw sets.
	src     *segRef // the segment, its footer as snap (read again without reading the footer)
	resume  bool
	rEnd    int64
	rRow    int
	resCost int64 // pool bytes for the bookkeeping while it waits
}

func (h *heldBlock) key() hitKey {
	if h.next == len(h.rows) {
		return hitKey{End: h.rEnd, Dev: h.dev, Rel: h.rel, Block: h.block, Row: h.rRow}
	}
	return hitKey{End: h.ends[h.next], Dev: h.dev, Rel: h.rel, Block: h.block, Row: h.rows[h.next]}
}

// heldHeap orders held blocks by their next row's key.
type heldHeap struct {
	h   []*heldBlock
	asc bool
}

func (m *heldHeap) Len() int           { return len(m.h) }
func (m *heldHeap) Less(i, j int) bool { return m.h[i].key().before(m.h[j].key(), m.asc) }
func (m *heldHeap) Swap(i, j int)      { m.h[i], m.h[j] = m.h[j], m.h[i] }
func (m *heldHeap) Push(x any)         { m.h = append(m.h, x.(*heldBlock)) }
func (m *heldHeap) Pop() any {
	n := len(m.h) - 1
	x := m.h[n]
	m.h[n] = nil
	m.h = m.h[:n]
	return x
}

// wave is a batch of read blocks and the bound of what's unread after it.
type wave struct {
	held  []*heldBlock
	bound int64
	more  bool
	err   error
}

type stream struct {
	e   *Engine
	asc bool
	fn  func(h *Hit) error

	last    hitKey // the last record given
	emitted bool

	mu   sync.Mutex
	free []freePacked // packed buffers to reuse, still charged
	held atomic.Int64 // blocks read and not yet given back

	used   atomic.Int64 // the stream's pool bytes
	budget int64        // past it, the stream trims (half the pool)

	// The reader's window and filter (set before its first wave), for
	// blocks read again.
	f        *Filter
	from, to int64

	// Segments with trimmed blocks waiting (the merge's own): their readers,
	// opened from the footer on first use, and how many blocks wait.
	again map[*flowseg.Footer]*againSeg
}

type againSeg struct {
	r     *flowseg.Reader
	waits int
	cost  int64 // the footer's pool bytes
}

type freePacked struct {
	pk   *flowseg.Packed
	cost int64
}

// streamWave is how many blocks the reader decodes at a time: what it keeps
// is about the blocks overlapping in flow time plus two waves, and the
// caller writing the rows is slower than half the workers decoding them.
func (e *Engine) streamWave() int { return max(e.o.Workers/2, 1) }

// reserve charges n bytes to the pool, past its cap if it must (the
// consumer trims back under the budget after each wave).
func (s *stream) reserve(n int64) bool {
	if n <= 0 {
		return true
	}
	if !s.e.pool.reserve(n) {
		s.e.pool.used.Add(n)
	}
	s.used.Add(n)
	return true
}

// release returns n bytes reserve took.
func (s *stream) release(n int64) {
	if n != 0 {
		s.e.pool.release(n)
		s.used.Add(-n)
	}
}

// getPacked is a packed buffer and its charge.
func (s *stream) getPacked() (*flowseg.Packed, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n := len(s.free); n > 0 {
		f := s.free[n-1]
		s.free = s.free[:n-1]
		return f.pk, f.cost
	}
	return &flowseg.Packed{}, 0
}

// put gives a held block back: its rows' pool bytes, and its packed buffer
// for reuse (a wave's worth kept, charged; the rest dropped).
func (s *stream) put(h *heldBlock) {
	s.release(h.cost)
	h.cost, h.raw = 0, nil
	s.held.Add(-1)
	s.unwait(h)
	s.putPacked(h)
}

// putPacked gives back h's packed rows (h stays, without them).
func (s *stream) putPacked(h *heldBlock) {
	if h.pk == nil {
		return
	}
	s.mu.Lock()
	if len(s.free) < s.e.streamWave() {
		s.free = append(s.free, freePacked{h.pk, h.pkCost})
	} else {
		s.release(h.pkCost)
	}
	s.mu.Unlock()
	h.pk, h.pkCost = nil, 0
}

// wait records that trimmed block h waits to be read again.
func (s *stream) wait(h *heldBlock) {
	if h.resume {
		return
	}
	h.resume = true
	h.resCost = heldWaitCost
	s.reserve(h.resCost)
	if s.again == nil {
		s.again = map[*flowseg.Footer]*againSeg{}
	}
	a := s.again[h.src.snap]
	if a == nil {
		f := h.src.snap
		a = &againSeg{cost: int64(len(f.Blocks))*entryCost + int64(len(f.RawChunks))*rawCost}
		s.reserve(a.cost)
		s.again[h.src.snap] = a
	}
	a.waits++
}

// unwait undoes wait (h read again, or given back).
func (s *stream) unwait(h *heldBlock) {
	if !h.resume {
		return
	}
	h.resume = false
	s.release(h.resCost)
	h.resCost = 0
	if a := s.again[h.src.snap]; a != nil {
		if a.waits--; a.waits <= 0 {
			if a.r != nil {
				a.r.Close()
			}
			s.release(a.cost)
			delete(s.again, h.src.snap)
		}
	}
}

// heldWaitCost is a waiting block's bookkeeping, about.
const heldWaitCost = 256

// close returns the free buffers' charge and closes the readers of blocks
// that waited.
func (s *stream) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.free {
		s.release(f.cost)
	}
	s.free = nil
	for k, a := range s.again {
		if a.r != nil {
			a.r.Close()
		}
		s.release(a.cost)
		delete(s.again, k)
	}
}

// run streams the window; errStreamFull when the pool can't hold what it must.
func (s *stream) run(ctx context.Context, q Query) error {
	defer s.close()
	rctx, cancel := context.WithCancel(ctx)
	defer cancel()
	waves := make(chan wave) // the reader decodes one wave ahead
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(waves)
		s.read(rctx, q, waves)
	}()
	h := &heldHeap{asc: s.asc}
	s.budget = s.e.pool.cap / 2
	finish := func(err error) error {
		cancel()
		for w := range waves { // the reader stops at its next wave
			for _, x := range w.held {
				s.put(x)
			}
		}
		wg.Wait()
		for _, x := range h.h {
			s.put(x)
		}
		h.h = nil
		return err
	}
	var hit Hit
	for w := range waves {
		if w.err != nil {
			return finish(w.err)
		}
		for _, x := range w.held {
			if len(x.rows) == 0 {
				s.put(x)
				continue
			}
			heap.Push(h, x)
		}
		for h.Len() > 0 {
			top := h.h[0]
			k := top.key()
			end := k.End
			if w.more && ((!s.asc && end <= w.bound) || (s.asc && end >= w.bound)) {
				break // something unread may still come first
			}
			if top.next == len(top.rows) { // a trimmed block's turn: read it again
				if err := s.readAgain(ctx, top); err != nil {
					return finish(err)
				}
				if len(top.rows) == 0 {
					heap.Pop(h)
					s.put(top)
				} else {
					heap.Fix(h, 0)
				}
				continue
			}
			row := top.rows[top.next]
			hit.DeviceID, hit.Rel, hit.Block, hit.Row = top.dev, top.rel, top.block, row
			if top.pk != nil {
				top.pk.Next(&hit.Record)
			} else {
				hit.Record = top.raw[top.next]
			}
			if err := s.fn(&hit); err != nil {
				return finish(err)
			}
			s.last, s.emitted = hitKey{End: end, Dev: top.dev, Rel: top.rel, Block: top.block, Row: row}, true
			switch top.next++; {
			case top.next < len(top.rows):
				heap.Fix(h, 0)
			case top.resume:
				s.putPacked(top) // its kept rows are given; it waits at its resume key
				s.release(top.cost)
				top.cost, top.rows, top.ends, top.next = 0, nil, nil, 0
				heap.Fix(h, 0)
			default:
				heap.Pop(h)
				s.put(top)
			}
		}
		if !w.more && h.Len() == 0 {
			break
		}
		if s.used.Load() > s.budget {
			if err := s.trim(h); err != nil {
				return finish(err)
			}
		}
		s.e.gcNudge() // a big pool share: keep the garbage from growing the heap past it
	}
	return finish(ctx.Err())
}

// read plans the window and sends its blocks, read, a wave at a time.
func (s *stream) read(ctx context.Context, q Query, waves chan<- wave) {
	e := s.e
	send := func(w wave) bool {
		select {
		case waves <- w:
			return true
		case <-ctx.Done():
			for _, x := range w.held {
				s.put(x)
			}
			return false
		}
	}
	p, err := e.planOrdered(ctx, &q, s.asc)
	if err != nil {
		send(wave{err: err})
		return
	}
	defer p.release()
	rd := newReaders(p)
	defer rd.close()
	f := q.filter()
	s.f, s.from, s.to = f, p.from, p.to
	for {
		blocks := p.take(ctx, rd, e.streamWave())
		if len(blocks) == 0 {
			break
		}
		held, err := s.decode(ctx, p, rd, blocks, f)
		if err != nil {
			for _, x := range held {
				s.put(x)
			}
			send(wave{err: err})
			return
		}
		bound, more := p.bound(ctx)
		if !send(wave{held: held, bound: bound, more: more}) {
			return
		}
	}
	switch {
	case p.err != nil:
		send(wave{err: p.err})
	case ctx.Err() != nil:
		send(wave{err: ctx.Err()})
	default:
		send(wave{})
	}
}

// decode reads a wave's blocks with the engine's workers (their slots'
// buffers, as Search's scan).
func (s *stream) decode(ctx context.Context, p *plan, rd *readers, blocks []planned, f *Filter) ([]*heldBlock, error) {
	e := s.e
	var got []*slot
	select {
	case sl := <-e.slots:
		got = append(got, sl)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
more:
	for len(got) < min(e.o.Workers, len(blocks)) {
		select {
		case sl := <-e.slots:
			got = append(got, sl)
		default:
			break more
		}
	}
	defer func() {
		for _, sl := range got {
			e.slots <- sl
		}
	}()
	held := make([]*heldBlock, len(blocks))
	var next atomic.Int64
	var full atomic.Bool
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	for w := range got {
		wg.Add(1)
		go func(sl *slot) {
			defer wg.Done()
			var re []rowEnd
			for {
				i := int(next.Add(1) - 1)
				if i >= len(blocks) || ctx.Err() != nil || full.Load() {
					return
				}
				b := &blocks[i]
				var x *heldBlock
				var err error
				x, re, err = s.decodeOne(p, rd, b, f, sl, re)
				rd.done(b.seg)
				switch {
				case errors.Is(err, errStreamFull):
					full.Store(true)
				case err != nil:
					errMu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMu.Unlock()
				}
				held[i] = x
			}
		}(got[w])
	}
	wg.Wait()
	if firstErr != nil {
		e.o.Logger.Warn("flows: a block couldn't be read; skipped", "err", firstErr)
	}
	out := held[:0]
	for _, x := range held {
		if x != nil {
			out = append(out, x)
		}
	}
	switch {
	case full.Load():
		return out, errStreamFull
	case ctx.Err() != nil:
		return out, ctx.Err()
	}
	return out, nil
}

// rowEnd is a matching row and its effective end.
type rowEnd struct {
	end int64
	row int
}

// decodeOne reads one planned block: its matching rows, sorted and packed.
// nil (with the read error) when it couldn't be read; re is scratch.
func (s *stream) decodeOne(p *plan, rd *readers, b *planned, f *Filter, sl *slot, re []rowEnd) (*heldBlock, []rowEnd, error) {
	seg := &p.segs[b.seg]
	x := &heldBlock{dev: seg.DeviceID, rel: seg.Rel, block: b.block}
	s.held.Add(1)
	fail := func(err error) (*heldBlock, []rowEnd, error) {
		s.put(x)
		return nil, re, err
	}
	r, err := rd.get(b.seg)
	if err != nil {
		return fail(err)
	}
	if b.raw {
		type rawRow struct {
			rowEnd
			rec flow.Record
		}
		var rows []rawRow
		err = rawRecords(r, s.e.ruleIEs(), func(i int, rec *flow.Record) {
			st, en := flowseg.EffectiveTimes(rec)
			if en >= p.from && st < p.to && f.Match(rec) {
				rows = append(rows, rawRow{rowEnd{en, -1 - i}, *rec})
			}
		})
		if err != nil {
			return fail(err)
		}
		slices.SortFunc(rows, func(a, b rawRow) int { return s.cmpRow(a.rowEnd, b.rowEnd) })
		x.rows, x.ends, x.raw = make([]int, len(rows)), make([]int64, len(rows)), make([]flow.Record, len(rows))
		for i := range rows {
			x.rows[i], x.ends[i], x.raw[i] = rows[i].row, rows[i].end, rows[i].rec
		}
		n := int64(len(rows)) * (16 + recordSize)
		if !s.reserve(n) {
			return fail(errStreamFull)
		}
		x.cost = n
		return x, re, nil
	}
	if !f.Empty() { // as Search's scan: a block the index rules out isn't read
		info, err := r.Block(b.block)
		if err != nil {
			return fail(err)
		}
		if !f.BlockMay(info) {
			return x, re, nil
		}
	}
	blk := &sl.blk
	s.e.streamDecodes.Add(1)
	if err := r.Decode(b.block, flowseg.ColAll, blk); err != nil {
		return fail(err)
	}
	x.src = &segRef{DeviceID: seg.DeviceID, Rel: seg.Rel, Path: seg.Path, snap: r.Footer()}
	re = s.selectRows(blk, &sl.rec, f, p.from, p.to, re)
	s.packRows(x, blk, re)
	return x, re, nil
}

// selectRows is a decoded block's rows in the window that pass f, sorted in
// the result order (re is scratch).
func (s *stream) selectRows(blk *flowseg.Block, rec *flow.Record, f *Filter, from, to int64, re []rowEnd) []rowEnd {
	re = re[:0]
	if f.Empty() { // the times alone decide
		for row := 0; row < blk.Rows; row++ {
			if st, en := blk.EffectiveTimes(row); en >= from && st < to {
				re = append(re, rowEnd{en, row})
			}
		}
	} else {
		for row := 0; row < blk.Rows; row++ {
			blk.Record(row, rec)
			if st, en := flowseg.EffectiveTimes(rec); en >= from && st < to && f.Match(rec) {
				re = append(re, rowEnd{en, row})
			}
		}
	}
	slices.SortFunc(re, s.cmpRow)
	return re
}

// packRows makes re (sorted) x's rows, packed from blk, and charges them.
func (s *stream) packRows(x *heldBlock, blk *flowseg.Block, re []rowEnd) {
	if len(re) == 0 {
		return
	}
	pk, pkCost := s.getPacked()
	x.pk, x.pkCost = pk, pkCost
	pk.Reset(blk)
	x.rows, x.ends = make([]int, len(re)), make([]int64, len(re))
	for i := range re {
		x.rows[i], x.ends[i] = re[i].row, re[i].end
		pk.Add(blk, re[i].row)
	}
	if d := pk.Bytes() - pkCost; d > 0 {
		s.reserve(d)
		x.pkCost += d
	}
	x.cost = int64(len(re)) * 16
	s.reserve(x.cost)
}

// readAgain reads a trimmed block again when the merge reaches its resume
// key, and keeps its rows from that key on.
func (s *stream) readAgain(ctx context.Context, x *heldBlock) error {
	a := s.again[x.src.snap]
	if a.r == nil {
		r, err := flowseg.OpenSnapshot(x.src.Path, x.src.snap) // the footer read before; only the block is read
		if err != nil {
			s.e.o.Logger.Warn("flows: a block couldn't be read again; its rest is skipped", "file", x.rel, "err", err)
			s.unwait(x)
			return nil
		}
		a.r = r
	}
	var sl *slot
	select {
	case sl = <-s.e.slots:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { s.e.slots <- sl }()
	s.e.streamDecodes.Add(1)
	s.e.streamRereads.Add(1)
	from := rowEnd{x.rEnd, x.rRow}
	if err := a.r.Decode(x.block, flowseg.ColAll, &sl.blk); err != nil {
		s.e.o.Logger.Warn("flows: a block couldn't be read again; its rest is skipped", "file", x.rel, "block", x.block, "err", err)
		s.unwait(x)
		return nil
	}
	re := s.selectRows(&sl.blk, &sl.rec, s.f, s.from, s.to, nil)
	i, _ := slices.BinarySearchFunc(re, from, s.cmpRow)
	s.unwait(x)
	s.packRows(x, &sl.blk, re[i:])
	x.next = 0
	return nil
}

// trim keeps each held block's rows up to the end-time horizon that fits
// a quarter of the pool, drops the rest (a block keeps the key to resume
// at; see Stream), and is errStreamFull if what's left is still over the
// budget.
func (s *stream) trim(h *heldHeap) error {
	type cand struct {
		x     *heldBlock
		per   int64 // bytes a row, about
		dense int64 // where its dense run of ends starts (see below)
	}
	var cs []cand
	var fixed int64 // what trimming can't drop
	lo, hi := int64(math.MaxInt64), int64(math.MinInt64)
	for _, x := range h.h {
		if x.pk == nil || x.next >= len(x.rows) {
			fixed += x.cost + x.pkCost + x.resCost
			continue
		}
		cs = append(cs, cand{x: x, per: (x.pkCost+x.cost)/int64(len(x.rows)) + 1})
		a, b := x.ends[x.next], x.ends[len(x.ends)-1]
		lo, hi = min(lo, a, b), max(hi, a, b)
	}
	if len(cs) > 0 {
		// The horizon t: ascending, rows ending at or before it are kept;
		// descending, at or after it. t = lo+d (hi-d descending) keeps more
		// as d grows: take the largest d that fits the target.
		horizon := func(d int64) int64 {
			if s.asc {
				return lo + d
			}
			return hi - d
		}
		within := func(end, t int64) bool {
			if s.asc {
				return end <= t
			}
			return end >= t
		}
		cut := func(x *heldBlock, t int64) int {
			return x.next + sort.Search(len(x.rows)-x.next, func(i int) bool { return !within(x.ends[x.next+i], t) })
		}
		// A block read early for a few rows that end far before the rest
		// (the rest a dense run, a block's usual seconds of spread) keeps
		// those few past the horizon and drops only the dense run, so it's
		// read again once, when the merge reaches the run, not once per
		// horizon (and a block trimmed before keeps all it kept). The run
		// starts within twice the middle half's spread (and 2 s) of the
		// median end.
		for i := range cs {
			x := cs[i].x
			n := len(x.rows) - x.next
			q1, q2, q3 := x.ends[x.next+n/4], x.ends[x.next+n/2], x.ends[x.next+3*n/4]
			spread := 2*max(q3-q1, q1-q3) + 2000
			if s.asc {
				cs[i].dense = q2 - spread - 1
			} else {
				cs[i].dense = q2 + spread + 1
			}
		}
		protect := true
		horizonOf := func(c *cand, t int64) int64 {
			switch {
			case !protect:
				return t
			case c.x.resume && s.asc: // trimmed before: what it kept are the few rows
				return math.MaxInt64
			case c.x.resume:
				return math.MinInt64
			case s.asc:
				return max(t, c.dense)
			}
			return min(t, c.dense)
		}
		kept := func(t int64) int64 {
			n := fixed
			for i := range cs {
				n += int64(cut(cs[i].x, horizonOf(&cs[i], t))-cs[i].x.next) * cs[i].per
			}
			return n
		}
		target := s.budget / 2
		if kept(horizon(0)) > target {
			protect = false // the few rows aren't few: the horizon alone
		}
		d0, d1 := int64(0), hi-lo // the answer is in [d0, d1]
		for d0 < d1 {
			mid := d0 + (d1-d0+1)/2
			if kept(horizon(mid)) <= target {
				d0 = mid
			} else {
				d1 = mid - 1
			}
		}
		t := horizon(d0)
		for i := range cs {
			c := &cs[i]
			x := c.x
			k := cut(x, horizonOf(c, t))
			if k == len(x.rows) && x.next == 0 {
				continue // all within the horizon, and nothing given yet
			}
			// What's kept is copied out (a block mostly given keeps only its
			// rest), and what's past the horizon dropped, to read again.
			if k < len(x.rows) {
				s.e.streamTrims.Add(1)
				x.rEnd, x.rRow = x.ends[k], x.rows[k]
			}
			n := k - x.next
			var pk *flowseg.Packed
			if n > 0 {
				pk = &flowseg.Packed{}
				x.pk.Take(n, pk)
			}
			trimmed := k < len(x.rows)
			s.putPacked(x)
			s.release(x.cost)
			x.rows, x.ends = slices.Clone(x.rows[x.next:k]), slices.Clone(x.ends[x.next:k])
			x.next, x.cost = 0, int64(n)*16
			s.reserve(x.cost)
			if pk != nil {
				x.pk, x.pkCost = pk, pk.Bytes()
				s.reserve(x.pkCost)
			}
			if trimmed {
				s.wait(x)
			}
		}
	}
	if s.used.Load() > s.budget {
		return errStreamFull
	}
	return nil
}

// cmpRow orders one block's rows: by end (descending unless asc), then row.
func (s *stream) cmpRow(a, b rowEnd) int {
	if a.end != b.end {
		if (a.end > b.end) != s.asc {
			return -1
		}
		return 1
	}
	return a.row - b.row
}

// pages carries on from the last record given with Search's pages.
func (s *stream) pages(ctx context.Context, q Query) error {
	qk := q.key("search", s.asc)
	cursor := ""
	if s.emitted {
		cursor = encodeCursor(s.last, qk, &q)
	}
	for {
		res, err := s.e.Search(ctx, q, streamPage, s.asc, cursor, time.Minute)
		if err != nil {
			return err
		}
		for i := range res.Hits {
			if err := s.fn(&res.Hits[i]); err != nil {
				return err
			}
		}
		if res.Cursor == "" {
			return nil
		}
		cursor = res.Cursor
	}
}

// recordSize is a flow.Record's in-memory size, for raw rows' charge.
const recordSize = int64(unsafe.Sizeof(flow.Record{}))
