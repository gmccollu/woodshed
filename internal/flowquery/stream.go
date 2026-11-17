package flowquery

import (
	"container/heap"
	"context"
	"errors"
	"slices"
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
// buffers. A window whose blocks overlap so much
// in flow time that the pool can't hold them (or a pool other queries have
// filled) makes it carry on from the last record it gave with Search's pages,
// which hold at most a page.
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

// errStreamFull is the pool refusing another held block.
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
}

func (h *heldBlock) key() hitKey {
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
}

type freePacked struct {
	pk   *flowseg.Packed
	cost int64
}

// streamWave is how many blocks the reader decodes at a time: what it keeps
// is about the blocks overlapping in flow time plus two waves, and the
// caller writing the rows is slower than half the workers decoding them.
func (e *Engine) streamWave() int { return max(e.o.Workers/2, 1) }

// reserve takes n bytes from the pool. Past the stream's first held block, a
// pool that can't make room refuses (the first is always charged, as a
// plan's first segment is).
func (s *stream) reserve(n int64) bool {
	if n <= 0 || s.e.pool.reserve(n) {
		return true
	}
	if s.held.Load() > 1 {
		return false
	}
	s.e.pool.used.Add(n)
	return true
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
	s.e.pool.release(h.cost)
	h.cost, h.raw = 0, nil
	s.held.Add(-1)
	if h.pk == nil {
		return
	}
	s.mu.Lock()
	if len(s.free) < s.e.streamWave() {
		s.free = append(s.free, freePacked{h.pk, h.pkCost})
	} else {
		s.e.pool.release(h.pkCost)
	}
	s.mu.Unlock()
	h.pk, h.pkCost = nil, 0
}

// close returns the free buffers' charge.
func (s *stream) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.free {
		s.e.pool.release(f.cost)
	}
	s.free = nil
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
			end := top.ends[top.next]
			if w.more && ((!s.asc && end <= w.bound) || (s.asc && end >= w.bound)) {
				break // something unread may still come first
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
			if top.next++; top.next == len(top.rows) {
				heap.Pop(h)
				s.put(top)
			} else {
				heap.Fix(h, 0)
			}
		}
		if !w.more && h.Len() == 0 {
			break
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
	blk, rec := &sl.blk, &sl.rec
	s.e.streamDecodes.Add(1)
	if err := r.Decode(b.block, flowseg.ColAll, blk); err != nil {
		return fail(err)
	}
	re = re[:0]
	if f.Empty() { // the times alone decide
		for row := 0; row < blk.Rows; row++ {
			if st, en := blk.EffectiveTimes(row); en >= p.from && st < p.to {
				re = append(re, rowEnd{en, row})
			}
		}
	} else {
		for row := 0; row < blk.Rows; row++ {
			blk.Record(row, rec)
			if st, en := flowseg.EffectiveTimes(rec); en >= p.from && st < p.to && f.Match(rec) {
				re = append(re, rowEnd{en, row})
			}
		}
	}
	if len(re) == 0 {
		return x, re, nil
	}
	slices.SortFunc(re, s.cmpRow)
	pk, pkCost := s.getPacked()
	x.pk, x.pkCost = pk, pkCost
	pk.Reset(blk)
	x.rows, x.ends = make([]int, len(re)), make([]int64, len(re))
	for i := range re {
		x.rows[i], x.ends[i] = re[i].row, re[i].end
		pk.Add(blk, re[i].row)
	}
	if d := pk.Bytes() - pkCost; d > 0 {
		if !s.reserve(d) {
			return fail(errStreamFull)
		}
		x.pkCost += d
	}
	n := int64(len(re)) * 16
	if !s.reserve(n) {
		return fail(errStreamFull)
	}
	x.cost = n
	return x, re, nil
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
