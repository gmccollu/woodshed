package flowquery

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// A query's plan streams the window (SPEC §13.10 decision 56): segments come
// from the index a page at a time, in time order (newest end first, or with
// asc lowest start first), and their blocks are loaded a batch of segments at
// a time, sorted within the batch. A batch stops at planBatch directory
// entries loaded or planBatchSegs segments (always a whole segment): a
// loaded segment holds every block's entry and raw chunk, its footer's or its
// snapshot's, in the window or not, and a closed one an open file until its
// planned blocks are read, so a narrow window over many segments can't fill
// memory with directories, or run out of files, while it plans few blocks.
// So what a plan holds doesn't depend on the window's length or its exporter
// count. Reading isn't in one global block order any more, but every bound a
// caller uses (complete_from, a search page's certainty) is the bound of
// everything still unread: the batch's next block and the next segment.

const (
	planPage      = 256    // index rows read at a time
	planBatch     = 16_384 // directory entries loaded at a time (at least one whole segment)
	planBatchSegs = 256    // segments loaded at a time
)

// pageRows and batchBlocks are the engine's (tests make them small).
func (e *Engine) pageRows() int {
	if e.page > 0 {
		return e.page
	}
	return planPage
}

func (e *Engine) batchBlocks() int {
	if e.batch > 0 {
		return e.batch
	}
	return planBatch
}

// openMargin widens an open segment's indexed start for ascending plans: its
// index row lags the writer, and a record written since may start earlier.
const openMargin = time.Hour

type segRef struct {
	DeviceID, Rel, Path string
	snap                *flowseg.Footer        // a snapshot (the writer's footer); nil: read the file
	lazy                func() *flowseg.Footer // takes the snapshot when the batch loads
	live                bool                   // another process is writing it (OpenLive)
	open                bool                   // being written: its bounds aren't final
	start, end          int64                  // flow time, from the index (open: widened)
	records             int64                  // the index's count (0: not indexed)
}

// openSeg opens a segment that has no snapshot: closed through its footer,
// else (still being written, by another process) read-only up to its last
// complete block.
func openSeg(path string) (*flowseg.Reader, bool, error) {
	r, err := flowseg.Open(path)
	if errors.Is(err, flowseg.ErrNoFooter) {
		r, err = flowseg.OpenLive(path)
		return r, true, err
	}
	return r, false, err
}

type plan struct {
	e    *Engine
	devs []string
	asc  bool
	from int64
	to   int64
	// skip and skipSeg drop a block or a whole segment before it loads (a
	// search page's cursor).
	skip    func(b *planned) bool
	skipSeg func(s *segRef) bool

	// Segments not loaded yet: open segments with no index row, then the index
	// pages, merged with the open ones by their key.
	unindexed []segRef // open, never indexed: first
	pending   []segRef // the current index page's rest
	cur       *index.FlowSegCursor
	indexDone bool
	openRels  map[string]OpenSegment // indexed open segments the pages haven't reached
	openStart map[string]int64       // their indexed starts

	// The loaded batch.
	segs   []segRef
	blocks []planned
	done   int

	// Progress.
	recsEst      int64 // records: the index's for unloaded segments, exact for loaded ones
	blocksLoaded int64
	rowsLoaded   int64
	err          error
}

// planFor starts the window's plan.
func (e *Engine) planFor(ctx context.Context, q *Query, asc bool) (*plan, error) {
	p := &plan{e: e, devs: q.DeviceIDs, asc: asc, from: q.From.UnixMilli(), to: q.To.UnixMilli(), openRels: map[string]OpenSegment{},
		openStart: map[string]int64{}}
	if e.o.Open != nil {
		want := map[string]bool{}
		for _, d := range q.DeviceIDs {
			want[d] = true
		}
		for _, os := range e.o.Open(q.DeviceIDs) {
			if q.DeviceIDs == nil || want[os.DeviceID] {
				p.openRels[os.Rel] = os
			}
		}
	}
	_, recs, err := e.o.Index.FlowSegmentsCount(ctx, q.DeviceIDs, q.From, q.To)
	if err != nil {
		return nil, err
	}
	p.recsEst = recs
	// Open segments the index doesn't list yet go first; find them by asking
	// for their rows.
	seen := map[string]bool{}
	if len(p.openRels) > 0 {
		var c *index.FlowSegCursor
		for {
			rows, err := e.o.Index.FlowSegmentsPage(ctx, q.DeviceIDs, q.From, q.To, false, c, e.pageRows())
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				if _, ok := p.openRels[r.Path]; ok {
					seen[r.Path] = true
					p.openStart[r.Path] = r.Start
				}
			}
			// Open segments hold the newest ends: stop past the hour they could be in.
			if len(rows) < e.pageRows() || len(seen) == len(p.openRels) || rows[len(rows)-1].End < p.from {
				break
			}
			last := rows[len(rows)-1]
			c = &index.FlowSegCursor{Key: last.End, Path: last.Path}
		}
		rels := make([]string, 0, len(p.openRels))
		for rel := range p.openRels {
			if !seen[rel] {
				rels = append(rels, rel)
			}
		}
		sort.Strings(rels)
		for _, rel := range rels {
			p.unindexed = append(p.unindexed, p.openRef(p.openRels[rel], nil))
			delete(p.openRels, rel)
		}
	}
	return p, ctx.Err()
}

// openRef is an open segment's reference; row is its index row, if any.
func (p *plan) openRef(os OpenSegment, row *index.FlowSegment) segRef {
	ref := segRef{DeviceID: os.DeviceID, Rel: os.Rel, Path: os.Path, snap: os.Footer, lazy: os.Snap, open: true,
		start: math.MinInt64, end: math.MaxInt64}
	if row != nil {
		ref.start, ref.records = row.Start-openMargin.Milliseconds(), row.Records
	}
	return ref
}

// nextSeg pops the next segment to load, or false when none is left.
func (p *plan) nextSeg(ctx context.Context) (segRef, bool) {
	if len(p.unindexed) > 0 {
		s := p.unindexed[0]
		p.unindexed = p.unindexed[1:]
		return s, true
	}
	if len(p.pending) == 0 && !p.indexDone {
		from, to := time.UnixMilli(p.from).UTC(), time.UnixMilli(p.to).UTC()
		rows, err := p.e.o.Index.FlowSegmentsPage(ctx, p.devs, from, to, p.asc, p.cur, p.e.pageRows())
		if err != nil {
			p.err = err
			p.indexDone = true
			return segRef{}, false
		}
		if len(rows) < p.e.pageRows() {
			p.indexDone = true
		}
		if len(rows) > 0 {
			last := rows[len(rows)-1]
			k := last.End
			if p.asc {
				k = last.Start
			}
			p.cur = &index.FlowSegCursor{Key: k, Path: last.Path}
		}
		for i := range rows {
			r := &rows[i]
			if os, ok := p.openRels[r.Path]; ok {
				p.pending = append(p.pending, p.openRef(os, r))
				delete(p.openRels, r.Path)
				delete(p.openStart, r.Path)
				continue
			}
			p.pending = append(p.pending, segRef{DeviceID: r.DeviceID, Rel: r.Path,
				Path: filepath.Join(p.e.o.DataDir, filepath.FromSlash(r.Path)), start: r.Start, end: r.End, records: r.Records})
		}
	}
	if len(p.pending) == 0 {
		return segRef{}, false
	}
	s := p.pending[0]
	p.pending = p.pending[1:]
	if p.skipSeg != nil && p.skipSeg(&s) {
		p.recsEst -= s.records
		return p.nextSeg(ctx)
	}
	return s, true
}

// peekKey is the next unloaded segment's bound: its end (desc) or start
// (asc); ok false when none is left.
func (p *plan) peekKey(ctx context.Context) (int64, bool) {
	if len(p.unindexed) > 0 {
		if p.asc {
			return math.MinInt64, true
		}
		return math.MaxInt64, true
	}
	if len(p.pending) == 0 && !p.indexDone {
		// Fetch the next page (nextSeg's way), then put the segment back.
		s, ok := p.nextSeg(ctx)
		if !ok {
			return 0, false
		}
		p.pending = append([]segRef{s}, p.pending...)
	}
	if len(p.pending) == 0 {
		return 0, false
	}
	s := p.pending[0]
	if p.asc {
		return s.start, true
	}
	return s.end, true
}

// load reads the next batch of segments' blocks (rd's readers are the
// batch's: it starts empty, and keeps the readers opened here).
func (p *plan) load(ctx context.Context, rd *readers) {
	rd.reset(p)
	p.segs, p.blocks, p.done = p.segs[:0], p.blocks[:0], 0
	for entries := 0; entries < p.e.batchBlocks() && len(p.segs) < planBatchSegs; {
		ref, ok := p.nextSeg(ctx)
		if !ok {
			break
		}
		if ref.open && ref.snap == nil && ref.lazy != nil {
			ref.snap = ref.lazy()
		}
		var r *flowseg.Reader
		var foot *flowseg.Footer
		var err error
		switch {
		case ref.snap != nil:
			foot = ref.snap
		default:
			// A closed segment, or an open one closed since it was listed.
			r, ref.live, err = openSeg(ref.Path)
			if err != nil {
				p.recsEst -= ref.records
				continue // deleted by retention since
			}
			foot = r.Footer()
		}
		si := len(p.segs)
		p.segs = append(p.segs, ref)
		planned0 := len(p.blocks)
		// A segment costs an entry even with no blocks (its footer, its file).
		entries += 1 + len(foot.Blocks) + len(foot.RawChunks)
		var rows int64
		for i := range foot.Blocks {
			b := &foot.Blocks[i]
			if b.Rows == 0 || !b.Overlaps(p.from, p.to-1) {
				continue
			}
			pb := planned{seg: si, block: i, rows: b.Rows, minStart: b.MinStart, maxStart: b.MaxStart, minEnd: b.MinEnd, maxEnd: b.MaxEnd}
			p.blocksLoaded++
			p.rowsLoaded += int64(b.Rows)
			if p.skip != nil && p.skip(&pb) {
				continue
			}
			rows += int64(b.Rows)
			p.blocks = append(p.blocks, pb)
		}
		p.recsEst += rows - ref.records
		if foot.RawStatus[flow.StatusNoTemplate] > 0 || (foot.Raw > 0 && foot.RawStatus == [4]int64{}) {
			lo, hi := foot.MinReceived-rawSpan.Milliseconds(), foot.MaxReceived
			if hi >= p.from && lo < p.to {
				p.blocks = append(p.blocks, planned{seg: si, block: -1, raw: true, minStart: lo, maxStart: hi, minEnd: lo, maxEnd: hi})
			}
		}
		if r != nil {
			if len(p.blocks) > planned0 {
				rd.put(si, r)
			} else {
				r.Close() // nothing to read: don't hold its file for the batch
			}
		}
	}
	asc := p.asc
	sort.SliceStable(p.blocks, func(i, j int) bool {
		a, b := p.blocks[i], p.blocks[j]
		if asc {
			if a.minEnd != b.minEnd {
				return a.minEnd < b.minEnd
			}
		} else if a.maxEnd != b.maxEnd {
			return a.maxEnd > b.maxEnd
		}
		if a.seg != b.seg {
			return p.segs[a.seg].Rel < p.segs[b.seg].Rel
		}
		return a.block < b.block
	})
	rd.track(p.blocks)
}

// more reports whether blocks may remain.
func (p *plan) more(ctx context.Context) bool {
	if p.done < len(p.blocks) {
		return true
	}
	_, ok := p.peekKey(ctx)
	return ok
}

// take returns up to n of the next blocks, loading the next batch when the
// current one is read (the blocks returned before must have been scanned).
func (p *plan) take(ctx context.Context, rd *readers, n int) []planned {
	for p.done >= len(p.blocks) {
		if _, ok := p.peekKey(ctx); !ok {
			return nil
		}
		p.load(ctx, rd)
	}
	hi := min(p.done+n, len(p.blocks))
	out := p.blocks[p.done:hi]
	p.done = hi
	return out
}

// bound is the bound of everything unread: the greatest end (desc) or the
// least end (asc) any unread block can have; ok false when nothing's left.
func (p *plan) bound(ctx context.Context) (int64, bool) {
	var b int64
	ok := false
	if p.done < len(p.blocks) {
		nb := p.blocks[p.done] // the batch is sorted
		b, ok = nb.maxEnd, true
		if p.asc {
			b = nb.minEnd
		}
	}
	if k, more := p.peekKey(ctx); more {
		if !ok || (!p.asc && k > b) || (p.asc && k < b) {
			b = k
		}
		ok = true
	}
	// An open segment the pages haven't reached yet (its row lags the writer):
	// any end (desc), or from its indexed start less openMargin (asc).
	for _, st := range p.openStart {
		if v := st - openMargin.Milliseconds(); p.asc && (!ok || v < b) {
			b = v
		} else if !p.asc {
			b = math.MaxInt64
		}
		ok = true
	}
	return b, ok
}

// frontier is complete_from: every block ending after it has been read.
func (p *plan) frontier(ctx context.Context) time.Time {
	b, ok := p.bound(ctx)
	switch {
	case !ok:
		b = p.from
	case b == math.MaxInt64 || b > p.to:
		b = p.to
	}
	return time.UnixMilli(max(b, p.from)).UTC()
}

// progress is the plan's progress after recsDone records of blocksDone.
func (p *plan) progress(ctx context.Context, blocksDone, recsDone int64) Progress {
	total := max(p.recsEst, recsDone)
	blocks := p.blocksLoaded
	if more := p.more(ctx); more {
		if rest := total - p.rowsLoaded; rest > 0 {
			per := int64(flowseg.MaxBlockRows)
			if p.blocksLoaded > 0 {
				per = max(p.rowsLoaded/p.blocksLoaded, 1)
			}
			blocks += (rest + per - 1) / per
		}
	} else {
		total, blocks = recsDone, blocksDone
	}
	return Progress{BlocksDone: blocksDone, BlocksTotal: max(blocks, blocksDone), RecordsDone: recsDone, RecordsTotal: total,
		CompleteFrom: p.frontier(ctx)}
}

// readers opens the segments a batch's blocks need, shared by the workers,
// and closes each once its last block is read, so only the segments being
// read hold their directories.
type readers struct {
	mu   sync.Mutex
	p    *plan
	rds  map[int]*flowseg.Reader
	left map[int]int // blocks still to read, by segment
}

func newReaders(p *plan) *readers {
	r := &readers{p: p}
	r.track(p.blocks[p.done:])
	return r
}

// reset closes every reader (a new batch: segment numbers start again).
func (r *readers) reset(p *plan) {
	r.close()
	r.mu.Lock()
	r.p, r.left = p, map[int]int{}
	r.mu.Unlock()
}

// track counts blocks still to read.
func (r *readers) track(blocks []planned) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.left == nil {
		r.left = map[int]int{}
	}
	for _, b := range blocks {
		r.left[b.seg]++
	}
}

func (r *readers) put(si int, rd *flowseg.Reader) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rds == nil {
		r.rds = map[int]*flowseg.Reader{}
	}
	r.rds[si] = rd
}

// done records a block of segment si read.
func (r *readers) done(si int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.left[si]--; r.left[si] <= 0 {
		if rd := r.rds[si]; rd != nil {
			rd.Close()
			delete(r.rds, si)
		}
	}
}

func (r *readers) get(si int) (*flowseg.Reader, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rd := r.rds[si]; rd != nil {
		return rd, nil
	}
	s := r.p.segs[si]
	var rd *flowseg.Reader
	var err error
	switch {
	case s.snap != nil:
		rd, err = flowseg.OpenSnapshot(s.Path, s.snap)
	case s.live:
		rd, err = flowseg.OpenLive(s.Path)
	default:
		rd, err = flowseg.Open(s.Path)
	}
	if err != nil {
		return nil, err
	}
	if r.rds == nil {
		r.rds = map[int]*flowseg.Reader{}
	}
	r.rds[si] = rd
	return rd, nil
}

func (r *readers) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rd := range r.rds {
		rd.Close()
	}
	r.rds = nil
}
