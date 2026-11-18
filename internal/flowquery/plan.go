package flowquery

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unsafe"

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
	wide                bool                   // holds raw sets an ordered plan reads first (their records' times are unknown)
	start, end          int64                  // flow time, from the index (open: widened)
	records             int64                  // the index's count (0: not indexed)
	// id is the file snap was read from, when it was read from one (a page
	// stream keeps snap between pages: a file written again under the same
	// name isn't the one its offsets are for).
	id flowseg.Identity
}

// errReplaced is a segment file that isn't the one its kept footer was read
// from (deleted and written again under its name).
var errReplaced = errors.New("flows: segment replaced since its footer was read")

// openLoad is an open segment a plan has loaded: how much of it the plan
// planned (its snapshot's blocks and raw chunks then), so a page stream
// that resumes can read what's been written to it since.
type openLoad struct {
	ref    segRef // the segment (snap: the newest snapshot a page stream read blocks of)
	blocks int
	raw    int
	cost   int64 // ref.snap's directory, charged to the page stream that keeps it (pages.go)
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

	// Segments not loaded yet: the open segments, listed once when the plan
	// starts and keyed then (their index rows change while the plan pages,
	// so the pages skip them), merged with the index pages by key.
	opens   []segRef        // unread open segments, in key order
	openSet map[string]bool // every open segment's rel (the pages skip them)
	// An ordered plan's (Search, Stream) closed segments holding raw sets
	// still to decode: loaded before the rest, in rel order, since the
	// records decoded from them may end anywhere (an exporter's clock ahead
	// of Woodshed's puts them after their received time), so no bound but
	// the widest is true until they're read.
	ordered   bool
	wides     []segRef
	wideSet   map[string]bool
	pending   []segRef // the current index page's rest
	cur       *index.FlowSegCursor
	indexDone bool

	// The loaded batch.
	segs   []segRef
	blocks []planned
	done   int

	// charged is the loaded batch's bytes, reserved in the engine's pool.
	charged int64

	// What the plan was made against, for a page stream that resumes
	// (pages.go): the index's segment count for the window, the segments
	// the index said hold raw sets to decode (ordered plans), and the open
	// segments loaded so far.
	segCount   int64
	ntSet      map[string]bool
	openLoaded map[string]*openLoad

	// Progress.
	recsEst      int64 // records: the index's for unloaded segments, exact for loaded ones
	blocksLoaded int64
	rowsLoaded   int64
	err          error
}

// planFor starts the window's plan.
func (e *Engine) planFor(ctx context.Context, q *Query, asc bool) (*plan, error) {
	return e.newPlan(ctx, q, asc, false)
}

// planOrdered starts a plan whose bounds must hold for every record, raw
// sets' included: a search page's or Stream's, which give records in order
// and call them certain from the bounds.
func (e *Engine) planOrdered(ctx context.Context, q *Query, asc bool) (*plan, error) {
	return e.newPlan(ctx, q, asc, true)
}

func (e *Engine) newPlan(ctx context.Context, q *Query, asc, ordered bool) (*plan, error) {
	e.sweepPages() // any query releases abandoned listings' page streams
	p := &plan{e: e, devs: q.DeviceIDs, asc: asc, from: q.From.UnixMilli(), to: q.To.UnixMilli(), openSet: map[string]bool{},
		ordered: ordered}
	n, recs, err := e.o.Index.FlowSegmentsCount(ctx, q.DeviceIDs, q.From, q.To)
	if err != nil {
		return nil, err
	}
	p.recsEst, p.segCount = recs, n
	if err := p.listWides(ctx, q); err != nil {
		return nil, err
	}
	if e.o.Open == nil {
		return p, ctx.Err()
	}
	want := map[string]bool{}
	for _, d := range q.DeviceIDs {
		want[d] = true
	}
	var rels []string
	byRel := map[string]OpenSegment{}
	for _, os := range e.o.Open(q.DeviceIDs) {
		if (q.DeviceIDs == nil || want[os.DeviceID]) && !p.openSet[os.Rel] {
			p.openSet[os.Rel] = true
			byRel[os.Rel] = os
			rels = append(rels, os.Rel)
		}
	}
	// Their keys: any end (descending: they hold the newest flows), or the
	// indexed start less openMargin (ascending; none indexed yet: first).
	starts := map[string]int64{}
	wideRaw := map[string]bool{} // open segments the index says hold raw sets to decode
	if (asc || ordered) && len(rels) > 0 {
		rows, err := e.o.Index.FlowSegmentsByPath(ctx, rels)
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			starts[r.Path] = r.Start
			wideRaw[r.Path] = r.NoTemplate > 0
		}
	}
	for _, rel := range rels {
		ref := segRef{DeviceID: byRel[rel].DeviceID, Rel: rel, Path: byRel[rel].Path, snap: byRel[rel].Footer,
			lazy: byRel[rel].Snap, open: true, start: math.MinInt64, end: math.MaxInt64}
		if st, ok := starts[rel]; ok && st-openMargin.Milliseconds() > math.MinInt64 {
			ref.start = st - openMargin.Milliseconds()
		}
		if p.ordered && wideRaw[rel] {
			ref.start = math.MinInt64 // its raw sets: first ascending too
		}
		p.opens = append(p.opens, ref)
	}
	sort.Slice(p.opens, func(i, j int) bool {
		a, b := p.opens[i], p.opens[j]
		if a.start != b.start {
			return a.start < b.start
		}
		return a.Rel < b.Rel
	})
	return p, ctx.Err()
}

// listWides lists an ordered plan's closed segments with raw sets to
// decode (the index's no_template count), in rel order.
func (p *plan) listWides(ctx context.Context, q *Query) error {
	if !p.ordered {
		return nil
	}
	rows, err := p.e.o.Index.FlowSegmentsNoTemplate(ctx, q.DeviceIDs, q.From, q.To)
	if err != nil {
		return err
	}
	p.wideSet, p.ntSet = map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		p.ntSet[r.Path] = true
	}
	var open map[string]bool
	if p.e.o.Open != nil {
		open = map[string]bool{}
		for _, os := range p.e.o.Open(q.DeviceIDs) {
			open[os.Rel] = true
		}
	}
	for _, r := range rows {
		if open[r.Path] {
			continue // listed with the open segments
		}
		p.wideSet[r.Path] = true
		p.wides = append(p.wides, segRef{DeviceID: r.DeviceID, Rel: r.Path,
			Path: filepath.Join(p.e.o.DataDir, filepath.FromSlash(r.Path)), wide: true, start: math.MinInt64, end: math.MaxInt64,
			records: r.Records})
	}
	sort.Slice(p.wides, func(i, j int) bool { return p.wides[i].Rel < p.wides[j].Rel })
	return nil
}

// openFirst reports whether the next open segment comes before the index's
// next row (with a page loaded): always descending, by start ascending.
func (p *plan) openFirst() bool {
	if len(p.opens) == 0 {
		return false
	}
	return !p.asc || len(p.pending) == 0 || p.opens[0].start <= p.pending[0].start
}

// fill loads index pages until a row waits in pending or the index is done.
// Rows of open segments are left out (they load from p.opens).
func (p *plan) fill(ctx context.Context) {
	for len(p.pending) == 0 && !p.indexDone {
		from, to := time.UnixMilli(p.from).UTC(), time.UnixMilli(p.to).UTC()
		rows, err := p.e.o.Index.FlowSegmentsPage(ctx, p.devs, from, to, p.asc, p.cur, p.e.pageRows())
		if err != nil {
			p.err = err
			p.indexDone = true
			return
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
			if p.openSet[r.Path] {
				p.recsEst -= r.Records // counted when it loads
				continue
			}
			if p.wideSet[r.Path] {
				continue // loaded first (listWides)
			}
			p.pending = append(p.pending, segRef{DeviceID: r.DeviceID, Rel: r.Path,
				Path: filepath.Join(p.e.o.DataDir, filepath.FromSlash(r.Path)), start: r.Start, end: r.End, records: r.Records})
		}
	}
}

// nextSeg pops the next segment to load, or false when none is left.
func (p *plan) nextSeg(ctx context.Context) (segRef, bool) {
	if len(p.wides) > 0 {
		s := p.wides[0]
		p.wides = p.wides[1:]
		return s, true
	}
	for {
		if !p.asc && len(p.opens) > 0 {
			break // descending, the open segments go first: no page needed
		}
		p.fill(ctx)
		if p.openFirst() || len(p.pending) == 0 {
			break
		}
		s := p.pending[0]
		p.pending = p.pending[1:]
		if p.skipSeg != nil && p.skipSeg(&s) {
			p.recsEst -= s.records
			continue
		}
		return s, true
	}
	if len(p.opens) == 0 {
		return segRef{}, false
	}
	s := p.opens[0]
	p.opens = p.opens[1:]
	return s, true
}

// peekKey is the next unloaded segment's bound: its end (desc) or start
// (asc); ok false when none is left. Skipped segments are dropped on the way.
func (p *plan) peekKey(ctx context.Context) (int64, bool) {
	if len(p.wides) > 0 {
		if p.asc {
			return math.MinInt64, true
		}
		return math.MaxInt64, true
	}
	if !p.asc && len(p.opens) > 0 {
		return math.MaxInt64, true
	}
	for {
		p.fill(ctx)
		if p.openFirst() {
			return p.opens[0].start, true
		}
		if len(p.pending) == 0 {
			return 0, false
		}
		if s := &p.pending[0]; p.skipSeg != nil && p.skipSeg(s) {
			p.recsEst -= s.records
			p.pending = p.pending[1:]
			continue
		}
		if p.asc {
			return p.pending[0].start, true
		}
		return p.pending[0].end, true
	}
}

// Batch bytes charged to the engine's pool (decision 51's 128 MiB), so the
// directories running and saved plans hold count with the tables: each
// loaded segment's entries, raw chunks and planned blocks.
var (
	entryCost   = int64(unsafe.Sizeof(flowseg.BlockInfo{}))
	rawCost     = int64(unsafe.Sizeof(flowseg.RawChunk{}))
	plannedCost = int64(unsafe.Sizeof(planned{}))
)

// release returns the batch's pool bytes (idempotent).
func (p *plan) release() {
	p.e.pool.release(p.charged)
	p.charged = 0
}

// load reads the next batch of segments' blocks (rd's readers are the
// batch's: it starts empty, and keeps the readers opened here). Past the
// first segment, a segment the pool can't make room for (after dropping
// saved states) ends the batch, its bytes charged anyway: a plan is over
// the pool by one segment at most.
func (p *plan) load(ctx context.Context, rd *readers) {
	rd.reset(p)
	p.release()
	clear(p.segs) // no stale snapshots past the new length
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
		if r != nil {
			ref.id = r.Identity()
		}
		if ref.open {
			if p.openLoaded == nil {
				p.openLoaded = map[string]*openLoad{}
			}
			p.openLoaded[ref.Rel] = &openLoad{ref: segRef{DeviceID: ref.DeviceID, Rel: ref.Rel, Path: ref.Path, id: ref.id, open: true},
				blocks: len(foot.Blocks), raw: len(foot.RawChunks)}
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
			// The records decoded from raw sets are matched against the
			// window one by one, so the sets are always read: their records'
			// times needn't be near their received times. An ordered plan
			// bounds them by nothing (read first; they hold no rows to
			// count); the others keep the received times as the position
			// they read them at.
			lo, hi := foot.MinReceived-rawSpan.Milliseconds(), foot.MaxReceived
			if p.ordered {
				lo, hi = math.MinInt64, math.MaxInt64
			}
			p.blocks = append(p.blocks, planned{seg: si, block: -1, raw: true, minStart: lo, maxStart: hi, minEnd: lo, maxEnd: hi})
		}
		if r != nil {
			if len(p.blocks) > planned0 {
				rd.put(si, r)
			} else {
				r.Close() // nothing to read: don't hold its file for the batch
			}
		}
		cost := int64(len(foot.Blocks))*entryCost + int64(len(foot.RawChunks))*rawCost + int64(len(p.blocks)-planned0)*plannedCost
		if si == 0 || p.e.pool.reserve(cost) {
			if si == 0 {
				p.e.pool.used.Add(cost)
			}
			p.charged += cost
			continue
		}
		p.e.pool.used.Add(cost)
		p.charged += cost
		break
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
	if s.id != (flowseg.Identity{}) && rd.Identity() != s.id {
		rd.Close()
		return nil, errReplaced
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
