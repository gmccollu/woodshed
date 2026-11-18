package flowquery

import (
	"cmp"
	"container/heap"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"slices"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// The engine reads segments for a window: it plans every block whose flow
// time overlaps it, newest first by flow end (oldest first by end for
// ascending searches), skips blocks the filter's index check rules out, and
// reads the rest in parallel within a time budget. A top-N or summary that
// runs out of budget keeps its running counts on the server under a cursor
// (§10.1.5's rules: 10 minutes, at most 8, least recently used out) and
// reports progress: blocks and records done of those the window touches,
// and complete_from, the flow time after which every block has been read.

// OpenSegment is a segment the store is still writing, as of its snapshot.
type OpenSegment struct {
	DeviceID, Rel, Path string
	Footer              *flowseg.Footer
	// Snap, when Footer is nil, takes the snapshot when the plan reaches the
	// segment (nil: it closed since; it's read from its file).
	Snap func() *flowseg.Footer
}

// Options configure an Engine.
type Options struct {
	DataDir string
	Index   *index.DB
	// Open returns the open segments of deviceIDs (nil: all).
	Open func(deviceIDs []string) []OpenSegment
	// Workers read blocks in parallel, shared by every query on the engine
	// (default GOMAXPROCS, at most DefaultWorkers): each holds a block's
	// decode buffers (about 10 MiB).
	Workers int
	Clock   func() time.Time
	Logger  *slog.Logger
	// MaxExactKeys overrides DefaultExactKeys (tests).
	MaxExactKeys int
	// PoolBytes is the bytes all queries' exact top-N tables and summary
	// values may take (default DefaultPoolBytes); saved states are dropped,
	// least recently used first, to make room, then tables turn approximate.
	PoolBytes int64
	// RuleIDIEs fill rule_id in raw sets decoded on read (as the collector does).
	RuleIDIEs []flow.IEKey
}

// Engine runs flow queries. Safe for concurrent use.
type Engine struct {
	o      Options
	mu     sync.Mutex
	states map[string]*state
	pages  map[string]*pageState        // search pages' continuations, by the cursor they were given under (pages.go)
	rules  atomic.Pointer[[]flow.IEKey] // RuleIDIEs in effect (SetRuleIDIEs)
	pool   *Pool
	slots  chan *slot

	// saves counts saved states and page streams (e.mu): their least
	// recently used order. Not the clock, whose readings tie (Windows'
	// resolution) and which tests move.
	saves uint64

	page, batch int // plan sizes, for tests (0: planPage, planBatch)

	// Stream's blocks decoded and its falls back to pages (tests).
	streamDecodes, streamFallbacks atomic.Int64
	// Stream's blocks trimmed and read again (tests).
	streamTrims, streamRereads atomic.Int64
	// fillHook runs as a search page's second pass starts (tests).
	fillHook func()
	// Search pages started as a stream, continued from a saved one, and
	// served by searchStateless after a stream ran over its budget; saved
	// streams dropped on resume because the store changed under them; blocks
	// they read as they resumed (written to open segments since); and rows a
	// stream left out because they came up behind the last it gave (tests).
	pageStarts, pageResumes, pageFallbacks, pageRebuilds, pageCatchUps, streamLate atomic.Int64
	// The saved page streams' pool bytes (pageState.bytes), and the timer
	// that sweeps them once expired.
	savedPageBytes atomic.Int64
	pageTimer      *time.Timer
	// statelessPages makes every search page searchStateless's (tests).
	statelessPages bool

	gcMu                  sync.Mutex
	gcCycles, gcAllocBase uint64
}

// While a query holds a big exact table (at least gcNudgePool of the pool),
// the engine runs a collection after any wave that follows gcNudgeBytes of
// allocation. Go's pacer lets garbage reach the live heap's size before
// collecting, so a long scan beside a 130 MiB table would otherwise peak
// near twice that; the table holds no pointers, so a collection is cheap.
const (
	gcNudgePool  = 32 << 20
	gcNudgeBytes = 16 << 20
)

var gcSamples = []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}, {Name: "/gc/cycles/total:gc-cycles"}}

func (e *Engine) gcNudge() {
	if e.pool.Used()-e.savedPageBytes.Load() < gcNudgePool { // saved page streams sit idle: they make no garbage
		return
	}
	e.gcMu.Lock()
	defer e.gcMu.Unlock()
	s := slices.Clone(gcSamples)
	metrics.Read(s)
	allocs, cycles := s[0].Value.Uint64(), s[1].Value.Uint64()
	if cycles != e.gcCycles {
		e.gcCycles, e.gcAllocBase = cycles, allocs // collected since: count from here
		return
	}
	if allocs-e.gcAllocBase >= gcNudgeBytes {
		runtime.GC()
		metrics.Read(s)
		e.gcAllocBase, e.gcCycles = s[0].Value.Uint64(), s[1].Value.Uint64()
	}
}

// DefaultWorkers caps the default worker count (the reference box's 4
// vCPU), which bounds the block buffers (SPEC §13.6).
const DefaultWorkers = 4

// slot is a worker's reusable decode buffers.
type slot struct {
	blk flowseg.Block
	rec flow.Record
}

// SetRuleIDIEs changes the IEs that fill rule_id in raw sets decoded on read
// (a settings save), from the next query on.
func (e *Engine) SetRuleIDIEs(rules []flow.IEKey) {
	r := append([]flow.IEKey(nil), rules...)
	e.rules.Store(&r)
}

func (e *Engine) ruleIEs() []flow.IEKey {
	if r := e.rules.Load(); r != nil {
		return *r
	}
	return nil
}

// State limits for continued top-N and summaries (as Events v2's).
const (
	StateTTL       = 10 * time.Minute
	MaxStates      = 8
	waveBlocksPerW = 2
)

// ErrExpired is a cursor whose running counts are gone.
var ErrExpired = errors.New("This flow query expired; start it again.")

// ErrCursor is a cursor from another query.
var ErrCursor = errors.New("cursor: from another query; start again without it.")

// New returns an engine.
func New(o Options) *Engine {
	if o.Workers <= 0 {
		o.Workers = min(runtime.GOMAXPROCS(0), DefaultWorkers)
	}
	if o.PoolBytes <= 0 {
		o.PoolBytes = DefaultPoolBytes
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.MaxExactKeys <= 0 {
		o.MaxExactKeys = DefaultExactKeys
	}
	e := &Engine{o: o, states: map[string]*state{}, pages: map[string]*pageState{}, pool: NewPool(o.PoolBytes), slots: make(chan *slot, o.Workers)}
	for range o.Workers {
		e.slots <- &slot{}
	}
	e.pool.full = e.evictOne
	e.SetRuleIDIEs(o.RuleIDIEs)
	return e
}

// Query is a window, a device selection and a filter.
type Query struct {
	DeviceIDs []string // nil: every device
	From, To  time.Time
	Filter    *Filter // nil: everything
	// DefaultRange says From and To were filled in from "now" (the request
	// named neither): a continuation keeps the first request's range rather
	// than a cursor mismatch.
	DefaultRange bool
}

func (q *Query) filter() *Filter {
	if q.Filter == nil {
		return &Filter{}
	}
	return q.Filter
}

// key is the query's identity, for cursors.
func (q *Query) key(extra ...any) string {
	from, to := q.From.UnixMilli(), q.To.UnixMilli()
	if q.DefaultRange {
		from, to = 0, 0
	}
	b, _ := json.Marshal(append([]any{q.DeviceIDs, from, to, q.Filter}, extra...))
	return string(b)
}

// Progress is a flow answer's progress.
type Progress struct {
	BlocksDone, BlocksTotal   int64
	RecordsDone, RecordsTotal int64
	CompleteFrom              time.Time
}

// planned is one block to read.
type planned struct {
	seg      int // index into plan.segs
	block    int
	rows     int
	minStart int64
	maxStart int64
	minEnd   int64
	maxEnd   int64
	// raw: not a block but the segment's raw sets, decoded on read where the
	// segment holds their template (SPEC §13.1.3); times bound by received.
	raw bool
}

// rawSpan is how far before its received time a raw set's records may start.
const rawSpan = time.Hour

// rawRecords decodes a segment's raw sets kept for lack of a template, with the
// segment's own templates, calling fn with each record (marked late).
func rawRecords(r *flowseg.Reader, rules []flow.IEKey, fn func(i int, rec *flow.Record)) error {
	ts := r.Templates()
	i := 0
	return r.Raw(func(rs *flow.RawSet) bool {
		if rs.Status != flow.StatusNoTemplate {
			return true
		}
		t := templateFor(ts, rs)
		if t == nil {
			return true
		}
		recs, err := flow.DecodeRawSet(t, rs, flow.RedecodeOptions{RuleIDIEs: rules})
		if err != nil {
			return true
		}
		for j := range recs {
			recs[j].Status = flow.StatusLate
			fn(i, &recs[j])
			i++
		}
		return true
	})
}

// templateFor picks the segment's template for a raw set: the same version,
// exporter port, domain and ID, the first received after the set, else the
// latest (as reindex --flows-redecode does).
func templateFor(ts []*flow.Template, rs *flow.RawSet) *flow.Template {
	var after, latest *flow.Template
	for _, t := range ts {
		if t.ID != rs.TemplateID || t.Domain != rs.Domain || t.ExporterPort != rs.ExporterPort || t.Version != rs.Version {
			continue
		}
		if t.Received >= rs.Received && (after == nil || t.Received < after.Received) {
			after = t
		}
		if latest == nil || t.Received > latest.Received {
			latest = t
		}
	}
	if after != nil {
		return after
	}
	return latest
}

// colsFor are the columns a task reads with filter f.
func colsFor(f *Filter, extra flowseg.Cols) flowseg.Cols {
	has, samp, st, dom := f.Cols()
	c := flowseg.Cols(has) | flowseg.Cols(flow.HasStart|flow.HasEnd|flow.HasEventTime) | flowseg.ColReceived | extra
	if samp {
		c |= flowseg.ColSampling
	}
	if st {
		c |= flowseg.ColStatus
	}
	if dom {
		c |= flowseg.ColDomain
	}
	return c
}

// scanFn handles one matching record of block b (the worker's own state
// is w).
type scanFn func(w int, b *planned, row int, r *flow.Record)

// preFn, when a scan has one, sees each row of a block (not raw sets) in
// the window, with its effective end, before its record is filled; false
// skips the row. With an empty filter the record is then filled only for the
// rows it passes (a search page's, which keeps few of the rows it reads).
type preFn func(w int, b *planned, row int, end int64) bool

// scan reads blocks [lo, hi) of p with the workers, calling fn for every
// record that passes f and overlaps the window. It stops early when ctx is
// done. It returns the number of records read (rows of blocks decoded or
// ruled out by the index).
func (e *Engine) scan(ctx context.Context, p *plan, rd *readers, blocks []planned, f *Filter, cols flowseg.Cols, fn scanFn) error {
	return e.scanPre(ctx, p, rd, blocks, f, cols, nil, fn)
}

// scanPre is scan with a preFn (nil: none).
func (e *Engine) scanPre(ctx context.Context, p *plan, rd *readers, blocks []planned, f *Filter, cols flowseg.Cols, pre preFn,
	fn scanFn) error {
	if len(blocks) == 0 {
		return nil
	}
	useIndex := !f.Empty()
	// The workers' buffers are the engine's, shared with other queries: wait
	// for one, take any others free.
	var got []*slot
	select {
	case sl := <-e.slots:
		got = append(got, sl)
	case <-ctx.Done():
		return ctx.Err()
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
	jobs := make(chan *planned)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	for w := range got {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			blk, rec := &got[w].blk, &got[w].rec
			for b := range jobs {
				e.scanBlock(p, rd, b, w, blk, rec, useIndex, f, cols, pre, fn, &errMu, &firstErr)
				rd.done(b.seg)
			}
		}(w)
	}
	for i := range blocks {
		if ctx.Err() != nil {
			break
		}
		jobs <- &blocks[i]
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		e.o.Logger.Warn("flows: a block couldn't be read; skipped", "err", firstErr)
	}
	return ctx.Err()
}

// scanBlock reads one planned block for a scan's worker w.
func (e *Engine) scanBlock(p *plan, rd *readers, b *planned, w int, blk *flowseg.Block, rec *flow.Record, useIndex bool,
	f *Filter, cols flowseg.Cols, pre preFn, fn scanFn, errMu *sync.Mutex, firstErr *error) {
	fail := func(err error) {
		errMu.Lock()
		if *firstErr == nil {
			*firstErr = err
		}
		errMu.Unlock()
	}
	r, err := rd.get(b.seg)
	if err == nil && b.raw {
		err = rawRecords(r, e.ruleIEs(), func(i int, rec *flow.Record) {
			s, en := flowseg.EffectiveTimes(rec)
			if en >= p.from && s < p.to && f.Match(rec) {
				fn(w, b, -1-i, rec)
			}
		})
		if err != nil {
			fail(fmt.Errorf("flows: %s raw sets: %w", p.segs[b.seg].Rel, err))
		}
		return
	}
	if err == nil && useIndex {
		var info *flowseg.BlockInfo
		if info, err = r.Block(b.block); err == nil && !f.BlockMay(info) {
			return
		}
	}
	if err == nil {
		err = r.Decode(b.block, cols, blk)
	}
	if err != nil {
		fail(fmt.Errorf("flows: %s block %d: %w", p.segs[b.seg].Rel, b.block, err))
		return
	}
	if pre != nil && f.Empty() {
		for row := 0; row < blk.Rows; row++ {
			s, en := blk.EffectiveTimes(row)
			if en < p.from || s >= p.to || !pre(w, b, row, en) {
				continue
			}
			blk.Record(row, rec)
			fn(w, b, row, rec)
		}
		return
	}
	for row := 0; row < blk.Rows; row++ {
		blk.Record(row, rec)
		s, en := flowseg.EffectiveTimes(rec)
		if en < p.from || s >= p.to || !f.Match(rec) || (pre != nil && !pre(w, b, row, en)) {
			continue
		}
		fn(w, b, row, rec)
	}
}

// wave is how many blocks are read between budget checks.
func (e *Engine) wave() int { return max(e.o.Workers*waveBlocksPerW, 4) }

// ---- states (cursors) ----

type state struct {
	id       string
	key      string
	used     time.Time // for StateTTL
	seq      uint64    // e.saves when saved: the LRU order
	plan     *plan
	done     int // blocks done
	recsDone int64
	agg      aggregator // a top-N's
	total    Sums
	sum      *summaryAcc
	mu       sync.Mutex
}

// free returns a state's pool bytes.
func (st *state) free() {
	if st.plan != nil {
		st.plan.release()
	}
	if st.agg != nil {
		st.agg.free()
	}
	if st.sum != nil {
		st.sum.free()
	}
}

// evictOne drops the least recently used saved state (the pool's full
// hook), a search page's continuation before a top-N's or a summary's, and
// reports whether there was one.
func (e *Engine) evictOne() bool {
	if e.evictPage() {
		return true // a page continuation first: its page can be read from the cursor alone
	}
	e.mu.Lock()
	var old *state
	for _, s := range e.states {
		if old == nil || s.seq < old.seq {
			old = s
		}
	}
	if old != nil {
		delete(e.states, old.id)
	}
	e.mu.Unlock()
	if old == nil {
		return false
	}
	old.free()
	return true
}

func (e *Engine) newState(key string, p *plan) *state {
	b := make([]byte, 12)
	rand.Read(b)
	return &state{id: "fq_" + hex.EncodeToString(b), key: key, plan: p}
}

func (e *Engine) saveState(st *state) {
	var gone []*state
	defer func() {
		for _, s := range gone {
			s.free()
		}
	}()
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.o.Clock()
	e.saves++
	st.used, st.seq = now, e.saves
	for id, s := range e.states {
		if now.Sub(s.used) > StateTTL {
			delete(e.states, id)
			gone = append(gone, s)
		}
	}
	e.states[st.id] = st
	for len(e.states) > MaxStates {
		var old *state
		for _, s := range e.states {
			if old == nil || s.seq < old.seq {
				old = s
			}
		}
		delete(e.states, old.id)
		gone = append(gone, old)
	}
}

func (e *Engine) takeState(cursor, key string) (*state, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.states[cursor]
	if st == nil || e.o.Clock().Sub(st.used) > StateTTL {
		delete(e.states, cursor)
		if st != nil {
			go st.free() // not under e.mu
		}
		return nil, ErrExpired
	}
	if st.key != key {
		return nil, ErrCursor
	}
	delete(e.states, cursor)
	return st, nil
}

// ---- top-N ----

// TopResult is a top-N answer.
type TopResult struct {
	Rows  []Row
	Total Sums
	// ZeroOmitted counts the keys with none of the metric, which are never
	// rows (SPEC §13.3); Total still counts their records.
	ZeroOmitted int64
	Approx      bool
	// ErrorBound: a key in neither table has at most this of the metric (0
	// while exact); any key not in Rows has at most the larger of it and the
	// last row's. Each approximate row has its own Err.
	ErrorBound int64
	Progress   Progress
	Partial    bool
	Cursor     string
}

// Top ranks the window's records by by and metric, within budget.
func (e *Engine) Top(ctx context.Context, q Query, by, metric string, n int, budget time.Duration, cursor string) (TopResult, error) {
	key := q.key("top", by, metric)
	var st *state
	if cursor != "" {
		var err error
		if st, err = e.takeState(cursor, key); err != nil {
			return TopResult{}, err
		}
	} else {
		if !contains(ByKeys, by) {
			return TopResult{}, fmt.Errorf("by: %q isn't one of %v", by, ByKeys)
		}
		if !contains(Metrics, metric) {
			return TopResult{}, fmt.Errorf("metric: %q isn't one of %v", metric, Metrics)
		}
		p, err := e.planFor(ctx, &q, false)
		if err != nil {
			return TopResult{}, err
		}
		st = e.newState(key, p)
		st.agg = newAggregator(by, metric, aggOptions{maxKeys: e.o.MaxExactKeys, pool: e.pool, size: querySize})
	}
	saved := false
	defer func() {
		if !saved {
			st.free()
		}
	}()
	f := q.filter()
	cols := colsFor(f, flowseg.Cols(KeyCols(by)|CounterCols)|flowseg.ColSampling)
	// The workers share the state's one table (agg.go): each combines repeated
	// keys locally and hands them over in batches, flushed before reading.
	conv := by == "conversation"
	locals := make([]local, e.o.Workers)
	totals := make([]Sums, e.o.Workers)
	for i := range locals {
		locals[i] = st.agg.newLocal()
	}
	add := func(w int, _ *planned, _ int, r *flow.Record) {
		totals[w].add(r, conv)
		locals[w].add(r)
	}
	deadline := time.Now().Add(budget)
	rd := newReaders(st.plan)
	defer rd.close()
	// At least one wave per request, so a continuation always progresses.
	for first := true; st.plan.more(ctx) && (first || time.Now().Before(deadline)); first = false {
		blocks := st.plan.take(ctx, rd, e.wave())
		if len(blocks) == 0 {
			break
		}
		// A wave, once started, finishes (only the client's cancel stops it),
		// so the counts always cover whole blocks.
		if err := e.scan(ctx, st.plan, rd, blocks, f, cols, add); err != nil {
			return TopResult{}, err
		}
		e.gcNudge()
		for _, b := range blocks {
			st.recsDone += int64(b.rows)
		}
		st.done += len(blocks)
	}
	if err := st.plan.err; err != nil {
		return TopResult{}, err
	}
	for i := range locals {
		locals[i].flush()
		st.total.merge(&totals[i])
	}
	rows, zero := st.agg.rows(n)
	res := TopResult{Rows: rows, Total: st.total, ZeroOmitted: zero, Approx: st.agg.approx(), ErrorBound: st.agg.errorBound(),
		Progress: st.plan.progress(ctx, int64(st.done), st.recsDone)}
	if st.plan.more(ctx) {
		res.Partial = true
		saved = true
		e.saveState(st)
		res.Cursor = st.id
	}
	return res, nil
}

// ---- search ----

// Hit is one search result.
type Hit struct {
	DeviceID string
	Rel      string
	Block    int
	Row      int
	Record   flow.Record

	// src is the hit's segment while a search page still has to fill its
	// record (it was read with the page's key and filter columns only).
	src *segRef
}

// Ref is a hit's opaque reference.
func (h *Hit) Ref() string { return string(h.AppendRef(nil)) }

// AppendRef appends h.Ref() to dst.
func (h *Hit) AppendRef(dst []byte) []byte {
	var raw [96]byte
	b := append(raw[:0], h.Rel...)
	b = append(b, '|')
	b = strconv.AppendInt(b, int64(h.Block), 10)
	b = append(b, '|')
	b = strconv.AppendInt(b, int64(h.Row), 10)
	return base64.RawURLEncoding.AppendEncode(dst, b)
}

// order key: (end, then dev, rel, block, row) — descending end first.
type hitKey struct {
	End        int64
	Dev, Rel   string
	Block, Row int
}

func keyOfHit(h *Hit) hitKey {
	_, en := flowseg.EffectiveTimes(&h.Record)
	return hitKey{End: en, Dev: h.DeviceID, Rel: h.Rel, Block: h.Block, Row: h.Row}
}

// before reports whether a comes before b in the result order.
func (a hitKey) before(b hitKey, asc bool) bool {
	if a.End != b.End {
		if asc {
			return a.End < b.End
		}
		return a.End > b.End
	}
	if c := cmp.Compare(a.Dev, b.Dev); c != 0 {
		return c < 0
	}
	if c := cmp.Compare(a.Rel, b.Rel); c != 0 {
		return c < 0
	}
	if a.Block != b.Block {
		return a.Block < b.Block
	}
	return a.Row < b.Row
}

// hitHeap keeps the best limit hits; its root is the worst kept.
type hitHeap struct {
	h   []*Hit
	k   []hitKey
	asc bool
}

func (h *hitHeap) Len() int           { return len(h.h) }
func (h *hitHeap) Less(i, j int) bool { return h.k[j].before(h.k[i], h.asc) }
func (h *hitHeap) Swap(i, j int)      { h.h[i], h.h[j] = h.h[j], h.h[i]; h.k[i], h.k[j] = h.k[j], h.k[i] }
func (h *hitHeap) Push(x any)         { p := x.(pair); h.h = append(h.h, p.h); h.k = append(h.k, p.k) }
func (h *hitHeap) Pop() any {
	n := len(h.h) - 1
	p := pair{h.h[n], h.k[n]}
	h.h, h.k = h.h[:n], h.k[:n]
	return p
}

type pair struct {
	h *Hit
	k hitKey
}

// SearchResult is a page of hits.
type SearchResult struct {
	Hits     []Hit
	Cursor   string // "" when the window is exhausted
	Partial  bool
	Progress Progress
}

// searchCursor resumes after a key.
type searchCursor struct {
	Key   hitKey `json:"k"`
	Query string `json:"q"`
	From  int64  `json:"f,omitempty"` // the first page's range (unix ms)
	To    int64  `json:"t,omitempty"`
}

// searchStateless is a page of Search from the cursor's values alone: up
// to limit records, newest first by flow end (asc: oldest first), after
// cursor. Search continues a page's saved stream instead when it has one
// (pages.go); this is the page when it can't.
//
// A page reads in two passes (see search), so a segment retention deletes
// between them would leave its hits out: the page is then read again, once,
// without it (a second miss drops them, as an unreadable block's are). A
// cancel during the second pass loses the page, as one during the first does.
func (e *Engine) searchStateless(ctx context.Context, q Query, limit int, asc bool, cursor string, budget time.Duration) (SearchResult, error) {
	res, err := e.search(ctx, q, limit, asc, cursor, budget, false)
	if errors.Is(err, errRefill) {
		res, err = e.search(ctx, q, limit, asc, cursor, budget, true)
	}
	return res, err
}

// errRefill is a second pass that couldn't read a block of the first's.
var errRefill = errors.New("flows: a block of the page is gone")

// search is one try at a page; final drops the hits of a block the second
// pass can't read, else that's errRefill.
func (e *Engine) search(ctx context.Context, q Query, limit int, asc bool, cursor string, budget time.Duration,
	final bool) (SearchResult, error) {
	qk := q.key("search", asc)
	after, err := parseCursor(&q, qk, cursor)
	if err != nil {
		return SearchResult{}, err
	}
	p, err := e.planOrdered(ctx, &q, asc)
	if err != nil {
		return SearchResult{}, err
	}
	defer p.release()
	p.skipBefore(after)
	f := q.filter()
	// Two passes: the page's blocks are read with the columns that order
	// and filter them (a page reads several times the rows it keeps), and
	// only the blocks holding the hits it returns are read again in full.
	cols := colsFor(f, 0)
	h := &hitHeap{asc: asc}
	local := make([]*hitHeap, e.o.Workers)
	for i := range local {
		local[i] = &hitHeap{asc: asc}
	}
	deadline := time.Now().Add(budget)
	rd := newReaders(p)
	defer rd.close()
	done := 0
	var recs int64
	certain := func() bool { // the page can't change: nothing unread can beat the worst kept
		b, more := p.bound(ctx)
		if !more || h.Len() < limit {
			return !more
		}
		w := h.k[0].End
		if asc {
			return b > w
		}
		return b < w
	}
	// Past the budget, a page still reads until the bound of what's unread
	// passes the cursor it started from (else a partial page's cursor, that
	// bound, could repeat: the next unloaded segment's end bounds it, and
	// several exporters' segments end alike).
	progressed := func() bool {
		b, more := p.bound(ctx)
		switch {
		case !more:
			return true
		case after == nil && asc:
			return b > math.MinInt64
		case after == nil:
			return b < math.MaxInt64
		case asc:
			return b > after.End+1
		}
		return b < after.End-1
	}
	for first := true; !certain() && (first || time.Now().Before(deadline) || !progressed()); first = false {
		blocks := p.take(ctx, rd, e.wave())
		if len(blocks) == 0 {
			break
		}
		// Each worker keeps its own best limit hits (no lock, and a Hit only
		// for a row that makes its cut: most rows a page reads don't), merged
		// after the wave. h isn't written while the wave runs, so the workers
		// also compare against what's already kept.
		full := h.Len() >= limit
		var worst hitKey
		if full {
			worst = h.k[0]
		}
		// keep reports whether a row with key k makes worker w's cut.
		keep := func(w int, k *hitKey) bool {
			if (after != nil && !after.before(*k, asc)) || (full && !k.before(worst, asc)) {
				return false
			}
			lh := local[w]
			return lh.Len() < limit || k.before(lh.k[0], asc)
		}
		// The wave's segments, for the second pass (a batch's p.segs are
		// reused when the next loads).
		srcs := map[int]*segRef{}
		for _, b := range blocks {
			if !b.raw && srcs[b.seg] == nil {
				ref := p.segs[b.seg]
				srcs[b.seg] = &ref
			}
		}
		pre := func(w int, b *planned, row int, end int64) bool {
			seg := &p.segs[b.seg]
			return keep(w, &hitKey{End: end, Dev: seg.DeviceID, Rel: seg.Rel, Block: b.block, Row: row})
		}
		err := e.scanPre(ctx, p, rd, blocks, f, cols, pre, func(w int, b *planned, row int, r *flow.Record) {
			_, en := flowseg.EffectiveTimes(r)
			seg := &p.segs[b.seg]
			k := hitKey{End: en, Dev: seg.DeviceID, Rel: seg.Rel, Block: b.block, Row: row}
			if !keep(w, &k) {
				return // a raw set's (pre has seen the rest)
			}
			lh := local[w]
			hit := &Hit{DeviceID: seg.DeviceID, Rel: seg.Rel, Block: b.block, Row: row, Record: *r}
			if !b.raw {
				hit.src = srcs[b.seg] // a raw set's record is whole already
			}
			if lh.Len() < limit {
				heap.Push(lh, pair{hit, k})
			} else {
				lh.h[0], lh.k[0] = hit, k
				heap.Fix(lh, 0)
			}
		})
		if err != nil && ctx.Err() != nil {
			return SearchResult{}, ctx.Err()
		}
		for _, lh := range local {
			for i := range lh.h {
				hit, k := lh.h[i], lh.k[i]
				if h.Len() < limit {
					heap.Push(h, pair{hit, k})
				} else if k.before(h.k[0], asc) {
					h.h[0], h.k[0] = hit, k
					heap.Fix(h, 0)
				}
			}
			clear(lh.h)
			lh.h, lh.k = lh.h[:0], lh.k[:0]
		}
		for _, b := range blocks {
			recs += int64(b.rows)
		}
		done += len(blocks)
	}
	if p.err != nil {
		return SearchResult{}, p.err
	}
	ps := make([]pair, h.Len())
	for i := range ps {
		ps[i] = pair{h.h[i], h.k[i]}
	}
	slices.SortFunc(ps, func(a, b pair) int {
		if a.k.before(b.k, asc) {
			return -1
		}
		return 1
	})
	res := SearchResult{Progress: p.progress(ctx, int64(done), recs)}
	bound, more := p.bound(ctx) // hits strictly beyond it are certain: nothing unread can beat them
	complete := !more
	for _, x := range ps {
		if !complete && ((!asc && x.k.End <= bound) || (asc && x.k.End >= bound)) {
			break
		}
		res.Hits = append(res.Hits, *x.h)
	}
	switch {
	case complete && len(ps) < limit:
		// The window is exhausted.
	case len(res.Hits) == limit:
		res.Cursor = encodeCursor(keyOfHit(&res.Hits[len(res.Hits)-1]), qk, &q)
	default:
		// Out of budget: what's certain, and a cursor past every block read.
		res.Partial = true
		var k hitKey
		switch {
		case len(res.Hits) > 0:
			k = keyOfHit(&res.Hits[len(res.Hits)-1])
		case asc:
			k = hitKey{End: max(bound, math.MinInt64+1) - 1, Dev: "\U0010ffff"}
		default:
			k = hitKey{End: min(bound, math.MaxInt64-1) + 1, Dev: "\U0010ffff"}
		}
		res.Cursor = encodeCursor(k, qk, &q)
	}
	if err := e.fill(ctx, &res, final); err != nil {
		return SearchResult{}, err
	}
	return res, nil
}

// fill reads the blocks holding a page's hits again with every column and
// fills their records (the second pass). A block that can no longer be read
// (retention deleted its segment since) is errRefill, or with final drops
// its hits, as an unreadable block's are skipped. The hits' extras are
// copied into the page's own buffers: a decoded block's extras share a
// copy of the whole column, which a page holding one row of each of many
// blocks would otherwise keep alive (about 230 KiB a hit).
func (e *Engine) fill(ctx context.Context, res *SearchResult, final bool) error {
	if e.fillHook != nil {
		e.fillHook()
	}
	type blockKey struct {
		src   *segRef
		block int
	}
	groups := map[blockKey][]int{}
	var order []blockKey
	for i := range res.Hits {
		h := &res.Hits[i]
		if h.src == nil {
			continue
		}
		k := blockKey{h.src, h.Block}
		if groups[k] == nil {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	if len(order) == 0 {
		return nil
	}
	var got []*slot
	select {
	case sl := <-e.slots:
		got = append(got, sl)
	case <-ctx.Done():
		return ctx.Err()
	}
more:
	for len(got) < min(e.o.Workers, len(order)) {
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
	// One reader per segment, opened once; each worker takes whole blocks.
	var mu sync.Mutex
	rds := map[*segRef]*flowseg.Reader{}
	failed := map[*segRef]error{}
	open := func(s *segRef) (*flowseg.Reader, error) {
		mu.Lock()
		defer mu.Unlock()
		if r := rds[s]; r != nil {
			return r, nil
		}
		if err := failed[s]; err != nil {
			return nil, err
		}
		var r *flowseg.Reader
		var err error
		switch {
		case s.snap != nil:
			r, err = flowseg.OpenSnapshot(s.Path, s.snap)
		case s.live:
			r, err = flowseg.OpenLive(s.Path)
		default:
			r, err = openSegForFill(s.Path)
		}
		if err != nil {
			failed[s] = err
			return nil, err
		}
		rds[s] = r
		return r, nil
	}
	defer func() {
		for _, r := range rds {
			r.Close()
		}
	}()
	drop := make([]bool, len(res.Hits))
	var next atomic.Int64
	var wg sync.WaitGroup
	var errMu sync.Mutex
	var firstErr error
	for w := range got {
		wg.Add(1)
		go func(sl *slot) {
			defer wg.Done()
			for {
				i := int(next.Add(1) - 1)
				if i >= len(order) || ctx.Err() != nil {
					return
				}
				k := order[i]
				r, err := open(k.src)
				if err == nil {
					err = r.Decode(k.block, flowseg.ColAll, &sl.blk)
				}
				for _, j := range groups[k] {
					h := &res.Hits[j]
					if err != nil {
						drop[j] = true
						continue
					}
					sl.blk.Record(h.Row, &h.Record)
				}
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("flows: %s block %d: %w", k.src.Rel, k.block, err)
					}
					errMu.Unlock()
				}
			}
		}(got[w])
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if firstErr != nil {
		if !final {
			return errRefill
		}
		e.o.Logger.Warn("flows: a block couldn't be read again; its hits are left out", "err", firstErr)
	}
	out := res.Hits[:0]
	for i := range res.Hits {
		res.Hits[i].src = nil
		if !drop[i] {
			out = append(out, res.Hits[i])
		}
	}
	res.Hits = out
	ownExtras(res.Hits)
	return nil
}

// ownExtras copies the hits' extras (lists and values) into two buffers of
// the page's own, keeping nil and empty lists and values as they are.
func ownExtras(hits []Hit) {
	var nx, nv int
	for i := range hits {
		for _, x := range hits[i].Record.Extras {
			nx++
			nv += len(x.Value)
		}
	}
	if nx == 0 {
		return
	}
	xs := make([]flow.Extra, 0, nx)
	vals := make([]byte, 0, nv)
	for i := range hits {
		r := &hits[i].Record
		if len(r.Extras) == 0 {
			continue // nil or empty: no shared memory
		}
		o := len(xs)
		for _, x := range r.Extras {
			if len(x.Value) > 0 {
				v := len(vals)
				vals = append(vals, x.Value...)
				x.Value = vals[v:len(vals):len(vals)]
			}
			xs = append(xs, x)
		}
		r.Extras = xs[o:len(xs):len(xs)]
	}
}

// openSegForFill opens a closed segment, or one another process has been
// writing (read up to its last complete block), as the plan's first read did.
func openSegForFill(path string) (*flowseg.Reader, error) {
	r, _, err := openSeg(path)
	return r, err
}

// parseCursor is a page cursor's key (nil without one), checked against
// the query's key qk; with the default range the query takes the first
// page's range from it.
func parseCursor(q *Query, qk, cursor string) (*hitKey, error) {
	if cursor == "" {
		return nil, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(cursor)
	var c searchCursor
	if err != nil || json.Unmarshal(b, &c) != nil || c.Query != hash(qk) {
		return nil, ErrCursor
	}
	if q.DefaultRange && c.To != 0 {
		q.From, q.To = time.UnixMilli(c.From).UTC(), time.UnixMilli(c.To).UTC()
	}
	return &c.Key, nil
}

// skipBefore skips the segments and blocks wholly before a page's cursor
// key (nil: none).
func (p *plan) skipBefore(after *hitKey) {
	if after == nil {
		return
	}
	asc := p.asc
	p.skip = func(b *planned) bool { return (!asc && b.minEnd > after.End) || (asc && b.maxEnd < after.End) }
	p.skipSeg = func(s *segRef) bool {
		return !s.open && !s.wide && ((!asc && s.start > after.End) || (asc && s.end < after.End))
	}
}

func encodeCursor(k hitKey, qk string, q *Query) string {
	b, _ := json.Marshal(searchCursor{Key: k, Query: hash(qk), From: q.From.UnixMilli(), To: q.To.UnixMilli()})
	return base64.RawURLEncoding.EncodeToString(b)
}

func hash(s string) string {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

// ---- every record (export) ----

// Each calls fn with every record in the window that passes the filter, one
// device at a time (deviceIDs order, or by device ID), oldest first by flow end
// within each segment's block order. It reads every column.
func (e *Engine) Each(ctx context.Context, q Query, fn func(deviceID string, r *flow.Record) error) error {
	devs, err := e.flowDevices(ctx, &q)
	if err != nil {
		return err
	}
	f := q.filter()
	var blk flowseg.Block
	var rec flow.Record
	for _, dev := range devs {
		qd := q
		qd.DeviceIDs = []string{dev}
		p, err := e.planFor(ctx, &qd, true)
		if err != nil {
			return err
		}
		rd := newReaders(p)
		one := func(b *planned) error {
			defer rd.done(b.seg)
			if err := ctx.Err(); err != nil {
				return err
			}
			r, err := rd.get(b.seg)
			if err != nil {
				return nil
			}
			if b.raw {
				var ferr error
				rerr := rawRecords(r, e.ruleIEs(), func(_ int, rec *flow.Record) {
					s, en := flowseg.EffectiveTimes(rec)
					if ferr == nil && en >= p.from && s < p.to && f.Match(rec) {
						ferr = fn(dev, rec)
					}
				})
				if rerr != nil {
					e.o.Logger.Warn("flows: raw sets couldn't be read", "file", p.segs[b.seg].Rel, "err", rerr)
				}
				return ferr
			}
			if err := r.Decode(b.block, flowseg.ColAll, &blk); err != nil {
				e.o.Logger.Warn("flows: a block couldn't be read; skipped", "file", p.segs[b.seg].Rel, "block", b.block, "err", err)
				return nil
			}
			for row := 0; row < blk.Rows; row++ {
				blk.Record(row, &rec)
				s, en := flowseg.EffectiveTimes(&rec)
				if en < p.from || s >= p.to || !f.Match(&rec) {
					continue
				}
				if err := fn(dev, &rec); err != nil {
					return err
				}
			}
			return nil
		}
		for p.more(ctx) {
			blocks := p.take(ctx, rd, e.batchBlocks())
			if len(blocks) == 0 {
				break
			}
			for i := range blocks {
				if err := one(&blocks[i]); err != nil {
					rd.close()
					p.release()
					return err
				}
			}
		}
		rd.close()
		p.release()
		if p.err != nil {
			return p.err
		}
	}
	return nil
}

// flowDevices is the devices with flows in q's window (q's, or every one),
// sorted: the index's and those with an open segment.
func (e *Engine) flowDevices(ctx context.Context, q *Query) ([]string, error) {
	ids, err := e.o.Index.FlowDevices(ctx, q.DeviceIDs, q.From, q.To)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if e.o.Open != nil {
		want := map[string]bool{}
		for _, d := range q.DeviceIDs {
			want[d] = true
		}
		for _, os := range e.o.Open(q.DeviceIDs) {
			if !seen[os.DeviceID] && (q.DeviceIDs == nil || want[os.DeviceID]) {
				seen[os.DeviceID] = true
				ids = append(ids, os.DeviceID)
			}
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Count is the number of records Each would give (by reading the counted
// columns only), per device.
func (e *Engine) Count(ctx context.Context, q Query) (map[string]int64, error) {
	p, err := e.planFor(ctx, &q, false)
	if err != nil {
		return nil, err
	}
	defer p.release()
	f := q.filter()
	out := map[string]int64{}
	counts := make([]map[string]int64, e.o.Workers)
	for i := range counts {
		counts[i] = map[string]int64{}
	}
	rd := newReaders(p)
	defer rd.close()
	for p.more(ctx) {
		blocks := p.take(ctx, rd, e.batchBlocks())
		if len(blocks) == 0 {
			break
		}
		if f.Empty() {
			// Blocks wholly inside the window count without decoding.
			partial := blocks[:0]
			for _, b := range blocks {
				if !b.raw && b.minEnd >= p.from && b.maxStart < p.to {
					out[p.segs[b.seg].DeviceID] += int64(b.rows)
					rd.done(b.seg)
					continue
				}
				partial = append(partial, b)
			}
			blocks = partial
		}
		if err := e.scan(ctx, p, rd, blocks, f, colsFor(f, 0), func(w int, b *planned, _ int, _ *flow.Record) {
			counts[w][p.segs[b.seg].DeviceID]++
		}); err != nil {
			return nil, err
		}
	}
	if p.err != nil {
		return nil, p.err
	}
	for _, c := range counts {
		for k, v := range c {
			out[k] += v
		}
	}
	return out, nil
}

// Raw calls fn with the raw sets of the window's segments whose received
// time is in [from, to), for the devices.
func (e *Engine) Raw(ctx context.Context, q Query, fn func(deviceID string, rs *flow.RawSet) error) error {
	from, to := q.From.UnixMilli(), q.To.UnixMilli()
	for after := ""; ; {
		// A page of the window's segments at a time, so a bundle's raw.txt
		// doesn't hold every raw-holding segment's row.
		segs, err := e.o.Index.FlowSegmentsWithRaw(ctx, q.DeviceIDs, q.From, q.To, after, planPage)
		if err != nil {
			return err
		}
		for _, s := range segs {
			rd, _, err := openSeg(filepath.Join(e.o.DataDir, filepath.FromSlash(s.Path)))
			if err != nil {
				continue
			}
			var ferr error
			rd.Raw(func(rs *flow.RawSet) bool {
				if rs.Received < from || rs.Received >= to {
					return true
				}
				if ferr = fn(s.DeviceID, rs); ferr != nil {
					return false
				}
				return ctx.Err() == nil
			})
			rd.Close()
			if ferr != nil {
				return ferr
			}
		}
		if len(segs) < planPage || ctx.Err() != nil {
			return ctx.Err()
		}
		after = segs[len(segs)-1].Path
	}
}

// RuleIDIEs returns the rule IEs in effect.
func (e *Engine) RuleIDIEs() []flow.IEKey { return e.ruleIEs() }
