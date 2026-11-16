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
	"path/filepath"
	"runtime"
	"slices"
	"sort"
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
}

// Options configure an Engine.
type Options struct {
	DataDir string
	Index   *index.DB
	// Open returns the open segments of deviceIDs (nil: all).
	Open    func(deviceIDs []string) []OpenSegment
	Workers int // default GOMAXPROCS
	Clock   func() time.Time
	Logger  *slog.Logger
	// MaxExactKeys overrides DefaultExactKeys (tests).
	MaxExactKeys int
	// RuleIDIEs fill rule_id in raw sets decoded on read (as the collector does).
	RuleIDIEs []flow.IEKey
}

// Engine runs flow queries. Safe for concurrent use.
type Engine struct {
	o      Options
	mu     sync.Mutex
	states map[string]*state
	rules  atomic.Pointer[[]flow.IEKey] // RuleIDIEs in effect (SetRuleIDIEs)
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
		o.Workers = runtime.GOMAXPROCS(0)
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
	e := &Engine{o: o, states: map[string]*state{}}
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

type segRef struct {
	DeviceID, Rel, Path string
	snap                *flowseg.Footer // nil: a closed segment
	live                bool            // another process is writing it (OpenLive)
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
	segs   []segRef
	blocks []planned
	asc    bool
	from   int64
	to     int64
	rows   int64
}

// planFor lists the window's blocks, ordered.
func (e *Engine) planFor(ctx context.Context, q *Query, asc bool) (*plan, error) {
	rows, err := e.o.Index.FlowSegments(ctx, q.DeviceIDs, q.From, q.To)
	if err != nil {
		return nil, err
	}
	p := &plan{asc: asc, from: q.From.UnixMilli(), to: q.To.UnixMilli()}
	open := map[string]OpenSegment{}
	if e.o.Open != nil {
		for _, os := range e.o.Open(q.DeviceIDs) {
			open[os.Rel] = os
		}
	}
	seen := map[string]bool{}
	add := func(ref segRef, f *flowseg.Footer) {
		si := len(p.segs)
		p.segs = append(p.segs, ref)
		for i := range f.Blocks {
			b := &f.Blocks[i]
			if b.Rows == 0 || !b.Overlaps(p.from, p.to-1) {
				continue
			}
			p.blocks = append(p.blocks, planned{seg: si, block: i, rows: b.Rows, minStart: b.MinStart, maxStart: b.MaxStart,
				minEnd: b.MinEnd, maxEnd: b.MaxEnd})
			p.rows += int64(b.Rows)
		}
		if f.RawStatus[flow.StatusNoTemplate] > 0 || (f.Raw > 0 && f.RawStatus == [4]int64{}) {
			lo, hi := f.MinReceived-rawSpan.Milliseconds(), f.MaxReceived
			if hi >= p.from && lo < p.to {
				p.blocks = append(p.blocks, planned{seg: si, block: -1, raw: true, minStart: lo, maxStart: hi, minEnd: lo, maxEnd: hi})
			}
		}
	}
	for _, r := range rows {
		seen[r.Path] = true
		if os, ok := open[r.Path]; ok {
			add(segRef{DeviceID: os.DeviceID, Rel: os.Rel, Path: os.Path, snap: os.Footer}, os.Footer)
			continue
		}
		path := filepath.Join(e.o.DataDir, filepath.FromSlash(r.Path))
		rd, live, err := openSeg(path)
		if err != nil {
			continue // deleted by retention since
		}
		add(segRef{DeviceID: r.DeviceID, Rel: r.Path, Path: path, live: live}, rd.Footer())
		rd.Close()
	}
	for rel, os := range open {
		if !seen[rel] && os.Footer != nil && len(os.Footer.Blocks) > 0 {
			add(segRef{DeviceID: os.DeviceID, Rel: os.Rel, Path: os.Path, snap: os.Footer}, os.Footer)
		}
	}
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
	return p, nil
}

// frontier is complete_from after done blocks (descending plans): the max
// end of the next unread block, at least the window's start.
func (p *plan) frontier(done int) time.Time {
	if done >= len(p.blocks) {
		return time.UnixMilli(p.from).UTC()
	}
	return time.UnixMilli(max(p.blocks[done].maxEnd, p.from)).UTC()
}

// readers opens the segments a range of blocks needs, shared by the workers.
type readers struct {
	mu  sync.Mutex
	p   *plan
	rds map[int]*flowseg.Reader
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

// scan reads blocks [lo, hi) of p with the workers, calling fn for every
// record that passes f and overlaps the window. It stops early when ctx is
// done. It returns the number of records read (rows of blocks decoded or
// ruled out by the index).
func (e *Engine) scan(ctx context.Context, p *plan, rd *readers, lo, hi int, f *Filter, cols flowseg.Cols, fn scanFn) error {
	if lo >= hi {
		return nil
	}
	useIndex := !f.Empty()
	jobs := make(chan int)
	var wg sync.WaitGroup
	var firstErr error
	var errMu sync.Mutex
	workers := min(e.o.Workers, hi-lo)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			var blk flowseg.Block
			var rec flow.Record
			for bi := range jobs {
				b := &p.blocks[bi]
				r, err := rd.get(b.seg)
				if err == nil && b.raw {
					err = rawRecords(r, e.ruleIEs(), func(i int, rec *flow.Record) {
						s, en := flowseg.EffectiveTimes(rec)
						if en >= p.from && s < p.to && f.Match(rec) {
							fn(w, b, -1-i, rec)
						}
					})
					if err != nil {
						errMu.Lock()
						if firstErr == nil {
							firstErr = fmt.Errorf("flows: %s raw sets: %w", p.segs[b.seg].Rel, err)
						}
						errMu.Unlock()
					}
					continue
				}
				if err == nil && useIndex {
					var info *flowseg.BlockInfo
					if info, err = r.Block(b.block); err == nil && !f.BlockMay(info) {
						continue
					}
				}
				if err == nil {
					err = r.Decode(b.block, cols, &blk)
				}
				if err != nil {
					errMu.Lock()
					if firstErr == nil {
						firstErr = fmt.Errorf("flows: %s block %d: %w", p.segs[b.seg].Rel, b.block, err)
					}
					errMu.Unlock()
					continue
				}
				for row := 0; row < blk.Rows; row++ {
					blk.Record(row, &rec)
					s, en := flowseg.EffectiveTimes(&rec)
					if en < p.from || s >= p.to || !f.Match(&rec) {
						continue
					}
					fn(w, b, row, &rec)
				}
			}
		}(w)
	}
	for bi := lo; bi < hi; bi++ {
		if ctx.Err() != nil {
			break
		}
		jobs <- bi
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		e.o.Logger.Warn("flows: a block couldn't be read; skipped", "err", firstErr)
	}
	return ctx.Err()
}

// wave is how many blocks are read between budget checks.
func (e *Engine) wave() int { return max(e.o.Workers*waveBlocksPerW, 4) }

// ---- states (cursors) ----

type state struct {
	id       string
	key      string
	used     time.Time
	plan     *plan
	done     int // blocks done
	recsDone int64
	top      *Top
	sum      *summaryAcc
	mu       sync.Mutex
}

func (e *Engine) newState(key string, p *plan) *state {
	b := make([]byte, 12)
	rand.Read(b)
	return &state{id: "fq_" + hex.EncodeToString(b), key: key, plan: p}
}

func (e *Engine) saveState(st *state) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.o.Clock()
	st.used = now
	for id, s := range e.states {
		if now.Sub(s.used) > StateTTL {
			delete(e.states, id)
		}
	}
	e.states[st.id] = st
	for len(e.states) > MaxStates {
		var old *state
		for _, s := range e.states {
			if old == nil || s.used.Before(old.used) {
				old = s
			}
		}
		delete(e.states, old.id)
	}
}

func (e *Engine) takeState(cursor, key string) (*state, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.states[cursor]
	if st == nil || e.o.Clock().Sub(st.used) > StateTTL {
		delete(e.states, cursor)
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
	Rows     []Row
	Total    Sums
	Approx   bool
	Progress Progress
	Partial  bool
	Cursor   string
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
		p, err := e.planFor(ctx, &q, false)
		if err != nil {
			return TopResult{}, err
		}
		top, err := NewTop(by, metric)
		if err != nil {
			return TopResult{}, err
		}
		top.MaxExact = e.o.MaxExactKeys
		st = e.newState(key, p)
		st.top = top
	}
	f := q.filter()
	cols := colsFor(f, flowseg.Cols(KeyCols(by)|CounterCols)|flowseg.ColSampling)
	tops := make([]*Top, e.o.Workers)
	deadline := time.Now().Add(budget)
	rd := &readers{p: st.plan}
	defer rd.close()
	// At least one wave per request, so a continuation always progresses.
	for first := true; st.done < len(st.plan.blocks) && (first || time.Now().Before(deadline)); first = false {
		hi := min(st.done+e.wave(), len(st.plan.blocks))
		for i := range tops {
			tops[i], _ = NewTop(by, metric)
			tops[i].MaxExact = e.o.MaxExactKeys
		}
		// A wave, once started, finishes (only the client's cancel stops it),
		// so the counts always cover whole blocks.
		if err := e.scan(ctx, st.plan, rd, st.done, hi, f, cols, func(w int, _ *planned, _ int, r *flow.Record) { tops[w].Add(r) }); err != nil {
			return TopResult{}, err
		}
		for _, t := range tops {
			st.top.Merge(t)
		}
		for _, b := range st.plan.blocks[st.done:hi] {
			st.recsDone += int64(b.rows)
		}
		st.done = hi
	}
	res := TopResult{Rows: st.top.Rows(n), Total: st.top.Total, Approx: st.top.Approx(),
		Progress: Progress{BlocksDone: int64(st.done), BlocksTotal: int64(len(st.plan.blocks)), RecordsDone: st.recsDone,
			RecordsTotal: st.plan.rows, CompleteFrom: st.plan.frontier(st.done)}}
	if st.done < len(st.plan.blocks) {
		res.Partial = true
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
}

// Ref is a hit's opaque reference.
func (h *Hit) Ref() string {
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%d|%d", h.Rel, h.Block, h.Row)))
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

// Search returns up to limit records, newest first by flow end (asc: oldest
// first), after cursor.
func (e *Engine) Search(ctx context.Context, q Query, limit int, asc bool, cursor string, budget time.Duration) (SearchResult, error) {
	qk := q.key("search", asc)
	var after *hitKey
	if cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(cursor)
		var c searchCursor
		if err != nil || json.Unmarshal(b, &c) != nil || c.Query != hash(qk) {
			return SearchResult{}, ErrCursor
		}
		after = &c.Key
		if q.DefaultRange && c.To != 0 {
			q.From, q.To = time.UnixMilli(c.From).UTC(), time.UnixMilli(c.To).UTC()
		}
	}
	p, err := e.planFor(ctx, &q, asc)
	if err != nil {
		return SearchResult{}, err
	}
	// Skip blocks wholly before the cursor.
	if after != nil {
		kept := p.blocks[:0]
		for _, b := range p.blocks {
			if (!asc && b.minEnd > after.End) || (asc && b.maxEnd < after.End) {
				p.rows -= int64(b.rows)
				continue
			}
			kept = append(kept, b)
		}
		p.blocks = kept
	}
	f := q.filter()
	cols := colsFor(f, flowseg.ColAll)
	h := &hitHeap{asc: asc}
	var mu sync.Mutex
	deadline := time.Now().Add(budget)
	rd := &readers{p: p}
	defer rd.close()
	done := 0
	var recs int64
	certain := func() bool { // the page can't change: the next block can't beat the worst kept
		if h.Len() < limit || done >= len(p.blocks) {
			return done >= len(p.blocks)
		}
		nb := p.blocks[done]
		w := h.k[0].End
		if asc {
			return nb.minEnd > w
		}
		return nb.maxEnd < w
	}
	for first := true; !certain() && (first || time.Now().Before(deadline)); first = false {
		hi := min(done+e.wave(), len(p.blocks))
		err := e.scan(ctx, p, rd, done, hi, f, cols, func(_ int, b *planned, row int, r *flow.Record) {
			hit := &Hit{DeviceID: p.segs[b.seg].DeviceID, Rel: p.segs[b.seg].Rel, Block: b.block, Row: row, Record: *r}
			k := keyOfHit(hit)
			if after != nil && !after.before(k, asc) {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if h.Len() < limit {
				heap.Push(h, pair{hit, k})
			} else if k.before(h.k[0], asc) {
				h.h[0], h.k[0] = hit, k
				heap.Fix(h, 0)
			}
		})
		if err != nil && ctx.Err() != nil {
			return SearchResult{}, ctx.Err()
		}
		for _, b := range p.blocks[done:hi] {
			recs += int64(b.rows)
		}
		done = hi
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
	res := SearchResult{Progress: Progress{BlocksDone: int64(done), BlocksTotal: int64(len(p.blocks)), RecordsDone: recs,
		RecordsTotal: p.rows, CompleteFrom: p.frontier(done)}}
	complete := done >= len(p.blocks)
	var bound int64 // hits strictly beyond it are certain: no unread block can beat them
	if !complete {
		bound = p.blocks[done].maxEnd
		if asc {
			bound = p.blocks[done].minEnd
		}
	}
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
			k = hitKey{End: bound - 1, Dev: "\U0010ffff"}
		default:
			k = hitKey{End: bound + 1, Dev: "\U0010ffff"}
		}
		res.Cursor = encodeCursor(k, qk, &q)
	}
	return res, nil
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
	p, err := e.planFor(ctx, &q, true)
	if err != nil {
		return err
	}
	sort.SliceStable(p.blocks, func(i, j int) bool {
		a, b := p.segs[p.blocks[i].seg], p.segs[p.blocks[j].seg]
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		return false
	})
	f := q.filter()
	rd := &readers{p: p}
	defer rd.close()
	var blk flowseg.Block
	var rec flow.Record
	for _, b := range p.blocks {
		if err := ctx.Err(); err != nil {
			return err
		}
		r, err := rd.get(b.seg)
		if err != nil {
			continue
		}
		if b.raw {
			var ferr error
			rerr := rawRecords(r, e.ruleIEs(), func(_ int, rec *flow.Record) {
				s, en := flowseg.EffectiveTimes(rec)
				if ferr == nil && en >= p.from && s < p.to && f.Match(rec) {
					ferr = fn(p.segs[b.seg].DeviceID, rec)
				}
			})
			if ferr != nil {
				return ferr
			}
			if rerr != nil {
				e.o.Logger.Warn("flows: raw sets couldn't be read", "file", p.segs[b.seg].Rel, "err", rerr)
			}
			continue
		}
		if err := r.Decode(b.block, flowseg.ColAll, &blk); err != nil {
			e.o.Logger.Warn("flows: a block couldn't be read; skipped", "file", p.segs[b.seg].Rel, "block", b.block, "err", err)
			continue
		}
		for row := 0; row < blk.Rows; row++ {
			blk.Record(row, &rec)
			s, en := flowseg.EffectiveTimes(&rec)
			if en < p.from || s >= p.to || !f.Match(&rec) {
				continue
			}
			if err := fn(p.segs[b.seg].DeviceID, &rec); err != nil {
				return err
			}
		}
	}
	return nil
}

// Count is the number of records Each would give (by reading the counted
// columns only), per device.
func (e *Engine) Count(ctx context.Context, q Query) (map[string]int64, error) {
	p, err := e.planFor(ctx, &q, false)
	if err != nil {
		return nil, err
	}
	f := q.filter()
	out := map[string]int64{}
	if f.Empty() {
		// Blocks wholly inside the window count without decoding.
		var partial []planned
		for _, b := range p.blocks {
			if !b.raw && b.minEnd >= p.from && b.maxStart < p.to {
				out[p.segs[b.seg].DeviceID] += int64(b.rows)
				continue
			}
			partial = append(partial, b)
		}
		p.blocks = partial
	}
	counts := make([]map[string]int64, e.o.Workers)
	for i := range counts {
		counts[i] = map[string]int64{}
	}
	rd := &readers{p: p}
	defer rd.close()
	if err := e.scan(ctx, p, rd, 0, len(p.blocks), f, colsFor(f, 0), func(w int, b *planned, _ int, _ *flow.Record) {
		counts[w][p.segs[b.seg].DeviceID]++
	}); err != nil {
		return nil, err
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
	segs, err := e.o.Index.FlowSegmentsWithRaw(ctx, q.DeviceIDs)
	if err != nil {
		return err
	}
	from, to := q.From.UnixMilli(), q.To.UnixMilli()
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
	return ctx.Err()
}

// RuleIDIEs returns the rule IEs in effect.
func (e *Engine) RuleIDIEs() []flow.IEKey { return e.ruleIEs() }
