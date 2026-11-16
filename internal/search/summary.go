package search

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gmccollu/woodshed/internal/datatype"
)

// Summaries: the Events field panel and histogram (GET /api/search/summary,
// SPEC §10.1.1, §10.1.2 and §10.1.5).
//
// One scan reads newest first and counts every matching line; it never
// samples. It reads like a desc search, but instead of merging lines into
// pages it moves every line it finds into a holdback, and commits a held line
// to the counts once no unread line can be newer: when its received time is
// above every stream's bound. So each response covers [counted_from, to)
// exactly, with counted_from one past the highest bound still unread, even
// when lines within a file are slightly out of order. The running counts, the
// holdback and the scan's position (a search cursor) stay on the server; the
// client's cursor only names them.
//
// The histogram of an unfiltered query is read from the stats and checkpoints
// instead (histindex.go), without opening a log file.

// Summary limits and defaults (SPEC §10.1.5).
const (
	DefaultSummaryBudget = 2 * time.Second
	MaxSummaryBudget     = 10 * time.Second
	DefaultTop           = 10
	MaxTop               = 50
	MaxDistinct          = 10000 // distinct values tracked per field
	MaxBuckets           = 1000
	SummaryTTL           = 10 * time.Minute
	MaxSummaries         = 8 // running summaries kept
	MaxSummaryScans      = 2 // summary scans running at once
)

// BucketSizes are the histogram bucket sizes a client may ask for.
var BucketSizes = []time.Duration{time.Second, 5 * time.Second, 15 * time.Second, time.Minute, 5 * time.Minute,
	15 * time.Minute, time.Hour, 2 * time.Hour, 6 * time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

// DefaultBucket is the bucket size for a range (SPEC §10.1.2): at most 120
// buckets, then 7 days.
func DefaultBucket(rng time.Duration) time.Duration {
	limits := []time.Duration{2 * time.Minute, 10 * time.Minute, 30 * time.Minute, 2 * time.Hour, 10 * time.Hour,
		30 * time.Hour, 5 * 24 * time.Hour, 10 * 24 * time.Hour, 30 * 24 * time.Hour, 120 * 24 * time.Hour}
	for i, l := range limits {
		if rng <= l {
			return BucketSizes[i]
		}
	}
	return BucketSizes[len(BucketSizes)-1]
}

// weekOrigin puts 7-day buckets on Mondays: 1970-01-05 was a Monday.
const weekOrigin = 4 * 24 * 3600 * 1000

// bucketStart is the start (ms) of the bucket of size ms holding t.
func bucketStart(t, size int64) int64 {
	off := int64(0)
	if size == 7*24*3600*1000 {
		off = weekOrigin
	}
	return floorDiv(t-off, size)*size + off
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// SummaryQuery is one /api/search/summary request.
type SummaryQuery struct {
	Filter
	Devices        []string
	Group          string
	Ungrouped      bool
	ExcludeDevices []string
	// Fields are the field keys to count, in any order; nil means every field,
	// and an empty non-nil slice none (fields=none).
	Fields      []string
	Top         int  // values per field (default 10, at most 50)
	NoHistogram bool // histogram=false
	Bucket      time.Duration
	Budget      time.Duration // default 2 s, at most 10 s
	Cursor      string

	forceScan bool // tests: never use the index histogram
}

// Bucket is one histogram bucket. Count is nil while it hasn't been counted.
type Bucket struct {
	Start  time.Time
	Count  *int64
	Approx bool
}

// Histogram is a summary's histogram.
type Histogram struct {
	BucketSeconds int64
	Source        string // "index" or "scan"
	Buckets       []Bucket
}

// FieldValue is one value of a field.
type FieldValue struct {
	Value, Label string
	Count        int64
	Filterable   bool
}

// FieldCounts is one field's counts.
type FieldCounts struct {
	Key, Label     string
	Values         []FieldValue
	Other, None    int64
	Distinct       int
	DistinctCapped bool
}

// Summary is one /api/search/summary response.
type Summary struct {
	From, To     time.Time
	Matched      int64
	CountedFrom  time.Time
	Histogram    *Histogram // nil: not asked for
	Fields       []FieldCounts
	NextCursor   string
	Partial      bool
	ScannedBytes int64
	ScannedFiles int
	Elapsed      time.Duration
}

// ErrSummaryExpired is the error for a cursor whose running counts are gone.
var ErrSummaryExpired = &QueryError{Msg: "This summary expired; start it again."}

// ---- running state ----

// slot is one tracked value of a field.
type slot struct {
	value string // the first spelling seen
	n     int64
}

// tally counts one free-text field (host, app). Values are grouped by a key
// folded the way the field's filter matches (case, and a leading '%' for
// app), so a value's count is what filtering on it returns.
type tally struct {
	byKey    map[string]int32
	slots    []slot
	overflow int64 // lines whose value wasn't tracked (past MaxDistinct)
	none     int64 // lines without a value
	capped   bool
}

const (
	idNone     = -1 // the line has no value
	idOverflow = -2 // a value past MaxDistinct
)

func newTally() *tally { return &tally{byKey: map[string]int32{}} }

// id returns the slot of v, adding it if there's room.
func (t *tally) id(v string, app bool) int32 {
	if v == "" {
		return idNone
	}
	k := foldKey(v, app)
	if i, ok := t.byKey[k]; ok {
		return i
	}
	if len(t.slots) >= MaxDistinct {
		t.capped = true
		return idOverflow
	}
	i := int32(len(t.slots))
	t.byKey[strings.Clone(k)] = i
	t.slots = append(t.slots, slot{value: strings.Clone(v)})
	return i
}

func (t *tally) add(id int32) {
	switch {
	case id >= 0:
		t.slots[id].n++
	case id == idOverflow:
		t.overflow++
	default:
		t.none++
	}
}

// foldKey is the grouping key of a host (case folded) or app (case folded,
// without a leading '%') value. It doesn't allocate for lower-case ASCII.
func foldKey(v string, app bool) string {
	if app {
		v = trimPct(v)
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c >= utf8.RuneSelf || ('A' <= c && c <= 'Z') {
			return strings.ToLower(v)
		}
	}
	return v
}

// held is a line found but not yet committed to the counts. For a data type
// other than syslog, ext is its row in sumState.extRows (-1: none).
type held struct {
	ms        int64
	dev       int32
	pri       int16 // -1: no PRI
	host, app int32
	ext       int32
}

type sumState struct {
	id   [16]byte
	seq  uint64
	bind []byte

	fromMs, toMs     int64
	bucketMs, origin int64
	nb               int

	devs   []string
	labels []string
	dt     datatype.Type // the data type

	// Another type than syslog: the non-device fields counted (genKeys, in
	// schema order), a tally each, and the held lines' value rows (extRows,
	// reused through extFree once committed).
	genKeys []string
	gen     []*tally
	extRows [][]int32
	extFree []int32

	wantFields []string // keys in schema order
	wantHist   bool
	scanHist   bool // the histogram comes from the scan
	idxHist    []Bucket

	started    bool
	done       bool
	scanCursor string // the scan's position (a search cursor)
	committed  int64  // lines committed
	countedMs  int64  // every line in [countedMs, toMs) is committed

	devN       []int64
	sevN       [9]int64 // 0-7, unknown
	facN       [25]int64
	host, app  *tally
	hist       []int64
	hold       []held
	holdFlushN int

	used time.Time // for SummaryTTL
	lru  uint64    // put order, for MaxSummaries

	// kept holds the compressed-file passes paused when a request's budget
	// ran out; they close with the state. passBlocks counts blocks read by
	// passes (tests).
	kept       *keptReaders
	passBlocks int
	wall       time.Time   // wall-clock time of the last put, for the reaper
	reaper     *time.Timer // closes kept readers once the state expires
}

// summaries keeps the running summaries, least recently used out first.
type summaries struct {
	mu   sync.Mutex
	byID map[[16]byte]*sumState
	tick uint64
	sem  chan struct{}
}

func newSummaries() *summaries {
	return &summaries{byID: map[[16]byte]*sumState{}, sem: make(chan struct{}, MaxSummaryScans)}
}

// take removes and returns the state for id at seq, or nil.
func (c *summaries) take(id [16]byte, seq uint64, now time.Time) *sumState {
	c.mu.Lock()
	gone := c.expireLocked(now)
	st := c.byID[id]
	if st != nil && st.seq != seq {
		st = nil
	}
	if st != nil {
		delete(c.byID, id)
	}
	c.mu.Unlock()
	for _, s := range gone {
		s.drop()
	}
	if st != nil && st.reaper != nil {
		st.reaper.Stop()
	}
	return st
}

func (c *summaries) put(st *sumState, now time.Time) {
	c.mu.Lock()
	st.used, st.wall = now, time.Now()
	c.tick++
	st.lru = c.tick
	c.byID[st.id] = st
	gone := c.expireLocked(now)
	for len(c.byID) > MaxSummaries {
		var old *sumState
		for _, s := range c.byID {
			if old == nil || s.lru < old.lru {
				old = s
			}
		}
		delete(c.byID, old.id)
		gone = append(gone, old)
	}
	// The cache is only swept when it's used, so a state left alone closes its
	// readers on a timer (wall clock).
	st.reaper = time.AfterFunc(SummaryTTL+time.Second, func() {
		c.mu.Lock()
		cur := c.byID[st.id]
		stale := cur == st && time.Since(st.wall) > SummaryTTL
		if stale {
			delete(c.byID, st.id)
		}
		c.mu.Unlock()
		if stale {
			st.kept.closeAll()
		}
	})
	c.mu.Unlock()
	for _, s := range gone {
		s.drop()
	}
}

// expireLocked removes the states past SummaryTTL and returns them (the
// caller drops them outside the lock).
func (c *summaries) expireLocked(now time.Time) []*sumState {
	var gone []*sumState
	for id, s := range c.byID {
		if now.Sub(s.used) > SummaryTTL {
			delete(c.byID, id)
			gone = append(gone, s)
		}
	}
	return gone
}

// drop releases a state that's no longer cached.
func (st *sumState) drop() {
	if st.reaper != nil {
		st.reaper.Stop()
	}
	st.kept.closeAll()
}

// ---- cursor ----

const summaryCursorVersion = 1

func (q *SummaryQuery) binding() []byte {
	sq := Query{Filter: q.Filter, Devices: q.Devices, Group: q.Group, Ungrouped: q.Ungrouped, ExcludeDevices: q.ExcludeDevices}
	h := sha256.New()
	h.Write([]byte("woodshed-summary-v1"))
	h.Write(sq.binding())
	var b []byte
	if q.Fields == nil {
		b = append(b, 0xff)
	} else {
		fs := sortedUnique(q.Fields)
		b = binary.AppendUvarint(b, uint64(len(fs)))
		for _, f := range fs {
			b = binary.AppendUvarint(b, uint64(len(f)))
			b = append(b, f...)
		}
	}
	b = binary.AppendVarint(b, int64(q.Bucket))
	if q.NoHistogram {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	h.Write(b)
	return h.Sum(nil)[:bindLen]
}

func (e *Engine) encodeSummaryCursor(st *sumState) string {
	b := []byte{summaryCursorVersion}
	b = append(b, st.bind...)
	b = append(b, st.id[:]...)
	b = binary.AppendUvarint(b, st.seq)
	mac := hmac.New(sha256.New, e.key)
	mac.Write(b)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(b)[:len(b)+macLen])
}

func (e *Engine) decodeSummaryCursor(s string, bind []byte) (id [16]byte, seq uint64, err error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) < 1+bindLen+16+1+macLen {
		return id, 0, errCursorInvalid
	}
	body, sum := raw[:len(raw)-macLen], raw[len(raw)-macLen:]
	mac := hmac.New(sha256.New, e.key)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil)[:macLen], sum) || body[0] != summaryCursorVersion {
		return id, 0, errCursorInvalid
	}
	if !bytes.Equal(body[1:1+bindLen], bind) {
		return id, 0, errCursorOther
	}
	copy(id[:], body[1+bindLen:])
	seq, n := binary.Uvarint(body[1+bindLen+16:])
	if n <= 0 || 1+bindLen+16+n != len(body) {
		return id, 0, errCursorInvalid
	}
	return id, seq, nil
}

// ---- the request ----

// knownField reports whether k is a field key of the type.
func knownField(dt datatype.Type, k string) bool {
	for _, f := range dt.Fields() {
		if f.Key == k {
			return true
		}
	}
	return false
}

// syslog reports whether the summary counts syslog (its own counters).
func (st *sumState) syslog() bool { return st.dt == nil || st.dt.Name() == TypeSyslog }

// extRow returns a free row of len(genKeys) value IDs for a held line.
func (st *sumState) extRow() int32 {
	if n := len(st.extFree); n > 0 {
		r := st.extFree[n-1]
		st.extFree = st.extFree[:n-1]
		return r
	}
	st.extRows = append(st.extRows, make([]int32, len(st.genKeys)))
	return int32(len(st.extRows) - 1)
}

// CheckBucket validates a bucket size for a range: one of BucketSizes, giving
// at most MaxBuckets buckets.
func CheckBucket(size time.Duration, fromMs, toMs int64) error {
	if !slices.Contains(BucketSizes, size) {
		return &QueryError{Msg: "bucket must be one of 1, 5, 15, 60, 300, 900, 3600, 7200, 21600, 86400 and 604800 (seconds)."}
	}
	ms := size.Milliseconds()
	n := (bucketStart(toMs-1, ms)-bucketStart(fromMs, ms))/ms + 1
	if n > MaxBuckets {
		return &QueryError{Msg: fmt.Sprintf("bucket=%d gives %d buckets over this range; the limit is %d.", int64(size/time.Second), n, MaxBuckets)}
	}
	return nil
}

// histogramUnfiltered reports whether f filters only by devices and time, so
// the histogram can come from the index.
func histogramUnfiltered(f Filter) bool {
	return f.Q == "" && f.Exclude == "" && len(f.Apps) == 0 && len(f.Hosts) == 0 && len(f.ExcludeApps) == 0 &&
		len(f.ExcludeHosts) == 0 && f.Severities == 0 && f.Facilities == 0 && (f.Trap == nil || f.Trap.Empty()) &&
		(f.Poll == nil || f.Poll.Empty())
}

// Summary runs one request of a summary.
func (e *Engine) Summary(ctx context.Context, q SummaryQuery) (Summary, error) {
	start := time.Now()
	budget := q.Budget
	if budget <= 0 {
		budget = DefaultSummaryBudget
	}
	budget = min(budget, MaxSummaryBudget)
	deadline := start.Add(budget)
	c, err := e.compile(q.Filter)
	if err != nil {
		return Summary{}, err
	}
	for _, f := range q.Fields {
		if !knownField(c.dt, f) {
			return Summary{}, &QueryError{Msg: fmt.Sprintf("fields: unknown field %q.", f)}
		}
	}
	top := q.Top
	if top <= 0 {
		top = DefaultTop
	}
	top = min(top, MaxTop)
	bind := q.binding()

	var st *sumState
	if q.Cursor != "" {
		id, seq, err := e.decodeSummaryCursor(q.Cursor, bind)
		if err != nil {
			return Summary{}, err
		}
		if st = e.sums.take(id, seq, e.now()); st == nil {
			return Summary{}, ErrSummaryExpired
		}
	} else {
		if st, err = e.newSummary(ctx, q, bind, c); err != nil {
			return Summary{}, err
		}
	}

	var scanned int64
	var files int
	if !st.done {
		// At most MaxSummaryScans scans at once; the others wait within their own
		// budget and return what they have.
		t := time.NewTimer(time.Until(deadline))
		select {
		case e.sums.sem <- struct{}{}:
			t.Stop()
			scanned, files, err = e.summaryScan(ctx, st, c, deadline)
			<-e.sums.sem
			if err != nil {
				st.drop()
				return Summary{}, err // the state is dropped: a cancelled scan can't resume
			}
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			st.drop()
			return Summary{}, ctx.Err()
		}
	}
	out := e.summaryOut(st, top)
	out.ScannedBytes, out.ScannedFiles, out.Elapsed = scanned, files, time.Since(start)
	if st.done {
		st.drop()
	} else {
		st.seq++
		e.sums.put(st, e.now())
		out.NextCursor = e.encodeSummaryCursor(st)
		out.Partial = true
	}
	return out, nil
}

func (e *Engine) newSummary(ctx context.Context, q SummaryQuery, bind []byte, c compiled) (*sumState, error) {
	st := &sumState{bind: bind, wantHist: !q.NoHistogram, dt: c.dt, kept: newKeptReaders()}
	_, _ = rand.Read(st.id[:])
	var err error
	if st.fromMs, st.toMs, err = e.resolveRange(q.Filter); err != nil {
		return nil, err
	}
	size := q.Bucket
	if size == 0 {
		size = DefaultBucket(time.Duration(st.toMs-st.fromMs) * time.Millisecond)
	} else if err := CheckBucket(size, st.fromMs, st.toMs); err != nil {
		return nil, err
	}
	st.bucketMs = size.Milliseconds()
	st.origin = bucketStart(st.fromMs, st.bucketMs)
	st.nb = int((bucketStart(st.toMs-1, st.bucketMs)-st.origin)/st.bucketMs) + 1
	for _, f := range st.dt.Fields() {
		if q.Fields == nil || slices.Contains(q.Fields, f.Key) {
			st.wantFields = append(st.wantFields, f.Key)
			if !st.syslog() && f.Key != FieldDevice {
				st.genKeys = append(st.genKeys, f.Key)
				st.gen = append(st.gen, newTally())
			}
		}
	}
	all, err := e.idx.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	none := c.none
	if !none {
		st.devs = selectDevices(all, q.Devices, q.Group, q.Ungrouped, q.ExcludeDevices)
	}
	label := map[string]string{}
	for _, d := range all {
		l := d.Name
		if l == "" {
			l = d.IP
		}
		if l == "" {
			l = d.ID
		}
		label[d.ID] = l
	}
	for _, d := range st.devs {
		st.labels = append(st.labels, label[d])
	}
	st.devN = make([]int64, len(st.devs))
	st.host, st.app = newTally(), newTally()
	st.countedMs = st.toMs
	if st.wantHist {
		if !q.forceScan && st.bucketMs >= time.Minute.Milliseconds() && histogramUnfiltered(q.Filter) && !none {
			if st.idxHist, err = e.indexHistogram(ctx, st); err != nil {
				return nil, err
			}
		} else {
			st.scanHist = true
			st.hist = make([]int64, st.nb)
		}
	}
	// No scan is needed for the index histogram alone.
	st.done = len(st.devs) == 0 || (len(st.wantFields) == 0 && st.wantHist && !st.scanHist)
	if st.done {
		st.countedMs = st.fromMs
	}
	return st, nil
}

// flush commits the held lines that are newer than every unread line.
func (st *sumState) flush(r *run, streams []*stream) {
	bound := int64(math.MinInt64)
	for _, s := range streams {
		if s.done {
			continue
		}
		if k, _ := s.key(r); k > bound {
			bound = k
		}
	}
	keep := st.hold[:0]
	for _, h := range st.hold {
		if h.ms > bound {
			st.commit(h)
		} else {
			keep = append(keep, h)
		}
	}
	clear(st.hold[len(keep):])
	st.hold = keep
	if bound == math.MinInt64 {
		st.countedMs = st.fromMs
	} else {
		st.countedMs = min(max(bound+1, st.fromMs), st.countedMs)
	}
}

func (st *sumState) commit(h held) {
	st.committed++
	st.devN[h.dev]++
	if !st.syslog() {
		if h.ext >= 0 {
			for i, id := range st.extRows[h.ext] {
				st.gen[i].add(id)
			}
			st.extFree = append(st.extFree, h.ext)
		}
		if st.scanHist {
			st.hist[(h.ms-st.origin)/st.bucketMs]++
		}
		return
	}
	sev, fac := 8, 24
	if h.pri >= 0 {
		sev, fac = int(h.pri&7), int(h.pri>>3)
	}
	st.sevN[sev]++
	st.facN[fac]++
	if slices.Contains(st.wantFields, FieldHost) {
		st.host.add(h.host)
	}
	if slices.Contains(st.wantFields, FieldApp) {
		st.app.add(h.app)
	}
	if st.scanHist {
		st.hist[(h.ms-st.origin)/st.bucketMs]++
	}
}

// ---- the response ----

func (e *Engine) summaryOut(st *sumState, top int) Summary {
	out := Summary{From: time.UnixMilli(st.fromMs).UTC(), To: time.UnixMilli(st.toMs).UTC(), Matched: st.committed,
		CountedFrom: time.UnixMilli(st.countedMs).UTC()}
	if st.wantHist {
		h := &Histogram{BucketSeconds: st.bucketMs / 1000, Source: "scan"}
		if st.idxHist != nil {
			h.Source = "index"
			h.Buckets = st.idxHist
			if len(st.wantFields) == 0 {
				out.Matched = 0
				for _, b := range st.idxHist {
					out.Matched += *b.Count
				}
			}
		} else {
			h.Buckets = make([]Bucket, st.nb)
			for i := range h.Buckets {
				s := st.origin + int64(i)*st.bucketMs
				h.Buckets[i].Start = time.UnixMilli(s).UTC()
				if !st.done && s+st.bucketMs <= st.countedMs {
					continue // wholly before counted_from: not counted yet
				}
				n := st.hist[i]
				h.Buckets[i].Count = &n
			}
		}
		out.Histogram = h
	}
	for _, k := range st.wantFields {
		var fs FieldSchema
		for _, f := range st.dt.Fields() {
			if f.Key == k {
				fs = f
			}
		}
		fc := FieldCounts{Key: k, Label: fs.Label, Values: []FieldValue{}}
		var vals []FieldValue
		gi := slices.Index(st.genKeys, k)
		switch {
		case gi >= 0:
			t := st.gen[gi]
			for _, s := range t.slots {
				if s.n > 0 {
					vals = append(vals, FieldValue{Value: s.value, Label: st.dt.ValueLabel(k, s.value), Count: s.n,
						Filterable: filterable(s.value, false)})
				}
			}
			fc.None, fc.DistinctCapped = t.none, t.capped
			fc.Other += t.overflow
		case k == FieldDevice:
			for i, n := range st.devN {
				if n > 0 {
					vals = append(vals, FieldValue{Value: st.devs[i], Label: st.labels[i], Count: n, Filterable: true})
				}
			}
		case k == FieldSeverity || k == FieldFacility:
			counts := st.sevN[:]
			if k == FieldFacility {
				counts = st.facN[:]
			}
			for i, n := range counts {
				if n > 0 {
					d := fs.Domain[i]
					vals = append(vals, FieldValue{Value: d.Value, Label: d.Label, Count: n, Filterable: true})
				}
			}
		default:
			t := st.host
			if k == FieldApp {
				t = st.app
			}
			for _, s := range t.slots {
				if s.n > 0 {
					vals = append(vals, FieldValue{Value: s.value, Label: s.value, Count: s.n, Filterable: filterable(s.value, k == FieldApp)})
				}
			}
			fc.None, fc.DistinctCapped = t.none, t.capped
			fc.Other += t.overflow
		}
		slices.SortFunc(vals, func(a, b FieldValue) int {
			if a.Count != b.Count {
				if a.Count > b.Count {
					return -1
				}
				return 1
			}
			return strings.Compare(a.Value, b.Value)
		})
		fc.Distinct = len(vals)
		if fs.Domain == nil && len(vals) > top {
			for _, v := range vals[top:] {
				fc.Other += v.Count
			}
			vals = vals[:top]
		}
		fc.Values = append(fc.Values, vals...)
		out.Fields = append(out.Fields, fc)
	}
	return out
}

// filterable reports whether a host or app value can go into its filter
// parameter as is: not with a comma (the list separator), surrounding blanks,
// or (for app) a trailing '*' (a prefix pattern).
func filterable(v string, app bool) bool {
	if strings.Contains(v, ",") || strings.TrimSpace(v) != v || v == "" {
		return false
	}
	return !app || !strings.HasSuffix(v, "*")
}

// PickBucket is the histogram bucket for a range: size when given (checked
// like CheckBucket), else DefaultBucket. Flow summaries use it too.
func PickBucket(size time.Duration, from, to time.Time) (time.Duration, error) {
	if size == 0 {
		size = DefaultBucket(to.Sub(from))
	}
	if err := CheckBucket(size, from.UnixMilli(), to.UnixMilli()); err != nil {
		return 0, err
	}
	return size, nil
}

// BucketOrigin is where buckets of size start: the Unix epoch, or a Monday
// for 7-day buckets.
func BucketOrigin(size time.Duration) time.Time {
	if size == 7*24*time.Hour {
		return time.UnixMilli(weekOrigin).UTC()
	}
	return time.Unix(0, 0).UTC()
}
