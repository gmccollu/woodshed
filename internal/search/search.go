// Package search is the engine behind /api/search and /api/context
// (docs/api.md), and the line scanner the export builder uses.
//
// It reads the log files directly, using the index only to pick files and
// offsets: index.FilesInRange selects a device's files, and each file's
// checkpoints bound the part of it a time range can touch. Files are read with
// logfile's shared-delete opener, so a search never blocks rotation,
// compression or retention, and a file that disappears mid-search is skipped.
//
// # Order
//
// Results come from a merge of per-device streams. Each device's stream is its
// matching lines in file order (reversed for desc); the merge always takes the
// stream whose next line has the newest (desc) or oldest (asc) received time,
// ties going to the lower device ID. A stream that hasn't found its next match
// yet competes with a bound on the lines it hasn't read: for desc the
// checkpoint high-water mark (exact), for asc the last checkpoint passed minus
// maxSkew. So the first page of a desc search reads backwards from now across
// all devices together, and stops once it has limit results.
//
// # Cursors
//
// A cursor holds each unfinished stream's position (file ID and offset), the
// resolved time range and a hash of the other parameters, HMAC-signed with a
// key made at startup. A cursor from before a restart, or a changed one, is a
// QueryError. Positions are file IDs and offsets in the uncompressed stream,
// which don't change when a file is renamed or compressed, so pages
// concatenated are exactly one full scan, even while the files rotate.
//
// # Reading
//
// Plain files are read backwards (desc) or forwards (asc) in blocks.
// Compressed files are always read forwards; for desc one pass keeps the last
// matches of the region it read (up to the results still needed), so a page
// never holds more than a block per device plus those matches.
package search

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log/slog"
	"runtime"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Defaults for Options.
const (
	DefaultBudget    = 10 * time.Second
	DefaultPageBytes = 8 << 20
	DefaultBlock     = 128 << 10
	DefaultRingBytes = 2 << 20
	DefaultLimit     = 500
	MaxLimit         = 5000
	DefaultRange     = 24 * time.Hour
	MaxContext       = 500
)

// ErrNotFound is returned by Context for a ref whose file is gone.
var ErrNotFound = errors.New("search: not found")

// Options configures an Engine.
type Options struct {
	DataDir string
	Index   *index.DB
	// Budget is the time one Search may take (default 10 s).
	Budget time.Duration
	// PageBytes caps the raw bytes of one page's results (default 8 MiB). A page
	// cut short by it is partial, like one that ran out of time.
	PageBytes int
	// Key signs cursors. Default: 32 random bytes, so cursors don't survive a
	// restart.
	Key    []byte
	Now    func() time.Time
	Logger *slog.Logger

	block, ringBytes int
}

// Engine runs searches. It is safe for concurrent use.
type Engine struct {
	dataDir   string
	idx       *index.DB
	budget    time.Duration
	pageBytes int
	key       []byte
	now       func() time.Time
	log       *slog.Logger
	block     int
	ringBytes int
	passes    *passCache
	readers   *readerCache
	sums      *summaries
	decodeSem chan struct{} // bounds parallel decompression

	testHookOpen func(rel string) // called before each file open
	testMaxSteps int              // >0: a request's budget is this many reads, not Budget
	prefetches   atomic.Int64     // prefetch runs, for tests
	inflated     atomic.Int64     // bytes decompressed from .gz files, for tests
	sumWorkers   int              // >0: parallel compressed passes per summary scan (tests)
	sumNoKeep    bool             // tests: don't keep paused passes (the old behaviour, for comparison)
}

// New returns an Engine.
func New(opts Options) *Engine {
	e := &Engine{dataDir: opts.DataDir, idx: opts.Index, budget: opts.Budget, pageBytes: opts.PageBytes,
		key: opts.Key, now: opts.Now, log: opts.Logger, block: opts.block, ringBytes: opts.ringBytes}
	if e.budget <= 0 {
		e.budget = DefaultBudget
	}
	if e.pageBytes <= 0 {
		e.pageBytes = DefaultPageBytes
	}
	if len(e.key) == 0 {
		e.key = make([]byte, 32)
		_, _ = rand.Read(e.key)
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.log == nil {
		e.log = slog.Default()
	}
	if e.block <= 0 {
		e.block = DefaultBlock
	}
	if e.ringBytes <= 0 {
		e.ringBytes = DefaultRingBytes
	}
	e.passes = newPassCache(256 << 20)
	e.decodeSem = make(chan struct{}, max(1, runtime.NumCPU()-1))
	e.readers = newReaderCache(64, 2*time.Minute)
	e.sums = newSummaries()
	return e
}

// Filter selects lines: by text, severity, time, program/tag and host. It's
// shared by search and export, so an export of a search returns the same lines.
type Filter struct {
	Q     string
	Regex bool // Q (and Exclude) is an RE2 regular expression
	// Terms: Q (and Exclude) are boolean terms (syntax=terms, SPEC §10.1.3).
	// It can't be combined with Regex.
	Terms bool
	Case  bool // case-sensitive (substring, regex and terms; Q and Exclude)
	// Exclude drops the lines whose raw message matches it, like Q with the
	// same Regex and Case. Empty: nothing is dropped.
	Exclude string
	// Apps and Hosts keep only lines whose parsed header (syslog.Parse) has one
	// of these programs/tags or hostnames, ignoring case. An app ending in '*'
	// is a prefix, and a leading '%' is ignored on both sides, so "FW-6-*" and
	// "%FW-6-*" both match "%FW-6-302013". Empty: no filter. The header is
	// parsed only for lines that passed every other check.
	Apps, Hosts []string
	// ExcludeApps and ExcludeHosts drop the lines whose program/tag or
	// hostname matches one of them, with the rules of Apps and Hosts. A line
	// without a program/tag (or hostname) is never dropped by them.
	ExcludeApps, ExcludeHosts []string
	// Severities: 0 means all; hub.SeverityNone matches nothing.
	Severities hub.SeveritySet
	// Facilities: 0 means all; FacilityNone matches nothing.
	Facilities FacilitySet
	// From and To bound the received time: From <= received < To. Zero values
	// default (Search: To = now, From = To - 24 h).
	From, To time.Time
}

// Query is one /api/search request.
type Query struct {
	Filter
	// Devices, Group and Ungrouped pick the devices as for the live tail. Hidden
	// devices are searched only when named in Devices. ExcludeDevices are then
	// left out (an exclusion wins over a name).
	Devices        []string
	Group          string
	Ungrouped      bool
	ExcludeDevices []string
	Asc            bool // oldest first; the default is newest first
	Limit          int  // default 500, at most 5,000
	Cursor         string
}

// Line is one result.
type Line struct {
	Received time.Time
	DeviceID string
	Severity int    // 0-7, or model.Unknown
	Raw      []byte // the message as received
	Ref      string
	App      string // the parsed program/tag ("" when there's none)
	Host     string // the parsed header hostname ("" when there's none)
}

// Page is one /api/search response.
type Page struct {
	Results      []Line
	NextCursor   string // "" when the range is exhausted
	ScannedBytes int64
	ScannedFiles int
	Elapsed      time.Duration
	Partial      bool
}

// ceilMs is t in Unix milliseconds, rounded up: lines are stored with
// millisecond times, so "received >= from" is "ms >= ceilMs(from)".
func ceilMs(t time.Time) int64 {
	ms := t.UnixMilli()
	if time.UnixMilli(ms).Before(t) {
		ms++
	}
	return ms
}

// compiled is a Filter's matchers.
type compiled struct {
	m      *matcher
	ex     *matcher      // nil: no exclude
	fields *fieldMatcher // nil: no app or host filter
}

func (e *Engine) compile(f Filter) (compiled, error) {
	if f.Terms && f.Regex {
		return compiled{}, &QueryError{Msg: ErrTermsWithRegex}
	}
	compile := func(q string) (*matcher, error) {
		if f.Terms {
			return newTermsMatcher(q, f.Case)
		}
		return newMatcher(q, f.Regex, f.Case)
	}
	m, err := compile(f.Q)
	if err != nil {
		return compiled{}, err
	}
	c := compiled{m: m, fields: newFieldMatcher(f.Apps, f.Hosts, f.ExcludeApps, f.ExcludeHosts)}
	if f.Exclude != "" {
		if c.ex, err = compile(f.Exclude); err != nil {
			return compiled{}, &QueryError{Msg: "exclude: " + err.Error()}
		}
		if c.ex.kind == matchAll {
			c.ex = nil // a terms exclude with no terms (only spaces) excludes nothing
		}
	}
	return c, nil
}

// resolveRange applies the defaults and checks the range.
func (e *Engine) resolveRange(f Filter) (fromMs, toMs int64, err error) {
	to := f.To
	if to.IsZero() {
		to = e.now()
	}
	from := f.From
	if from.IsZero() {
		from = to.Add(-DefaultRange)
	}
	if !from.Before(to) {
		return 0, 0, &QueryError{Msg: `"from" must be before "to".`}
	}
	return ceilMs(from), ceilMs(to), nil
}

// devices resolves the query's device selection to IDs, sorted.
func (e *Engine) devices(ctx context.Context, named []string, group string, ungrouped bool, excluded []string) ([]string, error) {
	all, err := e.idx.ListDevices(ctx)
	if err != nil {
		return nil, err
	}
	return selectDevices(all, named, group, ungrouped, excluded), nil
}

// selectDevices applies a device selection to every device (sorted by ID).
func selectDevices(all []index.Device, named []string, group string, ungrouped bool, excluded []string) []string {
	want := map[string]bool{}
	for _, d := range named {
		want[d] = true
	}
	drop := map[string]bool{}
	for _, d := range excluded {
		drop[d] = true
	}
	var out []string
	for _, d := range all {
		if len(named) > 0 && !want[d.ID] {
			continue
		}
		if drop[d.ID] {
			continue
		}
		if len(named) == 0 && d.Hidden {
			continue
		}
		if group != "" && d.Group != group {
			continue
		}
		if ungrouped && d.Group != "" {
			continue
		}
		out = append(out, d.ID)
	}
	return out
}

// ResolveDevices is the device selection of a search or export: named devices
// (hidden ones too) or every visible device, narrowed by group or ungrouped,
// less the excluded ones.
func (e *Engine) ResolveDevices(ctx context.Context, named []string, group string, ungrouped bool, excluded []string) ([]string, error) {
	return e.devices(ctx, named, group, ungrouped, excluded)
}

// filesByDevice returns each device's files that may hold lines in
// [fromMs, toMs), oldest first.
func (e *Engine) filesByDevice(ctx context.Context, devs []string, fromMs, toMs int64) (map[string][]*fileInfo, error) {
	out := map[string][]*fileInfo{}
	if len(devs) == 0 {
		return out, nil
	}
	// The active file's row trails the file by up to a few seconds, so widen
	// the lower edge; the checkpoints narrow it again per file.
	spans, err := e.idx.FilesInRange(ctx, devs, time.UnixMilli(fromMs).Add(-maxSkew), time.UnixMilli(toMs))
	if err != nil {
		return nil, err
	}
	for _, sp := range spans {
		out[sp.DeviceID] = append(out[sp.DeviceID], &fileInfo{File: sp.File})
	}
	for _, fs := range out {
		sort.SliceStable(fs, func(i, j int) bool { return fs[i].key().less(fs[j].key()) })
	}
	return out, nil
}

// Search runs one page of a search.
func (e *Engine) Search(ctx context.Context, q Query) (Page, error) {
	start := time.Now()
	c, err := e.compile(q.Filter)
	if err != nil {
		return Page{}, err
	}
	limit := q.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	limit = min(limit, MaxLimit)
	bind := q.binding()

	r := &run{e: e, ctx: ctx, deadline: start.Add(e.budget), maxSteps: e.testMaxSteps, now: e.now(), desc: !q.Asc, m: c.m,
		ex: c.ex, fields: c.fields, sevs: q.Severities, facs: q.Facilities, need: limit, files: map[int64]struct{}{}}
	var streams []*stream
	if q.Cursor != "" {
		cur, err := e.decodeCursor(q.Cursor, bind)
		if err != nil {
			return Page{}, err
		}
		r.fromMs, r.toMs = cur.fromMs, cur.toMs
		devs := make([]string, len(cur.streams))
		for i, cs := range cur.streams {
			devs[i] = cs.dev
		}
		files, err := e.filesByDevice(ctx, devs, r.fromMs, r.toMs)
		if err != nil {
			return Page{}, err
		}
		for _, cs := range cur.streams {
			streams = append(streams, cs.resume(files[cs.dev], r.desc))
		}
	} else {
		if r.fromMs, r.toMs, err = e.resolveRange(q.Filter); err != nil {
			return Page{}, err
		}
		if q.Severities == hub.SeverityNone || q.Facilities == FacilityNone {
			return Page{Results: []Line{}, Elapsed: time.Since(start)}, nil
		}
		devs, err := e.devices(ctx, q.Devices, q.Group, q.Ungrouped, q.ExcludeDevices)
		if err != nil {
			return Page{}, err
		}
		files, err := e.filesByDevice(ctx, devs, r.fromMs, r.toMs)
		if err != nil {
			return Page{}, err
		}
		for _, d := range devs {
			s := newStream(d, files[d])
			if r.desc {
				s.fi = len(s.files) - 1
			}
			streams = append(streams, s)
		}
	}
	r.streams = streams
	r.cacheKey = string(bind) + string(binary.AppendVarint(binary.AppendVarint(nil, r.fromMs), r.toMs))
	// Every stream may hold a compressed-file pass in the cache at once: share
	// its budget between them, so paging through all devices doesn't evict one
	// device's pass to make room for the next.
	r.ringBytes = min(e.ringBytes, max(int(e.passes.max)/(2*max(len(streams), 1)), 256<<10))
	if !r.desc {
		for _, s := range streams {
			s.warm(r) // after cacheKey: warm takes parked readers
		}
	}
	defer func() {
		for _, s := range streams {
			s.park(r)
		}
	}()

	page := Page{Results: []Line{}}
	var pageBytes int
	for {
		if r.need == 0 || pageBytes >= e.pageBytes {
			if pageBytes >= e.pageBytes && r.need > 0 {
				page.Partial = true
			}
			break
		}
		s := r.pick(streams)
		if s == nil {
			break // exhausted
		}
		if s.head() == nil {
			// Read more of the best stream. Every request reads at least once, so
			// a cursor always moves on; re-reading a line the previous page found
			// (pending) doesn't count against the budget.
			if !s.pending {
				if r.steps > 0 && r.expired() {
					page.Partial = true
					break
				}
				r.steps++
			}
			s.step(r)
			if r.err != nil {
				break
			}
			continue
		}
		h := s.pop()
		ln := e.line(s.dev, h)
		pageBytes += len(ln.Raw)
		page.Results = append(page.Results, ln)
		r.need--
	}
	if r.err != nil {
		return Page{}, r.err
	}
	page.NextCursor = e.encodeCursor(bind, r, streams)
	page.ScannedBytes = r.scanned
	page.ScannedFiles = len(r.files)
	page.Elapsed = time.Since(start)
	if page.NextCursor == "" {
		page.Partial = false
	}
	return page, nil
}

// pick returns the stream the merge takes from next: the one whose next line
// (or bound on the lines it hasn't read) comes first. It returns nil when every
// stream is exhausted.
func (r *run) pick(streams []*stream) *stream {
	best, bestKey, bestHas := -1, int64(0), false
	for i, s := range streams {
		if s.done && s.head() == nil {
			continue
		}
		k, has := s.key(r)
		if best < 0 || better(r.desc, k, has, s.dev, bestKey, bestHas, streams[best].dev) {
			best, bestKey, bestHas = i, k, has
		}
	}
	if best < 0 {
		return nil
	}
	return streams[best]
}

// better reports whether candidate (k, has, dev) goes before the current best.
// A stream without a head (only a bound) goes first on a tie, so it is read
// before a line with the same time is returned.
func better(desc bool, k int64, has bool, dev string, bk int64, bhas bool, bdev string) bool {
	if k != bk {
		if desc {
			return k > bk
		}
		return k < bk
	}
	if has != bhas {
		return !has
	}
	return dev < bdev
}

func (e *Engine) line(dev string, h hit) Line {
	raw := logfile.Unescape(nil, h.esc)
	app, host := Fields(raw)
	return Line{
		Received: time.UnixMilli(h.ms).UTC(),
		DeviceID: dev,
		Severity: Severity(raw),
		Raw:      raw,
		Ref:      encodeRef(h.file.ID, h.off, h.ms),
		App:      app,
		Host:     host,
	}
}

// ---- refs ----

// A ref is a line's file ID, offset and received time (the time catches a
// stale or forged offset). It isn't signed: it can only name a line of a file
// in the index, which any client may read anyway.
func encodeRef(fileID, off, ms int64) string {
	b := make([]byte, 0, 3*binary.MaxVarintLen64)
	b = binary.AppendUvarint(b, uint64(fileID))
	b = binary.AppendUvarint(b, uint64(off))
	b = binary.AppendVarint(b, ms)
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeRef(ref string) (fileID, off, ms int64, err error) {
	bad := &QueryError{Msg: "Invalid ref."}
	b, err := base64.RawURLEncoding.Strict().DecodeString(ref)
	if err != nil || len(b) == 0 {
		return 0, 0, 0, bad
	}
	id, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, 0, 0, bad
	}
	b = b[n:]
	o, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, 0, 0, bad
	}
	b = b[n:]
	t, n := binary.Varint(b)
	if n <= 0 || n != len(b) || id == 0 || id > 1<<62 || o > 1<<62 {
		return 0, 0, 0, bad
	}
	return int64(id), int64(o), t, nil
}

// sortedUnique returns the sorted, de-duplicated non-empty strings of s.
func sortedUnique(s []string) []string {
	out := slices.Clone(s)
	out = slices.DeleteFunc(out, func(v string) bool { return v == "" })
	slices.Sort(out)
	return slices.Compact(out)
}
