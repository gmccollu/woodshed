// Package export builds the export zips (SPEC §4.1, docs/api.md "Exports"): a
// queue that builds one zip at a time, with progress, cancel and a 24 h expiry.
//
// Exports live in <data>/exports/: <id>.zip once ready, <id>.zip.tmp while
// building (renamed into place when complete, so a zip is never seen half
// written) and <id>.json, the entry's state, so ready exports survive a
// restart. An export that was queued or building when the service stopped is
// marked failed at the next start.
//
// The lines come from search.Scanner with the request's filter, so an export
// holds exactly what a search with the same parameters shows.
package export

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/atomicfile"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Dir is the exports folder inside the data dir.
const Dir = "exports"

// Defaults.
const (
	DefaultTTL  = 24 * time.Hour     // a ready export is deleted this long after it's ready
	DefaultKeep = 7 * 24 * time.Hour // expired and failed entries stay listed this long
)

// State is an export's state.
type State string

// States (docs/api.md).
const (
	Queued   State = "queued"
	Building State = "building"
	Ready    State = "ready"
	Failed   State = "failed"
	Expired  State = "expired"
)

// Errors.
var (
	ErrNotFound = errors.New("export: not found")
	ErrNotReady = errors.New("export: not ready")
	ErrClosed   = errors.New("export: closed")
)

// RequestError is an invalid request (a 400). Empty marks a bundle whose
// window held nothing from any device it would pick (`woodshed bundle` exits 1).
type RequestError struct {
	Msg   string
	Empty bool
}

func (e *RequestError) Error() string { return e.Msg }

// Filters are the request's filters, echoed in Info.
type Filters struct {
	Group      string          `json:"group"`
	Ungrouped  bool            `json:"ungrouped"`
	Severities hub.SeveritySet `json:"severities"` // 0: all; hub.SeverityNone: nothing
	Q          string          `json:"q"`
	Regex      bool            `json:"regex"`
	Case       bool            `json:"case"`
	Apps       []string        `json:"app,omitempty"`  // program/tag values, as for search
	Hosts      []string        `json:"host,omitempty"` // header hostnames, as for search
	Exclude    string          `json:"exclude,omitempty"`
	// 1.1: syntax=terms, facilities and the exclude forms (docs/api.md).
	Terms          bool               `json:"terms,omitempty"`
	Facilities     search.FacilitySet `json:"facilities,omitempty"` // 0: all; search.FacilityNone: nothing
	ExcludeDevices []string           `json:"exclude_devices,omitempty"`
	ExcludeApps    []string           `json:"exclude_app,omitempty"`
	ExcludeHosts   []string           `json:"exclude_host,omitempty"`
	// 1.2: the data types in the zip (empty: syslog, the 1.1 zip) and, with
	// one type of traps, its filter (SPEC §11.1, docs/api.md).
	Types []string             `json:"types,omitempty"`
	Trap  *datatype.TrapFilter `json:"trap,omitempty"`
	// 1.3: with one type of polls, its filter (SPEC §12.6).
	Poll *datatype.PollFilter `json:"poll,omitempty"`
	// 2.0: with one type of flows, its filter parameters (flowquery.Parse
	// reads them), and the flow files in the zip (nil: csv and ipfix).
	Flow        map[string]string `json:"flow,omitempty"`
	FlowFormats []string          `json:"flow_formats,omitempty"`
	// 1.2: the incident bundle (SPEC §11.3): Kind "bundle", the moment and
	// the spans before and after it, and whether the devices are the ones
	// active in the window. A bundle's Types are resolved when it's created
	// (every type with data in the window when the request names none).
	Kind          string        `json:"kind,omitempty"` // "" (an export) or KindBundle
	At            *time.Time    `json:"at,omitempty"`
	Before        time.Duration `json:"before,omitempty"`
	After         time.Duration `json:"after,omitempty"`
	ActiveDevices bool          `json:"active_devices,omitempty"`
}

// Kinds of export (docs/api.md: kind).
const (
	KindExport = "export"
	KindBundle = "bundle"
)

// IsBundle reports whether the request is an incident bundle.
func (f Filters) IsBundle() bool { return f.Kind == KindBundle }

// TypesOrSyslog is the export's data types, syslog when it names none. A
// bundle's are its own (none when nothing was stored in its window).
func (f Filters) TypesOrSyslog() []string {
	if f.IsBundle() {
		return f.Types
	}
	if len(f.Types) == 0 {
		return []string{datatype.Syslog}
	}
	return f.Types
}

// typeFilter is the request's search filter for one of its types: the
// filters apply only to an export of one type (the API refuses them with
// several), so another type gets only the range.
func (r Request) typeFilter(typ string) search.Filter {
	ts := r.TypesOrSyslog()
	if len(ts) == 1 && ts[0] == typ {
		f := r.filter()
		f.Type = typ
		if r.Trap != nil {
			_ = r.Trap.Compile() // a filter read back from the entry's file
			f.Trap = r.Trap
		}
		if r.Poll != nil && typ == datatype.Poll {
			f.Poll = r.Poll
		}
		return f
	}
	return search.Filter{From: r.From, To: r.To, Type: typ}
}

// Folders maps the zip's folders to the data types (manifest.json).
var Folders = map[string]string{"logs": datatype.Syslog, "traps": datatype.Trap, "poll": datatype.Poll}

// FolderOf is a type's folder in the zip: syslog stays in logs/ as in 1.1;
// another type gets its folder name ("traps/" for traps).
func FolderOf(typ string) string {
	for f, t := range Folders {
		if t == typ {
			return f
		}
	}
	return typ
}

// Request is a POST /api/exports body, parsed.
type Request struct {
	AllDevices bool     // every non-hidden device
	Devices    []string // named devices (hidden ones included)
	From, To   time.Time
	Filters
}

// Info is one export as GET /api/exports shows it.
type Info struct {
	ID        string     `json:"id"`
	Created   time.Time  `json:"created"`
	Devices   []string   `json:"devices"` // resolved device IDs
	From      time.Time  `json:"from"`
	To        time.Time  `json:"to"`
	State     State      `json:"state"`
	Progress  float64    `json:"progress"`
	Lines     int64      `json:"lines"`
	SizeBytes int64      `json:"size_bytes"`
	Error     string     `json:"error"`
	ReadyAt   *time.Time `json:"ready_at"`
	ExpiresAt *time.Time `json:"expires_at"`
	Filters   Filters    `json:"filters"`
	// Named is the devices the request named (empty when it picked by group).
	Named []string `json:"named,omitempty"`
}

// Options configures a Manager.
type Options struct {
	DataDir string
	Index   *index.DB
	Search  *search.Engine
	Version string
	TTL     time.Duration // default DefaultTTL
	Keep    time.Duration // default DefaultKeep
	Now     func() time.Time
	Logger  *slog.Logger

	// Level is the deflate level (default 5).
	Level int
	// Location is the local time zone a bundle's README names (default
	// time.Local).
	Location *time.Location
	// zip64Limit lowers the zip64 threshold, for tests.
	zip64Limit int64
	// janitor is how often expiry runs (default 1 min).
	janitor time.Duration
	// testHookLine is called before each line is written.
	testHookLine func()
}

// Manager is the export queue. It is safe for concurrent use.
type Manager struct {
	builder
	opts Options
	dir  string
	log  *slog.Logger

	mu      sync.Mutex
	entries map[string]*entry
	queue   []string // queued IDs, oldest first
	seq     int64
	wake    chan struct{}
	closed  bool

	stop chan struct{}
	wg   sync.WaitGroup

	// flows is the flow query engine (SetFlows), nil until the server sets it.
	flows atomic.Pointer[flowquery.Engine]
}

// SetFlows gives the manager the flow query engine, for flows in exports
// and bundles (SPEC §13.4).
func (m *Manager) SetFlows(e *flowquery.Engine) { m.flows.Store(e) }

type entry struct {
	info   Info
	seq    int64              // creation order in this process (ties in Created)
	cancel context.CancelFunc // set while building
	gone   bool               // deleted while building
	reason string             // why it was cancelled
}

var idRE = regexp.MustCompile(`^exp_[0-9a-f]{16}$`)

// Open loads the exports folder: ready exports whose zip is there are kept,
// queued and building ones (interrupted by a stop) become failed, leftover
// temp files are deleted. Call Start to run the queue.
func Open(opts Options) (*Manager, error) {
	if opts.TTL <= 0 {
		opts.TTL = DefaultTTL
	}
	if opts.Keep <= 0 {
		opts.Keep = DefaultKeep
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.janitor <= 0 {
		opts.janitor = time.Minute
	}
	m := &Manager{builder: newBuilder(opts), opts: opts, dir: filepath.Join(opts.DataDir, Dir), log: opts.Logger,
		entries: map[string]*entry{}, wake: make(chan struct{}, 1), stop: make(chan struct{})}
	if err := os.MkdirAll(m.dir, 0o750); err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	des, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	for _, de := range des {
		name := de.Name()
		switch {
		case strings.HasSuffix(name, ".tmp"):
			os.Remove(filepath.Join(m.dir, name))
		case strings.HasSuffix(name, ".json") && idRE.MatchString(strings.TrimSuffix(name, ".json")):
			b, err := atomicfile.ReadFile(filepath.Join(m.dir, name))
			var info Info
			if err != nil || json.Unmarshal(b, &info) != nil || info.ID+".json" != name {
				m.log.Warn("export: ignoring an unreadable export entry", "file", name)
				continue
			}
			e := &entry{info: info}
			switch info.State {
			case Queued, Building:
				e.info.State, e.info.Error = Failed, "Woodshed stopped before this export finished. Start it again."
				e.info.Progress = 0
				m.save(e)
			case Ready:
				if _, err := os.Stat(m.zipPath(info.ID)); err != nil {
					e.info.State, e.info.Error = Failed, "The export's zip file is missing."
					m.save(e)
				}
			}
			m.entries[info.ID] = e
		}
	}
	// Zips without an entry (the entry was lost) are deleted.
	for _, de := range des {
		if id, ok := strings.CutSuffix(de.Name(), ".zip"); ok && m.entries[id] == nil {
			os.Remove(filepath.Join(m.dir, de.Name()))
		}
	}
	return m, nil
}

// Start runs the build worker and the expiry janitor until Close.
func (m *Manager) Start() {
	m.wg.Add(2)
	go m.worker()
	go m.janitor()
	m.expire()
}

// Close cancels a running build (it becomes failed) and stops the queue.
func (m *Manager) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	for _, e := range m.entries {
		if e.cancel != nil {
			e.reason = "Woodshed stopped before this export finished. Start it again."
			e.cancel()
		}
	}
	m.mu.Unlock()
	close(m.stop)
	m.wg.Wait()
}

func (m *Manager) zipPath(id string) string { return filepath.Join(m.dir, id+".zip") }
func (m *Manager) tmpPath(id string) string { return filepath.Join(m.dir, id+".zip.tmp") }

// save writes an entry's state file (atomically). Callers hold mu or own e.
func (m *Manager) save(e *entry) {
	b, _ := json.MarshalIndent(e.info, "", "  ")
	p := filepath.Join(m.dir, e.info.ID+".json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err == nil {
		err = atomicfile.Rename(tmp, p)
		if err != nil {
			m.log.Warn("export: couldn't save an entry", "id", e.info.ID, "err", err)
		}
	}
}

func (m *Manager) event(level index.Level, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := m.idx.AddEvent(ctx, index.Event{Level: level, Kind: index.KindExport, Text: text}); err != nil {
		m.log.Warn("export: couldn't record an event", "err", err, "text", text)
	}
}

// filter is the search filter of a request.
func (r Request) filter() search.Filter {
	return search.Filter{Q: r.Q, Regex: r.Regex, Terms: r.Terms, Case: r.Case, Severities: r.Severities, Facilities: r.Facilities,
		From: r.From, To: r.To, Apps: r.Apps, Hosts: r.Hosts, ExcludeApps: r.ExcludeApps, ExcludeHosts: r.ExcludeHosts, Exclude: r.Exclude}
}

// resolve validates a request and returns its devices. A bundle's window and
// types are resolved into r (resolveBundle).
func (b *builder) resolve(ctx context.Context, r *Request) ([]string, error) {
	if r.IsBundle() {
		return b.resolveBundle(ctx, r)
	}
	if r.Kind != "" && r.Kind != KindExport {
		return nil, &RequestError{Msg: fmt.Sprintf("kind must be %q or %q, not %q.", KindExport, KindBundle, r.Kind)}
	}
	if r.From.IsZero() || r.To.IsZero() {
		return nil, &RequestError{Msg: `"from" and "to" are required.`}
	}
	if !r.From.Before(r.To) {
		return nil, &RequestError{Msg: `"from" must be before "to".`}
	}
	if r.AllDevices && (len(r.Devices) > 0 || r.Group != "" || r.Ungrouped) {
		return nil, &RequestError{Msg: "all_devices picks every device; don't send devices, group or ungrouped with it."}
	}
	if !r.AllDevices && len(r.Devices) == 0 && r.Group == "" && !r.Ungrouped {
		return nil, &RequestError{Msg: "Pick at least one device (devices, group, ungrouped or all_devices)."}
	}
	if r.Group != "" && r.Ungrouped {
		return nil, &RequestError{Msg: "group and ungrouped=true are alternatives; send one."}
	}
	for _, t := range r.TypesOrSyslog() {
		if datatype.Get(t) == nil {
			return nil, &RequestError{Msg: fmt.Sprintf("types: unknown data type %q.", t)}
		}
	}
	if len(r.TypesOrSyslog()) > 1 && !r.filtersEmpty() {
		return nil, &RequestError{Msg: "types: Filters apply to one data type; pick one, or leave the filters out."}
	}
	if err := b.eng.CheckFilter(r.typeFilter(r.TypesOrSyslog()[0])); err != nil {
		var qe *search.QueryError
		if errors.As(err, &qe) {
			return nil, &RequestError{Msg: qe.Msg}
		}
		return nil, err
	}
	devs, err := b.eng.ResolveDevices(ctx, r.Devices, r.Group, r.Ungrouped, r.ExcludeDevices)
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, &RequestError{Msg: "No device matches the selection."}
	}
	return devs, nil
}

// Estimate is POST /api/exports/estimate: an upper bound from the index.
func (m *Manager) Estimate(ctx context.Context, r Request) (search.Estimate, error) {
	devs, err := m.resolve(ctx, &r)
	if err != nil {
		return search.Estimate{}, err
	}
	var est search.Estimate
	for _, t := range r.TypesOrSyslog() {
		e, err := m.eng.Estimate(ctx, devs, r.typeFilter(t))
		if err != nil {
			return search.Estimate{}, err
		}
		est.Lines += e.Lines
		est.Bytes += e.Bytes
		est.Files += e.Files
		est.Parts = append(est.Parts, e.Parts...)
	}
	return est, nil
}

// filtersEmpty reports whether the request has no line filters (only the
// devices and the range).
func (r Request) filtersEmpty() bool {
	f := r.Filters
	return f.Q == "" && f.Exclude == "" && f.Severities == 0 && f.Facilities == 0 && len(f.Apps) == 0 && len(f.Hosts) == 0 &&
		len(f.ExcludeApps) == 0 && len(f.ExcludeHosts) == 0 && (f.Trap == nil || f.Trap.Empty()) &&
		(f.Poll == nil || f.Poll.Empty())
}

// Create queues an export.
func (m *Manager) Create(ctx context.Context, r Request) (Info, error) {
	devs, err := m.resolve(ctx, &r)
	if err != nil {
		return Info{}, err
	}
	info := Info{ID: newID(), Created: m.now().UTC(), Devices: devs,
		From: r.From.UTC(), To: r.To.UTC(), State: Queued, Filters: r.Filters, Named: r.Devices}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return Info{}, ErrClosed
	}
	m.seq++
	e := &entry{info: info, seq: m.seq}
	m.entries[info.ID] = e
	m.queue = append(m.queue, info.ID)
	m.save(e)
	m.mu.Unlock()
	select {
	case m.wake <- struct{}{}:
	default:
	}
	what := "Export"
	if r.IsBundle() {
		what = "Incident bundle"
	}
	m.event(index.LevelInfo, fmt.Sprintf("%s %s queued: %s, %s to %s.", what, info.ID, plural(len(devs), "device"),
		info.From.Format(time.RFC3339), info.To.Format(time.RFC3339)))
	return info, nil
}

// newID returns a new export ID.
func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "exp_" + hex.EncodeToString(b[:])
}

// List returns every export, newest first.
func (m *Manager) List() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	es := make([]*entry, 0, len(m.entries))
	for _, e := range m.entries {
		es = append(es, e)
	}
	sort.Slice(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if !a.info.Created.Equal(b.info.Created) {
			return a.info.Created.After(b.info.Created)
		}
		if a.seq != b.seq {
			return a.seq > b.seq
		}
		return a.info.ID > b.info.ID
	})
	out := make([]Info, len(es))
	for i, e := range es {
		out[i] = e.info
	}
	return out
}

// Get returns one export.
func (m *Manager) Get(id string) (Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[id]
	if e == nil {
		return Info{}, ErrNotFound
	}
	return e.info, nil
}

// Download opens a ready export's zip. ErrNotFound for an unknown or expired
// export, ErrNotReady for one that isn't ready.
func (m *Manager) Download(id string) (*os.File, Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[id]
	if e == nil || e.info.State == Expired {
		return nil, Info{}, ErrNotFound
	}
	if e.info.State != Ready {
		return nil, e.info, ErrNotReady
	}
	// Shared-delete on Windows: expiry or the low-disk guard can still delete
	// the zip while a download is running.
	f, err := logfile.OpenFile(m.zipPath(id))
	if err != nil {
		return nil, e.info, ErrNotFound
	}
	return f, e.info, nil
}

// Delete cancels a queued or building export, or deletes a ready (or failed,
// or expired) one. The entry is gone afterwards.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	e := m.entries[id]
	if e == nil {
		m.mu.Unlock()
		return ErrNotFound
	}
	state := e.info.State
	delete(m.entries, id)
	m.queue = removeID(m.queue, id)
	if e.cancel != nil {
		e.gone, e.reason = true, "cancelled"
		e.cancel()
	}
	m.mu.Unlock()
	if state != Building {
		m.removeFiles(id)
	}
	switch state {
	case Queued, Building:
		m.event(index.LevelInfo, fmt.Sprintf("Export %s cancelled.", id))
	default:
		m.event(index.LevelInfo, fmt.Sprintf("Export %s deleted.", id))
	}
	return nil
}

func (m *Manager) removeFiles(id string) {
	os.Remove(m.zipPath(id))
	os.Remove(m.tmpPath(id))
	os.Remove(filepath.Join(m.dir, id+".json"))
}

func removeID(q []string, id string) []string {
	out := q[:0]
	for _, x := range q {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

// Reclaim frees disk for the store's low-disk guard: it deletes ready exports,
// oldest first, then cancels a running build, until need bytes are freed. It
// returns the bytes freed.
func (m *Manager) Reclaim(need uint64) uint64 {
	m.mu.Lock()
	var ready []*entry
	var building *entry
	for _, e := range m.entries {
		switch {
		case e.info.State == Ready:
			ready = append(ready, e)
		case e.cancel != nil:
			building = e
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].info.ReadyAt.Before(*ready[j].info.ReadyAt) })
	var freed uint64
	var deleted []string
	for _, e := range ready {
		if freed >= need {
			break
		}
		if st, err := os.Stat(m.zipPath(e.info.ID)); err == nil {
			freed += uint64(st.Size())
		}
		os.Remove(m.zipPath(e.info.ID))
		e.info.State, e.info.Error, e.info.Progress = Expired, "Deleted early to free disk space.", 0
		m.save(e)
		deleted = append(deleted, e.info.ID)
	}
	var cancelled string
	if freed < need && building != nil {
		if st, err := os.Stat(m.tmpPath(building.info.ID)); err == nil {
			freed += uint64(st.Size())
		}
		building.reason = "Stopped to free disk space: the disk holding the data folder is nearly full."
		building.cancel()
		cancelled = building.info.ID
	}
	m.mu.Unlock()
	for _, id := range deleted {
		m.event(index.LevelWarn, fmt.Sprintf("Export %s deleted early to free disk space.", id))
	}
	if cancelled != "" {
		m.event(index.LevelWarn, fmt.Sprintf("Export %s stopped to free disk space.", cancelled))
	}
	return freed
}

// worker builds queued exports one at a time.
func (m *Manager) worker() {
	defer m.wg.Done()
	for {
		m.mu.Lock()
		var e *entry
		var ctx context.Context
		if len(m.queue) > 0 && !m.closed {
			e = m.entries[m.queue[0]]
			m.queue = m.queue[1:]
			if e != nil {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(context.Background())
				e.cancel = cancel
				e.info.State = Building
				m.save(e)
			}
		}
		m.mu.Unlock()
		if e != nil {
			m.run(ctx, e)
			continue
		}
		select {
		case <-m.stop:
			return
		case <-m.wake:
		}
	}
}

// run builds one export and records the outcome.
func (m *Manager) run(ctx context.Context, e *entry) {
	id := e.info.ID
	t0 := time.Now()
	res, err := m.build(ctx, e)
	m.mu.Lock()
	e.cancel = nil
	gone, reason := e.gone, e.reason
	if err != nil {
		os.Remove(m.tmpPath(id))
		if gone {
			m.mu.Unlock()
			m.removeFiles(id)
			return
		}
		msg := err.Error()
		if ctx.Err() != nil && reason != "" {
			msg = reason
		}
		e.info.State, e.info.Error, e.info.Progress = Failed, msg, 0
		m.save(e)
		m.mu.Unlock()
		m.log.Warn("export failed", "id", id, "err", msg)
		m.event(index.LevelError, fmt.Sprintf("Export %s failed: %s", id, msg))
		return
	}
	now := m.now().UTC()
	exp := now.Add(m.opts.TTL)
	e.info.State, e.info.Progress, e.info.Lines, e.info.SizeBytes = Ready, 1, res.lines, res.size
	e.info.ReadyAt, e.info.ExpiresAt = &now, &exp
	m.save(e)
	m.mu.Unlock()
	m.log.Info("export ready", "id", id, "lines", res.lines, "bytes", res.size, "took", time.Since(t0).Round(time.Millisecond))
	m.event(index.LevelInfo, fmt.Sprintf("Export %s ready: %d lines in %s, %d bytes (took %s).", id, res.lines,
		plural(res.files, "file"), res.size, time.Since(t0).Round(time.Millisecond)))
}

func (m *Manager) setProgress(e *entry, p float64) {
	m.mu.Lock()
	if p > e.info.Progress && p < 1 {
		e.info.Progress = p
	}
	m.mu.Unlock()
}

// janitor expires ready exports and forgets old expired and failed ones.
func (m *Manager) janitor() {
	defer m.wg.Done()
	t := time.NewTicker(m.opts.janitor)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.expire()
		}
	}
}

// expire runs one expiry pass.
func (m *Manager) expire() {
	now := m.now()
	var expired []string
	m.mu.Lock()
	for id, e := range m.entries {
		switch e.info.State {
		case Ready:
			if e.info.ExpiresAt != nil && !now.Before(*e.info.ExpiresAt) {
				os.Remove(m.zipPath(id))
				e.info.State = Expired
				m.save(e)
				expired = append(expired, id)
			}
		case Expired, Failed:
			since := e.info.Created
			if e.info.ExpiresAt != nil {
				since = *e.info.ExpiresAt
			}
			if now.Sub(since) > m.opts.Keep {
				delete(m.entries, id)
				m.removeFiles(id)
			}
		}
	}
	m.mu.Unlock()
	sort.Strings(expired)
	for _, id := range expired {
		m.event(index.LevelInfo, fmt.Sprintf("Export %s expired and was deleted.", id))
	}
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}

// ValidID reports whether id has the form of an export ID. Routes take only IDs,
// never paths.
func ValidID(id string) bool { return idRE.MatchString(id) }
