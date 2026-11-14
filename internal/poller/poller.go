// Package poller is Woodshed's SNMP poller (SPEC §12): it polls the targets
// an administrator configured, every interval, for a small fixed set of OIDs
// (the presets) plus each target's custom OIDs, and writes one poll record per
// cycle per part (internal/pollrec) through the store's poll stream, with
// rates computed at write time and restarts marked.
//
// It's the only package besides the update check that sends packets to hosts
// Woodshed didn't hear from first, and it sends only SNMP Get, GetNext and
// GetBulk requests (and v3 discovery), only to configured targets, from one
// ephemeral UDP socket that exists only while there is a target to poll. With
// no targets it opens no socket and sends nothing.
package poller

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// Sink stores records: the server's store, poll stream.
type Sink interface {
	// Write stores one record for device, received at at.
	Write(device netip.Addr, at time.Time, rec []byte) error
	// Paused reports whether the disk guard has paused writing (the poller
	// stops polling until it resumes).
	Paused() bool
	// AddHourly merges headline rollups (poll_hourly).
	AddHourly(rows []pollrec.Hourly)
}

// Creds gives a target's secrets, from the credentials store.
type Creds interface {
	// Community is a v1/v2c target's community (nil: none stored).
	Community(targetID string) []byte
	// User is a v3 user by name.
	User(name string) (snmp.User, bool)
}

// EngineStore records a target's learned v3 engine (the index).
type EngineStore interface {
	SetEngine(targetID string, engineID []byte, boots, engineTime int64, at time.Time)
}

// Target is one configured target.
type Target struct {
	ID string
	Settings
	// Engine is the cached v3 engine: its ID, boots, and engine time at the
	// wall-clock time EngineAt.
	EngineID    []byte
	EngineBoots int64
	EngineTime  int64
	EngineAt    time.Time
}

// Options configures a Poller.
type Options struct {
	Sink    Sink
	Creds   Creds
	Engines EngineStore // may be nil
	// Now is the clock (time.Now by default); readings must carry the
	// monotonic clock.
	Now         func() time.Time
	Concurrency int // at most this many devices at once (32 by default)
	// OnSend, when set, sees every destination a request goes to (tests).
	OnSend func(netip.AddrPort)
	Logger *slog.Logger
	// Event records a line in Woodshed's events log (may be nil).
	Event func(level, text string)
}

// Target states (docs/api.md state.status).
const (
	StateOK         = "ok"
	StateFailing    = "failing"
	StateBackingOff = "backing_off"
	StateDisabled   = "disabled"
	StatePending    = "pending"
)

// Backoff (SPEC §12.2): after this many failed cycles in a row the interval
// doubles, up to MaxBackoff.
const (
	BackoffAfter = 3
	MaxBackoff   = 10 * time.Minute
)

// UnreachableAfter is how long a target must fail before the banner names it.
const UnreachableAfter = 10 * time.Minute

// State is a target's live state (docs/api.md state).
type State struct {
	Status           string     `json:"status"`
	LastAttempt      *time.Time `json:"last_attempt"`
	LastOK           *time.Time `json:"last_ok"`
	FailingSince     *time.Time `json:"failing_since"`
	BackoffS         int        `json:"backoff_s"`
	Error            string     `json:"error"`
	RTTms            int64      `json:"rtt_ms"`
	EngineID         string     `json:"engine_id"`
	SysName          string     `json:"sys_name"`
	SysDescr         string     `json:"sys_descr"`
	HCCounters       bool       `json:"hc_counters"`
	HostResources    bool       `json:"host_resources"`
	InterfacesPolled int        `json:"interfaces_polled"`
	InterfacesTotal  int        `json:"interfaces_total"`
	// WrongSource is an address replies came from instead of the target's.
	WrongSource string `json:"wrong_source,omitempty"`
}

// Poller polls the configured targets. Safe for concurrent use.
type Poller struct {
	o   Options
	now func() time.Time
	log *slog.Logger

	mu      sync.Mutex
	targets map[string]*tstate
	sock    *socket
	conc    int
	sem     chan struct{}
	wake    chan struct{}
	rollup  *pollrec.Rollup
	hour    hourStats
	closed  bool
	tests   int // test polls holding the socket

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	done   chan struct{}
}

// New starts a poller with no targets (it sends nothing until SetTargets).
func New(o Options) *Poller {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 32
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Poller{o: o, now: o.Now, log: o.Logger, targets: map[string]*tstate{}, conc: o.Concurrency,
		sem: make(chan struct{}, o.Concurrency), wake: make(chan struct{}, 1), rollup: pollrec.NewRollup(),
		ctx: ctx, cancel: cancel, done: make(chan struct{})}
	go p.run()
	return p
}

// Close stops polling, waits for running cycles and flushes the rollups.
func (p *Poller) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()
	p.cancel()
	<-p.done
	p.wg.Wait()
	p.flushRollup()
	p.mu.Lock()
	if p.sock != nil {
		p.sock.close()
		p.sock = nil
	}
	p.mu.Unlock()
}

// SetConcurrency changes how many devices are polled at once.
func (p *Poller) SetConcurrency(n int) {
	if n <= 0 {
		n = 32
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if n != p.conc {
		p.conc = n
		p.sem = make(chan struct{}, n) // running cycles release into the old one
	}
}

func (p *Poller) kick() {
	select {
	case p.wake <- struct{}{}:
	default:
	}
}

// offset is a target's start offset within its interval (a hash of its ID),
// so cycles don't bunch.
func offset(id string, interval time.Duration) time.Duration {
	h := fnv.New64a()
	h.Write([]byte(id))
	if interval <= 0 {
		return 0
	}
	return time.Duration(h.Sum64() % uint64(interval))
}

// SetTargets replaces the target set. A target whose settings didn't change
// keeps its state (its schedule, previous samples and engine); a new or
// changed one starts within one interval.
func (p *Poller) SetTargets(ts []Target) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	now := p.now()
	keep := map[string]bool{}
	for _, t := range ts {
		keep[t.ID] = true
		old := p.targets[t.ID]
		if old != nil && old.sameSettings(t) {
			old.mu.Lock()
			old.t.Settings = t.Settings
			old.mu.Unlock()
			continue
		}
		st := newState(t)
		st.nextDue = now.Add(offset(t.ID, st.interval()))
		if old != nil {
			old.mu.Lock()
			old.retired = true
			old.mu.Unlock()
		}
		p.targets[t.ID] = st
	}
	for id, st := range p.targets {
		if !keep[id] {
			st.mu.Lock()
			st.retired = true
			st.mu.Unlock()
			delete(p.targets, id)
		}
	}
	p.syncSocketLocked()
	p.kick()
}

// syncSocketLocked opens the socket when a target is enabled and closes it
// when none is (and no test poll holds it).
func (p *Poller) syncSocketLocked() {
	any := false
	for _, st := range p.targets {
		if st.t.Enabled {
			any = true
			break
		}
	}
	if any && p.sock == nil {
		s, err := openSocket(p.o.OnSend)
		if err != nil {
			p.log.Warn("poller: can't open the UDP socket", "err", err)
			return
		}
		p.sock = s
		for _, st := range p.targets {
			st.mu.Lock()
			st.attach(s)
			st.mu.Unlock()
		}
	}
	if !any && p.sock != nil && p.tests == 0 {
		p.sock.close()
		p.sock = nil
	}
}

// run is the scheduler: it dispatches each target's cycle when it's due.
func (p *Poller) run() {
	defer close(p.done)
	flush := time.NewTicker(time.Minute)
	defer flush.Stop()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		next := p.dispatchDue()
		d := time.Until(next)
		if next.IsZero() || d > time.Minute {
			d = time.Minute
		}
		if d < 0 {
			d = 0
		}
		timer.Reset(d)
		select {
		case <-p.ctx.Done():
			return
		case <-p.wake:
		case <-timer.C:
		case <-flush.C:
			p.flushRollup()
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
}

// dispatchDue starts every due cycle and returns the next due time.
func (p *Poller) dispatchDue() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	var next time.Time
	paused := p.o.Sink != nil && p.o.Sink.Paused()
	for _, st := range p.targets {
		st.mu.Lock()
		if !st.t.Enabled || st.sock == nil {
			st.mu.Unlock()
			continue
		}
		if !now.Before(st.nextDue) {
			due := st.nextDue
			iv := st.effInterval()
			switch {
			case paused:
				// Nothing could be stored: no poll, no record.
			case st.busy:
				st.overruns++
				p.hour.add(now, "", true)
				go p.writeOverrun(st)
			default:
				st.busy = true
				p.wg.Add(1)
				go p.cycle(st, p.sem)
			}
			st.nextDue = due.Add(iv)
			if !st.nextDue.After(now) {
				// Fell behind (a long pause or a suspended machine): start again
				// from now rather than firing every missed interval.
				st.nextDue = now.Add(iv)
			}
		}
		if next.IsZero() || st.nextDue.Before(next) {
			next = st.nextDue
		}
		st.mu.Unlock()
	}
	return next
}

// cycle runs one target's cycle in a concurrency slot.
func (p *Poller) cycle(st *tstate, sem chan struct{}) {
	defer p.wg.Done()
	select {
	case sem <- struct{}{}:
	case <-p.ctx.Done():
		st.mu.Lock()
		st.busy = false
		st.mu.Unlock()
		return
	}
	defer func() { <-sem }()
	c := newCycleRun(p, st)
	c.run(p.ctx)
	st.mu.Lock()
	st.busy = false
	st.mu.Unlock()
	p.kick()
}

func (p *Poller) writeOverrun(st *tstate) {
	st.mu.Lock()
	cycle := st.cycle + 1
	st.cycle = cycle
	dev, cred, iv := st.device, st.credLabel(), st.t.IntervalS
	st.mu.Unlock()
	rec := pollrec.New(pollrec.KindStatus, cycle).Str("status", "overrun").
		Str("detail", "skipped: the previous cycle was still running").Str("cred", cred).Int("interval_s", int64(iv)).Record()
	if p.o.Sink != nil {
		_ = p.o.Sink.Write(dev, p.now().UTC(), pollrec.Format(rec))
	}
}

func (p *Poller) flushRollup() {
	p.mu.Lock()
	rows := p.rollup.Take()
	p.mu.Unlock()
	if len(rows) > 0 && p.o.Sink != nil {
		p.o.Sink.AddHourly(rows)
	}
}

func (p *Poller) addCycle(c *pollrec.Cycle) {
	p.mu.Lock()
	p.rollup.AddCycle(c)
	p.mu.Unlock()
}

// FlushRollups writes the rollups held so far (tests; Close does it too).
func (p *Poller) FlushRollups() { p.flushRollup() }

// States are every target's live state, by ID.
func (p *Poller) States() map[string]State {
	p.mu.Lock()
	sts := make([]*tstate, 0, len(p.targets))
	for _, st := range p.targets {
		sts = append(sts, st)
	}
	p.mu.Unlock()
	now := p.now()
	out := make(map[string]State, len(sts))
	for _, st := range sts {
		st.mu.Lock()
		out[st.t.ID] = st.state(now)
		st.mu.Unlock()
	}
	return out
}

// Summary is GET /api/poll.
type Summary struct {
	Targets    int        `json:"targets"`
	Answering  int        `json:"answering"`
	Failing    int        `json:"failing"`
	BackingOff int        `json:"backing_off"`
	LastCycle  *time.Time `json:"last_cycle"`
	Hour       HourTotals `json:"hour"`
}

// HourTotals are the last hour's counts.
type HourTotals struct {
	Cycles    int64            `json:"cycles"`
	Failures  map[string]int64 `json:"failures"`
	Overruns  int64            `json:"overruns"`
	Unmatched int64            `json:"unmatched"`
}

// Summary returns the polling state.
func (p *Poller) Summary() Summary {
	states := p.States()
	now := p.now()
	s := Summary{Targets: len(states)}
	for _, st := range states {
		switch st.Status {
		case StateOK:
			s.Answering++
		case StateFailing:
			s.Failing++
		case StateBackingOff:
			s.BackingOff++
		}
		if st.LastAttempt != nil && (s.LastCycle == nil || st.LastAttempt.After(*s.LastCycle)) {
			t := *st.LastAttempt
			s.LastCycle = &t
		}
	}
	p.mu.Lock()
	s.Hour = p.hour.totals(now)
	p.mu.Unlock()
	return s
}

// Unreachable lists the targets that haven't answered for UnreachableAfter,
// as "device (address)" (the poll_unreachable banner), sorted.
func (p *Poller) Unreachable() []string {
	p.mu.Lock()
	sts := make([]*tstate, 0, len(p.targets))
	for _, st := range p.targets {
		sts = append(sts, st)
	}
	p.mu.Unlock()
	now := p.now()
	var out []string
	for _, st := range sts {
		st.mu.Lock()
		if st.t.Enabled && st.fails > 0 && !st.failingSince.IsZero() && now.Sub(st.failingSince) >= UnreachableAfter {
			name := st.t.DeviceID
			if st.t.Address != st.t.DeviceID {
				name += " (" + st.t.Address + ")"
			}
			out = append(out, name)
		}
		st.mu.Unlock()
	}
	sort.Strings(out)
	return out
}

// ---- the last hour's counts ----

// hourStats keeps 60 one-minute buckets.
type hourStats struct {
	b [60]minuteStats
}

type minuteStats struct {
	minute    int64
	cycles    int64
	overruns  int64
	unmatched int64
	failures  map[string]int64
}

func (h *hourStats) bucket(now time.Time) *minuteStats {
	m := now.Unix() / 60
	b := &h.b[m%60]
	if b.minute != m {
		*b = minuteStats{minute: m}
	}
	return b
}

// add counts a cycle (failure "" is an answered one) or an overrun.
func (h *hourStats) add(now time.Time, failure string, overrun bool) {
	b := h.bucket(now)
	switch {
	case overrun:
		b.overruns++
	default:
		b.cycles++
		if failure != "" {
			if b.failures == nil {
				b.failures = map[string]int64{}
			}
			b.failures[failure]++
		}
	}
}

func (h *hourStats) totals(now time.Time) HourTotals {
	m := now.Unix() / 60
	t := HourTotals{Failures: map[string]int64{}}
	for _, b := range h.b {
		if b.minute <= m-60 || b.minute > m {
			continue
		}
		t.Cycles += b.cycles
		t.Overruns += b.overruns
		t.Unmatched += b.unmatched
		for k, v := range b.failures {
			t.Failures[k] += v
		}
	}
	return t
}

// Overruns is the last hour's skipped cycles (the poll_overrun banner).
func (p *Poller) Overruns() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.hour.totals(p.now()).Overruns
}

// unmatchedSeen moves the socket's unmatched count into the hour's buckets.
func (p *Poller) noteUnmatched() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sock == nil {
		return
	}
	if n := p.sock.unmatched.Swap(0); n > 0 {
		p.hour.bucket(p.now()).unmatched += n
	}
}

var errClosed = errors.New("poller: closed")
