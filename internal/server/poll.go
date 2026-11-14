package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/poller"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The SNMP poller's service side (SPEC §12): the poller, wired to the store's
// poll stream, the credentials store and the index; the API's poll routes;
// the poll banners; and the devices' polled flag.

// pollSide holds the poller and its readers.
type pollSide struct {
	p  *poller.Poller
	rd *poller.Reader

	testMu    sync.Mutex
	testing   map[string]bool // test polls running, by target ID
	testTimes []time.Time     // the last minute's tests (10 a minute in all)

	targetsMu sync.Mutex // serializes target changes with SetTargets
}

// Test poll limits (docs/api.md "Test poll").
const (
	pollTestsPerMinute = 10
)

// openPoll creates the poller (it sends nothing until startPoll gives it the
// targets).
func (b *backend) openPoll(cfg config.Config, onSend func(netip.AddrPort), unit time.Duration) {
	b.poll = &pollSide{testing: map[string]bool{}}
	b.poll.p = poller.New(poller.Options{
		Sink:         pollSink{b},
		Creds:        pollCreds{b},
		Engines:      pollEngines{b},
		Concurrency:  cfg.Poll.Concurrency,
		OnSend:       onSend,
		IntervalUnit: unit,
		Logger:       b.log,
		Event: func(level, text string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = b.idx.AddEvent(ctx, index.Event{Level: index.Level(level), Kind: index.KindError, Text: text})
		},
	})
	b.poll.rd = &poller.Reader{Idx: b.idx, DataDir: cfg.Storage.DataDir}
}

// startPoll loads the targets from the index and starts polling them.
func (b *backend) startPoll(ctx context.Context) error {
	if b.poll == nil {
		return nil
	}
	return b.applyPollTargets(ctx)
}

// closePoll stops polling (before the store closes) and flushes the rollups.
func (b *backend) closePoll() {
	if b.poll != nil {
		b.poll.p.Close()
	}
}

// applyPollTargets gives the poller the index's targets.
func (b *backend) applyPollTargets(ctx context.Context) error {
	b.poll.targetsMu.Lock()
	defer b.poll.targetsMu.Unlock()
	rows, err := b.idx.PollTargets(ctx)
	if err != nil {
		return err
	}
	var ts []poller.Target
	for _, r := range rows {
		t, err := pollTargetOf(r)
		if err != nil {
			b.log.Warn("poll target unreadable, skipped", "id", r.ID, "err", err)
			continue
		}
		ts = append(ts, t)
	}
	b.poll.p.SetTargets(ts)
	return nil
}

func pollTargetOf(r index.PollTarget) (poller.Target, error) {
	var s poller.Settings
	if err := json.Unmarshal([]byte(r.Settings), &s); err != nil {
		return poller.Target{}, err
	}
	s.Address, s.Port, s.DeviceID = r.Address, r.Port, r.DeviceID
	return poller.Target{ID: r.ID, Settings: s, EngineID: r.EngineID, EngineBoots: r.EngineBoots, EngineTime: r.EngineTime,
		EngineAt: r.EngineAt}, nil
}

// ---- the poller's dependencies ----

type pollSink struct{ b *backend }

func (s pollSink) Write(dev netip.Addr, at time.Time, rec []byte) error {
	b := s.b
	if b.firstMsg.Load() == 0 {
		b.firstMsg.CompareAndSwap(0, at.UnixMilli())
	}
	if pollrec.KindOf(rec) != pollrec.KindStatus {
		b.live.add(dev, at)
	}
	return b.store.WriteType(logfile.TypePoll, model.Message{Received: at, Sender: dev, Raw: rec})
}

func (s pollSink) Paused() bool { return s.b.store.Paused() }

func (s pollSink) AddHourly(rows []pollrec.Hourly) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.b.idx.AddPollHourly(ctx, rows); err != nil {
		s.b.log.Warn("poll rollups not saved", "err", err)
	}
}

type pollCreds struct{ b *backend }

func (c pollCreds) Community(id string) []byte {
	if c.b.snmp == nil {
		return nil
	}
	return c.b.snmp.rcv.PollCommunity(id)
}

func (c pollCreds) User(name string) (snmp.User, bool) {
	if c.b.snmp == nil {
		return snmp.User{}, false
	}
	return c.b.snmp.rcv.PollUser(name)
}

type pollEngines struct{ b *backend }

func (e pollEngines) SetEngine(id string, engineID []byte, boots, etime int64, at time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.b.idx.SetPollEngine(ctx, id, engineID, boots, etime, at); err != nil {
		e.b.log.Warn("poll engine not saved", "id", id, "err", err)
	}
}

// ---- api.PollBackend ----

func (b *backend) apiPollTarget(r index.PollTarget, states map[string]poller.State) (api.PollTarget, error) {
	t, err := pollTargetOf(r)
	if err != nil {
		return api.PollTarget{}, err
	}
	out := api.PollTarget{ID: r.ID, Settings: t.Settings, Version: r.Version}
	if t.Version != "3" && b.snmp != nil {
		out.CommunitySet = len(b.snmp.rcv.PollCommunity(r.ID)) > 0
	}
	st, ok := states[r.ID]
	if !ok {
		st = poller.State{Status: poller.StatePending}
		if !t.Enabled {
			st.Status = poller.StateDisabled
		}
	}
	out.State = st
	return out, nil
}

func (b *backend) PollTargets(ctx context.Context) ([]api.PollTarget, error) {
	rows, err := b.idx.PollTargets(ctx)
	if err != nil {
		return nil, err
	}
	states := b.poll.p.States()
	out := make([]api.PollTarget, 0, len(rows))
	for _, r := range rows {
		t, err := b.apiPollTarget(r, states)
		if err != nil {
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

func (b *backend) PollTarget(ctx context.Context, id string) (api.PollTarget, error) {
	r, err := b.idx.PollTarget(ctx, id)
	if errors.Is(err, index.ErrNotFound) {
		return api.PollTarget{}, api.ErrNotFound
	}
	if err != nil {
		return api.PollTarget{}, err
	}
	return b.apiPollTarget(r, b.poll.p.States())
}

func (b *backend) hasV3User(name string) bool { return b.snmp != nil && b.snmp.rcv.HasUser(name) }

// deviceTaken refuses a second target for one device: each device's poll
// files hold one target's cycles (SPEC §12.3; decided, build 2026-11-15).
func (b *backend) deviceTaken(ctx context.Context, s poller.Settings, exceptID string) error {
	rows, err := b.idx.PollTargets(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.ID != exceptID && r.Address == s.Address && r.Port == s.Port {
			return api.ErrPollTargetExists
		}
	}
	for _, r := range rows {
		if r.DeviceID == s.DeviceID && r.ID != exceptID {
			return &poller.ValidationError{Errors: map[string]string{"device_id": fmt.Sprintf(
				"is already polled by another target (%s port %d); a device has one poll target", r.Address, r.Port)}}
		}
	}
	return nil
}

func settingsJSON(s poller.Settings) (string, error) {
	raw, err := json.Marshal(s)
	return string(raw), err
}

func (b *backend) CreatePollTarget(ctx context.Context, in poller.Input) (api.PollTarget, error) {
	cfg := b.config()
	s, community, err := poller.Resolve(in, nil, cfg.Poll, false, b.hasV3User)
	if err != nil {
		return api.PollTarget{}, err
	}
	if err := b.deviceTaken(ctx, s, ""); err != nil {
		return api.PollTarget{}, err
	}
	raw, err := settingsJSON(s)
	if err != nil {
		return api.PollTarget{}, err
	}
	r, err := b.idx.CreatePollTarget(ctx, index.PollTarget{Address: s.Address, Port: s.Port, DeviceID: s.DeviceID, Settings: raw},
		cfg.Poll.MaxTargets, b.now())
	switch {
	case errors.Is(err, index.ErrPollTargetExists):
		return api.PollTarget{}, api.ErrPollTargetExists
	case errors.Is(err, index.ErrPollTargetLimit):
		return api.PollTarget{}, api.ErrPollTargetLimit
	case err != nil:
		return api.PollTarget{}, err
	}
	if community != nil {
		if err := b.snmp.rcv.SetPollCommunity(r.ID, community); err != nil {
			_ = b.idx.DeletePollTarget(ctx, r.ID)
			return api.PollTarget{}, err
		}
	}
	b.pollEvent(fmt.Sprintf("SNMP polling added: %s port %d (device %s, SNMPv%s)", s.Address, s.Port, s.DeviceID, s.Version))
	if err := b.applyPollTargets(ctx); err != nil {
		return api.PollTarget{}, err
	}
	return b.PollTarget(ctx, r.ID)
}

func (b *backend) UpdatePollTarget(ctx context.Context, id string, in poller.Input, ifVersion int64) (api.PollTarget, error) {
	cur, err := b.idx.PollTarget(ctx, id)
	if errors.Is(err, index.ErrNotFound) {
		return api.PollTarget{}, api.ErrNotFound
	}
	if err != nil {
		return api.PollTarget{}, err
	}
	ct, err := pollTargetOf(cur)
	if err != nil {
		return api.PollTarget{}, err
	}
	stored := b.snmp != nil && len(b.snmp.rcv.PollCommunity(id)) > 0
	s, community, err := poller.Resolve(in, &ct.Settings, b.config().Poll, stored, b.hasV3User)
	if err != nil {
		return api.PollTarget{}, err
	}
	if err := b.deviceTaken(ctx, s, id); err != nil {
		return api.PollTarget{}, err
	}
	raw, err := settingsJSON(s)
	if err != nil {
		return api.PollTarget{}, err
	}
	_, err = b.idx.UpdatePollTarget(ctx, index.PollTarget{ID: id, Address: s.Address, Port: s.Port, DeviceID: s.DeviceID, Settings: raw},
		ifVersion, b.now())
	switch {
	case errors.Is(err, index.ErrNotFound):
		return api.PollTarget{}, api.ErrNotFound
	case errors.Is(err, index.ErrPollTargetChanged):
		return api.PollTarget{}, api.ErrPollTargetChanged
	case errors.Is(err, index.ErrPollTargetExists):
		return api.PollTarget{}, api.ErrPollTargetExists
	case err != nil:
		return api.PollTarget{}, err
	}
	credChanged := false
	switch {
	case s.Version == "3" && stored:
		// Now a v3 target: the community isn't needed any more.
		if err := b.snmp.rcv.SetPollCommunity(id, nil); err != nil {
			return api.PollTarget{}, err
		}
	case community != nil:
		if err := b.snmp.rcv.SetPollCommunity(id, community); err != nil {
			return api.PollTarget{}, err
		}
		credChanged = true
	}
	b.pollEvent(fmt.Sprintf("SNMP polling changed: %s port %d (device %s, SNMPv%s)", s.Address, s.Port, s.DeviceID, s.Version))
	if err := b.applyPollTargets(ctx); err != nil {
		return api.PollTarget{}, err
	}
	if credChanged {
		b.poll.p.CredsChanged()
	}
	return b.PollTarget(ctx, id)
}

func (b *backend) DeletePollTarget(ctx context.Context, id string) error {
	cur, err := b.idx.PollTarget(ctx, id)
	if errors.Is(err, index.ErrNotFound) {
		return api.ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := b.idx.DeletePollTarget(ctx, id); err != nil {
		if errors.Is(err, index.ErrNotFound) {
			return api.ErrNotFound
		}
		return err
	}
	if b.snmp != nil {
		if err := b.snmp.rcv.SetPollCommunity(id, nil); err != nil {
			b.log.Warn("the poll target's community wasn't removed", "id", id, "err", err)
		}
	}
	b.pollEvent(fmt.Sprintf("SNMP polling removed: %s port %d (device %s)", cur.Address, cur.Port, cur.DeviceID))
	return b.applyPollTargets(ctx)
}

func (b *backend) pollEvent(text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = b.idx.AddEvent(ctx, index.Event{Level: index.LevelInfo, Kind: index.KindAuth, Text: text})
}

// TestPoll runs a test poll: of a body (not saved; a missing community uses
// the stored one when the body names a stored target's id), or of a stored
// target. At most one per target at a time and 10 a minute in all.
func (b *backend) TestPoll(ctx context.Context, in poller.Input, id string) (poller.TestResult, error) {
	var cur *poller.Settings
	if id != "" {
		r, err := b.idx.PollTarget(ctx, id)
		if errors.Is(err, index.ErrNotFound) {
			return poller.TestResult{}, api.ErrNotFound
		}
		if err != nil {
			return poller.TestResult{}, err
		}
		t, err := pollTargetOf(r)
		if err != nil {
			return poller.TestResult{}, err
		}
		cur = &t.Settings
	}
	stored := id != "" && b.snmp != nil && len(b.snmp.rcv.PollCommunity(id)) > 0
	in.ID = nil
	s, community, err := poller.Resolve(in, cur, b.config().Poll, stored, b.hasV3User)
	if err != nil {
		return poller.TestResult{}, err
	}
	if community == nil && stored {
		community = b.snmp.rcv.PollCommunity(id)
	}
	var user *snmp.User
	if s.Version == "3" {
		u, ok := b.snmp.rcv.PollUser(s.V3User)
		if !ok {
			return poller.TestResult{}, &poller.ValidationError{Errors: map[string]string{"v3_user": "its secrets can't be read here; enter its passphrases again in Settings → SNMP traps"}}
		}
		user = &u
	}
	key := id
	if key == "" {
		key = fmt.Sprintf("%s:%d", s.Address, s.Port)
	}
	ps := b.poll
	ps.testMu.Lock()
	now := time.Now()
	ps.testTimes = slices.DeleteFunc(ps.testTimes, func(t time.Time) bool { return now.Sub(t) >= time.Minute })
	switch {
	case ps.testing[key]:
		ps.testMu.Unlock()
		return poller.TestResult{}, &api.RetryAfterError{After: 2 * time.Second, Msg: "A test poll of this device is already running."}
	case len(ps.testTimes) >= pollTestsPerMinute:
		wait := time.Minute - now.Sub(ps.testTimes[0])
		ps.testMu.Unlock()
		return poller.TestResult{}, &api.RetryAfterError{After: wait, Msg: "At most 10 test polls a minute. Try again shortly."}
	}
	ps.testing[key] = true
	ps.testTimes = append(ps.testTimes, now)
	ps.testMu.Unlock()
	defer func() {
		ps.testMu.Lock()
		delete(ps.testing, key)
		ps.testMu.Unlock()
	}()
	return ps.p.Test(ctx, s, community, user), nil
}

// polledDevices maps each polled device to its target's state.
func (b *backend) polledDevices(ctx context.Context) (map[string]string, map[string]string, error) {
	rows, err := b.idx.PollTargets(ctx)
	if err != nil {
		return nil, nil, err
	}
	states := b.poll.p.States()
	status, target := map[string]string{}, map[string]string{}
	for _, r := range rows {
		st := states[r.ID].Status
		if st == "" {
			st = poller.StatePending
		}
		if _, ok := status[r.DeviceID]; !ok || st == poller.StateOK {
			status[r.DeviceID] = st
			target[r.DeviceID] = r.ID
		}
	}
	return status, target, nil
}

// markPolled sets the devices' polled flag and poll_status.
func (b *backend) markPolled(ctx context.Context, ds []api.Device) {
	if b.poll == nil {
		return
	}
	status, _, err := b.polledDevices(ctx)
	if err != nil {
		b.log.Warn("reading the poll targets failed", "err", err)
		return
	}
	for i := range ds {
		if st, ok := status[ds[i].ID]; ok {
			ds[i].Polled, ds[i].PollStatus = true, st
		}
	}
}

func (b *backend) PollSeries(ctx context.Context, q poller.SeriesQuery) (poller.SeriesResult, error) {
	return b.poll.rd.Series(ctx, q)
}

func (b *backend) PollTimeline(ctx context.Context, q api.PollTimelineQuery) (poller.Timeline, error) {
	status, _, err := b.polledDevices(ctx)
	if err != nil {
		return poller.Timeline{}, err
	}
	var sel []string
	switch {
	case len(q.Devices) > 0:
		sel = q.Devices
	case q.Group != "" || q.Ungrouped:
		groups := b.groups.Load()
		for id := range status {
			g := ""
			if groups != nil {
				g = (*groups)[id]
			}
			if (q.Ungrouped && g == "") || (q.Group != "" && strings.EqualFold(g, q.Group)) {
				sel = append(sel, id)
			}
		}
	default:
		for id := range status {
			sel = append(sel, id)
		}
	}
	var polled []string
	for _, d := range sel {
		if _, ok := status[d]; ok && !slices.Contains(polled, d) {
			polled = append(polled, d)
		}
	}
	slices.Sort(polled)
	return b.poll.rd.Timeline(ctx, polled, q.From, q.To, q.Bucket)
}

func (b *backend) PollDevice(ctx context.Context, id string, from, to time.Time) (poller.Panel, error) {
	status, targets, err := b.polledDevices(ctx)
	if err != nil {
		return poller.Panel{}, err
	}
	tid, ok := targets[id]
	if !ok {
		return poller.Panel{}, api.ErrNotFound
	}
	_ = status
	p, err := b.poll.rd.Panel(ctx, id, from, to)
	if err != nil {
		return p, err
	}
	p.TargetID = tid
	if r, err := b.idx.PollTarget(ctx, tid); err == nil {
		p.Address = r.Address
	}
	// What the poller knows now fills what the window doesn't show.
	if st, ok := b.poll.p.States()[tid]; ok {
		if p.System.SysName == "" {
			p.System.SysName = st.SysName
		}
		if p.System.SysDescr == "" {
			p.System.SysDescr = st.SysDescr
		}
		if p.HCCounters == nil && st.LastOK != nil {
			hc := st.HCCounters
			p.HCCounters = &hc
		}
		if p.HostResources == nil && st.LastOK != nil {
			hr := st.HostResources
			p.HostResources = &hr
		}
		if p.InterfacesLeftOut == 0 && st.InterfacesTotal > st.InterfacesPolled {
			p.InterfacesLeftOut = st.InterfacesTotal - st.InterfacesPolled
		}
	}
	return p, nil
}

func (b *backend) PollState(ctx context.Context) (poller.Summary, error) {
	return b.poll.p.Summary(), nil
}

// pollBanners are poll_unreachable and poll_overrun (SPEC §12.5).
func (b *backend) pollBanners() []api.Banner {
	if b.poll == nil {
		return nil
	}
	var out []api.Banner
	if u := b.poll.p.Unreachable(); len(u) > 0 {
		names := u
		more := ""
		if len(names) > 5 {
			more = fmt.Sprintf(" and %d more", len(names)-5)
			names = names[:5]
		}
		text := fmt.Sprintf("%d polled devices aren't answering: %s%s. Devices → Polling shows why.", len(u), strings.Join(names, ", "), more)
		if len(u) == 1 {
			text = fmt.Sprintf("1 polled device isn't answering: %s. Devices → Polling shows why.", names[0])
		}
		out = append(out, api.Banner{Kind: "poll_unreachable", Level: api.LevelWarn, Text: text})
	}
	if n := b.poll.p.Overruns(); n > 0 {
		cycles := "cycles were"
		if n == 1 {
			cycles = "cycle was"
		}
		text := fmt.Sprintf("%d polling %s skipped in the last hour because polling couldn't keep up. "+
			"Set a longer interval for the slow devices, or raise poll.concurrency in Settings → Polling.", n, cycles)
		out = append(out, api.Banner{Kind: "poll_overrun", Level: api.LevelWarn, Text: text})
	}
	return out
}

// pollCredsChanged makes the poller read the v3 users again (one was added,
// changed or deleted in Settings → SNMP traps).
func (b *backend) pollCredsChanged() {
	if b.poll != nil {
		b.poll.p.CredsChanged()
	}
}

// applyPollSettings applies a settings save's [poll] changes.
func (b *backend) applyPollSettings(cur, next config.Poll) {
	if b.poll != nil && !reflect.DeepEqual(cur, next) && cur.Concurrency != next.Concurrency {
		b.poll.p.SetConcurrency(next.Concurrency)
	}
}

// RunStatePoll is the run-state file's polling part (docs/api.md "Run-state
// file"), for `woodshed status`.
type RunStatePoll struct {
	Targets      int                  `json:"targets"`
	Answering    int                  `json:"answering"`
	NotAnswering []RunStatePollTarget `json:"not_answering"`
	LastCycle    *time.Time           `json:"last_cycle"`
}

// RunStatePollTarget is a target that isn't answering.
type RunStatePollTarget struct {
	DeviceID string    `json:"device_id"`
	Address  string    `json:"address"`
	Since    time.Time `json:"since"`
}

// runStatePoll is nil without targets.
func (b *backend) runStatePoll() *RunStatePoll {
	if b.poll == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := b.idx.PollTargets(ctx)
	if err != nil || len(rows) == 0 {
		return nil
	}
	states := b.poll.p.States()
	rs := &RunStatePoll{Targets: len(rows), NotAnswering: []RunStatePollTarget{}}
	for _, r := range rows {
		st := states[r.ID]
		switch st.Status {
		case poller.StateOK:
			rs.Answering++
		case poller.StateFailing, poller.StateBackingOff:
			since := time.Time{}
			if st.FailingSince != nil {
				since = st.FailingSince.Truncate(time.Second)
			}
			rs.NotAnswering = append(rs.NotAnswering, RunStatePollTarget{DeviceID: r.DeviceID, Address: r.Address, Since: since})
		}
		if st.LastAttempt != nil && (rs.LastCycle == nil || st.LastAttempt.After(*rs.LastCycle)) {
			t := st.LastAttempt.Truncate(time.Second)
			rs.LastCycle = &t
		}
	}
	return rs
}
