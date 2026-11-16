// Package trap is Woodshed's SNMP trap receiver (SPEC §11.2): it decodes the
// SNMP listener's datagrams (internal/snmp), applies the community list and
// USM, stores each trap as a record line through the store's trap stream
// (SPEC §11.2.4), and answers informs and v3 discovery once the store has
// them, within the reply limits. It also keeps the v3 users and communities
// (creds.go), Woodshed's own engine (snmp-engine.json), the MIB folder, and
// the counts and failing senders that Settings and `woodshed snmp status`
// show.
package trap

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// Settings are the receiver's settings from [listeners.snmp].
type Settings struct {
	AnswerInforms bool
	StrictTime    bool   // v3_strict_time
	EngineID      string // hex override; "" is the generated one
	MIBDir        string // "" is <data>/mibs
}

// Options configures a Receiver.
type Options struct {
	DataDir string
	// Write stores one trap record (the store's trap stream); an error means it
	// wasn't stored (paused, refused by the device limits) and no reply goes out.
	Write func(m model.Message) error
	// TryWrite is Write that never blocks (the store's TryWriteType), for
	// TryHandle: false means it did nothing and the write must happen later.
	// Without it TryHandle always leaves the write to its finish func.
	TryWrite func(m model.Message) (ok bool, err error)
	// Admit admits a sender as Write would, without storing anything: v3
	// discovery Reports go only to admitted senders.
	Admit func(addr netip.Addr) error
	// Event records a service event (MIB load problems, unreadable credentials).
	Event  func(level, text string)
	Clock  func() time.Time
	Logger *slog.Logger

	// ReplyPerSource and ReplyTotal override the reply limits (replies a
	// second; 0: ReplyPerSource and ReplyTotal, SPEC §11.2.3). Only `woodshed
	// bench` sets them, to measure informs from one sender past the limit.
	ReplyPerSource, ReplyTotal int
}

// Receiver handles the SNMP listener's datagrams. Safe for concurrent use.
type Receiver struct {
	opts Options

	mu      sync.Mutex // guards set, engine, usm swaps and the MIB state
	set     Settings
	engine  *snmp.Engine
	usm     atomic.Pointer[snmp.USM]
	answer  atomic.Bool
	creds   *creds
	comms   atomic.Pointer[communitySet]
	mibInfo api.SNMPMIBs

	counts   counts
	failures failures
	limit    limiter
	dups     dedup
	lastSeen atomic.Int64 // unix ms of the latest trap (for status)
}

// Open loads the engine (raising its boots), the credentials and the MIB
// folder. A credentials file that can't be read is an error; one that reads
// but won't decrypt (another machine or account) isn't: its users show as
// needing their passphrases again.
func Open(opts Options, set Settings) (*Receiver, error) {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Event == nil {
		opts.Event = func(string, string) {}
	}
	r := &Receiver{opts: opts, set: set}
	r.failures.m = map[netip.Addr]*failure{}
	r.limit.per = map[netip.Addr]*bucket{}
	r.limit.perSource, r.limit.all = ReplyPerSource, ReplyTotal
	if opts.ReplyPerSource > 0 {
		r.limit.perSource = float64(opts.ReplyPerSource)
	}
	if opts.ReplyTotal > 0 {
		r.limit.all = float64(opts.ReplyTotal)
	}
	r.dups.seen = map[string]time.Time{}
	r.answer.Store(set.AnswerInforms)
	override, err := engineOverride(set.EngineID)
	if err != nil {
		return nil, err
	}
	e, err := snmp.LoadEngine(filepath.Join(opts.DataDir, snmp.EngineFile), override, opts.Clock())
	if err != nil {
		return nil, fmt.Errorf("trap: engine: %w", err)
	}
	r.engine = e
	if r.creds, err = openCreds(opts.DataDir); err != nil {
		return nil, err
	}
	if !r.creds.readable {
		opts.Event("warn", fmt.Sprintf("the SNMP v3 users' passphrases can't be decrypted here (the data folder came from "+
			"another machine or account); %d users need their passphrases again in Settings", len(r.creds.users)))
	}
	if err := r.applyUsers(); err != nil {
		return nil, err
	}
	cs := r.creds.communitySet()
	r.comms.Store(&cs)
	r.ReloadMIBs()
	return r, nil
}

func engineOverride(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	id, err := snmp.ParseEngineID(s)
	if err != nil {
		return nil, fmt.Errorf("trap: listeners.snmp.engine_id: %w", err)
	}
	return id, nil
}

// newUSM builds a USM for the engine with the current users and time rule.
func (r *Receiver) newUSM(e *snmp.Engine) (*snmp.USM, error) {
	u := snmp.NewUSM(e)
	u.SetStrictTime(r.set.StrictTime)
	if err := u.SetUsers(r.creds.snmpUsers(e.ID)); err != nil {
		return nil, fmt.Errorf("trap: v3 users: %s", sanitize(err))
	}
	return u, nil
}

// applyUsers rebuilds the USM's users from the credentials store.
func (r *Receiver) applyUsers() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if u := r.usm.Load(); u != nil {
		if err := u.SetUsers(r.creds.snmpUsers(r.engine.ID)); err != nil {
			return fmt.Errorf("trap: v3 users: %s", sanitize(err))
		}
		return nil
	}
	u, err := r.newUSM(r.engine)
	if err != nil {
		return err
	}
	r.usm.Store(u)
	return nil
}

// Apply changes the settings live: answering informs and the time rule at
// once; a new engine ID makes a new USM (same boots, same start); a new MIB
// folder is read.
func (r *Receiver) Apply(set Settings) error {
	r.mu.Lock()
	old := r.set
	r.set = set
	r.answer.Store(set.AnswerInforms)
	if old.EngineID != set.EngineID {
		override, err := engineOverride(set.EngineID)
		if err != nil {
			r.set = old
			r.mu.Unlock()
			return err
		}
		id := override
		if id == nil {
			// Back to the stored ID: read it without raising boots again.
			if st, err := readEngineID(r.opts.DataDir); err == nil {
				id = st
			} else {
				id = r.engine.ID
			}
		}
		e := &snmp.Engine{ID: id, Boots: r.engine.Boots, Start: r.engine.Start}
		u, err := r.newUSM(e)
		if err != nil {
			r.set = old
			r.mu.Unlock()
			return err
		}
		r.engine = e
		r.usm.Store(u)
	} else if old.StrictTime != set.StrictTime {
		r.usm.Load().SetStrictTime(set.StrictTime)
	}
	mibChanged := old.MIBDir != set.MIBDir
	r.mu.Unlock()
	if mibChanged {
		r.ReloadMIBs()
	}
	return nil
}

func readEngineID(dataDir string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, snmp.EngineFile))
	if err != nil {
		return nil, err
	}
	var st struct {
		EngineID string `json:"engine_id"`
	}
	if err := jsonUnmarshal(b, &st); err != nil {
		return nil, err
	}
	return snmp.ParseEngineID(st.EngineID)
}

// MIBFolder is the MIB folder in effect.
func (r *Receiver) MIBFolder() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.set.MIBDir != "" {
		return r.set.MIBDir
	}
	return filepath.Join(r.opts.DataDir, "mibs")
}

// ReloadMIBs reads the MIB folder again (POST /api/snmp/mibs/reload) and makes
// the set the one names come from. The default folder is created when it's
// missing; a folder the user named that's missing is an error in the report.
func (r *Receiver) ReloadMIBs() api.SNMPMIBs {
	dir := r.MIBFolder()
	r.mu.Lock()
	custom := r.set.MIBDir != ""
	r.mu.Unlock()
	if !custom {
		_ = os.MkdirAll(dir, 0o750)
	}
	set, rep := snmp.LoadMIBDir(dir)
	datatype.SetMIBs(set)
	info := api.SNMPMIBs{Dir: dir, Files: rep.Files, Names: rep.Names, LoadedAt: r.opts.Clock().UTC()}
	if _, err := os.Stat(dir); custom && err != nil {
		info.Errors = append(info.Errors, api.SNMPMIBError{File: dir, Message: "the MIB folder can't be read: " + osErrText(err)})
	}
	for _, e := range rep.Errors {
		info.Errors = append(info.Errors, api.SNMPMIBError{File: e.File, Line: e.Line, Message: e.Msg})
	}
	for _, e := range rep.Warnings {
		info.Warnings = append(info.Warnings, api.SNMPMIBError{File: e.File, Line: e.Line, Message: e.Msg})
	}
	r.mu.Lock()
	r.mibInfo = info
	r.mu.Unlock()
	if len(info.Errors) > 0 {
		r.opts.Event("warn", fmt.Sprintf("%d MIB files in %s didn't load; Settings → SNMP traps lists them", len(info.Errors), dir))
	}
	return info
}

// MIBs is the MIB folder's state.
func (r *Receiver) MIBs() api.SNMPMIBs {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mibInfo
}

// Engine is Woodshed's own engine now.
func (r *Receiver) Engine() api.SNMPEngine {
	r.mu.Lock()
	e := r.engine
	r.mu.Unlock()
	return api.SNMPEngine{ID: hex.EncodeToString(e.ID), Boots: e.Boots, Time: e.Time(r.opts.Clock())}
}

// Counts are the last 24 hours' counts.
func (r *Receiver) Counts() api.SNMPCounts { return r.counts.snapshot(r.opts.Clock()) }

// Failures are the failing senders of the last 24 hours, most first.
func (r *Receiver) Failures() []api.SNMPFailure { return r.failures.list(r.opts.Clock()) }

// ---- users and communities ----

// Users lists the v3 users, without secrets.
func (r *Receiver) Users() []api.SNMPUser { return r.creds.list() }

// UnreadableUsers counts users whose secrets don't decrypt here.
func (r *Receiver) UnreadableUsers() int { return r.creds.unreadable() }

// PutUser adds (update == "") or changes a user, and applies it at once.
func (r *Receiver) PutUser(in api.SNMPUserInput, update string) (api.SNMPUser, error) {
	r.mu.Lock()
	self := r.engine.ID
	r.mu.Unlock()
	u, err := r.creds.put(in, update, self)
	if err != nil {
		return api.SNMPUser{}, err
	}
	return u, r.applyUsers()
}

// DeleteUser removes a user.
func (r *Receiver) DeleteUser(name string) error {
	if err := r.creds.remove(name); err != nil {
		return err
	}
	return r.applyUsers()
}

// Communities are the accept list as "#hash8" values.
func (r *Receiver) Communities() []string { return r.creds.communityHashes() }

// SetCommunities replaces the accept list (see creds.setCommunities).
func (r *Receiver) SetCommunities(in []string) error {
	if _, err := r.creds.setCommunities(in); err != nil {
		return err
	}
	cs := r.creds.communitySet()
	r.comms.Store(&cs)
	return nil
}

// PollCommunity is a poll target's stored community (nil: none).
func (r *Receiver) PollCommunity(targetID string) []byte { return r.creds.pollCommunity(targetID) }

// SetPollCommunity stores a poll target's community; nil removes it.
func (r *Receiver) SetPollCommunity(targetID string, community []byte) error {
	return r.creds.setPollCommunity(targetID, community)
}

// PollUser is a v3 user with its secrets, for polling.
func (r *Receiver) PollUser(name string) (snmp.User, bool) { return r.creds.pollUser(name) }

// HasUser reports whether a v3 user exists (its secrets readable or not).
func (r *Receiver) HasUser(name string) bool { return r.creds.hasUser(name) }

// ---- the datagrams ----

// Handle decodes, stores and answers one datagram (listen.Options.Trap).
func (r *Receiver) Handle(p *listen.TrapPacket) { r.handle(p, false) }

// TryHandle is Handle for the SNMP reader's fast path (listen.Options.TrapTry):
// it never blocks. When storing the record would block it returns a func that
// stores it and sends what follows (an inform's Response), for the listener's
// drainer to call; everything before the write (decoding, counting) happens
// here, exactly once.
func (r *Receiver) TryHandle(p *listen.TrapPacket) (finish func()) { return r.handle(p, true) }

func (r *Receiver) handle(p *listen.TrapPacket, try bool) (finish func()) {
	now := p.Received
	addr := p.From.Addr().Unmap()
	usm := r.usm.Load()
	m := snmp.Decode(p.Raw, usm, now)
	r.counts.inc(&r.counts.received, now) // every datagram, stored or not (by_status counts the stored ones)

	// The community list (v1/v2c): a refusal is counted, not stored (SPEC §11.2.2).
	if (m.Version == snmp.V1 || m.Version == snmp.V2c) && m.Community != nil && !r.comms.Load().allows(m.Community) {
		p.Refuse(listen.RejectCommunity)
		r.counts.inc(&r.counts.refused, now)
		return
	}
	// A v3 discovery probe gets a Report and isn't stored (§11.8, build 4).
	if m.Discovery {
		if r.opts.Admit == nil || r.opts.Admit(addr) == nil {
			r.reply(p, usm, m, now, true)
		}
		return
	}
	dup := false
	if m.PDU != nil && m.PDU.Type == snmp.PDUInform && m.PDU.HasRequestID() {
		key := addr.String() + "|" + m.Version.String() + "|" + string(m.ContextEngineID) + "|" + strconv.FormatInt(m.PDU.RequestID, 10)
		dup = r.dups.check(key, now)
	}
	rec := snmp.FormatRecord(nil, m, snmp.RecordOptions{Names: datatype.MIBs(), Dup: dup})
	r.counts.addStatus(now, m.Status)
	if m.TimeResync {
		r.counts.inc(&r.counts.resyncs, now)
		r.failures.resync(addr, now)
	}
	if m.Status != snmp.StatusOK && m.Status != snmp.StatusUnexpectedPDU && !(m.TimeResync && m.Status == snmp.StatusNotInTime) {
		r.failures.add(addr, now, m.Status.String(), m.Err)
	}
	msg := model.Message{Received: now, Sender: addr, Raw: rec}
	if try {
		if r.opts.TryWrite == nil {
			return func() { r.stored(p, usm, m, now, r.opts.Write(msg)) }
		}
		ok, err := r.opts.TryWrite(msg)
		if !ok {
			return func() { r.stored(p, usm, m, now, r.opts.Write(msg)) }
		}
		r.stored(p, usm, m, now, err)
		return nil
	}
	r.stored(p, usm, m, now, r.opts.Write(msg))
	return nil
}

// stored is what follows the write of m's record: an error means it isn't in
// the store's buffer, so it's never acknowledged (the sender retries).
func (r *Receiver) stored(p *listen.TrapPacket, usm *snmp.USM, m *snmp.Message, now time.Time, err error) {
	if err != nil {
		return
	}
	r.lastSeen.Store(now.UnixMilli())
	switch m.Reply {
	case snmp.ReplyResponse:
		if r.answer.Load() {
			r.reply(p, usm, m, now, false)
		}
	case snmp.ReplyReport:
		r.reply(p, usm, m, now, true)
	}
}

// reply builds and sends what m calls for, within the reply limits.
func (r *Receiver) reply(p *listen.TrapPacket, usm *snmp.USM, m *snmp.Message, now time.Time, report bool) {
	if !r.limit.allow(p.From.Addr().Unmap(), now) {
		r.counts.inc(&r.counts.limited, now)
		return
	}
	b, err := usm.Reply(m, now)
	if err != nil || b == nil {
		if err != nil {
			r.opts.Logger.Debug("trap: no reply", "from", p.From.Addr(), "err", sanitize(err))
		}
		return
	}
	if err := p.Reply(b); err != nil {
		r.opts.Logger.Debug("trap: reply failed", "to", p.From, "err", err)
		return
	}
	if report {
		r.counts.inc(&r.counts.discovery, now)
	} else {
		r.counts.inc(&r.counts.answered, now)
	}
}

// LastTrap is the received time of the latest stored trap (zero if none).
func (r *Receiver) LastTrap() time.Time {
	if ms := r.lastSeen.Load(); ms != 0 {
		return time.UnixMilli(ms).UTC()
	}
	return time.Time{}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// osErrText is an OS error without the path (the folder is shown beside it).
func osErrText(err error) string {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}
