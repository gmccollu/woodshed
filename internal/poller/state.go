package poller

import (
	"encoding/hex"
	"net/netip"
	"reflect"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// tstate is one target's live state. mu guards everything; a cycle holds it
// only between requests, never across one.
type tstate struct {
	mu       sync.Mutex
	t        Target
	device   netip.Addr // the device ID's address: the store's sender
	to       netip.AddrPort
	sock     *socket
	tr       *transport
	sess     *snmp.Session
	sessErr  string // why the session can't be made (a missing credential)
	credHash string // the community's #hash8

	nextDue  time.Time
	busy     bool
	dropSess bool // drop the session when the running cycle ends (credentials changed)
	retired  bool // replaced or removed: a running cycle writes nothing more
	cycle    uint64
	overruns int64

	fails        int
	failingSince time.Time
	lastAttempt  time.Time
	lastOK       time.Time
	lastErr      string
	rtt          time.Duration

	// What the agent has, learned at the hourly refresh.
	infoAt     time.Time // the last system-info read (zero: never)
	sysName    string
	sysDescr   string
	hrAt       time.Time // the last HOST-RESOURCES refresh
	hrUptimeOK bool      // hrSystemUptime answers
	hrCPUs     []uint32  // hrProcessorLoad indexes
	hrRAM      []uint32  // hrStorage rows of type hrStorageRam
	ifAt       time.Time // the last interface table refresh
	ifRefresh  bool      // refresh at the next cycle (a discontinuity)
	hc         bool      // ifXTable HC counters answer
	ifx        bool      // ifXTable answers at all
	ifTotal    int
	ifs        []*ifState // the polled interfaces, by index

	// Previous samples.
	prevUp     uint64
	prevUpAt   time.Time
	havePrevUp bool
	prevHr     uint64
	havePrevHr bool
	oidPrev    map[string]sample

	storedEngine []byte // the engine ID last given to the EngineStore
	storedBoots  int64
}

// ifState is one polled interface.
type ifState struct {
	index    int
	name     string
	descr    string
	alias    string
	speed    uint64 // Mb/s
	prev     map[string]sample
	oper     string
	discTime uint64
	haveDisc bool
}

func newState(t Target) *tstate {
	st := &tstate{t: t, oidPrev: map[string]sample{}}
	st.device, _ = DeviceAddr(t.DeviceID)
	if a, err := netip.ParseAddr(t.Address); err == nil {
		st.to = netip.AddrPortFrom(a.Unmap(), uint16(t.Port))
	}
	return st
}

// sameSettings reports whether t polls the same way (only then is the state
// kept).
func (st *tstate) sameSettings(t Target) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return reflect.DeepEqual(st.t.Settings, t.Settings)
}

func (st *tstate) interval() time.Duration { return time.Duration(st.t.IntervalS) * time.Second }

// effInterval is the interval with backoff: after BackoffAfter failed cycles
// in a row it doubles for each further failure, up to MaxBackoff.
func (st *tstate) effInterval() time.Duration {
	iv := st.interval()
	if iv <= 0 {
		iv = time.Minute
	}
	if st.fails < BackoffAfter {
		return iv
	}
	cap := max(MaxBackoff, iv)
	for i := BackoffAfter - 1; i < st.fails && iv < cap; i++ {
		iv *= 2
	}
	return min(iv, cap)
}

// attach gives the target the shared socket.
func (st *tstate) attach(s *socket) {
	st.sock = s
	st.tr = s.transport(st.to)
	st.sess = nil
}

// credLabel names the target's credential for status lines: the community's
// hash prefix, or the v3 user.
func (st *tstate) credLabel() string {
	if st.t.Version == "3" {
		return st.t.V3User
	}
	return st.credHash
}

func (st *tstate) state(now time.Time) State {
	s := State{Status: StatePending, Error: st.lastErr, RTTms: st.rtt.Milliseconds(), SysName: st.sysName, SysDescr: st.sysDescr,
		HCCounters: st.hc, HostResources: st.hrUptimeOK || len(st.hrCPUs) > 0 || len(st.hrRAM) > 0,
		InterfacesPolled: len(st.ifs), InterfacesTotal: st.ifTotal}
	ts := func(t time.Time) *time.Time {
		if t.IsZero() {
			return nil
		}
		u := t.UTC().Truncate(time.Millisecond)
		return &u
	}
	s.LastAttempt, s.LastOK, s.FailingSince = ts(st.lastAttempt), ts(st.lastOK), ts(st.failingSince)
	switch {
	case !st.t.Enabled:
		s.Status = StateDisabled
	case st.lastAttempt.IsZero():
		s.Status = StatePending
	case st.fails == 0:
		s.Status = StateOK
	case st.fails < BackoffAfter:
		s.Status = StateFailing
	default:
		s.Status = StateBackingOff
		s.BackoffS = int(st.effInterval() / time.Second)
	}
	if st.sess != nil {
		if e := st.sess.Engine(); e.Known() {
			s.EngineID = hex.EncodeToString(e.ID)
		}
	} else if len(st.t.EngineID) > 0 {
		s.EngineID = hex.EncodeToString(st.t.EngineID)
	}
	if st.tr != nil {
		if w := st.tr.wrong(); w.IsValid() {
			s.WrongSource = w.String()
		}
	}
	_ = now
	return s
}
