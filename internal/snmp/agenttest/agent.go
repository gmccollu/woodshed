// Package agenttest is a tiny SNMP agent for tests (SPEC §12.8): a responder
// on loopback with a programmable view (the system group, ifTable and
// ifXTable, HOST-RESOURCES CPU and memory, extra scalars and tables), counters
// that advance at a set rate on its own clock, and hooks to inject what the
// poller must handle: a Counter32 wrap, a Counter64 drop, a discontinuity
// time change, an interface renamed under its index, an agent restart, a
// reboot, a sysUpTime wrap, tooBig, noSuchObject, replies from another
// address, slowness and silence. It's authoritative for SNMPv3 with every
// auth and priv protocol internal/snmp supports.
//
// It answers Get, GetNext and GetBulk only; anything else is counted
// (Unexpected) and never answered. It's imported only by tests and never
// ships in the product binary.
package agenttest

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// Interface is one row of ifTable/ifXTable. Rates are per second.
type Interface struct {
	Index     int
	Name      string // ifName
	Descr     string // ifDescr
	Alias     string // ifAlias
	SpeedMbps uint64 // ifHighSpeed
	Oper      int    // ifOperStatus: 1 up, 2 down, …; 0 is up

	InBps, OutBps           float64 // octet counters advance at bps/8 a second
	InUcastPps, OutUcastPps float64
	InMcastPps, OutMcastPps float64
	InBcastPps, OutBcastPps float64
	InErrPs, OutErrPs       float64
	InDiscPs, OutDiscPs     float64
}

// Options configures an Agent.
type Options struct {
	// Addr is where it listens ("127.0.0.1:0" by default).
	Addr string
	// Community is the v1/v2c community it answers (any other gets nothing,
	// as real agents do); "" answers no v1/v2c request.
	Community string
	// Users are the v3 users it knows (their Level is the lowest accepted).
	Users []snmp.User
	// EngineID and Boots are its v3 engine (a fresh ID and boots 1 by
	// default).
	EngineID []byte
	Boots    int64

	SysName, SysDescr string
	SysObjectID       snmp.OID

	Interfaces []Interface
	// NoIfXTable leaves out ifXTable (no HC counters, no names), like an old
	// agent.
	NoIfXTable bool
	// HostResources serves hrSystemUptime, hrProcessorLoad (CPUs) and one
	// hrStorageRam row (MemUsed and MemTotal bytes, in 1,024-byte units).
	HostResources     bool
	CPUs              []int
	MemUsed, MemTotal uint64

	// Extra are more objects, by OID: scalars (ending in .0) or table cells.
	Extra map[string]snmp.Value

	// Clock is its clock (time.Now by default): uptimes, counters and the v3
	// engine time read it.
	Clock func() time.Time
}

// counter is a value that advances at a rate from a base time.
type counter struct {
	base float64
	rate float64 // per second
	at   time.Time
}

func (c *counter) value(now time.Time) float64 {
	return c.base + c.rate*now.Sub(c.at).Seconds()
}

func (c *counter) setRate(now time.Time, r float64) {
	c.base, c.at, c.rate = c.value(now), now, r
}

func (c *counter) add(now time.Time, d float64) {
	c.base, c.at = c.value(now)+d, now
}

// ifState is an interface's live state.
type ifState struct {
	Interface
	ctr  [12]counter // the 12 counters, ctrIn… below
	off  [12]float64 // added to the 32-bit forms only (for a wrap)
	disc uint64      // ifCounterDiscontinuityTime (ticks)
}

const (
	ctrInOctets = iota
	ctrOutOctets
	ctrInUcast
	ctrOutUcast
	ctrInMcast
	ctrOutMcast
	ctrInBcast
	ctrOutBcast
	ctrInErr
	ctrOutErr
	ctrInDisc
	ctrOutDisc
)

// Agent is a running test agent.
type Agent struct {
	opts  Options
	conn  *net.UDPConn
	other *net.UDPConn // for wrong-source replies
	guard *net.UDPConn // [::]:port, held so no wildcard socket takes our port (nil where refused)

	mu         sync.Mutex
	usm        *snmp.USM
	engine     *snmp.Engine
	sysStart   time.Time // sysUpTime counts from here
	upOff      uint64    // ticks added to sysUpTime (a wrap test)
	hrStart    time.Time
	ifs        []*ifState
	cpus       []int
	memUsed    uint64
	extra      map[string]snmp.Value
	view       []entry // sorted by OID
	noSuch     []snmp.OID
	maxVbs     int
	delay      time.Duration
	silent     bool
	wrongSrc   bool
	requests   map[string]int
	unexpected int
	sources    map[netip.AddrPort]int

	done chan struct{}
}

// entry is one object in the view; val computes its value now.
type entry struct {
	oid snmp.OID
	val func(a *Agent, now time.Time) snmp.Value
}

// Start starts an agent on loopback.
func Start(opts Options) (*Agent, error) {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:0"
	}
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.EngineID == nil {
		opts.EngineID = snmp.NewEngineID()
	}
	if opts.Boots == 0 {
		opts.Boots = 1
	}
	if opts.SysName == "" {
		opts.SysName = "test-agent"
	}
	if opts.SysDescr == "" {
		opts.SysDescr = "Woodshed test agent"
	}
	if opts.SysObjectID == nil {
		opts.SysObjectID = snmp.OID{1, 3, 6, 1, 4, 1, 32473, 2, 1}
	}
	ap, err := netip.ParseAddrPort(opts.Addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(ap))
	if err != nil {
		return nil, err
	}
	// macOS lets a dual-stack socket on [::] take an ephemeral port that a
	// socket on 127.0.0.1 already holds; a poller whose socket got this
	// agent's port would send to itself-shadowed 127.0.0.1:port and its replies
	// would go to the agent. Holding [::]:port too keeps the port to us (where
	// the OS refuses that bind, as Linux does, it can't happen anyway).
	guard, _ := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: conn.LocalAddr().(*net.UDPAddr).Port})
	now := opts.Clock()
	a := &Agent{opts: opts, conn: conn, guard: guard, sysStart: now, hrStart: now, cpus: slices.Clone(opts.CPUs), memUsed: opts.MemUsed,
		extra: map[string]snmp.Value{}, requests: map[string]int{}, sources: map[netip.AddrPort]int{}, done: make(chan struct{})}
	for k, v := range opts.Extra {
		a.extra[k] = v
	}
	for _, in := range opts.Interfaces {
		st := &ifState{Interface: in}
		if st.Oper == 0 {
			st.Oper = 1
		}
		rates := []float64{in.InBps / 8, in.OutBps / 8, in.InUcastPps, in.OutUcastPps, in.InMcastPps, in.OutMcastPps,
			in.InBcastPps, in.OutBcastPps, in.InErrPs, in.OutErrPs, in.InDiscPs, in.OutDiscPs}
		for i := range st.ctr {
			st.ctr[i] = counter{rate: rates[i], at: now}
		}
		a.ifs = append(a.ifs, st)
	}
	sort.Slice(a.ifs, func(i, j int) bool { return a.ifs[i].Index < a.ifs[j].Index })
	if err := a.newEngine(opts.Boots, now); err != nil {
		conn.Close()
		return nil, err
	}
	a.buildView()
	go a.serve()
	return a, nil
}

func (a *Agent) newEngine(boots int64, now time.Time) error {
	a.engine = &snmp.Engine{ID: a.opts.EngineID, Boots: boots, Start: now}
	a.usm = snmp.NewUSM(a.engine)
	if len(a.opts.Users) > 0 {
		return a.usm.SetUsers(a.opts.Users)
	}
	return nil
}

// Addr is the agent's address and port.
func (a *Agent) Addr() netip.AddrPort { return a.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

// EngineID is its v3 engine ID.
func (a *Agent) EngineID() []byte { return a.opts.EngineID }

// Boots is its v3 engineBoots now.
func (a *Agent) Boots() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.engine.Boots
}

// Close stops it.
func (a *Agent) Close() error {
	err := a.conn.Close()
	<-a.done
	if a.guard != nil {
		a.guard.Close()
	}
	a.mu.Lock()
	if a.other != nil {
		a.other.Close()
	}
	a.mu.Unlock()
	return err
}

// ---- the hooks ----

func (a *Agent) iface(index int) *ifState {
	for _, s := range a.ifs {
		if s.Index == index {
			return s
		}
	}
	panic(fmt.Sprintf("agenttest: no interface %d", index))
}

// SetRates changes an interface's octet rates (bits per second).
func (a *Agent) SetRates(index int, inBps, outBps float64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	s := a.iface(index)
	s.ctr[ctrInOctets].setRate(now, inBps/8)
	s.ctr[ctrOutOctets].setRate(now, outBps/8)
}

// AddErrors adds to an interface's error and discard counters.
func (a *Agent) AddErrors(index int, inErr, outErr, inDisc, outDisc uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	s := a.iface(index)
	s.ctr[ctrInErr].add(now, float64(inErr))
	s.ctr[ctrOutErr].add(now, float64(outErr))
	s.ctr[ctrInDisc].add(now, float64(inDisc))
	s.ctr[ctrOutDisc].add(now, float64(outDisc))
}

// WrapCounter32 sets the 32-bit octet counters of an interface (ifInOctets,
// ifOutOctets) to within margin octets of 2^32, so they wrap at the rate.
func (a *Agent) WrapCounter32(index int, margin uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	s := a.iface(index)
	for _, c := range []int{ctrInOctets, ctrOutOctets} {
		cur := uint64(s.ctr[c].value(now)+s.off[c]) % (1 << 32)
		s.off[c] += float64((1<<32 - margin) - cur)
	}
}

// DropCounter64 lowers an interface's HC octet counters by d (a Counter64
// going down: a discontinuity, never a wrap).
func (a *Agent) DropCounter64(index int, d uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	s := a.iface(index)
	for _, c := range []int{ctrInOctets, ctrOutOctets} {
		s.ctr[c].add(now, -float64(d))
	}
}

// BumpDiscontinuity sets an interface's ifCounterDiscontinuityTime to the
// current sysUpTime.
func (a *Agent) BumpDiscontinuity(index int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.iface(index).disc = a.sysUpTimeLocked(a.opts.Clock())
}

// Rename gives an interface another ifName (and ifDescr) under its index.
func (a *Agent) Rename(index int, name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.iface(index)
	s.Name, s.Descr = name, name
}

// SetOper sets an interface's ifOperStatus (1 up, 2 down).
func (a *Agent) SetOper(index, oper int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.iface(index).Oper = oper
}

// SetCPU sets the processors' loads.
func (a *Agent) SetCPU(loads ...int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cpus = slices.Clone(loads)
}

// SetMemUsed sets the RAM used, in bytes.
func (a *Agent) SetMemUsed(b uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.memUsed = b
}

// Restart is an agent restart: sysUpTime starts again from 0 and v3
// engineBoots goes up; hrSystemUptime and the counters carry on.
func (a *Agent) Restart() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	a.sysStart, a.upOff = now, 0
	_ = a.newEngine(a.engine.Boots+1, now)
}

// RestartKeepBoots is an agent restart that doesn't raise v3 engineBoots (an
// agent that doesn't keep it across restarts): sysUpTime and the engine time
// start again from 0, boots stay.
func (a *Agent) RestartKeepBoots() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	a.sysStart, a.upOff = now, 0
	_ = a.newEngine(a.engine.Boots, now)
}

// Reboot is a device reboot: Restart, and hrSystemUptime and every counter
// start again from 0.
func (a *Agent) Reboot() {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	a.sysStart, a.upOff, a.hrStart = now, 0, now
	for _, s := range a.ifs {
		for i := range s.ctr {
			s.ctr[i] = counter{rate: s.ctr[i].rate, at: now}
			s.off[i] = 0
		}
		s.disc = 0
	}
	_ = a.newEngine(a.engine.Boots+1, now)
}

// SetUptime makes sysUpTime read ticks now (for its 497-day wrap: set it
// just under 2^32).
func (a *Agent) SetUptime(ticks uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.opts.Clock()
	a.sysStart, a.upOff = now, ticks
}

// SetMaxVarbinds makes a request whose Response would hold more than n
// varbinds get tooBig (0: no limit).
func (a *Agent) SetMaxVarbinds(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.maxVbs = n
}

// SetNoSuchObject makes every object under prefix missing (noSuchObject;
// noSuchName in v1; skipped by GetNext).
func (a *Agent) SetNoSuchObject(prefix snmp.OID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.noSuch = append(a.noSuch, prefix)
}

// SetDelay delays every reply.
func (a *Agent) SetDelay(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.delay = d
}

// SetSilent makes it answer nothing (or answer again).
func (a *Agent) SetSilent(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.silent = on
}

// SetWrongSource makes it reply from another port (a misconfigured agent).
func (a *Agent) SetWrongSource(on bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.wrongSrc = on
}

// SetExtra sets (or with a zero Value, removes) an extra object.
func (a *Agent) SetExtra(oid string, v snmp.Value) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v.Kind == 0 {
		delete(a.extra, oid)
	} else {
		a.extra[oid] = v
	}
	a.buildView()
}

// Requests counts the requests answered or not, by PDU type ("get",
// "getnext", "getbulk", "discovery").
func (a *Agent) Requests() map[string]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]int{}
	for k, v := range a.requests {
		out[k] = v
	}
	return out
}

// Unexpected counts datagrams that weren't a Get, GetNext or GetBulk (a Set
// among them).
func (a *Agent) Unexpected() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.unexpected
}

// Sources are the addresses requests came from, with counts.
func (a *Agent) Sources() map[netip.AddrPort]int {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[netip.AddrPort]int{}
	for k, v := range a.sources {
		out[k] = v
	}
	return out
}

// ---- the view ----

var (
	oidSystem      = snmp.OID{1, 3, 6, 1, 2, 1, 1}
	oidIfNumber    = snmp.OID{1, 3, 6, 1, 2, 1, 2, 1, 0}
	oidIfEntry     = snmp.OID{1, 3, 6, 1, 2, 1, 2, 2, 1}
	oidIfXEntry    = snmp.OID{1, 3, 6, 1, 2, 1, 31, 1, 1, 1}
	oidHrUptime    = snmp.OID{1, 3, 6, 1, 2, 1, 25, 1, 1, 0}
	oidHrStorage   = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 3, 1}
	oidHrStorRam   = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 1, 2}
	oidHrProcLoad  = snmp.OID{1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2}
	oidHrStorOther = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 1, 4} // hrStorageFixedDisk
)

func cat(o snmp.OID, sub ...uint32) snmp.OID { return append(slices.Clone(o), sub...) }

func str(s string) snmp.Value    { return snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(s)} }
func integer(v int64) snmp.Value { return snmp.Value{Kind: snmp.KindInteger, Int: v} }
func gauge(v uint64) snmp.Value  { return snmp.Value{Kind: snmp.KindGauge32, Uint: v & 0xffffffff} }
func c32(v uint64) snmp.Value    { return snmp.Value{Kind: snmp.KindCounter32, Uint: v & 0xffffffff} }
func c64(v uint64) snmp.Value    { return snmp.Value{Kind: snmp.KindCounter64, Uint: v} }
func timeticks(v uint64) snmp.Value {
	return snmp.Value{Kind: snmp.KindTimeTicks, Uint: v & 0xffffffff}
}

func (a *Agent) sysUpTimeLocked(now time.Time) uint64 {
	return (uint64(now.Sub(a.sysStart)/(10*time.Millisecond)) + a.upOff) & 0xffffffff
}

func ctrVal(s *ifState, c int, now time.Time) uint64 {
	v := s.ctr[c].value(now)
	if v < 0 {
		v = 0
	}
	return uint64(v)
}

func ctr32(s *ifState, c int, now time.Time) uint64 {
	v := s.ctr[c].value(now) + s.off[c]
	if v < 0 {
		v = 0
	}
	return uint64(v) % (1 << 32)
}

// buildView lists every object, sorted. Values are computed per request.
func (a *Agent) buildView() {
	var v []entry
	add := func(o snmp.OID, f func(a *Agent, now time.Time) snmp.Value) { v = append(v, entry{o, f}) }
	add(cat(oidSystem, 1, 0), func(a *Agent, _ time.Time) snmp.Value { return str(a.opts.SysDescr) })
	add(cat(oidSystem, 2, 0), func(a *Agent, _ time.Time) snmp.Value {
		return snmp.Value{Kind: snmp.KindOID, OID: a.opts.SysObjectID}
	})
	add(cat(oidSystem, 3, 0), func(a *Agent, now time.Time) snmp.Value { return timeticks(a.sysUpTimeLocked(now)) })
	add(cat(oidSystem, 5, 0), func(a *Agent, _ time.Time) snmp.Value { return str(a.opts.SysName) })
	add(oidIfNumber, func(a *Agent, _ time.Time) snmp.Value { return integer(int64(len(a.ifs))) })
	type col struct {
		n uint32
		f func(s *ifState, now time.Time) snmp.Value
	}
	ifCols := []col{
		{1, func(s *ifState, _ time.Time) snmp.Value { return integer(int64(s.Index)) }},
		{2, func(s *ifState, _ time.Time) snmp.Value { return str(s.Descr) }},
		{3, func(s *ifState, _ time.Time) snmp.Value { return integer(6) }},
		{5, func(s *ifState, _ time.Time) snmp.Value { return gauge(min(s.SpeedMbps*1e6, 0xffffffff)) }},
		{7, func(s *ifState, _ time.Time) snmp.Value { return integer(1) }},
		{8, func(s *ifState, _ time.Time) snmp.Value { return integer(int64(s.Oper)) }},
		{10, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrInOctets, now)) }},
		{11, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrInUcast, now)) }},
		{13, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrInDisc, now)) }},
		{14, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrInErr, now)) }},
		{16, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrOutOctets, now)) }},
		{17, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrOutUcast, now)) }},
		{19, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrOutDisc, now)) }},
		{20, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrOutErr, now)) }},
	}
	ifxCols := []col{
		{1, func(s *ifState, _ time.Time) snmp.Value { return str(s.Name) }},
		{2, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrInMcast, now)) }},
		{3, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrInBcast, now)) }},
		{4, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrOutMcast, now)) }},
		{5, func(s *ifState, now time.Time) snmp.Value { return c32(ctr32(s, ctrOutBcast, now)) }},
		{6, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrInOctets, now)) }},
		{7, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrInUcast, now)) }},
		{8, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrInMcast, now)) }},
		{9, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrInBcast, now)) }},
		{10, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrOutOctets, now)) }},
		{11, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrOutUcast, now)) }},
		{12, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrOutMcast, now)) }},
		{13, func(s *ifState, now time.Time) snmp.Value { return c64(ctrVal(s, ctrOutBcast, now)) }},
		{15, func(s *ifState, _ time.Time) snmp.Value { return gauge(s.SpeedMbps) }},
		{18, func(s *ifState, _ time.Time) snmp.Value { return str(s.Alias) }},
		{19, func(s *ifState, _ time.Time) snmp.Value { return timeticks(s.disc) }},
	}
	for _, c := range ifCols {
		for i := range a.ifs {
			add(cat(oidIfEntry, c.n, uint32(a.ifs[i].Index)), func(a *Agent, now time.Time) snmp.Value { return c.f(a.ifs[i], now) })
		}
	}
	if !a.opts.NoIfXTable {
		for _, c := range ifxCols {
			for i := range a.ifs {
				add(cat(oidIfXEntry, c.n, uint32(a.ifs[i].Index)), func(a *Agent, now time.Time) snmp.Value { return c.f(a.ifs[i], now) })
			}
		}
	}
	if a.opts.HostResources {
		add(oidHrUptime, func(a *Agent, now time.Time) snmp.Value {
			return timeticks(uint64(now.Sub(a.hrStart) / (10 * time.Millisecond)))
		})
		// Two storage rows: a disk (not RAM, so the poller must skip it) and RAM.
		rows := []struct {
			idx  uint32
			typ  snmp.OID
			used func(a *Agent) uint64
			size uint64
		}{
			{1, oidHrStorOther, func(*Agent) uint64 { return 1 << 20 }, 1 << 22},
			{2, oidHrStorRam, func(a *Agent) uint64 { return a.memUsed / 1024 }, a.opts.MemTotal / 1024},
		}
		for _, r := range rows {
			add(cat(oidHrStorage, 1, r.idx), func(*Agent, time.Time) snmp.Value { return integer(int64(r.idx)) })
			add(cat(oidHrStorage, 2, r.idx), func(*Agent, time.Time) snmp.Value { return snmp.Value{Kind: snmp.KindOID, OID: r.typ} })
			add(cat(oidHrStorage, 3, r.idx), func(*Agent, time.Time) snmp.Value { return str(fmt.Sprintf("storage %d", r.idx)) })
			add(cat(oidHrStorage, 4, r.idx), func(*Agent, time.Time) snmp.Value { return integer(1024) })
			add(cat(oidHrStorage, 5, r.idx), func(*Agent, time.Time) snmp.Value { return integer(int64(r.size)) })
			add(cat(oidHrStorage, 6, r.idx), func(a *Agent, _ time.Time) snmp.Value { return integer(int64(r.used(a))) })
		}
		for i := range a.cpus {
			add(cat(oidHrProcLoad, uint32(196608+i)), func(a *Agent, _ time.Time) snmp.Value {
				if i < len(a.cpus) {
					return integer(int64(a.cpus[i]))
				}
				return integer(0)
			})
		}
	}
	for k := range a.extra {
		o, err := snmp.ParseOID(k)
		if err != nil {
			continue
		}
		add(o, func(a *Agent, _ time.Time) snmp.Value { return a.extra[k] })
	}
	sort.Slice(v, func(i, j int) bool { return snmp.CompareOID(v[i].oid, v[j].oid) < 0 })
	a.view = v
}

func (a *Agent) missing(o snmp.OID) bool {
	for _, p := range a.noSuch {
		if o.HasPrefix(p) {
			return true
		}
	}
	return false
}

// lookup finds an exact object; next finds the first object after o (skipping
// missing ones and, for v1, Counter64 objects, RFC 3584 §4.2.2.1).
func (a *Agent) lookup(o snmp.OID, now time.Time, v1 bool) (snmp.Value, bool) {
	i := sort.Search(len(a.view), func(i int) bool { return snmp.CompareOID(a.view[i].oid, o) >= 0 })
	if i < len(a.view) && a.view[i].oid.Equal(o) && !a.missing(o) {
		val := a.view[i].val(a, now)
		if v1 && val.Kind == snmp.KindCounter64 {
			return snmp.Value{}, false
		}
		return val, true
	}
	return snmp.Value{}, false
}

func (a *Agent) next(o snmp.OID, now time.Time, v1 bool) (snmp.Varbind, bool) {
	i := sort.Search(len(a.view), func(i int) bool { return snmp.CompareOID(a.view[i].oid, o) > 0 })
	for ; i < len(a.view); i++ {
		if a.missing(a.view[i].oid) {
			continue
		}
		val := a.view[i].val(a, now)
		if v1 && val.Kind == snmp.KindCounter64 {
			continue
		}
		return snmp.Varbind{OID: a.view[i].oid, Value: val}, true
	}
	return snmp.Varbind{}, false
}

// ---- serving ----

func (a *Agent) serve() {
	defer close(a.done)
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		raw := slices.Clone(buf[:n])
		a.mu.Lock()
		delay, silent := a.delay, a.silent
		a.mu.Unlock()
		if delay > 0 {
			go func() {
				time.Sleep(delay)
				a.handle(raw, from, silent)
			}()
			continue
		}
		a.handle(raw, from, silent)
	}
}

func (a *Agent) handle(raw []byte, from netip.AddrPort, silent bool) {
	a.mu.Lock()
	now := a.opts.Clock()
	a.sources[from]++
	m := snmp.DecodeRequest(raw, a.usm, now)
	var out []byte
	switch {
	case m.Discovery || m.Reply == snmp.ReplyReport:
		if m.Discovery {
			a.requests["discovery"]++
		} else {
			a.requests["report"]++
		}
		out, _ = a.usm.Reply(m, now)
	case m.Status == snmp.StatusOK && m.PDU != nil:
		if m.Version != snmp.V3 && (a.opts.Community == "" || string(m.Community) != a.opts.Community) {
			break // a wrong community gets no answer
		}
		a.requests[m.PDU.Type.String()]++
		vbs, es, ei := a.answer(m, now)
		out, _ = a.usm.ResponseTo(m, vbs, es, ei, now)
	case m.Status == snmp.StatusUnexpectedPDU:
		a.unexpected++
	default:
		// A wrong user, digest, key or level: the Report a real agent sends.
		a.requests["refused"]++
		out, _ = a.usm.FailureReport(m, now)
	}
	wrong := a.wrongSrc
	a.mu.Unlock()
	if out == nil || silent {
		return
	}
	conn := a.conn
	if wrong {
		a.mu.Lock()
		if a.other == nil {
			a.other, _ = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		}
		conn = a.other
		a.mu.Unlock()
		if conn == nil {
			return
		}
	}
	_, _ = conn.WriteToUDPAddrPort(out, from)
}

// answer builds the Response's varbinds and error status.
func (a *Agent) answer(m *snmp.Message, now time.Time) ([]snmp.Varbind, int64, int64) {
	p := m.PDU
	v1 := m.Version == snmp.V1
	var out []snmp.Varbind
	null := func() []snmp.Varbind {
		r := make([]snmp.Varbind, len(p.Varbinds))
		for i, vb := range p.Varbinds {
			r[i] = snmp.Varbind{OID: vb.OID, Value: snmp.Value{Kind: snmp.KindNull}}
		}
		return r
	}
	switch p.Type {
	case snmp.PDUGet:
		for i, vb := range p.Varbinds {
			val, ok := a.lookup(vb.OID, now, v1)
			if !ok {
				if v1 {
					return null(), snmp.ErrStatusNoSuchName, int64(i + 1)
				}
				val = snmp.Value{Kind: snmp.KindNoSuchObject}
				if j := sort.Search(len(a.view), func(j int) bool { return snmp.CompareOID(a.view[j].oid, vb.OID) >= 0 }); j < len(a.view) &&
					parentOf(a.view[j].oid, vb.OID) && !a.missing(vb.OID) {
					val = snmp.Value{Kind: snmp.KindNoSuchInstance}
				}
			}
			out = append(out, snmp.Varbind{OID: vb.OID, Value: val})
		}
	case snmp.PDUGetNext:
		for i, vb := range p.Varbinds {
			n, ok := a.next(vb.OID, now, v1)
			if !ok {
				if v1 {
					return null(), snmp.ErrStatusNoSuchName, int64(i + 1)
				}
				n = snmp.Varbind{OID: vb.OID, Value: snmp.Value{Kind: snmp.KindEndOfMibView}}
			}
			out = append(out, n)
		}
	case snmp.PDUGetBulk:
		nonRep, maxRep := int(p.ErrorStatus), int(p.ErrorIndex)
		nonRep = min(max(nonRep, 0), len(p.Varbinds))
		maxRep = max(maxRep, 0)
		for _, vb := range p.Varbinds[:nonRep] {
			n, ok := a.next(vb.OID, now, false)
			if !ok {
				n = snmp.Varbind{OID: vb.OID, Value: snmp.Value{Kind: snmp.KindEndOfMibView}}
			}
			out = append(out, n)
		}
		rep := p.Varbinds[nonRep:]
		cur := make([]snmp.OID, len(rep))
		for i, vb := range rep {
			cur[i] = vb.OID
		}
		for r := 0; r < maxRep && len(rep) > 0; r++ {
			allEnd := true
			for i := range cur {
				n, ok := a.next(cur[i], now, false)
				if !ok {
					n = snmp.Varbind{OID: cur[i], Value: snmp.Value{Kind: snmp.KindEndOfMibView}}
				} else {
					allEnd = false
					cur[i] = n.OID
				}
				out = append(out, n)
			}
			if allEnd {
				break
			}
		}
	}
	if a.maxVbs > 0 && len(out) > a.maxVbs {
		return null(), snmp.ErrStatusTooBig, 0
	}
	return out, 0, 0
}

// parentOf reports whether o names a column (an object type) whose instance
// q would be: they share every sub-identifier but the instance part. Here: o
// and q agree up to len(q)-1.
func parentOf(o, q snmp.OID) bool {
	if len(q) < 2 || len(o) < len(q)-1 {
		return false
	}
	return slices.Equal(o[:len(q)-1], q[:len(q)-1])
}
