package poller

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// OIDs the presets poll (SPEC §12.1; only IETF MIBs).
var (
	oidSysDescr    = snmp.OID{1, 3, 6, 1, 2, 1, 1, 1, 0}
	oidSysObjectID = snmp.OID{1, 3, 6, 1, 2, 1, 1, 2, 0}
	oidSysUpTime   = snmp.OIDSysUpTime
	oidSysName     = snmp.OID{1, 3, 6, 1, 2, 1, 1, 5, 0}

	oidHrSystemUptime = snmp.OID{1, 3, 6, 1, 2, 1, 25, 1, 1, 0}
	oidHrStorageType  = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 2}
	oidHrStorageUnits = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 4}
	oidHrStorageSize  = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 5}
	oidHrStorageUsed  = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6}
	oidHrStorageRam   = snmp.OID{1, 3, 6, 1, 2, 1, 25, 2, 1, 2}
	oidHrProcessorLd  = snmp.OID{1, 3, 6, 1, 2, 1, 25, 3, 3, 1, 2}

	oidIfEntry  = snmp.OID{1, 3, 6, 1, 2, 1, 2, 2, 1}
	oidIfXEntry = snmp.OID{1, 3, 6, 1, 2, 1, 31, 1, 1, 1}
)

func col(base snmp.OID, c uint32) snmp.OID { return append(slices.Clone(base), c) }
func inst(o snmp.OID, idx ...uint32) snmp.OID {
	return append(slices.Clone(o), idx...)
}

// ifCounter is one per-cycle interface column and the record key it feeds.
type ifCounter struct {
	key  string
	oid  snmp.OID
	rate string // the rate key, "" for none
	kind string // "octets", "delta" (errors, discards: per cycle) or "pkts" (per second)
}

// The interface columns polled each cycle: 64-bit when the agent has them
// (ifXTable HC), else the 32-bit ifTable ones (SPEC §12.1, §12.11 #1).
var (
	ifCommon = []ifCounter{
		{"in_err", col(oidIfEntry, 14), "in_err_d", "delta"},
		{"out_err", col(oidIfEntry, 20), "out_err_d", "delta"},
		{"in_disc", col(oidIfEntry, 13), "in_disc_d", "delta"},
		{"out_disc", col(oidIfEntry, 19), "out_disc_d", "delta"},
	}
	ifHC = []ifCounter{
		{"in_octets", col(oidIfXEntry, 6), "in_bps", "octets"},
		{"out_octets", col(oidIfXEntry, 10), "out_bps", "octets"},
		{"in_ucast", col(oidIfXEntry, 7), "in_ucast_pps", "pkts"},
		{"out_ucast", col(oidIfXEntry, 11), "out_ucast_pps", "pkts"},
		{"in_mcast", col(oidIfXEntry, 8), "in_mcast_pps", "pkts"},
		{"out_mcast", col(oidIfXEntry, 12), "out_mcast_pps", "pkts"},
		{"in_bcast", col(oidIfXEntry, 9), "in_bcast_pps", "pkts"},
		{"out_bcast", col(oidIfXEntry, 13), "out_bcast_pps", "pkts"},
	}
	if32 = []ifCounter{
		{"in_octets", col(oidIfEntry, 10), "in_bps", "octets"},
		{"out_octets", col(oidIfEntry, 16), "out_bps", "octets"},
		{"in_ucast", col(oidIfEntry, 11), "in_ucast_pps", "pkts"},
		{"out_ucast", col(oidIfEntry, 17), "out_ucast_pps", "pkts"},
	}
	// The ifXTable 32-bit multicast and broadcast counters, for an agent with
	// ifXTable but without HC counters.
	if32X = []ifCounter{
		{"in_mcast", col(oidIfXEntry, 2), "in_mcast_pps", "pkts"},
		{"out_mcast", col(oidIfXEntry, 4), "out_mcast_pps", "pkts"},
		{"in_bcast", col(oidIfXEntry, 3), "in_bcast_pps", "pkts"},
		{"out_bcast", col(oidIfXEntry, 5), "out_bcast_pps", "pkts"},
	}
	oidIfOper     = col(oidIfEntry, 8)
	oidIfDescr    = col(oidIfEntry, 2)
	oidIfSpeed    = col(oidIfEntry, 5)
	oidIfName     = col(oidIfXEntry, 1)
	oidIfHCIn     = col(oidIfXEntry, 6)
	oidIfHigh     = col(oidIfXEntry, 15)
	oidIfAlias    = col(oidIfXEntry, 18)
	oidIfDiscTime = col(oidIfXEntry, 19)
)

// Walk limits for the hourly refreshes.
const (
	maxIfRows = 4096
	maxHrRows = 256
	refresh   = time.Hour
)

// cycleRun is one cycle of one target.
type cycleRun struct {
	p        *Poller
	st       *tstate
	t        Target
	cycle    uint64
	sess     *snmp.Session
	dev      netip.Addr
	cred     string
	head     *pollrec.Cycle
	answered bool
	start    time.Time
}

// errPausedWrite stops a cycle when the store pauses mid-cycle.
var errPausedWrite = errors.New("poller: writing is paused")

func newCycleRun(p *Poller, st *tstate) *cycleRun {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.cycle++
	c := &cycleRun{p: p, st: st, t: st.t, cycle: st.cycle, dev: st.device}
	c.sess = st.ensureSession(p)
	c.cred = st.credLabel()
	return c
}

// ensureSession makes the target's session from its credential (st.mu held).
func (st *tstate) ensureSession(p *Poller) *snmp.Session {
	if st.sess != nil || st.tr == nil {
		return st.sess
	}
	cfg := snmp.SessionConfig{Version: st.t.version(), Timeout: time.Duration(st.t.TimeoutMS) * time.Millisecond,
		Retries: st.t.Retries, Now: p.now}
	st.sessErr = ""
	switch cfg.Version {
	case snmp.V3:
		u, ok := p.o.Creds.User(st.t.V3User)
		if !ok {
			st.sessErr = fmt.Sprintf("v3 user %q isn't configured (or its secrets don't decrypt here)", st.t.V3User)
			return nil
		}
		cfg.User = &u
		if len(st.t.EngineID) > 0 {
			el := int64(0)
			if !st.t.EngineAt.IsZero() {
				el = int64(time.Since(st.t.EngineAt) / time.Second)
			}
			cfg.Engine = snmp.EngineInfo{ID: st.t.EngineID, Boots: st.t.EngineBoots, Time: st.t.EngineTime + max(el, 0), At: p.now()}
			st.storedEngine, st.storedBoots = st.t.EngineID, st.t.EngineBoots
		}
	default:
		cfg.Community = p.o.Creds.Community(st.t.ID)
		if len(cfg.Community) == 0 {
			st.sessErr = "no community is stored for this target"
			return nil
		}
		st.credHash = snmp.CommunityHash(cfg.Community)
	}
	s, err := snmp.NewSession(cfg, st.tr)
	if err != nil {
		st.sessErr = strings.TrimPrefix(err.Error(), "snmp: ")
		return nil
	}
	st.sess = s
	return s
}

// CredsChanged drops every session, so the next cycle reads the credentials
// again (a community or v3 user changed). Engines and samples are kept.
func (p *Poller) CredsChanged() {
	p.mu.Lock()
	sts := make([]*tstate, 0, len(p.targets))
	for _, st := range p.targets {
		sts = append(sts, st)
	}
	p.mu.Unlock()
	for _, st := range sts {
		st.mu.Lock()
		if st.sess != nil && !st.busy {
			if e := st.sess.Engine(); e.Known() {
				st.t.EngineID, st.t.EngineBoots, st.t.EngineTime, st.t.EngineAt = e.ID, e.Boots, e.Time+int64(p.now().Sub(e.At)/time.Second), time.Now()
			}
			st.sess = nil
		} else if st.busy {
			st.dropSess = true
		}
		st.mu.Unlock()
	}
}

func (c *cycleRun) run(ctx context.Context) {
	c.start = c.p.now()
	c.head = pollrec.NewCycle(c.t.DeviceID, c.cycle, c.start.UTC())
	var err error
	if c.sess == nil {
		c.st.mu.Lock()
		err = &snmp.RequestError{Status: snmp.FailError, Detail: c.st.sessErr}
		c.st.mu.Unlock()
	} else {
		err = c.poll(ctx)
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	end := c.p.now()
	status := ""
	if err != nil && !errors.Is(err, errPausedWrite) {
		status = snmp.FailStatus(err)
		detail := err.Error()
		var re *snmp.RequestError
		if errors.As(err, &re) {
			detail = re.Detail
		}
		c.write(pollrec.New(pollrec.KindStatus, c.cycle).Str("status", status).Str("detail", detail).Str("cred", c.cred).
			Int("interval_s", int64(c.t.IntervalS)).Record(), end)
		c.st.mu.Lock()
		c.st.lastErr = detail
		c.st.mu.Unlock()
	}
	if c.answered {
		c.p.addCycle(c.head)
	}
	c.p.mu.Lock()
	c.p.hour.add(end, status, false)
	c.p.mu.Unlock()
	c.p.noteUnmatched()

	st := c.st
	st.mu.Lock()
	st.lastAttempt = c.start
	if c.sess != nil {
		st.rtt = c.sess.LastRTT()
	}
	if c.answered {
		st.fails, st.failingSince, st.lastOK = 0, time.Time{}, c.start
		if err == nil {
			st.lastErr = ""
		}
	} else if err != nil {
		if st.fails == 0 {
			st.failingSince = c.start
		}
		st.fails++
	}
	var save func()
	if c.sess != nil && c.p.o.Engines != nil {
		if e := c.sess.Engine(); e.Known() && (!slices.Equal(e.ID, st.storedEngine) || e.Boots != st.storedBoots) {
			st.storedEngine, st.storedBoots = slices.Clone(e.ID), e.Boots
			id, et := st.t.ID, e.Time+int64(end.Sub(e.At)/time.Second)
			eid, boots := slices.Clone(e.ID), e.Boots
			save = func() { c.p.o.Engines.SetEngine(id, eid, boots, et, time.Now().UTC()) }
		}
	}
	if st.dropSess {
		st.sess, st.dropSess = nil, false
	}
	st.mu.Unlock()
	if save != nil {
		save()
	}
}

// write stores one record, unless the target was replaced meanwhile.
func (c *cycleRun) write(r pollrec.Record, at time.Time) error {
	c.st.mu.Lock()
	retired := c.st.retired
	c.st.mu.Unlock()
	if retired || c.p.o.Sink == nil {
		return nil
	}
	if err := c.p.o.Sink.Write(c.dev, at.UTC(), pollrec.Format(r)); err != nil {
		return errPausedWrite
	}
	if r.Kind == pollrec.KindSys || r.Kind == pollrec.KindIf {
		c.head.Add(&r)
	}
	return nil
}

func (c *cycleRun) get(ctx context.Context, oids []snmp.OID) ([]snmp.Varbind, error) {
	vbs, err := c.sess.Get(ctx, oids)
	if err == nil {
		c.answered = true
	}
	return vbs, err
}

func (c *cycleRun) walk(ctx context.Context, base snmp.OID, maxRows int) ([]snmp.Varbind, bool, error) {
	rows, capped, err := c.sess.Walk(ctx, base, maxRows)
	if err == nil || len(rows) > 0 {
		c.answered = true
	}
	return rows, capped, err
}

func missing(v snmp.Value) bool {
	return v.Kind == snmp.KindNoSuchObject || v.Kind == snmp.KindNoSuchInstance || v.Kind == snmp.KindEndOfMibView || v.Kind == snmp.KindNull
}

// poll runs the cycle's requests and writes its records.
func (c *cycleRun) poll(ctx context.Context) error {
	st := c.st
	now := c.p.now()
	wantSys := c.t.has(config.PresetSystem)

	st.mu.Lock()
	hrDue := wantSys && (st.hrAt.IsZero() || now.Sub(st.hrAt) >= refresh)
	st.mu.Unlock()
	if hrDue {
		if err := c.refreshHR(ctx); err != nil {
			return err
		}
	}

	// 1. sysUpTime always (restarts and the wrap rules need it); HOST-RESOURCES
	// with the system preset.
	st.mu.Lock()
	oids := []snmp.OID{oidSysUpTime}
	hrUp := wantSys && st.hrUptimeOK
	if hrUp {
		oids = append(oids, oidHrSystemUptime)
	}
	cpus, rams := slices.Clone(st.hrCPUs), slices.Clone(st.hrRAM)
	if !wantSys {
		cpus, rams = nil, nil
	}
	st.mu.Unlock()
	for _, i := range cpus {
		oids = append(oids, inst(oidHrProcessorLd, i))
	}
	for _, r := range rams {
		oids = append(oids, inst(oidHrStorageUnits, r), inst(oidHrStorageSize, r), inst(oidHrStorageUsed, r))
	}
	vbs, err := c.get(ctx, oids)
	if err != nil {
		return err
	}
	at := c.p.now()
	sys := pollrec.New(pollrec.KindSys, c.cycle)
	var uptime, hr uint64
	haveUp, haveHr := false, false
	if v := vbs[0].Value; v.Kind == snmp.KindTimeTicks {
		uptime, haveUp = v.Uint, true
		sys.Uint("uptime", uptime)
	}
	k := 1
	if hrUp {
		if v := vbs[1].Value; v.Kind == snmp.KindTimeTicks {
			hr, haveHr = v.Uint, true
			sys.Uint("hr_uptime", hr)
		} else {
			st.mu.Lock()
			st.hrUptimeOK = false // off until the next hourly refresh
			st.mu.Unlock()
		}
		k = 2
	}
	if len(cpus) > 0 {
		var sum int64
		n := 0
		for i := range cpus {
			if v := vbs[k+i].Value; v.Kind == snmp.KindInteger {
				sum += v.Int
				n++
			}
		}
		if n > 0 {
			sys.Int("cpu", (sum+int64(n)/2)/int64(n))
		}
		k += len(cpus)
	}
	if len(rams) > 0 {
		var used, size uint64
		ok := false
		for i := range rams {
			u, s, us := vbs[k+3*i].Value, vbs[k+3*i+1].Value, vbs[k+3*i+2].Value
			if u.Kind == snmp.KindInteger && s.Kind == snmp.KindInteger && us.Kind == snmp.KindInteger && u.Int > 0 && s.Int >= 0 && us.Int >= 0 {
				size += uint64(s.Int) * uint64(u.Int)
				used += uint64(us.Int) * uint64(u.Int)
				ok = true
			}
		}
		if ok {
			sys.Uint("mem_used", used).Uint("mem_total", size)
		}
	}
	sys.Int("rtt_ms", c.sess.LastRTT().Milliseconds()).Int("interval_s", int64(c.t.IntervalS))

	// Restarts (SPEC §12.2.2).
	bootsUp, prevBoots, boots := c.sess.TakeBootsUp()
	st.mu.Lock()
	elapsed := at.Sub(st.prevUpAt)
	upDrop := haveUp && st.havePrevUp && uptimeDropped(st.prevUp, uptime, elapsed)
	hrDrop := haveHr && st.havePrevHr && uptimeDropped(st.prevHr, hr, elapsed)
	prevUp, prevHr, havePrevHr := st.prevUp, st.prevHr, st.havePrevHr
	if haveUp {
		st.prevUp, st.prevUpAt, st.havePrevUp = uptime, at, true
	}
	if haveHr {
		st.prevHr, st.havePrevHr = hr, true
	}
	restart := upDrop || bootsUp
	if restart {
		st.ifRefresh = true
	}
	st.mu.Unlock()
	if err := c.write(sys.Record(), at); err != nil {
		return err
	}
	if restart {
		rb := pollrec.New(pollrec.KindRestart, c.cycle)
		reboot := "?"
		// hrSystemUptime tells a reboot from an agent restart only when it
		// moves; one stuck at a value (0 on some agents) can't.
		if haveHr && havePrevHr && hr != prevHr {
			reboot = "0"
			if hrDrop {
				reboot = "1"
			}
		}
		rb.Str("reboot", reboot)
		var src []string
		if haveUp {
			rb.Uint("uptime", uptime).Uint("prev_uptime", prevUp)
		}
		if upDrop {
			src = append(src, "sysUpTime")
		}
		if haveHr && havePrevHr {
			rb.Uint("hr_uptime", hr).Uint("prev_hr_uptime", prevHr)
			if hrDrop {
				src = append(src, "hrSystemUptime")
			}
		}
		if bootsUp {
			rb.Int("boots", boots).Int("prev_boots", prevBoots)
			src = append(src, "engineBoots")
		}
		rb.Str("source", strings.Join(src, ","))
		if err := c.write(rb.Record(), at); err != nil {
			return err
		}
		c.p.event("info", fmt.Sprintf("SNMP poll: %s restarted (%s; reboot=%s)", c.t.DeviceID, strings.Join(src, ", "), reboot))
	}

	// 2. Interfaces.
	if c.t.has(config.PresetInterfaces) {
		if err := c.interfaces(ctx, restart); err != nil {
			return err
		}
	}

	// 3. System info (hourly), after the interface refresh so it can say what
	// was found.
	st.mu.Lock()
	infoDue := c.t.has(config.PresetSystemInfo) && (st.infoAt.IsZero() || c.p.now().Sub(st.infoAt) >= refresh || restart)
	st.mu.Unlock()
	if infoDue {
		vbs, err := c.get(ctx, []snmp.OID{oidSysName, oidSysDescr, oidSysObjectID})
		if err != nil {
			return err
		}
		at := c.p.now()
		info := pollrec.New(pollrec.KindInfo, c.cycle)
		st.mu.Lock()
		if v := vbs[0].Value; v.Kind == snmp.KindOctetString {
			st.sysName = text(v.Bytes)
			info.Str("sys_name", st.sysName)
		}
		if v := vbs[1].Value; v.Kind == snmp.KindOctetString {
			st.sysDescr = text(v.Bytes)
			info.Str("sys_descr", st.sysDescr)
		}
		if v := vbs[2].Value; v.Kind == snmp.KindOID {
			info.Str("sys_oid", v.OID.String())
		}
		if c.t.has(config.PresetInterfaces) {
			info.Str("hc", boolStr(st.hc)).Int("ifs_total", int64(st.ifTotal)).Int("ifs_polled", int64(len(st.ifs)))
		}
		if wantSys {
			info.Str("hr", boolStr(st.hrUptimeOK || len(st.hrCPUs) > 0 || len(st.hrRAM) > 0))
		}
		st.infoAt = at
		st.mu.Unlock()
		if err := c.write(info.Record(), at); err != nil {
			return err
		}
	}

	// 4. Custom OIDs.
	if len(c.t.Custom) > 0 {
		if err := c.custom(ctx, !restart); err != nil {
			return err
		}
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// text is an octet string as record text: UTF-8 as is, anything else hex.
func text(b []byte) string {
	if utf8.Valid(b) {
		ok := true
		for _, r := range string(b) {
			if r < ' ' && r != '\t' || r == 0x7f {
				ok = false
				break
			}
		}
		if ok {
			return string(b)
		}
	}
	return "0x" + hex.EncodeToString(b)
}

// refreshHR finds the processors and the RAM rows (hourly).
func (c *cycleRun) refreshHR(ctx context.Context) error {
	cpuRows, _, err := c.walk(ctx, oidHrProcessorLd, maxHrRows)
	if err != nil {
		return err
	}
	typeRows, _, err := c.walk(ctx, oidHrStorageType, maxHrRows)
	if err != nil {
		return err
	}
	up, err := c.get(ctx, []snmp.OID{oidHrSystemUptime})
	if err != nil {
		return err
	}
	var cpus, rams []uint32
	for _, r := range cpuRows {
		if r.Value.Kind == snmp.KindInteger && len(r.OID) == len(oidHrProcessorLd)+1 {
			cpus = append(cpus, r.OID[len(oidHrProcessorLd)])
		}
	}
	for _, r := range typeRows {
		if r.Value.Kind == snmp.KindOID && r.Value.OID.Equal(oidHrStorageRam) && len(r.OID) == len(oidHrStorageType)+1 {
			rams = append(rams, r.OID[len(oidHrStorageType)])
		}
	}
	c.st.mu.Lock()
	c.st.hrCPUs, c.st.hrRAM = cpus, rams
	c.st.hrUptimeOK = up[0].Value.Kind == snmp.KindTimeTicks
	c.st.hrAt = c.p.now()
	c.st.mu.Unlock()
	return nil
}

// ifRow is one row of the interface table at a refresh.
type ifRow struct {
	index       int
	name, descr string
	alias       string
	speed       uint64
	oper        int64
	pinnedOrder int // position in the pinned list, or -1
	listedOrder int // position in the target's list, or -1
}

// selectInterfaces picks the polled interfaces (SPEC §12.1, §12.11 #3): a
// list's interfaces; or for "all", up to max: the pinned ones, then those
// that are up by speed (highest first), then the rest, each by index. The
// result is in ifIndex order.
func selectInterfaces(rows []ifRow, s Settings) []ifRow {
	match := func(refs []IfRef, r ifRow) int {
		for i, ref := range refs {
			if (ref.Name != "" && (ref.Name == r.name || ref.Name == r.descr)) || (ref.Name == "" && ref.Index == r.index) {
				return i
			}
		}
		return -1
	}
	var out []ifRow
	if !s.Interfaces.All {
		for _, r := range rows {
			if match(s.Interfaces.List, r) >= 0 {
				out = append(out, r)
			}
		}
	} else {
		cand := slices.Clone(rows)
		for i := range cand {
			cand[i].pinnedOrder = match(s.Pinned, cand[i])
		}
		sort.SliceStable(cand, func(i, j int) bool {
			a, b := cand[i], cand[j]
			if (a.pinnedOrder >= 0) != (b.pinnedOrder >= 0) {
				return a.pinnedOrder >= 0
			}
			if a.pinnedOrder >= 0 {
				return a.pinnedOrder < b.pinnedOrder
			}
			if (a.oper == 1) != (b.oper == 1) {
				return a.oper == 1
			}
			if a.oper == 1 && a.speed != b.speed {
				return a.speed > b.speed
			}
			return a.index < b.index
		})
		out = cand
	}
	if len(out) > s.MaxInterfaces {
		out = out[:s.MaxInterfaces]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].index < out[j].index })
	return out
}

// refreshInterfaces walks the interface table's names, speeds and states and
// picks the polled interfaces (hourly, after a discontinuity or a restart).
func (c *cycleRun) refreshInterfaces(ctx context.Context) ([]*ifState, map[int]bool, error) {
	rows := map[int]*ifRow{}
	get := func(i int) *ifRow {
		r := rows[i]
		if r == nil {
			r = &ifRow{index: i}
			rows[i] = r
		}
		return r
	}
	walkCol := func(base snmp.OID, f func(r *ifRow, v snmp.Value)) (int, error) {
		vbs, _, err := c.walk(ctx, base, maxIfRows)
		if err != nil {
			return 0, err
		}
		n := 0
		for _, vb := range vbs {
			if len(vb.OID) != len(base)+1 {
				continue
			}
			f(get(int(vb.OID[len(base)])), vb.Value)
			n++
		}
		return n, nil
	}
	if _, err := walkCol(oidIfDescr, func(r *ifRow, v snmp.Value) { r.descr = text(v.Bytes) }); err != nil {
		return nil, nil, err
	}
	if _, err := walkCol(oidIfOper, func(r *ifRow, v snmp.Value) { r.oper = v.Int }); err != nil {
		return nil, nil, err
	}
	if _, err := walkCol(oidIfSpeed, func(r *ifRow, v snmp.Value) {
		if r.speed == 0 {
			r.speed = v.Uint / 1e6
		}
	}); err != nil {
		return nil, nil, err
	}
	ifx, hc := false, false
	if c.t.version() != snmp.V1 {
		n, err := walkCol(oidIfName, func(r *ifRow, v snmp.Value) { r.name = text(v.Bytes) })
		if err != nil {
			return nil, nil, err
		}
		ifx = n > 0
		if ifx {
			if _, err := walkCol(oidIfAlias, func(r *ifRow, v snmp.Value) { r.alias = text(v.Bytes) }); err != nil {
				return nil, nil, err
			}
			if _, err := walkCol(oidIfHigh, func(r *ifRow, v snmp.Value) {
				if v.Kind == snmp.KindGauge32 && v.Uint > 0 {
					r.speed = v.Uint
				}
			}); err != nil {
				return nil, nil, err
			}
		}
	}
	list := make([]ifRow, 0, len(rows))
	for _, r := range rows {
		if r.name == "" {
			r.name = r.descr
		}
		list = append(list, *r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].index < list[j].index })
	if ifx && len(list) > 0 {
		vbs, err := c.get(ctx, []snmp.OID{inst(oidIfHCIn, uint32(list[0].index))})
		if err != nil {
			return nil, nil, err
		}
		hc = vbs[0].Value.Kind == snmp.KindCounter64
	}
	sel := selectInterfaces(list, c.t.Settings)

	st := c.st
	st.mu.Lock()
	defer st.mu.Unlock()
	old := map[int]*ifState{}
	for _, s := range st.ifs {
		old[s.index] = s
	}
	renamed := map[int]bool{}
	var out []*ifState
	for _, r := range sel {
		s := old[r.index]
		if s == nil || s.name != r.name || hc != st.hc {
			if s != nil && s.name != r.name {
				renamed[r.index] = true
			}
			ns := &ifState{index: r.index, prev: map[string]sample{}}
			if s != nil {
				ns.oper = s.oper
			}
			s = ns
		}
		s.name, s.descr, s.alias, s.speed = r.name, r.descr, r.alias, r.speed
		out = append(out, s)
	}
	st.ifs, st.ifTotal, st.hc, st.ifx, st.ifAt, st.ifRefresh = out, len(list), hc, ifx, c.p.now(), false
	return out, renamed, nil
}

// interfaces polls the interface counters and writes one if record each.
func (c *cycleRun) interfaces(ctx context.Context, restart bool) error {
	st := c.st
	st.mu.Lock()
	due := st.ifAt.IsZero() || c.p.now().Sub(st.ifAt) >= refresh || st.ifRefresh || restart
	ifs, hc, ifx := st.ifs, st.hc, st.ifx
	st.mu.Unlock()
	renamed := map[int]bool{}
	if due {
		var err error
		if ifs, renamed, err = c.refreshInterfaces(ctx); err != nil {
			return err
		}
		st.mu.Lock()
		hc, ifx = st.hc, st.ifx
		st.mu.Unlock()
		at := c.p.now()
		for _, s := range ifs {
			r := pollrec.New(pollrec.KindInfo, c.cycle).Int("if", int64(s.index)).Str("name", s.name).Str("descr", s.descr).
				Str("alias", s.alias)
			if s.speed > 0 {
				r.Uint("speed_mbps", s.speed)
			}
			if err := c.write(r.Record(), at); err != nil {
				return err
			}
		}
	}
	if len(ifs) == 0 {
		return nil
	}
	cols := slices.Clone(ifCommon)
	if hc {
		cols = append(ifHC, cols...)
	} else {
		cols = append(slices.Clone(if32), cols...)
		if ifx {
			cols = append(cols, if32X...)
		}
	}
	per := len(cols) + 1 // + ifOperStatus
	if ifx {
		per++ // + ifCounterDiscontinuityTime
	}
	oids := make([]snmp.OID, 0, per*len(ifs))
	for _, s := range ifs {
		idx := uint32(s.index)
		for _, cc := range cols {
			oids = append(oids, inst(cc.oid, idx))
		}
		oids = append(oids, inst(oidIfOper, idx))
		if ifx {
			oids = append(oids, inst(oidIfDiscTime, idx))
		}
	}
	vbs, err := c.get(ctx, oids)
	if err != nil {
		return err
	}
	at := c.p.now()
	for i, s := range ifs {
		row := vbs[i*per : (i+1)*per]
		hadPrev := len(s.prev) > 0
		rec := pollrec.New(pollrec.KindIf, c.cycle).Int("if", int64(s.index)).Str("name", s.name)
		st.mu.Lock()
		operV := row[len(cols)].Value
		if operV.Kind == snmp.KindInteger {
			o := pollrec.OperName(operV.Int)
			rec.Str("oper", o)
			if s.oper != "" && s.oper != o {
				rec.Str("oper_was", s.oper)
			}
			s.oper = o
		}
		if s.speed > 0 {
			rec.Uint("speed_mbps", s.speed)
		}
		if !hc {
			rec.Str("bits", "32")
		}
		disc := restart || renamed[s.index]
		if ifx {
			if v := row[len(cols)+1].Value; v.Kind == snmp.KindTimeTicks {
				if s.haveDisc && v.Uint != s.discTime {
					disc = true
					st.ifRefresh = true
				}
				s.discTime, s.haveDisc = v.Uint, true
			}
		}
		var wraps []string
		anyDrop := false
		for j, cc := range cols {
			v := row[j].Value
			var kind counterKind
			switch v.Kind {
			case snmp.KindCounter32:
				kind = counter32
			case snmp.KindCounter64:
				kind = counter64
			default:
				continue
			}
			rec.Uint(cc.key, v.Uint)
			prev := s.prev[cc.key]
			var bound uint64
			if cc.kind == "octets" && prev.ok {
				bound = octetBound(s.speed, at.Sub(prev.at).Seconds())
			}
			d := counterDelta(prev, v.Uint, at, kind, bound, !restart, disc)
			s.prev[cc.key] = sample{value: v.Uint, at: at, ok: true}
			if !d.ok {
				if prev.ok && (disc || restart || v.Uint < prev.value) {
					anyDrop = true
				}
				continue
			}
			if d.wrapped {
				wraps = append(wraps, cc.key)
			}
			switch cc.kind {
			case "octets":
				rec.Float(cc.rate, float64(d.delta)*8/d.seconds)
			case "pkts":
				rec.Float(cc.rate, float64(d.delta)/d.seconds)
			case "delta":
				rec.Uint(cc.rate, d.delta)
			}
		}
		st.mu.Unlock()
		if anyDrop || (disc && (hadPrev || renamed[s.index])) {
			rec.Str("disc", "1")
		}
		if len(wraps) > 0 {
			rec.Str("wraps", strings.Join(wraps, ","))
		}
		r := rec.Record()
		if err := c.write(r, at); err != nil {
			return err
		}
	}
	return nil
}

// typeName is a value's record type (as in trap records).
func typeName(v snmp.Value) (string, string) {
	switch v.Kind {
	case snmp.KindInteger:
		return "int", strconv.FormatInt(v.Int, 10)
	case snmp.KindOctetString:
		t := text(v.Bytes)
		if strings.HasPrefix(t, "0x") && !(utf8.Valid(v.Bytes) && string(v.Bytes) == t) {
			return "hex", t
		}
		return "str", t
	case snmp.KindNull:
		return "null", ""
	case snmp.KindOID:
		return "oid", v.OID.String()
	case snmp.KindIPAddress:
		if a, ok := netip.AddrFromSlice(v.Bytes); ok {
			return "ip", a.String()
		}
		return "ip", "0x" + hex.EncodeToString(v.Bytes)
	case snmp.KindCounter32:
		return "c32", strconv.FormatUint(v.Uint, 10)
	case snmp.KindGauge32:
		return "g32", strconv.FormatUint(v.Uint, 10)
	case snmp.KindTimeTicks:
		return "ticks", strconv.FormatUint(v.Uint, 10)
	case snmp.KindOpaque:
		return "opaque", "0x" + hex.EncodeToString(v.Bytes)
	case snmp.KindCounter64:
		return "c64", strconv.FormatUint(v.Uint, 10)
	case snmp.KindNoSuchObject:
		return "nosuchobject", ""
	case snmp.KindNoSuchInstance:
		return "nosuchinstance", ""
	case snmp.KindEndOfMibView:
		return "endofmibview", ""
	}
	return "hex", "0x" + hex.EncodeToString(v.Bytes)
}

// custom polls the custom OIDs: the scalars in one Get, then each walk.
func (c *cycleRun) custom(ctx context.Context, uptimeForward bool) error {
	var scalars []snmp.OID
	var labels []Custom
	for _, cu := range c.t.Custom {
		if cu.Kind == CustomScalar {
			o, _ := snmp.ParseOID(cu.OID)
			scalars = append(scalars, o)
			labels = append(labels, cu)
		}
	}
	if len(scalars) > 0 {
		vbs, err := c.get(ctx, scalars)
		if err != nil {
			return err
		}
		at := c.p.now()
		for i, vb := range vbs {
			if err := c.write(c.oidRecord(labels[i], "", vb.Value, at, uptimeForward, false), at); err != nil {
				return err
			}
		}
	}
	for _, cu := range c.t.Custom {
		if cu.Kind != CustomWalk {
			continue
		}
		base, _ := snmp.ParseOID(cu.OID)
		rows, capped, err := c.walk(ctx, base, cu.MaxRows)
		if err != nil {
			return err
		}
		at := c.p.now()
		if len(rows) == 0 {
			if err := c.write(c.oidRecord(cu, "", snmp.Value{Kind: snmp.KindNoSuchObject}, at, uptimeForward, false), at); err != nil {
				return err
			}
			continue
		}
		for i, r := range rows {
			if err := c.write(c.oidRecord(cu, snmp.OID(r.OID[len(base):]).String(), r.Value, at, uptimeForward, capped && i == len(rows)-1), at); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *cycleRun) oidRecord(cu Custom, row string, v snmp.Value, at time.Time, uptimeForward, capped bool) pollrec.Record {
	typ, val := typeName(v)
	rec := pollrec.New(pollrec.KindOID, c.cycle).Str("oid", cu.OID)
	if row != "" {
		rec.Str("row", row)
	}
	if cu.Label != "" {
		rec.Str("label", cu.Label)
	}
	rec.Str("type", typ).Str("value", val)
	if typ == "c32" || typ == "c64" {
		kind := counter32
		if typ == "c64" {
			kind = counter64
		}
		key := cu.OID + "|" + row
		c.st.mu.Lock()
		prev := c.st.oidPrev[key]
		d := counterDelta(prev, v.Uint, at, kind, 0, uptimeForward, false)
		c.st.oidPrev[key] = sample{value: v.Uint, at: at, ok: true}
		c.st.mu.Unlock()
		if d.ok {
			rec.Float("rate", float64(d.delta)/d.seconds)
		} else if prev.ok {
			rec.Str("disc", "1")
		}
	}
	if capped {
		rec.Str("capped", "1")
	}
	return rec.Record()
}

func (p *Poller) event(level, text string) {
	if p.o.Event != nil {
		p.o.Event(level, text)
	}
}
