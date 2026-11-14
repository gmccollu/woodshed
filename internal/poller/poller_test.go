package poller

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

// ---- harness ----

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type line struct {
	dev netip.Addr
	at  time.Time
	rec pollrec.Record
}

type memSink struct {
	mu     sync.Mutex
	lines  []line
	hourly []pollrec.Hourly
	paused atomic.Bool
}

func (s *memSink) Write(dev netip.Addr, at time.Time, rec []byte) error {
	r, err := pollrec.Parse(rec)
	if err != nil {
		panic("unparseable record: " + string(rec))
	}
	s.mu.Lock()
	s.lines = append(s.lines, line{dev, at, r})
	s.mu.Unlock()
	return nil
}
func (s *memSink) Paused() bool { return s.paused.Load() }
func (s *memSink) AddHourly(rows []pollrec.Hourly) {
	s.mu.Lock()
	s.hourly = append(s.hourly, rows...)
	s.mu.Unlock()
}

func (s *memSink) take() []line {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.lines
	s.lines = nil
	return out
}

type memCreds struct {
	comm  map[string][]byte
	users map[string]snmp.User
}

func (c *memCreds) Community(id string) []byte { return c.comm[id] }
func (c *memCreds) User(n string) (snmp.User, bool) {
	u, ok := c.users[n]
	return u, ok
}

type harness struct {
	t     *testing.T
	p     *Poller
	a     *agenttest.Agent
	sink  *memSink
	clock *fakeClock
	st    *tstate
}

const testComm = "test-community"

func defaultSettings() Settings {
	d := config.DefaultPoll()
	return Settings{Address: "127.0.0.1", Enabled: true, Version: "2c", IntervalS: 60, TimeoutMS: 400, Retries: 0,
		Presets: d.Presets, Interfaces: Interfaces{All: true}, MaxInterfaces: 64, DeviceID: "127.0.0.1"}
}

func newHarness(t *testing.T, ao agenttest.Options, s Settings, users ...snmp.User) *harness {
	t.Helper()
	fc := &fakeClock{t: t0}
	ao.Clock = fc.Now
	if ao.Community == "" {
		ao.Community = testComm
	}
	ao.Users = append(ao.Users, users...)
	a, err := agenttest.Start(ao)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	sink := &memSink{}
	creds := &memCreds{comm: map[string][]byte{"pt_1": []byte(testComm)}, users: map[string]snmp.User{}}
	for _, u := range users {
		creds.users[u.Name] = u
	}
	p := New(Options{Sink: sink, Creds: creds, Now: fc.Now})
	t.Cleanup(p.Close)
	s.Port = int(a.Addr().Port())
	p.SetTargets([]Target{{ID: "pt_1", Settings: s}})
	p.mu.Lock()
	st := p.targets["pt_1"]
	p.mu.Unlock()
	st.mu.Lock()
	st.nextDue = fc.Now().Add(1000 * time.Hour) // the test drives the cycles
	st.mu.Unlock()
	fc.Advance(time.Hour) // the agent has been up an hour
	return &harness{t: t, p: p, a: a, sink: sink, clock: fc, st: st}
}

// cycle runs one cycle now and returns its records.
func (h *harness) cycle() []line {
	h.t.Helper()
	c := newCycleRun(h.p, h.st)
	c.run(context.Background())
	return h.sink.take()
}

func find(ls []line, kind string, match func(r *pollrec.Record) bool) *pollrec.Record {
	for i := range ls {
		if ls[i].rec.Kind == kind && (match == nil || match(&ls[i].rec)) {
			return &ls[i].rec
		}
	}
	return nil
}

func ifRec(ls []line, idx string) *pollrec.Record {
	return find(ls, pollrec.KindIf, func(r *pollrec.Record) bool { return r.Value("if") == idx })
}

func near(t *testing.T, what string, got string, want, tol float64) {
	t.Helper()
	var v float64
	if _, err := fmt.Sscan(got, &v); err != nil || math.Abs(v-want) > tol*want {
		t.Errorf("%s = %q, want about %v", what, got, want)
	}
}

func twoIfs() []agenttest.Interface {
	return []agenttest.Interface{
		{Index: 1, Name: "eth1", Descr: "eth1", Alias: "uplink", SpeedMbps: 1000, InBps: 8e6, OutBps: 4e6, InUcastPps: 100, OutUcastPps: 50,
			InBcastPps: 10},
		{Index: 2, Name: "eth2", Descr: "eth2", SpeedMbps: 100, InBps: 1e6, OutBps: 1e6, Oper: 2},
	}
}

// ---- tests ----

func TestPollRecordsAndRates(t *testing.T) {
	s := defaultSettings()
	s.Custom = []Custom{{OID: "1.3.6.1.4.1.32473.1.2.0", Kind: CustomScalar, Label: "queue depth"},
		{OID: "1.3.6.1.4.1.32473.1.3", Kind: CustomWalk, Label: "drops", MaxRows: 2}}
	h := newHarness(t, agenttest.Options{Interfaces: twoIfs(), HostResources: true, CPUs: []int{10, 31}, MemUsed: 4 << 30,
		MemTotal: 8 << 30, SysName: "edge-fw-01", Extra: map[string]snmp.Value{
			"1.3.6.1.4.1.32473.1.2.0": {Kind: snmp.KindGauge32, Uint: 17},
			"1.3.6.1.4.1.32473.1.3.1": {Kind: snmp.KindCounter32, Uint: 5},
			"1.3.6.1.4.1.32473.1.3.2": {Kind: snmp.KindCounter32, Uint: 6},
			"1.3.6.1.4.1.32473.1.3.3": {Kind: snmp.KindCounter32, Uint: 7},
		}}, s)
	ls := h.cycle()
	sys := find(ls, pollrec.KindSys, nil)
	if sys == nil || sys.Value("cpu") != "21" || sys.Value("mem_used") != "4294967296" || sys.Value("mem_total") != "8589934592" ||
		sys.Value("hr_uptime") == "" || sys.Value("interval_s") != "60" {
		t.Fatalf("sys %+v", sys)
	}
	info := find(ls, pollrec.KindInfo, func(r *pollrec.Record) bool { return r.Value("sys_name") != "" })
	if info == nil || info.Value("sys_name") != "edge-fw-01" || info.Value("hc") != "1" || info.Value("hr") != "1" ||
		info.Value("ifs_total") != "2" || info.Value("ifs_polled") != "2" {
		t.Errorf("info %+v", info)
	}
	if a := find(ls, pollrec.KindInfo, func(r *pollrec.Record) bool { return r.Value("if") == "1" }); a == nil || a.Value("alias") != "uplink" ||
		a.Value("speed_mbps") != "1000" {
		t.Errorf("if info %+v", a)
	}
	e1 := ifRec(ls, "1")
	if e1 == nil || e1.Value("oper") != "up" || e1.Value("in_octets") != "3600000000" || e1.Value("in_bps") != "" || e1.Value("bits") != "" {
		t.Fatalf("first if line %+v", e1)
	}
	if e2 := ifRec(ls, "2"); e2 == nil || e2.Value("oper") != "down" {
		t.Errorf("eth2 %+v", e2)
	}
	if q := find(ls, pollrec.KindOID, func(r *pollrec.Record) bool { return r.Value("label") == "queue depth" }); q == nil ||
		q.Value("type") != "g32" || q.Value("value") != "17" {
		t.Errorf("scalar %+v", q)
	}
	var rows []*pollrec.Record
	for i := range ls {
		if ls[i].rec.Kind == pollrec.KindOID && ls[i].rec.Value("label") == "drops" {
			rows = append(rows, &ls[i].rec)
		}
	}
	if len(rows) != 2 || rows[0].Value("row") != "1" || rows[1].Value("capped") != "1" {
		t.Errorf("walk rows %+v", rows)
	}

	h.clock.Advance(60 * time.Second)
	h.a.AddErrors(1, 5, 0, 2, 0)
	h.a.SetOper(2, 1)
	h.a.SetExtra("1.3.6.1.4.1.32473.1.3.1", snmp.Value{Kind: snmp.KindCounter32, Uint: 65})
	ls = h.cycle()
	e1 = ifRec(ls, "1")
	if e1 == nil {
		t.Fatal("no eth1 line")
	}
	near(t, "in_bps", e1.Value("in_bps"), 8e6, 0.001)
	near(t, "out_bps", e1.Value("out_bps"), 4e6, 0.001)
	near(t, "in_ucast_pps", e1.Value("in_ucast_pps"), 100, 0.001)
	near(t, "in_bcast_pps", e1.Value("in_bcast_pps"), 10, 0.001)
	if e1.Value("in_err_d") != "5" || e1.Value("in_disc_d") != "2" || e1.Value("out_err_d") != "0" || e1.Value("disc") != "" {
		t.Errorf("eth1 deltas %+v", e1)
	}
	if e2 := ifRec(ls, "2"); e2 == nil || e2.Value("oper") != "up" || e2.Value("oper_was") != "down" {
		t.Errorf("oper change %+v", e2)
	}
	if find(ls, pollrec.KindInfo, nil) != nil {
		t.Error("info lines every cycle (they're hourly)")
	}
	if r := find(ls, pollrec.KindOID, func(r *pollrec.Record) bool { return r.Value("row") == "1" }); r == nil || r.Value("rate") != "1" {
		t.Errorf("oid rate %+v", r)
	}
	h.p.FlushRollups()
	got := map[string]float64{}
	for _, hr := range h.sink.hourly {
		got[hr.Series] = hr.Max
	}
	if got["in_bps"] < 8.9e6 || got["cpu"] != 21 || got["errors_d"] != 5 || got["mem_used_pct"] != 50 {
		t.Errorf("rollups %v", got)
	}
	st := h.p.States()["pt_1"]
	if st.Status != StateOK || !st.HCCounters || !st.HostResources || st.InterfacesPolled != 2 || st.SysName != "edge-fw-01" {
		t.Errorf("state %+v", st)
	}
}

func TestCounter32Wrap(t *testing.T) {
	ifs := []agenttest.Interface{{Index: 1, Name: "eth1", SpeedMbps: 1000, InBps: 8e6, OutBps: 8e6}}
	h := newHarness(t, agenttest.Options{Interfaces: ifs, NoIfXTable: true}, defaultSettings())
	h.cycle()
	h.a.WrapCounter32(1, 1000)
	h.cycle() // the samples just before the wrap
	h.clock.Advance(60 * time.Second)
	ls := h.cycle()
	e := ifRec(ls, "1")
	if e == nil || e.Value("bits") != "32" || e.Value("wraps") != "in_octets,out_octets" || e.Value("disc") != "" {
		t.Fatalf("wrap: %+v", e)
	}
	near(t, "in_bps", e.Value("in_bps"), 8e6, 0.001)
	st := h.p.States()["pt_1"]
	if st.HCCounters {
		t.Error("hc_counters on a 32-bit agent")
	}
}

func TestCounter32ImplausibleWrap(t *testing.T) {
	// 1 Mb/s interface, 8 Mb/s of traffic: a "wrap" would be 8x the speed.
	ifs := []agenttest.Interface{{Index: 1, Name: "eth1", SpeedMbps: 1, InBps: 8e6}}
	h := newHarness(t, agenttest.Options{Interfaces: ifs, NoIfXTable: true}, defaultSettings())
	h.cycle()
	h.a.WrapCounter32(1, 1000)
	h.cycle()
	h.clock.Advance(60 * time.Second)
	ls := h.cycle()
	if e := ifRec(ls, "1"); e == nil || e.Value("disc") != "1" || e.Value("in_bps") != "" || e.Value("wraps") != "" {
		t.Errorf("implausible wrap: %+v", e)
	}
}

func TestCounter64DropAndDiscontinuity(t *testing.T) {
	h := newHarness(t, agenttest.Options{Interfaces: twoIfs()}, defaultSettings())
	h.cycle()
	h.clock.Advance(60 * time.Second)
	h.cycle()
	h.clock.Advance(60 * time.Second)
	h.a.DropCounter64(1, 1e12)
	ls := h.cycle()
	if e := ifRec(ls, "1"); e == nil || e.Value("disc") != "1" || e.Value("in_bps") != "" || e.Value("wraps") != "" {
		t.Errorf("c64 drop: %+v", e)
	}
	if e := ifRec(ls, "2"); e == nil || e.Value("disc") != "" || e.Value("in_bps") == "" {
		t.Errorf("the other interface: %+v", e)
	}
	h.clock.Advance(60 * time.Second)
	h.a.BumpDiscontinuity(2)
	ls = h.cycle()
	if e := ifRec(ls, "2"); e == nil || e.Value("disc") != "1" || e.Value("in_bps") != "" {
		t.Errorf("discontinuity time: %+v", e)
	}
	// The discontinuity refreshes the names at the next cycle.
	h.clock.Advance(60 * time.Second)
	ls = h.cycle()
	if find(ls, pollrec.KindInfo, func(r *pollrec.Record) bool { return r.Value("if") == "2" }) == nil {
		t.Error("no refresh after a discontinuity")
	}
	if e := ifRec(ls, "2"); e == nil || e.Value("in_bps") == "" {
		t.Errorf("rates after the discontinuity: %+v", e)
	}
}

func TestRenameUnderSameIndex(t *testing.T) {
	h := newHarness(t, agenttest.Options{Interfaces: twoIfs()}, defaultSettings())
	h.cycle()
	h.a.Rename(1, "eth9")
	h.clock.Advance(61 * time.Minute) // the hourly refresh
	ls := h.cycle()
	if e := ifRec(ls, "1"); e == nil || e.Value("name") != "eth9" || e.Value("disc") != "1" || e.Value("in_bps") != "" {
		t.Errorf("renamed: %+v", e)
	}
}

func TestRestartsAndReboots(t *testing.T) {
	t.Run("agent restart without HOST-RESOURCES", func(t *testing.T) {
		h := newHarness(t, agenttest.Options{Interfaces: twoIfs()}, defaultSettings())
		h.cycle()
		h.clock.Advance(60 * time.Second)
		h.a.Restart()
		h.clock.Advance(10 * time.Second)
		ls := h.cycle()
		r := find(ls, pollrec.KindRestart, nil)
		if r == nil || r.Value("reboot") != "?" || r.Value("source") != "sysUpTime" || r.Value("uptime") != "1000" || r.Value("prev_uptime") != "360000" {
			t.Fatalf("restart %+v", r)
		}
		if e := ifRec(ls, "1"); e == nil || e.Value("disc") != "1" || e.Value("in_bps") != "" {
			t.Errorf("rates across a restart: %+v", e)
		}
	})
	t.Run("reboot with HOST-RESOURCES", func(t *testing.T) {
		h := newHarness(t, agenttest.Options{Interfaces: twoIfs(), HostResources: true, MemTotal: 1 << 30}, defaultSettings())
		h.cycle()
		h.clock.Advance(60 * time.Second)
		h.a.Reboot()
		h.clock.Advance(10 * time.Second)
		ls := h.cycle()
		r := find(ls, pollrec.KindRestart, nil)
		if r == nil || r.Value("reboot") != "1" || r.Value("source") != "sysUpTime,hrSystemUptime" {
			t.Fatalf("reboot %+v", r)
		}
	})
	t.Run("agent restart with HOST-RESOURCES", func(t *testing.T) {
		h := newHarness(t, agenttest.Options{Interfaces: twoIfs(), HostResources: true, MemTotal: 1 << 30}, defaultSettings())
		h.cycle()
		h.clock.Advance(60 * time.Second)
		h.a.Restart()
		ls := h.cycle()
		if r := find(ls, pollrec.KindRestart, nil); r == nil || r.Value("reboot") != "0" {
			t.Fatalf("restart %+v", r)
		}
	})
	t.Run("sysUpTime 497-day wrap", func(t *testing.T) {
		h := newHarness(t, agenttest.Options{Interfaces: twoIfs()}, defaultSettings())
		h.a.SetUptime(wrap32 - 3000)
		h.cycle()
		h.clock.Advance(60 * time.Second)
		ls := h.cycle()
		if r := find(ls, pollrec.KindRestart, nil); r != nil {
			t.Errorf("a marker for the wrap: %+v", r)
		}
		if s := find(ls, pollrec.KindSys, nil); s == nil || s.Value("uptime") != "3000" {
			t.Errorf("sys %+v", s)
		}
		if e := ifRec(ls, "1"); e == nil || e.Value("in_bps") == "" {
			t.Errorf("rates across the wrap: %+v", e)
		}
	})
	t.Run("engineBoots up (v3)", func(t *testing.T) {
		u := snmp.User{Name: "monitor", Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128, AuthPass: []byte("maplesyrup-test"),
			PrivPass: []byte("privpass-for-tests"), Level: snmp.AuthPriv}
		s := defaultSettings()
		s.Version, s.V3User = "3", "monitor"
		h := newHarness(t, agenttest.Options{Interfaces: twoIfs()}, s, u)
		h.cycle()
		h.clock.Advance(60 * time.Second)
		h.a.Restart()
		ls := h.cycle()
		r := find(ls, pollrec.KindRestart, nil)
		if r == nil || r.Value("source") != "sysUpTime,engineBoots" || r.Value("boots") != "2" || r.Value("prev_boots") != "1" {
			t.Fatalf("restart %+v (lines %+v)", r, ls)
		}
		if st := h.p.States()["pt_1"]; st.EngineID == "" {
			t.Error("no engine in the state")
		}
	})
}

func TestFailuresAndBackoff(t *testing.T) {
	h := newHarness(t, agenttest.Options{Interfaces: twoIfs()}, defaultSettings())
	h.a.SetSilent(true)
	for i := 1; i <= 4; i++ {
		ls := h.cycle()
		if len(ls) != 1 || ls[0].rec.Kind != pollrec.KindStatus || ls[0].rec.Value("status") != "timeout" ||
			!strings.HasPrefix(ls[0].rec.Value("cred"), "#") || ls[0].rec.Value("detail") != "no answer" {
			t.Fatalf("cycle %d: %+v", i, ls)
		}
		h.clock.Advance(time.Minute)
	}
	st := h.p.States()["pt_1"]
	if st.Status != StateBackingOff || st.BackoffS != 240 || st.FailingSince == nil {
		t.Errorf("state %+v", st)
	}
	h.st.mu.Lock()
	h.st.fails = 10
	iv := h.st.effInterval()
	h.st.mu.Unlock()
	if iv != MaxBackoff {
		t.Errorf("backoff capped at %v", iv)
	}
	h.clock.Advance(UnreachableAfter)
	if u := h.p.Unreachable(); len(u) != 1 || u[0] != "127.0.0.1" {
		t.Errorf("unreachable %v", u)
	}
	h.a.SetSilent(false)
	if ls := h.cycle(); find(ls, pollrec.KindSys, nil) == nil {
		t.Errorf("after silence: %+v", ls)
	}
	if st := h.p.States()["pt_1"]; st.Status != StateOK || st.FailingSince != nil {
		t.Errorf("after answering: %+v", st)
	}
	if sum := h.p.Summary(); sum.Hour.Failures["timeout"] != 4 || sum.Hour.Cycles != 5 || sum.Answering != 1 {
		t.Errorf("summary %+v", sum)
	}
}

func TestV3WrongPassphrase(t *testing.T) {
	u := snmp.User{Name: "monitor", Auth: snmp.AuthSHA1, AuthPass: []byte("maplesyrup-test"), Level: snmp.AuthNoPriv}
	s := defaultSettings()
	s.Version, s.V3User = "3", "monitor"
	h := newHarness(t, agenttest.Options{}, s, u)
	bad := u
	bad.AuthPass = []byte("not-the-passphrase")
	h.p.o.Creds.(*memCreds).users["monitor"] = bad
	h.st.mu.Lock()
	h.st.sess = nil
	h.st.mu.Unlock()
	ls := h.cycle()
	if len(ls) != 1 || ls[0].rec.Value("status") != "auth_failed" || ls[0].rec.Value("cred") != "monitor" {
		t.Errorf("%+v", ls)
	}
}

func TestSelectInterfaces(t *testing.T) {
	rows := []ifRow{
		{index: 1, name: "lo", oper: 1, speed: 10},
		{index: 2, name: "eth0", oper: 1, speed: 1000},
		{index: 3, name: "eth1", oper: 2, speed: 10000},
		{index: 4, name: "eth2", oper: 1, speed: 10000},
		{index: 5, name: "eth3", oper: 2, speed: 1},
	}
	got := func(s Settings) string {
		var n []string
		for _, r := range selectInterfaces(rows, s) {
			n = append(n, r.name)
		}
		return strings.Join(n, ",")
	}
	s := Settings{Interfaces: Interfaces{All: true}, MaxInterfaces: 3}
	if g := got(s); g != "lo,eth0,eth2" {
		t.Errorf("up by speed: %s", g)
	}
	s.Pinned = []IfRef{{Name: "eth3"}}
	if g := got(s); g != "eth0,eth2,eth3" {
		t.Errorf("pinned first: %s", g)
	}
	s = Settings{Interfaces: Interfaces{List: []IfRef{{Name: "eth1"}, {Index: 1}}}, MaxInterfaces: 64}
	if g := got(s); g != "lo,eth1" {
		t.Errorf("list: %s", g)
	}
}

func TestLeftOutInterfaces(t *testing.T) {
	var ifs []agenttest.Interface
	for i := 1; i <= 10; i++ {
		ifs = append(ifs, agenttest.Interface{Index: i, Name: "ge" + string(rune('0'+i%10)), SpeedMbps: uint64(i * 100)})
	}
	s := defaultSettings()
	s.MaxInterfaces = 4
	h := newHarness(t, agenttest.Options{Interfaces: ifs}, s)
	ls := h.cycle()
	n := 0
	for _, l := range ls {
		if l.rec.Kind == pollrec.KindIf {
			n++
		}
	}
	if n != 4 {
		t.Errorf("%d interfaces polled, want 4", n)
	}
	st := h.p.States()["pt_1"]
	if st.InterfacesPolled != 4 || st.InterfacesTotal != 10 {
		t.Errorf("state %+v", st)
	}
	// The fastest four (all up): indexes 7-10.
	if ifRec(ls, "10") == nil || ifRec(ls, "7") == nil || ifRec(ls, "6") != nil {
		t.Error("not the fastest four")
	}
}

// TestSchedulerOverrunsAndPause uses the real clock: a slow agent makes the
// next cycle due while one runs (an overrun), and a paused store stops
// polling.
func TestSchedulerOverrunsAndPause(t *testing.T) {
	a, err := agenttest.Start(agenttest.Options{Community: testComm, Interfaces: twoIfs()})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	sink := &memSink{}
	p := New(Options{Sink: sink, Creds: &memCreds{comm: map[string][]byte{"pt_1": []byte(testComm)}}})
	defer p.Close()
	s := defaultSettings()
	s.Port, s.IntervalS, s.TimeoutMS, s.Presets = int(a.Addr().Port()), 1, 3000, []string{config.PresetSystem}
	a.SetDelay(1600 * time.Millisecond)
	p.SetTargets([]Target{{ID: "pt_1", Settings: s}})
	time.Sleep(4500 * time.Millisecond)
	if p.Overruns() == 0 {
		t.Error("no overrun with a 1.6 s reply at a 1 s interval")
	}
	if find(sink.take(), pollrec.KindStatus, func(r *pollrec.Record) bool { return r.Value("status") == "overrun" }) == nil {
		t.Error("no overrun record")
	}
	a.SetDelay(0)
	time.Sleep(2 * time.Second) // let the slow cycles drain
	sink.paused.Store(true)
	time.Sleep(200 * time.Millisecond)
	before := a.Requests()["get"]
	time.Sleep(2500 * time.Millisecond)
	if after := a.Requests()["get"]; after != before {
		t.Errorf("polled while paused: %d -> %d", before, after)
	}
	sink.paused.Store(false)
	time.Sleep(2500 * time.Millisecond)
	if a.Requests()["get"] == before {
		t.Error("didn't resume")
	}
}

// With no targets the poller opens no socket (so it can send nothing), and
// it closes the socket when the last target goes.
func TestNoTargetsNoSocket(t *testing.T) {
	var sent atomic.Int64
	p := New(Options{Sink: &memSink{}, Creds: &memCreds{}, OnSend: func(netip.AddrPort) { sent.Add(1) }})
	defer p.Close()
	p.SetTargets(nil)
	off := defaultSettings()
	off.Enabled, off.Port = false, 9
	p.SetTargets([]Target{{ID: "pt_off", Settings: off}})
	time.Sleep(100 * time.Millisecond)
	p.mu.Lock()
	open := p.sock != nil
	p.mu.Unlock()
	if open || sent.Load() != 0 {
		t.Errorf("socket open %v, %d sent, with only a disabled target", open, sent.Load())
	}
	on := off
	on.Enabled = true
	p.SetTargets([]Target{{ID: "pt_on", Settings: on}})
	p.mu.Lock()
	open = p.sock != nil
	p.mu.Unlock()
	if !open {
		t.Error("no socket with a target")
	}
	p.SetTargets(nil)
	p.mu.Lock()
	open = p.sock != nil
	p.mu.Unlock()
	if open {
		t.Error("socket still open with no targets")
	}
}

// TestPollerCantSendASet: internal/poller builds requests only through
// snmp.Session (Get, GetNext, GetBulk); it never references the encoders or
// PDU types that could build anything else (SPEC §12.2).
func TestPollerCantSendASet(t *testing.T) {
	forbidden := map[string]bool{"EncodePDU": true, "EncodeV3": true, "EncodeCommunity": true, "EncodeRequest": true,
		"EncodeRequestV3": true, "EncodeDiscovery": true, "PDUSet": true, "PDUType": true, "PDU": true, "ResponseTo": true,
		"FailureReport": true, "Reply": true, "PDUGet": true, "PDUGetNext": true, "PDUGetBulk": true, "PDUResponse": true,
		"PDUInform": true, "PDUTrap": true, "PDUV1Trap": true, "PDUReport": true, "Request": true, "RequestKind": true}
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, b, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "snmp" && forbidden[sel.Sel.Name] {
				t.Errorf("%s uses snmp.%s", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			return true
		})
	}
	if checked < 5 {
		t.Fatalf("checked only %d files", checked)
	}
}

// A target added while another is already polled gets polled too (it shares
// the open socket).
func TestTargetAddedLater(t *testing.T) {
	a, err := agenttest.Start(agenttest.Options{Community: testComm})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	sink := &memSink{}
	p := New(Options{Sink: sink, Creds: &memCreds{comm: map[string][]byte{"pt_1": []byte(testComm), "pt_2": []byte(testComm)}},
		IntervalUnit: 10 * time.Millisecond})
	defer p.Close()
	s := defaultSettings()
	s.Port, s.Presets = int(a.Addr().Port()), []string{config.PresetSystem}
	p.SetTargets([]Target{{ID: "pt_1", Settings: s}})
	s2 := s
	s2.DeviceID = "127.0.0.2"
	p.SetTargets([]Target{{ID: "pt_1", Settings: s}, {ID: "pt_2", Settings: s2}})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := p.States()
		if st["pt_1"].Status == StateOK && st["pt_2"].Status == StateOK {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("states %+v", p.States())
}

func TestTestPoll(t *testing.T) {
	a, err := agenttest.Start(agenttest.Options{Community: testComm, Interfaces: twoIfs(), SysName: "edge-fw-01",
		Extra: map[string]snmp.Value{"1.3.6.1.4.1.32473.1.2.0": {Kind: snmp.KindGauge32, Uint: 17}}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	s := defaultSettings()
	s.Port = int(a.Addr().Port())
	s.Custom = []Custom{{OID: "1.3.6.1.4.1.32473.1.2.0", Kind: CustomScalar, Label: "queue depth"}, {OID: "1.3.6.1.4.1.32473.9", Kind: CustomWalk, MaxRows: 5}}
	res := StandaloneTest(context.Background(), s, []byte(testComm), nil)
	if res.Exit != ExitPartial || res.OK || len(res.Steps) != 5 {
		t.Fatalf("%+v", res)
	}
	want := map[string]bool{"system": true, "host_resources": false, "interfaces": true, "oid 1.3.6.1.4.1.32473.1.2.0 (queue depth)": true,
		"oid 1.3.6.1.4.1.32473.9": false}
	for _, st := range res.Steps {
		if ok, found := want[st.Step]; !found || ok != st.OK {
			t.Errorf("step %+v", st)
		}
	}
	if !strings.Contains(res.Steps[0].Detail, "edge-fw-01") || !strings.Contains(res.Steps[2].Detail, "2 interfaces, 64-bit counters; 2 would be polled") {
		t.Errorf("details %+v", res.Steps)
	}
	if ExitCode(res.Exit) != 4 {
		t.Error("exit code")
	}
	// No answer, and a wrong source.
	res = StandaloneTest(context.Background(), s, []byte("wrong"), nil)
	if res.Exit != ExitNoAnswer || ExitCode(res.Exit) != 1 {
		t.Errorf("wrong community %+v", res)
	}
	a.SetWrongSource(true)
	res = StandaloneTest(context.Background(), s, []byte(testComm), nil)
	if res.Exit != ExitNoAnswer || res.Steps[len(res.Steps)-1].Step != "replies" {
		t.Errorf("wrong source %+v", res)
	}
	// v3 with a wrong passphrase: auth.
	u := snmp.User{Name: "monitor", Auth: snmp.AuthSHA1, AuthPass: []byte("maplesyrup-test"), Level: snmp.AuthNoPriv}
	b, err := agenttest.Start(agenttest.Options{Users: []snmp.User{u}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	s3 := defaultSettings()
	s3.Port, s3.Version, s3.V3User, s3.Presets = int(b.Addr().Port()), "3", "monitor", []string{config.PresetInterfaces}
	res = StandaloneTest(context.Background(), s3, nil, &u)
	if res.Exit != ExitOK || res.Steps[0].Step != "discovery" || !strings.Contains(res.Steps[0].Detail, "boots 1") {
		t.Errorf("v3 %+v", res)
	}
	bad := u
	bad.AuthPass = []byte("not-the-passphrase")
	res = StandaloneTest(context.Background(), s3, nil, &bad)
	if res.Exit != ExitAuth || ExitCode(res.Exit) != 3 {
		t.Errorf("v3 wrong pass %+v", res)
	}
}
