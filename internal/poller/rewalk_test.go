package poller

import (
	"context"
	"log/slog"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

// Interfaces that appear after the agent starts, and the interface table's
// change signals (SPEC §12.1): the restart follow-up walks, ifNumber and
// ifTableLastChange, and what they cost in steady state. Every test drives
// the cycles itself on a fake clock, so request counts are exact.

var (
	oidIfNumberPrefix = snmp.OID{1, 3, 6, 1, 2, 1, 2, 1}     // ifNumber (ifTable is 2.2)
	oidIfLastPrefix   = snmp.OID{1, 3, 6, 1, 2, 1, 31, 1, 5} // ifTableLastChange
)

func lateIf(index int, name string) agenttest.Interface {
	return agenttest.Interface{Index: index, Name: name, Descr: name, SpeedMbps: 10000, InBps: 2e6, OutBps: 2e6}
}

// rewalkSettings are the defaults with a timeout long enough that a busy
// runner never retries a request (retries would change the counts).
func rewalkSettings() Settings {
	s := defaultSettings()
	s.TimeoutMS = 30000
	return s
}

// counted runs one cycle and returns its records and the walk requests
// (GetBulk and GetNext) and Gets it sent.
func (h *harness) counted() (ls []line, walks, gets int) {
	h.t.Helper()
	before := h.a.Requests()
	ls = h.cycle()
	after := h.a.Requests()
	return ls, after["getbulk"] + after["getnext"] - before["getbulk"] - before["getnext"], after["get"] - before["get"]
}

func ifInfo(ls []line, idx string) *pollrec.Record {
	return find(ls, pollrec.KindInfo, func(r *pollrec.Record) bool { return r.Value("if") == idx })
}

func sysInfo(ls []line) *pollrec.Record {
	return find(ls, pollrec.KindInfo, func(r *pollrec.Record) bool { return r.Value("if") == "" })
}

// firstSample checks an interface's first sample after it appeared: polled,
// no rate yet, and no discontinuity.
func firstSample(t *testing.T, ls []line, idx string) {
	t.Helper()
	if e := ifRec(ls, idx); e == nil || e.Value("in_bps") != "" || e.Value("disc") != "" || e.Value("in_octets") == "" {
		t.Errorf("first sample of if %s: %+v", idx, e)
	}
	if ifInfo(ls, idx) == nil {
		t.Errorf("no info record for if %s", idx)
	}
}

// steadyRate checks an interface that was polled before: a rate, no
// discontinuity.
func steadyRate(t *testing.T, ls []line, idx string) {
	t.Helper()
	if e := ifRec(ls, idx); e == nil || e.Value("in_bps") == "" || e.Value("disc") != "" {
		t.Errorf("if %s: %+v", idx, e)
	}
}

func noStatus(t *testing.T, ls []line) {
	t.Helper()
	if s := find(ls, pollrec.KindStatus, nil); s != nil {
		t.Errorf("a status record: %+v", s)
	}
}

// The lab case: after a reboot the agent answers 2 s in, and an interface
// (a bridge) appears 20 s after the reboot. With a 60 s interval it's polled
// at the first follow-up walk, with or without ifNumber and
// ifTableLastChange; one that appears after about 3 minutes (a line card) is
// caught by ifNumber at once or, without it, by the 5th-cycle follow-up.
func TestLateInterfaceAfterRestart(t *testing.T) {
	for _, tc := range []struct {
		name     string
		signals  bool          // the agent answers ifNumber and ifTableLastChange
		appear   time.Duration // after the reboot
		polledAt int           // the first cycle after the restart's (0) that polls it
		walksAt  []int         // the cycles that walk the interface table
	}{
		{"20 s, with ifNumber", true, 20 * time.Second, 1, []int{0, 1, 2, 5}},
		{"20 s, without change signals", false, 20 * time.Second, 1, []int{0, 1, 2, 5}},
		{"200 s, with ifNumber", true, 200 * time.Second, 4, []int{0, 1, 2, 4, 5}},
		{"200 s, without change signals", false, 200 * time.Second, 5, []int{0, 1, 2, 5}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ifs := append(twoIfs(), lateIf(3, "br0"))
			h := newHarness(t, agenttest.Options{Interfaces: ifs, HostResources: true, MemTotal: 1 << 30}, rewalkSettings())
			if !tc.signals {
				h.a.SetNoSuchObject(oidIfNumberPrefix)
				h.a.SetNoSuchObject(oidIfLastPrefix)
			}
			h.cycle()
			h.clock.Advance(60 * time.Second)
			if ls := h.cycle(); ifRec(ls, "3") == nil {
				t.Fatalf("br0 isn't polled before the reboot: %+v", ls)
			}
			h.clock.Advance(58 * time.Second)
			h.a.RemoveInterface(3) // gone while the device is down
			h.a.Reboot()
			bootAt := h.clock.Now()
			h.clock.Advance(2 * time.Second) // the agent answers 2 s after the reboot
			added := false
			for k := 0; k <= 7; k++ {
				at := bootAt.Add(2*time.Second + time.Duration(k)*time.Minute)
				if !added && !bootAt.Add(tc.appear).After(at) {
					h.clock.Advance(bootAt.Add(tc.appear).Sub(h.clock.Now()))
					h.a.AddInterface(lateIf(3, "br0"))
					added = true
				}
				h.clock.Advance(at.Sub(h.clock.Now()))
				ls, walks, _ := h.counted()
				noStatus(t, ls)
				if r := find(ls, pollrec.KindRestart, nil); (r != nil) != (k == 0) {
					t.Fatalf("cycle %d: restart marker %+v", k, r)
				}
				if want := slices.Contains(tc.walksAt, k); (walks > 0) != want {
					t.Errorf("cycle %d: %d walk requests, want a walk: %v", k, walks, want)
				}
				switch {
				case k < tc.polledAt:
					if e := ifRec(ls, "3"); e != nil {
						t.Errorf("cycle %d: br0 polled before it appeared: %+v", k, e)
					}
				case k == tc.polledAt:
					firstSample(t, ls, "3")
					if si := sysInfo(ls); si == nil || si.Value("ifs_total") != "3" || si.Value("ifs_polled") != "3" {
						t.Errorf("cycle %d: system info %+v", k, si)
					}
				default:
					steadyRate(t, ls, "3")
					if e := ifRec(ls, "3"); e != nil {
						near(t, "br0 in_bps", e.Value("in_bps"), 2e6, 0.001)
					}
				}
				if k == 0 {
					if e := ifRec(ls, "1"); e == nil || e.Value("disc") != "1" {
						t.Errorf("the restart cycle: %+v", e)
					}
				} else {
					steadyRate(t, ls, "1") // a new interface is no discontinuity on the others
					steadyRate(t, ls, "2")
				}
			}
		})
	}
}

// Between hourly walks, a changed ifNumber or ifTableLastChange walks the
// table at that cycle; a second change within changeGap of that walk waits
// for it.
func TestInterfaceTableChangeRefreshes(t *testing.T) {
	start := func(t *testing.T, hide ...snmp.OID) *harness {
		h := newHarness(t, agenttest.Options{Interfaces: twoIfs()}, rewalkSettings())
		for _, o := range hide {
			h.a.SetNoSuchObject(o)
		}
		h.cycle()
		for range 2 {
			h.clock.Advance(60 * time.Second)
			if _, walks, _ := h.counted(); walks != 0 {
				t.Fatalf("%d walk requests in steady state", walks)
			}
		}
		return h
	}
	t.Run("ifNumber", func(t *testing.T) {
		h := start(t, oidIfLastPrefix)
		h.clock.Advance(30 * time.Second)
		h.a.AddInterface(lateIf(3, "tun0"))
		h.clock.Advance(30 * time.Second)
		ls, walks, _ := h.counted()
		noStatus(t, ls)
		if walks == 0 {
			t.Fatal("no walk after ifNumber changed")
		}
		firstSample(t, ls, "3")
		steadyRate(t, ls, "1")
		steadyRate(t, ls, "2")
		if si := sysInfo(ls); si == nil || si.Value("ifs_total") != "3" || si.Value("ifs_polled") != "3" {
			t.Errorf("system info %+v", si)
		}
		h.clock.Advance(60 * time.Second)
		ls, walks, _ = h.counted()
		if walks != 0 {
			t.Errorf("%d walk requests the cycle after", walks)
		}
		steadyRate(t, ls, "3")
		if sysInfo(ls) != nil {
			t.Error("system info again the cycle after")
		}
	})
	t.Run("ifTableLastChange", func(t *testing.T) {
		// One interface replaced by another: ifNumber (left out here anyway)
		// would stay 2; ifTableLastChange moves.
		h := start(t, oidIfNumberPrefix)
		h.clock.Advance(30 * time.Second)
		h.a.RemoveInterface(2)
		h.a.AddInterface(lateIf(3, "tun0"))
		h.clock.Advance(30 * time.Second)
		ls, walks, _ := h.counted()
		noStatus(t, ls)
		if walks == 0 {
			t.Fatal("no walk after ifTableLastChange changed")
		}
		firstSample(t, ls, "3")
		steadyRate(t, ls, "1")
		if e := ifRec(ls, "2"); e != nil {
			t.Errorf("the removed interface is still polled: %+v", e)
		}
		if sysInfo(ls) != nil {
			t.Error("system info though the counts didn't change")
		}
	})
	t.Run("removed", func(t *testing.T) {
		h := start(t)
		h.clock.Advance(30 * time.Second)
		h.a.RemoveInterface(2)
		h.clock.Advance(30 * time.Second)
		ls, walks, _ := h.counted()
		noStatus(t, ls)
		if walks == 0 {
			t.Fatal("no walk after an interface went")
		}
		if e := ifRec(ls, "2"); e != nil {
			t.Errorf("the removed interface is still polled: %+v", e)
		}
		steadyRate(t, ls, "1")
		if si := sysInfo(ls); si == nil || si.Value("ifs_total") != "1" || si.Value("ifs_polled") != "1" {
			t.Errorf("system info %+v", si)
		}
	})
	t.Run("a second change within changeGap", func(t *testing.T) {
		h := start(t)
		h.clock.Advance(60 * time.Second)
		h.a.AddInterface(lateIf(3, "tun0"))
		walkedAt := h.clock.Now()
		if ls, walks, _ := h.counted(); walks == 0 || ifRec(ls, "3") == nil {
			t.Fatalf("the first change: %d walk requests, %+v", walks, ls)
		}
		h.clock.Advance(30 * time.Second)
		h.a.AddInterface(lateIf(4, "tun1"))
		h.clock.Advance(30 * time.Second)
		for h.clock.Now().Sub(walkedAt) < changeGap {
			ls, walks, _ := h.counted()
			if walks != 0 || ifRec(ls, "4") != nil {
				t.Fatalf("%v after the first change walk: %d walk requests, if 4 %+v", h.clock.Now().Sub(walkedAt), walks, ifRec(ls, "4"))
			}
			steadyRate(t, ls, "3")
			h.clock.Advance(60 * time.Second)
		}
		ls, walks, _ := h.counted()
		if walks == 0 {
			t.Fatalf("no walk %v after the first change walk", h.clock.Now().Sub(walkedAt))
		}
		firstSample(t, ls, "4")
		steadyRate(t, ls, "3")
	})
}

// countHandler counts the log records the poller writes.
type countHandler struct{ n *atomic.Int64 }

func (h countHandler) Enabled(context.Context, slog.Level) bool  { return true }
func (h countHandler) Handle(context.Context, slog.Record) error { h.n.Add(1); return nil }
func (h countHandler) WithAttrs([]slog.Attr) slog.Handler        { return h }
func (h countHandler) WithGroup(string) slog.Handler             { return h }

// An agent without ifTableLastChange (or ifNumber) is polled as usual: the
// OID is left out after its first answer, with no status record, event or log
// line, and costs no request in steady state (v1, whose noSuchName makes the
// session ask again, pays one extra Get at the hourly try).
func TestMissingChangeSignalsAreQuiet(t *testing.T) {
	for _, tc := range []struct {
		name    string
		version string
		ao      agenttest.Options
		hide    []snmp.OID
		numOff  bool
	}{
		{"v2c without ifTableLastChange", "2c", agenttest.Options{}, []snmp.OID{oidIfLastPrefix}, false},
		{"v2c without either", "2c", agenttest.Options{}, []snmp.OID{oidIfLastPrefix, oidIfNumberPrefix}, true},
		{"v1 without ifXTable", "1", agenttest.Options{NoIfXTable: true}, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var events, logs atomic.Int64
			s := rewalkSettings()
			s.Version = tc.version
			ao := tc.ao
			ao.Interfaces = twoIfs()
			h := newHarnessWith(t, ao, s, func(o *Options) {
				o.Event = func(string, string) { events.Add(1) }
				o.Logger = slog.New(countHandler{&logs})
			})
			for _, o := range tc.hide {
				h.a.SetNoSuchObject(o)
			}
			noStatus(t, h.cycle())
			for i := range 10 {
				h.clock.Advance(60 * time.Second)
				ls, walks, gets := h.counted()
				noStatus(t, ls)
				// The system Get and the counters' Get, nothing more.
				if walks != 0 || gets != 2 {
					t.Errorf("cycle %d: %d walk requests, %d Gets", i+2, walks, gets)
				}
				if s := find(ls, pollrec.KindSys, nil); s == nil || s.Value("uptime") == "" {
					t.Errorf("cycle %d: sys %+v", i+2, s)
				}
				steadyRate(t, ls, "1")
			}
			h.clock.Advance(time.Hour) // the hourly try and walk
			noStatus(t, h.cycle())
			h.st.mu.Lock()
			numOff, lastOff := h.st.ifNumOff, h.st.ifLastOff
			h.st.mu.Unlock()
			if numOff != tc.numOff || !lastOff {
				t.Errorf("ifNumOff %v ifLastOff %v, want %v true", numOff, lastOff, tc.numOff)
			}
			if events.Load() != 0 || logs.Load() != 0 {
				t.Errorf("%d events and %d log records", events.Load(), logs.Load())
			}
		})
	}
}

// No extra requests in steady state: over 30 cycles, every cycle is the
// system Get and the counters' Get (the change signals ride in the first),
// and nothing is walked.
func TestNoExtraWalksInSteadyState(t *testing.T) {
	u := snmp.User{Name: "monitor", Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128, AuthPass: []byte("maplesyrup-test"),
		PrivPass: []byte("privpass-for-tests"), Level: snmp.AuthPriv}
	for _, version := range []string{"1", "2c", "3"} {
		t.Run("v"+version, func(t *testing.T) {
			s := rewalkSettings()
			s.Version = version
			var users []snmp.User
			if version == "3" {
				s.V3User = "monitor"
				users = append(users, u)
			}
			h := newHarness(t, agenttest.Options{Interfaces: twoIfs(), HostResources: true, CPUs: []int{5}, MemTotal: 1 << 30}, s, users...)
			noStatus(t, h.cycle())
			before := h.a.Requests()
			const n = 30
			for range n {
				h.clock.Advance(60 * time.Second)
				noStatus(t, h.cycle())
			}
			after := h.a.Requests()
			if w := after["getbulk"] + after["getnext"] - before["getbulk"] - before["getnext"]; w != 0 {
				t.Errorf("%d walk requests in %d steady cycles", w, n)
			}
			if g := after["get"] - before["get"]; g != 2*n {
				t.Errorf("%d Gets in %d steady cycles, want %d", g, n, 2*n)
			}
			h.st.mu.Lock()
			numOff, lastOff := h.st.ifNumOff, h.st.ifLastOff
			h.st.mu.Unlock()
			if numOff || lastOff {
				t.Errorf("ifNumOff %v ifLastOff %v on an agent with both", numOff, lastOff)
			}
		})
	}
}
