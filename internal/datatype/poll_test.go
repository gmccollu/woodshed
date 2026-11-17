package datatype

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// Poll records as the poller writes them (SPEC §12.3).
var pollRecs = map[string]string{
	"sys":     `kind=sys cycle=1042 uptime=104512345 hr_uptime=104513000 cpu=12 mem_used=3221225472 mem_total=8589934592 rtt_ms=4 interval_s=60`,
	"eth3":    `kind=if cycle=1042 if=3 name="eth3" oper=up speed_mbps=1000 in_octets=987654321012 out_octets=123456789012 in_bps=81234567 out_bps=3456789 in_err=12 out_err=0 in_err_d=0 out_err_d=0 in_disc=340 out_disc=0 in_disc_d=0 out_disc_d=0`,
	"eth1dn":  `kind=if cycle=1043 if=1 name="Eth1" oper=down oper_was=up speed_mbps=1000 in_octets=5 out_octets=6`,
	"oid":     `kind=oid cycle=1042 oid=1.3.6.1.4.1.32473.1.2.0 label="queue depth" type=g32 value=17`,
	"timeout": `kind=status cycle=1043 status=timeout detail="no answer after 1 retry" interval_s=60`,
	"restart": `kind=restart cycle=1046 reboot=1 uptime=1532 prev_uptime=104518345 source=sysUpTime,hrSystemUptime`,
	"info":    `kind=info cycle=1042 if=3 name="eth3" descr="eth3" alias="uplink" speed_mbps=1000`,
}

func TestPollParams(t *testing.T) {
	has := func(names ...string) func(string) bool {
		return func(p string) bool { return slices.Contains(names, p) }
	}
	var pe *ParamError
	if err := CheckParams(Get(Poll), has("severities")); !errors.As(err, &pe) || pe.Msg != "severities: not a filter for SNMP polls." {
		t.Errorf("poll with severities: %v", err)
	}
	if err := CheckParams(Get(Poll), has("trap_oid")); err == nil || err.Error() != "trap_oid: not a filter for SNMP polls." {
		t.Errorf("poll with trap_oid: %v", err)
	}
	if err := CheckParams(Get(Trap), has("kinds")); err == nil || err.Error() != "kinds: not a filter for SNMP traps." {
		t.Errorf("trap with kinds: %v", err)
	}
	if err := CheckParams(Get(Syslog), has("poll_status")); err == nil || err.Error() != "poll_status: not a filter for syslog." {
		t.Errorf("syslog with poll_status: %v", err)
	}
	if CheckParams(Get(Poll), has("q", "kinds", "ifs", "exclude_ifs", "oper", "poll_status", "reboot", "devices")) != nil {
		t.Error("own parameters refused")
	}
	if Get(Poll).Label() != "SNMP polls" || Get(Poll).Dir() != "poll" || Get(Poll).Default() {
		t.Error("poll type")
	}
}

func TestPollFieldValues(t *testing.T) {
	ty := Get(Poll)
	want := map[string]map[string]string{
		"sys":     {"kind": "sys", "if": "", "oper": "", "status": "ok", "reboot": ""},
		"eth3":    {"kind": "if", "if": "eth3", "oper": "up", "status": "ok", "reboot": ""},
		"timeout": {"kind": "status", "status": "timeout"},
		"restart": {"kind": "restart", "reboot": "1", "status": "ok"},
		"info":    {"kind": "info", "if": "eth3"},
	}
	for name, w := range want {
		got := map[string]string{}
		ty.FieldValues([]byte(pollRecs[name]), &Scratch{}, func(k, v string) { got[k] = v })
		for k, v := range w {
			if got[k] != v {
				t.Errorf("%s: %s = %q, want %q", name, k, got[k], v)
			}
		}
	}
	if ty.ValueLabel(FieldStatus, "overrun") != "skipped (overrun)" || ty.ValueLabel(FieldReboot, "?") != "restart (may have rebooted)" ||
		ty.ValueLabel(FieldKind, "if") != "interface" {
		t.Error("labels")
	}
}

func TestPollFilter(t *testing.T) {
	cases := []struct {
		params map[string]string
		want   string
	}{
		{map[string]string{}, "eth1dn eth3 info oid restart sys timeout"},
		{map[string]string{"kinds": "if"}, "eth1dn eth3"},
		{map[string]string{"kinds": "none"}, ""},
		{map[string]string{"ifs": "ETH3"}, "eth3 info"},
		{map[string]string{"ifs": "1"}, "eth1dn"},
		{map[string]string{"exclude_ifs": "eth3"}, "eth1dn oid restart sys timeout"},
		{map[string]string{"oper": "down"}, "eth1dn"},
		{map[string]string{"poll_status": "timeout"}, "timeout"},
		{map[string]string{"poll_status": "ok", "kinds": "sys,status"}, "sys"},
		{map[string]string{"reboot": "1,?"}, "restart"},
	}
	for _, c := range cases {
		f, err := ParsePollFilter(func(k string) string { return c.params[k] })
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for name, rec := range pollRecs {
			if f.Pre([]byte(rec)) && f.Post([]byte(rec), &Scratch{}) {
				got = append(got, name)
			}
		}
		sort.Strings(got)
		if g := strings.Join(got, " "); g != c.want {
			t.Errorf("%v: %q, want %q", c.params, g, c.want)
		}
	}
	for _, bad := range []map[string]string{{"kinds": "flow"}, {"oper": "sideways"}, {"poll_status": "ok,none"}, {"reboot": "2"}} {
		if _, err := ParsePollFilter(func(k string) string { return bad[k] }); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	f, _ := ParsePollFilter(func(k string) string { return map[string]string{"kinds": "if,sys"}[k] })
	if n, ok := f.WithKinds("sys", "status", "restart"); !ok || !slices.Equal(n.Kinds, []string{"sys"}) {
		t.Errorf("WithKinds %+v", n)
	}
	if _, ok := f.WithKinds("oid"); ok {
		t.Error("WithKinds oid")
	}
	if b, _ := json.Marshal(f); string(b) != `{"kinds":["if","sys"]}` {
		t.Errorf("json %s", b)
	}
}

func TestPollResult(t *testing.T) {
	r := PollResultOf([]byte(pollRecs["eth3"]))
	if r.Kind != "if" || r.Cycle != 1042 || r.If != "eth3" || r.Oper != "up" || r.Status != "ok" || r.Values["in_bps"] != "81234567" ||
		r.Values["if"] != "3" {
		t.Errorf("%+v", r)
	}
	if _, ok := r.Values["oper"]; ok {
		t.Error("oper in values")
	}
	r = PollResultOf([]byte(pollRecs["restart"]))
	if r.Reboot != "1" || r.Values["source"] != "sysUpTime,hrSystemUptime" {
		t.Errorf("%+v", r)
	}
	if r := PollResultOf([]byte("not a record")); r.Kind != "" || r.Values["error"] == "" {
		t.Errorf("%+v", r)
	}
}

func TestPollSummary(t *testing.T) {
	s := Get(Poll).NewSummary().(*PollSummary)
	base := time.Date(2026, 11, 15, 9, 30, 0, 0, time.UTC)
	add := func(sec int, rec string) { s.Add([]byte(rec), base.Add(time.Duration(sec)*time.Second)) }
	add(0, `kind=sys cycle=1 uptime=100000 hr_uptime=100000 cpu=91 mem_used=72 mem_total=100 interval_s=60`)
	add(0, `kind=if cycle=1 if=1 name="eth1" oper=up in_bps=812000000 out_bps=95000000 in_err_d=0 out_err_d=0 in_disc_d=0 out_disc_d=0`)
	add(0, `kind=if cycle=1 if=3 name="eth3" oper=up in_bps=1000 out_bps=10 in_err_d=12 out_err_d=0 in_disc_d=340 out_disc_d=0`)
	add(58, `kind=if cycle=2 if=3 name="eth3" oper=down oper_was=up in_err_d=0 out_err_d=0`)
	add(60, `kind=status cycle=3 status=timeout detail="no answer" interval_s=60`)
	add(100, `kind=if cycle=4 if=3 name="eth3" oper=up oper_was=down`)
	add(100, `kind=sys cycle=4 uptime=104512345 cpu=10 interval_s=60`)
	add(101, `kind=restart cycle=4 reboot=1 uptime=1 prev_uptime=2 source=sysUpTime,hrSystemUptime`)
	st := s.Stats()
	if st.Cycles != 4 || st.Answered != 3 || *st.IntervalS != 60 || *st.UptimeEndS != 1045123 || st.PeakInIf != "eth1" ||
		*st.ErrorsInD != 12 || *st.DiscardsInD != 340 || *st.CPUPeak != 91 || *st.MemPeakPct != 72 || len(st.OperChanges) != 1 ||
		st.OperChanges[0].Up == nil {
		t.Fatalf("%+v", st)
	}
	got := s.README(8, "09:30:00.000", "09:31:41.000")
	want := []string{
		"3 of 4 cycles answered (60 s); uptime 12 d 2 h at the end of the window",
		"peak in 812 Mb/s (eth1, 09:30), peak out 95 Mb/s (eth1, 09:30); CPU peak 91 % (09:30), memory peak 72 %",
		"errors +12 in (eth3), +0 out; discards +340 in (eth3), +0 out; eth3 down 09:30:58 to 09:31:40",
	}
	if !slices.Equal(got, want) {
		t.Errorf("README:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	rb := s.Reboots()
	if len(rb) != 1 || rb[0].Source != "poll" || rb[0].Detail != "sysUpTime and hrSystemUptime reset" || rb[0].Reboot != "1" || !rb[0].IsReboot() {
		t.Errorf("reboots %+v", rb)
	}
	if b, _ := json.Marshal(st); !strings.Contains(string(b), `"peak_in_if":"eth1"`) || !strings.Contains(string(b), `"oper_changes":[{"if":"eth3"`) {
		t.Errorf("json %s", b)
	}
	// Nothing measured: the fields are null, never 0.
	e := (&PollSummary{}).Stats()
	if b, _ := json.Marshal(e); !strings.Contains(string(b), `"cpu_peak":null`) || !strings.Contains(string(b), `"oper_changes":[]`) {
		t.Errorf("empty json %s", b)
	}
}

// Samples are the answered polls (sys lines) with hrSystemUptime when they
// carry it, oldest first, each tied to its cycle's restart line whichever was
// read first (the bundle reads traps against them, SPEC §12.6).
func TestPollSummarySamples(t *testing.T) {
	s := Get(Poll).NewSummary().(*PollSummary)
	t0 := time.Date(2026, 11, 16, 4, 0, 0, 0, time.UTC)
	s.Add([]byte(`kind=sys cycle=7 uptime=100 hr_uptime=5000 interval_s=60`), t0)
	s.Add([]byte(`kind=status cycle=8 status=timeout detail="no answer" interval_s=60`), t0.Add(time.Minute))
	s.Add([]byte(`kind=restart cycle=9 reboot=0 uptime=10 prev_uptime=100 source="sysUpTime"`), t0.Add(2*time.Minute))
	s.Add([]byte(`kind=sys cycle=9 uptime=10 hr_uptime=17000 interval_s=60`), t0.Add(2*time.Minute))
	s.Add([]byte(`kind=sys cycle=10 uptime=6010 interval_s=60`), t0.Add(3*time.Minute))
	got := s.Samples()
	if len(got) != 3 || !got[0].HaveHr || got[0].Hr != 5000 || got[0].HasRestart ||
		!got[1].HasRestart || !got[1].RestartAt.Equal(t0.Add(2*time.Minute)) || got[1].Hr != 17000 ||
		got[2].HaveHr || got[2].HasRestart {
		t.Errorf("samples %+v", got)
	}
}
