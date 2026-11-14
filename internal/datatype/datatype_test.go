package datatype

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

var t0 = time.Date(2026, 11, 14, 9, 30, 58, 0, time.UTC)

func oid(s string) snmp.OID {
	o, err := snmp.ParseOID(s)
	if err != nil {
		panic(err)
	}
	return o
}

// v2cRecord is the record of a v2c trap (or inform) with the given trap OID and
// extra varbinds, as the receiver stores it.
func v2cRecord(t testing.TB, community string, typ snmp.PDUType, id int64, trap string, vbs ...snmp.Varbind) []byte {
	t.Helper()
	all := []snmp.Varbind{
		{OID: snmp.OIDSysUpTime, Value: snmp.Value{Kind: snmp.KindTimeTicks, Uint: 8641234}},
		{OID: snmp.OIDSnmpTrapOID, Value: snmp.Value{Kind: snmp.KindOID, OID: oid(trap)}},
	}
	all = append(all, vbs...)
	raw := snmp.EncodeCommunity(snmp.V2c, []byte(community), snmp.EncodePDU(&snmp.PDU{Type: typ, RequestID: id, Varbinds: all}))
	m := snmp.Decode(raw, nil, t0)
	return snmp.FormatRecord(nil, m, snmp.RecordOptions{Names: snmp.BuiltinMIBs()})
}

func v1Record(t testing.TB, community, enterprise string, generic, specific int64) []byte {
	t.Helper()
	raw := snmp.EncodeCommunity(snmp.V1, []byte(community), snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUV1Trap,
		Enterprise: oid(enterprise), AgentAddr: []byte{192, 0, 2, 9}, Generic: generic, Specific: specific, Timestamp: 100}))
	m := snmp.Decode(raw, nil, t0)
	return snmp.FormatRecord(nil, m, snmp.RecordOptions{Names: snmp.BuiltinMIBs()})
}

var ifOper = snmp.Varbind{OID: oid("1.3.6.1.2.1.2.2.1.8.3"), Value: snmp.Value{Kind: snmp.KindInteger, Int: 2}}

func TestRegistryMatchesStorage(t *testing.T) {
	if len(Types()) != len(logfile.DataTypes) {
		t.Fatalf("%d types, %d folders", len(Types()), len(logfile.DataTypes))
	}
	for i, ty := range Types() {
		if ty.Name() != logfile.DataTypes[i].Name || ty.Dir() != logfile.DataTypes[i].Dir {
			t.Errorf("%s/%q vs %+v", ty.Name(), ty.Dir(), logfile.DataTypes[i])
		}
		if ty.Fields()[0].Key != FieldDevice {
			t.Errorf("%s: device isn't the first field", ty.Name())
		}
	}
	if Get("") != Get(Syslog) || !Get("").Default() || Get("flow") != nil || Get(Trap).Label() != "SNMP traps" {
		t.Fatal("Get")
	}
}

// Each type refuses the other's filter parameters (SPEC §11.2.5).
func TestCheckParams(t *testing.T) {
	has := func(names ...string) func(string) bool {
		return func(p string) bool {
			for _, n := range names {
				if n == p {
					return true
				}
			}
			return false
		}
	}
	err := CheckParams(Get(Trap), has("q", "severities"))
	var pe *ParamError
	if !errors.As(err, &pe) || pe.Msg != "severities: not a filter for SNMP traps." {
		t.Fatalf("trap with severities: %v", err)
	}
	if err := CheckParams(Get(Syslog), has("trap_oid")); err == nil || err.Error() != "trap_oid: not a filter for syslog." {
		t.Fatalf("syslog with trap_oid: %v", err)
	}
	if CheckParams(Get(Trap), has("q", "trap_oid", "devices")) != nil || CheckParams(Get(Syslog), has("app", "q")) != nil {
		t.Fatal("own parameters refused")
	}
}

func TestTrapFieldsAndText(t *testing.T) {
	rec := v2cRecord(t, "public", snmp.PDUTrap, 4711, "1.3.6.1.6.3.1.1.5.3", ifOper)
	ty := Get(Trap)
	got := map[string]string{}
	ty.FieldValues(rec, &Scratch{}, func(k, v string) { got[k] = v })
	want := map[string]string{"version": "2c", "pdu": "trap", "trap_oid": "1.3.6.1.6.3.1.1.5.3", "cred": snmp.CommunityHash([]byte("public")),
		"status": "ok", "enterprise": "", "generic": "", "specific": ""}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if strings.Contains(string(ty.Text(rec)), "raw=") || !strings.Contains(string(rec), " raw=") {
		t.Fatalf("text %q", ty.Text(rec))
	}
	if ty.ValueLabel(FieldTrapOID, "1.3.6.1.6.3.1.1.5.3") != "linkDown" || ty.ValueLabel(FieldGeneric, "0") != "coldStart" ||
		ty.ValueLabel(FieldStatus, "auth_failed") != "wrong auth" {
		t.Fatal("labels")
	}
	// A record holding another PDU type is "unexpected".
	got = map[string]string{}
	ty.FieldValues(v2cRecord(t, "public", snmp.PDUGet, 1, "1.3.6.1.6.3.1.1.5.3"), &Scratch{}, func(k, v string) { got[k] = v })
	if got["pdu"] != PDUUnexpected || got["status"] != "unexpected_pdu" {
		t.Fatalf("get: %v", got)
	}
}

func parse(t *testing.T, params map[string]string) *TrapFilter {
	t.Helper()
	f, err := ParseTrapFilter(func(k string) string { return params[k] })
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestTrapFilter(t *testing.T) {
	linkDown := v2cRecord(t, "public", snmp.PDUTrap, 1, "1.3.6.1.6.3.1.1.5.3", ifOper)
	inform := v2cRecord(t, "private", snmp.PDUInform, 2, "1.3.6.1.4.1.32473.1.0.1")
	v1 := v1Record(t, "public", "1.3.6.1.4.1.32473.1", 6, 17)
	cold := v1Record(t, "public", "1.3.6.1.4.1.32473.1", 0, 0)
	all := map[string][]byte{"linkDown": linkDown, "inform": inform, "v1": v1, "cold": cold}
	cases := []struct {
		params map[string]string
		want   string // records passing, sorted names
	}{
		{map[string]string{}, "cold inform linkDown v1"},
		{map[string]string{"snmp_versions": "2c"}, "inform linkDown"},
		{map[string]string{"snmp_versions": "none"}, ""},
		{map[string]string{"pdus": "inform,v1trap"}, "cold inform v1"},
		{map[string]string{"trap_oid": "linkDown"}, "linkDown"},
		{map[string]string{"trap_oid": "IF-MIB::linkDown"}, "linkDown"},
		{map[string]string{"trap_oid": "1.3.6.1.6.3.1.1.5.*"}, "cold linkDown"},
		{map[string]string{"trap_oid": "1.3.6.1.4.1.32473.*"}, "inform v1"},
		{map[string]string{"exclude_trap_oid": "1.3.6.1.4.1.32473.*"}, "cold linkDown"},
		{map[string]string{"enterprise": "1.3.6.1.4.1.32473.1"}, "cold v1"},
		{map[string]string{"exclude_enterprise": "1.3.6.1.4.1.32473.1"}, "inform linkDown"},
		{map[string]string{"generic": "0,6"}, "cold v1"},
		{map[string]string{"generic": "6"}, "v1"},
		{map[string]string{"specific": "17"}, "v1"},
		{map[string]string{"exclude_specific": "17"}, "cold inform linkDown"},
		{map[string]string{"cred": strings.ToUpper(snmp.CommunityHash([]byte("private")))}, "inform"},
		{map[string]string{"exclude_cred": snmp.CommunityHash([]byte("public"))}, "inform"},
		{map[string]string{"status": "ok"}, "cold inform linkDown v1"},
		{map[string]string{"status": "auth_failed"}, ""},
	}
	for _, c := range cases {
		f := parse(t, c.params)
		var got []string
		for _, n := range []string{"cold", "inform", "linkDown", "v1"} {
			if f.Pre(all[n]) && f.Post(all[n], &Scratch{}) {
				got = append(got, n)
			}
		}
		if g := strings.Join(got, " "); g != c.want {
			t.Errorf("%v: %q, want %q", c.params, g, c.want)
		}
	}
	if !parse(t, map[string]string{}).Empty() || parse(t, map[string]string{"pdus": "trap"}).Empty() {
		t.Fatal("Empty")
	}
	if !parse(t, map[string]string{"status": "none"}).None() {
		t.Fatal("None")
	}
	// Errors name the parameter.
	for params, want := range map[string]string{
		"trap_oid=noSuchTrap":   `trap_oid: "noSuchTrap" is not a name in the loaded MIBs.`,
		"snmp_versions=2":       `snmp_versions: "2" is not one of 1, 2c, 3 (or none on its own).`,
		"specific=x":            `specific: "x" is not an integer.`,
		"status=none,ok":        "status: none can't be combined with other values.",
		"enterprise=1.3.6.$":    `enterprise: "1.3.6.$" is not an OID or a MIB name.`,
		"exclude_trap_oid=9..1": `exclude_trap_oid: "9..1" is not an OID or a MIB name.`,
	} {
		k, v, _ := strings.Cut(params, "=")
		_, err := ParseTrapFilter(func(p string) string {
			if p == k {
				return v
			}
			return ""
		})
		if err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %s", params, err, want)
		}
	}
	// Bind is stable across value order.
	if parse(t, map[string]string{"pdus": "trap,inform"}).Bind() != parse(t, map[string]string{"pdus": "inform,trap"}).Bind() {
		t.Fatal("Bind")
	}
}

func TestTrapResult(t *testing.T) {
	r := Result(v2cRecord(t, "public", snmp.PDUTrap, 4711, "1.3.6.1.6.3.1.1.5.3", ifOper))
	if r.Version != "2c" || r.PDU != "trap" || r.TrapOID != "1.3.6.1.6.3.1.1.5.3" || r.TrapName != "linkDown" || r.Status != "ok" ||
		r.Generic != nil || r.Specific != nil || r.Uptime == nil || *r.Uptime != 8641234 {
		t.Fatalf("%+v", r)
	}
	if len(r.Varbinds) != 1 || r.Varbinds[0].Name != "ifOperStatus.3" || r.Varbinds[0].Value != "2" || r.Varbinds[0].ValueName != "down" {
		t.Fatalf("varbinds %+v", r.Varbinds)
	}
	v := Result(v1Record(t, "public", "1.3.6.1.4.1.32473.1", 6, 17))
	if v.Generic == nil || *v.Generic != 6 || v.Specific == nil || *v.Specific != 17 || v.Enterprise != "1.3.6.1.4.1.32473.1" {
		t.Fatalf("v1 %+v", v)
	}
	if b := Result([]byte("not a record")); b.Status != "malformed" || b.Varbinds == nil {
		t.Fatalf("broken %+v", b)
	}
}

func TestSummaries(t *testing.T) {
	t1 := time.Date(2026, 11, 14, 9, 30, 58, 0, time.UTC)
	ts := Get(Trap).NewSummary()
	for i, rec := range [][]byte{
		v2cRecord(t, "public", snmp.PDUTrap, 1, "1.3.6.1.6.3.1.1.5.3"),
		v2cRecord(t, "public", snmp.PDUTrap, 2, "1.3.6.1.6.3.1.1.5.3"),
		v1Record(t, "public", "1.3.6.1.4.1.32473.1", 0, 0), // coldStart
		v2cRecord(t, "public", snmp.PDUInform, 3, "1.3.6.1.6.3.1.1.5.2"),
		[]byte("status=malformed error=x"),
	} {
		ts.Add(rec, t1.Add(time.Duration(i)*time.Second))
	}
	if got := strings.Join(ts.README(5, "A", "B"), "|"); got != "5: linkDown 2, coldStart 1, warmStart 1, (malformed) 1; first A, last B" {
		t.Fatalf("trap README %q", got)
	}
	if rb := ts.Reboots(); len(rb) != 2 || rb[0].Source != "coldStart trap" || !rb[0].Time.Equal(t1.Add(2*time.Second)) ||
		rb[1].Source != "warmStart inform" {
		t.Fatalf("reboots %+v", rb)
	}
	if b, _ := json.Marshal(ts.Counts()); string(b) != `{"linkDown":2,"coldStart":1,"warmStart":1,"(malformed)":1}` || ts.Key() != "by_trap" {
		t.Fatalf("trap counts %s", b)
	}
	var back Counts
	if err := json.Unmarshal([]byte(`{"b":2,"a":1}`), &back); err != nil || len(back) != 2 || back[0] != (Count{"b", 2}) {
		t.Fatalf("unmarshal %+v %v", back, err)
	}

	ss := Get(Syslog).NewSummary()
	for _, r := range []string{"<11>x", "<11>y", "none", "<14>z"} {
		ss.Add([]byte(r), t1)
	}
	if got := strings.Join(ss.README(1234, "A", "B"), "|"); got !=
		"1,234 messages, first A, last B|err 2, info 1, unknown 1 (none of emerg, alert, crit, warning, notice, debug)" {
		t.Fatalf("syslog README %q", got)
	}
	if b, _ := json.Marshal(ss.Counts()); string(b) != `{"emerg":0,"alert":0,"crit":0,"err":2,"warning":0,"notice":0,"info":1,"debug":0,"unknown":1}` {
		t.Fatalf("syslog counts %s", b)
	}
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -1500: "-1,500"} {
		if got := Thousands(n); got != want {
			t.Errorf("Thousands(%d) = %q", n, got)
		}
	}
	many := Get(Trap).NewSummary()
	for i := 0; i < 12; i++ {
		many.Add(v2cRecord(t, "public", snmp.PDUTrap, int64(i), fmt.Sprintf("1.3.6.1.4.1.32473.1.0.%d", i)), t1)
	}
	if got := many.README(12, "A", "B")[0]; !strings.HasSuffix(got, ", and 2 more (2); first A, last B") {
		t.Fatalf("many %q", got)
	}
}
