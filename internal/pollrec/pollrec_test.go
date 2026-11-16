package pollrec

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The spec's example lines (SPEC §12.3), without the envelope.
var specLines = []string{
	`kind=sys cycle=1042 uptime=104512345 hr_uptime=104513000 cpu=12 mem_used=3221225472 mem_total=8589934592 rtt_ms=4`,
	`kind=if cycle=1042 if=3 name="eth3" oper=up speed_mbps=1000 in_octets=987654321012 out_octets=123456789012 in_bps=81234567 out_bps=3456789 in_err=12 out_err=0 in_err_d=0 out_err_d=0 in_disc=340 out_disc=0 in_disc_d=0 out_disc_d=0`,
	`kind=oid cycle=1042 oid=1.3.6.1.4.1.32473.1.2.0 label="queue depth" type=g32 value=17`,
	`kind=status cycle=1043 status=timeout detail="no answer after 1 retry"`,
	`kind=restart cycle=1046 reboot=1 uptime=1532 prev_uptime=104518345 source=sysUpTime,hrSystemUptime`,
}

func TestSpecLinesRoundTrip(t *testing.T) {
	for _, l := range specLines {
		r, err := Parse([]byte(l))
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		b := New(r.Kind, r.Cycle)
		for _, f := range r.Fields {
			b.Str(f.Key, f.Value)
		}
		if got := string(Format(b.Record())); got != l {
			t.Errorf("round trip:\n got %s\nwant %s", got, l)
		}
	}
}

func TestBuilderOrderAndQuoting(t *testing.T) {
	r := New(KindIf, 7).Uint("in_octets", 5).Str("name", `a "b" \c`).Uint("if", 3).Str("oper", "up").Record()
	got := string(Format(r))
	want := `kind=if cycle=7 if=3 name="a \"b\" \\c" oper=up in_octets=5`
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
	r2, err := Parse([]byte(got))
	if err != nil || r2.Value("name") != `a "b" \c` {
		t.Errorf("parse: %+v %v", r2, err)
	}
	// Control characters, invalid UTF-8 and spaces in values never break the line.
	r = New(KindInfo, 1).Str("alias", "x\ny\r\tz\x01\xff ü").Str("sys_oid", "with space").Record()
	line := Format(r)
	if strings.ContainsAny(string(line), "\r\n\t") {
		t.Errorf("line %q", line)
	}
	r2, _ = Parse(line)
	if r2.Value("alias") != "x\ny\r\tz\x01\xff ü" || r2.Value("sys_oid") != "with space" {
		t.Errorf("parse %+v", r2)
	}
	if KindOf(line) != KindInfo {
		t.Errorf("KindOf %q", KindOf(line))
	}
}

func TestFormatFloat(t *testing.T) {
	for v, want := range map[float64]string{0: "0", 1: "1", 1.5: "1.5", 2.004: "2", 81234567.4: "81234567.4", 1.239: "1.24", -0.001: "0"} {
		if got := FormatFloat(v); got != want {
			t.Errorf("%v: %s, want %s", v, got, want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, l := range []string{"", "cycle=1 kind=sys", "kind=", `kind=sys cycle=x`, `kind=sys name="open`, `kind=sys a`, `kind=sys x="\`} {
		if _, err := Parse([]byte(l)); err == nil {
			t.Errorf("%q parsed", l)
		}
	}
}

// FuzzPollRecord: any line parses or doesn't, without a panic; a parsed record
// formats to a line that parses back to the same record (SPEC §12.8).
func FuzzPollRecord(f *testing.F) {
	for _, l := range specLines {
		f.Add([]byte(l))
	}
	f.Add([]byte(`kind=info cycle=1 sys_name="x\x01" sys_descr="a\nb"`))
	f.Fuzz(func(t *testing.T, line []byte) {
		r, err := Parse(line)
		if err != nil {
			return
		}
		out := Format(r)
		r2, err := Parse(out)
		if err != nil {
			t.Fatalf("formatted line %q doesn't parse: %v", out, err)
		}
		// Format drops keys it can't write; compare what it kept.
		var kept []KV
		for _, kv := range r.Fields {
			if validKey(kv.Key) && kv.Key != "kind" && kv.Key != "cycle" {
				kept = append(kept, kv)
			}
		}
		if r2.Kind != r.Kind || r2.Cycle != r.Cycle || !reflect.DeepEqual(r2.Fields, kept) {
			t.Fatalf("round trip:\n%+v\n%+v", r, r2)
		}
		if strings.ContainsAny(string(out), "\r\n") {
			t.Fatalf("line with CR/LF: %q", out)
		}
	})
}

// A restart's reasons say what the uptime did: an uptime lower than the last
// sample is a reset; one that went up, but by less than the time since the
// last poll (an agent restarted soon after its previous start), isn't, and
// mustn't be called one (the 1.3 lab).
func TestRestartReasons(t *testing.T) {
	rec := func(line string) *Record {
		t.Helper()
		r, err := Parse([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		return &r
	}
	for _, c := range []struct {
		line string
		want []string
	}{
		{"kind=restart cycle=2 reboot=1 uptime=1532 prev_uptime=104518345 hr_uptime=1600 prev_hr_uptime=104519000 source=sysUpTime,hrSystemUptime",
			[]string{"sysUpTime and hrSystemUptime reset"}},
		{"kind=restart cycle=2 reboot=? uptime=650 prev_uptime=640 source=sysUpTime",
			[]string{"sysUpTime rose less than the time since the last poll"}},
		{"kind=restart cycle=2 reboot=1 uptime=650 prev_uptime=640 hr_uptime=12 prev_hr_uptime=9000 source=sysUpTime,hrSystemUptime",
			[]string{"hrSystemUptime reset", "sysUpTime rose less than the time since the last poll"}},
		{"kind=restart cycle=2 reboot=0 uptime=650 prev_uptime=640 boots=8 prev_boots=7 source=sysUpTime,engineBoots",
			[]string{"sysUpTime rose less than the time since the last poll", "engineBoots went up"}},
		{"kind=restart cycle=2 reboot=? boots=8 prev_boots=7 source=engineBoots", []string{"engineBoots went up"}},
		// No values to compare (an older line): a reset, as before.
		{"kind=restart cycle=2 reboot=? source=sysUpTime", []string{"sysUpTime reset"}},
		{"kind=restart cycle=2 reboot=? source=", nil},
	} {
		got := RestartReasons(rec(c.line))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s:\n got %q\nwant %q", c.line, got, c.want)
		}
	}
}
