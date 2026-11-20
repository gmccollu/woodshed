package syslog

import (
	"testing"

	"github.com/gmccollu/woodshed/internal/model"
)

func TestSeverityMatchesParse(t *testing.T) {
	cases := []string{
		"", "<", "<>", "<1", "<13>", "<13>x", "<191>x", "<192>x", "<999>x", "<0>x", "<7>x", "<007>x", "<0013>x",
		" <14>x", "\t<15>x", "\r\n<12>x", "\x00<11>x", "\xef\xbb\xbf<10>x", "x<13>", "<13 >", "<1a>", "<-1>",
		"<134>1 2026-11-14T09:30:58.112Z fw01 app 4242 ID47 - hello", "Nov 10 20:41:07 host app: no pri",
	}
	for _, tc := range parseCases {
		cases = append(cases, tc.raw)
	}
	for _, raw := range cases {
		var m model.Message
		Parse([]byte(raw), &m)
		if got := Severity([]byte(raw)); got != m.Severity {
			t.Errorf("Severity(%q) = %d, Parse says %d", raw, got, m.Severity)
		}
	}
}

func FuzzSeverity(f *testing.F) {
	for _, s := range []string{"<13>x", "<191>", "<192>", " \r\n<7>a", "\xef\xbb\xbf<0>"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		var m model.Message
		Parse(raw, &m)
		if got := Severity(raw); got != m.Severity {
			t.Fatalf("Severity(%q) = %d, Parse says %d", raw, got, m.Severity)
		}
	})
}

func TestSeverityAllocs(t *testing.T) {
	raw := []byte("<134>1 2026-11-14T09:30:58.112Z fw01 app 4242 ID47 - hello")
	if n := testing.AllocsPerRun(100, func() { _ = Severity(raw) }); n != 0 {
		t.Fatalf("Severity allocates %v times", n)
	}
}

func BenchmarkSeverity(b *testing.B) {
	raw := []byte("<134>1 2026-11-14T09:30:58.112Z fw01 app 4242 ID47 - hello")
	for i := 0; i < b.N; i++ {
		_ = Severity(raw)
	}
}
