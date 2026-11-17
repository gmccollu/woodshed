package logfile

import (
	"bytes"
	"testing"
	"time"
)

func TestLineFlags(t *testing.T) {
	rec := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		f    Flags
		want string
	}{
		{Flags{}, "2026-11-17T10:00:00.000Z 192.0.2.1 <13>short\n"},
		{Flags{Incomplete: true, Arrived: 9, Length: 50}, `2026-11-17T10:00:00.000Z 192.0.2.1 <13>short \#incomplete=9/50` + "\n"},
		{Flags{Truncated: true}, `2026-11-17T10:00:00.000Z 192.0.2.1 <13>short \#truncated` + "\n"},
		{Flags{Truncated: true, Incomplete: true, Arrived: 70000, Length: 100000},
			`2026-11-17T10:00:00.000Z 192.0.2.1 <13>short \#truncated,incomplete=70000/100000` + "\n"},
		{Flags{Incomplete: true}, `2026-11-17T10:00:00.000Z 192.0.2.1 <13>short \#incomplete` + "\n"},
	}
	for _, tc := range cases {
		line := AppendLineFlags(nil, rec, ip1, []byte("<13>short"), tc.f)
		if string(line) != tc.want {
			t.Errorf("%+v: got %q, want %q", tc.f, line, tc.want)
		}
		l, err := ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if string(l.Escaped) != "<13>short" || l.Flags != tc.f {
			t.Errorf("%+v: parsed %q %+v", tc.f, l.Escaped, l.Flags)
		}
	}
}

// Messages that look like a marker aren't one: the escaping turns their
// backslash into "\\".
func TestLineFlagsNotFromMessage(t *testing.T) {
	rec := time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC)
	for _, raw := range []string{`<13>x \#incomplete=9/50`, `\#truncated`, `<13>a \\#truncated`, "<13>a \\\n#truncated", "", " ", `a \`} {
		line := AppendLine(nil, rec, ip1, []byte(raw))
		l, err := ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if !l.Flags.IsZero() || string(l.Raw()) != raw {
			t.Errorf("%q: flags %+v, raw %q", raw, l.Flags, l.Raw())
		}
	}
	// An empty message with flags.
	l, err := ParseLine(AppendLineFlags(nil, rec, ip1, nil, Flags{Incomplete: true}))
	if err != nil || len(l.Escaped) != 0 || !l.Flags.Incomplete {
		t.Fatalf("empty: %+v %v", l, err)
	}
}

// Unknown flags (a later version's) are ignored; a malformed count keeps the
// flag without numbers.
func TestLineFlagsUnknown(t *testing.T) {
	for in, want := range map[string]Flags{
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#later,incomplete=3/4`: {Incomplete: true, Arrived: 3, Length: 4},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#later`:                {},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#incomplete=x/4`:       {Incomplete: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#incomplete=3/0`:       {Incomplete: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#incomplete=9/5`:       {Incomplete: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#incomplete=9/9`:       {Incomplete: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#incomplete=9/`:        {Incomplete: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#incompl`:              {Incomplete: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#trunc`:                {Truncated: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#truncated,inc`:        {Truncated: true, Incomplete: true},
		`2026-11-17T10:00:00.000Z 192.0.2.1 m \#`:                     {},
	} {
		l, err := ParseLine([]byte(in))
		if err != nil || string(l.Escaped) != "m" || l.Flags != want {
			t.Errorf("%q: %q %+v %v, want %+v", in, l.Escaped, l.Flags, err, want)
		}
	}
}

func FuzzLineFlags(f *testing.F) {
	f.Add([]byte(`<13>a \#x`), true, true, int64(9), int64(50))
	f.Add([]byte(""), false, true, int64(0), int64(0))
	f.Fuzz(func(t *testing.T, raw []byte, tr, inc bool, arrived, length int64) {
		fl := Flags{Truncated: tr, Incomplete: inc}
		if inc && arrived >= 0 && arrived < length {
			fl.Arrived, fl.Length = arrived, length
		}
		line := AppendLineFlags(nil, time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC), ip1, raw, fl)
		if bytes.IndexByte(line[:len(line)-1], '\n') >= 0 {
			t.Fatalf("embedded newline: %q", line)
		}
		l, err := ParseLine(line)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(l.Raw(), raw) || l.Flags != fl {
			t.Fatalf("%q %+v came back as %q %+v", raw, fl, l.Raw(), l.Flags)
		}
	})
}
