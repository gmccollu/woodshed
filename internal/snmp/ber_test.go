package snmp

import (
	"bytes"
	"math"
	"strings"
	"testing"
)

func TestReadTLV(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      []byte
		tag     byte
		content []byte
		err     string
	}{
		{"short", []byte{0x04, 0x02, 'h', 'i'}, 0x04, []byte("hi"), ""},
		{"empty content", []byte{0x05, 0x00}, 0x05, []byte{}, ""},
		{"long form", append([]byte{0x04, 0x81, 0x80}, bytes.Repeat([]byte{'a'}, 128)...), 0x04, bytes.Repeat([]byte{'a'}, 128), ""},
		{"long form, non-minimal", []byte{0x04, 0x82, 0x00, 0x01, 'x'}, 0x04, []byte("x"), ""},
		{"long form for a short length", []byte{0x04, 0x81, 0x01, 'x'}, 0x04, []byte("x"), ""},
		{"trailing bytes are left", []byte{0x02, 0x01, 0x05, 0xff}, 0x02, []byte{5}, ""},
		{"empty", nil, 0, nil, "unexpected end"},
		{"tag only", []byte{0x30}, 0, nil, "truncated header"},
		{"indefinite", []byte{0x30, 0x80, 0, 0}, 0, nil, "indefinite length"},
		{"reserved", []byte{0x30, 0xff}, 0, nil, "reserved length"},
		{"high tag", []byte{0x1f, 0x01, 0x00}, 0, nil, "high-tag-number"},
		{"length past the end", []byte{0x04, 0x05, 'a'}, 0, nil, "runs past the end"},
		{"length octets cut", []byte{0x04, 0x82, 0x01}, 0, nil, "truncated length"},
		{"huge length", []byte{0x04, 0x88, 1, 0, 0, 0, 0, 0, 0, 0}, 0, nil, "length too large"},
		{"length past the end (long)", []byte{0x04, 0x84, 0x7f, 0xff, 0xff, 0xff}, 0, nil, "runs past the end"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := readTLV(tc.in, 0)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("err = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.tag != tc.tag || !bytes.Equal(got.content, tc.content) {
				t.Fatalf("got tag %x content %x", got.tag, got.content)
			}
		})
	}
}

func TestIntegers(t *testing.T) {
	for _, tc := range []struct {
		in  []byte
		v   int64
		err bool
	}{
		{[]byte{0}, 0, false},
		{[]byte{0x7f}, 127, false},
		{[]byte{0x80}, -128, false},
		{[]byte{0xff}, -1, false},
		{[]byte{0x00, 0x80}, 128, false},
		{[]byte{0xff, 0x7f}, -129, false},
		{[]byte{0x00, 0x00, 0x00, 0x05}, 5, false}, // non-minimal, accepted
		{[]byte{0xff, 0xff, 0xff}, -1, false},      // non-minimal, accepted
		{[]byte{0x7f, 0xff, 0xff, 0xff}, math.MaxInt32, false},
		{[]byte{0x80, 0, 0, 0}, math.MinInt32, false},
		{[]byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxInt64, false},
		{[]byte{0x80, 0, 0, 0, 0, 0, 0, 0}, math.MinInt64, false},
		{[]byte{0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxInt64, false},
		{[]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}, 0, true},
		{nil, 0, true},
	} {
		v, err := parseInt(tlv{tag: tagInteger, content: tc.in})
		if (err != nil) != tc.err || (!tc.err && v != tc.v) {
			t.Errorf("parseInt(%x) = %d, %v; want %d, err %v", tc.in, v, err, tc.v, tc.err)
		}
	}
	for _, tc := range []struct {
		in  []byte
		v   uint64
		err bool
	}{
		{[]byte{0}, 0, false},
		{[]byte{0xff, 0xff, 0xff, 0xff}, math.MaxUint32, false}, // the sign bit set, read as unsigned
		{[]byte{0x00, 0xff, 0xff, 0xff, 0xff}, math.MaxUint32, false},
		{[]byte{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, math.MaxUint64, false},
		{[]byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}, 0, true},
		{nil, 0, true},
	} {
		v, err := parseUint(tlv{tag: tagCounter64, content: tc.in})
		if (err != nil) != tc.err || (!tc.err && v != tc.v) {
			t.Errorf("parseUint(%x) = %d, %v; want %d, err %v", tc.in, v, err, tc.v, tc.err)
		}
	}
	// Encoding is minimal and round-trips for every width and sign.
	for _, v := range []int64{0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, 32768, -32769, math.MaxInt32, math.MinInt32,
		1 << 40, -(1 << 40), math.MaxInt64, math.MinInt64} {
		b := appendInt(nil, tagInteger, v)
		got, _, err := readTLV(b, 0)
		if err != nil {
			t.Fatal(err)
		}
		if x, err := parseInt(got); err != nil || x != v {
			t.Errorf("int %d: round trip %d, %v (% x)", v, x, err, b)
		}
		if c := got.content; len(c) > 1 && ((c[0] == 0 && c[1]&0x80 == 0) || (c[0] == 0xff && c[1]&0x80 != 0)) {
			t.Errorf("int %d: not minimal: % x", v, b)
		}
	}
	for _, v := range []uint64{0, 1, 127, 128, 255, 256, math.MaxUint32, math.MaxUint32 + 1, math.MaxUint64} {
		b := appendUint(nil, tagCounter64, v)
		got, _, err := readTLV(b, 0)
		if err != nil {
			t.Fatal(err)
		}
		if x, err := parseUint(got); err != nil || x != v {
			t.Errorf("uint %d: round trip %d, %v (% x)", v, x, err, b)
		}
		if got.content[0]&0x80 != 0 {
			t.Errorf("uint %d: encoded with the sign bit set: % x", v, b)
		}
	}
}

func TestOIDs(t *testing.T) {
	for _, s := range []string{"1.3.6.1.2.1.1.3.0", "0.0", "2.999.3", "1.3.6.1.4.1.4294967295.0.4294967295", "1.39"} {
		o, err := ParseOID(s)
		if err != nil {
			t.Fatal(err)
		}
		b := appendOID(nil, o)
		got, _, err := readTLV(b, 0)
		if err != nil {
			t.Fatal(err)
		}
		back, err := parseOID(got)
		if err != nil || back.String() != s {
			t.Errorf("%s: round trip %s, %v (% x)", s, back, err, b)
		}
	}
	// 2.999 is 0x88 0x37 (X.690 §8.19.5's example).
	if b := appendOIDContent(nil, OID{2, 999, 3}); !bytes.Equal(b, []byte{0x88, 0x37, 0x03}) {
		t.Errorf("2.999.3 = % x", b)
	}
	// Non-minimal sub-identifiers (a leading 0x80) are accepted.
	if o, err := parseOID(tlv{content: []byte{0x2b, 0x80, 0x06}}); err != nil || o.String() != "1.3.6" {
		t.Errorf("non-minimal: %v %v", o, err)
	}
	for name, c := range map[string][]byte{
		"empty":     {},
		"truncated": {0x2b, 0x86},
		"too large": {0x2b, 0x90, 0x80, 0x80, 0x80, 0x00},
		"too long":  append([]byte{0x2b}, bytes.Repeat([]byte{1}, MaxOIDLen)...),
	} {
		if _, err := parseOID(tlv{content: c}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if o, err := parseOID(tlv{content: append([]byte{0x2b}, bytes.Repeat([]byte{1}, MaxOIDLen-2)...)}); err != nil || len(o) != MaxOIDLen {
		t.Errorf("an OID of exactly %d: %v (%d)", MaxOIDLen, err, len(o))
	}
	for _, bad := range []string{"", "1", "3.1", "1.40", "1.3.x", "1..3", "1.3.06", "1.3.4294967296"} {
		if _, err := ParseOID(bad); err == nil {
			t.Errorf("ParseOID(%q): no error", bad)
		}
	}
	if !(OID{1, 3, 6, 1}).HasPrefix(OID{1, 3}) || (OID{1, 3}).HasPrefix(OID{1, 3, 6}) {
		t.Error("HasPrefix")
	}
}

// TestValues round-trips every universal and SNMP application type.
func TestValues(t *testing.T) {
	for _, v := range []Value{
		intVal(-5), strVal("hello"), {Kind: KindOctetString, Bytes: []byte{0, 1, 0xff}}, {Kind: KindNull},
		oidVal(OID{1, 3, 6, 1}), {Kind: KindIPAddress, Bytes: []byte{10, 1, 0, 1}},
		{Kind: KindCounter32, Uint: math.MaxUint32}, {Kind: KindGauge32, Uint: 7}, ticks(8641234),
		{Kind: KindOpaque, Bytes: []byte{0x9f, 0x78, 0x04, 0x3f, 0x80, 0, 0}}, {Kind: KindCounter64, Uint: math.MaxUint64},
		{Kind: KindNoSuchObject}, {Kind: KindNoSuchInstance}, {Kind: KindEndOfMibView},
		{Kind: KindOther, Tag: 0x01, Bytes: []byte{0xff}}, // BOOLEAN
		{Kind: KindOther, Tag: tagNsapAddress, Bytes: []byte{1, 2}},
	} {
		b := appendValue(nil, v)
		got, _, err := readTLV(b, 0)
		if err != nil {
			t.Fatal(err)
		}
		back, err := parseValue(got)
		if err != nil {
			t.Fatalf("%v: %v", v, err)
		}
		if back.Kind != v.Kind || back.Int != v.Int || back.Uint != v.Uint || !bytes.Equal(back.Bytes, v.Bytes) || !back.OID.Equal(v.OID) {
			t.Errorf("%+v round trip %+v", v, back)
		}
	}
	// UInteger32 (RFC 1442) reads as Gauge32.
	if v, _ := parseValue(tlv{tag: tagUInteger32, content: []byte{5}}); v.Kind != KindGauge32 || v.Uint != 5 {
		t.Errorf("UInteger32: %+v", v)
	}
}
