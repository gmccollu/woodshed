package snmp

import (
	"bytes"
	"encoding/base64"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestRecordExample formats the spec's example trap (SPEC §11.2.4) and checks
// the line key by key.
func TestRecordExample(t *testing.T) {
	m := Decode(v2cMsg("public", PDUTrap, 4711, linkDownVarbinds()), nil, t0)
	rec := string(FormatRecord(nil, m, RecordOptions{Names: BuiltinMIBs()}))
	want := "v=2c pdu=trap id=4711 cred=" + CommunityHash([]byte("public")) + " status=ok uptime=8641234 trap=1.3.6.1.6.3.1.1.5.3(linkDown)" +
		" vb=1.3.6.1.2.1.2.2.1.1.3(ifIndex.3):int:3 vb=1.3.6.1.2.1.2.2.1.7.3(ifAdminStatus.3):int:1(up)" +
		" vb=1.3.6.1.2.1.2.2.1.8.3(ifOperStatus.3):int:2(down) raw="
	if !strings.HasPrefix(rec, want) {
		t.Fatalf("record\n got %s\nwant %s…", rec, want)
	}
	if CommunityHash([]byte("public")) != "#efa1f375" {
		// SHA-256("public") = efa1f375…; a fixed value so a change is noticed.
		t.Errorf("CommunityHash(public) = %s", CommunityHash([]byte("public")))
	}
	if strings.Contains(rec, "public") {
		t.Error("the community is in the record")
	}
	// Without names, OIDs are numeric only.
	plain := string(FormatRecord(nil, m, RecordOptions{}))
	if strings.Contains(plain, "(") {
		t.Errorf("names without a MIB set: %s", plain)
	}
}

// TestRecordMasking: the community's octets are '*' in raw=, the lengths are
// untouched, and the masked PDU still decodes to the same trap.
func TestRecordMasking(t *testing.T) {
	raw := v2cMsg("s3cret!", PDUTrap, 1, linkDownVarbinds())
	m := Decode(raw, nil, t0)
	rec, err := ParseRecord(FormatRecord(nil, m, RecordOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := base64.StdEncoding.DecodeString(rec.Raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(raw) || bytes.Contains(got, []byte("s3cret")) || !bytes.Contains(got, []byte("*******")) {
		t.Fatalf("masked raw % x", got)
	}
	back := Decode(got, nil, t0)
	if back.Status != StatusOK || string(back.Community) != "*******" || len(back.PDU.Varbinds) != len(m.PDU.Varbinds) {
		t.Errorf("masked raw decodes to %v %q", back.Status, back.Community)
	}
	if !bytes.Contains(raw, []byte("s3cret!")) {
		t.Error("masking changed the message itself (the Response needs the community)")
	}
	// Broken datagrams are masked too, as far as the community can be found.
	for name, b := range map[string][]byte{
		"truncated in the community": raw[:12],
		"truncated after it":         raw[:20],
		"wrong outer length":         append([]byte{0x30, 0x7f}, raw[2:]...),
		"v1":                         v1Trap("s3cret!", 0, 0, nil),
		"bad version":                append([]byte{0x30, byte(len(raw) - 2), 0x02, 0x01, 0x07}, raw[5:]...),
	} {
		got := MaskedRaw(b)
		if bytes.Contains(got, []byte("s3cr")) {
			t.Errorf("%s: community visible: %q", name, got)
		}
		if len(got) != len(b) {
			t.Errorf("%s: length changed", name)
		}
	}
	// The length octets cut off right after the tag: everything after it is masked.
	if got := MaskedRaw([]byte{0x30, 0x10, 0x02, 0x01, 0x01, 0x04, 0x85}); !bytes.Equal(got[6:], []byte("*")) {
		t.Errorf("cut length: % x", got)
	}
	// v3 is kept exactly.
	c := combo{AuthSHA1, PrivAES128, 0}
	v3 := v3Msg(t, c, "alice", V3Header{MsgID: 1, EngineID: senderEngine, EngineBoots: 1, EngineTime: 1}, &PDU{Type: PDUTrap, Varbinds: header(1, testTrapOID)})
	if !bytes.Equal(MaskedRaw(v3), v3) {
		t.Error("a v3 message was masked")
	}
}

func TestRecordValueTypes(t *testing.T) {
	o := OID{1, 3, 6, 1, 4, 1, 32473, 2}
	vbs := []Varbind{
		{o, intVal(-42)},
		{o, strVal(`say "hi" \ there`)},
		{o, Value{Kind: KindOctetString, Bytes: []byte{0x00, 0x1b, 0xff}}},
		{o, Value{Kind: KindOctetString, Bytes: []byte("two\nlines")}},
		{o, Value{Kind: KindOctetString}},
		{o, Value{Kind: KindNull}},
		{o, oidVal(OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1})},
		{o, Value{Kind: KindIPAddress, Bytes: []byte{10, 1, 0, 1}}},
		{o, Value{Kind: KindIPAddress, Bytes: []byte{1, 2, 3}}},
		{o, Value{Kind: KindCounter32, Uint: math.MaxUint32}},
		{o, Value{Kind: KindGauge32, Uint: 1}},
		{o, ticks(99)},
		{o, Value{Kind: KindCounter64, Uint: math.MaxUint64}},
		{o, Value{Kind: KindOpaque, Bytes: []byte{0x9f, 0x78}}},
		{o, Value{Kind: KindNoSuchObject}},
		{o, Value{Kind: KindNoSuchInstance}},
		{o, Value{Kind: KindEndOfMibView}},
		{o, Value{Kind: KindOther, Tag: 0x01, Bytes: []byte{0xff}}},
		{o, strVal("héllo wörld")},
	}
	want := []RecordVarbind{
		{Type: "int", Value: "-42"},
		{Type: "str", Value: `say "hi" \ there`},
		{Type: "hex", Value: "001bff"},
		{Type: "hex", Value: "74776f0a6c696e6573"},
		{Type: "str", Value: ""},
		{Type: "null"},
		{Type: "oid", Value: "1.3.6.1.6.3.1.1.5.1", Enum: "coldStart"},
		{Type: "ip", Value: "10.1.0.1"},
		{Type: "hex", Value: "010203"},
		{Type: "c32", Value: "4294967295"},
		{Type: "g32", Value: "1"},
		{Type: "ticks", Value: "99"},
		{Type: "c64", Value: "18446744073709551615"},
		{Type: "opaque", Value: "9f78"},
		{Type: "nosuchobject"},
		{Type: "nosuchinstance"},
		{Type: "endofmibview"},
		{Type: "hex", Value: "ff"},
		{Type: "str", Value: "héllo wörld"},
	}
	m := Decode(v2cMsg("public", PDUTrap, 1, append(header(5, testTrapOID), vbs...)), nil, t0)
	line := FormatRecord(nil, m, RecordOptions{Names: BuiltinMIBs()})
	if !bytes.Contains(line, []byte(`:str:"say \"hi\" \\ there"`)) {
		t.Errorf("escaping: %s", line)
	}
	if bytes.ContainsAny(line, "\n\r") {
		t.Error("a record with a line break")
	}
	r, err := ParseRecord(line)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Varbinds) != len(want) {
		t.Fatalf("%d varbinds, want %d: %s", len(r.Varbinds), len(want), line)
	}
	for i, w := range want {
		g := r.Varbinds[i]
		if g.OID != o.String() || g.Type != w.Type || g.Value != w.Value || g.Enum != w.Enum {
			t.Errorf("vb %d = %+v, want %+v", i, g, w)
		}
	}
}

// TestRecordRoundTrip formats messages of every kind and reads the fields back.
func TestRecordRoundTrip(t *testing.T) {
	c := combo{AuthSHA256, PrivAES128, 0}
	u := newTestUSM(t, c.user("alice"), combo{AuthMD5, PrivNone, 0}.user("bob"))
	mibs := BuiltinMIBs()
	cases := map[string]*Message{
		"v1":        Decode(v1Trap("public", 6, 9, []Varbind{{oidIfOper3, intVal(7)}}), nil, t0),
		"v2c":       Decode(v2cMsg("public", PDUTrap, 4711, linkDownVarbinds()), nil, t0),
		"inform":    Decode(v2cMsg("public", PDUInform, -3, linkDownVarbinds()), nil, t0),
		"get":       Decode(v2cMsg("public", PDUGet, 8, linkDownVarbinds()), nil, t0),
		"malformed": Decode(v2cMsg("public", PDUTrap, 1, linkDownVarbinds())[:30], nil, t0),
		"garbage":   Decode([]byte("hello"), nil, t0),
		"v3": Decode(v3Msg(t, c, "alice", V3Header{MsgID: 1, EngineID: senderEngine, EngineBoots: 1, EngineTime: 1, ContextName: []byte("ctx one"), ContextEngineID: mustHex(t, "800000000501")},
			&PDU{Type: PDUTrap, RequestID: 12, Varbinds: linkDownVarbinds()}), u, t0),
		"v3 failure": Decode(v3Msg(t, c, "eve#1", V3Header{MsgID: 1, EngineID: senderEngine, EngineBoots: 1, EngineTime: 1},
			&PDU{Type: PDUTrap, RequestID: 12, Varbinds: linkDownVarbinds()}), u, t0),
		"v3 odd user": Decode(v3Msg(t, combo{}, "\x00\x01", V3Header{MsgID: 1, EngineID: senderEngine, EngineBoots: 1, EngineTime: 1},
			&PDU{Type: PDUTrap, RequestID: 12, Varbinds: linkDownVarbinds()}), u, t0),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			for _, names := range []Namer{nil, mibs} {
				for _, dup := range []bool{false, true} {
					line := FormatRecord(nil, m, RecordOptions{Names: names, Dup: dup})
					r, err := ParseRecord(line)
					if err != nil {
						t.Fatalf("%s: %v", line, err)
					}
					checkRecord(t, m, r, dup, names != nil)
					if text := RecordText(line); bytes.Contains(text, []byte("raw=")) || !bytes.HasPrefix(line, text) {
						t.Errorf("RecordText: %s", text)
					}
				}
			}
		})
	}
	// Specific expectations.
	r, _ := ParseRecord(FormatRecord(nil, cases["v3"], RecordOptions{}))
	if r.Cred != "alice" || r.Level != "authPriv" || r.Engine != "8000000005aabbccddeeff0011" || r.Ctx != "ctx one" || r.CtxEngine != "800000000501" || r.ID != "12" {
		t.Errorf("v3 record: %+v", r)
	}
	r, _ = ParseRecord(FormatRecord(nil, cases["v1"], RecordOptions{Names: mibs}))
	if r.Enterprise != "1.3.6.1.4.1.32473.1" || r.Agent != "192.0.2.7" || r.Generic != "6" || r.Specific != "9" || r.Trap != "1.3.6.1.4.1.32473.1.0.9" || r.Uptime != "4242" || r.ID != "" {
		t.Errorf("v1 record: %+v", r)
	}
	r, _ = ParseRecord(FormatRecord(nil, cases["v3 failure"], RecordOptions{}))
	if r.Status != "unknown_user" || r.Cred != "eve#1" || len(r.Varbinds) != 0 || r.PDU != "" {
		t.Errorf("v3 failure record: %+v", r)
	}
	if line := FormatRecord(nil, cases["v3 odd user"], RecordOptions{}); !bytes.Contains(line, []byte("cred=0x0001")) {
		t.Errorf("odd user: %s", line)
	}
	if line := string(FormatRecord(nil, cases["get"], RecordOptions{})); !strings.Contains(line, "pdu=get id=8") || !strings.Contains(line, "status=unexpected_pdu error=") ||
		!strings.Contains(line, "vb=1.3.6.1.2.1.1.3.0:ticks:8641234") || strings.Contains(line, "uptime=") {
		t.Errorf("unexpected PDU: %s", line)
	}
	if line := string(FormatRecord(nil, cases["garbage"], RecordOptions{})); !regexp.MustCompile(`^status=malformed error="not an SNMP message[^"]*" raw=aGVsbG8=$`).MatchString(line) {
		t.Errorf("garbage: %s", line)
	}
}

// checkRecord compares a parsed record with the message it came from.
func checkRecord(t *testing.T, m *Message, r Record, dup, named bool) {
	t.Helper()
	if r.Version != m.Version.String() || r.Status != m.Status.String() || r.Error != m.Err || r.Dup != dup {
		t.Errorf("header: %+v", r)
	}
	if raw, err := base64.StdEncoding.DecodeString(r.Raw); err != nil || len(raw) != len(m.Raw) {
		t.Errorf("raw: %v", err)
	}
	switch {
	case m.Version == V3 && m.HeaderRead:
		if want := string(m.User); r.Cred != want && !(strings.HasPrefix(r.Cred, "0x") && !printable(m.User)) {
			t.Errorf("cred %q, want %q", r.Cred, want)
		}
	case m.Community != nil:
		if r.Cred != CommunityHash(m.Community) {
			t.Errorf("cred %q", r.Cred)
		}
	}
	p := m.PDU
	if p == nil {
		if r.PDU != "" || len(r.Varbinds) != 0 {
			t.Errorf("no PDU, but the record has %+v", r)
		}
		return
	}
	if r.PDU != p.Type.String() {
		t.Errorf("pdu %q", r.PDU)
	}
	if m.Status != StatusOK && p.Varbinds == nil {
		return // the record shows no varbinds
	}
	n := p.Notification()
	vbs := n.Varbinds
	if p.Type != PDUTrap && p.Type != PDUInform && p.Type != PDUV1Trap {
		vbs = p.Varbinds
	} else if n.TrapOID != nil && r.Trap != n.TrapOID.String() {
		t.Errorf("trap %q", r.Trap)
	}
	if len(r.Varbinds) != len(vbs) {
		t.Fatalf("%d varbinds, want %d", len(r.Varbinds), len(vbs))
	}
	for i, vb := range vbs {
		g := r.Varbinds[i]
		if g.OID != vb.OID.String() {
			t.Errorf("vb %d oid %s", i, g.OID)
		}
		if named && g.Name == "" && BuiltinMIBs().Name(vb.OID) != "" {
			t.Errorf("vb %d unnamed", i)
		}
		if vb.Value.Kind == KindInteger && g.Value != strconv.FormatInt(vb.Value.Int, 10) {
			t.Errorf("vb %d value %s", i, g.Value)
		}
	}
}

type hugeNamer struct{}

func (hugeNamer) Name(OID) string            { return strings.Repeat("n", 100000) }
func (hugeNamer) EnumName(OID, int64) string { return "" }

// TestRecordBound: a record that names would push past MaxRecordLen is written
// without names; the largest datagram without names fits.
func TestRecordBound(t *testing.T) {
	var vbs []Varbind
	for i := 0; i < 20; i++ {
		vbs = append(vbs, Varbind{OID: testEnterprise, Value: intVal(int64(i))})
	}
	m := Decode(v2cMsg("public", PDUTrap, 1, vbs), nil, t0)
	line := FormatRecord(nil, m, RecordOptions{Names: hugeNamer{}})
	if len(line) > MaxRecordLen || bytes.Contains(line, []byte("nnnn")) {
		t.Errorf("record of %d bytes, names kept: %v", len(line), bytes.Contains(line, []byte("nnnn")))
	}
	// A 65,507-byte datagram of the worst kind for expansion: one big OCTET STRING of quotes and backslashes.
	big := bytes.Repeat([]byte(`"\`), 32700)
	m = Decode(v2cMsg("public", PDUTrap, 1, []Varbind{{OID: testEnterprise, Value: Value{Kind: KindOctetString, Bytes: big}}}), nil, t0)
	if line := FormatRecord(nil, m, RecordOptions{}); recordLen(line) > MaxRecordLen {
		t.Errorf("worst-case record %d bytes escaped", recordLen(line))
	}
}

func TestParseRecordErrors(t *testing.T) {
	for _, bad := range []string{
		"", "v=2c", "status=ok vb=", "status=ok vb=1.3:", "status=ok vb=1.3:str:abc", `status=ok vb=1.3:str:"abc`,
		`status=ok error="x`, "status=ok =x", "status=ok vb=1.3(name:int:1", `status=ok vb=1.3:str:"a"junk`,
	} {
		if _, err := ParseRecord([]byte(bad)); err == nil {
			t.Errorf("ParseRecord(%q): no error", bad)
		}
	}
	// Unknown keys are skipped.
	if r, err := ParseRecord([]byte("v=2c newkey=1 status=ok")); err != nil || r.Version != "2c" {
		t.Errorf("unknown key: %v", err)
	}
}
