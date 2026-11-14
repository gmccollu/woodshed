package snmp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// The fuzz targets (SPEC §11.6). CI runs each for a fixed time (scripts/fuzz.sh);
// the seed corpora are in testdata/fuzz/<target>/ (regenerate them with
// WOODSHED_WRITE_FUZZ_SEEDS=1 go test -run TestWriteFuzzSeeds).

// fuzzCombos are the users FuzzMessage and FuzzUSM know, one per protocol family.
var fuzzCombos = []combo{
	{AuthMD5, PrivDES, 0},
	{AuthSHA1, PrivAES128, 0},
	{AuthSHA256, PrivAES256, KeyExtAlt},
	{AuthSHA512, PrivAES192, 0},
	{AuthSHA224, PrivNone, 0},
	{},
}

var (
	fuzzUsersOnce sync.Once
	fuzzUsers     []User
)

// fuzzUSM returns a fresh USM (so every input is decoded from the same state)
// whose users hold engine-bound keys for the sender's engine and the receiver's,
// so making it costs no password hashing.
func fuzzUSM(t testing.TB) *USM {
	fuzzUsersOnce.Do(func() {
		for _, c := range fuzzCombos {
			u := c.user("u-" + c.name())
			if c.auth != AuthNone {
				eks, err := u.Localize([][]byte{senderEngine, testEngine().ID})
				if err != nil {
					panic(err)
				}
				u.EngineKeys = eks
			}
			fuzzUsers = append(fuzzUsers, u)
		}
	})
	u := NewUSM(testEngine())
	if err := u.SetUsers(fuzzUsers); err != nil {
		t.Fatal(err)
	}
	return u
}

// seedMessages are valid and broken datagrams of every kind.
func seedMessages(t testing.TB) [][]byte {
	eng := testEngine()
	seeds := [][]byte{
		v1Trap("public", 0, 0, nil),
		v1Trap("public", 6, 17, []Varbind{{OID: oidIfIndex3, Value: intVal(3)}}),
		v2cMsg("public", PDUTrap, 4711, linkDownVarbinds()),
		v2cMsg("public", PDUInform, 7, linkDownVarbinds()),
		v2cMsg("public", PDUGet, 1, nil),
		v2cMsg("public", PDUTrap, 1, linkDownVarbinds())[:40],
		[]byte{0x30, 0x80, 0x02, 0x01, 0x01},
		[]byte("<13>Nov 14 not snmp"),
	}
	for i, c := range fuzzCombos {
		name := "u-" + c.name()
		seeds = append(seeds,
			v3Msg(t, c, name, V3Header{MsgID: int64(i), EngineID: senderEngine, EngineBoots: 1, EngineTime: 100},
				&PDU{Type: PDUTrap, RequestID: 5, Varbinds: linkDownVarbinds()}),
			v3Msg(t, c, name, V3Header{MsgID: int64(i), Reportable: true, EngineID: eng.ID, EngineBoots: eng.Boots, EngineTime: eng.Time(t0)},
				&PDU{Type: PDUInform, RequestID: 6, Varbinds: linkDownVarbinds()}))
	}
	probe, _ := EncodeV3(V3Header{MsgID: 1, Reportable: true, Level: NoAuthNoPriv}, Security{}, 0, EncodePDU(&PDU{Type: PDUGet, RequestID: 2}))
	return append(seeds, probe)
}

func FuzzBER(f *testing.F) {
	for _, s := range seedMessages(f) {
		f.Add(s)
	}
	f.Add([]byte{0x02, 0x09, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x06, 0x05, 0x2b, 0x8f, 0xff, 0xff, 0x7f})
	f.Fuzz(func(t *testing.T, data []byte) {
		walkBER(t, data, 0, 0)
	})
}

// walkBER decodes every TLV it can, recursively, and checks each primitive
// decoder's round trip.
func walkBER(t *testing.T, b []byte, off, depth int) {
	for len(b) > 0 && depth < 16 {
		tv, rest, err := readTLV(b, off)
		if err != nil {
			return
		}
		if tv.coff+len(tv.content) != tv.end() || len(rest) != len(b)-(tv.end()-off) {
			t.Fatalf("offsets: %+v", tv)
		}
		if v, err := parseInt(tv); err == nil {
			back, _, _ := readTLV(appendInt(nil, tagInteger, v), 0)
			if w, err := parseInt(back); err != nil || w != v {
				t.Fatalf("int %d round trip %d %v", v, w, err)
			}
		}
		if v, err := parseUint(tv); err == nil {
			back, _, _ := readTLV(appendUint(nil, tagCounter64, v), 0)
			if w, err := parseUint(back); err != nil || w != v {
				t.Fatalf("uint %d round trip %d %v", v, w, err)
			}
		}
		if o, err := parseOID(tv); err == nil {
			if len(o) > MaxOIDLen {
				t.Fatalf("OID of %d", len(o))
			}
			back, _, _ := readTLV(appendOID(nil, o), 0)
			if p, err := parseOID(back); err != nil || !p.Equal(o) {
				t.Fatalf("OID %s round trip %s %v", o, p, err)
			}
			if q, err := ParseOID(o.String()); err == nil && !q.Equal(o) {
				t.Fatalf("OID text %s", o)
			}
		}
		_, _ = parseValue(tv)
		if tv.tag&0x20 != 0 {
			walkBER(t, tv.content, tv.coff, depth+1)
		}
		b, off = rest, tv.end()
	}
}

func FuzzMessage(f *testing.F) {
	for _, s := range seedMessages(f) {
		f.Add(s, int64(0))
	}
	f.Fuzz(func(t *testing.T, raw []byte, dt int64) {
		orig := bytes.Clone(raw)
		u := fuzzUSM(t)
		now := t0.Add(time.Duration(dt%1e6) * time.Second)
		m := Decode(raw, u, now)
		if m == nil {
			t.Fatal("nil message")
		}
		if (m.Status == StatusOK) != (m.Err == "") {
			t.Fatalf("status %v with error %q", m.Status, m.Err)
		}
		if m.Status == StatusOK && !m.Discovery && m.PDU == nil {
			t.Fatalf("ok without a PDU")
		}
		if m.Status != StatusOK && m.Status != StatusMalformed && m.Status != StatusUnexpectedPDU && m.PDU != nil &&
			!(m.Status == StatusNotInTime && m.TimeResync) {
			t.Fatalf("%v keeps a PDU", m.Status)
		}
		if m.TimeResync && (m.Version != V3 || m.Reportable || m.Level == NoAuthNoPriv) {
			t.Fatalf("a time resync from a %v %v message (reportable %v)", m.Version, m.Level, m.Reportable)
		}
		// The record: bounded, parses back, and the community is masked.
		rec := FormatRecord(nil, m, RecordOptions{Names: BuiltinMIBs(), Dup: dt&1 == 1})
		if recordLen(rec) > MaxRecordLen {
			t.Fatalf("record of %d", recordLen(rec))
		}
		r, err := ParseRecord(rec)
		if err != nil {
			t.Fatalf("%s: %v", rec, err)
		}
		if r.Status != m.Status.String() || r.Error != m.Err || r.Version != m.Version.String() && m.Version >= 0 && m.Version <= 3 {
			t.Fatalf("record %+v for %v %q", r, m.Status, m.Err)
		}
		masked, _ := base64.StdEncoding.DecodeString(r.Raw)
		if len(masked) != len(raw) {
			t.Fatalf("raw= of %d bytes for %d", len(masked), len(raw))
		}
		if m.Community != nil && !bytes.Equal(masked[m.communityOff:m.communityOff+len(m.Community)], bytes.Repeat([]byte{'*'}, len(m.Community))) {
			t.Fatalf("community not masked")
		}
		// The reply, when there is one, builds and is bounded.
		if rep, err := u.Reply(m, now); err == nil && rep != nil {
			if m.Reply == ReplyResponse && len(rep) > len(raw)+MaxReplyGrowth {
				t.Fatalf("Response %d for %d", len(rep), len(raw))
			}
			if back := Decode(rep, nil, now); back.Status == StatusMalformed {
				t.Fatalf("our reply doesn't decode: %s", back.Err)
			}
		}
		if !bytes.Equal(raw, orig) {
			t.Fatal("raw modified")
		}
		// Deterministic from the same state.
		if m2 := Decode(raw, fuzzUSM(t), now); m2.Status != m.Status || m2.Err != m.Err {
			t.Fatalf("not deterministic: %v %q / %v %q", m.Status, m.Err, m2.Status, m2.Err)
		}
	})
}

// FuzzUSM drives authenticated (and encrypted) v3 messages with arbitrary
// contents through auth and decryption: either a valid message with a few
// bytes flipped, or a correctly signed one whose PDU is the fuzzer's bytes.
func FuzzUSM(f *testing.F) {
	f.Add([]byte{0xa7, 0x03, 0x02, 0x01, 0x05}, uint8(0), uint16(0), false)
	f.Add(EncodePDU(&PDU{Type: PDUInform, RequestID: 9, Varbinds: linkDownVarbinds()}), uint8(1), uint16(0), true)
	f.Add([]byte{0x30, 0x00}, uint8(2), uint16(40), false)
	f.Add(EncodePDU(&PDU{Type: PDUTrap, Varbinds: header(1, testTrapOID)}), uint8(3), uint16(7), false)
	f.Fuzz(func(t *testing.T, payload []byte, sel uint8, flip uint16, inform bool) {
		u := fuzzUSM(t)
		eng := u.Engine()
		c := fuzzCombos[int(sel)%len(fuzzCombos)]
		h := V3Header{MsgID: 3, EngineID: senderEngine, EngineBoots: 1, EngineTime: 100, Level: c.level(), User: []byte("u-" + c.name())}
		if inform {
			h.Reportable, h.EngineID, h.EngineBoots, h.EngineTime = true, eng.ID, eng.Boots, eng.Time(t0)
		}
		h.ContextEngineID = h.EngineID
		k := Keys{}
		for _, us := range fuzzUsers {
			if us.Name == string(h.User) {
				for _, ek := range us.EngineKeys {
					if bytes.Equal(ek.EngineID, h.EngineID) {
						k = ek.Keys
					}
				}
			}
		}
		raw, err := EncodeV3(h, Security{Auth: c.auth, Priv: c.priv, Keys: k}, uint64(flip), payload)
		if err != nil {
			t.Fatal(err)
		}
		if flip != 0 {
			raw[int(flip)%len(raw)] ^= byte(flip>>8 | 1)
		}
		m := Decode(raw, u, t0)
		if flip == 0 {
			switch m.Status {
			case StatusOK, StatusUnexpectedPDU, StatusDecryptFailed, StatusMalformed:
			default:
				t.Fatalf("a correctly signed message: %v %q", m.Status, m.Err)
			}
			if c.level() == AuthPriv && m.Status == StatusMalformed {
				t.Fatalf("decrypted data malformed rather than decrypt_failed: %q", m.Err)
			}
		}
		if _, err := u.Reply(m, t0); err != nil && m.Reply != ReplyNone {
			t.Fatalf("%v: %v", m.Reply, err)
		}
		_ = FormatRecord(nil, m, RecordOptions{})
	})
}

func FuzzRecord(f *testing.F) {
	for _, s := range seedMessages(f) {
		f.Add(s)
		m := Decode(s, nil, t0)
		f.Add(FormatRecord(nil, m, RecordOptions{Names: BuiltinMIBs()}))
	}
	f.Add([]byte(`status=ok vb=1.3:str:"a \"b\" \\" vb=1.3(x):int:5(y) raw=`))
	f.Fuzz(func(t *testing.T, data []byte) {
		// Any bytes: ParseRecord never panics.
		_, _ = ParseRecord(data)
		_ = RecordText(data)
		// Any datagram: format, then parse back to the same fields.
		m := Decode(data, nil, t0)
		for _, names := range []Namer{nil, BuiltinMIBs()} {
			rec := FormatRecord(nil, m, RecordOptions{Names: names})
			r, err := ParseRecord(rec)
			if err != nil {
				t.Fatalf("%s: %v", rec, err)
			}
			if r.Status != m.Status.String() || r.Error != m.Err {
				t.Fatalf("status %q %q", r.Status, r.Error)
			}
			if m.Community != nil && r.Cred != CommunityHash(m.Community) {
				t.Fatalf("cred %q", r.Cred)
			}
			if m.PDU != nil && r.PDU != m.PDU.Type.String() {
				t.Fatalf("pdu %q", r.PDU)
			}
			if m.PDU != nil && (m.Status == StatusOK || m.PDU.Varbinds != nil) {
				vbs := m.PDU.Varbinds
				if t := m.PDU.Type; t == PDUTrap || t == PDUInform || t == PDUV1Trap {
					vbs = m.PDU.Notification().Varbinds
				}
				if len(r.Varbinds) != len(vbs) {
					t.Fatalf("%d varbinds, want %d", len(r.Varbinds), len(vbs))
				}
				for i, vb := range vbs {
					g := r.Varbinds[i]
					if g.OID != vb.OID.String() {
						t.Fatalf("vb %d oid %s", i, g.OID)
					}
					if vb.Value.Kind == KindOctetString && g.Type == TypeStr && g.Value != string(vb.Value.Bytes) {
						t.Fatalf("vb %d str %q, want %q", i, g.Value, vb.Value.Bytes)
					}
				}
			}
			if !bytes.HasPrefix(rec, RecordText(rec)) {
				t.Fatal("RecordText")
			}
		}
	})
}

func FuzzMIB(f *testing.F) {
	f.Add([]byte(exampleMIBs))
	f.Add([]byte(exampleTraps))
	f.Add(builtinMIB)
	f.Add([]byte("X DEFINITIONS ::= BEGIN a OBJECT IDENTIFIER ::= { b 1 } b OBJECT IDENTIFIER ::= { a 1 } END"))
	f.Add([]byte("X DEFINITIONS ::= BEGIN T ::= TEXTUAL-CONVENTION SYNTAX INTEGER { a(-1) } o OBJECT-TYPE SYNTAX T ::= { iso 5 } END"))
	f.Fuzz(func(t *testing.T, data []byte) {
		n := 0
		_, _ = parseMIBFile(data, &n, 10000)
		s, rep := LoadMIBFiles([]MIBFile{{Name: "f.mib", Data: data}, {Name: "smi.mib", Data: []byte(exampleMIBs)}})
		if rep.Names != s.Len() {
			t.Fatalf("names %d vs %d", rep.Names, s.Len())
		}
		for _, e := range rep.Errors {
			if e.File == "" {
				t.Fatalf("error without a file: %+v", e)
			}
		}
		for _, o := range []OID{oidLinkDown, oidIfOper3, {1, 3, 6, 1, 4, 1, 32473, 0, 1}, {1}, {2, 999}} {
			_ = s.Name(o)
			_ = s.EnumName(o, 1)
		}
		_, _ = s.Lookup("linkDown")
	})
}

// TestWriteFuzzSeeds writes the seed corpora into testdata/fuzz. It runs only
// with WOODSHED_WRITE_FUZZ_SEEDS=1.
func TestWriteFuzzSeeds(t *testing.T) {
	if os.Getenv("WOODSHED_WRITE_FUZZ_SEEDS") == "" {
		t.Skip("set WOODSHED_WRITE_FUZZ_SEEDS=1 to regenerate testdata/fuzz")
	}
	write := func(target, name string, values ...any) {
		dir := filepath.Join("testdata", "fuzz", target)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		b.WriteString("go test fuzz v1\n")
		for _, v := range values {
			switch v := v.(type) {
			case []byte:
				fmt.Fprintf(&b, "[]byte(%q)\n", v)
			case int64:
				fmt.Fprintf(&b, "int64(%d)\n", v)
			case uint8:
				fmt.Fprintf(&b, "uint8(%d)\n", v)
			case uint16:
				fmt.Fprintf(&b, "uint16(%d)\n", v)
			case bool:
				fmt.Fprintf(&b, "bool(%v)\n", v)
			}
		}
		if err := os.WriteFile(filepath.Join(dir, name), b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for i, s := range seedMessages(t) {
		name := fmt.Sprintf("seed-%02d", i)
		write("FuzzBER", name, s)
		write("FuzzMessage", name, s, int64(i))
		write("FuzzRecord", name, s)
	}
	for i, c := range fuzzCombos {
		write("FuzzUSM", fmt.Sprintf("seed-%02d", i), EncodePDU(&PDU{Type: PDUTrap, RequestID: int64(i), Varbinds: linkDownVarbinds()}), uint8(i), uint16(0), i%2 == 1)
		_ = c
	}
	write("FuzzMIB", "seed-example-smi", []byte(exampleMIBs))
	write("FuzzMIB", "seed-example-traps", []byte(exampleTraps))
	write("FuzzMIB", "seed-builtin", builtinMIB)
}
