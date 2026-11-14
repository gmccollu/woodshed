package snmp

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestV1Traps(t *testing.T) {
	names := []string{"coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss"}
	mibs := BuiltinMIBs()
	for generic := int64(0); generic <= 6; generic++ {
		raw := v1Trap("public", generic, 17, []Varbind{{OID: oidIfIndex3, Value: intVal(3)}})
		m := Decode(raw, nil, t0)
		if m.Status != StatusOK || m.Version != V1 || m.PDU.Type != PDUV1Trap {
			t.Fatalf("generic %d: %v %q", generic, m.Status, m.Err)
		}
		if string(m.Community) != "public" || m.Reply != ReplyNone {
			t.Errorf("generic %d: community %q reply %v", generic, m.Community, m.Reply)
		}
		p := m.PDU
		if !p.Enterprise.Equal(testEnterprise) || !bytes.Equal(p.AgentAddr, []byte{192, 0, 2, 7}) || p.Generic != generic || p.Specific != 17 || p.Timestamp != 4242 {
			t.Errorf("generic %d: fields %+v", generic, p)
		}
		n := p.Notification()
		want := append(append(OID{}, testEnterprise...), 0, 17)
		if generic < 6 {
			want = append(append(OID{}, OIDSnmpTraps...), uint32(generic+1))
			if got := mibs.Name(n.TrapOID); got != names[generic] {
				t.Errorf("generic %d names %q, want %s", generic, got, names[generic])
			}
		}
		if !n.TrapOID.Equal(want) || n.Uptime != 4242 || len(n.Varbinds) != 1 {
			t.Errorf("generic %d: notification %v %d %d", generic, n.TrapOID, n.Uptime, len(n.Varbinds))
		}
	}
	if V1TrapOID(testEnterprise, 7, 0) != nil {
		t.Error("generic 7 translated")
	}
	// The reverse mapping (RFC 3584 §3.2), for the sender.
	for _, tc := range []struct {
		trap        OID
		ent         OID
		gen, specif int64
	}{
		{oidLinkDown, testEnterprise, 2, 0},
		{testTrapOID, testEnterprise, 6, 1},
		{OID{1, 3, 6, 1, 4, 1, 32473, 9}, OID{1, 3, 6, 1, 4, 1, 32473}, 6, 9},
	} {
		e, g, s := V1Fields(tc.trap, testEnterprise)
		if !e.Equal(tc.ent) || g != tc.gen || s != tc.specif {
			t.Errorf("V1Fields(%s) = %s %d %d", tc.trap, e, g, s)
		}
	}
}

func TestV2cTrapAndInform(t *testing.T) {
	vbs := linkDownVarbinds()
	m := Decode(v2cMsg("public", PDUTrap, 4711, vbs), nil, t0)
	if m.Status != StatusOK || m.Version != V2c || m.PDU.Type != PDUTrap || m.PDU.RequestID != 4711 || m.Reply != ReplyNone {
		t.Fatalf("trap: %v %q %+v", m.Status, m.Err, m.PDU)
	}
	n := m.PDU.Notification()
	if !n.HasUptime || n.Uptime != 8641234 || !n.TrapOID.Equal(oidLinkDown) || len(n.Varbinds) != 3 {
		t.Errorf("notification %+v", n)
	}

	raw := v2cMsg("s3cret-community", PDUInform, 99, vbs)
	m = Decode(raw, nil, t0)
	if m.Status != StatusOK || m.Reply != ReplyResponse {
		t.Fatalf("inform: %v %q reply %v", m.Status, m.Err, m.Reply)
	}
	resp, err := (*USM)(nil).Reply(m, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) > len(raw) {
		t.Errorf("the Response (%d) is larger than the inform (%d)", len(resp), len(raw))
	}
	r := Decode(resp, nil, t0)
	if r.PDU == nil || r.PDU.Type != PDUResponse || r.PDU.RequestID != 99 || string(r.Community) != "s3cret-community" {
		t.Fatalf("response: %+v", r)
	}
	if r.PDU.ErrorStatus != 0 || r.PDU.ErrorIndex != 0 || len(r.PDU.Varbinds) != len(vbs) {
		t.Errorf("response fields: %+v", r.PDU)
	}
	// A Response, decoded by the receiver, is an unexpected PDU (never answered).
	if r.Status != StatusUnexpectedPDU || r.Reply != ReplyNone || r.Err == "" {
		t.Errorf("response as received: %v %v %q", r.Status, r.Reply, r.Err)
	}
}

func TestUnexpectedPDUs(t *testing.T) {
	for _, typ := range []PDUType{PDUGet, PDUGetNext, PDUResponse, PDUSet, PDUGetBulk, PDUReport, 0xa9} {
		m := Decode(v2cMsg("public", typ, 5, header(1, testTrapOID)), nil, t0)
		if m.Status != StatusUnexpectedPDU || m.Reply != ReplyNone || m.PDU == nil || m.PDU.Type != typ {
			t.Errorf("%s: %v %v", typ, m.Status, m.Reply)
		}
		if typ != 0xa9 && len(m.PDU.Varbinds) != 2 {
			t.Errorf("%s: varbinds not kept: %d", typ, len(m.PDU.Varbinds))
		}
	}
	// A v2 trap in a v1 message, and a v1 Trap-PDU in a v2c message.
	m := Decode(EncodeCommunity(V1, []byte("public"), EncodePDU(&PDU{Type: PDUTrap, Varbinds: header(1, testTrapOID)})), nil, t0)
	if m.Status != StatusUnexpectedPDU {
		t.Errorf("v2 trap in v1: %v", m.Status)
	}
	m = Decode(EncodeCommunity(V2c, []byte("public"), EncodePDU(&PDU{Type: PDUV1Trap, Enterprise: testEnterprise})), nil, t0)
	if m.Status != StatusUnexpectedPDU {
		t.Errorf("v1 trap in v2c: %v", m.Status)
	}
}

// TestMalformed: every broken datagram is a Message with StatusMalformed and a
// reason, never a nil or a panic; what decoded before the break is kept.
func TestMalformed(t *testing.T) {
	good := v2cMsg("public", PDUTrap, 4711, linkDownVarbinds())
	for _, tc := range []struct {
		name string
		raw  []byte
		err  string
		cred bool
	}{
		{"empty", nil, "not an SNMP message", false},
		{"text", []byte("<13>Nov 14 hello"), "not an SNMP message", false},
		{"one byte", []byte{0x30}, "truncated header", false},
		{"truncated", good[:len(good)-5], "runs past the end", false},
		{"indefinite outer", append([]byte{0x30, 0x80}, good[2:]...), "indefinite", false},
		{"no version", []byte{0x30, 0x03, 0x04, 0x01, 'x'}, "version", false},
		{"version 2", []byte{0x30, 0x03, 0x02, 0x01, 0x02}, "unsupported SNMP version 2", false},
		{"no community", []byte{0x30, 0x03, 0x02, 0x01, 0x01}, "community", false},
		{"no PDU", []byte{0x30, 0x0a, 0x02, 0x01, 0x01, 0x04, 0x05, 'h', 'e', 'l', 'l', 'o'}, "PDU", true},
		{"not a PDU", []byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x04, 0x01, 'p', 0x30, 0x03, 0x02, 0x01, 0x00, 0x00}, "want a PDU", true},
		{"PDU without varbinds", EncodeCommunity(V2c, []byte("p"), appendTLV(nil, 0xa7, []byte{0x02, 0x01, 0x05, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00})), "varbind list", true},
		// A varbind whose name is a truncated OID.
		{"bad varbind", EncodeCommunity(V2c, []byte("p"), appendTLV(nil, 0xa7, append([]byte{0x02, 0x01, 0x05, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00},
			appendTLV(nil, tagSequence, appendTLV(nil, tagSequence, []byte{0x06, 0x02, 0x2b, 0x86, 0x05, 0x00}))...))), "varbind 1 name", true},
		{"bad value", EncodeCommunity(V2c, []byte("p"), appendTLV(nil, 0xa7, append([]byte{0x02, 0x01, 0x05, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00},
			appendTLV(nil, tagSequence, appendTLV(nil, tagSequence, []byte{0x06, 0x01, 0x2b, 0x02, 0x00}))...))), "empty integer", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Decode(tc.raw, nil, t0)
			if m == nil || m.Status != StatusMalformed || !strings.Contains(m.Err, tc.err) {
				t.Fatalf("got %v %q, want malformed %q", m.Status, m.Err, tc.err)
			}
			if (m.Community != nil) != tc.cred {
				t.Errorf("community read: %v", m.Community != nil)
			}
			if m.PDU != nil && m.PDU.Varbinds != nil {
				t.Error("varbinds kept for a malformed PDU")
			}
			if m.Reply != ReplyNone {
				t.Error("a malformed message asks for a reply")
			}
		})
	}
	// Trailing bytes after the message are ignored (the raw keeps them).
	if m := Decode(append(append([]byte(nil), good...), 0, 0, 0), nil, t0); m.Status != StatusOK {
		t.Errorf("trailing bytes: %v %q", m.Status, m.Err)
	}
	// Lenient: an agent-addr sent as an OCTET STRING, a time-stamp as an INTEGER.
	pdu := appendTLV(nil, 0xa4, []byte{0x06, 0x07, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0x7e, 0x04, 0x04, 10, 0, 0, 1,
		0x02, 0x01, 0x03, 0x02, 0x01, 0x00, 0x02, 0x01, 0x05, 0x30, 0x00})
	if m := Decode(EncodeCommunity(V1, []byte("p"), pdu), nil, t0); m.Status != StatusOK || m.PDU.Timestamp != 5 {
		t.Errorf("lenient v1: %v %q", m.Status, m.Err)
	}
}

// TestV3Combinations sends a trap and an inform at every level and protocol
// combination through the decoder, and checks the inform's Response decodes on
// the sender's side.
func TestV3Combinations(t *testing.T) {
	var users []User
	cs := allCombos()
	for _, c := range cs {
		users = append(users, c.user(c.name()))
	}
	u := newTestUSM(t, users...)
	now := t0
	eng := u.Engine()
	for i, c := range cs {
		t.Run(c.name(), func(t *testing.T) {
			// A trap: the sender is authoritative.
			vbs := append(header(100, testTrapOID), Varbind{OID: testEnterprise, Value: strVal(fmt.Sprintf("seq=test:%d", i))})
			raw := v3Msg(t, c, c.name(), V3Header{MsgID: 1, EngineID: senderEngine, EngineBoots: 3, EngineTime: 1000}, &PDU{Type: PDUTrap, RequestID: 77, Varbinds: vbs})
			m := Decode(raw, u, now)
			if m.Status != StatusOK || m.Level != c.level() || string(m.User) != c.name() || !bytes.Equal(m.EngineID, senderEngine) {
				t.Fatalf("trap: %v %q", m.Status, m.Err)
			}
			if m.PDU.RequestID != 77 || len(m.PDU.Varbinds) != 3 || string(m.PDU.Varbinds[2].Value.Bytes) != fmt.Sprintf("seq=test:%d", i) {
				t.Fatalf("trap PDU: %+v", m.PDU)
			}
			if m.Reply != ReplyNone {
				t.Errorf("trap asks for %v", m.Reply)
			}
			if c.priv != PrivNone && bytes.Contains(raw, []byte("seq=test")) {
				t.Error("the encrypted trap shows its varbind")
			}

			// An inform: Woodshed is authoritative.
			raw = v3Msg(t, c, c.name(), V3Header{MsgID: 555, Reportable: true, EngineID: eng.ID, EngineBoots: eng.Boots, EngineTime: eng.Time(now) - 3},
				&PDU{Type: PDUInform, RequestID: 88, Varbinds: vbs})
			m = Decode(raw, u, now)
			if m.Status != StatusOK || m.Reply != ReplyResponse {
				t.Fatalf("inform: %v %q reply %v", m.Status, m.Err, m.Reply)
			}
			resp, err := u.Reply(m, now)
			if err != nil {
				t.Fatal(err)
			}
			if len(resp) > len(raw)+MaxReplyGrowth {
				t.Errorf("Response %d bytes for a %d-byte inform", len(resp), len(raw))
			}
			// The sender decodes it: Woodshed's engine is the authoritative one there.
			client := NewUSM(&Engine{ID: senderEngine, Boots: 1, Start: now})
			if err := client.SetUsers([]User{c.user(c.name())}); err != nil {
				t.Fatal(err)
			}
			r := Decode(resp, client, now)
			if r.PDU == nil || r.PDU.Type != PDUResponse || r.PDU.RequestID != 88 || r.MsgID != 555 || r.Level != c.level() {
				t.Fatalf("response: %v %q %+v", r.Status, r.Err, r.PDU)
			}
			if r.EngineBoots != eng.Boots || r.EngineTime != eng.Time(now) || r.Reportable {
				t.Errorf("response header: boots %d time %d reportable %v", r.EngineBoots, r.EngineTime, r.Reportable)
			}
			if len(r.PDU.Varbinds) != len(vbs) {
				t.Errorf("response varbinds %d", len(r.PDU.Varbinds))
			}
		})
	}
}

// TestV3Failures: each USM failure has its status, a reason, only the parts
// readable without the keys, and the reply the RFC asks for.
func TestV3Failures(t *testing.T) {
	sha := combo{AuthSHA256, PrivAES128, 0}
	u := newTestUSM(t, sha.user("alice"), combo{AuthMD5, PrivNone, 0}.user("bob"),
		User{Name: "nopriv", Level: NoAuthNoPriv})
	eng := u.Engine()
	trap := &PDU{Type: PDUTrap, RequestID: 1, Varbinds: header(1, testTrapOID)}
	trapHdr := V3Header{MsgID: 9, EngineID: senderEngine, EngineBoots: 1, EngineTime: 10}

	wrongPass := sha
	check := func(name string, raw []byte, want Status, wantErr string) *Message {
		t.Helper()
		m := Decode(raw, u, t0)
		if m.Status != want || !strings.Contains(m.Err, wantErr) {
			t.Errorf("%s: %v %q, want %v %q", name, m.Status, m.Err, want, wantErr)
		}
		if m.Status != StatusOK && m.Status != StatusMalformed && (m.PDU != nil || m.ContextName != nil) {
			t.Errorf("%s: a failure keeps the PDU", name)
		}
		return m
	}

	check("unknown user", v3Msg(t, sha, "mallory", trapHdr, trap), StatusUnknownUser, `"mallory"`)

	// A wrong auth passphrase: the digest differs.
	k, _ := LocalizeKeys(AuthSHA256, PrivAES128, 0, []byte("not-the-passphrase"), testPrivPass, senderEngine)
	h := trapHdr
	h.Level, h.User, h.ContextEngineID = AuthPriv, []byte("alice"), senderEngine
	raw, _ := EncodeV3(h, Security{Auth: AuthSHA256, Priv: PrivAES128, Keys: k}, 1, EncodePDU(trap))
	check("wrong auth pass", raw, StatusAuthFailed, "wrong digest")
	_ = wrongPass

	// A wrong priv passphrase: authentic, but the plaintext doesn't decode.
	k, _ = LocalizeKeys(AuthSHA256, PrivAES128, 0, testAuthPass, []byte("not-the-privpass"), senderEngine)
	raw, _ = EncodeV3(h, Security{Auth: AuthSHA256, Priv: PrivAES128, Keys: k}, 2, EncodePDU(trap))
	check("wrong priv pass", raw, StatusDecryptFailed, "doesn't decode")

	// Below the user's level, and above what it has keys for.
	check("below", v3Msg(t, combo{AuthSHA256, PrivNone, 0}, "alice", trapHdr, trap), StatusLevel, "below")
	check("noauth for an auth user", v3Msg(t, combo{}, "bob", trapHdr, trap), StatusLevel, "below")
	check("above", v3Msg(t, combo{AuthMD5, PrivDES, 0}, "bob", trapHdr, trap), StatusLevel, "above")
	// Above the level is fine when the keys are there: alice at authPriv; bob's MD5 at authNoPriv is its level.
	check("bob ok", v3Msg(t, combo{AuthMD5, PrivNone, 0}, "bob", trapHdr, trap), StatusOK, "")
	check("nopriv ok", v3Msg(t, combo{}, "nopriv", trapHdr, trap), StatusOK, "")

	// The auth parameters' length must be the protocol's.
	raw = v3Msg(t, combo{AuthMD5, PrivNone, 0}, "bob", trapHdr, trap)
	m := Decode(raw, u, t0)
	short := bytes.Replace(raw, append([]byte{0x04, 12}, m.authParams...), append([]byte{0x04, 11}, m.authParams[:11]...), 1)
	short = fixLengths(t, short, -1)
	check("short auth params", short, StatusAuthFailed, "12")

	// An inform to another engine ID: unknown_engine and a Report with ours.
	h2 := V3Header{MsgID: 31, Reportable: true, EngineID: senderEngine, EngineBoots: eng.Boots, EngineTime: eng.Time(t0)}
	m = check("inform to another engine", v3Msg(t, sha, "alice", h2, &PDU{Type: PDUInform, RequestID: 4, Varbinds: header(1, testTrapOID)}), StatusUnknownEngine, "not this receiver's")
	if m.Reply != ReplyReport {
		t.Fatalf("no Report for an unknown engine")
	}
	rep, err := u.Reply(m, t0)
	if err != nil {
		t.Fatal(err)
	}
	r := Decode(rep, nil, t0)
	r.PDU, _ = r.PlainPDU()
	if !bytes.Equal(r.EngineID, eng.ID) || r.MsgID != 31 || r.Level != NoAuthNoPriv || r.PDU == nil || r.PDU.Type != PDUReport {
		t.Fatalf("Report: %+v", r)
	}
	if vb := r.PDU.Varbinds; len(vb) != 1 || !vb[0].OID.Equal(oidUnknownEngineIDs) || vb[0].Value.Kind != KindCounter32 {
		t.Errorf("Report varbinds %+v", vb)
	}

	// Engine-bound keys: another engine is unknown_engine.
	bound := sha.user("carol")
	eks, err := bound.Localize([][]byte{mustHex(t, "8000000005000000000000aaaa")})
	if err != nil {
		t.Fatal(err)
	}
	bound.AuthPass, bound.PrivPass, bound.EngineKeys = nil, nil, eks
	u2 := newTestUSM(t, bound)
	m = Decode(v3Msg(t, sha, "carol", trapHdr, trap), u2, t0)
	if m.Status != StatusUnknownEngine || !strings.Contains(m.Err, "no keys for engine") {
		t.Errorf("bound user, other engine: %v %q", m.Status, m.Err)
	}
	h3 := trapHdr
	h3.EngineID = eks[0].EngineID
	if m := Decode(v3Msg(t, sha, "carol", h3, trap), u2, t0); m.Status != StatusOK {
		t.Errorf("bound user, its engine: %v %q", m.Status, m.Err)
	}

	// Malformed v3 headers.
	for name, raw := range map[string][]byte{
		"priv without auth": func() []byte {
			b := v3Msg(t, combo{}, "nopriv", trapHdr, trap)
			i := bytes.Index(b, []byte{0x04, 0x01, 0x00}) // msgFlags
			b[i+2] = flagPriv
			return b
		}(),
		"security model 2": func() []byte {
			b := v3Msg(t, combo{}, "nopriv", trapHdr, trap)
			i := bytes.Index(b, []byte{0x04, 0x01, 0x00, 0x02, 0x01, 0x03})
			b[i+5] = 2
			return b
		}(),
	} {
		if m := Decode(raw, u, t0); m.Status != StatusMalformed {
			t.Errorf("%s: %v %q", name, m.Status, m.Err)
		}
	}
	if c := u.Counters(); c.UnknownUserNames == 0 || c.WrongDigests == 0 || c.DecryptionErrors == 0 || c.UnsupportedSecLevels == 0 || c.UnknownEngineIDs == 0 {
		t.Errorf("counters: %+v", c)
	}
}

// fixLengths adjusts the outer SEQUENCE and msgSecurityParameters lengths after
// an edit that changed the message's size by delta (short forms only).
func fixLengths(t *testing.T, b []byte, delta int) []byte {
	t.Helper()
	if b[1]&0x80 != 0 {
		t.Skip("long-form outer length")
	}
	b[1] = byte(int(b[1]) + delta)
	// msgSecurityParameters: the OCTET STRING after msgGlobalData, then its SEQUENCE.
	_, rest, _ := readTLV(b[2:], 2) // version
	gd, _, _ := readTLV(rest, 0)
	sp := 2 + 3 + 2 + len(gd.content)
	b[sp+1] = byte(int(b[sp+1]) + delta)
	b[sp+3] = byte(int(b[sp+3]) + delta)
	return b
}

func TestDiscovery(t *testing.T) {
	u := newTestUSM(t, combo{AuthSHA1, PrivAES128, 0}.user("alice"))
	eng := u.Engine()
	probe, err := EncodeV3(V3Header{MsgID: 4242, Reportable: true, Level: NoAuthNoPriv}, Security{}, 0, EncodePDU(&PDU{Type: PDUGet, RequestID: 314}))
	if err != nil {
		t.Fatal(err)
	}
	m := Decode(probe, u, t0)
	if !m.Discovery || m.Reply != ReplyReport || m.Status != StatusOK {
		t.Fatalf("probe: discovery %v reply %v status %v %q", m.Discovery, m.Reply, m.Status, m.Err)
	}
	rep, err := u.Reply(m, t0.Add(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	r := Decode(rep, nil, t0)
	if !bytes.Equal(r.EngineID, eng.ID) || r.EngineBoots != eng.Boots || r.EngineTime != eng.Time(t0.Add(30*time.Second)) || r.MsgID != 4242 {
		t.Fatalf("Report header: %x %d %d %d", r.EngineID, r.EngineBoots, r.EngineTime, r.MsgID)
	}
	if r.PDU, err = r.PlainPDU(); err != nil {
		t.Fatal(err)
	}
	if r.PDU == nil || r.PDU.Type != PDUReport || r.PDU.RequestID != 314 || !r.PDU.Varbinds[0].OID.Equal(oidUnknownEngineIDs) || r.PDU.Varbinds[0].Value.Uint != 1 {
		t.Fatalf("Report PDU: %+v", r.PDU)
	}
	if r.Reportable || r.Level != NoAuthNoPriv || !bytes.Equal(r.ContextEngineID, eng.ID) {
		t.Errorf("Report flags: reportable %v level %v ctx %x", r.Reportable, r.Level, r.ContextEngineID)
	}
	if len(rep) > len(probe)+64 {
		t.Errorf("Report %d bytes for a %d-byte probe", len(rep), len(probe))
	}
	// Without USM a probe is still recognised, but there's nothing to answer with.
	if m := Decode(probe, nil, t0); !m.Discovery || m.Reply != ReplyNone {
		t.Errorf("nil USM: %v %v", m.Discovery, m.Reply)
	}
}

func TestTimeliness(t *testing.T) {
	c := combo{AuthSHA1, PrivDES, 0}
	u := newTestUSM(t, c.user("alice"))
	eng := u.Engine()
	trap := &PDU{Type: PDUTrap, RequestID: 1, Varbinds: header(1, testTrapOID)}

	// Informs (Woodshed authoritative): boots must match, time within 150 s.
	for _, tc := range []struct {
		name        string
		boots, time int64
		ok          bool
	}{
		{"in time", eng.Boots, eng.Time(t0), true},
		{"149 s early", eng.Boots, eng.Time(t0) - 149, true},
		{"150 s late", eng.Boots, eng.Time(t0) + 150, true},
		{"151 s early", eng.Boots, eng.Time(t0) - 151, false},
		{"old boots", eng.Boots - 1, eng.Time(t0), false},
		{"new boots", eng.Boots + 1, eng.Time(t0), false},
	} {
		raw := v3Msg(t, c, "alice", V3Header{MsgID: 77, Reportable: true, EngineID: eng.ID, EngineBoots: tc.boots, EngineTime: tc.time},
			&PDU{Type: PDUInform, RequestID: 5, Varbinds: header(1, testTrapOID)})
		m := Decode(raw, u, t0)
		if tc.ok {
			if m.Status != StatusOK {
				t.Errorf("%s: %v %q", tc.name, m.Status, m.Err)
			}
			continue
		}
		if m.Status != StatusNotInTime || m.Reply != ReplyReport || !m.reportAuth {
			t.Fatalf("%s: %v %q reply %v", tc.name, m.Status, m.Err, m.Reply)
		}
		// The Report is authenticated with alice's key, so the sender can resync.
		rep, err := u.Reply(m, t0)
		if err != nil {
			t.Fatal(err)
		}
		client := NewUSM(&Engine{ID: senderEngine, Boots: 1, Start: t0})
		cu := c.user("alice")
		cu.Level = NoAuthNoPriv // a sender reads Reports at any level
		if err := client.SetUsers([]User{cu}); err != nil {
			t.Fatal(err)
		}
		r := Decode(rep, client, t0)
		if r.Level != AuthNoPriv || r.PDU == nil || r.PDU.Type != PDUReport || !r.PDU.Varbinds[0].OID.Equal(oidNotInTimeWindows) {
			t.Fatalf("%s: Report %v %q %+v", tc.name, r.Status, r.Err, r.PDU)
		}
		if r.EngineBoots != eng.Boots || r.EngineTime != eng.Time(t0) || r.MsgID != 77 {
			t.Errorf("%s: Report header %d %d", tc.name, r.EngineBoots, r.EngineTime)
		}
	}

	// Traps (the sender authoritative): RFC 3414 §3.2 7b against the last seen clock.
	send := func(eid []byte, boots, tm int64, at time.Time) *Message {
		return Decode(v3Msg(t, c, "alice", V3Header{MsgID: 1, EngineID: eid, EngineBoots: boots, EngineTime: tm}, trap), u, at)
	}
	eid := mustHex(t, "80000000050000000000001234")
	steps := []struct {
		name        string
		boots, time int64
		at          time.Duration
		ok          bool
	}{
		{"first contact", 5, 1000, 0, true},
		{"later", 5, 1100, 100 * time.Second, true},
		{"slightly older, within 150 s", 5, 1000, 100 * time.Second, true},
		{"older than 150 s", 5, 940, 100 * time.Second, false},
		{"lower boots", 4, 99999, 100 * time.Second, false},
		{"a reboot", 6, 3, 200 * time.Second, true},
		{"the old boots after the reboot", 5, 1300, 200 * time.Second, false},
		{"time runs on by itself", 6, 3, 400 * time.Second, false}, // the clock estimate is now ~203
	}
	for _, s := range steps {
		m := send(eid, s.boots, s.time, t0.Add(s.at))
		if (m.Status == StatusOK) != s.ok || (!s.ok && m.Status != StatusNotInTime) {
			t.Errorf("trap %s: %v %q", s.name, m.Status, m.Err)
		}
		if m.Reply != ReplyNone {
			t.Errorf("trap %s: asks for a reply", s.name)
		}
	}
	// A message that fails authentication doesn't move the clock.
	eid2 := mustHex(t, "80000000050000000000005678")
	send(eid2, 5, 1000, t0)
	bad := v3Msg(t, c, "alice", V3Header{MsgID: 1, EngineID: eid2, EngineBoots: 9, EngineTime: 1}, trap)
	bad[len(bad)-1] ^= 1 // break the digest (the ciphertext is covered)
	if m := Decode(bad, u, t0); m.Status != StatusAuthFailed {
		t.Fatalf("broken digest: %v", m.Status)
	}
	if m := send(eid2, 5, 1001, t0); m.Status != StatusOK {
		t.Errorf("after a forged boots 9: %v %q", m.Status, m.Err)
	}
}

func TestKeyCacheAndLimit(t *testing.T) {
	c := combo{AuthSHA1, PrivAES256, KeyExtAlt}
	u := newTestUSM(t, c.user("alice"), combo{AuthSHA1, PrivAES256, KeyExtDraft}.user("dave"))
	trap := &PDU{Type: PDUTrap, RequestID: 1, Varbinds: header(1, testTrapOID)}
	limited, ok := 0, 0
	for i := 0; i < 40; i++ {
		eid := []byte{0x80, 0, 0, 0, 5, 0xee, 2, 3, 4, 5, 6, 7, byte(i)}
		m := Decode(v3Msg(t, c, "alice", V3Header{MsgID: 1, EngineID: eid, EngineBoots: 1, EngineTime: 1}, trap), u, t0)
		switch {
		case m.Status == StatusOK:
			ok++
		case m.Status == StatusUnknownEngine && strings.Contains(m.Err, "limit"):
			limited++
		default:
			t.Fatalf("engine %d: %v %q", i, m.Status, m.Err)
		}
	}
	if ok != SlowLocalizePerSec || limited != 40-SlowLocalizePerSec || u.Counters().SlowLocalizeLimited != uint64(limited) {
		t.Errorf("alt extension: %d ok, %d limited", ok, limited)
	}
	// A cached engine needs no new hash, and a second later the bucket has refilled.
	eid := []byte{0x80, 0, 0, 0, 5, 0xee, 2, 3, 4, 5, 6, 7, 0}
	if m := Decode(v3Msg(t, c, "alice", V3Header{MsgID: 1, EngineID: eid, EngineBoots: 1, EngineTime: 2}, trap), u, t0); m.Status != StatusOK {
		t.Errorf("cached: %v %q", m.Status, m.Err)
	}
	if m := Decode(v3Msg(t, c, "alice", V3Header{MsgID: 1, EngineID: []byte{0x80, 0, 0, 0, 5, 9, 9, 9, 9, 9, 9, 9, 9}, EngineBoots: 1, EngineTime: 1}, trap), u, t0.Add(time.Second)); m.Status != StatusOK {
		t.Errorf("after a second: %v %q", m.Status, m.Err)
	}
	// The draft extension (one small hash) isn't limited.
	d := combo{AuthSHA1, PrivAES256, KeyExtDraft}
	for i := 0; i < 40; i++ {
		eid := []byte{0x80, 0, 0, 0, 5, 7, 7, 7, 7, 7, 7, 7, byte(i)}
		if m := Decode(v3Msg(t, d, "dave", V3Header{MsgID: 1, EngineID: eid, EngineBoots: 1, EngineTime: 1}, trap), u, t0); m.Status != StatusOK {
			t.Fatalf("draft, engine %d: %v %q", i, m.Status, m.Err)
		}
	}
	// The LRU keeps at most its size.
	l := newLRU[int](3)
	for i := 0; i < 5; i++ {
		l.put(fmt.Sprint(i), i)
	}
	if _, ok := l.get("0"); ok || l.len() != 3 {
		t.Error("LRU didn't evict")
	}
}

func TestUserValidate(t *testing.T) {
	for name, u := range map[string]User{
		"no name":           {Level: NoAuthNoPriv},
		"long name":         {Name: strings.Repeat("x", 33), Level: NoAuthNoPriv},
		"no level":          {Name: "a"},
		"level too high":    {Name: "a", Level: AuthNoPriv},
		"priv without auth": {Name: "a", Level: AuthPriv, Priv: PrivDES, PrivPass: testPrivPass},
		"short pass":        {Name: "a", Level: AuthNoPriv, Auth: AuthMD5, AuthPass: []byte("short")},
		"no priv pass":      {Name: "a", Level: AuthPriv, Auth: AuthMD5, Priv: PrivDES, AuthPass: testAuthPass},
		"bad engine key":    {Name: "a", Level: AuthNoPriv, Auth: AuthMD5, EngineKeys: []EngineKeys{{EngineID: senderEngine, Keys: Keys{Auth: []byte{1}}}}},
	} {
		if err := u.Validate(); err == nil {
			t.Errorf("%s: valid", name)
		}
	}
	u := NewUSM(testEngine())
	if err := u.SetUsers([]User{{Name: "a", Level: NoAuthNoPriv}, {Name: "a", Level: NoAuthNoPriv}}); err == nil {
		t.Error("duplicate users accepted")
	}
	// A lower configured level accepts higher levels.
	c := combo{AuthSHA256, PrivAES128, 0}
	low := c.user("low")
	low.Level = NoAuthNoPriv
	u = newTestUSM(t, low)
	for _, lc := range []combo{{}, {AuthSHA256, PrivNone, 0}, c} {
		if m := Decode(v3Msg(t, lc, "low", V3Header{MsgID: 1, EngineID: senderEngine, EngineBoots: 1, EngineTime: 1}, &PDU{Type: PDUTrap, Varbinds: header(1, testTrapOID)}), u, t0); m.Status != StatusOK {
			t.Errorf("low user at %s: %v %q", lc.level(), m.Status, m.Err)
		}
	}
}
