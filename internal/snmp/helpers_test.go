package snmp

import (
	"encoding/hex"
	"testing"
	"time"
)

// Test fixtures. 32473 is IANA's enterprise number for documentation (RFC 5612).
var (
	testEnterprise = OID{1, 3, 6, 1, 4, 1, 32473, 1}
	testTrapOID    = OID{1, 3, 6, 1, 4, 1, 32473, 1, 0, 1}
	oidIfIndex3    = OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 1, 3}
	oidIfAdmin3    = OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 3}
	oidIfOper3     = OID{1, 3, 6, 1, 2, 1, 2, 2, 1, 8, 3}
	oidLinkDown    = OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 3}
	t0             = time.Date(2026, 11, 14, 9, 30, 58, 0, time.UTC)

	// Test passphrases: fixed test values, not secrets.
	testAuthPass = []byte("maplesyrup")
	testPrivPass = []byte("privpass-for-tests")
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func ticks(v uint64) Value  { return Value{Kind: KindTimeTicks, Uint: v} }
func oidVal(o OID) Value    { return Value{Kind: KindOID, OID: o} }
func intVal(v int64) Value  { return Value{Kind: KindInteger, Int: v} }
func strVal(s string) Value { return Value{Kind: KindOctetString, Bytes: []byte(s)} }
func header(up uint64, trap OID) []Varbind {
	return []Varbind{{OID: OIDSysUpTime, Value: ticks(up)}, {OID: OIDSnmpTrapOID, Value: oidVal(trap)}}
}

// linkDownVarbinds is the spec's example trap (SPEC §11.2.4).
func linkDownVarbinds() []Varbind {
	return append(header(8641234, oidLinkDown),
		Varbind{OID: oidIfIndex3, Value: intVal(3)},
		Varbind{OID: oidIfAdmin3, Value: intVal(1)},
		Varbind{OID: oidIfOper3, Value: intVal(2)})
}

func v2cMsg(community string, typ PDUType, reqID int64, vbs []Varbind) []byte {
	return EncodeCommunity(V2c, []byte(community), EncodePDU(&PDU{Type: typ, RequestID: reqID, Varbinds: vbs}))
}

func v1Trap(community string, generic, specific int64, vbs []Varbind) []byte {
	return EncodeCommunity(V1, []byte(community), EncodePDU(&PDU{
		Type: PDUV1Trap, Enterprise: testEnterprise, AgentAddr: []byte{192, 0, 2, 7},
		Generic: generic, Specific: specific, Timestamp: 4242, Varbinds: vbs,
	}))
}

// testEngine is the receiver's engine.
func testEngine() *Engine {
	return &Engine{ID: mustHexNoT("80000000050102030405060708"), Boots: 7, Start: t0.Add(-1000 * time.Second)}
}

func mustHexNoT(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var senderEngine = mustHexNoT("8000000005aabbccddeeff0011")

// combos is every auth × priv combination plus noAuthNoPriv.
type combo struct {
	auth AuthProtocol
	priv PrivProtocol
	ext  KeyExt
}

func (c combo) level() Level {
	switch {
	case c.priv != PrivNone:
		return AuthPriv
	case c.auth != AuthNone:
		return AuthNoPriv
	}
	return NoAuthNoPriv
}

func (c combo) name() string {
	n := c.auth.String()
	if c.priv != PrivNone {
		n += "-" + c.priv.String()
		if c.priv == PrivAES192 || c.priv == PrivAES256 {
			n += "-" + c.ext.String()
		}
	}
	return n
}

func allCombos() []combo {
	cs := []combo{{AuthNone, PrivNone, 0}}
	auths := []AuthProtocol{AuthMD5, AuthSHA1, AuthSHA224, AuthSHA256, AuthSHA384, AuthSHA512}
	for _, a := range auths {
		cs = append(cs, combo{a, PrivNone, 0})
	}
	for _, a := range auths {
		for _, p := range []combo{{priv: PrivDES}, {priv: PrivAES128}, {priv: PrivAES192}, {priv: PrivAES192, ext: KeyExtAlt}, {priv: PrivAES256}, {priv: PrivAES256, ext: KeyExtAlt}} {
			cs = append(cs, combo{a, p.priv, p.ext})
		}
	}
	return cs
}

func (c combo) user(name string) User {
	u := User{Name: name, Level: c.level(), Auth: c.auth, Priv: c.priv, KeyExt: c.ext}
	if c.auth != AuthNone {
		u.AuthPass = testAuthPass
	}
	if c.priv != PrivNone {
		u.PrivPass = testPrivPass
	}
	return u
}

func (c combo) security(t testing.TB, engineID []byte) Security {
	t.Helper()
	k, err := LocalizeKeys(c.auth, c.priv, c.ext, testAuthPass, testPrivPass, engineID)
	if err != nil {
		t.Fatal(err)
	}
	return Security{Auth: c.auth, Priv: c.priv, Keys: k}
}

// v3Msg encodes a v3 message from a sender with the combo's keys.
func v3Msg(t testing.TB, c combo, user string, h V3Header, pdu *PDU) []byte {
	t.Helper()
	h.Level, h.User = c.level(), []byte(user)
	if h.ContextEngineID == nil {
		h.ContextEngineID = h.EngineID
	}
	b, err := EncodeV3(h, c.security(t, h.EngineID), 99, EncodePDU(pdu))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestUSM(t testing.TB, users ...User) *USM {
	t.Helper()
	u := NewUSM(testEngine())
	if err := u.SetUsers(users); err != nil {
		t.Fatal(err)
	}
	return u
}
