package snmp

import (
	"bytes"
	"testing"
	"time"
)

// Requests captured from net-snmp 5.6's snmpget, snmpgetnext and snmpbulkget
// on this repo's development machine (community "testcomm", a test value;
// SPEC §12.8: encodings are checked byte for byte against captured packets).
// Each is re-encoded with the captured request ID (and for the v3 probe, the
// msgID) and must come out identical.
var capturedRequests = []struct {
	name    string
	version Version
	kind    RequestKind
	oids    []string
	reps    int
	hex     string
}{
	{"v1 get", V1, ReqGet, []string{"1.3.6.1.2.1.1.3.0"}, 0,
		"302b020100040874657374636f6d6da01c02040e140570020100020100300e300c06082b060102010103000500"},
	{"v1 getnext", V1, ReqGetNext, []string{"1.3.6.1.2.1.2.2.1.2"}, 0,
		"302c020100040874657374636f6d6da11d02046be7ff12020100020100300f300d06092b06010201020201020500"},
	{"v2c get", V2c, ReqGet, []string{"1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0"}, 0,
		"3039020101040874657374636f6d6da02a02044f4e6430020100020100301c300c06082b060102010103000500300c06082b060102010105000500"},
	{"v2c getnext", V2c, ReqGetNext, []string{"1.3.6.1.2.1.2.2.1.2"}, 0,
		"302c020101040874657374636f6d6da11d0204551868ba020100020100300f300d06092b06010201020201020500"},
	{"v2c getbulk", V2c, ReqGetBulk, []string{"1.3.6.1.2.1.31.1.1.1.1"}, 25,
		"302d020101040874657374636f6d6da51e02043f7a4b160201000201193010300e060a2b060102011f010101010500"},
}

const capturedDiscovery = "303e020103301102043e7c9acc020300ffe30401040201030410300e0400020100020100040004000400301404000400a00e02040c425f120201000201003000"

func TestRequestEncodingMatchesCaptures(t *testing.T) {
	for _, c := range capturedRequests {
		want := mustHex(t, c.hex)
		_, id, ok := PeekID(want)
		if !ok {
			t.Fatalf("%s: PeekID", c.name)
		}
		var oids []OID
		for _, s := range c.oids {
			o, err := ParseOID(s)
			if err != nil {
				t.Fatal(err)
			}
			oids = append(oids, o)
		}
		got, err := EncodeRequest(c.version, []byte("testcomm"), Request{Kind: c.kind, RequestID: int32(id), MaxRepetitions: c.reps, OIDs: oids})
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %x\nwant %x", c.name, got, want)
		}
	}
	want := mustHex(t, capturedDiscovery)
	_, msgID, _ := PeekID(want)
	m := Decode(want, nil, time.Time{})
	pdu, err := m.PlainPDU()
	if err != nil {
		t.Fatal(err)
	}
	got, err := EncodeDiscovery(int32(msgID), int32(pdu.RequestID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("discovery:\n got %x\nwant %x", got, want)
	}
}

// TestRequesterCantEncodeASet: the requester's only PDUs are Get, GetNext and
// GetBulk (SPEC §12.2: the poller never sends a SetRequest).
func TestRequesterCantEncodeASet(t *testing.T) {
	sent := map[PDUType]bool{}
	for k := RequestKind(0); k < 255; k++ {
		for _, v := range []Version{V1, V2c} {
			b, err := EncodeRequest(v, []byte("c"), Request{Kind: k, RequestID: 1, OIDs: []OID{OIDSysUpTime}})
			if err != nil {
				continue
			}
			sent[Decode(b, nil, time.Time{}).PDU.Type] = true
		}
		b, err := EncodeRequestV3(RequestV3{MsgID: 1, Level: NoAuthNoPriv, EngineID: []byte{0x80, 0, 0, 0, 1}}, Security{}, 0,
			Request{Kind: k, RequestID: 1, OIDs: []OID{OIDSysUpTime}})
		if err != nil {
			continue
		}
		p, err := Decode(b, nil, time.Time{}).PlainPDU()
		if err != nil {
			t.Fatal(err)
		}
		sent[p.Type] = true
	}
	for typ := range sent {
		if typ != PDUGet && typ != PDUGetNext && typ != PDUGetBulk {
			t.Errorf("the requester encoded a %s PDU", typ)
		}
	}
	if len(sent) != 3 {
		t.Errorf("encoded %v, want exactly get, getnext and getbulk", sent)
	}
	if _, err := EncodeRequest(V1, []byte("c"), Request{Kind: ReqGetBulk, OIDs: []OID{OIDSysUpTime}}); err == nil {
		t.Error("v1 GetBulk encoded")
	}
}

func TestPeekID(t *testing.T) {
	b, _ := EncodeRequest(V2c, []byte("c"), Request{Kind: ReqGet, RequestID: 0x1234567, OIDs: []OID{OIDSysUpTime}})
	if v, id, ok := PeekID(b); !ok || v != V2c || id != 0x1234567 {
		t.Errorf("v2c: %v %x %v", v, id, ok)
	}
	b, _ = EncodeDiscovery(77, 88)
	if v, id, ok := PeekID(b); !ok || v != V3 || id != 77 {
		t.Errorf("v3: %v %d %v", v, id, ok)
	}
	for _, bad := range [][]byte{nil, {0x30}, {0x30, 0x03, 0x02, 0x01, 0x07}, b[:10]} {
		if _, _, ok := PeekID(bad); ok {
			t.Errorf("PeekID(%x) ok", bad)
		}
	}
}

// response builds an agent's Response (v1/v2c) for decoding tests.
func response(v Version, reqID int64, es, ei int64, vbs []Varbind) []byte {
	return EncodeCommunity(v, []byte("c"), EncodePDU(&PDU{Type: PDUResponse, RequestID: reqID, ErrorStatus: es, ErrorIndex: ei, Varbinds: vbs}))
}

func TestDecodeResponseValueTypes(t *testing.T) {
	vbs := []Varbind{
		{OID: OID{1, 3, 6, 1, 1}, Value: Value{Kind: KindInteger, Int: -5}},
		{OID: OID{1, 3, 6, 1, 2}, Value: Value{Kind: KindOctetString, Bytes: []byte("eth0")}},
		{OID: OID{1, 3, 6, 1, 3}, Value: Value{Kind: KindNull}},
		{OID: OID{1, 3, 6, 1, 4}, Value: Value{Kind: KindOID, OID: OID{1, 3, 6, 1, 4, 1, 32473}}},
		{OID: OID{1, 3, 6, 1, 5}, Value: Value{Kind: KindIPAddress, Bytes: []byte{192, 0, 2, 1}}},
		{OID: OID{1, 3, 6, 1, 6}, Value: Value{Kind: KindCounter32, Uint: 0xffffffff}},
		{OID: OID{1, 3, 6, 1, 7}, Value: Value{Kind: KindGauge32, Uint: 1000}},
		{OID: OID{1, 3, 6, 1, 8}, Value: Value{Kind: KindTimeTicks, Uint: 123456}},
		{OID: OID{1, 3, 6, 1, 9}, Value: Value{Kind: KindOpaque, Bytes: []byte{1, 2}}},
		{OID: OID{1, 3, 6, 1, 10}, Value: Value{Kind: KindCounter64, Uint: 1<<64 - 1}},
		{OID: OID{1, 3, 6, 1, 11}, Value: Value{Kind: KindNoSuchObject}},
		{OID: OID{1, 3, 6, 1, 12}, Value: Value{Kind: KindNoSuchInstance}},
		{OID: OID{1, 3, 6, 1, 13}, Value: Value{Kind: KindEndOfMibView}},
	}
	m := DecodeResponse(response(V2c, 9, 0, 0, vbs), nil)
	if m.Status != StatusOK || m.PDU.Type != PDUResponse || m.PDU.RequestID != 9 {
		t.Fatalf("%v %s %+v", m.Status, m.Err, m.PDU)
	}
	for i, vb := range m.PDU.Varbinds {
		if vb.Value.Kind != vbs[i].Value.Kind || vb.Value.Uint != vbs[i].Value.Uint || vb.Value.Int != vbs[i].Value.Int ||
			!bytes.Equal(vb.Value.Bytes, vbs[i].Value.Bytes) {
			t.Errorf("varbind %d: %+v, want %+v", i, vb.Value, vbs[i].Value)
		}
	}
	// Every error status decodes and is named.
	for es := int64(0); es <= 18; es++ {
		m := DecodeResponse(response(V2c, 1, es, 1, nil), nil)
		if m.Status != StatusOK || m.PDU.ErrorStatus != es {
			t.Errorf("error status %d: %v", es, m.Status)
		}
		if ErrorStatusName(es) == "" {
			t.Errorf("no name for %d", es)
		}
	}
	// A trap or a request isn't a reply.
	for _, typ := range []PDUType{PDUTrap, PDUInform, PDUGet, PDUSet, PDUReport} {
		m := DecodeResponse(v2cMsg("c", typ, 1, nil), nil)
		if m.Status == StatusOK {
			t.Errorf("v2c %s accepted as a reply", typ)
		}
	}
}

// v3Reply builds an agent's v3 reply (Response or Report) at a level.
func v3Reply(t *testing.T, typ PDUType, lvl Level, sec Security, engine []byte, boots, etime int64, msgID, reqID int64, vbs []Varbind) []byte {
	t.Helper()
	b, err := EncodeV3(V3Header{MsgID: msgID, Level: lvl, EngineID: engine, EngineBoots: boots, EngineTime: etime, User: []byte("monitor"),
		ContextEngineID: engine}, sec, 7, EncodePDU(&PDU{Type: typ, RequestID: reqID, Varbinds: vbs}))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDecodeResponseV3(t *testing.T) {
	engine := mustHex(t, "80001f8880a1b2c3d4e5f60708")
	for _, c := range []struct {
		a AuthProtocol
		p PrivProtocol
	}{{AuthNone, PrivNone}, {AuthMD5, PrivNone}, {AuthSHA1, PrivDES}, {AuthSHA256, PrivAES128}, {AuthSHA512, PrivAES256}} {
		lvl := NoAuthNoPriv
		if c.a != AuthNone {
			lvl = AuthNoPriv
		}
		if c.p != PrivNone {
			lvl = AuthPriv
		}
		var sec Security
		if lvl > NoAuthNoPriv {
			k, err := LocalizeKeys(c.a, c.p, KeyExtDraft, testAuthPass, testPrivPass, engine)
			if err != nil {
				t.Fatal(err)
			}
			sec = Security{Auth: c.a, Priv: c.p, Keys: k}
		}
		raw := v3Reply(t, PDUResponse, lvl, sec, engine, 3, 1000, 42, 43, []Varbind{{OID: OIDSysUpTime, Value: ticks(5)}})
		keys := func(e []byte) (Security, bool) { return sec, bytes.Equal(e, engine) }
		m := DecodeResponse(raw, keys)
		if m.Status != StatusOK || m.PDU.RequestID != 43 || m.MsgID != 42 || m.EngineBoots != 3 || m.EngineTime != 1000 {
			t.Errorf("%s/%s: %v %s", c.a, c.p, m.Status, m.Err)
		}
		if lvl > NoAuthNoPriv {
			// Another engine's keys: unknown_engine; a flipped byte: auth_failed.
			if m := DecodeResponse(raw, func([]byte) (Security, bool) { return Security{}, false }); m.Status != StatusUnknownEngine {
				t.Errorf("%s/%s no keys: %v", c.a, c.p, m.Status)
			}
			bad := bytes.Clone(raw)
			bad[len(bad)-1] ^= 1
			if m := DecodeResponse(bad, keys); m.Status != StatusAuthFailed {
				t.Errorf("%s/%s tampered: %v %s", c.a, c.p, m.Status, m.Err)
			}
		}
	}
}
