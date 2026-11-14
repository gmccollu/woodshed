package snmp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// The requester side (SPEC §12.2): what the poller sends and reads. It can
// encode exactly three PDUs, GetRequest, GetNextRequest and GetBulkRequest
// (RequestKind has no other value, and encodeRequestPDU refuses anything
// else), and it reads only Response and, for v3, Report. There is no way to
// build a SetRequest here; the poller uses only this file's API (a test in
// internal/poller checks that it can't reach EncodePDU or EncodeV3).

// RequestKind is a PDU the requester sends.
type RequestKind uint8

// The requests. v1 has no GetBulk.
const (
	ReqGet RequestKind = iota + 1
	ReqGetNext
	ReqGetBulk
)

func (k RequestKind) String() string {
	switch k {
	case ReqGet:
		return "get"
	case ReqGetNext:
		return "getnext"
	case ReqGetBulk:
		return "getbulk"
	}
	return fmt.Sprintf("request(%d)", uint8(k))
}

// pduType is the request's PDU tag, or false for a value that isn't one of
// the three requests.
func (k RequestKind) pduType() (PDUType, bool) {
	switch k {
	case ReqGet:
		return PDUGet, true
	case ReqGetNext:
		return PDUGetNext, true
	case ReqGetBulk:
		return PDUGetBulk, true
	}
	return 0, false
}

// Request is one request PDU.
type Request struct {
	Kind      RequestKind
	RequestID int32
	// NonRepeaters and MaxRepetitions are GetBulk's (RFC 3416 §4.2.3).
	NonRepeaters, MaxRepetitions int
	OIDs                         []OID
}

// Request limits (SPEC §12.2).
const (
	MaxRequestVarbinds = 32 // at most 32 varbinds per Get
	BulkRepetitions    = 25 // GetBulk's max-repetitions for walks
	RequestMaxSize     = ReplyMaxSize
)

// ErrNotARequest is the error for a PDU kind the requester can't send.
var ErrNotARequest = errors.New("snmp: only GetRequest, GetNextRequest and GetBulkRequest can be sent")

// encodeRequestPDU is the request's PDU. Every value it sends has a Null value
// (RFC 3416 §4.2.1).
func encodeRequestPDU(v Version, r Request) ([]byte, error) {
	t, ok := r.Kind.pduType()
	if !ok {
		return nil, ErrNotARequest
	}
	if t == PDUGetBulk && v == V1 {
		return nil, errors.New("snmp: SNMPv1 has no GetBulk")
	}
	if len(r.OIDs) > 2*MaxRequestVarbinds {
		return nil, fmt.Errorf("snmp: %d varbinds in one request (at most %d)", len(r.OIDs), 2*MaxRequestVarbinds)
	}
	vbs := make([]Varbind, len(r.OIDs))
	for i, o := range r.OIDs {
		if len(o) < 2 || len(o) > MaxOIDLen {
			return nil, fmt.Errorf("snmp: OID %s can't be requested", o)
		}
		vbs[i] = Varbind{OID: o, Value: Value{Kind: KindNull}}
	}
	p := &PDU{Type: t, RequestID: int64(r.RequestID), Varbinds: vbs}
	if t == PDUGetBulk {
		p.ErrorStatus, p.ErrorIndex = int64(r.NonRepeaters), int64(r.MaxRepetitions)
	}
	return EncodePDU(p), nil
}

// EncodeRequest returns a v1 or v2c request message.
func EncodeRequest(v Version, community []byte, r Request) ([]byte, error) {
	if v != V1 && v != V2c {
		return nil, fmt.Errorf("snmp: EncodeRequest: version %s isn't v1 or v2c", v)
	}
	pdu, err := encodeRequestPDU(v, r)
	if err != nil {
		return nil, err
	}
	return EncodeCommunity(v, community, pdu), nil
}

// RequestV3 is a v3 request's header: the agent is authoritative, so the
// engine ID, boots and time are the agent's as the requester knows them.
type RequestV3 struct {
	MsgID       int32
	Level       Level
	EngineID    []byte
	EngineBoots int64
	EngineTime  int64
	User        []byte
	ContextName []byte
}

// EncodeRequestV3 returns a v3 request, reportable, with the context engine
// ID set to the agent's. salt must change for every encrypted message.
func EncodeRequestV3(h RequestV3, sec Security, salt uint64, r Request) ([]byte, error) {
	pdu, err := encodeRequestPDU(V3, r)
	if err != nil {
		return nil, err
	}
	return EncodeV3(V3Header{
		MsgID: int64(h.MsgID), MaxSize: RequestMaxSize, Level: h.Level, Reportable: true,
		EngineID: h.EngineID, EngineBoots: h.EngineBoots, EngineTime: h.EngineTime, User: h.User,
		ContextEngineID: h.EngineID, ContextName: h.ContextName,
	}, sec, salt, pdu)
}

// EncodeDiscovery returns RFC 3414 §4's discovery probe: a reportable
// noAuthNoPriv Get with an empty engine ID and user and no varbinds.
func EncodeDiscovery(msgID, requestID int32) ([]byte, error) {
	return EncodeRequestV3(RequestV3{MsgID: msgID, Level: NoAuthNoPriv}, Security{}, 0, Request{Kind: ReqGet, RequestID: requestID})
}

// RandomID is a random 31-bit request ID or msgID (never 0).
func RandomID() int32 { return randomID() }

// randomID is RandomID's source (tests make it deterministic).
var randomID = cryptoRandomID

func cryptoRandomID() int32 {
	var b [4]byte
	for {
		_, _ = rand.Read(b[:])
		if v := int32(binary.BigEndian.Uint32(b[:]) & 0x7fffffff); v != 0 {
			return v
		}
	}
}

// PeekID reads the ID a reply is matched by without any keys: a v1 or v2c
// message's PDU request ID, or a v3 message's msgID.
func PeekID(raw []byte) (Version, int64, bool) {
	outer, _, err := readTLV(raw, 0)
	if err != nil || outer.tag != tagSequence {
		return VersionUnknown, 0, false
	}
	vt, b, err := readExpect(outer.content, outer.coff, tagInteger, "")
	if err != nil {
		return VersionUnknown, 0, false
	}
	v, err := parseInt(vt)
	if err != nil {
		return VersionUnknown, 0, false
	}
	switch Version(v) {
	case V1, V2c:
		ct, b, err := readExpect(b, vt.end(), tagOctetString, "")
		if err != nil {
			return VersionUnknown, 0, false
		}
		pt, _, err := readTLV(b, ct.end())
		if err != nil || !isPDUTag(pt.tag) {
			return VersionUnknown, 0, false
		}
		it, _, err := readExpect(pt.content, pt.coff, tagInteger, "")
		if err != nil {
			return VersionUnknown, 0, false
		}
		id, err := parseInt(it)
		return Version(v), id, err == nil
	case V3:
		gd, _, err := readExpect(b, vt.end(), tagSequence, "")
		if err != nil {
			return VersionUnknown, 0, false
		}
		it, _, err := readExpect(gd.content, gd.coff, tagInteger, "")
		if err != nil {
			return VersionUnknown, 0, false
		}
		id, err := parseInt(it)
		return V3, id, err == nil
	}
	return VersionUnknown, 0, false
}

// DecodeResponse decodes a datagram as the reply to a request: a Response, or
// for v3 a Report. keys returns the security for the agent engine ID the
// message names (false: none, so an authenticated message is unknown_engine).
// keys may be nil for v1, v2c and noAuthNoPriv v3. Like Decode it never
// returns nil; a datagram that isn't a reply has a status other than ok.
//
// A v3 message is authenticated with the keys before anything in its scoped
// PDU is read, and decrypted for authPriv; its boots and time are the agent's.
func DecodeResponse(raw []byte, keys func(engineID []byte) (Security, bool)) *Message {
	m := &Message{Raw: raw, Version: VersionUnknown, mode: modeRequester, reqKeys: keys}
	m.decode(nil, time.Time{})
	return m
}

// processResponse authenticates and decrypts a v3 reply (the requester is
// the non-authoritative side; RFC 3414 §3.2 without the local timeliness
// check, which the session makes against its own record of the agent's
// clock).
func (m *Message) processResponse() {
	if m.Level == NoAuthNoPriv {
		m.decodeScoped(m.Raw[m.data.off:m.data.end()], m.data.off, StatusMalformed, "")
		return
	}
	var sec Security
	ok := false
	if m.reqKeys != nil {
		sec, ok = m.reqKeys(m.EngineID)
	}
	if !ok {
		m.fail(StatusUnknownEngine, "no keys for engine %x", m.EngineID)
		return
	}
	if sec.Auth == AuthNone || len(sec.Keys.Auth) == 0 {
		m.fail(StatusLevel, "an authenticated reply, but the user has no authentication key")
		return
	}
	if n := sec.Auth.MACLen(); len(m.authParams) != n {
		m.fail(StatusAuthFailed, "authentication parameters are %d bytes; %s uses %d", len(m.authParams), sec.Auth, n)
		return
	}
	if !checkMAC(sec.Auth, sec.Keys.Auth, m.whole, m.authOff, m.authParams) {
		m.fail(StatusAuthFailed, "wrong digest (%s)", sec.Auth)
		return
	}
	if m.Level == AuthNoPriv {
		m.decodeScoped(m.Raw[m.data.off:m.data.end()], m.data.off, StatusMalformed, "")
		return
	}
	if sec.Priv == PrivNone || len(sec.Keys.Priv) < sec.Priv.KeyLen() {
		m.fail(StatusLevel, "an encrypted reply, but the user has no privacy key")
		return
	}
	plain, err := decrypt(sec.Priv, sec.Keys.Priv, m.privParams, m.data.content, m.EngineBoots, m.EngineTime)
	if err != nil {
		m.fail(StatusDecryptFailed, "%v", err)
		return
	}
	m.decodeScoped(plain, 0, StatusDecryptFailed, "the decrypted reply doesn't decode (a wrong privacy passphrase, protocol or key extension?): ")
}

// The usmStats counters a Report can carry (RFC 3414 §5), and what each means
// for the requester.
var (
	OIDUsmStatsUnsupportedSecLevels = OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0}
	OIDUsmStatsNotInTimeWindows     = oidNotInTimeWindows
	OIDUsmStatsUnknownUserNames     = OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0}
	OIDUsmStatsUnknownEngineIDs     = oidUnknownEngineIDs
	OIDUsmStatsWrongDigests         = OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0}
	OIDUsmStatsDecryptionErrors     = OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0}
)

// ErrorStatusName is RFC 3416's name for a PDU error-status.
func ErrorStatusName(s int64) string {
	names := []string{"noError", "tooBig", "noSuchName", "badValue", "readOnly", "genErr", "noAccess", "wrongType",
		"wrongLength", "wrongEncoding", "wrongValue", "noCreation", "inconsistentValue", "resourceUnavailable",
		"commitFailed", "undoFailed", "authorizationError", "notWritable", "inconsistentName"}
	if s >= 0 && int(s) < len(names) {
		return names[s]
	}
	return fmt.Sprintf("error %d", s)
}

// Error statuses the requester acts on.
const (
	ErrStatusTooBig     = 1
	ErrStatusNoSuchName = 2
)

// ResponseTo builds the Response to a request m that a test agent decoded
// (DecodeRequest), at m's version, community or level, with the agent's
// engine. It's the agent side, for internal/snmp/agenttest; the requester
// never sends a Response.
func (u *USM) ResponseTo(m *Message, vbs []Varbind, errStatus, errIndex int64, now time.Time) ([]byte, error) {
	if m.PDU == nil || m.mode != modeAgent {
		return nil, errors.New("snmp: ResponseTo: not a decoded request")
	}
	pdu := EncodePDU(&PDU{Type: PDUResponse, RequestID: m.PDU.RequestID, ErrorStatus: errStatus, ErrorIndex: errIndex, Varbinds: vbs})
	switch m.Version {
	case V1, V2c:
		return EncodeCommunity(m.Version, m.Community, pdu), nil
	case V3:
		if u == nil {
			return nil, errors.New("snmp: a v3 Response needs USM")
		}
		e := u.engine
		var sec Security
		if m.Level >= AuthNoPriv {
			if m.user == nil {
				return nil, errors.New("snmp: an authenticated Response needs the user")
			}
			keys, err := u.keysFor(m.user, e.ID, now)
			if err != nil {
				return nil, fmt.Errorf("snmp: Response: %w", err)
			}
			sec = Security{Auth: m.user.Auth, Priv: m.user.Priv, Keys: keys}
		}
		return EncodeV3(V3Header{
			MsgID: m.MsgID, Level: m.Level,
			EngineID: e.ID, EngineBoots: e.Boots, EngineTime: e.Time(now), User: m.User,
			ContextEngineID: e.ID, ContextName: m.ContextName,
		}, sec, u.salt.Add(1), pdu)
	}
	return nil, fmt.Errorf("snmp: no Response for SNMPv%s", m.Version)
}

// DecodeRequest decodes a datagram as a request to a test agent: v1 and v2c
// Get and GetNext, v2c and v3 GetBulk, and v3 through u as the authoritative
// engine (discovery and time-window Reports as for informs, USM.Reply). For
// internal/snmp/agenttest.
func DecodeRequest(raw []byte, u *USM, now time.Time) *Message {
	m := &Message{Raw: raw, Version: VersionUnknown, mode: modeAgent}
	m.decode(u, now)
	return m
}

// reportOID is the usmStats counter a Report carries (its first varbind).
func (p *PDU) reportOID() OID {
	if p == nil || p.Type != PDUReport || len(p.Varbinds) == 0 {
		return nil
	}
	return p.Varbinds[0].OID
}

// equalBytes is bytes.Equal (kept here so session.go reads plainly).
func equalBytes(a, b []byte) bool { return bytes.Equal(a, b) }

// FailureReport builds the noAuthNoPriv Report a real agent sends for a v3
// request USM refused (RFC 3414 §3.2: an unknown user, a wrong digest, a
// decryption error, an unsupported level), for internal/snmp/agenttest. It
// returns nil for a status that has no Report or a request that isn't
// reportable.
func (u *USM) FailureReport(m *Message, now time.Time) ([]byte, error) {
	if u == nil || m.Version != V3 || !m.HeaderRead || !m.Reportable || m.mode != modeAgent {
		return nil, nil
	}
	var oid OID
	switch m.Status {
	case StatusUnknownUser:
		oid = OIDUsmStatsUnknownUserNames
	case StatusAuthFailed:
		oid = OIDUsmStatsWrongDigests
	case StatusDecryptFailed:
		oid = OIDUsmStatsDecryptionErrors
	case StatusLevel:
		oid = OIDUsmStatsUnsupportedSecLevels
	default:
		return nil, nil
	}
	reqID := int64(0)
	if m.Level == NoAuthNoPriv && m.data.content != nil {
		reqID, _ = peekRequestID(m.Raw[m.data.off:m.data.end()])
	}
	e := u.engine
	pdu := EncodePDU(&PDU{Type: PDUReport, RequestID: reqID, Varbinds: []Varbind{{OID: oid, Value: Value{Kind: KindCounter32, Uint: 1}}}})
	return EncodeV3(V3Header{MsgID: m.MsgID, Level: NoAuthNoPriv, EngineID: e.ID, EngineBoots: e.Boots, EngineTime: e.Time(now),
		User: m.User, ContextEngineID: e.ID}, Security{}, 0, pdu)
}
