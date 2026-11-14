package snmp

import (
	"errors"
	"fmt"
	"time"
)

// ReplyMaxSize is the msgMaxSize Woodshed advertises: the largest UDP payload
// over IPv4 (SPEC §11.2.2).
const ReplyMaxSize = 65507

// MaxReplyGrowth is how much larger than the inform its Response may be. The
// Response echoes the inform's request ID and varbinds byte for byte, so only
// the re-encoded v3 header fields (msgMaxSize, boots, time, lengths) and DES
// padding can add octets; a reply over the limit is refused, never sent.
const MaxReplyGrowth = 32

// V3Header is a v3 message's header fields, for EncodeV3.
type V3Header struct {
	MsgID      int64
	MaxSize    int64 // 0 means ReplyMaxSize
	Level      Level
	Reportable bool

	EngineID    []byte // msgAuthoritativeEngineID
	EngineBoots int64
	EngineTime  int64
	User        []byte

	ContextEngineID []byte
	ContextName     []byte
}

// Security is what EncodeV3 needs to authenticate and encrypt: the protocols
// and the keys localized to the header's EngineID.
type Security struct {
	Auth AuthProtocol
	Priv PrivProtocol
	Keys Keys
}

// EncodeV3 returns a v3 message carrying pdu (an encoded PDU, EncodePDU), at
// h.Level: authenticated with sec's auth key and, for authPriv, encrypted with
// its priv key. salt must change for every message encrypted with the same key
// (a counter).
func EncodeV3(h V3Header, sec Security, salt uint64, pdu []byte) ([]byte, error) {
	if h.Level < NoAuthNoPriv || h.Level > AuthPriv {
		return nil, errors.New("snmp: EncodeV3: no security level")
	}
	if h.Level >= AuthNoPriv && (sec.Auth == AuthNone || len(sec.Keys.Auth) == 0) {
		return nil, errors.New("snmp: EncodeV3: authentication needs an auth protocol and key")
	}
	if h.Level == AuthPriv && (sec.Priv == PrivNone || len(sec.Keys.Priv) < sec.Priv.KeyLen()) {
		return nil, errors.New("snmp: EncodeV3: privacy needs a priv protocol and key")
	}
	maxSize := h.MaxSize
	if maxSize == 0 {
		maxSize = ReplyMaxSize
	}
	flags := byte(0)
	switch h.Level {
	case AuthNoPriv:
		flags = flagAuth
	case AuthPriv:
		flags = flagAuth | flagPriv
	}
	if h.Reportable {
		flags |= flagReportable
	}

	var scoped []byte
	scoped = appendTLV(scoped, tagOctetString, h.ContextEngineID)
	scoped = appendTLV(scoped, tagOctetString, h.ContextName)
	scoped = append(scoped, pdu...)
	scoped = appendTLV(nil, tagSequence, scoped)

	var privParams, data []byte
	if h.Level == AuthPriv {
		ct, pp, err := encrypt(sec.Priv, sec.Keys.Priv, scoped, h.EngineBoots, h.EngineTime, salt)
		if err != nil {
			return nil, err
		}
		privParams = pp
		data = appendTLV(nil, tagOctetString, ct)
	} else {
		data = scoped
	}
	var authParams []byte
	if h.Level >= AuthNoPriv {
		authParams = make([]byte, sec.Auth.MACLen())
	}

	var gd []byte
	gd = appendInt(gd, tagInteger, h.MsgID)
	gd = appendInt(gd, tagInteger, maxSize)
	gd = appendTLV(gd, tagOctetString, []byte{flags})
	gd = appendInt(gd, tagInteger, 3)

	var sp []byte
	sp = appendTLV(sp, tagOctetString, h.EngineID)
	sp = appendInt(sp, tagInteger, h.EngineBoots)
	sp = appendInt(sp, tagInteger, h.EngineTime)
	sp = appendTLV(sp, tagOctetString, h.User)
	sp = appendTLV(sp, tagOctetString, authParams)
	sp = appendTLV(sp, tagOctetString, privParams)
	sp = appendTLV(nil, tagSequence, sp)

	var msg []byte
	msg = appendInt(msg, tagInteger, int64(V3))
	msg = appendTLV(msg, tagSequence, gd)
	msg = appendTLV(msg, tagOctetString, sp)
	msg = append(msg, data...)
	msg = appendTLV(nil, tagSequence, msg)

	if h.Level >= AuthNoPriv {
		// Find the auth parameters by decoding the header back; then sign.
		m := &Message{Raw: msg, Version: VersionUnknown}
		m.decode(nil, time.Time{})
		if !m.HeaderRead || len(m.authParams) != len(authParams) {
			return nil, errors.New("snmp: EncodeV3: the message doesn't decode")
		}
		copy(msg[m.authOff:], mac(sec.Auth, sec.Keys.Auth, msg, m.authOff))
	}
	return msg, nil
}

// Reply builds the datagram m calls for (m.Reply): the Response to an inform or
// a Report. It returns nil and no error when m calls for nothing. u may be nil
// for v1 and v2c.
//
// The Response echoes the inform's request ID and varbinds as received; for v3
// it's sent at the inform's level with Woodshed's boots and time. A Report is
// noAuthNoPriv (discovery, an unknown engine ID) or authNoPriv with the user's
// key (a time-window miss, RFC 3414 §3.2 step 7a), and carries the usmStats
// counter.
func (u *USM) Reply(m *Message, now time.Time) ([]byte, error) {
	switch m.Reply {
	case ReplyNone:
		return nil, nil
	case ReplyResponse:
		out, err := u.response(m, now)
		if err != nil {
			return nil, err
		}
		if len(out) > len(m.Raw)+MaxReplyGrowth {
			return nil, fmt.Errorf("snmp: the Response (%d bytes) would be larger than the inform (%d)", len(out), len(m.Raw))
		}
		return out, nil
	case ReplyReport:
		return u.report(m, now)
	}
	return nil, fmt.Errorf("snmp: unknown reply kind %d", m.Reply)
}

func (u *USM) response(m *Message, now time.Time) ([]byte, error) {
	p := m.PDU
	if p == nil || p.Type != PDUInform || p.rawRequestID == nil || p.rawVarbinds == nil {
		return nil, errors.New("snmp: no inform to answer")
	}
	var c []byte
	c = append(c, p.rawRequestID...)
	c = appendInt(c, tagInteger, 0)
	c = appendInt(c, tagInteger, 0)
	c = append(c, p.rawVarbinds...)
	pdu := appendTLV(nil, byte(PDUResponse), c)
	switch m.Version {
	case V2c:
		return EncodeCommunity(V2c, m.Community, pdu), nil
	case V3:
		if u == nil || m.user == nil {
			return nil, errors.New("snmp: a v3 Response needs USM and the user")
		}
		e := u.engine
		var sec Security
		if m.Level >= AuthNoPriv {
			keys, err := u.keysFor(m.user, e.ID, now)
			if err != nil {
				return nil, fmt.Errorf("snmp: Response: %w", err)
			}
			sec = Security{Auth: m.user.Auth, Priv: m.user.Priv, Keys: keys}
		}
		return EncodeV3(V3Header{
			MsgID: m.MsgID, Level: m.Level,
			EngineID: e.ID, EngineBoots: e.Boots, EngineTime: e.Time(now), User: m.User,
			ContextEngineID: m.ContextEngineID, ContextName: m.ContextName,
		}, sec, u.salt.Add(1), pdu)
	}
	return nil, fmt.Errorf("snmp: no Response for SNMPv%s", m.Version)
}

func (u *USM) report(m *Message, now time.Time) ([]byte, error) {
	if u == nil || m.Version != V3 || m.reportOID == nil {
		return nil, errors.New("snmp: no Report to build")
	}
	e := u.engine
	pdu := EncodePDU(&PDU{
		Type: PDUReport, RequestID: m.reportReqID,
		Varbinds: []Varbind{{OID: m.reportOID, Value: Value{Kind: KindCounter32, Uint: u.reportCount(m.reportOID) & 0xffffffff}}},
	})
	h := V3Header{
		MsgID: m.MsgID, Level: NoAuthNoPriv,
		EngineID: e.ID, EngineBoots: e.Boots, EngineTime: e.Time(now), User: m.User,
		ContextEngineID: e.ID,
	}
	var sec Security
	if m.reportAuth {
		if m.user == nil {
			return nil, errors.New("snmp: an authenticated Report needs the user")
		}
		keys, err := u.keysFor(m.user, e.ID, now)
		if err != nil {
			return nil, fmt.Errorf("snmp: Report: %w", err)
		}
		h.Level = AuthNoPriv
		sec = Security{Auth: m.user.Auth, Keys: keys}
	}
	return EncodeV3(h, sec, 0, pdu)
}
