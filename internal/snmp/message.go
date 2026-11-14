package snmp

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
	"unicode"
	"unicode/utf8"
)

// Status is a received message's verdict, stored as the record's status= (SPEC
// §11.2.2). Every status but StatusOK carries an error text in Message.Err.
type Status uint8

// Statuses.
const (
	StatusOK            Status = iota
	StatusMalformed            // the BER doesn't decode, a wrong version, a truncated header
	StatusUnexpectedPDU        // a Get, Set, Response, Report, GetBulk, or a PDU the version doesn't allow
	StatusUnknownUser          // v3: no such user
	StatusUnknownEngine        // v3: an inform to another engine ID, or no keys for the sender's engine
	StatusNotInTime            // v3: outside the 150 s window
	StatusAuthFailed           // v3: wrong digest
	StatusDecryptFailed        // v3: the decrypted bytes don't decode
	StatusLevel                // v3: below the user's level, or above what the user has keys for
)

var statusNames = [...]string{"ok", "malformed", "unexpected_pdu", "unknown_user", "unknown_engine", "not_in_time", "auth_failed", "decrypt_failed", "level"}

func (s Status) String() string {
	if int(s) < len(statusNames) {
		return statusNames[s]
	}
	return fmt.Sprintf("status(%d)", s)
}

// Statuses returns every status name, in order.
func Statuses() []string { return append([]string(nil), statusNames[:]...) }

// ParseStatus returns the status with that name.
func ParseStatus(s string) (Status, bool) {
	for i, n := range statusNames {
		if n == s {
			return Status(i), true
		}
	}
	return 0, false
}

// Level is a v3 security level.
type Level uint8

// Security levels. The zero Level is "not set".
const (
	NoAuthNoPriv Level = iota + 1
	AuthNoPriv
	AuthPriv
)

func (l Level) String() string {
	switch l {
	case NoAuthNoPriv:
		return "noAuthNoPriv"
	case AuthNoPriv:
		return "authNoPriv"
	case AuthPriv:
		return "authPriv"
	}
	return ""
}

// ParseLevel parses noAuthNoPriv, authNoPriv or authPriv (any case).
func ParseLevel(s string) (Level, error) {
	for _, l := range []Level{NoAuthNoPriv, AuthNoPriv, AuthPriv} {
		if equalFold(s, l.String()) {
			return l, nil
		}
	}
	return 0, fmt.Errorf("snmp: unknown security level %q (noAuthNoPriv, authNoPriv or authPriv)", s)
}

// v3 msgFlags bits.
const (
	flagAuth       = 0x01
	flagPriv       = 0x02
	flagReportable = 0x04
)

// ReplyKind is what a received message calls for.
type ReplyKind uint8

// Replies. The listener sends them (subject to answer_informs, admission and the
// rate limits); USM.Reply builds them.
const (
	ReplyNone     ReplyKind = iota
	ReplyResponse           // an inform that decoded: the Response
	ReplyReport             // a v3 discovery, an unknown engine ID or a time-window miss: a Report
)

// Message is a received datagram, decoded as far as it goes.
type Message struct {
	// Raw is the datagram as received. Decode keeps it (no copy), and the record's
	// raw= is built from it.
	Raw []byte

	Version Version
	Status  Status
	Err     string // why, when Status isn't StatusOK

	// v1 and v2c.
	Community    []byte // nil until read
	communityOff int    // offset of the community's content octets in Raw

	// v3: the header (msgGlobalData and the USM security parameters). HeaderRead
	// is set once they decoded.
	HeaderRead      bool
	MsgID           int64
	MaxSize         int64
	Flags           byte
	SecurityModel   int64
	Level           Level
	Reportable      bool
	EngineID        []byte // msgAuthoritativeEngineID
	EngineBoots     int64
	EngineTime      int64
	User            []byte
	ContextEngineID []byte // set once the scoped PDU is readable
	ContextName     []byte

	// PDU is the decoded PDU: for v1 and v2c, and for v3 only once USM accepted
	// the message (a failure keeps only what's readable without the keys). For a
	// malformed PDU it holds what decoded (the type and request ID) and no
	// varbinds.
	PDU *PDU

	// Discovery is set for a v3 discovery probe (an empty engine ID, reportable):
	// it's answered with a Report and isn't a notification, so it isn't stored.
	Discovery bool

	// Reply is what the message calls for.
	Reply ReplyKind

	// v3 internals for USM and the reply.
	whole       []byte // the message SEQUENCE (the HMAC covers it)
	authOff     int    // offset of msgAuthenticationParameters' content in whole
	authParams  []byte
	privParams  []byte
	data        tlv   // msgData: the plaintext scoped PDU or the encrypted OCTET STRING
	reportOID   OID   // the usmStats counter a Report carries
	reportAuth  bool  // the Report is authenticated (notInTimeWindows)
	reportReqID int64 // the request ID for a Report, when readable
	user        *userState
}

func (m *Message) fail(s Status, format string, args ...any) {
	m.Status = s
	m.Err = fmt.Sprintf(format, args...)
}

// Decode decodes a received datagram. It never returns nil: a datagram that
// doesn't decode is a Message with StatusMalformed. v3 messages go through u
// (USM: users, keys, timeliness and the local engine); with a nil u every v3
// message but a discovery probe is unknown_user. now is the receive time.
//
// The Message keeps raw (and slices of it); the caller must not reuse it.
func Decode(raw []byte, u *USM, now time.Time) *Message {
	m := &Message{Raw: raw, Version: VersionUnknown}
	m.decode(u, now)
	return m
}

func (m *Message) decode(u *USM, now time.Time) {
	outer, _, err := readTLV(m.Raw, 0)
	if err != nil {
		m.fail(StatusMalformed, "not an SNMP message: %v", err)
		return
	}
	if outer.tag != tagSequence {
		m.fail(StatusMalformed, "not an SNMP message (tag 0x%02x, want a SEQUENCE)", outer.tag)
		return
	}
	b := outer.content
	vt, b, err := readExpect(b, outer.coff, tagInteger, "version")
	if err != nil {
		m.fail(StatusMalformed, "%v", err)
		return
	}
	v, err := parseInt(vt)
	if err != nil {
		m.fail(StatusMalformed, "version: %v", err)
		return
	}
	switch Version(v) {
	case V1, V2c:
		m.Version = Version(v)
		m.decodeCommunity(b, vt.end())
	case V3:
		m.Version = V3
		m.whole = m.Raw[outer.off:outer.end()]
		m.decodeV3(b, vt.end(), u, now)
	default:
		m.fail(StatusMalformed, "unsupported SNMP version %d", v)
	}
}

func (m *Message) decodeCommunity(b []byte, off int) {
	ct, b, err := readExpect(b, off, tagOctetString, "community")
	if err != nil {
		m.fail(StatusMalformed, "%v", err)
		return
	}
	m.Community, m.communityOff = ct.content, ct.coff
	pt, _, err := readTLV(b, ct.end())
	if err != nil {
		m.fail(StatusMalformed, "PDU: %v", err)
		return
	}
	if !isPDUTag(pt.tag) {
		m.fail(StatusMalformed, "want a PDU, got tag 0x%02x at byte %d", pt.tag, pt.off)
		return
	}
	m.setPDU(pt, StatusMalformed, "")
}

// setPDU decodes the PDU and sets the status: ok for the PDUs the version
// allows as notifications, unexpected_pdu for the rest; a PDU that doesn't decode
// is failStatus (malformed, or decrypt_failed after decryption) with prefix.
func (m *Message) setPDU(pt tlv, failStatus Status, prefix string) {
	p, err := parsePDU(pt)
	m.PDU = p
	allowed := (m.Version == V1 && p.Type == PDUV1Trap) ||
		(m.Version != V1 && (p.Type == PDUTrap || p.Type == PDUInform))
	switch {
	case !allowed:
		// Never answered; its contents are kept as far as they decode.
		m.fail(StatusUnexpectedPDU, "%s PDUs aren't accepted in SNMPv%s (only %s)", p.Type, m.Version, allowedPDUs(m.Version))
		if err != nil {
			m.Err += "; " + err.Error()
			p.Varbinds = nil
		}
	case err != nil:
		p.Varbinds = nil
		m.fail(failStatus, "%s%v", prefix, err)
		if failStatus == StatusDecryptFailed {
			m.PDU = nil // never keep decrypted guesses
		}
	default:
		m.Status, m.Err = StatusOK, ""
		if p.Type == PDUInform {
			m.Reply = ReplyResponse
		}
	}
}

func allowedPDUs(v Version) string {
	if v == V1 {
		return "Trap-PDUs"
	}
	return "SNMPv2-Trap and InformRequest"
}

// decodeV3 reads the v3 header and hands the message to USM.
func (m *Message) decodeV3(b []byte, off int, u *USM, now time.Time) {
	gd, b, err := readExpect(b, off, tagSequence, "msgGlobalData")
	if err != nil {
		m.fail(StatusMalformed, "%v", err)
		return
	}
	g, goff := gd.content, gd.coff
	var f tlv
	read := func(tag byte, what string) bool {
		f, g, err = readExpect(g, goff, tag, what)
		if err != nil {
			m.fail(StatusMalformed, "%v", err)
			return false
		}
		goff = f.end()
		return true
	}
	if !read(tagInteger, "msgID") {
		return
	}
	if m.MsgID, err = parseInt(f); err != nil {
		m.fail(StatusMalformed, "msgID: %v", err)
		return
	}
	if !read(tagInteger, "msgMaxSize") {
		return
	}
	if m.MaxSize, err = parseInt(f); err != nil {
		m.fail(StatusMalformed, "msgMaxSize: %v", err)
		return
	}
	if !read(tagOctetString, "msgFlags") {
		return
	}
	if len(f.content) == 0 {
		m.fail(StatusMalformed, "msgFlags is empty")
		return
	}
	m.Flags = f.content[0]
	if !read(tagInteger, "msgSecurityModel") {
		return
	}
	if m.SecurityModel, err = parseInt(f); err != nil {
		m.fail(StatusMalformed, "msgSecurityModel: %v", err)
		return
	}
	switch m.Flags & (flagAuth | flagPriv) {
	case 0:
		m.Level = NoAuthNoPriv
	case flagAuth:
		m.Level = AuthNoPriv
	case flagAuth | flagPriv:
		m.Level = AuthPriv
	default:
		m.fail(StatusMalformed, "msgFlags 0x%02x asks for privacy without authentication", m.Flags)
		return
	}
	m.Reportable = m.Flags&flagReportable != 0
	if m.SecurityModel != 3 {
		m.fail(StatusMalformed, "security model %d isn't USM (3)", m.SecurityModel)
		return
	}

	spo, b, err := readExpect(b, gd.end(), tagOctetString, "msgSecurityParameters")
	if err != nil {
		m.fail(StatusMalformed, "%v", err)
		return
	}
	sp, _, err := readExpect(spo.content, spo.coff, tagSequence, "msgSecurityParameters")
	if err != nil {
		m.fail(StatusMalformed, "%v", err)
		return
	}
	g, goff = sp.content, sp.coff
	if !read(tagOctetString, "msgAuthoritativeEngineID") {
		return
	}
	m.EngineID = f.content
	if !read(tagInteger, "msgAuthoritativeEngineBoots") {
		return
	}
	if m.EngineBoots, err = parseInt(f); err != nil {
		m.fail(StatusMalformed, "msgAuthoritativeEngineBoots: %v", err)
		return
	}
	if !read(tagInteger, "msgAuthoritativeEngineTime") {
		return
	}
	if m.EngineTime, err = parseInt(f); err != nil {
		m.fail(StatusMalformed, "msgAuthoritativeEngineTime: %v", err)
		return
	}
	if !read(tagOctetString, "msgUserName") {
		return
	}
	m.User = f.content
	if !read(tagOctetString, "msgAuthenticationParameters") {
		return
	}
	m.authParams, m.authOff = f.content, f.coff // whole starts at byte 0
	if !read(tagOctetString, "msgPrivacyParameters") {
		return
	}
	m.privParams = f.content
	m.HeaderRead = true

	m.data, _, err = readTLV(b, spo.end())
	if err != nil {
		m.fail(StatusMalformed, "msgData: %v", err)
		return
	}
	if m.Level == AuthPriv {
		if m.data.tag != tagOctetString {
			m.fail(StatusMalformed, "msgData: an encrypted message needs an OCTET STRING, got tag 0x%02x", m.data.tag)
			return
		}
	} else if m.data.tag != tagSequence {
		m.fail(StatusMalformed, "msgData: want a scoped PDU (SEQUENCE), got tag 0x%02x", m.data.tag)
		return
	}
	u.process(m, now)
}

// decodeScoped decodes a scoped PDU (plaintext, or decrypted). off is the
// offset of b in the datagram (0 for decrypted data). failStatus is the status
// when it doesn't decode.
func (m *Message) decodeScoped(b []byte, off int, failStatus Status, prefix string) {
	sp, _, err := readExpect(b, off, tagSequence, "scoped PDU")
	if err != nil {
		m.fail(failStatus, "%s%v", prefix, err)
		return
	}
	s, soff := sp.content, sp.coff
	ce, s, err := readExpect(s, soff, tagOctetString, "contextEngineID")
	if err != nil {
		m.fail(failStatus, "%s%v", prefix, err)
		return
	}
	cn, s, err := readExpect(s, ce.end(), tagOctetString, "contextName")
	if err != nil {
		m.fail(failStatus, "%s%v", prefix, err)
		return
	}
	pt, _, err := readTLV(s, cn.end())
	if err != nil {
		m.fail(failStatus, "%sPDU: %v", prefix, err)
		return
	}
	if !isPDUTag(pt.tag) {
		m.fail(failStatus, "%swant a PDU, got tag 0x%02x at byte %d", prefix, pt.tag, pt.off)
		return
	}
	m.ContextEngineID, m.ContextName = ce.content, cn.content
	m.setPDU(pt, failStatus, prefix)
	if m.Status == failStatus {
		m.ContextEngineID, m.ContextName = nil, nil
		if failStatus == StatusDecryptFailed {
			m.PDU = nil
		}
	}
}

// PlainPDU decodes the scoped PDU of a noAuthNoPriv v3 message without any USM
// check, for a sender reading a discovery Report (whose user is empty), and sets
// the context fields. The receiver never uses it: Decode applies USM.
func (m *Message) PlainPDU() (*PDU, error) {
	if m.Version != V3 || !m.HeaderRead || m.Level != NoAuthNoPriv {
		return nil, fmt.Errorf("snmp: not a readable noAuthNoPriv v3 message")
	}
	c := &Message{Raw: m.Raw, Version: V3}
	c.decodeScoped(m.Raw[m.data.off:m.data.end()], m.data.off, StatusMalformed, "")
	if c.PDU == nil || c.Status == StatusMalformed {
		return nil, fmt.Errorf("snmp: %s", c.Err)
	}
	m.ContextEngineID, m.ContextName = c.ContextEngineID, c.ContextName
	return c.PDU, nil
}

// peekRequestID reads the request ID of a plaintext scoped PDU, for a Report.
func peekRequestID(b []byte) (int64, bool) {
	sp, _, err := readExpect(b, 0, tagSequence, "")
	if err != nil {
		return 0, false
	}
	_, s, err := readExpect(sp.content, sp.coff, tagOctetString, "")
	if err != nil {
		return 0, false
	}
	_, s, err = readExpect(s, 0, tagOctetString, "")
	if err != nil {
		return 0, false
	}
	pt, _, err := readTLV(s, 0)
	if err != nil || !isPDUTag(pt.tag) || PDUType(pt.tag) == PDUV1Trap {
		return 0, false
	}
	it, _, err := readExpect(pt.content, pt.coff, tagInteger, "")
	if err != nil {
		return 0, false
	}
	id, err := parseInt(it)
	return id, err == nil
}

// printable reports whether b is UTF-8 made only of printable characters (space
// included), the record's rule for str.
func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if !unicode.IsPrint(r) {
			return false
		}
		b = b[n:]
	}
	return true
}

// quoteBytes is a name in an error text: quoted if printable, else 0x-hex.
func quoteBytes(b []byte) string {
	if printable(b) {
		return strconv.Quote(string(b))
	}
	return "0x" + hex.EncodeToString(b)
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
