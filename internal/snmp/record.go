package snmp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
)

// MaxRecordLen bounds a record line (SPEC §11.2.4: lines up to 1 MiB, with room
// for the envelope and the store's escaping). A record that would be longer with
// MIB names is written without them; without names any datagram fits.
const MaxRecordLen = 1<<20 - 256

// Namer names OIDs for the record. *MIBSet implements it.
type Namer interface {
	// Name returns the OID's name ("ifOperStatus.3"), or "".
	Name(OID) string
	// EnumName returns the name of an INTEGER value of the object at the OID, or "".
	EnumName(OID, int64) string
}

// RecordOptions are the record's inputs beyond the message.
type RecordOptions struct {
	Names Namer // the MIB set loaded at receipt; nil writes no names
	Dup   bool  // a retransmitted inform (dup=1)
}

// CommunityHash is the record's cred for a community: "#" and the first 8 hex
// digits of its SHA-256 (SPEC §11.2.4). The community itself is never stored.
func CommunityHash(community []byte) string {
	s := sha256.Sum256(community)
	return "#" + hex.EncodeToString(s[:4])
}

// MaskedRaw returns a copy of a v1/v2c datagram with the community's octets
// replaced by as many '*' bytes, so the BER still decodes (SPEC §11.2.4). A v3
// message is returned unchanged (copied): its secrets are never in the packet.
//
// It finds the community leniently, so a malformed datagram is masked too: the
// second element of the outer SEQUENCE, when it's an OCTET STRING and the version
// before it isn't 3, clipped to the datagram when its length runs past the end.
// A datagram too broken to show a version and an OCTET STRING there has no
// community to mask.
func MaskedRaw(raw []byte) []byte {
	out := append([]byte(nil), raw...)
	if start, end := communitySpan(raw); end > start {
		for i := start; i < end; i++ {
			out[i] = '*'
		}
	}
	return out
}

// communitySpan finds the community's content octets.
func communitySpan(raw []byte) (start, end int) {
	// The outer header: any tag, a definite length or not.
	if len(raw) < 2 {
		return 0, 0
	}
	pos, ok := skipHeader(raw, 0)
	if !ok {
		return 0, 0
	}
	// The version.
	if pos >= len(raw) || raw[pos] != tagInteger {
		return 0, 0
	}
	vt, _, err := readTLV(raw[pos:], pos)
	if err != nil {
		return 0, 0
	}
	if v, err := parseInt(vt); err == nil && v == int64(V3) {
		return 0, 0
	}
	pos = vt.end()
	if pos >= len(raw) || raw[pos] != tagOctetString {
		return 0, 0
	}
	cpos, ok := skipHeader(raw, pos)
	if !ok {
		// The length octets themselves are cut off: mask whatever follows the tag.
		return pos + 1, len(raw)
	}
	ct, _, err := readTLV(raw[pos:], pos)
	if err != nil {
		return cpos, len(raw)
	}
	return ct.coff, ct.end()
}

// skipHeader returns the offset after the tag and length at pos, whatever the
// length says, or false when the header itself is cut off or unreadable.
func skipHeader(b []byte, pos int) (int, bool) {
	if pos+2 > len(b) {
		return 0, false
	}
	l := b[pos+1]
	if l < 0x80 || l == 0x80 {
		return pos + 2, true
	}
	if l == 0xff {
		return 0, false
	}
	n := int(l & 0x7f)
	if pos+2+n > len(b) {
		return 0, false
	}
	return pos + 2 + n, true
}

// FormatRecord appends m's record (SPEC §11.2.4), without the envelope, to dst.
func FormatRecord(dst []byte, m *Message, o RecordOptions) []byte {
	start := len(dst)
	out := appendRecord(dst, m, o.Names, o.Dup)
	if o.Names != nil && recordLen(out[start:]) > MaxRecordLen {
		out = appendRecord(out[:start], m, nil, o.Dup)
	}
	return out
}

// recordLen is the record's length once the store escapes it (a backslash
// becomes two bytes; a record holds no CR or LF).
func recordLen(r []byte) int { return len(r) + bytes.Count(r, []byte{'\\'}) }

func appendRecord(dst []byte, m *Message, names Namer, dup bool) []byte {
	first := true
	key := func(k string) {
		if !first {
			dst = append(dst, ' ')
		}
		first = false
		dst = append(dst, k...)
		dst = append(dst, '=')
	}
	if v := m.Version.String(); v != "" && (m.Version == V1 || m.Version == V2c || m.Version == V3) {
		key("v")
		dst = append(dst, v...)
	}
	p := m.PDU
	if p != nil {
		key("pdu")
		dst = append(dst, p.Type.String()...)
		if p.hasRequestID {
			key("id")
			dst = strconv.AppendInt(dst, p.RequestID, 10)
		}
	}
	if dup {
		key("dup")
		dst = append(dst, '1')
	}
	switch {
	case m.Version == V3 && m.HeaderRead:
		key("cred")
		dst = appendToken(dst, m.User)
		key("level")
		dst = append(dst, m.Level.String()...)
		if len(m.EngineID) > 0 {
			key("engine")
			dst = hex.AppendEncode(dst, m.EngineID)
		}
		if len(m.ContextName) > 0 {
			key("ctx")
			dst = appendToken(dst, m.ContextName)
		}
		if len(m.ContextEngineID) > 0 && !bytes.Equal(m.ContextEngineID, m.EngineID) {
			key("ctx_engine")
			dst = hex.AppendEncode(dst, m.ContextEngineID)
		}
	case m.Community != nil:
		key("cred")
		dst = append(dst, CommunityHash(m.Community)...)
	}
	key("status")
	dst = append(dst, m.Status.String()...)
	if m.Status != StatusOK {
		key("error")
		dst = appendQuoted(dst, []byte(m.Err))
	}
	if p != nil && p.Varbinds != nil || p != nil && m.Status == StatusOK {
		if p.Type == PDUV1Trap {
			key("enterprise")
			dst = appendOIDName(dst, p.Enterprise, names)
			key("agent")
			dst = appendIP(dst, p.AgentAddr)
			key("generic")
			dst = strconv.AppendInt(dst, p.Generic, 10)
			key("specific")
			dst = strconv.AppendInt(dst, p.Specific, 10)
		}
		n := p.Notification()
		if p.Type == PDUV1Trap || p.Type == PDUTrap || p.Type == PDUInform {
			if n.HasUptime {
				key("uptime")
				dst = strconv.AppendUint(dst, n.Uptime, 10)
			}
			if n.TrapOID != nil {
				key("trap")
				dst = appendOIDName(dst, n.TrapOID, names)
			}
		} else {
			n.Varbinds = p.Varbinds
		}
		for _, vb := range n.Varbinds {
			key("vb")
			dst = appendVarbind(dst, vb, names)
		}
	}
	key("raw")
	if m.Version == V3 {
		dst = base64.StdEncoding.AppendEncode(dst, m.Raw)
	} else {
		dst = base64.StdEncoding.AppendEncode(dst, MaskedRaw(m.Raw))
	}
	return dst
}

// appendIP appends a 4-octet address in dotted form, anything else as 0x hex.
func appendIP(dst, a []byte) []byte {
	if len(a) != 4 {
		dst = append(dst, "0x"...)
		return hex.AppendEncode(dst, a)
	}
	for i, x := range a {
		if i > 0 {
			dst = append(dst, '.')
		}
		dst = strconv.AppendUint(dst, uint64(x), 10)
	}
	return dst
}

func appendOIDName(dst []byte, o OID, names Namer) []byte {
	dst = o.Append(dst)
	if names != nil {
		if n := names.Name(o); n != "" {
			dst = append(dst, '(')
			dst = append(dst, n...)
			dst = append(dst, ')')
		}
	}
	return dst
}

// Varbind type names in the record.
const (
	TypeInt            = "int"
	TypeStr            = "str"
	TypeHex            = "hex"
	TypeOID            = "oid"
	TypeIP             = "ip"
	TypeCounter32      = "c32"
	TypeGauge32        = "g32"
	TypeTimeTicks      = "ticks"
	TypeCounter64      = "c64"
	TypeOpaque         = "opaque"
	TypeNull           = "null"
	TypeNoSuchObject   = "nosuchobject"
	TypeNoSuchInstance = "nosuchinstance"
	TypeEndOfMibView   = "endofmibview"
)

func appendVarbind(dst []byte, vb Varbind, names Namer) []byte {
	dst = appendOIDName(dst, vb.OID, names)
	v := vb.Value
	switch v.Kind {
	case KindInteger:
		dst = append(dst, ":int:"...)
		dst = strconv.AppendInt(dst, v.Int, 10)
		if names != nil {
			if e := names.EnumName(vb.OID, v.Int); e != "" {
				dst = append(dst, '(')
				dst = append(dst, e...)
				dst = append(dst, ')')
			}
		}
	case KindOctetString:
		if printable(v.Bytes) {
			dst = append(dst, ":str:"...)
			dst = appendQuoted(dst, v.Bytes)
		} else {
			dst = append(dst, ":hex:"...)
			dst = hex.AppendEncode(dst, v.Bytes)
		}
	case KindNull:
		dst = append(dst, ":null"...)
	case KindOID:
		dst = append(dst, ":oid:"...)
		dst = appendOIDName(dst, v.OID, names)
	case KindIPAddress:
		if len(v.Bytes) == 4 {
			dst = append(dst, ":ip:"...)
			dst = appendIP(dst, v.Bytes)
		} else {
			dst = append(dst, ":hex:"...)
			dst = hex.AppendEncode(dst, v.Bytes)
		}
	case KindCounter32:
		dst = append(dst, ":c32:"...)
		dst = strconv.AppendUint(dst, v.Uint, 10)
	case KindGauge32:
		dst = append(dst, ":g32:"...)
		dst = strconv.AppendUint(dst, v.Uint, 10)
	case KindTimeTicks:
		dst = append(dst, ":ticks:"...)
		dst = strconv.AppendUint(dst, v.Uint, 10)
	case KindCounter64:
		dst = append(dst, ":c64:"...)
		dst = strconv.AppendUint(dst, v.Uint, 10)
	case KindOpaque:
		dst = append(dst, ":opaque:"...)
		dst = hex.AppendEncode(dst, v.Bytes)
	case KindNoSuchObject:
		dst = append(dst, ":nosuchobject"...)
	case KindNoSuchInstance:
		dst = append(dst, ":nosuchinstance"...)
	case KindEndOfMibView:
		dst = append(dst, ":endofmibview"...)
	default:
		dst = append(dst, ":hex:"...)
		dst = hex.AppendEncode(dst, v.Bytes)
	}
	return dst
}

// appendQuoted appends b in double quotes with " and \ escaped.
func appendQuoted(dst, b []byte) []byte {
	dst = append(dst, '"')
	for _, c := range b {
		if c == '"' || c == '\\' {
			dst = append(dst, '\\')
		}
		dst = append(dst, c)
	}
	return append(dst, '"')
}

// appendToken appends a user or context name: bare when it's plain (letters,
// digits, ._-@+%:/ and not starting with # or 0x), quoted when it's other
// printable text, and 0x-hex otherwise.
func appendToken(dst, b []byte) []byte {
	if bareToken(b) {
		return append(dst, b...)
	}
	if printable(b) && !bytes.ContainsAny(b, "\t") {
		return appendQuoted(dst, b)
	}
	dst = append(dst, "0x"...)
	return hex.AppendEncode(dst, b)
}

func bareToken(b []byte) bool {
	if len(b) == 0 || b[0] == '#' || (len(b) >= 2 && b[0] == '0' && (b[1] == 'x' || b[1] == 'X')) {
		return false
	}
	for _, c := range b {
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.' || c == '_' || c == '-' || c == '@' || c == '+' || c == '%' || c == ':' || c == '/':
		default:
			return false
		}
	}
	return true
}

// --- reading a record back ---

// Record is a stored record's fields, as text (what filters and the field panel
// compare). Absent keys are "".
type Record struct {
	Version        string
	PDU            string
	ID             string
	Dup            bool
	Cred           string // "#3f9a1c07", or the v3 user name (unquoted)
	Level          string
	Engine         string
	Ctx            string
	CtxEngine      string
	Status         string
	Error          string
	Enterprise     string
	EnterpriseName string
	Agent          string
	Generic        string
	Specific       string
	Uptime         string
	Trap           string
	TrapName       string
	Varbinds       []RecordVarbind
	Raw            string // base64
}

// RecordVarbind is one vb= of a record.
type RecordVarbind struct {
	OID   string
	Name  string
	Type  string // TypeInt, TypeStr, …
	Value string // str values unquoted; "" for null and the exceptions
	Enum  string // the named value of an int, or an oid value's name
}

// ParseRecord reads a record (without the envelope) back into its fields.
// Unknown keys are skipped, so later versions can add some.
func ParseRecord(rec []byte) (Record, error) { return parseRecord(rec, false) }

// ParseRecordHeader is ParseRecord without the varbinds and raw=: it stops at
// the first vb= or raw=, so a filter reads a record's header cheaply.
func ParseRecordHeader(rec []byte) (Record, error) { return parseRecord(rec, true) }

func parseRecord(rec []byte, header bool) (Record, error) {
	var r Record
	p := recParser{b: rec}
	for {
		p.skipSpaces()
		if p.done() {
			break
		}
		k, err := p.key()
		if err != nil {
			return r, err
		}
		if header && (k == "vb" || k == "raw") {
			break
		}
		if k == "vb" {
			vb, err := p.varbind()
			if err != nil {
				return r, err
			}
			r.Varbinds = append(r.Varbinds, vb)
			continue
		}
		v, err := p.value()
		if err != nil {
			return r, fmt.Errorf("snmp: record key %s: %w", k, err)
		}
		switch k {
		case "v":
			r.Version = v
		case "pdu":
			r.PDU = v
		case "id":
			r.ID = v
		case "dup":
			r.Dup = v == "1"
		case "cred":
			r.Cred = v
		case "level":
			r.Level = v
		case "engine":
			r.Engine = v
		case "ctx":
			r.Ctx = v
		case "ctx_engine":
			r.CtxEngine = v
		case "status":
			r.Status = v
		case "error":
			r.Error = v
		case "enterprise":
			r.Enterprise, r.EnterpriseName = splitName(v)
		case "agent":
			r.Agent = v
		case "generic":
			r.Generic = v
		case "specific":
			r.Specific = v
		case "uptime":
			r.Uptime = v
		case "trap":
			r.Trap, r.TrapName = splitName(v)
		case "raw":
			r.Raw = v
		}
	}
	if r.Status == "" {
		return r, errors.New("snmp: record has no status")
	}
	return r, nil
}

// RecordText returns the record without its raw= (what q matches, SPEC
// §11.2.4). raw= is last and base64 has no spaces, so it's the last " raw=".
func RecordText(rec []byte) []byte {
	if i := bytes.LastIndex(rec, []byte(" raw=")); i >= 0 {
		return rec[:i]
	}
	if bytes.HasPrefix(rec, []byte("raw=")) {
		return rec[:0]
	}
	return rec
}

// splitName splits "1.3.6.1(name)" into the OID and the name.
func splitName(v string) (string, string) {
	if len(v) > 0 && v[len(v)-1] == ')' {
		if i := bytes.IndexByte([]byte(v), '('); i >= 0 {
			return v[:i], v[i+1 : len(v)-1]
		}
	}
	return v, ""
}

type recParser struct {
	b []byte
	i int
}

func (p *recParser) done() bool { return p.i >= len(p.b) }

func (p *recParser) skipSpaces() {
	for p.i < len(p.b) && p.b[p.i] == ' ' {
		p.i++
	}
}

func (p *recParser) key() (string, error) {
	s := p.i
	for p.i < len(p.b) && p.b[p.i] != '=' && p.b[p.i] != ' ' {
		p.i++
	}
	if p.i >= len(p.b) || p.b[p.i] != '=' || p.i == s {
		return "", fmt.Errorf("snmp: record: want key=value at byte %d", s)
	}
	k := string(p.b[s:p.i])
	p.i++
	return k, nil
}

// value reads a bare token (to the next space) or a quoted string, unquoted.
func (p *recParser) value() (string, error) {
	if p.i < len(p.b) && p.b[p.i] == '"' {
		return p.quoted()
	}
	s := p.i
	for p.i < len(p.b) && p.b[p.i] != ' ' {
		p.i++
	}
	return string(p.b[s:p.i]), nil
}

func (p *recParser) quoted() (string, error) {
	s := p.i
	p.i++ // the opening quote
	var out []byte
	for p.i < len(p.b) {
		c := p.b[p.i]
		switch c {
		case '\\':
			if p.i+1 >= len(p.b) {
				return "", fmt.Errorf("unterminated string at byte %d", s)
			}
			out = append(out, p.b[p.i+1])
			p.i += 2
		case '"':
			p.i++
			if out == nil {
				out = []byte{}
			}
			return string(out), nil
		default:
			out = append(out, c)
			p.i++
		}
	}
	return "", fmt.Errorf("unterminated string at byte %d", s)
}

// varbind reads <oid>[(<name>)]:<type>[:<value>].
func (p *recParser) varbind() (RecordVarbind, error) {
	var vb RecordVarbind
	s := p.i
	for p.i < len(p.b) && (p.b[p.i] == '.' || ('0' <= p.b[p.i] && p.b[p.i] <= '9')) {
		p.i++
	}
	vb.OID = string(p.b[s:p.i])
	if vb.OID == "" {
		return vb, fmt.Errorf("snmp: record: vb= without an OID at byte %d", s)
	}
	if p.i < len(p.b) && p.b[p.i] == '(' {
		e := bytes.IndexByte(p.b[p.i:], ')')
		if e < 0 {
			return vb, fmt.Errorf("snmp: record: unclosed name at byte %d", p.i)
		}
		vb.Name = string(p.b[p.i+1 : p.i+e])
		p.i += e + 1
	}
	if p.i >= len(p.b) || p.b[p.i] != ':' {
		return vb, fmt.Errorf("snmp: record: vb= without a type at byte %d", p.i)
	}
	p.i++
	ts := p.i
	for p.i < len(p.b) && p.b[p.i] != ':' && p.b[p.i] != ' ' {
		p.i++
	}
	vb.Type = string(p.b[ts:p.i])
	if vb.Type == "" {
		return vb, fmt.Errorf("snmp: record: vb= with an empty type at byte %d", ts)
	}
	if p.i < len(p.b) && p.b[p.i] == ':' {
		p.i++
		if vb.Type == TypeStr {
			if p.i >= len(p.b) || p.b[p.i] != '"' {
				return vb, fmt.Errorf("snmp: record: str value isn't quoted at byte %d", p.i)
			}
			v, err := p.quoted()
			if err != nil {
				return vb, fmt.Errorf("snmp: record: %w", err)
			}
			vb.Value = v
		} else {
			v, _ := p.value()
			vb.Value, vb.Enum = splitName(v)
		}
	}
	if p.i < len(p.b) && p.b[p.i] != ' ' {
		return vb, fmt.Errorf("snmp: record: junk after vb= at byte %d", p.i)
	}
	return vb, nil
}
