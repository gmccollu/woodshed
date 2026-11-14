package snmp

import (
	"fmt"
	"strconv"
)

// Kind is a varbind value's type.
type Kind uint8

// Value kinds. KindOther is any tag outside the SMI (BOOLEAN, NsapAddress, a
// constructed value, …), kept as its content octets.
const (
	KindInteger Kind = iota + 1
	KindOctetString
	KindNull
	KindOID
	KindIPAddress
	KindCounter32
	KindGauge32
	KindTimeTicks
	KindOpaque
	KindCounter64
	KindNoSuchObject
	KindNoSuchInstance
	KindEndOfMibView
	KindOther
)

// Value is a varbind value.
type Value struct {
	Kind  Kind
	Tag   byte   // the BER tag as received
	Int   int64  // KindInteger
	Uint  uint64 // KindCounter32, KindGauge32, KindTimeTicks, KindCounter64
	Bytes []byte // KindOctetString, KindIPAddress, KindOpaque, KindOther
	OID   OID    // KindOID
}

// Varbind is one variable binding.
type Varbind struct {
	OID   OID
	Value Value
}

// PDUType is a PDU's BER tag.
type PDUType byte

// PDU types (RFC 3416; the v1 Trap-PDU from RFC 1157).
const (
	PDUGet      PDUType = 0xa0
	PDUGetNext  PDUType = 0xa1
	PDUResponse PDUType = 0xa2
	PDUSet      PDUType = 0xa3
	PDUV1Trap   PDUType = 0xa4
	PDUGetBulk  PDUType = 0xa5
	PDUInform   PDUType = 0xa6
	PDUTrap     PDUType = 0xa7
	PDUReport   PDUType = 0xa8
)

// String returns the record's name for the type: v1trap, trap, inform, get,
// getnext, response, set, getbulk, report, or 0xNN for any other tag.
func (p PDUType) String() string {
	switch p {
	case PDUGet:
		return "get"
	case PDUGetNext:
		return "getnext"
	case PDUResponse:
		return "response"
	case PDUSet:
		return "set"
	case PDUV1Trap:
		return "v1trap"
	case PDUGetBulk:
		return "getbulk"
	case PDUInform:
		return "inform"
	case PDUTrap:
		return "trap"
	case PDUReport:
		return "report"
	}
	return fmt.Sprintf("0x%02x", byte(p))
}

// PDU is a decoded PDU.
type PDU struct {
	Type PDUType
	// RequestID, ErrorStatus and ErrorIndex are the fields of every PDU but the v1
	// Trap-PDU (for GetBulk the last two are non-repeaters and max-repetitions).
	RequestID   int64
	ErrorStatus int64
	ErrorIndex  int64

	// The v1 Trap-PDU's fields.
	Enterprise OID
	AgentAddr  []byte // normally 4 octets
	Generic    int64
	Specific   int64
	Timestamp  uint64

	Varbinds []Varbind

	hasRequestID bool
	rawRequestID []byte // the request-id TLV as received, echoed in a Response
	rawVarbinds  []byte // the varbind list TLV as received, echoed in a Response
}

// HasRequestID reports whether RequestID was read (every PDU but the v1 trap,
// once decoded that far).
func (p *PDU) HasRequestID() bool { return p.hasRequestID }

// isPDUTag reports whether tag is a context-specific constructed tag, the shape
// of every SNMP PDU.
func isPDUTag(tag byte) bool { return tag&0xe0 == 0xa0 }

// parsePDU decodes the PDU TLV t. On an error it returns what it decoded so far
// (the type, and the request ID once read) without varbinds.
func parsePDU(t tlv) (*PDU, error) {
	p := &PDU{Type: PDUType(t.tag)}
	b, off := t.content, t.coff
	var err error
	field := func(tag byte, what string) (tlv, error) {
		var f tlv
		f, b, err = readExpect(b, off, tag, what)
		if err == nil {
			off = f.end()
		}
		return f, err
	}
	if p.Type == PDUV1Trap {
		f, err := field(tagOID, "enterprise")
		if err != nil {
			return p, err
		}
		if p.Enterprise, err = parseOID(f); err != nil {
			return p, fmt.Errorf("enterprise: %w", err)
		}
		// agent-addr is an IpAddress; some agents send an OCTET STRING.
		f, rest, err := readTLV(b, off)
		if err != nil {
			return p, fmt.Errorf("agent-addr: %w", err)
		}
		if f.tag != tagIPAddress && f.tag != tagOctetString {
			return p, errAt(off, "agent-addr: want an IpAddress, got tag 0x%02x", f.tag)
		}
		p.AgentAddr = f.content
		b, off = rest, f.end()
		if f, err = field(tagInteger, "generic-trap"); err != nil {
			return p, err
		}
		if p.Generic, err = parseInt(f); err != nil {
			return p, fmt.Errorf("generic-trap: %w", err)
		}
		if f, err = field(tagInteger, "specific-trap"); err != nil {
			return p, err
		}
		if p.Specific, err = parseInt(f); err != nil {
			return p, fmt.Errorf("specific-trap: %w", err)
		}
		// time-stamp is TimeTicks; some agents send an INTEGER.
		f, rest, err = readTLV(b, off)
		if err != nil {
			return p, fmt.Errorf("time-stamp: %w", err)
		}
		if f.tag != tagTimeTicks && f.tag != tagInteger {
			return p, errAt(off, "time-stamp: want TimeTicks, got tag 0x%02x", f.tag)
		}
		if p.Timestamp, err = parseUint(f); err != nil {
			return p, fmt.Errorf("time-stamp: %w", err)
		}
		b, off = rest, f.end()
	} else {
		f, err := field(tagInteger, "request-id")
		if err != nil {
			return p, err
		}
		if p.RequestID, err = parseInt(f); err != nil {
			return p, fmt.Errorf("request-id: %w", err)
		}
		p.hasRequestID = true
		p.rawRequestID = rawTLV(t, f)
		if f, err = field(tagInteger, "error-status"); err != nil {
			return p, err
		}
		if p.ErrorStatus, err = parseInt(f); err != nil {
			return p, fmt.Errorf("error-status: %w", err)
		}
		if f, err = field(tagInteger, "error-index"); err != nil {
			return p, err
		}
		if p.ErrorIndex, err = parseInt(f); err != nil {
			return p, fmt.Errorf("error-index: %w", err)
		}
	}
	vl, err := field(tagSequence, "varbind list")
	if err != nil {
		return p, err
	}
	vbs, err := parseVarbinds(vl)
	if err != nil {
		return p, err
	}
	p.Varbinds = vbs
	p.rawVarbinds = rawTLV(t, vl)
	return p, nil
}

// rawTLV returns the whole encoding (header and content) of f, which lies inside
// parent's content.
func rawTLV(parent, f tlv) []byte {
	start := f.off - parent.coff
	end := f.end() - parent.coff
	return parent.content[start:end:end]
}

func parseVarbinds(vl tlv) ([]Varbind, error) {
	b, off := vl.content, vl.coff
	var vbs []Varbind
	for len(b) > 0 {
		seq, rest, err := readExpect(b, off, tagSequence, fmt.Sprintf("varbind %d", len(vbs)+1))
		if err != nil {
			return nil, err
		}
		b, off = rest, seq.end()
		ot, vrest, err := readExpect(seq.content, seq.coff, tagOID, fmt.Sprintf("varbind %d name", len(vbs)+1))
		if err != nil {
			return nil, err
		}
		oid, err := parseOID(ot)
		if err != nil {
			return nil, fmt.Errorf("varbind %d name: %w", len(vbs)+1, err)
		}
		vt, _, err := readTLV(vrest, ot.end())
		if err != nil {
			return nil, fmt.Errorf("varbind %d (%s) value: %w", len(vbs)+1, oid, err)
		}
		v, err := parseValue(vt)
		if err != nil {
			return nil, fmt.Errorf("varbind %d (%s) value: %w", len(vbs)+1, oid, err)
		}
		vbs = append(vbs, Varbind{OID: oid, Value: v})
	}
	return vbs, nil
}

func parseValue(t tlv) (Value, error) {
	v := Value{Tag: t.tag}
	var err error
	switch t.tag {
	case tagInteger:
		v.Kind = KindInteger
		v.Int, err = parseInt(t)
	case tagOctetString:
		v.Kind, v.Bytes = KindOctetString, t.content
	case tagNull:
		v.Kind = KindNull
	case tagOID:
		v.Kind = KindOID
		v.OID, err = parseOID(t)
	case tagIPAddress:
		v.Kind, v.Bytes = KindIPAddress, t.content
	case tagCounter32:
		v.Kind = KindCounter32
		v.Uint, err = parseUint(t)
	case tagGauge32, tagUInteger32:
		v.Kind = KindGauge32
		v.Uint, err = parseUint(t)
	case tagTimeTicks:
		v.Kind = KindTimeTicks
		v.Uint, err = parseUint(t)
	case tagOpaque:
		v.Kind, v.Bytes = KindOpaque, t.content
	case tagCounter64:
		v.Kind = KindCounter64
		v.Uint, err = parseUint(t)
	case tagNoSuchObject:
		v.Kind = KindNoSuchObject
	case tagNoSuchInstance:
		v.Kind = KindNoSuchInstance
	case tagEndOfMibView:
		v.Kind = KindEndOfMibView
	default:
		v.Kind, v.Bytes = KindOther, t.content
	}
	return v, err
}

// --- the notification view ---

// Well-known OIDs.
var (
	OIDSysUpTime          = OID{1, 3, 6, 1, 2, 1, 1, 3, 0}
	OIDSnmpTrapOID        = OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0}
	OIDSnmpTrapEnterprise = OID{1, 3, 6, 1, 6, 3, 1, 1, 4, 3, 0}
	OIDSnmpTraps          = OID{1, 3, 6, 1, 6, 3, 1, 1, 5}
)

// Notification is a trap's header view: its uptime, its trap OID and the
// varbinds the header doesn't already show.
type Notification struct {
	Uptime    uint64
	HasUptime bool
	TrapOID   OID // nil when the PDU has none
	Varbinds  []Varbind
}

// Notification returns the PDU's header view. For a v1 trap the uptime is the
// time-stamp and the trap OID is the RFC 3584 §3.1 translation (so v1 and v2c
// traps of the same kind compare); every varbind follows. For other PDUs the
// first sysUpTime.0 (TimeTicks) and snmpTrapOID.0 (OID) varbinds are the header
// and leave the list; the rest follow in PDU order.
func (p *PDU) Notification() Notification {
	if p.Type == PDUV1Trap {
		return Notification{Uptime: p.Timestamp, HasUptime: true, TrapOID: V1TrapOID(p.Enterprise, p.Generic, p.Specific), Varbinds: p.Varbinds}
	}
	n := Notification{}
	up, trap := -1, -1
	for i, vb := range p.Varbinds {
		if up < 0 && vb.Value.Kind == KindTimeTicks && vb.OID.Equal(OIDSysUpTime) {
			up = i
			n.Uptime, n.HasUptime = vb.Value.Uint, true
		} else if trap < 0 && vb.Value.Kind == KindOID && vb.OID.Equal(OIDSnmpTrapOID) {
			trap = i
			n.TrapOID = vb.Value.OID
		}
		if up >= 0 && trap >= 0 {
			break
		}
	}
	if up < 0 && trap < 0 {
		n.Varbinds = p.Varbinds
		return n
	}
	n.Varbinds = make([]Varbind, 0, len(p.Varbinds))
	for i, vb := range p.Varbinds {
		if i != up && i != trap {
			n.Varbinds = append(n.Varbinds, vb)
		}
	}
	return n
}

// V1TrapOID is RFC 3584 §3.1's snmpTrapOID for a v1 trap: snmpTraps.(generic+1)
// for the generic traps 0–5, enterprise.0.specific for enterpriseSpecific (6).
// It returns nil for a generic value outside 0–6.
func V1TrapOID(enterprise OID, generic, specific int64) OID {
	switch {
	case generic >= 0 && generic <= 5:
		return append(OIDSnmpTraps[:len(OIDSnmpTraps):len(OIDSnmpTraps)], uint32(generic+1))
	case generic == 6 && specific >= 0 && specific <= 0xffffffff && len(enterprise) < MaxOIDLen-1:
		o := make(OID, 0, len(enterprise)+2)
		return append(append(o, enterprise...), 0, uint32(specific))
	}
	return nil
}

// V1Fields is RFC 3584 §3.2's v2-to-v1 mapping, for a sender: the enterprise,
// generic and specific fields for trapOID. For snmpTraps.1–6 the enterprise is
// defaultEnterprise.
func V1Fields(trapOID, defaultEnterprise OID) (enterprise OID, generic, specific int64) {
	if len(trapOID) == len(OIDSnmpTraps)+1 && trapOID.HasPrefix(OIDSnmpTraps) && trapOID[len(trapOID)-1] >= 1 && trapOID[len(trapOID)-1] <= 6 {
		return defaultEnterprise, int64(trapOID[len(trapOID)-1]) - 1, 0
	}
	n := len(trapOID)
	if n >= 3 && trapOID[n-2] == 0 {
		return trapOID[:n-2], 6, int64(trapOID[n-1])
	}
	if n >= 2 {
		return trapOID[:n-1], 6, int64(trapOID[n-1])
	}
	return defaultEnterprise, 6, 0
}

// --- encoding ---

// AppendValue appends v's BER encoding.
func appendValue(dst []byte, v Value) []byte {
	switch v.Kind {
	case KindInteger:
		return appendInt(dst, tagInteger, v.Int)
	case KindOctetString:
		return appendTLV(dst, tagOctetString, v.Bytes)
	case KindNull:
		return append(dst, tagNull, 0)
	case KindOID:
		return appendOID(dst, v.OID)
	case KindIPAddress:
		return appendTLV(dst, tagIPAddress, v.Bytes)
	case KindCounter32:
		return appendUint(dst, tagCounter32, v.Uint)
	case KindGauge32:
		return appendUint(dst, tagGauge32, v.Uint)
	case KindTimeTicks:
		return appendUint(dst, tagTimeTicks, v.Uint)
	case KindOpaque:
		return appendTLV(dst, tagOpaque, v.Bytes)
	case KindCounter64:
		return appendUint(dst, tagCounter64, v.Uint)
	case KindNoSuchObject:
		return append(dst, tagNoSuchObject, 0)
	case KindNoSuchInstance:
		return append(dst, tagNoSuchInstance, 0)
	case KindEndOfMibView:
		return append(dst, tagEndOfMibView, 0)
	}
	tag := v.Tag
	if tag == 0 {
		tag = tagOctetString
	}
	return appendTLV(dst, tag, v.Bytes)
}

func appendVarbinds(dst []byte, vbs []Varbind) []byte {
	var list []byte
	for _, vb := range vbs {
		var one []byte
		one = appendOID(one, vb.OID)
		one = appendValue(one, vb.Value)
		list = appendTLV(list, tagSequence, one)
	}
	return appendTLV(dst, tagSequence, list)
}

// EncodePDU returns the PDU's BER encoding. A v1 Trap-PDU's AgentAddr must be 4
// octets (nil encodes 0.0.0.0).
func EncodePDU(p *PDU) []byte {
	var c []byte
	if p.Type == PDUV1Trap {
		c = appendOID(c, p.Enterprise)
		addr := p.AgentAddr
		if addr == nil {
			addr = []byte{0, 0, 0, 0}
		}
		c = appendTLV(c, tagIPAddress, addr)
		c = appendInt(c, tagInteger, p.Generic)
		c = appendInt(c, tagInteger, p.Specific)
		c = appendUint(c, tagTimeTicks, p.Timestamp)
	} else {
		c = appendInt(c, tagInteger, p.RequestID)
		c = appendInt(c, tagInteger, p.ErrorStatus)
		c = appendInt(c, tagInteger, p.ErrorIndex)
	}
	c = appendVarbinds(c, p.Varbinds)
	return appendTLV(nil, byte(p.Type), c)
}

// EncodeCommunity returns a v1 or v2c message: the version, the community and
// the encoded PDU.
func EncodeCommunity(v Version, community, pdu []byte) []byte {
	var c []byte
	c = appendInt(c, tagInteger, int64(v))
	c = appendTLV(c, tagOctetString, community)
	c = append(c, pdu...)
	return appendTLV(nil, tagSequence, c)
}

// Version is an SNMP message version, as encoded (v1 0, v2c 1, v3 3).
type Version int

// Versions. VersionUnknown is a message whose version wasn't read.
const (
	VersionUnknown Version = -1
	V1             Version = 0
	V2c            Version = 1
	V3             Version = 3
)

// String returns the record's name: "1", "2c", "3", or "" when unknown.
func (v Version) String() string {
	switch v {
	case V1:
		return "1"
	case V2c:
		return "2c"
	case V3:
		return "3"
	}
	if v == VersionUnknown {
		return ""
	}
	return strconv.Itoa(int(v))
}
