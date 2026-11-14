// Package snmp is Woodshed's SNMP codec for the trap receiver (SPEC §11.2): BER,
// the v1, v2c and v3 messages a receiver sees, USM (RFC 3414, RFC 7860, RFC 3826
// and the AES-192/256 drafts), the inform Response and the discovery Report, the
// stored record line, and a MIB reader that takes only names, notifications and
// integer enumerations.
//
// Decoding is lenient where real devices are sloppy (non-minimal lengths and
// integers, unsigned values sent with the sign bit set, an IpAddress sent as an
// OCTET STRING) and bounded everywhere else: definite lengths only, lengths
// checked against the data, at most 128 sub-identifiers in an OID. Decode never
// fails: a datagram it can't read is a Message with StatusMalformed and the
// reason, because a device sending broken traps is evidence.
package snmp

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// BER tags SNMP uses (RFC 3416, RFC 2578).
const (
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagNull        = 0x05
	tagOID         = 0x06
	tagSequence    = 0x30

	tagIPAddress   = 0x40
	tagCounter32   = 0x41
	tagGauge32     = 0x42
	tagTimeTicks   = 0x43
	tagOpaque      = 0x44
	tagNsapAddress = 0x45
	tagCounter64   = 0x46
	tagUInteger32  = 0x47 // RFC 1442's, obsolete; read as Gauge32

	tagNoSuchObject   = 0x80
	tagNoSuchInstance = 0x81
	tagEndOfMibView   = 0x82
)

// MaxOIDLen is the most sub-identifiers an OID may have (RFC 2578 §3.5).
const MaxOIDLen = 128

// DecodeError is a BER or structure error at a byte offset in the datagram (or
// in the decrypted scoped PDU, for errors found after decryption).
type DecodeError struct {
	Off int
	Msg string
}

func (e *DecodeError) Error() string { return e.Msg + " at byte " + strconv.Itoa(e.Off) }

func errAt(off int, format string, args ...any) error {
	return &DecodeError{Off: off, Msg: fmt.Sprintf(format, args...)}
}

// tlv is one decoded tag-length-value.
type tlv struct {
	tag     byte
	off     int    // offset of the tag byte
	coff    int    // offset of the first content byte
	content []byte // the content octets (a slice of the input, capacity clipped)
}

func (t tlv) end() int { return t.coff + len(t.content) }

// readTLV reads the TLV at the start of b, whose first byte is at offset off. It
// returns the TLV and the bytes after it. Only definite lengths are accepted (BER
// for SNMP requires them); long-form lengths with leading zero octets are accepted.
func readTLV(b []byte, off int) (tlv, []byte, error) {
	if len(b) == 0 {
		return tlv{}, nil, errAt(off, "unexpected end of data")
	}
	tag := b[0]
	if tag&0x1f == 0x1f {
		return tlv{}, nil, errAt(off, "tag 0x%02x uses the high-tag-number form, which SNMP doesn't", tag)
	}
	if len(b) < 2 {
		return tlv{}, nil, errAt(off, "truncated header (tag 0x%02x without a length)", tag)
	}
	l, hdr := int(b[1]), 2
	switch {
	case l < 0x80:
	case l == 0x80:
		return tlv{}, nil, errAt(off, "indefinite length (tag 0x%02x); SNMP requires definite lengths", tag)
	case l == 0xff:
		return tlv{}, nil, errAt(off, "reserved length octet 0xff")
	default:
		n := l & 0x7f
		if len(b) < 2+n {
			return tlv{}, nil, errAt(off, "truncated length (%d length octets, %d bytes left)", n, len(b)-2)
		}
		v := 0
		for _, c := range b[2 : 2+n] {
			if v > math.MaxInt32>>8 {
				return tlv{}, nil, errAt(off, "length too large")
			}
			v = v<<8 | int(c)
		}
		l, hdr = v, 2+n
	}
	if l > len(b)-hdr {
		return tlv{}, nil, errAt(off, "length %d runs past the end of the data (%d bytes left)", l, len(b)-hdr)
	}
	t := tlv{tag: tag, off: off, coff: off + hdr, content: b[hdr : hdr+l : hdr+l]}
	return t, b[hdr+l:], nil
}

// readExpect reads a TLV and checks its tag.
func readExpect(b []byte, off int, tag byte, what string) (tlv, []byte, error) {
	t, rest, err := readTLV(b, off)
	if err != nil {
		return t, rest, fmt.Errorf("%s: %w", what, err)
	}
	if t.tag != tag {
		return t, rest, errAt(off, "%s: want tag 0x%02x, got 0x%02x", what, tag, t.tag)
	}
	return t, rest, nil
}

// parseInt reads a signed INTEGER of up to 64 bits. Redundant leading sign octets
// (a non-minimal encoding) are accepted.
func parseInt(t tlv) (int64, error) {
	c := t.content
	if len(c) == 0 {
		return 0, errAt(t.off, "empty integer")
	}
	for len(c) > 1 && ((c[0] == 0 && c[1]&0x80 == 0) || (c[0] == 0xff && c[1]&0x80 != 0)) {
		c = c[1:]
	}
	if len(c) > 8 {
		return 0, errAt(t.off, "integer wider than 64 bits")
	}
	v := int64(int8(c[0]))
	for _, x := range c[1:] {
		v = v<<8 | int64(x)
	}
	return v, nil
}

// parseUint reads an unsigned value (Counter32, Gauge32, TimeTicks, Counter64).
// The content is read as an unsigned magnitude, so a value sent with the sign bit
// set and no leading zero (a common agent bug: 0xffffffff as four octets) reads as
// meant.
func parseUint(t tlv) (uint64, error) {
	c := t.content
	if len(c) == 0 {
		return 0, errAt(t.off, "empty integer")
	}
	for len(c) > 1 && c[0] == 0 {
		c = c[1:]
	}
	if len(c) > 8 {
		return 0, errAt(t.off, "unsigned value wider than 64 bits")
	}
	var v uint64
	for _, x := range c {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// OID is an object identifier.
type OID []uint32

// String returns the dotted form, "1.3.6.1.2.1.1.3.0".
func (o OID) String() string {
	return string(o.Append(nil))
}

// Append appends the dotted form to dst.
func (o OID) Append(dst []byte) []byte {
	for i, s := range o {
		if i > 0 {
			dst = append(dst, '.')
		}
		dst = strconv.AppendUint(dst, uint64(s), 10)
	}
	return dst
}

// Equal reports whether o and p are the same OID.
func (o OID) Equal(p OID) bool {
	if len(o) != len(p) {
		return false
	}
	for i := range o {
		if o[i] != p[i] {
			return false
		}
	}
	return true
}

// HasPrefix reports whether p is a prefix of o (or o itself).
func (o OID) HasPrefix(p OID) bool {
	return len(o) >= len(p) && o[:len(p)].Equal(p)
}

// ParseOID parses a dotted OID ("1.3.6.1.4.1.32473", a leading dot allowed).
func ParseOID(s string) (OID, error) {
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return nil, fmt.Errorf("snmp: empty OID")
	}
	parts := strings.Split(s, ".")
	if len(parts) > MaxOIDLen {
		return nil, fmt.Errorf("snmp: OID %q has more than %d sub-identifiers", s, MaxOIDLen)
	}
	o := make(OID, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseUint(p, 10, 32)
		if err != nil || p == "" || (len(p) > 1 && p[0] == '0') {
			return nil, fmt.Errorf("snmp: %q is not a numeric OID", s)
		}
		o[i] = uint32(v)
	}
	if len(o) < 2 || o[0] > 2 || (o[0] < 2 && o[1] >= 40) {
		return nil, fmt.Errorf("snmp: %q is not a valid OID (it must start 0.n, 1.n or 2.n, with n < 40 under 0 and 1)", s)
	}
	return o, nil
}

// parseOID reads an OBJECT IDENTIFIER. Non-minimal sub-identifiers (a leading
// 0x80 octet) are accepted; a sub-identifier above 2^32-1, a truncated last one,
// or more than MaxOIDLen are errors.
func parseOID(t tlv) (OID, error) {
	c := t.content
	if len(c) == 0 {
		return nil, errAt(t.off, "empty OID")
	}
	o := make(OID, 0, min(len(c)+1, MaxOIDLen))
	var v uint64
	for i, x := range c {
		v = v<<7 | uint64(x&0x7f)
		if v > math.MaxUint32+80 {
			return nil, errAt(t.off, "OID sub-identifier larger than 4294967295")
		}
		if x&0x80 != 0 {
			if i == len(c)-1 {
				return nil, errAt(t.off, "OID ends in the middle of a sub-identifier")
			}
			continue
		}
		if len(o) == 0 {
			switch {
			case v < 40:
				o = append(o, 0, uint32(v))
			case v < 80:
				o = append(o, 1, uint32(v-40))
			default:
				o = append(o, 2, uint32(v-80))
			}
		} else {
			if v > math.MaxUint32 {
				return nil, errAt(t.off, "OID sub-identifier larger than 4294967295")
			}
			o = append(o, uint32(v))
		}
		if len(o) > MaxOIDLen {
			return nil, errAt(t.off, "OID has more than %d sub-identifiers", MaxOIDLen)
		}
		v = 0
	}
	return o, nil
}

// --- encoding ---

// appendLength appends a BER definite length, in the minimal form.
func appendLength(dst []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(dst, byte(n))
	case n < 0x100:
		return append(dst, 0x81, byte(n))
	case n < 0x10000:
		return append(dst, 0x82, byte(n>>8), byte(n))
	case n < 0x1000000:
		return append(dst, 0x83, byte(n>>16), byte(n>>8), byte(n))
	default:
		return append(dst, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
}

// appendTLV appends a TLV with the given content.
func appendTLV(dst []byte, tag byte, content []byte) []byte {
	dst = append(dst, tag)
	dst = appendLength(dst, len(content))
	return append(dst, content...)
}

// appendInt appends a signed integer in the minimal two's-complement form.
func appendInt(dst []byte, tag byte, v int64) []byte {
	n := 1
	for n < 8 && !(v>>(8*n-1) == 0 || v>>(8*n-1) == -1) {
		n++
	}
	dst = append(dst, tag, byte(n))
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, byte(v>>(8*i)))
	}
	return dst
}

// appendUint appends an unsigned integer (with a leading zero octet when the top
// bit is set).
func appendUint(dst []byte, tag byte, v uint64) []byte {
	n := 1
	for n < 8 && v>>(8*n) != 0 {
		n++
	}
	lead := v>>(8*n-1)&1 == 1
	l := n
	if lead {
		l++
	}
	dst = append(dst, tag, byte(l))
	if lead {
		dst = append(dst, 0)
	}
	for i := n - 1; i >= 0; i-- {
		dst = append(dst, byte(v>>(8*i)))
	}
	return dst
}

// appendOIDContent appends an OID's content octets. o must have at least two
// sub-identifiers, the first 0, 1 or 2 (ParseOID's rule); others encode as 0.0.
func appendOIDContent(dst []byte, o OID) []byte {
	if len(o) < 2 || o[0] > 2 {
		return append(dst, 0)
	}
	dst = appendSubID(dst, uint64(o[0])*40+uint64(o[1]))
	for _, s := range o[2:] {
		dst = appendSubID(dst, uint64(s))
	}
	return dst
}

func appendSubID(dst []byte, v uint64) []byte {
	var tmp [10]byte
	i := len(tmp) - 1
	tmp[i] = byte(v & 0x7f)
	for v >>= 7; v > 0; v >>= 7 {
		i--
		tmp[i] = byte(v&0x7f) | 0x80
	}
	return append(dst, tmp[i:]...)
}

func appendOID(dst []byte, o OID) []byte {
	return appendTLV(dst, tagOID, appendOIDContent(nil, o))
}
