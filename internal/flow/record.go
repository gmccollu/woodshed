// Package flow is Woodshed's NetFlow v5, NetFlow v9 and IPFIX collector
// (SPEC §13.1): the decoders, the template cache, the exporter metadata from
// options data, the buffer for data that arrives before its template, and the
// record every other part of the flow type works with (this file).
//
// A Record is one decoded flow or firewall-event record, with every column of
// SPEC §13.2 and §13.2.1. Columns a record doesn't carry are absent (their bit
// in Has is clear), so the API can show null and the segment format can skip
// them; the few that are always present (Received, Status, TimeSource,
// Sampling, Domain) have no bit.
package flow

import (
	"net/netip"
	"strconv"
	"strings"
)

// Column bits of Record.Has: which optional columns a record carries.
const (
	HasStart uint64 = 1 << iota
	HasEnd
	HasEventTime
	HasSrc
	HasDst
	HasSrcPort
	HasDstPort
	HasProto
	HasTCPFlags
	HasToS
	HasPackets
	HasBytes
	HasInIf
	HasOutIf
	HasSrcAS
	HasDstAS
	HasNextHop
	HasVLAN
	HasDirection
	HasEndReason
	HasFwEvent
	HasNatEvent
	HasPostNATSrc
	HasPostNATDst
	HasPostNATSrcPort
	HasPostNATDstPort
	HasInitiatorBytes
	HasResponderBytes
	HasInitiatorPackets
	HasResponderPackets
	HasRevBytes
	HasRevPackets
	HasRuleID
	HasInIfName
	HasOutIfName
	// HasTotals marks Bytes and Packets as totals (octetTotalCount,
	// packetTotalCount) rather than deltas, for the no-double-count rule
	// (SPEC §13.2.1, Record.Countable).
	HasTotals
)

// Status is a stored record's (or raw set's) decode status (SPEC §13.3's
// status filter).
type Status uint8

// Statuses. Records are StatusOK or StatusLate; raw sets are StatusNoTemplate
// or StatusMalformed.
const (
	StatusOK Status = iota
	StatusLate
	StatusNoTemplate
	StatusMalformed
)

var statusNames = [...]string{"ok", "late", "no_template", "malformed"}

func (s Status) String() string {
	if int(s) < len(statusNames) {
		return statusNames[s]
	}
	return "status" + strconv.Itoa(int(s))
}

// StatusNames lists the status filter's values, in order.
func StatusNames() []string { return append([]string(nil), statusNames[:]...) }

// TimeSource says where a record's start and end came from.
type TimeSource uint8

// Time sources (SPEC §13.2): the exporter's own times, or the received time
// (no time in the record, or an exporter clock more than an hour off).
const (
	TimeExporter TimeSource = iota
	TimeReceived
)

func (t TimeSource) String() string {
	if t == TimeReceived {
		return "received"
	}
	return "exporter"
}

// Version is the export protocol a record or template came in.
const (
	V5    = 5
	V9    = 9
	IPFIX = 10
)

// Extra is one IE without a column (an enterprise-specific IE, or one
// Woodshed has no column for), kept as it came (SPEC §13.1.3). PEN is 0 for
// an IANA IE.
type Extra struct {
	PEN   uint32
	ID    uint16
	Value []byte
}

// String is the extra's display form, "pen:id=hex".
func (e Extra) String() string {
	const hexd = "0123456789abcdef"
	var b strings.Builder
	b.WriteString(strconv.FormatUint(uint64(e.PEN), 10))
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(uint64(e.ID), 10))
	b.WriteByte('=')
	for _, c := range e.Value {
		b.WriteByte(hexd[c>>4])
		b.WriteByte(hexd[c&15])
	}
	return b.String()
}

// Record is one stored flow or event record. Times are unix milliseconds UTC.
type Record struct {
	Has uint64 // the Has* bits

	Received  int64 // when Woodshed read the datagram (the original one for a late decode)
	Start     int64 // flow start (HasStart); an event-only record has Start = End = EventTime
	End       int64 // flow end (HasEnd)
	EventTime int64 // observationTimeMilliseconds or a v9 event time (HasEventTime)

	Src, Dst         netip.Addr // pre-NAT; IPv4 in its 4-byte form
	SrcPort, DstPort uint16
	Proto            uint8
	TCPFlags         uint16 // tcpControlBits: FIN 0x01 … CWR 0x80, NS 0x100
	ToS              uint8
	Packets, Bytes   uint64 // as exported (deltas, or totals with HasTotals)
	InIf, OutIf      uint32
	InIfName         string // from the exporter's options data in force when it arrived
	OutIfName        string
	SrcAS, DstAS     uint32
	NextHop          netip.Addr
	VLAN             uint16
	Direction        uint8 // flowDirection: 0 ingress, 1 egress
	EndReason        uint8 // flowEndReason

	FwEvent        uint8 // firewallEvent (233): 1 created, 2 deleted, 3 denied, 4 alert, 5 update
	NatEvent       uint8 // natEvent (230)
	PostNATSrc     netip.Addr
	PostNATDst     netip.Addr
	PostNATSrcPort uint16
	PostNATDstPort uint16

	InitiatorBytes, ResponderBytes     uint64
	InitiatorPackets, ResponderPackets uint64
	RevBytes, RevPackets               uint64 // RFC 5103 reverse counters
	RuleID                             string // from listeners.flow.rule_id_ies

	// Sampling is 1 (unsampled), N (1 in N) or 0 (unknown: the exporter said
	// nothing). Never scaled silently (SPEC §13.1.2).
	Sampling uint32
	// Domain is the IPFIX observation domain ID or the v9 source ID (0 for v5).
	Domain uint32
	// ExporterPort is the exporter's UDP source port (part of the template key).
	ExporterPort uint16
	Version      uint8  // V5, V9 or IPFIX
	TemplateID   uint16 // 0 for v5
	// Template is the definition this record was decoded with (nil for v5).
	// Shared and immutable: a segment stores each distinct one once.
	Template *Template

	Status     Status
	TimeSource TimeSource
	Extras     []Extra
}

// Is reports whether every bit of mask is set in Has.
func (r *Record) Is(mask uint64) bool { return r.Has&mask == mask }

// Firewall event values (firewallEvent, IE 233).
const (
	FwCreated = 1
	FwDeleted = 2
	FwDenied  = 3
	FwAlert   = 4
	FwUpdate  = 5
)

var fwEventNames = [...]string{"", "created", "deleted", "denied", "alert", "update"}

// FwEventName is a firewall event's name ("created", …), or its number.
func FwEventName(v uint8) string {
	if v > 0 && int(v) < len(fwEventNames) {
		return fwEventNames[v]
	}
	return strconv.Itoa(int(v))
}

// FwEventNames lists the named firewall events, in value order.
func FwEventNames() []string { return append([]string(nil), fwEventNames[1:]...) }

// ParseFwEvent reads a firewall event name or number 0–255.
func ParseFwEvent(s string) (uint8, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range fwEventNames {
		if i > 0 && n == s {
			return uint8(i), true
		}
	}
	return parseByte(s)
}

// NAT event values (natEvent, IE 230; RFC 8158 and the IANA registry).
var natEventNames = [...]string{
	"", "nat_create", "nat_delete", "addresses_exhausted", "nat44_session_create", "nat44_session_delete",
	"nat64_session_create", "nat64_session_delete", "nat44_bib_create", "nat44_bib_delete", "nat64_bib_create",
	"nat64_bib_delete", "ports_exhausted", "quota_exceeded", "address_binding_create", "address_binding_delete",
	"port_block_allocation", "port_block_deallocation", "threshold_reached",
}

// NatEventName is a NAT event's registry name, or its number.
func NatEventName(v uint8) string {
	if v > 0 && int(v) < len(natEventNames) {
		return natEventNames[v]
	}
	return strconv.Itoa(int(v))
}

// NatEventNames lists the named NAT events, in value order.
func NatEventNames() []string { return append([]string(nil), natEventNames[1:]...) }

// ParseNatEvent reads a NAT event name or number 0–255.
func ParseNatEvent(s string) (uint8, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for i, n := range natEventNames {
		if i > 0 && n == s {
			return uint8(i), true
		}
	}
	return parseByte(s)
}

// NATCreate reports whether a NAT event value creates a translation (counted
// as a translated connection in the bundle README).
func NATCreate(v uint8) bool { return v == 1 || v == 4 || v == 6 }

var protoNames = map[uint8]string{1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp", 58: "icmpv6", 132: "sctp"}

// ProtoName is a protocol's name ("tcp"), or its number.
func ProtoName(p uint8) string {
	if n, ok := protoNames[p]; ok {
		return n
	}
	return strconv.Itoa(int(p))
}

// ParseProto reads a protocol name or number 0–255.
func ParseProto(s string) (uint8, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	for p, n := range protoNames {
		if n == s {
			return p, true
		}
	}
	return parseByte(s)
}

func parseByte(s string) (uint8, bool) {
	n, err := strconv.ParseUint(s, 10, 8)
	if err != nil {
		return 0, false
	}
	return uint8(n), true
}

// TCP flag letters, lowest bit first: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
var tcpFlagNames = [...]string{"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}

// TCPFlagLetters is the CSV's form of tcp flags: the letters of the set bits
// in the order S A F R P U E C ("SAF"), as common flow tools print them.
func TCPFlagLetters(f uint16) string {
	order := []uint16{0x02, 0x10, 0x01, 0x04, 0x08, 0x20, 0x40, 0x80}
	letters := "SAFRPUEC"
	var b []byte
	for i, bit := range order {
		if f&bit != 0 {
			b = append(b, letters[i])
		}
	}
	return string(b)
}

// ParseTCPFlags reads a comma list of flag names (fin, syn, rst, psh, ack,
// urg, ece, cwr) into a mask.
func ParseTCPFlags(s string) (uint16, bool) {
	var m uint16
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		ok := false
		for i, n := range tcpFlagNames {
			if n == p {
				m |= 1 << i
				ok = true
			}
		}
		if !ok {
			return 0, false
		}
	}
	return m, true
}

// TCPFlagNames lists the tcp_flags filter's names, lowest bit first.
func TCPFlagNames() []string { return append([]string(nil), tcpFlagNames[:]...) }

// Countable reports whether a record's Bytes and Packets add to sums under
// SPEC §13.2.1's no-double-count rule: deltas always do; totals (and the
// initiator and responder counts) only on a final record, a deleted event or
// a non-event record. created, update and denied records keep their counts
// but add nothing.
func (r *Record) Countable() bool {
	if !r.Is(HasFwEvent) {
		return true
	}
	if !r.Is(HasTotals) && !(r.Has&(HasBytes|HasPackets) == 0 && r.Has&(HasInitiatorBytes|HasResponderBytes) != 0) {
		// Delta counters add as usual, events or not.
		return true
	}
	return r.FwEvent == FwDeleted
}

// SumBytes and SumPackets are what a record adds to a forward-direction sum
// (zero when it isn't Countable): its bytes, else the initiator count.
func (r *Record) SumBytes() uint64 {
	if !r.Countable() {
		return 0
	}
	if r.Is(HasBytes) {
		return r.Bytes
	}
	if r.Is(HasInitiatorBytes) {
		return r.InitiatorBytes
	}
	return 0
}

// SumPackets: see SumBytes.
func (r *Record) SumPackets() uint64 {
	if !r.Countable() {
		return 0
	}
	if r.Is(HasPackets) {
		return r.Packets
	}
	if r.Is(HasInitiatorPackets) {
		return r.InitiatorPackets
	}
	return 0
}

// ConvBytes is what a record adds to a conversation (both directions): its
// bytes plus the reverse counter, else initiator plus responder (SPEC
// §13.2.1).
func (r *Record) ConvBytes() uint64 {
	if !r.Countable() {
		return 0
	}
	if r.Is(HasBytes) {
		return r.Bytes + r.opt(HasRevBytes, r.RevBytes)
	}
	return r.opt(HasInitiatorBytes, r.InitiatorBytes) + r.opt(HasResponderBytes, r.ResponderBytes)
}

// opt is v when the record has the column, else 0.
func (r *Record) opt(bit, v uint64) uint64 {
	if r.Has&bit != 0 {
		return v
	}
	return 0
}

// ConvPackets: see ConvBytes.
func (r *Record) ConvPackets() uint64 {
	if !r.Countable() {
		return 0
	}
	if r.Is(HasPackets) {
		return r.Packets + r.opt(HasRevPackets, r.RevPackets)
	}
	return r.opt(HasInitiatorPackets, r.InitiatorPackets) + r.opt(HasResponderPackets, r.ResponderPackets)
}

// IsConnection reports whether a record counts toward the connections metric:
// deleted and denied events for an event-style record, every other record.
func (r *Record) IsConnection() bool {
	if !r.Is(HasFwEvent) {
		return true
	}
	return r.FwEvent == FwDeleted || r.FwEvent == FwDenied
}

// TemplateField is one field of a template.
type TemplateField struct {
	PEN    uint32 // enterprise number; 0 for an IANA IE
	ID     uint16 // the element ID (without the enterprise bit)
	Length uint16 // 65535 is variable length (IPFIX)
}

// Template is a template definition as an exporter sent it (SPEC §13.1.2).
// Immutable once decoded; records share it.
type Template struct {
	Version      uint8 // V9 or IPFIX
	ExporterPort uint16
	Domain       uint32
	ID           uint16
	Options      bool
	ScopeCount   int // options templates: how many of Fields are scope fields
	Fields       []TemplateField
	Received     int64 // when this definition arrived (unix ms)
}

// RawSet is a set (or a whole packet) stored undecoded (SPEC §13.1.3): data
// whose template never arrived, or a malformed packet with what came after the
// break.
type RawSet struct {
	Received int64
	// Exporter is the exporter's source address (unmapped): the device the
	// set belongs to.
	Exporter     netip.Addr
	ExporterPort uint16
	Domain       uint32
	Version      uint8
	TemplateID   uint16 // the set ID it needed (0 for a malformed packet)
	Status       Status // StatusNoTemplate or StatusMalformed
	// Header is the export header the set came in (sequence, times), so a
	// later decode can convert times; Data is the set's bytes (or the packet's).
	Header []byte
	Data   []byte
}
