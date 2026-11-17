package flowseg

import (
	"math/bits"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Cols selects the columns ReadBlock decodes. The optional columns use their
// flow.Has* bit (a decoded record has that Has bit set where the column has a
// value); the always-present ones have their own bits above them.
type Cols uint64

// The always-present columns.
const (
	ColReceived   Cols = 1 << 48
	ColSampling   Cols = 1 << 49
	ColDomain     Cols = 1 << 50 // Record.Domain
	ColMeta       Cols = 1 << 51 // Record.Version and Record.ExporterPort
	ColTemplate   Cols = 1 << 52 // Record.Template and Record.TemplateID
	ColStatus     Cols = 1 << 53
	ColTimeSource Cols = 1 << 54
	ColExtras     Cols = 1 << 55

	// ColOptional is every flow.Has* column.
	ColOptional Cols = Cols(flow.HasTotals<<1 - 1)
	// ColAll decodes everything.
	ColAll = ColOptional | ColReceived | ColSampling | ColDomain | ColMeta | ColTemplate | ColStatus | ColTimeSource | ColExtras
)

// Physical column IDs are the bit positions of Cols; ColDomain and ColMeta
// share one stored column (exporter_domain), and colDict is the block's
// address dictionary.
const (
	colExpDomain = 50 // stores ColDomain and ColMeta
	colDict      = 62
)

type colKind uint8

const (
	kindNone   colKind = iota
	kindTime           // zigzag(v - block min), varints
	kindAddr           // varint index into the block's address dictionary
	kindUint           // varints
	kindByte           // one byte
	kindString         // per-block dictionary + varint index
	kindFlag           // presence only (HasTotals)
)

// kindOf is each optional column's encoding.
var kindOf [64]colKind

func init() {
	set := func(k colKind, cols ...uint64) {
		for _, c := range cols {
			kindOf[bits.TrailingZeros64(c)] = k
		}
	}
	set(kindTime, flow.HasStart, flow.HasEnd, flow.HasEventTime)
	set(kindAddr, flow.HasSrc, flow.HasDst, flow.HasNextHop, flow.HasPostNATSrc, flow.HasPostNATDst)
	set(kindUint, flow.HasSrcPort, flow.HasDstPort, flow.HasTCPFlags, flow.HasPackets, flow.HasBytes, flow.HasInIf,
		flow.HasOutIf, flow.HasSrcAS, flow.HasDstAS, flow.HasVLAN, flow.HasPostNATSrcPort, flow.HasPostNATDstPort,
		flow.HasInitiatorBytes, flow.HasResponderBytes, flow.HasInitiatorPackets, flow.HasResponderPackets,
		flow.HasRevBytes, flow.HasRevPackets)
	set(kindByte, flow.HasProto, flow.HasToS, flow.HasDirection, flow.HasEndReason, flow.HasFwEvent, flow.HasNatEvent)
	set(kindString, flow.HasRuleID, flow.HasInIfName, flow.HasOutIfName)
	set(kindFlag, flow.HasTotals)
	for i := 0; i <= bits.TrailingZeros64(flow.HasTotals); i++ {
		if kindOf[i] == kindNone {
			panic("flowseg: optional column without an encoding")
		}
	}
}

// uintOf and setUint read and write an integer optional column of a record.
func uintOf(r *flow.Record, id int) uint64 {
	switch uint64(1) << id {
	case flow.HasSrcPort:
		return uint64(r.SrcPort)
	case flow.HasDstPort:
		return uint64(r.DstPort)
	case flow.HasTCPFlags:
		return uint64(r.TCPFlags)
	case flow.HasPackets:
		return r.Packets
	case flow.HasBytes:
		return r.Bytes
	case flow.HasInIf:
		return uint64(r.InIf)
	case flow.HasOutIf:
		return uint64(r.OutIf)
	case flow.HasSrcAS:
		return uint64(r.SrcAS)
	case flow.HasDstAS:
		return uint64(r.DstAS)
	case flow.HasVLAN:
		return uint64(r.VLAN)
	case flow.HasPostNATSrcPort:
		return uint64(r.PostNATSrcPort)
	case flow.HasPostNATDstPort:
		return uint64(r.PostNATDstPort)
	case flow.HasInitiatorBytes:
		return r.InitiatorBytes
	case flow.HasResponderBytes:
		return r.ResponderBytes
	case flow.HasInitiatorPackets:
		return r.InitiatorPackets
	case flow.HasResponderPackets:
		return r.ResponderPackets
	case flow.HasRevBytes:
		return r.RevBytes
	case flow.HasRevPackets:
		return r.RevPackets
	case flow.HasProto:
		return uint64(r.Proto)
	case flow.HasToS:
		return uint64(r.ToS)
	case flow.HasDirection:
		return uint64(r.Direction)
	case flow.HasEndReason:
		return uint64(r.EndReason)
	case flow.HasFwEvent:
		return uint64(r.FwEvent)
	case flow.HasNatEvent:
		return uint64(r.NatEvent)
	}
	return 0
}

func setUint(r *flow.Record, id int, v uint64) {
	switch uint64(1) << id {
	case flow.HasSrcPort:
		r.SrcPort = uint16(v)
	case flow.HasDstPort:
		r.DstPort = uint16(v)
	case flow.HasTCPFlags:
		r.TCPFlags = uint16(v)
	case flow.HasPackets:
		r.Packets = v
	case flow.HasBytes:
		r.Bytes = v
	case flow.HasInIf:
		r.InIf = uint32(v)
	case flow.HasOutIf:
		r.OutIf = uint32(v)
	case flow.HasSrcAS:
		r.SrcAS = uint32(v)
	case flow.HasDstAS:
		r.DstAS = uint32(v)
	case flow.HasVLAN:
		r.VLAN = uint16(v)
	case flow.HasPostNATSrcPort:
		r.PostNATSrcPort = uint16(v)
	case flow.HasPostNATDstPort:
		r.PostNATDstPort = uint16(v)
	case flow.HasInitiatorBytes:
		r.InitiatorBytes = v
	case flow.HasResponderBytes:
		r.ResponderBytes = v
	case flow.HasInitiatorPackets:
		r.InitiatorPackets = v
	case flow.HasResponderPackets:
		r.ResponderPackets = v
	case flow.HasRevBytes:
		r.RevBytes = v
	case flow.HasRevPackets:
		r.RevPackets = v
	case flow.HasProto:
		r.Proto = uint8(v)
	case flow.HasToS:
		r.ToS = uint8(v)
	case flow.HasDirection:
		r.Direction = uint8(v)
	case flow.HasEndReason:
		r.EndReason = uint8(v)
	case flow.HasFwEvent:
		r.FwEvent = uint8(v)
	case flow.HasNatEvent:
		r.NatEvent = uint8(v)
	}
}

// uintMax is the largest value an integer column holds (wider values in a
// corrupt or hostile file are refused).
func uintMax(id int) uint64 {
	switch uint64(1) << id {
	case flow.HasPackets, flow.HasBytes, flow.HasInitiatorBytes, flow.HasResponderBytes, flow.HasInitiatorPackets,
		flow.HasResponderPackets, flow.HasRevBytes, flow.HasRevPackets:
		return ^uint64(0)
	case flow.HasInIf, flow.HasOutIf, flow.HasSrcAS, flow.HasDstAS:
		return 1<<32 - 1
	}
	if kindOf[id] == kindByte {
		return 255
	}
	return 1<<16 - 1
}

func timeOf(r *flow.Record, id int) int64 {
	switch uint64(1) << id {
	case flow.HasStart:
		return r.Start
	case flow.HasEnd:
		return r.End
	}
	return r.EventTime
}

func setTime(r *flow.Record, id int, v int64) {
	switch uint64(1) << id {
	case flow.HasStart:
		r.Start = v
	case flow.HasEnd:
		r.End = v
	default:
		r.EventTime = v
	}
}

func stringOf(r *flow.Record, id int) string {
	switch uint64(1) << id {
	case flow.HasRuleID:
		return r.RuleID
	case flow.HasInIfName:
		return r.InIfName
	}
	return r.OutIfName
}

func setString(r *flow.Record, id int, v string) {
	switch uint64(1) << id {
	case flow.HasRuleID:
		r.RuleID = v
	case flow.HasInIfName:
		r.InIfName = v
	default:
		r.OutIfName = v
	}
}
