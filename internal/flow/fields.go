package flow

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
)

// A template is compiled once into a plan: one op per field, so decoding a
// record is a loop over the fields with a switch, no map lookups.

type op uint8

const (
	opExtra op = iota // no column: kept in Extras
	opDrop            // a redundant form of a column already set (a second time IE)
	opBytesDelta
	opPktsDelta
	opBytesTotal
	opPktsTotal
	opProto
	opToS
	opTCPFlags
	opSrcPort
	opDstPort
	opSrc
	opDst
	opInIf
	opOutIf
	opNextHop
	opSrcAS
	opDstAS
	opVLAN
	opDirection
	opEndReason
	opFwEvent
	opNatEvent
	opPostSrc
	opPostDst
	opPostSrcPort
	opPostDstPort
	opInitBytes
	opRespBytes
	opInitPkts
	opRespPkts
	opRevBytes
	opRevPkts
	// times
	opStartSec
	opEndSec
	opStartMs
	opEndMs
	opStartNTPUs // dateTimeMicroseconds: NTP format
	opEndNTPUs
	opStartNTPNs
	opEndNTPNs
	opStartDeltaUs
	opEndDeltaUs
	opStartUptime
	opEndUptime
	opSysInit
	opDurMs
	opDurUs
	opObsSec
	opObsMs
	opObsNTPUs
	opObsNTPNs
	// sampling
	opSampInterval
	opSamplerID
	opSampPktInterval
	opSampPktSpace
	opSampSize
	opSampPop
	opSampProb
	opRule // a rule_id IE (rank in the plan's rule list)
)

// Varlen is a variable-length field's length in a template (IPFIX).
const Varlen = 65535

type fieldOp struct {
	op   op
	rank uint8 // opRule: the IE's position in rule_id_ies
	pen  uint32
	id   uint16
	n    uint16 // the template's length (Varlen for variable)
}

// plan is a compiled template.
type plan struct {
	t      *Template
	ops    []fieldOp
	minLen int // the shortest a record can be (variable fields at 1 byte)
	fixed  bool
	gen    uint64 // the settings generation it was compiled for
}

// numOK reports whether an unsigned field of length n can hold a column.
func numOK(n uint16) bool { return n >= 1 && n <= 8 }

// classify returns the op for one template field (rules aside).
func classify(f TemplateField) op {
	n := f.Length
	if f.PEN == PENReverse {
		switch f.ID {
		case ieOctetDelta, ieOctetTotal:
			if numOK(n) {
				return opRevBytes
			}
		case iePacketDelta, iePacketTotal:
			if numOK(n) {
				return opRevPkts
			}
		}
		return opExtra
	}
	if f.PEN != 0 {
		return opExtra
	}
	addr := func(v4, v6 op) op {
		switch n {
		case 4:
			return v4
		case 16:
			return v6
		}
		return opExtra
	}
	num := func(o op) op {
		if numOK(n) {
			return o
		}
		return opExtra
	}
	ntp := func(o op) op {
		if n == 8 {
			return o
		}
		return opExtra
	}
	switch f.ID {
	case ieOctetDelta:
		return num(opBytesDelta)
	case iePacketDelta:
		return num(opPktsDelta)
	case ieOctetTotal:
		return num(opBytesTotal)
	case iePacketTotal:
		return num(opPktsTotal)
	case ieProto:
		return num(opProto)
	case ieToS:
		return num(opToS)
	case ieTCPFlags:
		return num(opTCPFlags)
	case ieSrcPort:
		return num(opSrcPort)
	case ieDstPort:
		return num(opDstPort)
	case ieSrcV4:
		return addr(opSrc, opExtra)
	case ieSrcV6:
		return addr(opExtra, opSrc)
	case ieDstV4:
		return addr(opDst, opExtra)
	case ieDstV6:
		return addr(opExtra, opDst)
	case ieInIf:
		return num(opInIf)
	case ieOutIf:
		return num(opOutIf)
	case ieNextHopV4:
		return addr(opNextHop, opExtra)
	case ieNextHopV6:
		return addr(opExtra, opNextHop)
	case ieSrcAS:
		return num(opSrcAS)
	case ieDstAS:
		return num(opDstAS)
	case ieVLAN:
		return num(opVLAN)
	case ieDirection:
		return num(opDirection)
	case ieEndReason:
		return num(opEndReason)
	case ieFwEvent:
		return num(opFwEvent)
	case ieNatEvent:
		return num(opNatEvent)
	case iePostNATSrcV4:
		return addr(opPostSrc, opExtra)
	case iePostNATSrcV6:
		return addr(opExtra, opPostSrc)
	case iePostNATDstV4:
		return addr(opPostDst, opExtra)
	case iePostNATDstV6:
		return addr(opExtra, opPostDst)
	case iePostNAPTSrcPort:
		return num(opPostSrcPort)
	case iePostNAPTDstPort:
		return num(opPostDstPort)
	case ieInitiatorOctets:
		return num(opInitBytes)
	case ieResponderOctets:
		return num(opRespBytes)
	case ieInitiatorPackets:
		return num(opInitPkts)
	case ieResponderPackets:
		return num(opRespPkts)
	case ieStartSec:
		return num(opStartSec)
	case ieEndSec:
		return num(opEndSec)
	case ieStartMs:
		return num(opStartMs)
	case ieEndMs:
		return num(opEndMs)
	case ieStartUs:
		return ntp(opStartNTPUs)
	case ieEndUs:
		return ntp(opEndNTPUs)
	case ieStartNs:
		return ntp(opStartNTPNs)
	case ieEndNs:
		return ntp(opEndNTPNs)
	case ieStartDeltaUs:
		return num(opStartDeltaUs)
	case ieEndDeltaUs:
		return num(opEndDeltaUs)
	case ieStartUptime:
		return num(opStartUptime)
	case ieEndUptime:
		return num(opEndUptime)
	case ieSysInitMs:
		return num(opSysInit)
	case ieDurationMs:
		return num(opDurMs)
	case ieDurationUs:
		return num(opDurUs)
	case ieObsTimeSec:
		return num(opObsSec)
	case ieObsTimeMs:
		return num(opObsMs)
	case ieObsTimeUs:
		return ntp(opObsNTPUs)
	case ieObsTimeNs:
		return ntp(opObsNTPNs)
	case ieSamplingInterval:
		return num(opSampInterval)
	case ieSamplerID, ieSelectorID:
		return num(opSamplerID)
	case ieSamplingPacketInterval:
		return num(opSampPktInterval)
	case ieSamplingPacketSpace:
		return num(opSampPktSpace)
	case ieSamplingSize:
		return num(opSampSize)
	case ieSamplingPopulation:
		return num(opSampPop)
	case ieSamplingProbability:
		if n == 4 || n == 8 {
			return opSampProb
		}
	}
	return opExtra
}

// timeRank orders the forms of one time: the most precise absolute form
// wins, and any other form present is redundant (opDrop).
func timeRank(o op) (slot, rank int) {
	switch o {
	case opStartNTPNs:
		return 1, 6
	case opStartNTPUs:
		return 1, 5
	case opStartMs:
		return 1, 4
	case opStartSec:
		return 1, 3
	case opStartUptime:
		return 1, 2
	case opStartDeltaUs:
		return 1, 1
	case opEndNTPNs:
		return 2, 6
	case opEndNTPUs:
		return 2, 5
	case opEndMs:
		return 2, 4
	case opEndSec:
		return 2, 3
	case opEndUptime:
		return 2, 2
	case opEndDeltaUs:
		return 2, 1
	case opObsNTPNs:
		return 3, 4
	case opObsNTPUs:
		return 3, 3
	case opObsMs:
		return 3, 2
	case opObsSec:
		return 3, 1
	case opDurUs:
		return 4, 1
	case opDurMs:
		return 4, 2
	}
	return 0, 0
}

// compile builds a template's plan. rules are the rule_id IEs, in priority
// order.
func compile(t *Template, rules []IEKey, gen uint64) *plan {
	p := &plan{t: t, ops: make([]fieldOp, len(t.Fields)), fixed: true, gen: gen}
	best := [5]int{-1, -1, -1, -1, -1}
	bestRank := [5]int{}
	for i, f := range t.Fields {
		fo := fieldOp{pen: f.PEN, id: f.ID, n: f.Length}
		if t.Options && i < t.ScopeCount {
			fo.op = opExtra
		} else {
			fo.op = classify(f)
			for r, k := range rules {
				if k.PEN == f.PEN && k.ID == f.ID && r < 255 {
					fo.op, fo.rank = opRule, uint8(r)
					break
				}
			}
		}
		if slot, rank := timeRank(fo.op); slot > 0 {
			if best[slot] >= 0 && p.ops[best[slot]].id == f.ID && p.ops[best[slot]].pen == f.PEN {
				// The same IE twice: the second is kept as it came.
				fo.op = opExtra
			} else if best[slot] < 0 || rank > bestRank[slot] {
				if best[slot] >= 0 {
					p.ops[best[slot]].op = opDrop
				}
				best[slot], bestRank[slot] = i, rank
			} else {
				fo.op = opDrop
			}
		}
		p.ops[i] = fo
		if f.Length == Varlen {
			p.fixed = false
			p.minLen++
		} else {
			p.minLen += int(f.Length)
		}
	}
	return p
}

func beUint(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// ntpToMs converts an NTP-format timestamp (RFC 7011 §6.1.9) to unix ms.
func ntpToMs(v uint64) int64 {
	const ntpEpoch = 2208988800 // seconds from 1900 to 1970
	sec := int64(v>>32) - ntpEpoch
	frac := v & 0xffffffff
	return sec*1000 + int64(frac*1000>>32)
}

// msToNTP is ntpToMs's inverse (for the IPFIX file).
func msToNTP(ms int64) uint64 {
	const ntpEpoch = 2208988800
	sec := ms/1000 + ntpEpoch
	frac := (uint64(ms%1000)<<32 + 999) / 1000
	return uint64(sec)<<32 | frac
}

func addrOf(b []byte) netip.Addr {
	if len(b) == 4 {
		return netip.AddrFrom4([4]byte(b))
	}
	a := netip.AddrFrom16([16]byte(b))
	if a.Is4In6() {
		return a.Unmap()
	}
	return a
}

// hdrCtx is what a record's times are relative to: the export header and
// the domain's system init time.
type hdrCtx struct {
	exportMs  int64 // the header's export time (v9 unix_secs, IPFIX export time), unix ms
	uptimeMs  int64 // v9: the header's sysUptime; -1 when none (IPFIX)
	sysInitMs int64 // IPFIX: systemInitTimeMilliseconds from options data; 0 when unknown
	received  int64
	skewed    bool // the exporter's clock is more than an hour off
}

// recSampling is the sampling a record's own IEs give.
type recSampling struct {
	interval, pktInterval, pktSpace, size, pop uint64
	prob                                       float64
	samplerID                                  uint32
	hasSampler                                 bool
}

func (s *recSampling) rate() uint32 {
	switch {
	case s.interval > 0:
		return clampRate(s.interval)
	case s.pktInterval > 0:
		return clampRate((s.pktInterval + s.pktSpace) / s.pktInterval)
	case s.size > 0 && s.pop >= s.size:
		return clampRate(s.pop / s.size)
	case s.prob > 0 && s.prob <= 1:
		return clampRate(uint64(math.Round(1 / s.prob)))
	}
	return 0
}

func clampRate(v uint64) uint32 {
	if v == 0 {
		return 1
	}
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

var errShort = errors.New("record runs past the set")

// fieldLen reads a field's length at b (handling variable length): the data
// offset and length.
func fieldLen(b []byte, n uint16) (off, l int, err error) {
	if n != Varlen {
		if len(b) < int(n) {
			return 0, 0, errShort
		}
		return 0, int(n), nil
	}
	if len(b) < 1 {
		return 0, 0, errShort
	}
	if b[0] < 255 {
		l = int(b[0])
		off = 1
	} else {
		if len(b) < 3 {
			return 0, 0, errShort
		}
		l = int(binary.BigEndian.Uint16(b[1:3]))
		off = 3
	}
	if len(b) < off+l {
		return 0, 0, errShort
	}
	return off, l, nil
}

// extraRef is a field kept as an extra: its op index and value bounds.
type extraRef struct {
	i    uint16
	s, e int32
}

// decodeRecord decodes one data record at b into r (reset first) and returns
// its length and the sampling its own IEs give (the caller resolves sampling
// and interface names).
func (p *plan) decodeRecord(b []byte, r *Record, h *hdrCtx) (int, recSampling, error) {
	var (
		pos                          int
		startAbs, endAbs, obs        int64
		haveStart, haveEnd, haveObs  bool
		startUp, endUp               uint64
		haveStartUp, haveEndUp       bool
		startDelta, endDelta         uint64
		haveStartDelta, haveEndDelta bool
		dur                          int64
		haveDur                      bool
		sysInit                      = h.sysInitMs
		bytesTot, pktsTot            uint64
		haveBytesTot, havePktsTot    bool
		samp                         recSampling
		ruleRank                     = 256
		ruleVal                      []byte
		ruleVar                      bool
		extraBytes                   int
		exBuf                        [32]extraRef
	)
	extras := exBuf[:0]
	for i := range p.ops {
		fo := &p.ops[i]
		off, l, err := fieldLen(b[pos:], fo.n)
		if err != nil {
			return 0, samp, err
		}
		v := b[pos+off : pos+off+l]
		s0 := pos + off
		pos += off + l
		switch fo.op {
		case opDrop:
			continue
		case opRule:
			if int(fo.rank) < ruleRank {
				ruleRank, ruleVal, ruleVar = int(fo.rank), v, fo.n == Varlen
			}
			// A rule IE also stays in extras, so exports carry it as it came.
			fallthrough
		case opExtra:
			extras = append(extras, extraRef{uint16(i), int32(s0), int32(pos)})
			extraBytes += l
			continue
		}
		u := beUint(v)
		switch fo.op {
		case opBytesDelta:
			r.Bytes, r.Has = u, r.Has|HasBytes
		case opPktsDelta:
			r.Packets, r.Has = u, r.Has|HasPackets
		case opBytesTotal:
			bytesTot, haveBytesTot = u, true
		case opPktsTotal:
			pktsTot, havePktsTot = u, true
		case opProto:
			r.Proto, r.Has = uint8(u), r.Has|HasProto
		case opToS:
			r.ToS, r.Has = uint8(u), r.Has|HasToS
		case opTCPFlags:
			r.TCPFlags, r.Has = uint16(u), r.Has|HasTCPFlags
		case opSrcPort:
			r.SrcPort, r.Has = uint16(u), r.Has|HasSrcPort
		case opDstPort:
			r.DstPort, r.Has = uint16(u), r.Has|HasDstPort
		case opSrc:
			r.Src, r.Has = addrOf(v), r.Has|HasSrc
		case opDst:
			r.Dst, r.Has = addrOf(v), r.Has|HasDst
		case opInIf:
			r.InIf, r.Has = uint32(u), r.Has|HasInIf
		case opOutIf:
			r.OutIf, r.Has = uint32(u), r.Has|HasOutIf
		case opNextHop:
			r.NextHop, r.Has = addrOf(v), r.Has|HasNextHop
		case opSrcAS:
			r.SrcAS, r.Has = uint32(u), r.Has|HasSrcAS
		case opDstAS:
			r.DstAS, r.Has = uint32(u), r.Has|HasDstAS
		case opVLAN:
			r.VLAN, r.Has = uint16(u), r.Has|HasVLAN
		case opDirection:
			r.Direction, r.Has = uint8(u), r.Has|HasDirection
		case opEndReason:
			r.EndReason, r.Has = uint8(u), r.Has|HasEndReason
		case opFwEvent:
			r.FwEvent, r.Has = uint8(u), r.Has|HasFwEvent
		case opNatEvent:
			r.NatEvent, r.Has = uint8(u), r.Has|HasNatEvent
		case opPostSrc:
			r.PostNATSrc, r.Has = addrOf(v), r.Has|HasPostNATSrc
		case opPostDst:
			r.PostNATDst, r.Has = addrOf(v), r.Has|HasPostNATDst
		case opPostSrcPort:
			r.PostNATSrcPort, r.Has = uint16(u), r.Has|HasPostNATSrcPort
		case opPostDstPort:
			r.PostNATDstPort, r.Has = uint16(u), r.Has|HasPostNATDstPort
		case opInitBytes:
			r.InitiatorBytes, r.Has = u, r.Has|HasInitiatorBytes
		case opRespBytes:
			r.ResponderBytes, r.Has = u, r.Has|HasResponderBytes
		case opInitPkts:
			r.InitiatorPackets, r.Has = u, r.Has|HasInitiatorPackets
		case opRespPkts:
			r.ResponderPackets, r.Has = u, r.Has|HasResponderPackets
		case opRevBytes:
			r.RevBytes, r.Has = u, r.Has|HasRevBytes
		case opRevPkts:
			r.RevPackets, r.Has = u, r.Has|HasRevPackets
		case opStartSec:
			startAbs, haveStart = int64(u)*1000, true
		case opEndSec:
			endAbs, haveEnd = int64(u)*1000, true
		case opStartMs:
			startAbs, haveStart = int64(u&(1<<62-1)), true
		case opEndMs:
			endAbs, haveEnd = int64(u&(1<<62-1)), true
		case opStartNTPUs, opStartNTPNs:
			startAbs, haveStart = ntpToMs(u), true
		case opEndNTPUs, opEndNTPNs:
			endAbs, haveEnd = ntpToMs(u), true
		case opStartDeltaUs:
			startDelta, haveStartDelta = u, true
		case opEndDeltaUs:
			endDelta, haveEndDelta = u, true
		case opStartUptime:
			startUp, haveStartUp = u, true
		case opEndUptime:
			endUp, haveEndUp = u, true
		case opSysInit:
			sysInit = int64(u & (1<<62 - 1))
		case opDurMs:
			dur, haveDur = int64(min(u, 1<<40)), true
		case opDurUs:
			dur, haveDur = int64(min(u, 1<<50)/1000), true
		case opObsSec:
			obs, haveObs = int64(u)*1000, true
		case opObsMs:
			obs, haveObs = int64(u&(1<<62-1)), true
		case opObsNTPUs, opObsNTPNs:
			obs, haveObs = ntpToMs(u), true
		case opSampInterval:
			samp.interval = u
		case opSamplerID:
			samp.samplerID, samp.hasSampler = uint32(u), true
		case opSampPktInterval:
			samp.pktInterval = u
		case opSampPktSpace:
			samp.pktSpace = u
		case opSampSize:
			samp.size = u
		case opSampPop:
			samp.pop = u
		case opSampProb:
			if l == 4 {
				samp.prob = float64(math.Float32frombits(uint32(u)))
			} else {
				samp.prob = math.Float64frombits(u)
			}
		}
	}
	// Totals fill bytes and packets (marked HasTotals) only when the record
	// has no delta counter at all; otherwise they're kept as extras.
	if r.Has&(HasBytes|HasPackets) == 0 && (haveBytesTot || havePktsTot) {
		if haveBytesTot {
			r.Bytes, r.Has = bytesTot, r.Has|HasBytes
		}
		if havePktsTot {
			r.Packets, r.Has = pktsTot, r.Has|HasPackets
		}
		r.Has |= HasTotals
	} else {
		if haveBytesTot {
			r.Extras = appendExtraU64(r.Extras, 0, ieOctetTotal, bytesTot)
		}
		if havePktsTot {
			r.Extras = appendExtraU64(r.Extras, 0, iePacketTotal, pktsTot)
		}
	}
	if ruleVal != nil {
		r.RuleID, r.Has = RuleIDText(ruleVal, ruleVar), r.Has|HasRuleID
	}
	if len(extras) > 0 {
		arena := make([]byte, 0, extraBytes)
		ex := make([]Extra, 0, len(extras)+len(r.Extras))
		for _, x := range extras {
			s := len(arena)
			arena = append(arena, b[x.s:x.e]...)
			fo := &p.ops[x.i]
			ex = append(ex, Extra{PEN: fo.pen, ID: fo.id, Value: arena[s:len(arena):len(arena)]})
		}
		r.Extras = append(ex, r.Extras...)
	}

	// Times.
	if haveStartUp || haveEndUp {
		var base int64
		ok := true
		switch {
		case h.uptimeMs >= 0:
			base = h.exportMs - h.uptimeMs
		case sysInit > 0:
			base = sysInit
		default:
			ok = false
		}
		if ok {
			// v9 times are relative to the header's uptime (modulo 2^32 ms);
			// IPFIX ones to the system init time.
			conv := func(up uint64) int64 {
				if h.uptimeMs >= 0 {
					return h.exportMs - int64(int32(uint32(h.uptimeMs)-uint32(up)))
				}
				return base + int64(uint32(up))
			}
			if haveStartUp && !haveStart {
				startAbs, haveStart = conv(startUp), true
			}
			if haveEndUp && !haveEnd {
				endAbs, haveEnd = conv(endUp), true
			}
		}
	}
	if haveStartDelta && !haveStart {
		startAbs, haveStart = h.exportMs-int64(startDelta/1000), true
	}
	if haveEndDelta && !haveEnd {
		endAbs, haveEnd = h.exportMs-int64(endDelta/1000), true
	}
	if haveDur {
		switch {
		case haveStart && !haveEnd:
			endAbs, haveEnd = startAbs+dur, true
		case haveEnd && !haveStart:
			startAbs, haveStart = endAbs-dur, true
		}
	}
	if haveObs {
		r.EventTime, r.Has = obs, r.Has|HasEventTime
	}
	switch {
	case haveStart && !haveEnd:
		endAbs, haveEnd = startAbs, true
	case haveEnd && !haveStart:
		startAbs, haveStart = endAbs, true
	case !haveStart && !haveEnd && haveObs:
		startAbs, endAbs, haveStart, haveEnd = obs, obs, true, true
	}
	if haveStart {
		if endAbs < startAbs {
			startAbs, endAbs = endAbs, startAbs
		}
		r.Start, r.End = startAbs, endAbs
		r.Has |= HasStart | HasEnd
		if h.skewed {
			skewToReceived(r, h.received)
		}
	} else {
		r.Start, r.End = h.received, h.received
		r.Has |= HasStart | HasEnd
		r.TimeSource = TimeReceived
	}
	return pos, samp, nil
}

// skewToReceived puts a record from an exporter whose clock is more than an
// hour off on received time (SPEC §13.2): the end becomes the received time,
// the start keeps the duration, an event time becomes the received time, and
// the exporter's own times are kept in extras as flowStartMilliseconds,
// flowEndMilliseconds and observationTimeMilliseconds.
func skewToReceived(r *Record, received int64) {
	r.Extras = appendExtraU64(r.Extras, 0, ieStartMs, uint64(r.Start))
	r.Extras = appendExtraU64(r.Extras, 0, ieEndMs, uint64(r.End))
	d := r.End - r.Start
	r.End = received
	r.Start = received - min(d, 24*3600*1000)
	if r.Is(HasEventTime) {
		r.Extras = appendExtraU64(r.Extras, 0, ieObsTimeMs, uint64(r.EventTime))
		r.EventTime = received
	}
	r.TimeSource = TimeReceived
}

func appendExtraU64(ex []Extra, pen uint32, id uint16, v uint64) []Extra {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return append(ex, Extra{PEN: pen, ID: id, Value: b})
}

// isTimeIE reports whether an IANA IE is one of the time forms (the IPFIX
// file reader uses it to recognise a received-time record's kept times).
func isTimeIE(id uint16) bool {
	switch id {
	case ieStartMs, ieEndMs, ieObsTimeMs:
		return true
	}
	return false
}

// RuleIDText renders a rule_id IE's value (decided (build, 2026-11-16)): a
// fixed-length field of 1 to 8 bytes as an unsigned big-endian integer in
// decimal; otherwise (variable length, or longer) printable ASCII as text
// with trailing NULs trimmed, else lower-case hex.
func RuleIDText(v []byte, varlen bool) string {
	if !varlen && len(v) >= 1 && len(v) <= 8 {
		return uitoa(beUint(v))
	}
	t := v
	for len(t) > 0 && t[len(t)-1] == 0 {
		t = t[:len(t)-1]
	}
	printable := len(t) > 0
	for _, c := range t {
		if c < 0x20 || c > 0x7e {
			printable = false
			break
		}
	}
	if printable {
		return string(t)
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 2*len(v))
	for _, c := range v {
		out = append(out, hexd[c>>4], hexd[c&15])
	}
	return string(out)
}

func uitoa(v uint64) string {
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
		if v == 0 {
			break
		}
	}
	return string(b[i:])
}
