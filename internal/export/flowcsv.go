package export

import (
	"bytes"
	"encoding/csv"
	"net/netip"
	"strconv"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// flows.csv rows, appended by hand: a listing or an export writes one per
// record, and building a []string for encoding/csv cost about 40
// allocations a row (SPEC §13.6, flow listing). The bytes are encoding/csv's
// with UseCRLF (flowcsv_test.go checks them against it): a row whose cells
// all go unquoted is written here, and any row with a cell encoding/csv
// would quote (a comma, a quote, a line break, a leading space, `\.`) goes
// through encoding/csv itself.

// flowCSVTime is flows.csv's timestamp layout (flowMS).
const flowCSVTime = "2006-01-02T15:04:05.000Z"

// AppendFlowCSVRow appends a record's flows.csv row to dst: RFC 4180 quoting,
// CRLF at the end.
func AppendFlowCSVRow(dst []byte, r *flow.Record) []byte {
	start := len(dst)
	if out, ok := appendFlowCSVPlain(dst, r); ok {
		return out
	}
	var b bytes.Buffer
	cw := csv.NewWriter(&b)
	cw.UseCRLF = true
	_ = cw.Write(FlowCSVRow(r))
	cw.Flush()
	return append(dst[:start], b.Bytes()...)
}

// csvPlain reports whether encoding/csv writes s as it is (fieldNeedsQuotes
// false). A cell starting with a non-ASCII byte counts as quoted (encoding/csv
// quotes a leading Unicode space), so the row takes the slow path.
func csvPlain(s string) bool {
	if s == "" {
		return true
	}
	if s == `\.` {
		return false
	}
	switch s[0] {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return false
	}
	if s[0] >= 0x80 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ',', '"', '\r', '\n':
			return false
		}
	}
	return true
}

// appendFlowCSVPlain appends the row when no cell needs quoting; ok false
// (dst's contents past its length undefined) otherwise.
func appendFlowCSVPlain(b []byte, r *flow.Record) (_ []byte, ok bool) {
	ok = true
	u := func(b []byte, bit uint64, v uint64) []byte {
		if r.Is(bit) {
			b = strconv.AppendUint(b, v, 10)
		}
		return append(b, ',')
	}
	t := func(b []byte, bit uint64, ms int64) []byte {
		if r.Is(bit) {
			b = time.UnixMilli(ms).UTC().AppendFormat(b, flowCSVTime)
		}
		return append(b, ',')
	}
	s := func(b []byte, v string) []byte {
		if !csvPlain(v) {
			ok = false
		}
		return append(append(b, v...), ',')
	}
	str := func(b []byte, bit uint64, v string) []byte {
		if !r.Is(bit) {
			return append(b, ',')
		}
		return s(b, v)
	}
	a := func(b []byte, bit uint64, v netip.Addr) []byte {
		switch {
		case !r.Is(bit):
			return append(b, ',')
		case !v.IsValid() || v.Zone() != "":
			return s(b, v.String())
		}
		return append(v.AppendTo(b), ',') // what String gives: digits, dots, colons
	}
	b = t(b, flow.HasStart, r.Start)
	b = t(b, flow.HasEnd, r.End)
	b = t(b, flow.HasEventTime, r.EventTime)
	b = a(b, flow.HasSrc, r.Src)
	b = u(b, flow.HasSrcPort, uint64(r.SrcPort))
	b = a(b, flow.HasDst, r.Dst)
	b = u(b, flow.HasDstPort, uint64(r.DstPort))
	b = u(b, flow.HasProto, uint64(r.Proto))
	b = str(b, flow.HasTCPFlags, flow.TCPFlagLetters(r.TCPFlags))
	b = u(b, flow.HasPackets, r.Packets)
	b = u(b, flow.HasBytes, r.Bytes)
	b = append(strconv.AppendUint(b, uint64(r.Sampling), 10), ',')
	if r.Sampling > 0 {
		b = u(b, flow.HasPackets, r.Packets*uint64(r.Sampling))
		b = u(b, flow.HasBytes, r.Bytes*uint64(r.Sampling))
	} else {
		b = append(b, ",,"...)
	}
	b = u(b, flow.HasInIf, uint64(r.InIf))
	b = str(b, flow.HasInIfName, r.InIfName)
	b = u(b, flow.HasOutIf, uint64(r.OutIf))
	b = str(b, flow.HasOutIfName, r.OutIfName)
	b = append(strconv.AppendUint(b, uint64(r.Domain), 10), ',')
	b = str(b, flow.HasFwEvent, flow.FwEventName(r.FwEvent))
	b = str(b, flow.HasNatEvent, flow.NatEventName(r.NatEvent))
	b = a(b, flow.HasPostNATSrc, r.PostNATSrc)
	b = u(b, flow.HasPostNATSrcPort, uint64(r.PostNATSrcPort))
	b = a(b, flow.HasPostNATDst, r.PostNATDst)
	b = u(b, flow.HasPostNATDstPort, uint64(r.PostNATDstPort))
	b = u(b, flow.HasInitiatorBytes, r.InitiatorBytes)
	b = u(b, flow.HasResponderBytes, r.ResponderBytes)
	b = u(b, flow.HasInitiatorPackets, r.InitiatorPackets)
	b = u(b, flow.HasResponderPackets, r.ResponderPackets)
	b = u(b, flow.HasRevBytes, r.RevBytes)
	b = u(b, flow.HasRevPackets, r.RevPackets)
	b = str(b, flow.HasRuleID, r.RuleID)
	b = u(b, flow.HasToS, uint64(r.ToS))
	b = u(b, flow.HasSrcAS, uint64(r.SrcAS))
	b = u(b, flow.HasDstAS, uint64(r.DstAS))
	b = a(b, flow.HasNextHop, r.NextHop)
	b = s(b, r.TimeSource.String())
	b = s(b, r.Status.String())
	b = time.UnixMilli(r.Received).UTC().AppendFormat(b, flowCSVTime)
	return append(b, '\r', '\n'), ok
}
