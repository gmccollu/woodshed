package api

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strconv"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
)

// A flow result's JSON, appended by hand: a listing writes one per record,
// and the reflection-based encoder cost several microseconds each (SPEC
// §13.6, flow listing). The bytes are exactly what encoding/json gives for
// the docs/api.md shape (flowjson_test.go checks them against it): compact,
// keys in order, null for a column the record lacks, and strings escaped as
// encoding/json escapes them (HTML characters too; any string that needs
// escaping goes through encoding/json itself).

// jsonTime is the API's timestamp layout (UTC, milliseconds).
const jsonTime = "2006-01-02T15:04:05.000Z07:00"

// AppendFlowLineJSON appends a flow SearchLine's JSON (as l.MarshalJSON
// gives it) to dst. l.Flow must be set.
func AppendFlowLineJSON(dst []byte, l *SearchLine) []byte {
	dst = append(dst, `{"received":"`...)
	dst = l.Received.UTC().AppendFormat(dst, jsonTime)
	dst = append(dst, `","device_id":`...)
	dst = appendJSONString(dst, l.DeviceID)
	dst = append(dst, `,"type":`...)
	dst = appendJSONString(dst, datatype.Flow)
	dst = append(dst, `,"ref":`...)
	dst = appendJSONString(dst, l.Ref)
	dst = append(dst, `,"fields":`...)
	dst = appendFlowResultJSON(dst, l.Flow)
	return append(dst, '}')
}

// appendJSONString appends s as a JSON string, as encoding/json writes it.
func appendJSONString(dst []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x80 || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			q, _ := json.Marshal(s) // a string always encodes
			return append(dst, q...)
		}
	}
	dst = append(dst, '"')
	dst = append(dst, s...)
	return append(dst, '"')
}

// appendFlowResultJSON appends FlowResult{r}'s JSON.
func appendFlowResultJSON(b []byte, r *flow.Record) []byte {
	t := func(b []byte, key string, bit uint64, ms int64) []byte {
		b = append(b, key...)
		if !r.Is(bit) {
			return append(b, "null"...)
		}
		b = append(b, '"')
		b = time.UnixMilli(ms).UTC().AppendFormat(b, jsonTime)
		return append(b, '"')
	}
	u := func(b []byte, key string, bit uint64, v uint64) []byte {
		b = append(b, key...)
		if !r.Is(bit) {
			return append(b, "null"...)
		}
		return strconv.AppendUint(b, v, 10)
	}
	s := func(b []byte, key string, bit uint64, v string) []byte {
		b = append(b, key...)
		if !r.Is(bit) {
			return append(b, "null"...)
		}
		return appendJSONString(b, v)
	}
	a := func(b []byte, key string, bit uint64, v netip.Addr) []byte {
		b = append(b, key...)
		if !r.Is(bit) {
			return append(b, "null"...)
		}
		if !v.IsValid() || v.Zone() != "" {
			return appendJSONString(b, v.String())
		}
		b = append(b, '"')
		b = v.AppendTo(b) // what String gives for a valid address without a zone
		return append(b, '"')
	}
	b = t(b, `{"start":`, flow.HasStart, r.Start)
	b = t(b, `,"end":`, flow.HasEnd, r.End)
	b = a(b, `,"src":`, flow.HasSrc, r.Src)
	b = u(b, `,"src_port":`, flow.HasSrcPort, uint64(r.SrcPort))
	b = a(b, `,"dst":`, flow.HasDst, r.Dst)
	b = u(b, `,"dst_port":`, flow.HasDstPort, uint64(r.DstPort))
	b = u(b, `,"proto":`, flow.HasProto, uint64(r.Proto))
	b = s(b, `,"proto_name":`, flow.HasProto, flow.ProtoName(r.Proto))
	b = append(b, `,"tcp_flags":`...)
	if r.Is(flow.HasTCPFlags) {
		b = appendJSONString(b, flow.TCPFlagLetters(r.TCPFlags))
	} else {
		b = append(b, "null"...)
	}
	b = u(b, `,"packets":`, flow.HasPackets, r.Packets)
	b = u(b, `,"bytes":`, flow.HasBytes, r.Bytes)
	b = append(b, `,"sampling":`...)
	b = strconv.AppendUint(b, uint64(r.Sampling), 10)
	scaled := func(b []byte, key string, bit uint64, v uint64) []byte {
		if r.Sampling == 0 {
			return append(append(b, key...), "null"...)
		}
		return u(b, key, bit, v*uint64(r.Sampling))
	}
	b = scaled(b, `,"packets_scaled":`, flow.HasPackets, r.Packets)
	b = scaled(b, `,"bytes_scaled":`, flow.HasBytes, r.Bytes)
	b = u(b, `,"in_if":`, flow.HasInIf, uint64(r.InIf))
	b = s(b, `,"in_if_name":`, flow.HasInIfName, r.InIfName)
	b = u(b, `,"out_if":`, flow.HasOutIf, uint64(r.OutIf))
	b = s(b, `,"out_if_name":`, flow.HasOutIfName, r.OutIfName)
	b = append(b, `,"domain":`...)
	b = strconv.AppendUint(b, uint64(r.Domain), 10)
	b = s(b, `,"fw_event":`, flow.HasFwEvent, flow.FwEventName(r.FwEvent))
	b = s(b, `,"nat_event":`, flow.HasNatEvent, flow.NatEventName(r.NatEvent))
	b = t(b, `,"event_time":`, flow.HasEventTime, r.EventTime)
	b = a(b, `,"post_nat_src":`, flow.HasPostNATSrc, r.PostNATSrc)
	b = u(b, `,"post_nat_src_port":`, flow.HasPostNATSrcPort, uint64(r.PostNATSrcPort))
	b = a(b, `,"post_nat_dst":`, flow.HasPostNATDst, r.PostNATDst)
	b = u(b, `,"post_nat_dst_port":`, flow.HasPostNATDstPort, uint64(r.PostNATDstPort))
	b = u(b, `,"initiator_bytes":`, flow.HasInitiatorBytes, r.InitiatorBytes)
	b = u(b, `,"responder_bytes":`, flow.HasResponderBytes, r.ResponderBytes)
	b = u(b, `,"initiator_packets":`, flow.HasInitiatorPackets, r.InitiatorPackets)
	b = u(b, `,"responder_packets":`, flow.HasResponderPackets, r.ResponderPackets)
	b = u(b, `,"rev_bytes":`, flow.HasRevBytes, r.RevBytes)
	b = u(b, `,"rev_packets":`, flow.HasRevPackets, r.RevPackets)
	b = append(b, `,"rule_id":`...)
	b = appendJSONString(b, r.RuleID)
	b = u(b, `,"tos":`, flow.HasToS, uint64(r.ToS))
	b = u(b, `,"src_as":`, flow.HasSrcAS, uint64(r.SrcAS))
	b = u(b, `,"dst_as":`, flow.HasDstAS, uint64(r.DstAS))
	b = append(b, `,"next_hop":`...)
	if r.Is(flow.HasNextHop) {
		b = appendJSONString(b, r.NextHop.String())
	} else {
		b = append(b, `""`...)
	}
	b = append(b, `,"time_source":`...)
	b = appendJSONString(b, r.TimeSource.String())
	b = append(b, `,"status":`...)
	b = appendJSONString(b, r.Status.String())
	b = append(b, `,"late":`...)
	b = strconv.AppendBool(b, r.Status == flow.StatusLate)
	b = append(b, `,"extras":[`...)
	for i, e := range r.Extras {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, `{"pen":`...)
		b = strconv.AppendUint(b, uint64(e.PEN), 10)
		b = append(b, `,"id":`...)
		b = strconv.AppendUint(b, uint64(e.ID), 10)
		b = append(b, `,"hex":"`...)
		b = hex.AppendEncode(b, e.Value)
		b = append(b, `"}`...)
	}
	return append(b, "]}"...)
}
