package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
)

// AppendFlowLineJSON must give the reflection-based encoder's bytes exactly
// (the CLI's --json, /api/search's flow results).

type refFlowResult struct{ r *flow.Record }

func (f refFlowResult) MarshalJSON() ([]byte, error) { return refFlowResultJSON(FlowResult{f.r}) }

// refLine is a SearchLine encoded the old way (json.Marshal of the line).
type refLine struct{ l SearchLine }

func (l refLine) MarshalJSON() ([]byte, error) { return refFlowLineJSON(l.l) }

var jsonStrings = []string{"", "Gi0/1", "rule-7", "a<b>&c", `q"uote\back`, "tab\there", "nl\n", "\x00\x1f", "ünï", "  ",
	"bad\xffutf8", "emoji 🙂", "/", "x\x7fy", "line sep"}

func randAddr(rng *rand.Rand) netip.Addr {
	switch rng.IntN(5) {
	case 0:
		return netip.AddrFrom4([4]byte{byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256))})
	case 1:
		var b [16]byte
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		return netip.AddrFrom16(b)
	case 2:
		return netip.MustParseAddr("::ffff:192.0.2.1")
	case 3:
		return netip.MustParseAddr("fe80::1").WithZone([]string{"eth0", "a<b", "z\"q"}[rng.IntN(3)])
	}
	return netip.Addr{} // invalid: never stored, but encoded the same
}

func randFlowRecord(rng *rand.Rand) flow.Record {
	u64 := func() uint64 {
		switch rng.IntN(4) {
		case 0:
			return 0
		case 1:
			return ^uint64(0) - uint64(rng.IntN(3))
		}
		return rng.Uint64() >> rng.IntN(64)
	}
	ms := func() int64 {
		switch rng.IntN(6) {
		case 0:
			return 0
		case 1:
			return -int64(rng.IntN(1 << 40))
		case 2:
			return 253402300799999 + int64(rng.IntN(1000)) // past year 9999
		}
		return 1794930766130 + int64(rng.IntN(1<<30))
	}
	str := func() string { return jsonStrings[rng.IntN(len(jsonStrings))] }
	r := flow.Record{Has: rng.Uint64(), Received: ms(), Start: ms(), End: ms(), EventTime: ms(), Src: randAddr(rng), Dst: randAddr(rng),
		SrcPort: uint16(u64()), DstPort: uint16(u64()), Proto: uint8(u64()), TCPFlags: uint16(u64()), ToS: uint8(u64()),
		Packets: u64(), Bytes: u64(), InIf: uint32(u64()), OutIf: uint32(u64()), InIfName: str(), OutIfName: str(),
		SrcAS: uint32(u64()), DstAS: uint32(u64()), NextHop: randAddr(rng), FwEvent: uint8(rng.IntN(8)), NatEvent: uint8(rng.IntN(20)),
		PostNATSrc: randAddr(rng), PostNATDst: randAddr(rng), PostNATSrcPort: uint16(u64()), PostNATDstPort: uint16(u64()),
		InitiatorBytes: u64(), ResponderBytes: u64(), InitiatorPackets: u64(), ResponderPackets: u64(), RevBytes: u64(),
		RevPackets: u64(), RuleID: str(), Sampling: []uint32{0, 1, 1000, ^uint32(0)}[rng.IntN(4)], Domain: uint32(u64()),
		Status: flow.Status(rng.IntN(6)), TimeSource: flow.TimeSource(rng.IntN(3))}
	if rng.IntN(3) > 0 {
		for range rng.IntN(4) {
			v := make([]byte, rng.IntN(6))
			for i := range v {
				v[i] = byte(rng.IntN(256))
			}
			r.Extras = append(r.Extras, flow.Extra{PEN: uint32(u64()), ID: uint16(u64()), Value: v})
		}
	}
	return r
}

func TestFlowLineJSONMatchesReflection(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	devs := []string{"192.0.2.10", "edge<1>", "dev\"q", "ünï"}
	for i := 0; i < 20000; i++ {
		rec := randFlowRecord(rng)
		if i < 2 {
			rec.Has = []uint64{0, ^uint64(0)}[i]
		}
		l := SearchLine{Received: time.UnixMilli(rec.Received).UTC(), DeviceID: devs[rng.IntN(len(devs))], Type: datatype.Flow,
			Ref: "c2VnfDF8Mg", Flow: &rec}
		want, err := json.Marshal(refLine{l})
		if err != nil {
			t.Fatal(err)
		}
		got := AppendFlowLineJSON([]byte("prefix"), &l)
		if !bytes.Equal(got[6:], want) || string(got[:6]) != "prefix" {
			t.Fatalf("record %d (%s):\n got %s\nwant %s", i, hex.EncodeToString([]byte(rec.RuleID)), got[6:], want)
		}
		viaMarshal, err := json.Marshal(l) // the API's page encoder
		if err != nil || !bytes.Equal(viaMarshal, want) {
			t.Fatalf("record %d: json.Marshal(line):\n got %s\nwant %s (%v)", i, viaMarshal, want, err)
		}
		res, err := json.Marshal(FlowResult{&rec})
		wantRes, _ := json.Marshal(refFlowResult{&rec})
		if err != nil || !bytes.Equal(res, wantRes) {
			t.Fatalf("record %d: FlowResult:\n got %s\nwant %s", i, res, wantRes)
		}
	}
}

func BenchmarkFlowLineJSON(b *testing.B) {
	rec := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto |
		flow.HasTCPFlags | flow.HasBytes | flow.HasPackets | flow.HasInIf | flow.HasOutIf, Received: 1794930766130, Start: 1794930736268,
		End: 1794930766130, Src: netip.MustParseAddr("10.20.1.2"), Dst: netip.MustParseAddr("198.51.100.7"), SrcPort: 40000, DstPort: 443,
		Proto: 6, TCPFlags: 0x1b, Bytes: 123456, Packets: 99, InIf: 3, OutIf: 4, Sampling: 1, Domain: 1}
	l := SearchLine{Received: time.UnixMilli(rec.Received).UTC(), DeviceID: "127.0.0.1", Type: datatype.Flow, Ref: "c2VnfDF8Mg", Flow: &rec}
	b.Run("append", func(b *testing.B) {
		var buf []byte
		for b.Loop() {
			buf = AppendFlowLineJSON(buf[:0], &l)
		}
	})
	b.Run("reflection", func(b *testing.B) {
		for b.Loop() {
			_, _ = json.Marshal(refLine{l})
		}
	})
}

// refFlowResultJSON is the reflection-based encoder AppendFlowLineJSON
// replaced, kept as the tests' reference for its bytes.
func refFlowResultJSON(f FlowResult) ([]byte, error) {
	r := f.r
	type ex struct {
		PEN uint32 `json:"pen"`
		ID  uint16 `json:"id"`
		Hex string `json:"hex"`
	}
	t := func(bit uint64, ms int64) any {
		if !r.Is(bit) {
			return nil
		}
		return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z07:00")
	}
	u := func(bit uint64, v uint64) any {
		if !r.Is(bit) {
			return nil
		}
		return v
	}
	str := func(bit uint64, v string) any {
		if !r.Is(bit) {
			return nil
		}
		return v
	}
	var proto, protoName any
	if r.Is(flow.HasProto) {
		proto, protoName = r.Proto, flow.ProtoName(r.Proto)
	}
	var flags any
	if r.Is(flow.HasTCPFlags) {
		flags = flow.TCPFlagLetters(r.TCPFlags)
	}
	var fw, nat any
	if r.Is(flow.HasFwEvent) {
		fw = flow.FwEventName(r.FwEvent)
	}
	if r.Is(flow.HasNatEvent) {
		nat = flow.NatEventName(r.NatEvent)
	}
	var pScaled, bScaled any
	if r.Sampling > 0 {
		if r.Is(flow.HasPackets) {
			pScaled = r.Packets * uint64(r.Sampling)
		}
		if r.Is(flow.HasBytes) {
			bScaled = r.Bytes * uint64(r.Sampling)
		}
	}
	var nextHop any = ""
	if r.Is(flow.HasNextHop) {
		nextHop = r.NextHop.String()
	}
	extras := make([]ex, 0, len(r.Extras))
	for _, e := range r.Extras {
		extras = append(extras, ex{e.PEN, e.ID, hex.EncodeToString(e.Value)})
	}
	addr := func(bit uint64, v interface{ String() string }) any { return str(bit, v.String()) }
	return json.Marshal(struct {
		Start            any    `json:"start"`
		End              any    `json:"end"`
		Src              any    `json:"src"`
		SrcPort          any    `json:"src_port"`
		Dst              any    `json:"dst"`
		DstPort          any    `json:"dst_port"`
		Proto            any    `json:"proto"`
		ProtoName        any    `json:"proto_name"`
		TCPFlags         any    `json:"tcp_flags"`
		Packets          any    `json:"packets"`
		Bytes            any    `json:"bytes"`
		Sampling         uint32 `json:"sampling"`
		PacketsScaled    any    `json:"packets_scaled"`
		BytesScaled      any    `json:"bytes_scaled"`
		InIf             any    `json:"in_if"`
		InIfName         any    `json:"in_if_name"`
		OutIf            any    `json:"out_if"`
		OutIfName        any    `json:"out_if_name"`
		Domain           uint32 `json:"domain"`
		FwEvent          any    `json:"fw_event"`
		NatEvent         any    `json:"nat_event"`
		EventTime        any    `json:"event_time"`
		PostNATSrc       any    `json:"post_nat_src"`
		PostNATSrcPort   any    `json:"post_nat_src_port"`
		PostNATDst       any    `json:"post_nat_dst"`
		PostNATDstPort   any    `json:"post_nat_dst_port"`
		InitiatorBytes   any    `json:"initiator_bytes"`
		ResponderBytes   any    `json:"responder_bytes"`
		InitiatorPackets any    `json:"initiator_packets"`
		ResponderPackets any    `json:"responder_packets"`
		RevBytes         any    `json:"rev_bytes"`
		RevPackets       any    `json:"rev_packets"`
		RuleID           string `json:"rule_id"`
		ToS              any    `json:"tos"`
		SrcAS            any    `json:"src_as"`
		DstAS            any    `json:"dst_as"`
		NextHop          any    `json:"next_hop"`
		TimeSource       string `json:"time_source"`
		Status           string `json:"status"`
		Late             bool   `json:"late"`
		Extras           []ex   `json:"extras"`
	}{
		t(flow.HasStart, r.Start), t(flow.HasEnd, r.End), addr(flow.HasSrc, r.Src), u(flow.HasSrcPort, uint64(r.SrcPort)),
		addr(flow.HasDst, r.Dst), u(flow.HasDstPort, uint64(r.DstPort)), proto, protoName, flags,
		u(flow.HasPackets, r.Packets), u(flow.HasBytes, r.Bytes), r.Sampling, pScaled, bScaled,
		u(flow.HasInIf, uint64(r.InIf)), str(flow.HasInIfName, r.InIfName), u(flow.HasOutIf, uint64(r.OutIf)),
		str(flow.HasOutIfName, r.OutIfName), r.Domain, fw, nat, t(flow.HasEventTime, r.EventTime),
		addr(flow.HasPostNATSrc, r.PostNATSrc), u(flow.HasPostNATSrcPort, uint64(r.PostNATSrcPort)),
		addr(flow.HasPostNATDst, r.PostNATDst), u(flow.HasPostNATDstPort, uint64(r.PostNATDstPort)),
		u(flow.HasInitiatorBytes, r.InitiatorBytes), u(flow.HasResponderBytes, r.ResponderBytes),
		u(flow.HasInitiatorPackets, r.InitiatorPackets), u(flow.HasResponderPackets, r.ResponderPackets),
		u(flow.HasRevBytes, r.RevBytes), u(flow.HasRevPackets, r.RevPackets), r.RuleID,
		u(flow.HasToS, uint64(r.ToS)), u(flow.HasSrcAS, uint64(r.SrcAS)), u(flow.HasDstAS, uint64(r.DstAS)), nextHop,
		r.TimeSource.String(), r.Status.String(), r.Status == flow.StatusLate, extras,
	})
}

// refFlowLineJSON is flowLineJSON's reflection-based reference.
func refFlowLineJSON(l SearchLine) ([]byte, error) {
	return json.Marshal(struct {
		Received string        `json:"received"`
		DeviceID string        `json:"device_id"`
		Type     string        `json:"type"`
		Ref      string        `json:"ref"`
		Fields   refFlowResult `json:"fields"`
	}{l.Received.UTC().Format("2006-01-02T15:04:05.000Z07:00"), l.DeviceID, datatype.Flow, l.Ref, refFlowResult{l.Flow}})
}
