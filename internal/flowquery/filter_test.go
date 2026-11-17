package flowquery

import (
	"errors"
	"net/netip"
	"net/url"
	"testing"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
)

func parseQ(t *testing.T, q string) *Filter {
	t.Helper()
	v, err := url.ParseQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(v.Get)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return f
}

func rec() *flow.Record {
	return &flow.Record{
		Has: flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto | flow.HasTCPFlags |
			flow.HasInIf | flow.HasOutIf | flow.HasInIfName | flow.HasBytes | flow.HasPackets | flow.HasStart | flow.HasEnd,
		Src: netip.MustParseAddr("10.20.0.5"), Dst: netip.MustParseAddr("198.51.100.7"), SrcPort: 51544, DstPort: 443,
		Proto: 6, TCPFlags: 0x1b, InIf: 3, InIfName: "eth3", OutIf: 1, Bytes: 1000, Packets: 10, Sampling: 1000, Domain: 1,
		Start: 1000, End: 5000,
	}
}

func TestFilterMatch(t *testing.T) {
	r := rec()
	ev := &flow.Record{Has: flow.HasSrc | flow.HasDst | flow.HasFwEvent | flow.HasPostNATSrc | flow.HasRuleID | flow.HasEventTime | flow.HasNatEvent,
		Src: netip.MustParseAddr("203.0.113.50"), Dst: netip.MustParseAddr("192.0.2.1"), FwEvent: flow.FwDenied,
		PostNATSrc: netip.MustParseAddr("192.0.2.10"), RuleID: "acl-7", NatEvent: 4, Sampling: 1}
	for q, want := range map[string][2]bool{
		"":                                {true, true},
		"src=10.20.0.0/16":                {true, false},
		"src=10.20.0.5":                   {true, false},
		"dst=10.20.0.5":                   {false, false},
		"ip=198.51.100.7,192.0.2.1":       {true, true},
		"exclude_ip=198.51.100.0/24":      {false, true},
		"dst_port=400-500":                {true, false},
		"port=51544":                      {true, false},
		"exclude_port=443":                {false, true},
		"proto=tcp":                       {true, false},
		"proto=17,6":                      {true, false},
		"exclude_proto=tcp":               {false, true},
		"in_if=3":                         {true, false},
		"in_if=ETH3":                      {true, false},
		"out_if=eth1":                     {false, false},
		"exclude_in_if=3":                 {false, true},
		"domain=1":                        {true, false},
		"tcp_flags=syn":                   {true, false},
		"tcp_flags=rst,urg":               {false, false},
		"sampled=yes":                     {true, false},
		"sampled=no":                      {false, true},
		"status=ok":                       {true, true},
		"status=late":                     {false, false},
		"fw_event=denied":                 {false, true},
		"fw_event=3":                      {false, true},
		"fw_event=none":                   {false, false},
		"nat_event=nat44_session_create":  {false, true},
		"post_nat_src=192.0.2.0/24":       {false, true},
		"post_nat_ip=192.0.2.10":          {false, true},
		"exclude_post_nat_src=192.0.2.10": {true, false},
		"ip_any=192.0.2.10":               {false, true},
		"ip_any=10.20.0.5":                {true, false},
		"rule_id=acl-7":                   {false, true},
		"exclude_rule_id=acl-7":           {true, false},
	} {
		f := parseQ(t, q)
		if got := [2]bool{f.Match(r), f.Match(ev)}; got != want {
			t.Errorf("%q: %v, want %v", q, got, want)
		}
		if f.Empty() != (q == "") {
			t.Errorf("%q: Empty %v", q, f.Empty())
		}
	}
}

func TestFilterErrors(t *testing.T) {
	for q, param := range map[string]string{
		"src=10.0.0.300": "src", "dst=x/8": "dst", "port=70000": "port", "dst_port=10-5": "dst_port",
		"proto=tcpx": "proto", "fw_event=gone": "fw_event", "nat_event=x": "nat_event", "domain=-1": "domain",
		"tcp_flags=syn,boom": "tcp_flags", "sampled=maybe": "sampled", "status=fine": "status",
		"fw_event=none,denied": "fw_event",
	} {
		v, _ := url.ParseQuery(q)
		_, err := Parse(v.Get)
		var pe *datatype.ParamError
		if !errors.As(err, &pe) || pe.Param != param {
			t.Errorf("%q: %v, want a ParamError on %s", q, err, param)
		}
	}
}

// fakeIndex rules out everything but what it holds.
type fakeIndex struct {
	protos map[uint8]bool
	addrs  map[netip.Addr]bool
	ports  map[uint16]bool
	ifs    map[uint32]bool
}

func (f fakeIndex) HasProto(p uint8) bool         { return f.protos[p] }
func (f fakeIndex) MayHaveAddr(a netip.Addr) bool { return f.addrs[a] }
func (f fakeIndex) MayHavePrefix(p netip.Prefix) bool {
	for a := range f.addrs {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
func (f fakeIndex) MayHavePort(p uint16) bool  { return f.ports[p] }
func (f fakeIndex) MayHaveInIf(i uint32) bool  { return f.ifs[i] }
func (f fakeIndex) MayHaveOutIf(i uint32) bool { return f.ifs[i] }

func TestBlockMay(t *testing.T) {
	b := fakeIndex{protos: map[uint8]bool{6: true}, addrs: map[netip.Addr]bool{netip.MustParseAddr("10.0.0.1"): true},
		ports: map[uint16]bool{443: true}, ifs: map[uint32]bool{3: true}}
	for q, want := range map[string]bool{
		"": true, "proto=udp": false, "proto=udp,tcp": true, "src=10.0.0.1": true, "src=10.0.0.2": false,
		"dst=10.0.0.0/24": true, "dst=10.1.0.0/24": false, "port=443": true, "port=80": false, "port=1-20": false, "port=1-100": true,
		"port=1-1000": true, "in_if=3": true, "in_if=4": false, "in_if=eth9": true, "exclude_src=10.0.0.1": true,
	} {
		if got := parseQ(t, q).BlockMay(b); got != want {
			t.Errorf("%q: %v, want %v", q, got, want)
		}
	}
}
