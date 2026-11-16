// Package flowquery is the flow type's query engine (SPEC §13.3): the flow
// filter, top-N aggregation (exact to 1,000,000 keys, then a space-saving
// top-K), and searches, summaries and top-N over segments, newest first by
// flow end, within a time budget, with progress and complete_from for partial
// answers.
package flowquery

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
)

// Limits on filter lists, so one request can't hold the server.
const (
	MaxListItems = 256
	MaxRuleIDLen = 256
	MaxIfNameLen = 256
)

// PortRange is an inclusive port range (a single port has Lo == Hi).
type PortRange struct{ Lo, Hi uint16 }

func (p PortRange) has(v uint16) bool { return v >= p.Lo && v <= p.Hi }

// IfRef is an interface given by index or by name (from the options data).
type IfRef struct {
	Index uint32
	Name  string // lowercase; "" for an index
}

func (r IfRef) match(idx uint32, name string, hasName bool) bool {
	if r.Name == "" {
		return idx == r.Index
	}
	return hasName && strings.EqualFold(name, r.Name)
}

// Filter is the compiled flow filter. Empty lists match everything.
type Filter struct {
	Src, Dst, IP, ExSrc, ExDst, ExIP, IPAny []netip.Prefix
	PostNATSrc, PostNATDst, PostNATIP       []netip.Prefix
	ExPostNATSrc, ExPostNATDst, ExPostNATIP []netip.Prefix
	SrcPort, DstPort, Port                  []PortRange
	ExSrcPort, ExDstPort, ExPort            []PortRange
	PostNATSrcPort, PostNATDstPort          []PortRange
	Proto, ExProto                          []uint8
	InIf, OutIf, ExInIf, ExOutIf            []IfRef
	Domain                                  []uint32
	TCPFlags                                uint16 // any of
	Sampled                                 []string
	Status                                  []flow.Status
	FwEvent, NatEvent                       []uint8
	RuleID, ExRuleID                        []string
	Nothing                                 bool // a closed set given as "none"
}

func perr(param, msg string) error {
	return &datatype.ParamError{Param: param, Msg: param + ": " + msg}
}

func list(get func(string) string, param string) ([]string, error) {
	var out []string
	for _, v := range strings.Split(get(param), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	if len(out) > MaxListItems {
		return nil, perr(param, fmt.Sprintf("at most %d values.", MaxListItems))
	}
	return out, nil
}

// ParsePrefix reads an address or a CIDR prefix; an address is a /32 or /128.
// IPv4-mapped IPv6 forms are unmapped.
func ParsePrefix(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" {
			return netip.Prefix{}, false
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

func prefixes(get func(string) string, param string) ([]netip.Prefix, error) {
	items, err := list(get, param)
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, it := range items {
		p, ok := ParsePrefix(it)
		if !ok {
			return nil, perr(param, fmt.Sprintf("%q isn't an IP address or a CIDR prefix (e.g. 10.20.0.0/16, 2001:db8::/32).", it))
		}
		out = append(out, p)
	}
	return out, nil
}

// ParsePortRange reads "443" or "8000-8100".
func ParsePortRange(s string) (PortRange, bool) {
	a, b, isRange := strings.Cut(s, "-")
	lo, err := strconv.ParseUint(strings.TrimSpace(a), 10, 16)
	if err != nil {
		return PortRange{}, false
	}
	hi := lo
	if isRange {
		if hi, err = strconv.ParseUint(strings.TrimSpace(b), 10, 16); err != nil || hi < lo {
			return PortRange{}, false
		}
	}
	return PortRange{uint16(lo), uint16(hi)}, true
}

func ports(get func(string) string, param string) ([]PortRange, error) {
	items, err := list(get, param)
	if err != nil {
		return nil, err
	}
	var out []PortRange
	for _, it := range items {
		r, ok := ParsePortRange(it)
		if !ok {
			return nil, perr(param, fmt.Sprintf("%q isn't a port (0–65535) or a range (8000-8100).", it))
		}
		out = append(out, r)
	}
	return out, nil
}

func bytesSet(get func(string) string, param, what string, parse func(string) (uint8, bool), f *Filter) ([]uint8, error) {
	items, err := list(get, param)
	if err != nil {
		return nil, err
	}
	var out []uint8
	for _, it := range items {
		if strings.EqualFold(it, "none") {
			if len(items) > 1 {
				return nil, perr(param, "none can't be combined with other values.")
			}
			f.Nothing = true
			continue
		}
		v, ok := parse(it)
		if !ok {
			return nil, perr(param, fmt.Sprintf("%q isn't %s.", it, what))
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

func ifRefs(get func(string) string, param string) ([]IfRef, error) {
	items, err := list(get, param)
	if err != nil {
		return nil, err
	}
	var out []IfRef
	for _, it := range items {
		if n, err := strconv.ParseUint(it, 10, 32); err == nil {
			out = append(out, IfRef{Index: uint32(n)})
			continue
		}
		if len(it) > MaxIfNameLen {
			return nil, perr(param, fmt.Sprintf("an interface name is at most %d bytes.", MaxIfNameLen))
		}
		out = append(out, IfRef{Name: strings.ToLower(it)})
	}
	return out, nil
}

// Parse reads the flow filter parameters through get ("" when absent).
// Errors are *datatype.ParamError naming the parameter.
func Parse(get func(string) string) (*Filter, error) {
	f := &Filter{}
	var err error
	for _, p := range []struct {
		param string
		out   *[]netip.Prefix
	}{
		{"src", &f.Src}, {"dst", &f.Dst}, {"ip", &f.IP}, {"exclude_src", &f.ExSrc}, {"exclude_dst", &f.ExDst},
		{"exclude_ip", &f.ExIP}, {"ip_any", &f.IPAny}, {"post_nat_src", &f.PostNATSrc}, {"post_nat_dst", &f.PostNATDst},
		{"post_nat_ip", &f.PostNATIP}, {"exclude_post_nat_src", &f.ExPostNATSrc}, {"exclude_post_nat_dst", &f.ExPostNATDst},
		{"exclude_post_nat_ip", &f.ExPostNATIP},
	} {
		if *p.out, err = prefixes(get, p.param); err != nil {
			return nil, err
		}
	}
	for _, p := range []struct {
		param string
		out   *[]PortRange
	}{
		{"src_port", &f.SrcPort}, {"dst_port", &f.DstPort}, {"port", &f.Port}, {"exclude_src_port", &f.ExSrcPort},
		{"exclude_dst_port", &f.ExDstPort}, {"exclude_port", &f.ExPort}, {"post_nat_src_port", &f.PostNATSrcPort},
		{"post_nat_dst_port", &f.PostNATDstPort},
	} {
		if *p.out, err = ports(get, p.param); err != nil {
			return nil, err
		}
	}
	protoWhat := "a protocol name (tcp, udp, icmp, icmpv6, gre, esp, sctp) or a number 0–255"
	if f.Proto, err = bytesSet(get, "proto", protoWhat, flow.ParseProto, f); err != nil {
		return nil, err
	}
	if f.ExProto, err = bytesSet(get, "exclude_proto", protoWhat, flow.ParseProto, f); err != nil {
		return nil, err
	}
	if f.FwEvent, err = bytesSet(get, "fw_event", "a firewall event ("+strings.Join(flow.FwEventNames(), ", ")+") or a number 0–255",
		flow.ParseFwEvent, f); err != nil {
		return nil, err
	}
	if f.NatEvent, err = bytesSet(get, "nat_event", "a NAT event name (nat44_session_create, …) or a number 0–255",
		flow.ParseNatEvent, f); err != nil {
		return nil, err
	}
	for _, p := range []struct {
		param string
		out   *[]IfRef
	}{{"in_if", &f.InIf}, {"out_if", &f.OutIf}, {"exclude_in_if", &f.ExInIf}, {"exclude_out_if", &f.ExOutIf}} {
		if *p.out, err = ifRefs(get, p.param); err != nil {
			return nil, err
		}
	}
	doms, err := list(get, "domain")
	if err != nil {
		return nil, err
	}
	for _, d := range doms {
		n, err := strconv.ParseUint(d, 10, 32)
		if err != nil {
			return nil, perr("domain", fmt.Sprintf("%q isn't an observation domain or source ID (0–4294967295).", d))
		}
		f.Domain = append(f.Domain, uint32(n))
	}
	if v := get("tcp_flags"); strings.TrimSpace(v) != "" {
		m, ok := flow.ParseTCPFlags(v)
		if !ok {
			return nil, perr("tcp_flags", "use any of "+strings.Join(flow.TCPFlagNames(), ", ")+".")
		}
		f.TCPFlags = m
	}
	samp, err := list(get, "sampled")
	if err != nil {
		return nil, err
	}
	for _, s := range samp {
		s = strings.ToLower(s)
		if s != "yes" && s != "no" && s != "unknown" {
			return nil, perr("sampled", fmt.Sprintf("%q is not one of yes, no, unknown.", s))
		}
		f.Sampled = append(f.Sampled, s)
	}
	sts, err := list(get, "status")
	if err != nil {
		return nil, err
	}
	for _, s := range sts {
		i := slices.Index(flow.StatusNames(), strings.ToLower(s))
		if i < 0 {
			return nil, perr("status", fmt.Sprintf("%q is not one of %s.", s, strings.Join(flow.StatusNames(), ", ")))
		}
		f.Status = append(f.Status, flow.Status(i))
	}
	for _, p := range []struct {
		param string
		out   *[]string
	}{{"rule_id", &f.RuleID}, {"exclude_rule_id", &f.ExRuleID}} {
		items, err := list(get, p.param)
		if err != nil {
			return nil, err
		}
		for _, it := range items {
			if len(it) > MaxRuleIDLen {
				return nil, perr(p.param, fmt.Sprintf("a rule ID is at most %d bytes.", MaxRuleIDLen))
			}
		}
		*p.out = items
	}
	return f, nil
}

// Empty reports whether the filter lets every record through.
func (f *Filter) Empty() bool {
	return !f.Nothing && len(f.Src) == 0 && len(f.Dst) == 0 && len(f.IP) == 0 && len(f.ExSrc) == 0 && len(f.ExDst) == 0 &&
		len(f.ExIP) == 0 && len(f.IPAny) == 0 && len(f.PostNATSrc) == 0 && len(f.PostNATDst) == 0 && len(f.PostNATIP) == 0 &&
		len(f.ExPostNATSrc) == 0 && len(f.ExPostNATDst) == 0 && len(f.ExPostNATIP) == 0 && len(f.SrcPort) == 0 &&
		len(f.DstPort) == 0 && len(f.Port) == 0 && len(f.ExSrcPort) == 0 && len(f.ExDstPort) == 0 && len(f.ExPort) == 0 &&
		len(f.PostNATSrcPort) == 0 && len(f.PostNATDstPort) == 0 && len(f.Proto) == 0 && len(f.ExProto) == 0 &&
		len(f.InIf) == 0 && len(f.OutIf) == 0 && len(f.ExInIf) == 0 && len(f.ExOutIf) == 0 && len(f.Domain) == 0 &&
		f.TCPFlags == 0 && len(f.Sampled) == 0 && len(f.Status) == 0 && len(f.FwEvent) == 0 && len(f.NatEvent) == 0 &&
		len(f.RuleID) == 0 && len(f.ExRuleID) == 0
}

// OnlyRaw reports whether the filter can match only raw sets (status
// no_template or malformed alone).
func (f *Filter) OnlyRaw() bool {
	if len(f.Status) == 0 {
		return false
	}
	for _, s := range f.Status {
		if s == flow.StatusOK || s == flow.StatusLate {
			return false
		}
	}
	return true
}

func inPrefixes(ps []netip.Prefix, a netip.Addr, has bool) bool {
	if !has {
		return false
	}
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func inPorts(rs []PortRange, v uint16, has bool) bool {
	if !has {
		return false
	}
	for _, r := range rs {
		if r.has(v) {
			return true
		}
	}
	return false
}

func inIfs(rs []IfRef, idx uint32, has bool, name string, hasName bool) bool {
	if !has {
		return false
	}
	for _, r := range rs {
		if r.match(idx, name, hasName) {
			return true
		}
	}
	return false
}

// Match reports whether a record passes the filter (the time window aside).
func (f *Filter) Match(r *flow.Record) bool {
	if f.Nothing {
		return false
	}
	hs, hd := r.Is(flow.HasSrc), r.Is(flow.HasDst)
	if len(f.Src) > 0 && !inPrefixes(f.Src, r.Src, hs) {
		return false
	}
	if len(f.Dst) > 0 && !inPrefixes(f.Dst, r.Dst, hd) {
		return false
	}
	if len(f.IP) > 0 && !inPrefixes(f.IP, r.Src, hs) && !inPrefixes(f.IP, r.Dst, hd) {
		return false
	}
	if inPrefixes(f.ExSrc, r.Src, hs) || inPrefixes(f.ExDst, r.Dst, hd) ||
		inPrefixes(f.ExIP, r.Src, hs) || inPrefixes(f.ExIP, r.Dst, hd) {
		return false
	}
	pns, pnd := r.Is(flow.HasPostNATSrc), r.Is(flow.HasPostNATDst)
	if len(f.IPAny) > 0 && !inPrefixes(f.IPAny, r.Src, hs) && !inPrefixes(f.IPAny, r.Dst, hd) &&
		!inPrefixes(f.IPAny, r.PostNATSrc, pns) && !inPrefixes(f.IPAny, r.PostNATDst, pnd) {
		return false
	}
	if len(f.PostNATSrc) > 0 && !inPrefixes(f.PostNATSrc, r.PostNATSrc, pns) {
		return false
	}
	if len(f.PostNATDst) > 0 && !inPrefixes(f.PostNATDst, r.PostNATDst, pnd) {
		return false
	}
	if len(f.PostNATIP) > 0 && !inPrefixes(f.PostNATIP, r.PostNATSrc, pns) && !inPrefixes(f.PostNATIP, r.PostNATDst, pnd) {
		return false
	}
	if inPrefixes(f.ExPostNATSrc, r.PostNATSrc, pns) || inPrefixes(f.ExPostNATDst, r.PostNATDst, pnd) ||
		inPrefixes(f.ExPostNATIP, r.PostNATSrc, pns) || inPrefixes(f.ExPostNATIP, r.PostNATDst, pnd) {
		return false
	}
	sp, dp := r.Is(flow.HasSrcPort), r.Is(flow.HasDstPort)
	if len(f.SrcPort) > 0 && !inPorts(f.SrcPort, r.SrcPort, sp) {
		return false
	}
	if len(f.DstPort) > 0 && !inPorts(f.DstPort, r.DstPort, dp) {
		return false
	}
	if len(f.Port) > 0 && !inPorts(f.Port, r.SrcPort, sp) && !inPorts(f.Port, r.DstPort, dp) {
		return false
	}
	if inPorts(f.ExSrcPort, r.SrcPort, sp) || inPorts(f.ExDstPort, r.DstPort, dp) ||
		inPorts(f.ExPort, r.SrcPort, sp) || inPorts(f.ExPort, r.DstPort, dp) {
		return false
	}
	if len(f.PostNATSrcPort) > 0 && !inPorts(f.PostNATSrcPort, r.PostNATSrcPort, r.Is(flow.HasPostNATSrcPort)) {
		return false
	}
	if len(f.PostNATDstPort) > 0 && !inPorts(f.PostNATDstPort, r.PostNATDstPort, r.Is(flow.HasPostNATDstPort)) {
		return false
	}
	hp := r.Is(flow.HasProto)
	if len(f.Proto) > 0 && (!hp || !slices.Contains(f.Proto, r.Proto)) {
		return false
	}
	if hp && slices.Contains(f.ExProto, r.Proto) {
		return false
	}
	hi, ho := r.Is(flow.HasInIf), r.Is(flow.HasOutIf)
	hin, hon := r.Is(flow.HasInIfName), r.Is(flow.HasOutIfName)
	if len(f.InIf) > 0 && !inIfs(f.InIf, r.InIf, hi, r.InIfName, hin) {
		return false
	}
	if len(f.OutIf) > 0 && !inIfs(f.OutIf, r.OutIf, ho, r.OutIfName, hon) {
		return false
	}
	if inIfs(f.ExInIf, r.InIf, hi, r.InIfName, hin) || inIfs(f.ExOutIf, r.OutIf, ho, r.OutIfName, hon) {
		return false
	}
	if len(f.Domain) > 0 && !slices.Contains(f.Domain, r.Domain) {
		return false
	}
	if f.TCPFlags != 0 && (!r.Is(flow.HasTCPFlags) || r.TCPFlags&f.TCPFlags == 0) {
		return false
	}
	if len(f.Sampled) > 0 && !slices.Contains(f.Sampled, SampledValue(r.Sampling)) {
		return false
	}
	if len(f.Status) > 0 && !slices.Contains(f.Status, r.Status) {
		return false
	}
	if len(f.FwEvent) > 0 && (!r.Is(flow.HasFwEvent) || !slices.Contains(f.FwEvent, r.FwEvent)) {
		return false
	}
	if len(f.NatEvent) > 0 && (!r.Is(flow.HasNatEvent) || !slices.Contains(f.NatEvent, r.NatEvent)) {
		return false
	}
	hr := r.Is(flow.HasRuleID)
	if len(f.RuleID) > 0 && (!hr || !slices.Contains(f.RuleID, r.RuleID)) {
		return false
	}
	if hr && slices.Contains(f.ExRuleID, r.RuleID) {
		return false
	}
	return true
}

// SampledValue is the sampled field's value for a sampling rate.
func SampledValue(s uint32) string {
	switch s {
	case 0:
		return "unknown"
	case 1:
		return "no"
	}
	return "yes"
}

// BlockIndex is what a block's index can rule out (flowseg.BlockInfo).
type BlockIndex interface {
	HasProto(p uint8) bool
	MayHaveAddr(a netip.Addr) bool
	MayHavePrefix(p netip.Prefix) bool
	MayHavePort(p uint16) bool
	MayHaveInIf(i uint32) bool
	MayHaveOutIf(i uint32) bool
}

func mayPrefixes(b BlockIndex, ps []netip.Prefix) bool {
	if len(ps) == 0 {
		return true
	}
	for _, p := range ps {
		if p.IsSingleIP() {
			if b.MayHaveAddr(p.Addr()) {
				return true
			}
		} else if b.MayHavePrefix(p) {
			return true
		}
	}
	return false
}

// maxPortsProbed is the widest range whose ports are probed one by one.
const maxPortsProbed = 32

func mayPorts(b BlockIndex, rs []PortRange) bool {
	if len(rs) == 0 {
		return true
	}
	for _, r := range rs {
		if int(r.Hi)-int(r.Lo) >= maxPortsProbed {
			return true
		}
		for p := int(r.Lo); p <= int(r.Hi); p++ {
			if b.MayHavePort(uint16(p)) {
				return true
			}
		}
	}
	return false
}

func mayIfs(rs []IfRef, has func(uint32) bool) bool {
	if len(rs) == 0 {
		return true
	}
	for _, r := range rs {
		if r.Name != "" || has(r.Index) {
			return true
		}
	}
	return false
}

// BlockMay reports whether a block may hold a matching record: false only
// when its index rules every record out. Excludes never skip a block.
func (f *Filter) BlockMay(b BlockIndex) bool {
	if f.Nothing {
		return false
	}
	if !mayPrefixes(b, f.Src) || !mayPrefixes(b, f.Dst) || !mayPrefixes(b, f.IP) || !mayPrefixes(b, f.IPAny) ||
		!mayPrefixes(b, f.PostNATSrc) || !mayPrefixes(b, f.PostNATDst) || !mayPrefixes(b, f.PostNATIP) {
		return false
	}
	if !mayPorts(b, f.SrcPort) || !mayPorts(b, f.DstPort) || !mayPorts(b, f.Port) ||
		!mayPorts(b, f.PostNATSrcPort) || !mayPorts(b, f.PostNATDstPort) {
		return false
	}
	if len(f.Proto) > 0 {
		any := false
		for _, p := range f.Proto {
			if b.HasProto(p) {
				any = true
				break
			}
		}
		if !any {
			return false
		}
	}
	return mayIfs(f.InIf, b.MayHaveInIf) && mayIfs(f.OutIf, b.MayHaveOutIf)
}

// Cols are the optional columns (flow.Has* bits) the filter reads, plus
// NeedSampling and NeedStatus and NeedDomain for the always-present ones.
func (f *Filter) Cols() (has uint64, sampling, status, domain bool) {
	add := func(cond bool, bits uint64) {
		if cond {
			has |= bits
		}
	}
	add(len(f.Src)+len(f.ExSrc) > 0, flow.HasSrc)
	add(len(f.Dst)+len(f.ExDst) > 0, flow.HasDst)
	add(len(f.IP)+len(f.ExIP) > 0, flow.HasSrc|flow.HasDst)
	add(len(f.IPAny) > 0, flow.HasSrc|flow.HasDst|flow.HasPostNATSrc|flow.HasPostNATDst)
	add(len(f.PostNATSrc)+len(f.ExPostNATSrc) > 0, flow.HasPostNATSrc)
	add(len(f.PostNATDst)+len(f.ExPostNATDst) > 0, flow.HasPostNATDst)
	add(len(f.PostNATIP)+len(f.ExPostNATIP) > 0, flow.HasPostNATSrc|flow.HasPostNATDst)
	add(len(f.SrcPort)+len(f.ExSrcPort) > 0, flow.HasSrcPort)
	add(len(f.DstPort)+len(f.ExDstPort) > 0, flow.HasDstPort)
	add(len(f.Port)+len(f.ExPort) > 0, flow.HasSrcPort|flow.HasDstPort)
	add(len(f.PostNATSrcPort) > 0, flow.HasPostNATSrcPort)
	add(len(f.PostNATDstPort) > 0, flow.HasPostNATDstPort)
	add(len(f.Proto)+len(f.ExProto) > 0, flow.HasProto)
	add(len(f.InIf)+len(f.ExInIf) > 0, flow.HasInIf|flow.HasInIfName)
	add(len(f.OutIf)+len(f.ExOutIf) > 0, flow.HasOutIf|flow.HasOutIfName)
	add(f.TCPFlags != 0, flow.HasTCPFlags)
	add(len(f.FwEvent) > 0, flow.HasFwEvent)
	add(len(f.NatEvent) > 0, flow.HasNatEvent)
	add(len(f.RuleID)+len(f.ExRuleID) > 0, flow.HasRuleID)
	return has, len(f.Sampled) > 0, len(f.Status) > 0, len(f.Domain) > 0
}
