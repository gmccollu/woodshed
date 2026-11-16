package datatype

import (
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The flow type (SPEC §13.2, §13.3): records are columnar segments in
// logs/<device>/flows/, not lines, so the line methods (Text, FieldValues) do
// nothing and the search layer sends type=flow to the flow query engine
// (internal/flowquery), which parses and applies the filter. The registry
// entry gives the schema's fields, the filter parameters CheckParams refuses
// on the other types (and the reverse) and the label.

// Flow is the flow type's name.
const Flow = logfile.TypeFlow

// Flow field keys, in panel order (after device).
const (
	FieldProto    = "proto"
	FieldDstPort  = "dst_port"
	FieldSrcPort  = "src_port"
	FieldSrc      = "src"
	FieldDst      = "dst"
	FieldInIf     = "in_if"
	FieldOutIf    = "out_if"
	FieldFwEvent  = "fw_event"
	FieldNatEvent = "nat_event"
	FieldRuleID   = "rule_id"
	FieldDomain   = "domain"
	FieldSampled  = "sampled"
	FieldFlowStat = "status"
)

// FlowFilterParams are the flow type's own filter parameters (SPEC §13.3).
var FlowFilterParams = []string{
	"src", "dst", "ip", "exclude_src", "exclude_dst", "exclude_ip", "ip_any",
	"src_port", "dst_port", "port", "exclude_src_port", "exclude_dst_port", "exclude_port",
	"proto", "exclude_proto", "in_if", "out_if", "exclude_in_if", "exclude_out_if",
	"domain", "tcp_flags", "sampled", "status",
	"fw_event", "nat_event", "post_nat_src", "post_nat_dst", "post_nat_ip",
	"exclude_post_nat_src", "exclude_post_nat_dst", "exclude_post_nat_ip",
	"post_nat_src_port", "post_nat_dst_port", "rule_id", "exclude_rule_id",
}

var flowFields = func() []Field {
	fw := []DomainValue{}
	for _, n := range flow.FwEventNames() {
		fw = append(fw, DomainValue{n, n})
	}
	nat := []DomainValue{}
	for _, n := range flow.NatEventNames() {
		nat = append(nat, DomainValue{n, n})
	}
	st := []DomainValue{}
	for _, n := range flow.StatusNames() {
		l := n
		switch n {
		case "late":
			l = "late (template came after)"
		case "no_template":
			l = "no template"
		}
		st = append(st, DomainValue{n, l})
	}
	return []Field{
		deviceField,
		{Key: FieldProto, Label: "Protocol", Param: "proto", ExcludeParam: "exclude_proto"},
		{Key: FieldDstPort, Label: "Destination port", Param: "dst_port", ExcludeParam: "exclude_dst_port"},
		{Key: FieldSrcPort, Label: "Source port", Param: "src_port", ExcludeParam: "exclude_src_port"},
		{Key: FieldSrc, Label: "Source", Param: "src", ExcludeParam: "exclude_src"},
		{Key: FieldDst, Label: "Destination", Param: "dst", ExcludeParam: "exclude_dst"},
		{Key: FieldInIf, Label: "Input interface", Param: "in_if", ExcludeParam: "exclude_in_if"},
		{Key: FieldOutIf, Label: "Output interface", Param: "out_if", ExcludeParam: "exclude_out_if"},
		{Key: FieldFwEvent, Label: "Firewall event", Param: "fw_event", Domain: fw},
		{Key: FieldNatEvent, Label: "NAT event", Param: "nat_event", Domain: nat},
		{Key: FieldRuleID, Label: "Rule", Param: "rule_id", ExcludeParam: "exclude_rule_id"},
		{Key: FieldDomain, Label: "Observation domain", Param: "domain"},
		{Key: FieldSampled, Label: "Sampled", Param: "sampled", Domain: []DomainValue{{"yes", "sampled"}, {"no", "unsampled"},
			{"unknown", "sampling unknown"}}},
		{Key: FieldFlowStat, Label: "Status", Param: "status", Domain: st},
	}
}()

type flowType struct{}

func (flowType) Name() string                  { return Flow }
func (flowType) Label() string                 { return "Flows" }
func (flowType) Dir() string                   { return logfile.FlowDir }
func (flowType) Default() bool                 { return false }
func (flowType) Fields() []Field               { return flowFields }
func (flowType) FilterParams() []string        { return FlowFilterParams }
func (flowType) Text([]byte) []byte            { return nil }
func (flowType) NewSummary() Summary           { return nil }
func (flowType) ValueLabel(_, v string) string { return v }

// FieldValues does nothing: flow records aren't lines (flowquery reads them).
func (flowType) FieldValues([]byte, *Scratch, func(key, value string)) {}

// IsSegments reports whether a type stores columnar segments rather than
// lines (the flow type): the line search, the line export and the line
// summaries must leave it to the flow engine.
func IsSegments(name string) bool { return name == Flow }

// LineNames lists the line types' names, in registry order.
func LineNames() []string {
	var out []string
	for _, t := range types {
		if !IsSegments(t.Name()) {
			out = append(out, t.Name())
		}
	}
	return out
}
