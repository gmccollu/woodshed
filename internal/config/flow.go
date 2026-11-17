package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The flow listener (SPEC §13.1): flow v5/v9 and IPFIX over UDP, off by
// default. Both ports read every version.
const (
	DefaultFlowPort           = 2055
	DefaultIPFIXPort          = 4739
	DefaultTemplateTimeout    = Duration(30 * time.Minute)
	DefaultFlowPendingBytes   = 32 << 20
	DefaultFlowQueueMessages  = 50000
	DefaultFlowQueueBytes     = 128 << 20
	MinTemplateTimeout        = time.Minute
	MaxTemplateTimeout        = 24 * time.Hour
	MaxRuleIDIEs              = 8
	DefaultFlowBudgetPercent  = 40
	MaxFlowBudgetPercent      = 90
	MinFlowBudgetBytes        = 1 << 30
	MinFlowPendingBytes       = 1 << 20
	MaxFlowPendingBytes       = 1 << 30
	flowRuleIDHint            = `must be "<enterprise number>:<element ID>" (element ID 0 to 32767), e.g. "32473:7", or "0:<v9 field type>" (0 to 65535) for flow v9, e.g. "0:40003"`
	flowPortHint              = "must be 0 (off) or between 1 and 65535"
	flowPortsOffHint          = "at least one of flow_port and ipfix_port must be on while the flow listener is enabled"
	flowSamePortHint          = "can't be the same as ipfix_port"
	flowSyslogPortHint        = "can't be the same as the UDP syslog listener's port on the same address"
	flowSNMPPortHint          = "can't be the same as the SNMP trap listener's port on the same address"
	flowTemplateTimeoutHint   = "must be between 1m and 24h"
	flowBudgetHint            = "must be 0 (40 % of retention_bytes) or at least 1 GiB (1073741824) and at most 90 % of retention_bytes"
	flowPendingHint           = "must be between 1 MiB and 1 GiB"
	flowRuleIDCountHint       = "at most 8 entries"
	flowDurationExampleSuffix = " (e.g. 30m or 1h)"
)

// FlowDuration is a duration written compactly ("30m", "1h30m"), as
// docs/api.md shows template_timeout.
type FlowDuration Duration

// MarshalText writes d without zero trailing units ("30m", not "30m0s").
func (d FlowDuration) MarshalText() ([]byte, error) {
	return []byte(ShortDuration(time.Duration(d))), nil
}

// UnmarshalText reads Go duration text ("30m", "1h").
func (d *FlowDuration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("%q is not a duration%s", b, flowDurationExampleSuffix)
	}
	*d = FlowDuration(v)
	return nil
}

// ShortDuration formats d like time.Duration.String without zero trailing
// units: 30m, 1h, 1h30m, 45s.
func ShortDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// FlowListener is the flow collector (v5, v9, IPFIX)'s listener (SPEC §13.1).
type FlowListener struct {
	Enabled         bool         `toml:"enabled" json:"enabled" comment:"Flows: flow v5/v9 and IPFIX over UDP (Settings → Flows). Off by default."`
	Addr            string       `toml:"addr" json:"addr"`
	FlowPort        int          `toml:"flow_port" json:"flow_port" comment:"flow v5 and v9 (any version is accepted on either port); 0 turns this port off."`
	IPFIXPort       int          `toml:"ipfix_port" json:"ipfix_port" comment:"IPFIX; 0 turns this port off."`
	TemplateTimeout FlowDuration `toml:"template_timeout" json:"template_timeout" comment:"A template not refreshed for this long expires (1m to 24h)."`
	// RuleIDIEs names the IEs that carry a rule or ACL identifier, as
	// "<enterprise number>:<element ID>" (SPEC §13.2.1); the first one a
	// record has fills rule_id.
	RuleIDIEs []string `toml:"rule_id_ies" json:"rule_id_ies" comment:"IEs that carry a rule or ACL ID, as \"<enterprise number>:<element ID>\" (flow v9 field types as \"0:<type>\", e.g. \"0:40003\"); the first present fills rule_id. Empty by default (no standard IE exists)."`

	// File-only tuning (not in /api/settings). Zero means the default.
	PendingBytes  int64 `toml:"pending_bytes" json:"-" comment:"Buffer for flow data that arrived before its template, in bytes (at most 1 MiB per exporter)."`
	QueueMessages int   `toml:"queue_messages" json:"-" comment:"This listener's UDP queue: at most this many packets"`
	QueueBytes    int64 `toml:"queue_bytes" json:"-" comment:"and at most this many bytes, whichever fills first."`
}

// DefaultFlow is the flow listener's default configuration.
func DefaultFlow() FlowListener {
	return FlowListener{Addr: DefaultListenAddr, FlowPort: DefaultFlowPort, IPFIXPort: DefaultIPFIXPort,
		TemplateTimeout: FlowDuration(DefaultTemplateTimeout), RuleIDIEs: []string{},
		PendingBytes: DefaultFlowPendingBytes, QueueMessages: DefaultFlowQueueMessages, QueueBytes: DefaultFlowQueueBytes}
}

// Ports returns the flow listener's sockets: proto "flow" and "ipfix" with
// their ports, leaving out a port that's 0.
func (f FlowListener) Ports() []FlowSocket {
	var out []FlowSocket
	if f.FlowPort != 0 {
		out = append(out, FlowSocket{Proto: "flow", Port: f.FlowPort})
	}
	if f.IPFIXPort != 0 {
		out = append(out, FlowSocket{Proto: "ipfix", Port: f.IPFIXPort})
	}
	return out
}

// FlowSocket is one socket of the flow listener.
type FlowSocket struct {
	Proto string // "flow" or "ipfix"
	Port  int
}

// ParseRuleIDIE reads a rule_id_ies entry "<pen>:<id>": an IPFIX enterprise
// IE (a 32-bit enterprise number and a 15-bit element ID, 0–32767), or, with
// enterprise number 0, an IANA IE (0–32767) or a flow v9 field type, whose
// vendor range is 32768–65535 ("0:40003"; decided (build, 2026-11-17), SPEC
// §13.2.1). Flow v9 has no enterprise numbers, and an IANA IE never has the
// high bit, so "0:" with an ID above 32767 can only name a v9 field.
func ParseRuleIDIE(s string) (pen uint32, id uint16, ok bool) {
	a, b, found := strings.Cut(strings.TrimSpace(s), ":")
	if !found {
		return 0, 0, false
	}
	p, err1 := strconv.ParseUint(strings.TrimSpace(a), 10, 32)
	i, err2 := strconv.ParseUint(strings.TrimSpace(b), 10, 16)
	if err1 != nil || err2 != nil || (p != 0 && i > 32767) {
		return 0, 0, false
	}
	return uint32(p), uint16(i), true
}

// FlowBudget is storage.flow_budget_bytes in effect: 40 % of the cap for 0.
func (s Storage) FlowBudget() int64 {
	if s.FlowBudgetBytes > 0 {
		return s.FlowBudgetBytes
	}
	return s.RetentionBytes * DefaultFlowBudgetPercent / 100
}

func normalizeFlow(f *FlowListener) {
	if f.TemplateTimeout == 0 {
		f.TemplateTimeout = FlowDuration(DefaultTemplateTimeout)
	}
	if f.RuleIDIEs == nil {
		f.RuleIDIEs = []string{}
	}
	f.RuleIDIEs = trimList(f.RuleIDIEs)
	if f.Addr == "" {
		f.Addr = DefaultListenAddr
	}
	if f.PendingBytes == 0 {
		f.PendingBytes = DefaultFlowPendingBytes
	}
	if f.QueueMessages == 0 {
		f.QueueMessages = DefaultFlowQueueMessages
	}
	if f.QueueBytes == 0 {
		f.QueueBytes = DefaultFlowQueueBytes
	}
}

func checkFlowListener(e Errors, goos string, l Listeners) {
	f := l.Flow
	const k = "listeners.flow."
	for _, p := range []struct {
		key  string
		port int
	}{{"flow_port", f.FlowPort}, {"ipfix_port", f.IPFIXPort}} {
		if p.port < 0 || p.port > 65535 {
			e[k+p.key] = flowPortHint
			continue
		}
		if p.port == 0 {
			continue
		}
		ln := Listener{Enabled: f.Enabled, Addr: f.Addr, Port: p.port}
		sub := Errors{}
		checkListener(sub, goos, "listeners.flow", ln)
		if msg, ok := sub["listeners.flow.addr"]; ok {
			e[k+"addr"] = msg
		}
		switch {
		case l.UDP.Port == p.port && addrsOverlap(l.UDP.Addr, f.Addr):
			e[k+p.key] = flowSyslogPortHint
		case l.SNMP.Port == p.port && addrsOverlap(l.SNMP.Addr, f.Addr):
			e[k+p.key] = flowSNMPPortHint
		}
	}
	if _, bad := e[k+"addr"]; !bad {
		sub := Errors{}
		checkListener(sub, goos, "x", Listener{Addr: f.Addr, Port: 1})
		if msg, ok := sub["x.addr"]; ok {
			e[k+"addr"] = msg
		}
	}
	if f.FlowPort != 0 && f.FlowPort == f.IPFIXPort {
		e[k+"flow_port"] = flowSamePortHint
	}
	if f.Enabled && f.FlowPort == 0 && f.IPFIXPort == 0 {
		e[k+"flow_port"] = flowPortsOffHint
	}
	if d := time.Duration(f.TemplateTimeout); d < MinTemplateTimeout || d > MaxTemplateTimeout {
		e[k+"template_timeout"] = flowTemplateTimeoutHint
	}
	if len(f.RuleIDIEs) > MaxRuleIDIEs {
		e[k+"rule_id_ies"] = flowRuleIDCountHint
	}
	for i, s := range f.RuleIDIEs {
		if _, _, ok := ParseRuleIDIE(s); !ok {
			e[fmt.Sprintf("%srule_id_ies[%d]", k, i)] = flowRuleIDHint
		}
	}
	if n := f.PendingBytes; n != 0 && (n < MinFlowPendingBytes || n > MaxFlowPendingBytes) {
		e[k+"pending_bytes"] = flowPendingHint
	}
	if n := f.QueueMessages; n != 0 && (n < MinUDPQueueMessages || n > MaxUDPQueueMessages) {
		e[k+"queue_messages"] = fmt.Sprintf("must be between %d and %d", MinUDPQueueMessages, MaxUDPQueueMessages)
	}
	if n := f.QueueBytes; n != 0 && (n < MinUDPQueueBytes || n > MaxUDPQueueBytes) {
		e[k+"queue_bytes"] = fmt.Sprintf("must be between %d (1 MiB) and %d (1 GiB)", MinUDPQueueBytes, MaxUDPQueueBytes)
	}
}

func checkFlowBudget(e Errors, s Storage) {
	b := s.FlowBudgetBytes
	if b == 0 {
		return
	}
	if b < MinFlowBudgetBytes || b > s.RetentionBytes*MaxFlowBudgetPercent/100 {
		e["storage.flow_budget_bytes"] = flowBudgetHint
	}
}
