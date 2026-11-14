package config

import (
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

// The SNMP trap listener (SPEC §11.2.1): off by default, UDP 162.
const DefaultSNMPPort = 162

// SNMP community limits (docs/api.md, "SNMP trap listener").
const (
	MaxSNMPCommunities   = 100
	MaxSNMPCommunityLen  = 255
	MinSNMPEngineIDBytes = 5
	MaxSNMPEngineIDBytes = 32
)

// SNMPListener is the SNMP trap receiver (SPEC §11.2). v3 users and the v1/v2c
// community list are secrets: they're kept in the SNMP credentials file in the
// data folder (SPEC §11.2.6), never in the TOML. Communities travels through
// /api/settings only, as "#<hash8>" values on the way out (the server fills
// and reads it); it's never written to the file.
type SNMPListener struct {
	Enabled bool   `toml:"enabled" json:"enabled" comment:"SNMP traps and informs (Settings → Listeners → \"SNMP traps\"). Off by default."`
	Addr    string `toml:"addr" json:"addr"`
	Port    int    `toml:"port" json:"port" comment:"Traps and informs; any free UDP port."`
	// AnswerInforms replies to InformRequests (SPEC §11.2.3).
	AnswerInforms bool `toml:"answer_informs" json:"answer_informs" comment:"Reply to InformRequests (the sender retransmits an unanswered inform)."`
	// Communities is the v1/v2c accept list (empty accepts any), through
	// /api/settings only.
	Communities []string `toml:"-" json:"communities"`
	// MIBDir holds MIB files for names; "" means <data>/mibs.
	MIBDir string `toml:"mib_dir" json:"mib_dir" comment:"MIB files (*.mib, *.my, *.txt) for OID names; empty means the mibs folder in the data folder."`
	// EngineID overrides Woodshed's own v3 engine ID (hex); "" means the generated one.
	EngineID string `toml:"engine_id" json:"engine_id" comment:"Woodshed's own SNMPv3 engine ID in hex, for senders configured with a fixed one; empty means the generated one."`
	// V3StrictTime keeps RFC 3414's time window for traps as written (SPEC §11.8 #28).
	V3StrictTime bool `toml:"v3_strict_time" json:"-" comment:"true: RFC 3414's time window for v3 traps as written; a device that reboots without raising its boots stays not_in_time."`
}

// Listener returns the address part, for the shared address and port checks.
func (s SNMPListener) Listener() Listener {
	return Listener{Enabled: s.Enabled, Addr: s.Addr, Port: s.Port}
}

// DefaultSNMP is the SNMP listener's default configuration.
func DefaultSNMP() SNMPListener {
	return SNMPListener{Addr: DefaultListenAddr, Port: DefaultSNMPPort, AnswerInforms: true, Communities: []string{}}
}

// MIBFolder is the MIB folder in effect for a data folder.
func (s SNMPListener) MIBFolder(dataDir string) string {
	if d := strings.TrimSpace(s.MIBDir); d != "" {
		return d
	}
	return filepath.Join(dataDir, "mibs")
}

func checkSNMPListener(e Errors, goos string, l Listeners) {
	s := l.SNMP
	checkListener(e, goos, "listeners.snmp", s.Listener())
	if _, bad := e["listeners.snmp.port"]; !bad && s.Port == l.UDP.Port && addrsOverlap(l.UDP.Addr, s.Addr) {
		e["listeners.snmp.port"] = "can't be the same as the UDP syslog listener's port on the same address"
	}
	if d := strings.TrimSpace(s.MIBDir); d != "" && !isAbs(d) {
		e["listeners.snmp.mib_dir"] = "must be an absolute path (or empty for the mibs folder in the data folder)"
	}
	if id := strings.TrimSpace(s.EngineID); id != "" {
		if msg := checkEngineID(id); msg != "" {
			e["listeners.snmp.engine_id"] = msg
		}
	}
	if len(s.Communities) > MaxSNMPCommunities {
		e["listeners.snmp.communities"] = fmt.Sprintf("at most %d communities", MaxSNMPCommunities)
	}
	for i, c := range s.Communities {
		if len(c) < 1 || len(c) > MaxSNMPCommunityLen {
			e[fmt.Sprintf("listeners.snmp.communities[%d]", i)] = fmt.Sprintf("must be 1 to %d bytes", MaxSNMPCommunityLen)
		}
	}
}

// checkEngineID applies RFC 3411's SnmpEngineID rules to a hex engine ID: 5 to
// 32 octets, and not all zeros or all 0xff. It returns "" when it's valid.
func checkEngineID(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(strings.ReplaceAll(s, ":", ""), "0x"), "0X")
	b, err := hex.DecodeString(s)
	if err != nil {
		return "must be hex digits (an engine ID of 5 to 32 bytes, e.g. 8000000005a1b2c3d4e5f60718)"
	}
	if len(b) < MinSNMPEngineIDBytes || len(b) > MaxSNMPEngineIDBytes {
		return fmt.Sprintf("must be %d to %d bytes (%d to %d hex digits)", MinSNMPEngineIDBytes, MaxSNMPEngineIDBytes,
			2*MinSNMPEngineIDBytes, 2*MaxSNMPEngineIDBytes)
	}
	zero, ff := true, true
	for _, c := range b {
		zero = zero && c == 0
		ff = ff && c == 0xff
	}
	if zero || ff {
		return "can't be all zeros or all ff (RFC 3411)"
	}
	return ""
}
