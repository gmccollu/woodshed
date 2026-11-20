package config

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

// The syslog severity filter (SPEC §3.3, §13.10 decision 86): store syslog
// messages of a minimum severity and more severe, globally and per device.
// Messages with no valid PRI are always stored; traps, polls and flows aren't
// affected. The listeners apply it before a message is copied, and the
// messages left out are counted per device and severity.

// Severity levels (RFC 5424 §6.2.1): 0 is the most severe.
const (
	SeverityEmerg = 0
	SeverityDebug = 7
)

// DefaultMinSeverity keeps everything.
const DefaultMinSeverity = "debug"

// SeverityDefault is the per-device value meaning "use syslog.min_severity"
// (PATCH /api/devices, `woodshed severity-filter --device`).
const SeverityDefault = "default"

// SeverityNames are the canonical names, by level (as datatype.SeverityNames).
var SeverityNames = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// severityAliases are the other names people type for a level.
var severityAliases = map[string]int{
	"emergency": 0, "panic": 0, "critical": 2, "error": 3, "warn": 4, "informational": 6,
}

// SeverityText is a severity as written in the config: a name or a number. It
// exists so a bare TOML integer (min_severity = 6) reads too; Normalize turns
// both into the canonical name.
type SeverityText string

// UnmarshalText keeps the text as written (go-toml calls it for integers).
func (s *SeverityText) UnmarshalText(b []byte) error {
	*s = SeverityText(b)
	return nil
}

// ParseSeverity reads a severity: a name (emerg, alert, crit, err, warning,
// notice, info, debug, or emergency, panic, critical, error, warn,
// informational), any case, or a number 0-7.
func ParseSeverity(s string) (int, bool) {
	s = strings.ToLower(strings.TrimSpace(s))
	if n, err := strconv.Atoi(s); err == nil {
		return n, n >= SeverityEmerg && n <= SeverityDebug && len(s) == 1
	}
	if i := slices.Index(SeverityNames[:], s); i >= 0 {
		return i, true
	}
	n, ok := severityAliases[s]
	return n, ok
}

// SeverityName is level's canonical name ("info"), or "" outside 0-7.
func SeverityName(level int) string {
	if level < SeverityEmerg || level > SeverityDebug {
		return ""
	}
	return SeverityNames[level]
}

// SeverityPhrase is what a level keeps, in words: "everything" for debug,
// "info and above", "emerg only".
func SeverityPhrase(level int) string {
	switch level {
	case SeverityDebug:
		return "everything"
	case SeverityEmerg:
		return "emerg only"
	}
	return SeverityName(level) + " and above"
}

// Syslog configures how syslog messages are stored.
type Syslog struct {
	MinSeverity SeverityText `toml:"min_severity" json:"min_severity" comment:"Store syslog messages of this severity and more severe: emerg, alert, crit, err, warning, notice, info, or debug (the default: everything); 0 to 7 work too. Messages without a severity (no PRI) are always stored. The ones left out are counted per device, never dropped silently."`
	// MinSeverityByDevice is file-only in /api/settings: each device's own
	// value is set with PATCH /api/devices/{id} (the device's page).
	MinSeverityByDevice map[string]SeverityText `toml:"min_severity_by_device" json:"-" comment:"Per-device overrides of min_severity, by sender address: \"192.0.2.10\" = \"info\". Set them on the device's page or with woodshed severity-filter --device."`
}

func cloneSyslog(s Syslog) Syslog {
	s.MinSeverityByDevice = maps.Clone(s.MinSeverityByDevice)
	if s.MinSeverityByDevice == nil {
		s.MinSeverityByDevice = map[string]SeverityText{}
	}
	return s
}

// normalizeSyslog writes valid severities and addresses in their canonical
// form ("6" -> "info", "::ffff:192.0.2.1" -> "192.0.2.1"); an empty
// min_severity is the default. Invalid ones are left for Validate.
func normalizeSyslog(s *Syslog) {
	if strings.TrimSpace(string(s.MinSeverity)) == "" {
		s.MinSeverity = DefaultMinSeverity
	} else if n, ok := ParseSeverity(string(s.MinSeverity)); ok {
		s.MinSeverity = SeverityText(SeverityNames[n])
	}
	out := make(map[string]SeverityText, len(s.MinSeverityByDevice))
	for k, v := range s.MinSeverityByDevice {
		if a, err := netip.ParseAddr(strings.TrimSpace(k)); err == nil && a.Zone() == "" {
			k = a.Unmap().String()
		}
		if n, ok := ParseSeverity(string(v)); ok {
			v = SeverityText(SeverityNames[n])
		}
		out[k] = v
	}
	s.MinSeverityByDevice = out
}

func checkSyslog(e Errors, s Syslog) {
	if _, ok := ParseSeverity(string(s.MinSeverity)); !ok {
		e["syslog.min_severity"] = "must be a severity: emerg, alert, crit, err, warning, notice, info or debug (or 0 to 7)"
	}
	for k, v := range s.MinSeverityByDevice {
		key := fmt.Sprintf("syslog.min_severity_by_device[%q]", k)
		a, err := netip.ParseAddr(strings.TrimSpace(k))
		if err != nil || a.Zone() != "" {
			e[key] = "the key must be a device's IP address (e.g. \"192.0.2.10\")"
			continue
		}
		if _, ok := ParseSeverity(string(v)); !ok {
			e[key] = "must be a severity: emerg, alert, crit, err, warning, notice, info or debug (or 0 to 7)"
		}
	}
}

// Level is the global minimum severity (debug when it's not valid: Validate
// first).
func (s Syslog) Level() int {
	if n, ok := ParseSeverity(string(s.MinSeverity)); ok {
		return n
	}
	return SeverityDebug
}

// DeviceLevel is the minimum severity in effect for the sender ip, and
// whether it's the device's own (false: the global one).
func (s Syslog) DeviceLevel(ip netip.Addr) (level int, own bool) {
	if v, ok := s.MinSeverityByDevice[ip.Unmap().WithZone("").String()]; ok {
		if n, ok := ParseSeverity(string(v)); ok {
			return n, true
		}
	}
	return s.Level(), false
}

// DeviceLevels are the valid per-device overrides, by address.
func (s Syslog) DeviceLevels() map[netip.Addr]int {
	out := make(map[netip.Addr]int, len(s.MinSeverityByDevice))
	for k, v := range s.MinSeverityByDevice {
		a, err := netip.ParseAddr(k)
		n, ok := ParseSeverity(string(v))
		if err == nil && ok {
			out[a.Unmap().WithZone("")] = n
		}
	}
	return out
}

// SetDevice sets ip's own minimum severity (level 0-7), or with level < 0
// removes it so the device follows min_severity. It reports whether that
// changed anything.
func (s *Syslog) SetDevice(ip netip.Addr, level int) bool {
	k := ip.Unmap().WithZone("").String()
	old, had := s.MinSeverityByDevice[k]
	if level < 0 {
		if !had {
			return false
		}
		s.MinSeverityByDevice = maps.Clone(s.MinSeverityByDevice)
		delete(s.MinSeverityByDevice, k)
		return true
	}
	v := SeverityText(SeverityNames[level])
	if had && old == v {
		return false
	}
	s.MinSeverityByDevice = maps.Clone(s.MinSeverityByDevice)
	if s.MinSeverityByDevice == nil {
		s.MinSeverityByDevice = map[string]SeverityText{}
	}
	s.MinSeverityByDevice[k] = v
	return true
}

// Filtering reports whether any message can be left out: the global level or
// a device's is below debug.
func (s Syslog) Filtering() bool {
	if s.Level() < SeverityDebug {
		return true
	}
	for _, n := range s.DeviceLevels() {
		if n < SeverityDebug {
			return true
		}
	}
	return false
}
