package config

import (
	"fmt"
	"slices"
)

// The SNMP poller's defaults (SPEC §12.1, §12.9; docs/api.md "Settings"):
// Settings → Polling edits them, and each target can override the interval,
// presets and interfaces. Targets themselves are user data in the index, not
// here, and their communities are in the credentials store.

// Poll presets.
const (
	PresetSystem     = "system"
	PresetSystemInfo = "system-info"
	PresetInterfaces = "interfaces"
)

// PollPresets lists the presets.
func PollPresets() []string { return []string{PresetSystem, PresetSystemInfo, PresetInterfaces} }

// Poll defaults and ranges.
const (
	DefaultPollIntervalS     = 60
	DefaultPollTimeoutMS     = 2000
	DefaultPollRetries       = 1
	DefaultPollConcurrency   = 32
	DefaultPollMaxInterfaces = 64
	DefaultPollMaxTargets    = 500

	MinPollIntervalS, MaxPollIntervalS         = 30, 600
	MinPollTimeoutMS, MaxPollTimeoutMS         = 200, 10000
	MinPollRetries, MaxPollRetries             = 0, 5
	MinPollConcurrency, MaxPollConcurrency     = 1, 256
	MinPollMaxInterfaces, MaxPollMaxInterfaces = 1, 1024
	MinPollMaxTargets, MaxPollMaxTargets       = 1, 5000
)

// Poll configures the SNMP poller's defaults.
type Poll struct {
	IntervalS     int      `toml:"interval_s" json:"interval_s" comment:"Poll each device every this many seconds (30 to 600), unless the device's own setting says otherwise. With no polled devices (added under Devices → Polling), nothing is polled or sent."`
	TimeoutMS     int      `toml:"timeout_ms" json:"timeout_ms" comment:"Wait this long for each answer (200 to 10,000 ms),"`
	Retries       int      `toml:"retries" json:"retries" comment:"then try again this many times (0 to 5)."`
	Concurrency   int      `toml:"concurrency" json:"concurrency" comment:"Poll at most this many devices at once (1 to 256)."`
	MaxInterfaces int      `toml:"max_interfaces" json:"max_interfaces" comment:"Poll at most this many interfaces per device by default (1 to 1,024)."`
	MaxTargets    int      `toml:"max_targets" json:"max_targets" comment:"At most this many polled devices (1 to 5,000)."`
	Presets       []string `toml:"presets" json:"presets" comment:"What a new polled device gets by default: system, system-info, interfaces."`
}

// DefaultPoll is the [poll] section's defaults.
func DefaultPoll() Poll {
	return Poll{IntervalS: DefaultPollIntervalS, TimeoutMS: DefaultPollTimeoutMS, Retries: DefaultPollRetries,
		Concurrency: DefaultPollConcurrency, MaxInterfaces: DefaultPollMaxInterfaces, MaxTargets: DefaultPollMaxTargets,
		Presets: PollPresets()}
}

// normalizePoll keeps a nil preset list from serializing as null.
func normalizePoll(p *Poll) {
	if p.Presets == nil {
		p.Presets = []string{}
	}
}

func checkPoll(e Errors, p Poll) {
	rng := func(key string, v, lo, hi int) {
		if v < lo || v > hi {
			e["poll."+key] = fmt.Sprintf("must be between %d and %d", lo, hi)
		}
	}
	rng("interval_s", p.IntervalS, MinPollIntervalS, MaxPollIntervalS)
	rng("timeout_ms", p.TimeoutMS, MinPollTimeoutMS, MaxPollTimeoutMS)
	rng("retries", p.Retries, MinPollRetries, MaxPollRetries)
	rng("concurrency", p.Concurrency, MinPollConcurrency, MaxPollConcurrency)
	rng("max_interfaces", p.MaxInterfaces, MinPollMaxInterfaces, MaxPollMaxInterfaces)
	rng("max_targets", p.MaxTargets, MinPollMaxTargets, MaxPollMaxTargets)
	for i, s := range p.Presets {
		if !slices.Contains(PollPresets(), s) {
			e[fmt.Sprintf("poll.presets[%d]", i)] = "must be system, system-info or interfaces"
		} else if slices.Index(p.Presets, s) != i {
			e[fmt.Sprintf("poll.presets[%d]", i)] = "is listed twice"
		}
	}
}
