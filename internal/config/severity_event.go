package config

import (
	"fmt"
	"regexp"
	"strings"
)

// The severity filter's events (SPEC §13.10 decision 86). The server writes
// them on every change, beside a row in the index's severity_changes table,
// which is what a bundle reads; the parser is for the changes 2.1.0-rc1
// recorded only as events, before that table existed.

// StoppedNote ends an event for a change made while Woodshed was stopped.
const StoppedNote = " (changed while Woodshed was stopped)"

// FilterPhrase is what a level stores, for events: "store everything",
// "info and above", "emerg only".
func FilterPhrase(level int) string {
	if level == SeverityDebug {
		return "store everything"
	}
	return SeverityPhrase(level)
}

// DefaultSeverityEvent is the event for a change of the default
// (syslog.min_severity) from was to level: live, with how many devices keep
// their own setting, or found at start (stopped).
func DefaultSeverityEvent(level, was, keep int, stopped bool) string {
	if stopped {
		return fmt.Sprintf("default severity filter set to %s, was %s%s", FilterPhrase(level), SeverityPhrase(was), StoppedNote)
	}
	text := fmt.Sprintf("default severity filter set to %s (was %s)", FilterPhrase(level), SeverityPhrase(was))
	switch keep {
	case 0:
	case 1:
		text += "; 1 device keeps its own setting"
	default:
		text += fmt.Sprintf("; %d devices keep their own setting", keep)
	}
	return text
}

// DeviceSeverityEvent is the event for a change of a device's own setting:
// who is its address (and name), level and was its own levels after and before
// (-1: it follows the default, which was def after and wasDef before).
func DeviceSeverityEvent(who string, level, def, was, wasDef int, stopped bool) string {
	setting := func(l, d int) string {
		if l < 0 {
			return "the default (" + FilterPhrase(d) + ")"
		}
		return FilterPhrase(l)
	}
	text := fmt.Sprintf("severity filter for %s set to %s, was %s", who, setting(level, def), setting(was, wasDef))
	if stopped {
		text += StoppedNote
	}
	return text
}

// SeverityEvent is a severity filter event read back: Default for the
// default's setting (else a device's own), Level the setting after it and Was
// before (-1: the device follows the default); WasKnown is false when the text
// doesn't say (a device's events from 2.1.0-rc1).
type SeverityEvent struct {
	Default  bool
	Level    int
	Was      int
	WasKnown bool
}

var (
	phraseLevel = map[string]int{}
	defaultRE   *regexp.Regexp
	deviceRE    *regexp.Regexp
)

func init() {
	var alts []string
	for l := SeverityEmerg; l <= SeverityDebug; l++ {
		for _, p := range []string{FilterPhrase(l), SeverityPhrase(l)} {
			if _, ok := phraseLevel[p]; !ok {
				phraseLevel[p] = l
				alts = append(alts, regexp.QuoteMeta(p))
			}
		}
	}
	ph := "(" + strings.Join(alts, "|") + ")"
	stopped := regexp.QuoteMeta(StoppedNote)
	defaultRE = regexp.MustCompile(`^default severity filter set to ` + ph + `(?: \(was ` + ph + `\)(?:; .+)?|, was ` + ph + stopped + `)$`)
	// The device's address and name come first and may hold anything, so the
	// rest is matched from the end. 2.1.0-rc1 wrote "set to P", "set to the
	// default (P)" and, at start, "set to the default, P", with no "was".
	deviceRE = regexp.MustCompile(`^severity filter for .+ set to (?:the default \(` + ph + `\)|the default, ` + ph + `|` + ph + `)` +
		`(?:, was (?:the default \(` + ph + `\)|` + ph + `))?(?:` + stopped + `)?$`)
}

// ParseSeverityEvent reads a severity filter event's text; ok is false for a
// text it doesn't know.
func ParseSeverityEvent(text string) (e SeverityEvent, ok bool) {
	if m := defaultRE.FindStringSubmatch(text); m != nil {
		was := m[2]
		if was == "" {
			was = m[3]
		}
		return SeverityEvent{Default: true, Level: phraseLevel[m[1]], Was: phraseLevel[was], WasKnown: true}, true
	}
	m := deviceRE.FindStringSubmatch(text)
	if m == nil {
		return SeverityEvent{}, false
	}
	e.Level = -1
	if m[3] != "" {
		e.Level = phraseLevel[m[3]]
	}
	switch {
	case m[4] != "":
		e.Was, e.WasKnown = -1, true
	case m[5] != "":
		e.Was, e.WasKnown = phraseLevel[m[5]], true
	}
	return e, true
}
