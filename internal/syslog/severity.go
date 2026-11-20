package syslog

import "github.com/gmccollu/woodshed/internal/model"

// Severity is the severity Parse would give raw (0-7, or model.Unknown when
// there is no valid PRI), read from the PRI alone: the listeners' severity
// filter calls it on every message before copying it, so it skips what
// Parse skips before the PRI and reads at most "<NNN>", never allocating.
func Severity(raw []byte) int {
	i := skipLeading(raw, 0, true)
	if _, v, ok := parsePRI(raw, i); ok && v <= maxPRI {
		return v & 7
	}
	return model.Unknown
}
