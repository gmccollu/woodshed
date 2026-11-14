package datatype

import (
	"fmt"
	"strconv"
	"strings"
)

// FacilitySet is a set of syslog facilities 0-23 plus "unknown" (no parseable
// PRI), like hub.SeveritySet for severities. The zero value means "no facility
// filter" (all pass); FacilityNone (facilities=none) lets nothing pass.
type FacilitySet uint32

// Facility set bits beyond 0-23.
const (
	FacilityUnknownBit FacilitySet = 1 << 24
	FacilityNone       FacilitySet = 1 << 25
	AllFacilities      FacilitySet = 1<<25 - 1 // 0-23 and unknown
)

// Has reports whether fac (0-23, or model.Unknown) is in the set.
func (s FacilitySet) Has(fac int) bool {
	if fac < 0 || fac > 23 {
		return s&FacilityUnknownBit != 0
	}
	return s&(1<<uint(fac)) != 0
}

// With returns s with fac (0-23, or model.Unknown) added.
func (s FacilitySet) With(fac int) FacilitySet {
	if fac < 0 || fac > 23 {
		return s | FacilityUnknownBit
	}
	return s | 1<<uint(fac)
}

// Normalize turns the full set into the zero set (both mean all).
func (s FacilitySet) Normalize() FacilitySet {
	if s == AllFacilities {
		return 0
	}
	return s
}

// ParseFacilities reads a facilities= value: a comma-separated list of 0-23
// and "unknown", or "none" on its own. Blank items are ignored, so "" is the
// zero set (all).
func ParseFacilities(v string) (FacilitySet, error) {
	var s FacilitySet
	none := false
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		switch {
		case item == "":
		case strings.EqualFold(item, "none"):
			none = true
		case strings.EqualFold(item, "unknown"):
			s |= FacilityUnknownBit
		default:
			n, err := strconv.Atoi(item)
			if err != nil || n < 0 || n > 23 || len(item) > 2 {
				return 0, fmt.Errorf("facilities: %q is not a facility (0 to 23, unknown, or none on its own)", item)
			}
			s |= 1 << uint(n)
		}
	}
	if none {
		if s != 0 {
			return 0, fmt.Errorf("facilities: none can't be combined with other values")
		}
		return FacilityNone, nil
	}
	return s.Normalize(), nil
}

// List renders the set as the API's list: [] for all, ["none"], or the
// facilities followed by "unknown".
func (s FacilitySet) List() []any {
	out := []any{}
	switch s {
	case 0:
		return out
	case FacilityNone:
		return append(out, "none")
	}
	for i := 0; i < 24; i++ {
		if s.Has(i) {
			out = append(out, i)
		}
	}
	if s.Has(-1) {
		out = append(out, "unknown")
	}
	return out
}

// FacilityNames are the facility labels, 0-23.
var FacilityNames = [24]string{"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron",
	"authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5",
	"local6", "local7"}

// SeverityNames are the severity labels, 0-7.
var SeverityNames = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}
