package search

import (
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/hub"
)

// The syslog type's filter types live in internal/datatype (SPEC §11.1); these
// keep their 1.1 names here.

// FacilitySet is datatype.FacilitySet.
type FacilitySet = datatype.FacilitySet

// Facility set bits beyond 0-23.
const (
	FacilityUnknownBit = datatype.FacilityUnknownBit
	FacilityNone       = datatype.FacilityNone
	AllFacilities      = datatype.AllFacilities
)

// FacilityNames and SeverityNames are the syslog labels.
var (
	FacilityNames = datatype.FacilityNames
	SeverityNames = datatype.SeverityNames
)

// ParseFacilities reads a facilities= value (datatype.ParseFacilities).
func ParseFacilities(v string) (FacilitySet, error) { return datatype.ParseFacilities(v) }

// Fields returns the program/tag and hostname of a raw message
// (datatype.Fields).
func Fields(raw []byte) (app, host string) { return datatype.Fields(raw) }

// trimPct drops one leading '%' (datatype.TrimPct).
func trimPct(s string) string { return datatype.TrimPct(s) }

// typeFilter compiles a Filter's type part: the type and its own filter (nil
// when it lets everything through), and whether it matches nothing.
func typeFilter(f Filter) (datatype.Type, datatype.Filter, bool, error) {
	dt := datatype.Get(f.Type)
	if dt == nil {
		return nil, nil, false, &QueryError{Msg: "type: unknown data type \"" + f.Type + "\"."}
	}
	var tf datatype.Filter
	switch dt.Name() {
	case datatype.Syslog:
		if f.Trap != nil {
			return nil, nil, false, &QueryError{Msg: "trap filters don't apply to syslog."}
		}
		tf = datatype.NewSyslogFilter(f.Severities, f.Facilities, f.Apps, f.Hosts, f.ExcludeApps, f.ExcludeHosts)
	case datatype.Trap:
		if f.Severities != 0 || f.Facilities != 0 || len(f.Apps) > 0 || len(f.Hosts) > 0 || len(f.ExcludeApps) > 0 || len(f.ExcludeHosts) > 0 {
			return nil, nil, false, &QueryError{Msg: "severities: not a filter for SNMP traps."}
		}
		if f.Trap != nil {
			tf = f.Trap
		}
	}
	if tf == nil {
		return dt, nil, false, nil
	}
	none := tf.None()
	if tf.Empty() {
		tf = nil
	}
	return dt, tf, none, nil
}

var _ = hub.SeverityNone
