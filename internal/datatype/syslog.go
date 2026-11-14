package datatype

import (
	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/syslog"
)

// The syslog type: 1.1's records, filters and fields, unchanged. Its filter
// parameters are read by 1.1's parser (api.ParseSearch) into the same fields
// SyslogFilter holds, so a syslog request means exactly what it meant.

// Severity returns the syslog severity (0-7) of a raw message from its PRI, or
// model.Unknown when it has no valid one. It applies exactly the rules of
// syslog.Parse (leading BOMs, blanks, line breaks and NULs are skipped; the PRI
// is "<" 1-3 digits ">" with a value up to 191), without the rest of the
// parse: the storage line has no severity, so search and export read it from
// the raw message.
func Severity(raw []byte) int {
	p := PRI(raw)
	if p < 0 {
		return model.Unknown
	}
	return p & 7
}

// Facility returns the syslog facility (0-23) of a raw message from its PRI,
// or model.Unknown when it has no valid one (the rules of Severity).
func Facility(raw []byte) int {
	p := PRI(raw)
	if p < 0 {
		return model.Unknown
	}
	return p >> 3
}

// PRI returns the PRI value (0-191) of a raw message, or -1 when it has no
// valid one; see Severity for the rules.
func PRI(raw []byte) int {
	i := 0
	for i < len(raw) {
		c := raw[i]
		if c == 0xEF && i+2 < len(raw) && raw[i+1] == 0xBB && raw[i+2] == 0xBF {
			i += 3
			continue
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == 0 {
			i++
			continue
		}
		break
	}
	if i >= len(raw) || raw[i] != '<' {
		return -1
	}
	v, j := 0, i+1
	for j < len(raw) && j-(i+1) < 3 && raw[j] >= '0' && raw[j] <= '9' {
		v = v*10 + int(raw[j]-'0')
		j++
	}
	if j == i+1 || j >= len(raw) || raw[j] != '>' || v > 191 {
		return -1
	}
	return v
}

// Syslog field keys, in panel order.
const (
	FieldSeverity = "severity"
	FieldFacility = "facility"
	FieldHost     = "host"
	FieldApp      = "app"
)

var syslogFields = func() []Field {
	sev := make([]DomainValue, 0, 9)
	for i, n := range SeverityNames {
		sev = append(sev, DomainValue{itoa(i), n})
	}
	sev = append(sev, DomainValue{"unknown", "unknown"})
	fac := make([]DomainValue, 0, 25)
	for i, n := range FacilityNames {
		fac = append(fac, DomainValue{itoa(i), n})
	}
	fac = append(fac, DomainValue{"unknown", "unknown"})
	return []Field{
		deviceField,
		{Key: FieldSeverity, Label: "Severity", Param: "severities", Domain: sev},
		{Key: FieldFacility, Label: "Facility", Param: "facilities", Domain: fac},
		{Key: FieldHost, Label: "Host", Param: "host", ExcludeParam: "exclude_host"},
		{Key: FieldApp, Label: "Program/tag", Param: "app", ExcludeParam: "exclude_app"},
	}
}()

type syslogType struct{}

func (syslogType) Name() string    { return Syslog }
func (syslogType) Label() string   { return "Syslog" }
func (syslogType) Dir() string     { return "" }
func (syslogType) Default() bool   { return true }
func (syslogType) Fields() []Field { return syslogFields }
func (syslogType) FilterParams() []string {
	return []string{"severities", "min_severity", "facilities", "app", "host", "exclude_app", "exclude_host"}
}

// Text is the raw message.
func (syslogType) Text(rec []byte) []byte { return rec }

func (syslogType) FieldValues(rec []byte, sc *Scratch, emit func(key, value string)) {
	p := PRI(rec)
	sev, fac := "unknown", "unknown"
	if p >= 0 {
		sev, fac = itoa(p&7), itoa(p>>3)
	}
	emit(FieldSeverity, sev)
	emit(FieldFacility, fac)
	syslog.Parse(rec, &sc.Msg)
	emit(FieldHost, sc.Msg.Hostname)
	emit(FieldApp, sc.Msg.App)
}

func (syslogType) ValueLabel(key, value string) string {
	for _, f := range syslogFields {
		if f.Key == key {
			for _, d := range f.Domain {
				if d.Value == value {
					return d.Label
				}
			}
		}
	}
	return value
}

// NewSummary counts the records by severity.
func (syslogType) NewSummary() Summary { return &syslogSummary{} }

// SyslogFilter is the syslog type's filter: severities, facilities, and the
// program/tag and hostname of the header (FieldMatcher).
type SyslogFilter struct {
	Severities hub.SeveritySet // 0: all; hub.SeverityNone: nothing
	Facilities FacilitySet     // 0: all; FacilityNone: nothing
	Fields     *FieldMatcher   // nil: no app or host filter
}

// NewSyslogFilter compiles 1.1's syslog filter fields.
func NewSyslogFilter(sevs hub.SeveritySet, facs FacilitySet, apps, hosts, exApps, exHosts []string) *SyslogFilter {
	return &SyslogFilter{Severities: sevs, Facilities: facs, Fields: NewFieldMatcher(apps, hosts, exApps, exHosts)}
}

func (f *SyslogFilter) Empty() bool { return f.Severities == 0 && f.Facilities == 0 && f.Fields == nil }
func (f *SyslogFilter) None() bool {
	return f.Severities == hub.SeverityNone || f.Facilities == FacilityNone
}

// Pre checks the severity and facility (the PRI).
func (f *SyslogFilter) Pre(rec []byte) bool {
	if f.Severities == 0 && f.Facilities == 0 {
		return true
	}
	p := PRI(rec)
	sev, fac := model.Unknown, model.Unknown
	if p >= 0 {
		sev, fac = p&7, p>>3
	}
	if f.Severities != 0 && !f.Severities.Has(sev) {
		return false
	}
	return f.Facilities == 0 || f.Facilities.Has(fac)
}

// Post parses the header for the app and host filters.
func (f *SyslogFilter) Post(rec []byte, sc *Scratch) bool {
	return f.Fields == nil || f.Fields.Match(rec, &sc.Msg)
}
