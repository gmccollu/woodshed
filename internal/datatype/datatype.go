// Package datatype is Woodshed's pluggable data types (SPEC §11.1): a named
// kind of record (syslog, trap; later poll, flow) that shares the pipeline —
// device identity and admission, the store's per-device writers and their line
// envelope, the index, retention and the low-disk guard, the search engine,
// Events' summary and histogram, export — and brings its own parts: its folder
// inside the device folder, its schema fields, its filter, what q matches, the
// field panel's values, its API result and its bundle summary.
//
// Syslog is the first implementation, with 1.1's behaviour unchanged; SNMP
// traps (trap.go) the second. The storage side of the registry (each type's
// folder) is logfile.DataTypes; Types checks the two agree.
package datatype

import (
	"strconv"

	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Type names.
const (
	Syslog = logfile.TypeSyslog
	Trap   = logfile.TypeTrap
	Poll   = logfile.TypePoll
)

// DomainValue is one value of a closed field.
type DomainValue struct {
	Value, Label string
}

// Field describes one field of a type's field panel (GET /api/search/schema).
type Field struct {
	Key, Label string
	// Param is the filter parameter a value goes into; ExcludeParam the one
	// that excludes it ("" for a field with a Domain: send the complement).
	Param, ExcludeParam string
	// Domain is the complete value set of a closed field, or nil.
	Domain []DomainValue
}

// Scratch is a scan's reusable state for a type's filter and field values
// (one per goroutine).
type Scratch struct {
	Msg model.Message // syslog's header parse
	buf []byte
}

// Filter is a type's own filter, compiled: the parameters beyond the shared
// ones (q, syntax, regex, case, exclude, the devices and the range).
type Filter interface {
	// Empty reports whether it lets every record through.
	Empty() bool
	// None reports whether it lets nothing through (a "none" set).
	None() bool
	// Pre applies the cheap checks, before q; Post the costly ones, after q
	// and exclude. rec is the unescaped stored record.
	Pre(rec []byte) bool
	Post(rec []byte, sc *Scratch) bool
}

// Type is one data type.
type Type interface {
	// Name is the type parameter's value; Label the UI's.
	Name() string
	Label() string
	// Dir is the type's folder inside a device folder ("" is the device
	// folder itself).
	Dir() string
	// Default reports whether it's the type of a request without one.
	Default() bool
	// Fields are the schema's field descriptors, in panel order; "device"
	// first.
	Fields() []Field
	// FilterParams are the names of the type's own filter parameters; any
	// of them on a request of another type is a 400.
	FilterParams() []string
	// Text is the part of a record q and exclude match.
	Text(rec []byte) []byte
	// FieldValues calls emit with each field's value of a record (the device
	// aside; "" for a record without one), in Fields order.
	FieldValues(rec []byte, sc *Scratch, emit func(key, value string))
	// ValueLabel is a field value's label in the field panel.
	ValueLabel(key, value string) string
	// NewSummary starts a bundle's summary of one device's records of the
	// type (summary.go).
	NewSummary() Summary
}

// FieldDevice is every type's first field.
const FieldDevice = "device"

var deviceField = Field{Key: FieldDevice, Label: "Device", Param: "devices", ExcludeParam: "exclude_devices"}

// types is the registry, syslog first.
var types = []Type{syslogType{}, trapType{}, pollType{}, flowType{}}

// Types returns every type, the default first.
func Types() []Type { return types }

// Get returns the type with this name ("" is the default, syslog), or nil.
func Get(name string) Type {
	if name == "" {
		return types[0]
	}
	for _, t := range types {
		if t.Name() == name {
			return t
		}
	}
	return nil
}

// Names lists the type names, in registry order.
func Names() []string {
	out := make([]string, len(types))
	for i, t := range types {
		out[i] = t.Name()
	}
	return out
}

// CheckParams refuses another type's filter parameters on a request of type t
// (SPEC §11.2.5: "severities: not a filter for SNMP traps."). has reports
// whether a parameter is present.
func CheckParams(t Type, has func(string) bool) error {
	own := map[string]bool{}
	for _, p := range t.FilterParams() {
		own[p] = true
	}
	for _, o := range types {
		if o.Name() == t.Name() {
			continue
		}
		for _, p := range o.FilterParams() {
			// A name two types share (traps' and flows' status) is each one's own.
			if has(p) && !own[p] {
				return &ParamError{Param: p, Msg: p + ": not a filter for " + labelLower(t) + "."}
			}
		}
	}
	return nil
}

// labelLower is a type's label as it reads inside a sentence.
func labelLower(t Type) string {
	if t.Name() == Syslog {
		return "syslog"
	}
	return t.Label()
}

// ParamError is a filter parameter a type refuses (a 400 naming it).
type ParamError struct {
	Param string
	Msg   string
}

func (e *ParamError) Error() string { return e.Msg }

func itoa(i int) string { return strconv.Itoa(i) }
