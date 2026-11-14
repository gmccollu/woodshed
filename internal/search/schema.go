package search

import (
	"strconv"

	"github.com/gmccollu/woodshed/internal/datatype"
)

// The data types Events can show, and each one's fields (GET /api/search/schema,
// SPEC §10.1.1 and §10.1.6). The client builds its field panel from this list
// alone, so a new data type adds an entry here with its own fields.

// TypeSyslog is the default data type; TypeTrap the SNMP traps (SPEC §11.1).
const (
	TypeSyslog = datatype.Syslog
	TypeTrap   = datatype.Trap
)

// DomainValue is one value of a closed field.
type DomainValue = datatype.DomainValue

// FieldSchema describes one field of a type's field panel.
type FieldSchema = datatype.Field

// TypeSchema is one data type.
type TypeSchema struct {
	Type, Label string
	Default     bool
	Fields      []FieldSchema
}

// Field keys of the syslog type, in panel order.
const (
	FieldDevice   = datatype.FieldDevice
	FieldSeverity = datatype.FieldSeverity
	FieldFacility = datatype.FieldFacility
	FieldHost     = datatype.FieldHost
	FieldApp      = datatype.FieldApp
)

var syslogFields = datatype.Get(datatype.Syslog).Fields()

// Schema returns every data type, the default first (the registry in
// internal/datatype).
func Schema() []TypeSchema {
	var out []TypeSchema
	for _, t := range datatype.Types() {
		out = append(out, TypeSchema{Type: t.Name(), Label: t.Label(), Default: t.Default(), Fields: t.Fields()})
	}
	return out
}

// CheckType validates a type parameter ("" is the default).
func CheckType(t string) error {
	if t == "" || datatype.Get(t) != nil {
		return nil
	}
	return &QueryError{Msg: "type: unknown data type " + strconv.Quote(t) + "."}
}
