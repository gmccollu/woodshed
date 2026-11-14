package datatype

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// The SNMP trap type (SPEC §11.2.4, §11.2.5): records are snmp.FormatRecord
// lines in logs/<device>/traps/. Filters and the field panel read the record's
// header (snmp.ParseRecordHeader); q reads the record without raw=; names come
// from the current MIB set (SetMIBs), so a name can show that the stored line
// lacks.

// Trap field keys, in panel order (after device).
const (
	FieldVersion    = "version"
	FieldPDU        = "pdu"
	FieldTrapOID    = "trap_oid"
	FieldEnterprise = "enterprise"
	FieldGeneric    = "generic"
	FieldSpecific   = "specific"
	FieldCred       = "cred"
	FieldStatus     = "status"
)

// PDUUnexpected is the pdu field's value for any PDU but a trap or inform.
const PDUUnexpected = "unexpected"

var genericNames = []string{"coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss", "enterpriseSpecific"}

var trapFields = func() []Field {
	gen := make([]DomainValue, len(genericNames))
	for i, n := range genericNames {
		gen[i] = DomainValue{itoa(i), n}
	}
	var st []DomainValue
	for _, s := range snmp.Statuses() {
		l := s
		switch s {
		case "auth_failed":
			l = "wrong auth"
		case "decrypt_failed":
			l = "can't decrypt"
		case "level":
			l = "below the user's level"
		case "unexpected_pdu":
			l = "unexpected PDU"
		case "unknown_user":
			l = "unknown user"
		case "unknown_engine":
			l = "unknown engine"
		case "not_in_time":
			l = "not in time"
		}
		st = append(st, DomainValue{s, l})
	}
	return []Field{
		deviceField,
		{Key: FieldVersion, Label: "Version", Param: "snmp_versions", Domain: []DomainValue{{"1", "v1"}, {"2c", "v2c"}, {"3", "v3"}}},
		{Key: FieldPDU, Label: "PDU", Param: "pdus", Domain: []DomainValue{{"v1trap", "v1 trap"}, {"trap", "trap"}, {"inform", "inform"},
			{PDUUnexpected, "other PDU"}}},
		{Key: FieldTrapOID, Label: "Trap", Param: "trap_oid", ExcludeParam: "exclude_trap_oid"},
		{Key: FieldEnterprise, Label: "Enterprise (v1)", Param: "enterprise", ExcludeParam: "exclude_enterprise"},
		{Key: FieldGeneric, Label: "Generic trap (v1)", Param: "generic", Domain: gen},
		{Key: FieldSpecific, Label: "Specific trap (v1)", Param: "specific", ExcludeParam: "exclude_specific"},
		{Key: FieldCred, Label: "Community or user", Param: "cred", ExcludeParam: "exclude_cred"},
		{Key: FieldStatus, Label: "Status", Param: "status", Domain: st},
	}
}()

// The current MIB set (the server's, reloaded with Reload MIBs). Until a
// server sets it, the built-in set names the standard traps.
var mibs atomic.Pointer[snmp.MIBSet]

// SetMIBs makes s the MIB set filters, labels and results name OIDs with.
func SetMIBs(s *snmp.MIBSet) { mibs.Store(s) }

// MIBs returns the current MIB set.
func MIBs() *snmp.MIBSet {
	if s := mibs.Load(); s != nil {
		return s
	}
	s := snmp.BuiltinMIBs()
	mibs.CompareAndSwap(nil, s)
	return mibs.Load()
}

type trapType struct{}

func (trapType) Name() string    { return Trap }
func (trapType) Label() string   { return "SNMP traps" }
func (trapType) Dir() string     { return "traps" }
func (trapType) Default() bool   { return false }
func (trapType) Fields() []Field { return trapFields }
func (trapType) FilterParams() []string {
	return []string{"snmp_versions", "pdus", "trap_oid", "exclude_trap_oid", "enterprise", "exclude_enterprise", "generic",
		"specific", "exclude_specific", "cred", "exclude_cred", "status"}
}

// Text is the record without raw= (a search never matches base64).
func (trapType) Text(rec []byte) []byte { return snmp.RecordText(rec) }

// pduValue is the pdu field's value of a record's pdu=.
func pduValue(p string) string {
	switch p {
	case "v1trap", "trap", "inform":
		return p
	case "":
		return ""
	}
	return PDUUnexpected
}

func (trapType) FieldValues(rec []byte, sc *Scratch, emit func(key, value string)) {
	r, _ := snmp.ParseRecordHeader(rec)
	emit(FieldVersion, r.Version)
	emit(FieldPDU, pduValue(r.PDU))
	emit(FieldTrapOID, r.Trap)
	emit(FieldEnterprise, r.Enterprise)
	emit(FieldGeneric, r.Generic)
	emit(FieldSpecific, r.Specific)
	emit(FieldCred, r.Cred)
	emit(FieldStatus, r.Status)
}

func (trapType) ValueLabel(key, value string) string {
	switch key {
	case FieldTrapOID, FieldEnterprise:
		if o, err := snmp.ParseOID(value); err == nil {
			if n := MIBs().Name(o); n != "" {
				return n
			}
		}
		return value
	}
	for _, f := range trapFields {
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

// The standard reboot notifications (RFC 3418): coldStart and warmStart.
var (
	oidColdStart = "1.3.6.1.6.3.1.1.5.1"
	oidWarmStart = "1.3.6.1.6.3.1.1.5.2"
)

// IsReboot reports whether a trap OID is coldStart or warmStart, and which.
func IsReboot(trapOID string) (string, bool) {
	switch trapOID {
	case oidColdStart:
		return "coldStart", true
	case oidWarmStart:
		return "warmStart", true
	}
	return "", false
}

// Summary counts the records by trap name (or OID), most first, and says how
// many were reboots (coldStart, warmStart).
func (t trapType) Summary(recs [][]byte) []string {
	by := map[string]int64{}
	var reboots int64
	for _, rec := range recs {
		r, err := snmp.ParseRecordHeader(rec)
		if err != nil {
			continue
		}
		k := r.Trap
		if k == "" {
			k = "(" + r.Status + ")"
		} else {
			if _, ok := IsReboot(k); ok {
				reboots++
			}
			k = t.ValueLabel(FieldTrapOID, k)
		}
		by[k]++
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if by[keys[i]] != by[keys[j]] {
			return by[keys[i]] > by[keys[j]]
		}
		return keys[i] < keys[j]
	})
	var out []string
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s: %d", k, by[k]))
	}
	if reboots > 0 {
		out = append(out, fmt.Sprintf("reboots (coldStart, warmStart): %d", reboots))
	}
	return out
}

// ---- the filter ----

// oidPattern is one trap_oid or enterprise value: an OID, exact or (with a
// trailing ".*") a prefix that also matches the OID itself.
type oidPattern struct {
	oid    string
	prefix bool
}

func (p oidPattern) match(o string) bool {
	if o == "" {
		return false
	}
	if o == p.oid {
		return true
	}
	return p.prefix && strings.HasPrefix(o, p.oid) && len(o) > len(p.oid) && o[len(p.oid)] == '.'
}

func anyOID(ps []oidPattern, o string) bool {
	for _, p := range ps {
		if p.match(o) {
			return true
		}
	}
	return false
}

// TrapFilter is the trap type's filter (SPEC §11.2.5). Sets are nil for all;
// Nothing marks a set given as "none".
type TrapFilter struct {
	Versions, PDUs, Generic, Status []string // sets (empty: all)
	Nothing                         bool     // a set was "none": nothing passes
	TrapOID, ExcludeTrapOID         []string // OIDs as given, resolved (".*" kept)
	Enterprise, ExcludeEnterprise   []string
	Specific, ExcludeSpecific       []string // integers
	Cred, ExcludeCred               []string // community hashes or user names, lower-cased

	trap, exTrap, ent, exEnt []oidPattern
}

// ParseTrapFilter reads the trap filter parameters through get ("" when a
// parameter is absent). Errors name the parameter, as for syslog's.
func ParseTrapFilter(get func(string) string) (*TrapFilter, error) {
	f := &TrapFilter{}
	var err error
	sets := []struct {
		param string
		dom   []string
		out   *[]string
	}{
		{"snmp_versions", []string{"1", "2c", "3"}, &f.Versions},
		{"pdus", []string{"v1trap", "trap", "inform", PDUUnexpected}, &f.PDUs},
		{"generic", []string{"0", "1", "2", "3", "4", "5", "6"}, &f.Generic},
		{"status", snmp.Statuses(), &f.Status},
	}
	for _, s := range sets {
		var none bool
		if *s.out, none, err = parseSet(s.param, get(s.param), s.dom); err != nil {
			return nil, err
		}
		f.Nothing = f.Nothing || none
	}
	oids := []struct {
		param string
		out   *[]string
		pats  *[]oidPattern
	}{
		{"trap_oid", &f.TrapOID, &f.trap}, {"exclude_trap_oid", &f.ExcludeTrapOID, &f.exTrap},
		{"enterprise", &f.Enterprise, &f.ent}, {"exclude_enterprise", &f.ExcludeEnterprise, &f.exEnt},
	}
	for _, o := range oids {
		for _, v := range splitList(get(o.param)) {
			p, err := parseOIDPattern(o.param, v)
			if err != nil {
				return nil, err
			}
			s := p.oid
			if p.prefix {
				s += ".*"
			}
			*o.out = append(*o.out, s)
			*o.pats = append(*o.pats, p)
		}
	}
	for _, s := range []struct {
		param string
		out   *[]string
	}{{"specific", &f.Specific}, {"exclude_specific", &f.ExcludeSpecific}} {
		for _, v := range splitList(get(s.param)) {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, &ParamError{Param: s.param, Msg: fmt.Sprintf("%s: %q is not an integer.", s.param, v)}
			}
			*s.out = append(*s.out, strconv.FormatInt(n, 10))
		}
	}
	for _, s := range []struct {
		param string
		out   *[]string
	}{{"cred", &f.Cred}, {"exclude_cred", &f.ExcludeCred}} {
		for _, v := range splitList(get(s.param)) {
			*s.out = append(*s.out, strings.ToLower(v))
		}
	}
	return f, nil
}

// Compile rebuilds the patterns of a TrapFilter made by hand or decoded (a
// saved search, an export), resolving MIB names again.
func (f *TrapFilter) Compile() error {
	f.trap, f.exTrap, f.ent, f.exEnt = nil, nil, nil, nil
	for _, o := range []struct {
		param string
		in    []string
		pats  *[]oidPattern
	}{{"trap_oid", f.TrapOID, &f.trap}, {"exclude_trap_oid", f.ExcludeTrapOID, &f.exTrap},
		{"enterprise", f.Enterprise, &f.ent}, {"exclude_enterprise", f.ExcludeEnterprise, &f.exEnt}} {
		for _, v := range o.in {
			p, err := parseOIDPattern(o.param, v)
			if err != nil {
				return err
			}
			*o.pats = append(*o.pats, p)
		}
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// parseSet reads a closed set ("none" alone means nothing; "" all).
func parseSet(param, v string, dom []string) ([]string, bool, error) {
	var out []string
	none := false
	for _, item := range splitList(v) {
		if strings.EqualFold(item, "none") {
			none = true
			continue
		}
		if !slices.Contains(dom, item) {
			return nil, false, &ParamError{Param: param, Msg: fmt.Sprintf("%s: %q is not one of %s (or none on its own).", param, item,
				strings.Join(dom, ", "))}
		}
		if !slices.Contains(out, item) {
			out = append(out, item)
		}
	}
	if none && len(out) > 0 {
		return nil, false, &ParamError{Param: param, Msg: param + ": none can't be combined with other values."}
	}
	return out, none, nil
}

// parseOIDPattern reads an OID (dotted, a trailing ".*" for a prefix) or a
// MIB name ("linkDown", "IF-MIB::linkDown", also with ".*").
func parseOIDPattern(param, v string) (oidPattern, error) {
	p := oidPattern{}
	if s, ok := strings.CutSuffix(v, ".*"); ok {
		p.prefix, v = true, s
	}
	if o, err := snmp.ParseOID(v); err == nil && len(o) > 0 {
		p.oid = o.String()
		return p, nil
	}
	if v == "" || !(v[0] >= 'a' && v[0] <= 'z' || v[0] >= 'A' && v[0] <= 'Z') {
		return p, &ParamError{Param: param, Msg: fmt.Sprintf("%s: %q is not an OID or a MIB name.", param, v)}
	}
	o, err := MIBs().Lookup(v)
	if err != nil {
		if errors.Is(err, snmp.ErrUnknownName) {
			return p, &ParamError{Param: param, Msg: fmt.Sprintf("%s: %q is not a name in the loaded MIBs.", param, v)}
		}
		return p, &ParamError{Param: param, Msg: fmt.Sprintf("%s: %s.", param, strings.TrimPrefix(err.Error(), "snmp: "))}
	}
	p.oid = o.String()
	return p, nil
}

// Empty reports whether the filter lets every record through.
func (f *TrapFilter) Empty() bool {
	return !f.Nothing && len(f.Versions) == 0 && len(f.PDUs) == 0 && len(f.Generic) == 0 && len(f.Status) == 0 &&
		len(f.TrapOID) == 0 && len(f.ExcludeTrapOID) == 0 && len(f.Enterprise) == 0 && len(f.ExcludeEnterprise) == 0 &&
		len(f.Specific) == 0 && len(f.ExcludeSpecific) == 0 && len(f.Cred) == 0 && len(f.ExcludeCred) == 0
}

// None reports whether a set was "none".
func (f *TrapFilter) None() bool { return f.Nothing }

// Pre has nothing cheaper than the header parse.
func (f *TrapFilter) Pre([]byte) bool { return !f.Nothing }

// Post reads the record's header and applies every check.
func (f *TrapFilter) Post(rec []byte, _ *Scratch) bool {
	r, err := snmp.ParseRecordHeader(rec)
	if err != nil {
		return false
	}
	in := func(set []string, v string) bool { return len(set) == 0 || slices.Contains(set, v) }
	if !in(f.Versions, r.Version) || !in(f.PDUs, pduValue(r.PDU)) || !in(f.Status, r.Status) {
		return false
	}
	if len(f.Generic) > 0 && !slices.Contains(f.Generic, r.Generic) {
		return false
	}
	if len(f.trap) > 0 && !anyOID(f.trap, r.Trap) {
		return false
	}
	if len(f.exTrap) > 0 && anyOID(f.exTrap, r.Trap) {
		return false
	}
	if len(f.ent) > 0 && !anyOID(f.ent, r.Enterprise) {
		return false
	}
	if len(f.exEnt) > 0 && anyOID(f.exEnt, r.Enterprise) {
		return false
	}
	if len(f.Specific) > 0 && !slices.Contains(f.Specific, r.Specific) {
		return false
	}
	if len(f.ExcludeSpecific) > 0 && r.Specific != "" && slices.Contains(f.ExcludeSpecific, r.Specific) {
		return false
	}
	cred := strings.ToLower(r.Cred)
	if len(f.Cred) > 0 && !slices.Contains(f.Cred, cred) {
		return false
	}
	if len(f.ExcludeCred) > 0 && cred != "" && slices.Contains(f.ExcludeCred, cred) {
		return false
	}
	return true
}

// Bind is the filter's canonical form, for cursor bindings.
func (f *TrapFilter) Bind() string {
	var b strings.Builder
	for _, l := range [][]string{f.Versions, f.PDUs, f.Generic, f.Status, f.TrapOID, f.ExcludeTrapOID, f.Enterprise,
		f.ExcludeEnterprise, f.Specific, f.ExcludeSpecific, f.Cred, f.ExcludeCred} {
		s := slices.Clone(l)
		slices.Sort(s)
		b.WriteString(strings.Join(s, ","))
		b.WriteByte(0)
	}
	if f.Nothing {
		b.WriteString("none")
	}
	return b.String()
}

// ---- the API result ----

// TrapResult is the "fields" of a type=trap search result (docs/api.md), with
// names from the current MIB set.
type TrapResult struct {
	Version    string        `json:"version"`
	PDU        string        `json:"pdu"`
	TrapOID    string        `json:"trap_oid"`
	TrapName   string        `json:"trap_name"`
	Enterprise string        `json:"enterprise"`
	Generic    *int64        `json:"generic"`
	Specific   *int64        `json:"specific"`
	Cred       string        `json:"cred"`
	Status     string        `json:"status"`
	Error      string        `json:"error"`
	Uptime     *uint64       `json:"uptime"`
	Dup        bool          `json:"dup"`
	Varbinds   []TrapVarbind `json:"varbinds"`
}

// TrapVarbind is one varbind of a TrapResult.
type TrapVarbind struct {
	OID       string `json:"oid"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	ValueName string `json:"value_name"`
}

// Result decodes a trap record into its API fields. A record that doesn't
// parse gives the fields it has (status "malformed" when it has none).
func Result(rec []byte) TrapResult {
	r, err := snmp.ParseRecord(rec)
	if err != nil && r.Status == "" {
		if h, herr := snmp.ParseRecordHeader(rec); herr == nil {
			r = h
		}
	}
	set := MIBs()
	name := func(oid, stored string) string {
		if o, err := snmp.ParseOID(oid); err == nil {
			if n := set.Name(o); n != "" {
				return n
			}
		}
		return stored
	}
	out := TrapResult{Version: r.Version, PDU: r.PDU, TrapOID: r.Trap, Enterprise: r.Enterprise, Cred: r.Cred,
		Status: r.Status, Error: r.Error, Dup: r.Dup, Varbinds: []TrapVarbind{}}
	if out.Status == "" {
		out.Status = "malformed"
	}
	if r.Trap != "" {
		out.TrapName = name(r.Trap, r.TrapName)
	}
	if r.Version == "1" {
		if n, err := strconv.ParseInt(r.Generic, 10, 64); err == nil {
			out.Generic = &n
		}
		if n, err := strconv.ParseInt(r.Specific, 10, 64); err == nil {
			out.Specific = &n
		}
	}
	if n, err := strconv.ParseUint(r.Uptime, 10, 64); err == nil {
		out.Uptime = &n
	}
	for _, vb := range r.Varbinds {
		v := TrapVarbind{OID: vb.OID, Name: name(vb.OID, vb.Name), Type: vb.Type, Value: vb.Value, ValueName: vb.Enum}
		if o, err := snmp.ParseOID(vb.OID); err == nil {
			switch vb.Type {
			case snmp.TypeInt:
				if n, err := strconv.ParseInt(vb.Value, 10, 64); err == nil {
					if e := set.EnumName(o, n); e != "" {
						v.ValueName = e
					}
				}
			case snmp.TypeOID:
				if vo, err := snmp.ParseOID(vb.Value); err == nil {
					if n := set.Name(vo); n != "" {
						v.ValueName = n
					}
				}
			}
		}
		out.Varbinds = append(out.Varbinds, v)
	}
	return out
}
