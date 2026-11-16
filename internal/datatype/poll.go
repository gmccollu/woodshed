package datatype

import (
	"fmt"
	"slices"
	"strings"

	"github.com/gmccollu/woodshed/internal/pollrec"
)

// The SNMP poll type (SPEC §12.3): records are pollrec lines in
// logs/<device>/poll/, one per cycle per part. They're searchable as lines
// (the API, the summary and `woodshed search`); Events shows them as graphs,
// not as a tab. Filters and the field panel read the parsed record.

// Poll field keys, in panel order (after device).
const (
	FieldKind   = "kind"
	FieldIf     = "if"
	FieldOper   = "oper"
	FieldReboot = "reboot"
)

// The poll type's status field shares the trap type's key (FieldStatus), with
// its own domain.

func domainOf(vals []string, label func(string) string) []DomainValue {
	out := make([]DomainValue, len(vals))
	for i, v := range vals {
		l := v
		if label != nil {
			l = label(v)
		}
		out[i] = DomainValue{v, l}
	}
	return out
}

var pollKindLabels = map[string]string{
	pollrec.KindSys: "system", pollrec.KindIf: "interface", pollrec.KindOID: "custom OID", pollrec.KindStatus: "failed cycle",
	pollrec.KindRestart: "restart", pollrec.KindInfo: "names and descriptions",
}

var pollStatusLabels = map[string]string{
	"ok": "answered", "timeout": "timeout", "unreachable": "unreachable", "auth_failed": "wrong auth",
	"unknown_user": "unknown user", "unknown_engine": "unknown engine", "not_in_time": "not in time",
	"decrypt_failed": "can't decrypt", "error": "error", "overrun": "skipped (overrun)",
}

var pollRebootLabels = map[string]string{"1": "reboot", "0": "agent restart", "?": "restart (may have rebooted)"}

var pollFields = []Field{
	deviceField,
	{Key: FieldKind, Label: "Kind", Param: "kinds", Domain: domainOf(pollrec.Kinds(), func(v string) string { return pollKindLabels[v] })},
	{Key: FieldIf, Label: "Interface", Param: "ifs", ExcludeParam: "exclude_ifs"},
	{Key: FieldOper, Label: "Oper status", Param: "oper", Domain: domainOf(pollrec.OperNames, nil)},
	{Key: FieldStatus, Label: "Status", Param: "poll_status", Domain: domainOf(pollrec.Statuses(), func(v string) string { return pollStatusLabels[v] })},
	{Key: FieldReboot, Label: "Restart", Param: "reboot", Domain: domainOf([]string{"1", "0", "?"}, func(v string) string { return pollRebootLabels[v] })},
}

type pollType struct{}

func (pollType) Name() string    { return Poll }
func (pollType) Label() string   { return "SNMP polls" }
func (pollType) Dir() string     { return "poll" }
func (pollType) Default() bool   { return false }
func (pollType) Fields() []Field { return pollFields }
func (pollType) FilterParams() []string {
	return []string{"kinds", "ifs", "exclude_ifs", "oper", "poll_status", "reboot"}
}

// Text is the whole record: it holds no base64 or secrets.
func (pollType) Text(rec []byte) []byte { return pollrec.Text(rec) }

// pollStatus is a record's status field: kind=status's own, "ok" for every
// other kind (an answered cycle).
func pollStatus(r *pollrec.Record) string {
	if r.Kind == pollrec.KindStatus {
		return r.Value("status")
	}
	return "ok"
}

// pollIf is a record's if field: the interface name (or index) of an if or
// interface info record, "" otherwise.
func pollIf(r *pollrec.Record) string {
	if r.Kind != pollrec.KindIf && !(r.Kind == pollrec.KindInfo && r.Value("if") != "") {
		return ""
	}
	return pollrec.IfName(r)
}

func (pollType) FieldValues(rec []byte, _ *Scratch, emit func(key, value string)) {
	r, err := pollrec.Parse(rec)
	if err != nil {
		emit(FieldKind, "")
		emit(FieldIf, "")
		emit(FieldOper, "")
		emit(FieldStatus, "")
		emit(FieldReboot, "")
		return
	}
	emit(FieldKind, r.Kind)
	emit(FieldIf, pollIf(&r))
	oper := ""
	if r.Kind == pollrec.KindIf {
		oper = r.Value("oper")
	}
	emit(FieldOper, oper)
	emit(FieldStatus, pollStatus(&r))
	reboot := ""
	if r.Kind == pollrec.KindRestart {
		reboot = r.Value("reboot")
	}
	emit(FieldReboot, reboot)
}

func (pollType) ValueLabel(key, value string) string {
	for _, f := range pollFields {
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

func (pollType) NewSummary() Summary { return &PollSummary{} }

// ---- the filter ----

// PollFilter is the poll type's filter (SPEC §12.3): kinds, ifs and
// exclude_ifs (interface names, case-insensitive, or indexes), oper,
// poll_status and reboot. Sets are nil for all; Nothing marks a set given as
// "none".
type PollFilter struct {
	Kinds      []string `json:"kinds,omitempty"`
	Ifs        []string `json:"ifs,omitempty"`
	ExcludeIfs []string `json:"exclude_ifs,omitempty"`
	Oper       []string `json:"oper,omitempty"`
	Status     []string `json:"poll_status,omitempty"`
	Reboot     []string `json:"reboot,omitempty"`
	Nothing    bool     `json:"nothing,omitempty"`
}

// ParsePollFilter reads the poll filter parameters through get ("" when a
// parameter is absent). Errors name the parameter.
func ParsePollFilter(get func(string) string) (*PollFilter, error) {
	f := &PollFilter{}
	sets := []struct {
		param string
		dom   []string
		out   *[]string
	}{
		{"kinds", pollrec.Kinds(), &f.Kinds},
		{"oper", pollrec.OperNames, &f.Oper},
		{"poll_status", pollrec.Statuses(), &f.Status},
		{"reboot", []string{"1", "0", "?"}, &f.Reboot},
	}
	for _, s := range sets {
		v, none, err := parseSet(s.param, get(s.param), s.dom)
		if err != nil {
			return nil, err
		}
		*s.out = v
		f.Nothing = f.Nothing || none
	}
	for _, s := range []struct {
		param string
		out   *[]string
	}{{"ifs", &f.Ifs}, {"exclude_ifs", &f.ExcludeIfs}} {
		for _, v := range splitList(get(s.param)) {
			if len(v) > 256 {
				return nil, &ParamError{Param: s.param, Msg: fmt.Sprintf("%s: an interface name is at most 256 bytes.", s.param)}
			}
			*s.out = append(*s.out, strings.ToLower(v))
		}
	}
	return f, nil
}

// Empty reports whether the filter lets every record through.
func (f *PollFilter) Empty() bool {
	return !f.Nothing && len(f.Kinds) == 0 && len(f.Ifs) == 0 && len(f.ExcludeIfs) == 0 && len(f.Oper) == 0 &&
		len(f.Status) == 0 && len(f.Reboot) == 0
}

// None reports whether a set was "none".
func (f *PollFilter) None() bool { return f.Nothing }

// Pre checks the kind (it's the record's first key) without a parse.
func (f *PollFilter) Pre(rec []byte) bool {
	if f.Nothing {
		return false
	}
	if len(f.Kinds) > 0 && !slices.Contains(f.Kinds, pollrec.KindOf(rec)) {
		return false
	}
	return true
}

// ifMatch reports whether an interface (name or index) is in a list of
// lower-cased names and indexes.
func ifMatch(list []string, r *pollrec.Record) bool {
	name, idx := strings.ToLower(r.Value("name")), r.Value("if")
	for _, v := range list {
		if v == idx || (name != "" && v == name) {
			return true
		}
	}
	return false
}

// Post parses the record and applies every check.
func (f *PollFilter) Post(rec []byte, _ *Scratch) bool {
	r, err := pollrec.Parse(rec)
	if err != nil {
		return false
	}
	return f.Match(&r)
}

// Match applies the filter to a parsed record.
func (f *PollFilter) Match(r *pollrec.Record) bool {
	if f.Nothing {
		return false
	}
	if len(f.Kinds) > 0 && !slices.Contains(f.Kinds, r.Kind) {
		return false
	}
	hasIf := pollIf(r) != ""
	if len(f.Ifs) > 0 && (!hasIf || !ifMatch(f.Ifs, r)) {
		return false
	}
	if len(f.ExcludeIfs) > 0 && hasIf && ifMatch(f.ExcludeIfs, r) {
		return false
	}
	if len(f.Oper) > 0 && (r.Kind != pollrec.KindIf || !slices.Contains(f.Oper, r.Value("oper"))) {
		return false
	}
	if len(f.Status) > 0 && !slices.Contains(f.Status, pollStatus(r)) {
		return false
	}
	if len(f.Reboot) > 0 && (r.Kind != pollrec.KindRestart || !slices.Contains(f.Reboot, r.Value("reboot"))) {
		return false
	}
	return true
}

// Bind is the filter's canonical form, for cursor bindings.
func (f *PollFilter) Bind() string {
	var b strings.Builder
	b.WriteString("poll\x00")
	for _, l := range [][]string{f.Kinds, f.Ifs, f.ExcludeIfs, f.Oper, f.Status, f.Reboot} {
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

// WithKinds is the filter narrowed to the kinds also in kinds (an export's
// per-file pass); ok is false when nothing would pass.
func (f *PollFilter) WithKinds(kinds ...string) (*PollFilter, bool) {
	out := &PollFilter{}
	if f != nil {
		c := *f
		out = &c
	}
	if out.Nothing {
		return out, false
	}
	var ks []string
	for _, k := range kinds {
		if len(out.Kinds) == 0 || slices.Contains(out.Kinds, k) {
			ks = append(ks, k)
		}
	}
	out.Kinds = ks
	return out, len(ks) > 0
}

// ---- the API result ----

// PollResult is the "fields" of a type=poll search result (docs/api.md): the
// kind, cycle, interface, oper status, status and reboot, and every other key
// of the record as text in values.
type PollResult struct {
	Kind   string            `json:"kind"`
	Cycle  uint64            `json:"cycle"`
	If     string            `json:"if"`
	Oper   string            `json:"oper"`
	Status string            `json:"status"`
	Reboot string            `json:"reboot"`
	Values map[string]string `json:"values"`
}

// PollResultOf decodes a poll record into its API fields. A record that
// doesn't parse has an empty kind and the error as values.error.
func PollResultOf(rec []byte) PollResult {
	r, err := pollrec.Parse(rec)
	out := PollResult{Values: map[string]string{}}
	if err != nil {
		out.Values["error"] = err.Error()
		return out
	}
	out.Kind, out.Cycle, out.If, out.Status = r.Kind, r.Cycle, pollIf(&r), pollStatus(&r)
	if r.Kind == pollrec.KindIf {
		out.Oper = r.Value("oper")
	}
	if r.Kind == pollrec.KindRestart {
		out.Reboot = r.Value("reboot")
	}
	for _, kv := range r.Fields {
		switch kv.Key {
		case "oper":
			if r.Kind == pollrec.KindIf {
				continue
			}
		case "status":
			if r.Kind == pollrec.KindStatus {
				continue
			}
		case "reboot":
			if r.Kind == pollrec.KindRestart {
				continue
			}
		}
		out.Values[kv.Key] = kv.Value
	}
	return out
}

// RestartDetail says what a restart record shows, for the bundle and the
// timeline: "sysUpTime and hrSystemUptime reset", "sysUpTime reset; the device
// may have rebooted", "engineBoots went up; the agent restarted, not the
// device".
func RestartDetail(r *pollrec.Record) string {
	var reset []string
	boots := false
	for _, s := range strings.Split(r.Value("source"), ",") {
		switch s = strings.TrimSpace(s); s {
		case "":
		case "engineBoots":
			boots = true
		default:
			reset = append(reset, s)
		}
	}
	var parts []string
	if len(reset) > 0 {
		parts = append(parts, strings.Join(reset, " and ")+" reset")
	}
	if boots {
		parts = append(parts, "engineBoots went up")
	}
	d := strings.Join(parts, ", ")
	if d == "" {
		d = "the agent restarted"
	}
	switch r.Value("reboot") {
	case "?":
		d += "; the device may have rebooted"
	case "0":
		d += "; the agent restarted, not the device"
	}
	return d
}
