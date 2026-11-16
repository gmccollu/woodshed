package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/model"
)

// ---- types (docs/api.md "Severity filters", "Search", "Exports") ----

// Unknown is the severity of a message with no parseable PRI.
const Unknown = -1

// Severities is a severity filter. The zero value means all severities; None
// means nothing (severities=none); otherwise only Values (0-7, Unknown) pass.
type Severities struct {
	None   bool
	Values []int
}

// All reports whether the filter lets every severity through.
func (s Severities) All() bool { return !s.None && len(s.Values) == 0 }

// UnmarshalJSON reads the export body's form: [0, 1, "unknown"], ["none"] or
// [] (all).
func (s *Severities) UnmarshalJSON(b []byte) error {
	*s = Severities{}
	if string(b) == "null" {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(b, &items); err != nil {
		return errors.New("severities must be a list of 0 to 7 and \"unknown\" (or [\"none\"])")
	}
	var parts []string
	for _, it := range items {
		var n int
		var str string
		switch {
		case json.Unmarshal(it, &n) == nil:
			parts = append(parts, strconv.Itoa(n))
		case json.Unmarshal(it, &str) == nil && str != "":
			parts = append(parts, str)
		default:
			return fmt.Errorf("severities: %s is not a severity (0 to 7, \"unknown\" or \"none\")", it)
		}
	}
	v, err := parseSeverityList(strings.Join(parts, ","))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// MarshalJSON writes the echo form: [] for all, ["none"], or the list.
func (s Severities) MarshalJSON() ([]byte, error) {
	out := []any{}
	switch {
	case s.None:
		out = append(out, "none")
	default:
		for _, v := range s.Values {
			if v == Unknown {
				out = append(out, "unknown")
			} else {
				out = append(out, v)
			}
		}
	}
	return json.Marshal(out)
}

// parseSeverityList reads "0,3,unknown" or "none" ("" is all).
func parseSeverityList(v string) (Severities, error) {
	var s Severities
	seen := map[int]bool{}
	none := false
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		switch {
		case item == "":
		case strings.EqualFold(item, "none"):
			none = true
		case strings.EqualFold(item, "unknown"):
			if !seen[Unknown] {
				seen[Unknown] = true
				s.Values = append(s.Values, Unknown)
			}
		case len(item) == 1 && item[0] >= '0' && item[0] <= '7':
			n := int(item[0] - '0')
			if !seen[n] {
				seen[n] = true
				s.Values = append(s.Values, n)
			}
		default:
			return Severities{}, fmt.Errorf("severities: %q is not a severity (0 to 7, unknown, or none on its own)", item)
		}
	}
	if none {
		if len(s.Values) > 0 {
			return Severities{}, errors.New("severities: none can't be combined with other values")
		}
		return Severities{None: true}, nil
	}
	return s, nil
}

// SearchRequest is GET /api/search, parsed and checked.
type SearchRequest struct {
	Q          string
	Regex      bool
	Case       bool
	Devices    []string
	Group      string
	Ungrouped  bool
	Severities Severities
	From, To   time.Time // zero: the default (to = now, from = to - 24 h)
	Asc        bool      // order=asc
	Limit      int       // 1-5,000
	Cursor     string
	App        []string // program/tag values (a trailing '*' is a prefix)
	Host       []string // header hostnames
	Exclude    string   // drop lines matching this (regex and case as for Q)
	// 1.1 (docs/api.md): the data type ("syslog"), syntax=terms, facilities and
	// the exclude forms of devices, app and host.
	Type           string
	Terms          bool
	Facilities     Facilities
	ExcludeDevices []string
	ExcludeApp     []string
	ExcludeHost    []string
	// 1.2: the trap type's filter (Type "trap"; nil: none). Syslog's filters
	// above stay empty for traps, and the trap filter nil for syslog.
	Trap *datatype.TrapFilter
	// 1.3: the poll type's filter (Type "poll"; nil: none).
	Poll *datatype.PollFilter
}

// SearchLine is one search result or context line.
type SearchLine struct {
	Received time.Time
	DeviceID string
	Severity int    // 0-7, or Unknown
	Raw      []byte // as received (a trap: the record)
	Ref      string
	App      string // parsed program/tag, "" when none
	Host     string // parsed header hostname, "" when none
	// Type is "" or "syslog" for the 1.1 shape; "trap" adds the decoded
	// fields (docs/api.md, "Search results for type=trap").
	Type string
	Trap *datatype.TrapResult
}

// MarshalJSON gives the docs/api.md shape: received with millisecond
// precision (like the log files), severity null when unknown, raw as a string
// (bytes that aren't valid UTF-8 become U+FFFD). A trap line has its own
// shape: type, ref, raw (the record) and fields.
func (l SearchLine) MarshalJSON() ([]byte, error) {
	if l.Type == datatype.Poll {
		return json.Marshal(struct {
			Received string              `json:"received"`
			DeviceID string              `json:"device_id"`
			Type     string              `json:"type"`
			Ref      string              `json:"ref"`
			Raw      string              `json:"raw"`
			Fields   datatype.PollResult `json:"fields"`
		}{l.Received.UTC().Format("2006-01-02T15:04:05.000Z07:00"), l.DeviceID, l.Type, l.Ref,
			string(bytes.ToValidUTF8(l.Raw, []byte("�"))), datatype.PollResultOf(l.Raw)})
	}
	if l.Type != "" && l.Type != datatype.Syslog {
		f := l.Trap
		if f == nil {
			r := datatype.Result(l.Raw)
			f = &r
		}
		return json.Marshal(struct {
			Received string               `json:"received"`
			DeviceID string               `json:"device_id"`
			Type     string               `json:"type"`
			Ref      string               `json:"ref"`
			Raw      string               `json:"raw"`
			Fields   *datatype.TrapResult `json:"fields"`
		}{l.Received.UTC().Format("2006-01-02T15:04:05.000Z07:00"), l.DeviceID, l.Type, l.Ref,
			string(bytes.ToValidUTF8(l.Raw, []byte("�"))), f})
	}
	var sev any
	if l.Severity >= 0 && l.Severity <= 7 {
		sev = l.Severity
	}
	return json.Marshal(struct {
		Received string `json:"received"`
		DeviceID string `json:"device_id"`
		Severity any    `json:"severity"`
		Raw      string `json:"raw"`
		Ref      string `json:"ref"`
		App      string `json:"app"`
		Host     string `json:"host"`
	}{l.Received.UTC().Format("2006-01-02T15:04:05.000Z07:00"), l.DeviceID, sev, string(bytes.ToValidUTF8(l.Raw, []byte("�"))), l.Ref,
		strings.ToValidUTF8(l.App, "�"), strings.ToValidUTF8(l.Host, "�")})
}

// SearchPage is the body of GET /api/search.
type SearchPage struct {
	Results      []SearchLine `json:"results"`
	NextCursor   string       `json:"next_cursor"`
	ScannedBytes int64        `json:"scanned_bytes"`
	ScannedFiles int          `json:"scanned_files"`
	ElapsedMS    int64        `json:"elapsed_ms"`
	Partial      bool         `json:"partial"`
}

// ContextPage is the body of GET /api/context.
type ContextPage struct {
	Lines    []SearchLine `json:"lines"`
	HitIndex int          `json:"hit_index"`
	AtStart  bool         `json:"at_start"`
	AtEnd    bool         `json:"at_end"`
}

// ExportRequest is the body of POST /api/exports and /api/exports/estimate.
type ExportRequest struct {
	AllDevices bool // every non-hidden device (instead of Devices, Group or Ungrouped)
	Devices    []string
	Group      string
	Ungrouped  bool
	From, To   time.Time
	Severities Severities
	Q          string
	Regex      bool
	Case       bool
	App        []string
	Host       []string
	Exclude    string
	// 1.1, as for SearchRequest.
	Type           string
	Terms          bool
	Facilities     Facilities
	ExcludeDevices []string
	ExcludeApp     []string
	ExcludeHost    []string
	// 1.2: the data types in the zip (["syslog"] by default, so a 1.1 body
	// builds the 1.1 zip) and, with one type, its filter (Trap for traps).
	Types []string
	Trap  *datatype.TrapFilter
	Poll  *datatype.PollFilter // 1.3: the poll type's filter
	// 1.2: the incident bundle (Kind "bundle"): the moment, the spans around
	// it and the devices active in the window (docs/api.md "Exports"). From
	// and To are left zero; the backend works the window out, cut at now.
	Kind          string // "" or "export", "bundle"
	At            time.Time
	Before, After time.Duration
	ActiveDevices bool
}

// ExportEstimate is the body of POST /api/exports/estimate.
type ExportEstimate struct {
	Lines int64 `json:"lines"`
	Bytes int64 `json:"bytes"`
	Files int   `json:"files"`
}

// ExportFilters echoes an export's filters.
type ExportFilters struct {
	Group      string     `json:"group"`
	Ungrouped  bool       `json:"ungrouped"`
	Severities Severities `json:"severities"`
	Q          string     `json:"q"`
	Regex      bool       `json:"regex"`
	Case       bool       `json:"case"`
	App        []string   `json:"app"`
	Host       []string   `json:"host"`
	Exclude    string     `json:"exclude"`
	// 1.1.
	Type           string     `json:"type"`
	Syntax         string     `json:"syntax"`
	Facilities     Facilities `json:"facilities"`
	ExcludeDevices []string   `json:"exclude_devices"`
	ExcludeApp     []string   `json:"exclude_app"`
	ExcludeHost    []string   `json:"exclude_host"`
	// 1.2.
	Kind  string     `json:"kind"`
	Types []string   `json:"types"`
	Trap  *TrapLists `json:"trap,omitempty"`
	// 1.3: the poll type's filter.
	Poll *PollLists `json:"poll,omitempty"`
	// A bundle's moment and spans ("30m"), and whether its devices are the
	// active ones; omitted for exports.
	At            *time.Time `json:"at,omitempty"`
	Before        string     `json:"before,omitempty"`
	After         string     `json:"after,omitempty"`
	ActiveDevices bool       `json:"active_devices,omitempty"`
}

// TrapLists is a trap filter as JSON lists (saved searches, export bodies
// and their echo): the parameters of docs/api.md "Trap filters".
type TrapLists struct {
	SNMPVersions      ValueList `json:"snmp_versions,omitempty"`
	PDUs              ValueList `json:"pdus,omitempty"`
	TrapOID           ValueList `json:"trap_oid,omitempty"`
	ExcludeTrapOID    ValueList `json:"exclude_trap_oid,omitempty"`
	Enterprise        ValueList `json:"enterprise,omitempty"`
	ExcludeEnterprise ValueList `json:"exclude_enterprise,omitempty"`
	Generic           ValueList `json:"generic,omitempty"`
	Specific          ValueList `json:"specific,omitempty"`
	ExcludeSpecific   ValueList `json:"exclude_specific,omitempty"`
	Cred              ValueList `json:"cred,omitempty"`
	ExcludeCred       ValueList `json:"exclude_cred,omitempty"`
	Status            ValueList `json:"status,omitempty"`
}

// ValueList is a JSON list of filter values: strings, or numbers for the
// numeric ones ("generic": [0, 6] or ["0", "6"]).
type ValueList []string

// UnmarshalJSON reads strings and numbers (as written).
func (l *ValueList) UnmarshalJSON(b []byte) error {
	*l = nil
	if string(b) == "null" {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(b, &items); err != nil {
		return errors.New("must be a list of strings or numbers")
	}
	for _, it := range items {
		var s string
		var n json.Number
		switch {
		case json.Unmarshal(it, &s) == nil:
			*l = append(*l, s)
		case json.Unmarshal(it, &n) == nil:
			*l = append(*l, n.String())
		default:
			return fmt.Errorf("%s is not a string or a number", it)
		}
	}
	return nil
}

// get is the lists as query parameters, for datatype.ParseTrapFilter.
func (t *TrapLists) get(p string) string {
	if t == nil {
		return ""
	}
	m := map[string]ValueList{"snmp_versions": t.SNMPVersions, "pdus": t.PDUs, "trap_oid": t.TrapOID,
		"exclude_trap_oid": t.ExcludeTrapOID, "enterprise": t.Enterprise, "exclude_enterprise": t.ExcludeEnterprise,
		"generic": t.Generic, "specific": t.Specific, "exclude_specific": t.ExcludeSpecific, "cred": t.Cred,
		"exclude_cred": t.ExcludeCred, "status": t.Status}
	return strings.Join(m[p], ",")
}

// TrapListsOf is a trap filter's JSON lists (nil for none).
func TrapListsOf(f *datatype.TrapFilter) *TrapLists {
	if f == nil {
		return nil
	}
	gen := f.Generic
	sets := func(s []string) []string {
		if f.Nothing && len(s) == 0 {
			return nil
		}
		return s
	}
	t := &TrapLists{SNMPVersions: sets(f.Versions), PDUs: sets(f.PDUs), TrapOID: f.TrapOID, ExcludeTrapOID: f.ExcludeTrapOID,
		Enterprise: f.Enterprise, ExcludeEnterprise: f.ExcludeEnterprise, Generic: sets(gen), Specific: f.Specific,
		ExcludeSpecific: f.ExcludeSpecific, Cred: f.Cred, ExcludeCred: f.ExcludeCred, Status: sets(f.Status)}
	if f.Nothing && len(t.Status) == 0 && len(t.SNMPVersions) == 0 && len(t.PDUs) == 0 && len(t.Generic) == 0 {
		t.Status = []string{"none"}
	}
	return t
}

// Filter parses the lists like the query parameters.
func (t *TrapLists) Filter() (*datatype.TrapFilter, error) {
	if t == nil {
		return nil, nil
	}
	f, err := datatype.ParseTrapFilter(t.get)
	if err != nil || f.Empty() {
		return nil, err
	}
	return f, nil
}

// PollLists is a poll filter as JSON lists (saved searches, export bodies
// and their echo): the parameters of docs/api.md "Poll lines in search".
type PollLists struct {
	Kinds      ValueList `json:"kinds,omitempty"`
	Ifs        ValueList `json:"ifs,omitempty"`
	ExcludeIfs ValueList `json:"exclude_ifs,omitempty"`
	Oper       ValueList `json:"oper,omitempty"`
	PollStatus ValueList `json:"poll_status,omitempty"`
	Reboot     ValueList `json:"reboot,omitempty"`
}

// get is the lists as query parameters, for datatype.ParsePollFilter.
func (p *PollLists) get(name string) string {
	if p == nil {
		return ""
	}
	m := map[string]ValueList{"kinds": p.Kinds, "ifs": p.Ifs, "exclude_ifs": p.ExcludeIfs, "oper": p.Oper,
		"poll_status": p.PollStatus, "reboot": p.Reboot}
	return strings.Join(m[name], ",")
}

// PollListsOf is a poll filter's JSON lists (nil for none).
func PollListsOf(f *datatype.PollFilter) *PollLists {
	if f == nil {
		return nil
	}
	p := &PollLists{Kinds: f.Kinds, Ifs: f.Ifs, ExcludeIfs: f.ExcludeIfs, Oper: f.Oper, PollStatus: f.Status, Reboot: f.Reboot}
	if f.Nothing && len(p.Kinds) == 0 && len(p.Oper) == 0 && len(p.PollStatus) == 0 && len(p.Reboot) == 0 {
		p.Kinds = []string{"none"}
	}
	return p
}

// Filter parses the lists like the query parameters.
func (p *PollLists) Filter() (*datatype.PollFilter, error) {
	if p == nil {
		return nil, nil
	}
	f, err := datatype.ParsePollFilter(p.get)
	if err != nil || f.Empty() {
		return nil, err
	}
	return f, nil
}

// ExportInfo is one export in GET /api/exports.
type ExportInfo struct {
	ID        string        `json:"id"`
	Created   time.Time     `json:"created"`
	Devices   []string      `json:"devices"`
	From      time.Time     `json:"from"`
	To        time.Time     `json:"to"`
	State     string        `json:"state"` // queued, building, ready, failed, expired
	Progress  float64       `json:"progress"`
	Lines     int64         `json:"lines"`
	SizeBytes int64         `json:"size_bytes"`
	Error     string        `json:"error"`
	ReadyAt   *time.Time    `json:"ready_at"`
	ExpiresAt *time.Time    `json:"expires_at"`
	Filters   ExportFilters `json:"filters"`
	// Filename is the download's name ("" for woodshed-<from>-<to>.zip).
	Filename string `json:"-"`
}

func (e *ExportInfo) normalize() {
	e.Devices = nonNil(e.Devices)
	e.Filters.App, e.Filters.Host = nonNil(e.Filters.App), nonNil(e.Filters.Host)
	e.Filters.ExcludeDevices, e.Filters.ExcludeApp = nonNil(e.Filters.ExcludeDevices), nonNil(e.Filters.ExcludeApp)
	e.Filters.ExcludeHost = nonNil(e.Filters.ExcludeHost)
	if e.Filters.Type == "" {
		e.Filters.Type = "syslog"
	}
	if e.Filters.Kind == "" {
		e.Filters.Kind = "export"
	}
	if e.Filters.Types == nil && e.Filters.Kind != "bundle" {
		e.Filters.Types = []string{e.Filters.Type}
	}
	e.Filters.Types = nonNil(e.Filters.Types)
	if e.Filters.At != nil {
		t := e.Filters.At.UTC()
		e.Filters.At = &t
	}
	if e.Filters.Syntax == "" {
		e.Filters.Syntax = "text"
	}
	e.Created, e.From, e.To = e.Created.UTC(), e.From.UTC(), e.To.UTC()
	for _, p := range []**time.Time{&e.ReadyAt, &e.ExpiresAt} {
		if *p != nil {
			t := (*p).UTC()
			*p = &t
		}
	}
}

// ExportDownload is an open, ready export.
type ExportDownload struct {
	File    io.ReadSeekCloser
	ModTime time.Time
}

// RequestError is returned by a Backend method for a request that's wrong in a
// way only the backend can tell (an invalid regular expression, a cursor from
// another search, a group with no devices): a 400 with Msg.
type RequestError struct{ Msg string }

func (e *RequestError) Error() string { return e.Msg }

// ErrNotReady is returned by OpenExport for an export that isn't ready (409).
var ErrNotReady = errors.New("not ready")

// ---- handlers ----

func parseBoolParam(v url.Values, name string) (bool, error) {
	switch s := v.Get(name); s {
	case "", "false", "0":
		return false, nil
	case "true", "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be true or false, not %q", name, s)
	}
}

func parseTimeParam(v url.Values, name string) (time.Time, error) {
	s := v.Get(name)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q must be an RFC 3339 time, not %q", name, s)
	}
	return t.UTC(), nil
}

func splitList(s string) []string {
	var out []string
	for _, d := range strings.Split(s, ",") {
		if d = strings.TrimSpace(d); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// parseSeverityParams reads severities= (which wins) or min_severity=.
func parseSeverityParams(v url.Values) (Severities, error) {
	var ceiling *int
	if s := v.Get("min_severity"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 || n > 7 {
			return Severities{}, fmt.Errorf("min_severity must be an integer from 0 to 7, not %q", s)
		}
		ceiling = &n
	}
	set, err := parseSeverityList(v.Get("severities"))
	if err != nil {
		return Severities{}, err
	}
	if !set.All() || ceiling == nil {
		return set, nil
	}
	for i := 0; i <= *ceiling; i++ {
		set.Values = append(set.Values, i)
	}
	set.Values = append(set.Values, Unknown)
	return set, nil
}

// ParseSearch reads GET /api/search's query string (docs/api.md).
func ParseSearch(v url.Values) (SearchRequest, error) {
	var r SearchRequest
	var err error
	r.Q = v.Get("q")
	if r.Regex, err = parseBoolParam(v, "regex"); err != nil {
		return r, err
	}
	if r.Case, err = parseBoolParam(v, "case"); err != nil {
		return r, err
	}
	if r.Ungrouped, err = parseBoolParam(v, "ungrouped"); err != nil {
		return r, err
	}
	r.Devices, r.Group = splitList(v.Get("devices")), v.Get("group")
	if r.Group != "" && r.Ungrouped {
		return r, errors.New("group and ungrouped=true are alternatives; send one")
	}
	if r.Severities, err = parseSeverityParams(v); err != nil {
		return r, err
	}
	if r.From, err = parseTimeParam(v, "from"); err != nil {
		return r, err
	}
	if r.To, err = parseTimeParam(v, "to"); err != nil {
		return r, err
	}
	if !r.From.IsZero() && !r.To.IsZero() && !r.From.Before(r.To) {
		return r, errors.New(`"from" must be before "to"`)
	}
	switch o := v.Get("order"); o {
	case "", "desc":
	case "asc":
		r.Asc = true
	default:
		return r, fmt.Errorf("order must be desc or asc, not %q", o)
	}
	r.Limit = 500
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return r, fmt.Errorf("limit must be a positive integer, not %q", s)
		}
		r.Limit = min(n, 5000)
	}
	r.Cursor = v.Get("cursor")
	r.App, r.Host, r.Exclude = splitList(v.Get("app")), splitList(v.Get("host")), v.Get("exclude")
	if err := parseFilters11(v, &r); err != nil {
		return r, err
	}
	return r, nil
}

// parseFilters11 reads the 1.1 filter parameters: type, syntax, facilities,
// exclude_devices, exclude_app and exclude_host.
func parseFilters11(v url.Values, r *SearchRequest) error {
	var err error
	if r.Type, err = parseType(v.Get("type")); err != nil {
		return err
	}
	if r.Terms, err = parseSyntax(v.Get("syntax")); err != nil {
		return err
	}
	if r.Terms && r.Regex {
		return errors.New(errTermsRegex)
	}
	if r.Facilities, err = parseFacilityList(v.Get("facilities")); err != nil {
		return err
	}
	r.ExcludeDevices, r.ExcludeApp, r.ExcludeHost = splitList(v.Get("exclude_devices")), splitList(v.Get("exclude_app")), splitList(v.Get("exclude_host"))
	r.Trap, r.Poll, err = parseTypeFilter(r.Type, v.Get)
	return err
}

// requestOrBackendError answers a Backend error: 400 for a RequestError, 404
// for ErrNotFound, 409 for ErrNotReady, 500 otherwise.
func (s *Server) requestOrBackendError(w http.ResponseWriter, r *http.Request, err error, notFound string) {
	var re *RequestError
	switch {
	case errors.As(err, &re):
		writeError(w, http.StatusBadRequest, re.Msg)
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, notFound)
	case errors.Is(err, ErrNotReady):
		writeError(w, http.StatusConflict, "The export isn't ready yet.")
	case errors.Is(err, r.Context().Err()) && r.Context().Err() != nil:
		// The client went away; nobody reads this.
		writeError(w, http.StatusServiceUnavailable, "The request was cancelled.")
	default:
		s.backendError(w, r, err)
	}
}

func (s *Server) getSearch(w http.ResponseWriter, r *http.Request) {
	req, err := ParseSearch(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	page, err := s.backend.Search(r.Context(), req)
	if err != nil {
		s.requestOrBackendError(w, r, err, "Not found.")
		return
	}
	page.Results = nonNil(page.Results)
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) getContext(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	ref := v.Get("ref")
	if ref == "" {
		writeError(w, http.StatusBadRequest, "ref is required.")
		return
	}
	n := map[string]int{"before": 50, "after": 50}
	for _, k := range []string{"before", "after"} {
		if str := v.Get(k); str != "" {
			x, err := strconv.Atoi(str)
			if err != nil || x < 0 {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("%s must be an integer from 0 to 500, not %q", k, str))
				return
			}
			n[k] = min(x, 500)
		}
	}
	page, err := s.backend.Context(r.Context(), ref, n["before"], n["after"])
	if err != nil {
		s.requestOrBackendError(w, r, err, "That line's file is gone (deleted by retention).")
		return
	}
	page.Lines = nonNil(page.Lines)
	writeJSON(w, http.StatusOK, page)
}

// exportBody is the JSON body of POST /api/exports.
type exportBody struct {
	AllDevices bool       `json:"all_devices"`
	Devices    []string   `json:"devices"`
	Group      string     `json:"group"`
	Ungrouped  bool       `json:"ungrouped"`
	From       string     `json:"from"`
	To         string     `json:"to"`
	Severities Severities `json:"severities"`
	Q          string     `json:"q"`
	Regex      bool       `json:"regex"`
	Case       bool       `json:"case"`
	App        []string   `json:"app"`
	Host       []string   `json:"host"`
	Exclude    string     `json:"exclude"`
	// 1.1.
	Type           string     `json:"type"`
	Syntax         string     `json:"syntax"`
	Facilities     Facilities `json:"facilities"`
	ExcludeDevices []string   `json:"exclude_devices"`
	ExcludeApp     []string   `json:"exclude_app"`
	ExcludeHost    []string   `json:"exclude_host"`
	// 1.2 (docs/api.md "Exports and the incident bundle"): the data types,
	// the kind, and the trap filters as lists; 1.3 the poll filters.
	Types []string `json:"types"`
	Kind  string   `json:"kind"`
	TrapLists
	PollLists
	// The incident bundle (kind "bundle").
	At            string `json:"at"`
	Before        string `json:"before"`
	After         string `json:"after"`
	ActiveDevices bool   `json:"active_devices"`
}

func (s *Server) readExportRequest(w http.ResponseWriter, r *http.Request) (ExportRequest, bool) {
	var b exportBody
	if !decodeJSON(w, r, &b) {
		return ExportRequest{}, false
	}
	req := ExportRequest{AllDevices: b.AllDevices, Group: b.Group, Ungrouped: b.Ungrouped, Severities: b.Severities, Q: b.Q, Regex: b.Regex, Case: b.Case,
		Exclude: b.Exclude, Facilities: b.Facilities}
	for _, l := range []struct {
		in  []string
		out *[]string
	}{{b.Devices, &req.Devices}, {b.App, &req.App}, {b.Host, &req.Host}, {b.ExcludeDevices, &req.ExcludeDevices},
		{b.ExcludeApp, &req.ExcludeApp}, {b.ExcludeHost, &req.ExcludeHost}} {
		for _, d := range l.in {
			if d = strings.TrimSpace(d); d != "" {
				*l.out = append(*l.out, d)
			}
		}
	}
	bad := func(msg string) (ExportRequest, bool) {
		writeError(w, http.StatusBadRequest, msg)
		return ExportRequest{}, false
	}
	var err error
	if req.Type, err = parseType(b.Type); err != nil {
		return bad(err.Error())
	}
	switch b.Kind {
	case "", "export":
		if b.At != "" || b.Before != "" || b.After != "" || b.ActiveDevices {
			return bad(`at, before, after and active_devices are for kind "bundle".`)
		}
	case "bundle":
		if msg := readBundle(&b, &req); msg != "" {
			return bad(msg)
		}
		return req, true
	default:
		return bad(fmt.Sprintf("kind must be \"export\" or \"bundle\", not %q.", b.Kind))
	}
	if req.Types, err = parseTypes(b.Types, b.Type); err != nil {
		return bad(err.Error())
	}
	if len(req.Types) == 1 {
		req.Type = req.Types[0]
	}
	syslogFilters := len(b.Severities.Values) > 0 || b.Severities.None || len(b.Facilities.Values) > 0 || b.Facilities.None ||
		len(req.App) > 0 || len(req.Host) > 0 || len(req.ExcludeApp) > 0 || len(req.ExcludeHost) > 0
	lists := typeListsGet(&b.TrapLists, &b.PollLists)
	typeFilters := false
	for _, t := range []string{datatype.Trap, datatype.Poll} {
		for _, p := range datatype.Get(t).FilterParams() {
			typeFilters = typeFilters || lists(p) != ""
		}
	}
	if len(req.Types) > 1 && (syslogFilters || typeFilters || req.Q != "" || req.Exclude != "") {
		return bad("types: Filters apply to one data type; pick one, or leave the filters out.")
	}
	if len(req.Types) == 1 {
		get := func(p string) string {
			switch p {
			case "severities", "facilities":
				if syslogFilters && (p == "severities" && (len(b.Severities.Values) > 0 || b.Severities.None) ||
					p == "facilities" && (len(b.Facilities.Values) > 0 || b.Facilities.None)) {
					return "set"
				}
				return ""
			case "app":
				return strings.Join(req.App, ",")
			case "host":
				return strings.Join(req.Host, ",")
			case "exclude_app":
				return strings.Join(req.ExcludeApp, ",")
			case "exclude_host":
				return strings.Join(req.ExcludeHost, ",")
			}
			return lists(p)
		}
		if req.Trap, req.Poll, err = parseTypeFilter(req.Type, get); err != nil {
			return bad(err.Error())
		}
	}
	if req.Terms, err = parseSyntax(b.Syntax); err != nil {
		return bad(err.Error() + ".")
	}
	if req.Terms && req.Regex {
		return bad(errTermsRegex)
	}
	for _, f := range []struct {
		name, v string
		t       *time.Time
	}{{"from", b.From, &req.From}, {"to", b.To, &req.To}} {
		if f.v == "" {
			return bad(fmt.Sprintf("%q is required.", f.name))
		}
		if *f.t, err = time.Parse(time.RFC3339Nano, f.v); err != nil {
			return bad(fmt.Sprintf("%q must be an RFC 3339 time, not %q.", f.name, f.v))
		}
	}
	if !req.From.Before(req.To) {
		return bad(`"from" must be before "to".`)
	}
	if req.Group != "" && req.Ungrouped {
		return bad("group and ungrouped=true are alternatives; send one.")
	}
	if req.AllDevices && (len(req.Devices) > 0 || req.Group != "" || req.Ungrouped) {
		return bad("all_devices picks every device; don't send devices, group or ungrouped with it.")
	}
	if !req.AllDevices && len(req.Devices) == 0 && req.Group == "" && !req.Ungrouped {
		return bad("Pick at least one device (devices, group, ungrouped or all_devices).")
	}
	return req, true
}

// readBundle reads a bundle body (kind "bundle", docs/api.md "Exports") into
// req, or returns the 400's message. A bundle takes no filters, each named
// when sent, and no from or to: its window is at, before and after.
func readBundle(b *exportBody, req *ExportRequest) string {
	req.Kind = "bundle"
	lists := typeListsGet(&b.TrapLists, &b.PollLists)
	for _, x := range []struct {
		name string
		set  bool
	}{
		{"from", b.From != ""}, {"to", b.To != ""},
		{"all_devices", b.AllDevices}, {"exclude_devices", len(req.ExcludeDevices) > 0},
		{"q", b.Q != ""}, {"exclude", b.Exclude != ""}, {"regex", b.Regex}, {"case", b.Case},
		{"syntax", b.Syntax != "" && b.Syntax != "text"},
		{"severities", len(b.Severities.Values) > 0 || b.Severities.None}, {"facilities", len(b.Facilities.Values) > 0 || b.Facilities.None},
		{"app", len(req.App) > 0}, {"host", len(req.Host) > 0}, {"exclude_app", len(req.ExcludeApp) > 0},
		{"exclude_host", len(req.ExcludeHost) > 0},
	} {
		if !x.set {
			continue
		}
		switch x.name {
		case "from", "to":
			return x.name + `: a bundle's window is at, before and after; leave "from" and "to" out.`
		case "all_devices", "exclude_devices":
			return x.name + ": a bundle takes active_devices (every device that stored anything in the window), devices, group or ungrouped."
		}
		return x.name + ": a bundle takes no filters: it's everything around the moment. Filter with a plain export instead."
	}
	for _, t := range []string{datatype.Trap, datatype.Poll} {
		for _, p := range datatype.Get(t).FilterParams() {
			if lists(p) != "" {
				return p + ": a bundle takes no filters: it's everything around the moment. Filter with a plain export instead."
			}
		}
	}
	if b.At == "" {
		return "at is required: the moment the bundle is around (RFC 3339)."
	}
	at, err := time.Parse(time.RFC3339Nano, b.At)
	if err != nil {
		return fmt.Sprintf("at must be an RFC 3339 time, not %q.", b.At)
	}
	req.At = at.UTC()
	req.Before, req.After = 30*time.Minute, 10*time.Minute // the CLI's defaults
	for _, x := range []struct {
		name, v string
		d       *time.Duration
	}{{"before", b.Before, &req.Before}, {"after", b.After, &req.After}} {
		if x.v == "" {
			continue
		}
		if *x.d, err = model.ParseSpan(x.v); err != nil {
			return x.name + ": " + err.Error() + "."
		}
	}
	req.ActiveDevices = b.ActiveDevices
	if len(b.Types) > 0 || b.Type != "" {
		if req.Types, err = parseTypes(b.Types, b.Type); err != nil {
			return err.Error()
		}
	}
	req.Type = ""
	return ""
}

// parseTypes reads an export's types (and 1.1's type): none means the 1.1
// zip, syslog only.
func parseTypes(types []string, typ string) ([]string, error) {
	if len(types) == 0 {
		if typ == "" {
			typ = datatype.Syslog
		}
		return []string{typ}, nil
	}
	var out []string
	for _, t := range types {
		if datatype.Get(t) == nil || t == "" {
			return nil, fmt.Errorf("types: unknown data type %q.", t)
		}
		if !slicesContains(out, t) {
			out = append(out, t)
		}
	}
	if typ != "" && !(len(out) == 1 && out[0] == typ) {
		return nil, errors.New(`types: "type" and "types" disagree; send one.`)
	}
	return out, nil
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) postExport(w http.ResponseWriter, r *http.Request) {
	req, ok := s.readExportRequest(w, r)
	if !ok {
		return
	}
	info, err := s.backend.CreateExport(r.Context(), req)
	if err != nil {
		s.requestOrBackendError(w, r, err, "Not found.")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"id": info.ID})
}

func (s *Server) postEstimate(w http.ResponseWriter, r *http.Request) {
	req, ok := s.readExportRequest(w, r)
	if !ok {
		return
	}
	est, err := s.backend.EstimateExport(r.Context(), req)
	if err != nil {
		s.requestOrBackendError(w, r, err, "Not found.")
		return
	}
	writeJSON(w, http.StatusOK, est)
}

func (s *Server) listExports(w http.ResponseWriter, r *http.Request) {
	es, err := s.backend.Exports(r.Context())
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	es = nonNil(es)
	for i := range es {
		es[i].normalize()
	}
	writeJSON(w, http.StatusOK, es)
}

var exportIDRE = regexp.MustCompile(`^exp_[0-9a-f]{16}$`)

// exportID reads {id}, answering 404 itself for anything that isn't an export
// ID (routes take IDs, never paths).
func exportID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !exportIDRE.MatchString(id) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("No export with id %q.", id))
		return "", false
	}
	return id, true
}

func (s *Server) getExport(w http.ResponseWriter, r *http.Request) {
	id, ok := exportID(w, r)
	if !ok {
		return
	}
	e, err := s.backend.Export(r.Context(), id)
	if err != nil {
		s.requestOrBackendError(w, r, err, fmt.Sprintf("No export with id %q.", id))
		return
	}
	e.normalize()
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) deleteExport(w http.ResponseWriter, r *http.Request) {
	id, ok := exportID(w, r)
	if !ok {
		return
	}
	if err := s.backend.DeleteExport(r.Context(), id); err != nil {
		s.requestOrBackendError(w, r, err, fmt.Sprintf("No export with id %q.", id))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) downloadExport(w http.ResponseWriter, r *http.Request) {
	id, ok := exportID(w, r)
	if !ok {
		return
	}
	info, err := s.backend.Export(r.Context(), id)
	if err != nil {
		s.requestOrBackendError(w, r, err, fmt.Sprintf("No export with id %q.", id))
		return
	}
	if info.State == "expired" {
		writeError(w, http.StatusNotFound, "That export has expired (exports are deleted 24 hours after they're ready).")
		return
	}
	dl, err := s.backend.OpenExport(r.Context(), id)
	if err != nil {
		s.requestOrBackendError(w, r, err, fmt.Sprintf("No export with id %q.", id))
		return
	}
	defer dl.File.Close()
	name := info.Filename
	if name == "" {
		name = fmt.Sprintf("woodshed-%s-%s.zip", info.From.UTC().Format("20060102T150405Z"), info.To.UTC().Format("20060102T150405Z"))
	}
	h := w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="`+name+`"`)
	h.Set("Cache-Control", "no-store")
	http.ServeContent(w, r, name, dl.ModTime, dl.File)
}
