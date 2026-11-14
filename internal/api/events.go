package api

import (
	"github.com/gmccollu/woodshed/internal/datatype"

	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Events v2 (docs/api.md, SPEC §10.1): the 1.1 filter parameters, the field
// schema, summaries (field panel and histogram) and saved searches.

const errTermsRegex = "Terms and regex can't be combined: pick one."

// parseType reads type= ("" is syslog, the 1.1 meaning; SPEC §11.7).
func parseType(t string) (string, error) {
	if t == "" {
		return datatype.Syslog, nil
	}
	if datatype.Get(t) != nil {
		return t, nil
	}
	return "", fmt.Errorf("type: unknown data type %q.", t)
}

// parseTypeFilter refuses another type's filter parameters for typ, and reads
// the trap type's own (nil for syslog, whose filters 1.1's code reads).
func parseTypeFilter(typ string, get func(string) string) (*datatype.TrapFilter, error) {
	dt := datatype.Get(typ)
	if err := datatype.CheckParams(dt, func(p string) bool { return strings.TrimSpace(get(p)) != "" }); err != nil {
		return nil, err
	}
	if typ != datatype.Trap {
		return nil, nil
	}
	tf, err := datatype.ParseTrapFilter(get)
	if err != nil || tf.Empty() {
		return nil, err
	}
	return tf, nil
}

// parseSyntax reads syntax=: false for text (the default), true for terms.
func parseSyntax(s string) (bool, error) {
	switch s {
	case "", "text":
		return false, nil
	case "terms":
		return true, nil
	}
	return false, fmt.Errorf("syntax must be text or terms, not %q", s)
}

// Facilities is a facility filter, like Severities: the zero value means all
// facilities, None nothing, otherwise only Values (0-23, Unknown) pass.
type Facilities struct {
	None   bool
	Values []int
}

// All reports whether the filter lets every facility through.
func (f Facilities) All() bool { return !f.None && len(f.Values) == 0 }

// parseFacilityList reads "0,4,unknown" or "none" ("" is all).
func parseFacilityList(v string) (Facilities, error) {
	var f Facilities
	seen := map[int]bool{}
	none := false
	add := func(n int) {
		if !seen[n] {
			seen[n] = true
			f.Values = append(f.Values, n)
		}
	}
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		switch {
		case item == "":
		case strings.EqualFold(item, "none"):
			none = true
		case strings.EqualFold(item, "unknown"):
			add(Unknown)
		default:
			n, err := strconv.Atoi(item)
			if err != nil || n < 0 || n > 23 || len(item) > 2 {
				return Facilities{}, fmt.Errorf("facilities: %q is not a facility (0 to 23, unknown, or none on its own)", item)
			}
			add(n)
		}
	}
	if none {
		if len(f.Values) > 0 {
			return Facilities{}, errors.New("facilities: none can't be combined with other values")
		}
		return Facilities{None: true}, nil
	}
	return f, nil
}

// UnmarshalJSON reads [0, 4, "unknown"], ["none"] or [] (all).
func (f *Facilities) UnmarshalJSON(b []byte) error {
	*f = Facilities{}
	if string(b) == "null" {
		return nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(b, &items); err != nil {
		return errors.New("facilities must be a list of 0 to 23 and \"unknown\" (or [\"none\"])")
	}
	var parts []string
	for _, it := range items {
		var n int
		var str string
		switch {
		case json.Unmarshal(it, &n) == nil && n >= 0:
			parts = append(parts, strconv.Itoa(n))
		case json.Unmarshal(it, &str) == nil && str != "" && !strings.Contains(str, ","):
			parts = append(parts, str)
		default:
			return fmt.Errorf("facilities: %s is not a facility (0 to 23, \"unknown\" or \"none\")", it)
		}
	}
	v, err := parseFacilityList(strings.Join(parts, ","))
	if err != nil {
		return err
	}
	*f = v
	return nil
}

// MarshalJSON writes [] for all, ["none"], or the list.
func (f Facilities) MarshalJSON() ([]byte, error) {
	out := []any{}
	if f.None {
		out = append(out, "none")
	}
	for _, v := range f.Values {
		if v == Unknown {
			out = append(out, "unknown")
		} else {
			out = append(out, v)
		}
	}
	return json.Marshal(out)
}

// ---- GET /api/search/schema ----

// SearchType is one data type in GET /api/search/schema.
type SearchType struct {
	Type    string        `json:"type"`
	Label   string        `json:"label"`
	Default bool          `json:"default"`
	Fields  []SearchField `json:"fields"`
}

// SearchField is one field of a type's field panel.
type SearchField struct {
	Key          string        `json:"key"`
	Label        string        `json:"label"`
	Param        string        `json:"param"`
	ExcludeParam string        `json:"exclude_param"`
	Domain       []DomainValue `json:"domain"` // null for an open field
}

// DomainValue is one value of a closed field.
type DomainValue struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

func (s *Server) getSchema(w http.ResponseWriter, r *http.Request) {
	types, err := s.backend.SearchSchema(r.Context())
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]SearchType{"types": nonNil(types)})
}

// ---- GET /api/search/summary ----

// SummaryRequest is GET /api/search/summary, parsed. The search's Order,
// Limit and Cursor fields aren't used; Cursor here is the summary's.
type SummaryRequest struct {
	SearchRequest
	Fields    []string // nil: every field; empty and non-nil: none (fields=none)
	Top       int      // 1-50
	Histogram bool
	Bucket    int // seconds; 0: from the range
	BudgetMS  int // 1-10,000
}

// SummaryBucket is one histogram bucket. Count nil means not counted yet.
type SummaryBucket struct {
	Start  time.Time `json:"start"`
	Count  *int64    `json:"count"`
	Approx bool      `json:"approx"`
}

// SummaryHistogram is a summary's histogram.
type SummaryHistogram struct {
	BucketSeconds int64           `json:"bucket_seconds"`
	Source        string          `json:"source"` // "index" | "scan"
	Buckets       []SummaryBucket `json:"buckets"`
}

// SummaryValue is one value of a field.
type SummaryValue struct {
	Value      string `json:"value"`
	Label      string `json:"label"`
	Count      int64  `json:"count"`
	Filterable bool   `json:"filterable"`
}

// SummaryField is one field's counts.
type SummaryField struct {
	Key            string         `json:"key"`
	Label          string         `json:"label"`
	Values         []SummaryValue `json:"values"`
	Other          int64          `json:"other"`
	None           int64          `json:"none"`
	Distinct       int            `json:"distinct"`
	DistinctCapped bool           `json:"distinct_capped"`
}

// SummaryPage is the body of GET /api/search/summary.
type SummaryPage struct {
	Type         string            `json:"type"`
	From         time.Time         `json:"from"`
	To           time.Time         `json:"to"`
	Matched      int64             `json:"matched"`
	CountedFrom  time.Time         `json:"counted_from"`
	Histogram    *SummaryHistogram `json:"histogram,omitempty"`
	Fields       []SummaryField    `json:"fields"`
	NextCursor   string            `json:"next_cursor"`
	Partial      bool              `json:"partial"`
	ScannedBytes int64             `json:"scanned_bytes"`
	ScannedFiles int               `json:"scanned_files"`
	ElapsedMS    int64             `json:"elapsed_ms"`
}

func (p *SummaryPage) normalize() {
	p.Fields = nonNil(p.Fields)
	p.From, p.To, p.CountedFrom = p.From.UTC(), p.To.UTC(), p.CountedFrom.UTC()
	if p.Type == "" {
		p.Type = "syslog"
	}
	if p.Histogram != nil {
		p.Histogram.Buckets = nonNil(p.Histogram.Buckets)
		for i := range p.Histogram.Buckets {
			p.Histogram.Buckets[i].Start = p.Histogram.Buckets[i].Start.UTC()
		}
	}
	for i := range p.Fields {
		p.Fields[i].Values = nonNil(p.Fields[i].Values)
		for j := range p.Fields[i].Values {
			v := &p.Fields[i].Values[j]
			v.Value, v.Label = strings.ToValidUTF8(v.Value, "�"), strings.ToValidUTF8(v.Label, "�")
		}
	}
}

// ParseSummary reads GET /api/search/summary's query string.
func ParseSummary(v url.Values) (SummaryRequest, error) {
	sr, err := ParseSearch(v)
	if err != nil {
		return SummaryRequest{}, err
	}
	r := SummaryRequest{SearchRequest: sr, Top: 10, Histogram: true, BudgetMS: 2000}
	r.Asc, r.Limit = false, 0 // order and limit don't apply
	switch f := strings.TrimSpace(v.Get("fields")); {
	case f == "":
	case strings.EqualFold(f, "none"):
		r.Fields = []string{}
	default:
		r.Fields = splitList(f)
	}
	if s := v.Get("top"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return r, fmt.Errorf("top must be an integer from 1 to 50, not %q", s)
		}
		r.Top = min(n, 50)
	}
	if v.Get("histogram") != "" {
		if r.Histogram, err = parseBoolParam(v, "histogram"); err != nil {
			return r, err
		}
	}
	if s := v.Get("bucket"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return r, fmt.Errorf("bucket must be a number of seconds, not %q", s)
		}
		r.Bucket = n
	}
	if s := v.Get("budget_ms"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return r, fmt.Errorf("budget_ms must be an integer from 1 to 10000, not %q", s)
		}
		r.BudgetMS = min(n, 10000)
	}
	return r, nil
}

func (s *Server) getSummary(w http.ResponseWriter, r *http.Request) {
	req, err := ParseSummary(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	page, err := s.backend.Summary(r.Context(), req)
	if err != nil {
		s.requestOrBackendError(w, r, err, "Not found.")
		return
	}
	page.normalize()
	writeJSON(w, http.StatusOK, page)
}

// ---- saved searches ----

// SavedRange is a saved search's range: Last (a whole number of m, h or d),
// or From and To.
type SavedRange struct {
	Last     string
	From, To time.Time
}

// MarshalJSON writes {"last": "1h"} or {"from": "…", "to": "…"}.
func (r SavedRange) MarshalJSON() ([]byte, error) {
	if r.Last != "" {
		return json.Marshal(map[string]string{"last": r.Last})
	}
	return json.Marshal(map[string]time.Time{"from": r.From.UTC(), "to": r.To.UTC()})
}

// UnmarshalJSON reads the form MarshalJSON writes (stored saved searches; a
// request body is checked by readSaved instead).
func (r *SavedRange) UnmarshalJSON(b []byte) error {
	var v struct {
		Last string  `json:"last"`
		F    *string `json:"from"`
		T    *string `json:"to"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*r = SavedRange{Last: v.Last}
	for _, p := range []struct {
		s *string
		t *time.Time
	}{{v.F, &r.From}, {v.T, &r.To}} {
		if p.s != nil {
			t, err := time.Parse(time.RFC3339Nano, *p.s)
			if err != nil {
				return err
			}
			*p.t = t.UTC()
		}
	}
	return nil
}

// SavedQuery is a saved search's query: every Events parameter.
type SavedQuery struct {
	Q              string     `json:"q"`
	Syntax         string     `json:"syntax"` // "text" | "terms"
	Regex          bool       `json:"regex"`
	Case           bool       `json:"case"`
	Exclude        string     `json:"exclude"`
	Devices        []string   `json:"devices"`
	Group          string     `json:"group"`
	Ungrouped      bool       `json:"ungrouped"`
	ExcludeDevices []string   `json:"exclude_devices"`
	Severities     Severities `json:"severities"`
	Facilities     Facilities `json:"facilities"`
	App            []string   `json:"app"`
	ExcludeApp     []string   `json:"exclude_app"`
	Host           []string   `json:"host"`
	ExcludeHost    []string   `json:"exclude_host"`
	Order          string     `json:"order"` // "desc" | "asc"
	Range          SavedRange `json:"range"`
	// The trap type's filters (1.2), as lists; absent for syslog.
	TrapLists
}

func (q *SavedQuery) normalize() {
	for _, l := range []*[]string{&q.Devices, &q.ExcludeDevices, &q.App, &q.ExcludeApp, &q.Host, &q.ExcludeHost} {
		*l = nonNil(*l)
	}
	if q.Syntax == "" {
		q.Syntax = "text"
	}
	if q.Order == "" {
		q.Order = "desc"
	}
	if q.Range.Last == "" && q.Range.From.IsZero() {
		q.Range.Last = "24h"
	}
}

// Filter returns the query as a syslog SearchRequest (the range left
// unresolved: a Last range is resolved by the caller).
func (q SavedQuery) Filter() SearchRequest { return q.FilterOf(datatype.Syslog) }

// FilterOf is Filter for a saved search of type typ: the trap lists become
// the trap filter (already validated by readSaved).
func (q SavedQuery) FilterOf(typ string) SearchRequest {
	r := q.filter()
	if typ == "" {
		typ = datatype.Syslog
	}
	r.Type = typ
	if typ == datatype.Trap {
		r.Trap, _ = q.TrapLists.Filter()
	}
	return r
}

func (q SavedQuery) filter() SearchRequest {
	return SearchRequest{Type: "syslog", Q: q.Q, Terms: q.Syntax == "terms", Regex: q.Regex, Case: q.Case, Exclude: q.Exclude,
		Devices: q.Devices, Group: q.Group, Ungrouped: q.Ungrouped, ExcludeDevices: q.ExcludeDevices, Severities: q.Severities,
		Facilities: q.Facilities, App: q.App, ExcludeApp: q.ExcludeApp, Host: q.Host, ExcludeHost: q.ExcludeHost,
		Asc: q.Order == "asc", From: q.Range.From, To: q.Range.To}
}

// SavedSearch is one saved search.
type SavedSearch struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Type           string     `json:"type"`
	Created        time.Time  `json:"created"`
	Updated        time.Time  `json:"updated"`
	Query          SavedQuery `json:"query"`
	MissingDevices []string   `json:"missing_devices"`
	MissingGroup   bool       `json:"missing_group"`
	// Version changes on every save; the ETag is made from it.
	Version int64 `json:"-"`
}

func (s *SavedSearch) normalize() {
	s.Created, s.Updated = s.Created.UTC(), s.Updated.UTC()
	s.MissingDevices = nonNil(s.MissingDevices)
	if s.Type == "" {
		s.Type = "syslog"
	}
	s.Query.normalize()
}

// ETag is the saved search's entity tag.
func (s SavedSearch) ETag() string { return fmt.Sprintf(`"%s.%d"`, s.ID, s.Version) }

// SavedSearchInput is a create or update body, checked for shape here; the
// backend validates the query like /api/search (regular expressions, terms)
// and returns a *ValidationError keyed "query.q" / "query.exclude".
type SavedSearchInput struct {
	Name  string
	Type  string
	Query SavedQuery
}

// Saved-search errors from the Backend.
var (
	ErrSavedSearchLimit   = errors.New("There are already 200 saved searches; delete one first.")
	ErrSavedSearchChanged = errors.New("This saved search changed since you loaded it.")
)

// NameTakenError is a saved search name already in use.
type NameTakenError struct{ Name string }

func (e *NameTakenError) Error() string {
	return fmt.Sprintf("A saved search named %q already exists.", e.Name)
}

const (
	maxSavedBody  = 64 << 10
	maxSavedItems = 1000
	maxSavedName  = 80
)

var (
	savedIDRE   = regexp.MustCompile(`^ss_[0-9a-f]{8}$`)
	savedLastRE = regexp.MustCompile(`^([1-9][0-9]{0,6})([mhd])$`)
)

// savedBody is the JSON of a create or update.
type savedBody struct {
	Name  *string         `json:"name"`
	Type  string          `json:"type"`
	Query json.RawMessage `json:"query"`
}

// savedQueryBody is a query as sent: severities, facilities and the range are
// read separately so each gets its own error key.
type savedQueryBody struct {
	Q              string          `json:"q"`
	Syntax         string          `json:"syntax"`
	Regex          bool            `json:"regex"`
	Case           bool            `json:"case"`
	Exclude        string          `json:"exclude"`
	Devices        []string        `json:"devices"`
	Group          string          `json:"group"`
	Ungrouped      bool            `json:"ungrouped"`
	ExcludeDevices []string        `json:"exclude_devices"`
	Severities     json.RawMessage `json:"severities"`
	Facilities     json.RawMessage `json:"facilities"`
	App            []string        `json:"app"`
	ExcludeApp     []string        `json:"exclude_app"`
	Host           []string        `json:"host"`
	ExcludeHost    []string        `json:"exclude_host"`
	Order          string          `json:"order"`
	Range          json.RawMessage `json:"range"`
	TrapLists
}

// readSaved decodes and checks a create or update body. It writes the error
// response itself and returns false on failure.
func readSaved(w http.ResponseWriter, r *http.Request) (SavedSearchInput, bool) {
	var b savedBody
	if !decodeJSONLimit(w, r, &b, maxSavedBody) {
		return SavedSearchInput{}, false
	}
	errs := map[string]string{}
	var in SavedSearchInput
	if b.Name == nil {
		errs["name"] = "A name is required."
	} else {
		in.Name = strings.TrimSpace(*b.Name)
		switch n := utf8.RuneCountInString(in.Name); {
		case !utf8.ValidString(in.Name):
			errs["name"] = "Must be valid UTF-8."
		case n < 1 || n > maxSavedName:
			errs["name"] = fmt.Sprintf("Must be 1 to %d characters.", maxSavedName)
		case strings.ContainsFunc(in.Name, unicode.IsControl):
			errs["name"] = "Must not contain control characters."
		}
	}
	var err error
	if in.Type, err = parseType(b.Type); err != nil {
		errs["type"] = err.Error()
	}
	var qb savedQueryBody
	if len(b.Query) > 0 && string(b.Query) != "null" {
		dec := json.NewDecoder(strings.NewReader(string(b.Query)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&qb); err != nil {
			errs["query"] = "Invalid query: " + err.Error()
		}
	}
	q := &in.Query
	q.Q, q.Regex, q.Case, q.Exclude, q.Group, q.Ungrouped = qb.Q, qb.Regex, qb.Case, qb.Exclude, qb.Group, qb.Ungrouped
	for _, l := range []struct {
		key string
		in  []string
		out *[]string
	}{{"devices", qb.Devices, &q.Devices}, {"exclude_devices", qb.ExcludeDevices, &q.ExcludeDevices}, {"app", qb.App, &q.App},
		{"exclude_app", qb.ExcludeApp, &q.ExcludeApp}, {"host", qb.Host, &q.Host}, {"exclude_host", qb.ExcludeHost, &q.ExcludeHost}} {
		if len(l.in) > maxSavedItems {
			errs["query."+l.key] = fmt.Sprintf("At most %d items.", maxSavedItems)
			continue
		}
		for _, v := range l.in {
			if v = strings.TrimSpace(v); v != "" {
				*l.out = append(*l.out, v)
			}
		}
	}
	terms, err := parseSyntax(qb.Syntax)
	if err != nil {
		errs["query.syntax"] = err.Error() + "."
	}
	q.Syntax = map[bool]string{false: "text", true: "terms"}[terms]
	if terms && q.Regex {
		errs["query.syntax"] = errTermsRegex
	}
	if q.Group != "" && q.Ungrouped {
		errs["query.ungrouped"] = "group and ungrouped=true are alternatives; send one."
	}
	switch qb.Order {
	case "", "desc", "asc":
		q.Order = qb.Order
	default:
		errs["query.order"] = fmt.Sprintf("order must be desc or asc, not %q.", qb.Order)
	}
	if len(qb.Severities) > 0 {
		if err := json.Unmarshal(qb.Severities, &q.Severities); err != nil {
			errs["query.severities"] = err.Error()
		}
	}
	if len(qb.Facilities) > 0 {
		if err := json.Unmarshal(qb.Facilities, &q.Facilities); err != nil {
			errs["query.facilities"] = err.Error()
		}
	}
	if len(qb.Range) > 0 && string(qb.Range) != "null" {
		readRange(qb.Range, &q.Range, errs)
	}
	// Each type takes its own filters (SPEC §11.2.5): another type's are an
	// error on the key, and the trap lists are checked like the parameters.
	if in.Type != "" && errs["type"] == "" {
		syslogSet := map[string]bool{"severities": len(q.Severities.Values) > 0 || q.Severities.None,
			"facilities": len(q.Facilities.Values) > 0 || q.Facilities.None, "app": len(q.App) > 0, "host": len(q.Host) > 0,
			"exclude_app": len(q.ExcludeApp) > 0, "exclude_host": len(q.ExcludeHost) > 0}
		get := func(p string) string {
			if syslogSet[p] {
				return "set"
			}
			return qb.TrapLists.get(p)
		}
		if err := datatype.CheckParams(datatype.Get(in.Type), func(p string) bool { return get(p) != "" }); err != nil {
			var pe *datatype.ParamError
			if errors.As(err, &pe) {
				errs["query."+pe.Param] = err.Error()
			}
		} else if in.Type == datatype.Trap {
			if _, err := qb.TrapLists.Filter(); err != nil {
				var pe *datatype.ParamError
				if errors.As(err, &pe) {
					errs["query."+pe.Param] = err.Error()
				} else {
					errs["query"] = err.Error()
				}
			} else {
				q.TrapLists = qb.TrapLists
			}
		}
	}
	if len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "Some fields need fixing.", Errors: errs})
		return SavedSearchInput{}, false
	}
	q.normalize()
	return in, true
}

func readRange(raw json.RawMessage, out *SavedRange, errs map[string]string) {
	var rb struct {
		Last *string `json:"last"`
		From *string `json:"from"`
		To   *string `json:"to"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rb); err != nil {
		errs["query.range"] = `The range is {"last": "1h"} or {"from": "…", "to": "…"}.`
		return
	}
	switch {
	case rb.Last != nil && (rb.From != nil || rb.To != nil):
		errs["query.range"] = `Send either "last" or "from" and "to", not both.`
	case rb.Last != nil:
		m := savedLastRE.FindStringSubmatch(*rb.Last)
		bad := "A whole number of m, h or d from 1 minute to 400 days, such as 15m, 1h or 7d."
		if m == nil {
			errs["query.range.last"] = bad
			return
		}
		n, _ := strconv.Atoi(m[1])
		unit := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
		if d := time.Duration(n) * unit; d < time.Minute || d > 400*24*time.Hour {
			errs["query.range.last"] = bad
			return
		}
		out.Last = *rb.Last
	default:
		for _, f := range []struct {
			key string
			v   *string
			t   *time.Time
		}{{"from", rb.From, &out.From}, {"to", rb.To, &out.To}} {
			if f.v == nil {
				errs["query.range."+f.key] = "Required (or send \"last\")."
				continue
			}
			t, err := time.Parse(time.RFC3339Nano, *f.v)
			if err != nil {
				errs["query.range."+f.key] = fmt.Sprintf("Must be an RFC 3339 time, not %q.", *f.v)
				continue
			}
			*f.t = t.UTC()
		}
		if !out.From.IsZero() && !out.To.IsZero() && !out.From.Before(out.To) {
			errs["query.range.to"] = `"from" must be before "to".`
		}
	}
}

// LastDuration is a saved range's Last as a duration (0 if it has none).
func (r SavedRange) LastDuration() time.Duration {
	m := savedLastRE.FindStringSubmatch(r.Last)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1])
	return time.Duration(n) * map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour}[m[2]]
}

// savedID reads {id}, answering 404 itself for anything that isn't one.
func savedID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !savedIDRE.MatchString(id) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("No saved search with id %q.", id))
		return "", false
	}
	return id, true
}

func (s *Server) savedError(w http.ResponseWriter, r *http.Request, err error, id string) {
	var ve *ValidationError
	var nt *NameTakenError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "Some fields need fixing.", Errors: nonNilMap(ve.Fields)})
	case errors.As(err, &nt):
		writeError(w, http.StatusConflict, nt.Error())
	case errors.Is(err, ErrSavedSearchLimit), errors.Is(err, ErrSavedSearchChanged):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, fmt.Sprintf("No saved search with id %q.", id))
	default:
		s.requestOrBackendError(w, r, err, "Not found.")
	}
}

func (s *Server) listSaved(w http.ResponseWriter, r *http.Request) {
	typ, err := parseType(r.URL.Query().Get("type"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	list, err := s.backend.SavedSearches(r.Context(), typ)
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	list = nonNil(list)
	for i := range list {
		list[i].normalize()
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) createSaved(w http.ResponseWriter, r *http.Request) {
	in, ok := readSaved(w, r)
	if !ok {
		return
	}
	ss, err := s.backend.CreateSavedSearch(r.Context(), in)
	if err != nil {
		s.savedError(w, r, err, "")
		return
	}
	ss.normalize()
	w.Header().Set("ETag", ss.ETag())
	writeJSON(w, http.StatusCreated, ss)
}

func (s *Server) getSaved(w http.ResponseWriter, r *http.Request) {
	id, ok := savedID(w, r)
	if !ok {
		return
	}
	ss, err := s.backend.SavedSearch(r.Context(), id)
	if err != nil {
		s.savedError(w, r, err, id)
		return
	}
	ss.normalize()
	w.Header().Set("ETag", ss.ETag())
	writeJSON(w, http.StatusOK, ss)
}

func (s *Server) putSaved(w http.ResponseWriter, r *http.Request) {
	id, ok := savedID(w, r)
	if !ok {
		return
	}
	in, ok := readSaved(w, r)
	if !ok {
		return
	}
	// If-Match: the ETag from GET. The backend checks the version in the same
	// transaction as the save.
	var ifVersion int64
	if h := r.Header.Get("If-Match"); h != "" && strings.TrimSpace(h) != "*" {
		cur, err := s.backend.SavedSearch(r.Context(), id)
		if err != nil {
			s.savedError(w, r, err, id)
			return
		}
		if !etagMatches(h, cur.ETag()) {
			writeError(w, http.StatusConflict, ErrSavedSearchChanged.Error())
			return
		}
		ifVersion = cur.Version
	}
	ss, err := s.backend.UpdateSavedSearch(r.Context(), id, in, ifVersion)
	if err != nil {
		s.savedError(w, r, err, id)
		return
	}
	ss.normalize()
	w.Header().Set("ETag", ss.ETag())
	writeJSON(w, http.StatusOK, ss)
}

func (s *Server) deleteSaved(w http.ResponseWriter, r *http.Request) {
	id, ok := savedID(w, r)
	if !ok {
		return
	}
	if err := s.backend.DeleteSavedSearch(r.Context(), id); err != nil {
		s.savedError(w, r, err, id)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}
