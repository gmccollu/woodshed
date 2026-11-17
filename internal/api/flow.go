package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
)

// The flow type's API (SPEC §13, docs/api.md "Flows"): type=flow on search,
// the summary, saved searches and exports, and the flow routes (state, top-N,
// the timeline strip, an exporter's templates).

// FlowBackend is what the flow routes need from the service.
type FlowBackend interface {
	// FlowState serves GET /api/flows.
	FlowState(ctx context.Context) (FlowState, error)
	// FlowTop serves GET /api/flows/top (a *RequestError for a bad cursor).
	FlowTop(ctx context.Context, r FlowTopRequest) (FlowTopPage, error)
	// FlowTimeline serves GET /api/flows/timeline.
	FlowTimeline(ctx context.Context, q FlowTimelineQuery) (FlowTimeline, error)
	// FlowTemplates serves GET /api/flows/templates (ErrNotFound for a device
	// that never exported flows).
	FlowTemplates(ctx context.Context, deviceID string) (FlowTemplates, error)
}

// errFlowNoText is the 400 for q (and exclude) with type=flow.
const errFlowNoText = "q: flows have no text; use src, dst, ip, port or proto."

// FlowParams are a request's flow filter parameters, by name, as given
// (validated); absent ones aren't in the map.
type FlowParams map[string]string

// Get returns a parameter's value ("" when absent).
func (p FlowParams) Get(name string) string { return p[name] }

// Filter compiles the parameters.
func (p FlowParams) Filter() (*flowquery.Filter, error) { return flowquery.Parse(p.Get) }

// parseFlowParams reads and checks the flow filter parameters through get.
func parseFlowParams(get func(string) string) (FlowParams, error) {
	p := FlowParams{}
	for _, name := range datatype.FlowFilterParams {
		if v := strings.TrimSpace(get(name)); v != "" {
			p[name] = v
		}
	}
	if _, err := p.Filter(); err != nil {
		return nil, err
	}
	if len(p) == 0 {
		return nil, nil
	}
	return p, nil
}

// FlowLists is a flow filter as JSON lists (saved searches and export
// bodies). The status list is the trap lists' "status" key, which flows
// share (TrapLists.Status).
type FlowLists struct {
	Src               ValueList `json:"src,omitempty"`
	Dst               ValueList `json:"dst,omitempty"`
	IP                ValueList `json:"ip,omitempty"`
	ExcludeSrc        ValueList `json:"exclude_src,omitempty"`
	ExcludeDst        ValueList `json:"exclude_dst,omitempty"`
	ExcludeIP         ValueList `json:"exclude_ip,omitempty"`
	IPAny             ValueList `json:"ip_any,omitempty"`
	SrcPort           ValueList `json:"src_port,omitempty"`
	DstPort           ValueList `json:"dst_port,omitempty"`
	Port              ValueList `json:"port,omitempty"`
	ExcludeSrcPort    ValueList `json:"exclude_src_port,omitempty"`
	ExcludeDstPort    ValueList `json:"exclude_dst_port,omitempty"`
	ExcludePort       ValueList `json:"exclude_port,omitempty"`
	Proto             ValueList `json:"proto,omitempty"`
	ExcludeProto      ValueList `json:"exclude_proto,omitempty"`
	InIf              ValueList `json:"in_if,omitempty"`
	OutIf             ValueList `json:"out_if,omitempty"`
	ExcludeInIf       ValueList `json:"exclude_in_if,omitempty"`
	ExcludeOutIf      ValueList `json:"exclude_out_if,omitempty"`
	Domain            ValueList `json:"domain,omitempty"`
	TCPFlags          ValueList `json:"tcp_flags,omitempty"`
	Sampled           ValueList `json:"sampled,omitempty"`
	FwEvent           ValueList `json:"fw_event,omitempty"`
	NatEvent          ValueList `json:"nat_event,omitempty"`
	PostNATSrc        ValueList `json:"post_nat_src,omitempty"`
	PostNATDst        ValueList `json:"post_nat_dst,omitempty"`
	PostNATIP         ValueList `json:"post_nat_ip,omitempty"`
	ExcludePostNATSrc ValueList `json:"exclude_post_nat_src,omitempty"`
	ExcludePostNATDst ValueList `json:"exclude_post_nat_dst,omitempty"`
	ExcludePostNATIP  ValueList `json:"exclude_post_nat_ip,omitempty"`
	PostNATSrcPort    ValueList `json:"post_nat_src_port,omitempty"`
	PostNATDstPort    ValueList `json:"post_nat_dst_port,omitempty"`
	RuleID            ValueList `json:"rule_id,omitempty"`
	ExcludeRuleID     ValueList `json:"exclude_rule_id,omitempty"`
}

func (f *FlowLists) fields() map[string]*ValueList {
	return map[string]*ValueList{
		"src": &f.Src, "dst": &f.Dst, "ip": &f.IP, "exclude_src": &f.ExcludeSrc, "exclude_dst": &f.ExcludeDst,
		"exclude_ip": &f.ExcludeIP, "ip_any": &f.IPAny, "src_port": &f.SrcPort, "dst_port": &f.DstPort, "port": &f.Port,
		"exclude_src_port": &f.ExcludeSrcPort, "exclude_dst_port": &f.ExcludeDstPort, "exclude_port": &f.ExcludePort,
		"proto": &f.Proto, "exclude_proto": &f.ExcludeProto, "in_if": &f.InIf, "out_if": &f.OutIf,
		"exclude_in_if": &f.ExcludeInIf, "exclude_out_if": &f.ExcludeOutIf, "domain": &f.Domain, "tcp_flags": &f.TCPFlags,
		"sampled": &f.Sampled, "fw_event": &f.FwEvent, "nat_event": &f.NatEvent, "post_nat_src": &f.PostNATSrc,
		"post_nat_dst": &f.PostNATDst, "post_nat_ip": &f.PostNATIP, "exclude_post_nat_src": &f.ExcludePostNATSrc,
		"exclude_post_nat_dst": &f.ExcludePostNATDst, "exclude_post_nat_ip": &f.ExcludePostNATIP,
		"post_nat_src_port": &f.PostNATSrcPort, "post_nat_dst_port": &f.PostNATDstPort, "rule_id": &f.RuleID,
		"exclude_rule_id": &f.ExcludeRuleID,
	}
}

// get is the lists as query parameters ("status" isn't here: TrapLists has it).
func (f *FlowLists) get(name string) string {
	if f == nil {
		return ""
	}
	if l, ok := f.fields()[name]; ok {
		return strings.Join(*l, ",")
	}
	return ""
}

// FlowListsOf is flow parameters as JSON lists, and the status list.
func FlowListsOf(p FlowParams) (*FlowLists, ValueList) {
	if len(p) == 0 {
		return nil, nil
	}
	f := &FlowLists{}
	m := f.fields()
	for name, v := range p {
		if l, ok := m[name]; ok {
			*l = splitList(v)
		}
	}
	return f, splitList(p["status"])
}

// FlowResult is a flow search result's fields (docs/api.md "Flow search").
type FlowResult struct{ r *flow.Record }

// MarshalJSON writes every column, null for one the record lacks.
func (f FlowResult) MarshalJSON() ([]byte, error) { return appendFlowResultJSON(nil, f.r), nil }

// flowLineJSON is a flow SearchLine's shape.
func flowLineJSON(l SearchLine) ([]byte, error) { return AppendFlowLineJSON(nil, &l), nil }

// FlowProgress is a flow answer's progress (SPEC §13.3): blocks and records
// read of those the window can touch, and the flow time from which every
// block has been read.
type FlowProgress struct {
	BlocksDone   int64     `json:"blocks_done"`
	BlocksTotal  int64     `json:"blocks_total"`
	RecordsDone  int64     `json:"records_done"`
	RecordsTotal int64     `json:"records_total"`
	CompleteFrom time.Time `json:"complete_from"`
}

// ---- GET /api/flows ----

// FlowState is GET /api/flows.
type FlowState struct {
	Enabled   bool           `json:"enabled"`
	Budget    FlowBudget     `json:"budget"`
	Exporters []FlowExporter `json:"exporters"`
}

// FlowBudget is the flow budget and what it holds.
type FlowBudget struct {
	Bytes         int64    `json:"bytes"`
	UsedBytes     int64    `json:"used_bytes"`
	EstimatedDays *float64 `json:"estimated_days"` // null until there's a rate
}

// FlowExporter is one exporter's state.
type FlowExporter struct {
	DeviceID      string       `json:"device_id"`
	Domains       []FlowDomain `json:"domains"`
	RecordsPerSec float64      `json:"records_per_sec"`
	PendingBytes  int64        `json:"pending_bytes"`
	Counts24h     FlowCounts   `json:"counts_24h"`
	ClockSkewMS   int64        `json:"clock_skew_ms"`
	TimeSource    string       `json:"time_source"`
	// TimeOffsets24h and TimeOffsets1h: records whose flow time was far from
	// when they arrived (SPEC §13.10 decision 70), kept as sent.
	TimeOffsets24h FlowTimeOffsets `json:"time_offsets_24h"`
	TimeOffsets1h  FlowTimeOffsets `json:"time_offsets_1h"`
	LastSeen       *time.Time      `json:"last_seen,omitempty"`
	Versions       []int           `json:"versions,omitempty"`
}

// FlowTimeOffsets counts an exporter's records whose end was more than 1 h
// after they arrived (ahead) or more than 24 h before (behind), with the
// largest offset each way in ms (0 when none).
type FlowTimeOffsets struct {
	Ahead       int64 `json:"ahead"`
	Behind      int64 `json:"behind"`
	MaxAheadMS  int64 `json:"max_ahead_ms"`
	MaxBehindMS int64 `json:"max_behind_ms"`
}

// FlowDomain is one observation domain (or source ID) of an exporter.
type FlowDomain struct {
	ID           uint32     `json:"id"`
	Sampling     uint32     `json:"sampling"`
	Templates    int        `json:"templates"`
	LastTemplate *time.Time `json:"last_template"`
	// SeqMode (IPFIX, since 2.0) is how the domain numbers its messages,
	// learned from its stream: "rfc" (RFC 7011 §3.1: the data records sent
	// before the message) or "after" (counting the message's own records
	// too); absent while it isn't decided.
	SeqMode string `json:"seq_mode,omitempty"`
}

// FlowCounts are an exporter's last-24-hour counts.
type FlowCounts struct {
	Records      int64 `json:"records"`
	Late         int64 `json:"late"`
	NoTemplate   int64 `json:"no_template"`
	Malformed    int64 `json:"malformed"`
	SequenceGaps int64 `json:"sequence_gaps"`
	Duplicates   int64 `json:"duplicates"`
}

// ---- GET /api/flows/templates ----

// FlowTemplates is an exporter's cached templates, per domain.
type FlowTemplates struct {
	DeviceID string               `json:"device_id"`
	Domains  []FlowTemplateDomain `json:"domains"`
}

// FlowTemplateDomain is one domain's templates.
type FlowTemplateDomain struct {
	ID        uint32         `json:"id"`
	Templates []FlowTemplate `json:"templates"`
}

// FlowTemplate is one template definition.
type FlowTemplate struct {
	ID       uint16              `json:"id"`
	Options  bool                `json:"options"`
	Received time.Time           `json:"received"`
	Fields   []FlowTemplateField `json:"fields"`
}

// FlowTemplateField is one field of a template.
type FlowTemplateField struct {
	PEN    uint32 `json:"pen"`
	ID     uint16 `json:"id"`
	Name   string `json:"name"`
	Length uint16 `json:"length"`
}

// ---- GET /api/flows/top ----

// FlowTopRequest is GET /api/flows/top, parsed.
type FlowTopRequest struct {
	SearchRequest // the devices, the range and the flow filter (Flow)
	By, Metric    string
	Top           int
	BudgetMS      int
}

// FlowTopPage is GET /api/flows/top's body.
type FlowTopPage struct {
	By     string       `json:"by"`
	Metric string       `json:"metric"`
	From   time.Time    `json:"from"`
	To     time.Time    `json:"to"`
	Total  FlowTopTotal `json:"total"`
	Rows   []FlowTopRow `json:"rows"`
	Other  FlowTopOther `json:"other"`
	// ZeroOmitted counts the keys with none of the metric: they're never
	// rows (a denied-only source has 0 bytes), though Total and Other count
	// their records.
	ZeroOmitted int64 `json:"zero_omitted"`
	Approx      bool  `json:"approx"`
	// ErrorBound: past the exact limit, a key in neither table has at most
	// this much of the metric (0 while exact); any key not in rows has at
	// most the larger of it and the last row's value.
	ErrorBound int64         `json:"error_bound"`
	Progress   *FlowProgress `json:"progress"`
	Partial    bool          `json:"partial"`
	NextCursor string        `json:"next_cursor"`
	ElapsedMS  int64         `json:"elapsed_ms"`
}

// FlowTopTotal is the window's totals.
type FlowTopTotal struct {
	Flows          int64 `json:"flows"`
	Connections    int64 `json:"connections"`
	Bytes          int64 `json:"bytes"`
	Packets        int64 `json:"packets"`
	BytesScaled    int64 `json:"bytes_scaled"`
	PacketsScaled  int64 `json:"packets_scaled"`
	ScaledComplete bool  `json:"scaled_complete"`
}

// FlowTopRow is one row.
type FlowTopRow struct {
	Key              string     `json:"key"`
	Label            string     `json:"label"`
	Flows            int64      `json:"flows"`
	Connections      int64      `json:"connections"`
	Bytes            int64      `json:"bytes"`
	Packets          int64      `json:"packets"`
	BytesScaled      int64      `json:"bytes_scaled"`
	PacketsScaled    int64      `json:"packets_scaled"`
	ScaledLowerBound bool       `json:"scaled_lower_bound"`
	Share            float64    `json:"share"`
	First            *time.Time `json:"first"`
	Last             *time.Time `json:"last"`
	// Approx: the row was counted in the fixed-size approximate table. The
	// ranked metric is an upper bound, at most MaxError over; the other
	// counts cover the records since the key entered the table.
	Approx   bool  `json:"approx"`
	MaxError int64 `json:"max_error"`
}

// FlowTopOther is what the rows leave out.
type FlowTopOther struct {
	Flows int64 `json:"flows"`
	Bytes int64 `json:"bytes"`
}

// ---- GET /api/flows/timeline ----

// FlowTimelineQuery is the strip's selection.
type FlowTimelineQuery struct {
	Devices   []string
	Group     string
	Ungrouped bool
	From, To  time.Time
	Bucket    time.Duration
	Metric    string
}

// FlowTimeline is the strip: per exporting device (at most 4), and how many
// more were left out.
type FlowTimeline struct {
	Devices []FlowTimelineDevice `json:"devices"`
	More    int                  `json:"more"`
}

// FlowTimelineDevice is one device's points.
type FlowTimelineDevice struct {
	DeviceID string              `json:"device_id"`
	Points   []FlowTimelinePoint `json:"points"`
}

// FlowTimelinePoint is one bucket.
type FlowTimelinePoint struct {
	Start       time.Time `json:"start"`
	Bytes       int64     `json:"bytes"`
	BytesScaled int64     `json:"bytes_scaled"`
	Flows       int64     `json:"flows"`
	Packets     int64     `json:"packets"`
}

// checkFlowRequest reads what a flow request takes beyond search's: q and
// exclude are refused, the flow filter read.
func checkFlowRequest(r *SearchRequest, get func(string) string) error {
	if r.Type != datatype.Flow {
		return nil
	}
	if strings.TrimSpace(r.Q) != "" {
		return errors.New(errFlowNoText)
	}
	if strings.TrimSpace(r.Exclude) != "" {
		return errors.New("exclude: flows have no text; use the exclude_ filters (exclude_src, exclude_port, …).")
	}
	if r.Terms || r.Regex || r.Case {
		return errors.New("syntax, regex and case: flows have no text to match.")
	}
	var err error
	r.Flow, err = parseFlowParams(get)
	return err
}

// ParseFlowTop reads GET /api/flows/top's query string.
func ParseFlowTop(v url.Values) (FlowTopRequest, error) {
	if t := v.Get("type"); t != "" && t != datatype.Flow {
		return FlowTopRequest{}, fmt.Errorf("type: top-N is for flows; leave type out or send type=flow.")
	}
	if v.Get("q") != "" {
		return FlowTopRequest{}, errors.New(errFlowNoText)
	}
	v2 := url.Values{}
	for k, vs := range v {
		switch k {
		case "by", "metric", "top", "budget_ms", "limit", "order":
			continue
		}
		v2[k] = vs
	}
	v2.Set("type", datatype.Flow)
	sr, err := ParseSearch(v2)
	if err != nil {
		return FlowTopRequest{}, err
	}
	r := FlowTopRequest{SearchRequest: sr, By: "src", Top: 10, BudgetMS: 2000}
	r.Limit, r.Asc = 0, false
	if b := v.Get("by"); b != "" {
		if !slices.Contains(flowquery.ByKeys, b) {
			return r, fmt.Errorf("by must be one of %s, not %q.", strings.Join(flowquery.ByKeys, ", "), b)
		}
		r.By = b
	}
	r.Metric = "bytes"
	if f := r.Flow.Get("fw_event"); f != "" {
		// Denied events carry no bytes: count them.
		if denied, _ := flow.ParseFwEvent("denied"); slices.ContainsFunc(splitList(f), func(s string) bool {
			v, ok := flow.ParseFwEvent(s)
			return ok && v == denied
		}) {
			r.Metric = "flows"
		}
	}
	if m := v.Get("metric"); m != "" {
		if !slices.Contains(flowquery.Metrics, m) {
			return r, fmt.Errorf("metric must be one of %s, not %q.", strings.Join(flowquery.Metrics, ", "), m)
		}
		r.Metric = m
	}
	if s := v.Get("top"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return r, fmt.Errorf("top must be an integer from 1 to 100, not %q.", s)
		}
		r.Top = min(n, 100)
	}
	if s := v.Get("budget_ms"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			return r, fmt.Errorf("budget_ms must be an integer from 1 to 10000, not %q.", s)
		}
		r.BudgetMS = min(n, 10000)
	}
	return r, nil
}

func (s *Server) flowRoutes(mux *http.ServeMux) {
	b := s.backend
	mux.Handle("/api/flows", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		st, err := b.FlowState(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		st.Exporters = nonNil(st.Exporters)
		for i := range st.Exporters {
			st.Exporters[i].Domains = nonNil(st.Exporters[i].Domains)
		}
		writeJSON(w, http.StatusOK, st)
	}})
	mux.Handle("/api/flows/top", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		req, err := ParseFlowTop(r.URL.Query())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		page, err := b.FlowTop(r.Context(), req)
		if err != nil {
			s.requestOrBackendError(w, r, err, "Not found.")
			return
		}
		page.Rows = nonNil(page.Rows)
		page.From, page.To = page.From.UTC(), page.To.UTC()
		writeJSON(w, http.StatusOK, page)
	}})
	mux.Handle("/api/flows/timeline", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		q, err := parseFlowTimeline(r.URL.Query())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		tl, err := b.FlowTimeline(r.Context(), q)
		if err != nil {
			s.requestOrBackendError(w, r, err, "Not found.")
			return
		}
		tl.Devices = nonNil(tl.Devices)
		for i := range tl.Devices {
			tl.Devices[i].Points = nonNil(tl.Devices[i].Points)
		}
		writeJSON(w, http.StatusOK, tl)
	}})
	mux.Handle("/api/flows/templates", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.URL.Query().Get("device"))
		if id == "" {
			writeError(w, http.StatusBadRequest, "device is required.")
			return
		}
		t, err := b.FlowTemplates(r.Context(), id)
		if err != nil {
			s.requestOrBackendError(w, r, err, fmt.Sprintf("No flow exporter %q.", id))
			return
		}
		t.Domains = nonNil(t.Domains)
		for i := range t.Domains {
			t.Domains[i].Templates = nonNil(t.Domains[i].Templates)
			for j := range t.Domains[i].Templates {
				t.Domains[i].Templates[j].Fields = nonNil(t.Domains[i].Templates[j].Fields)
			}
		}
		writeJSON(w, http.StatusOK, t)
	}})
}

// flowBuckets are the strip's bucket sizes (the histogram's, from a minute).
var flowBuckets = []int{60, 300, 900, 3600, 7200, 21600, 86400, 604800}

func parseFlowTimeline(v url.Values) (FlowTimelineQuery, error) {
	var q FlowTimelineQuery
	var err error
	q.Devices, q.Group = splitList(v.Get("devices")), v.Get("group")
	if q.Ungrouped, err = parseBoolParam(v, "ungrouped"); err != nil {
		return q, err
	}
	if q.From, err = parseTimeParam(v, "from"); err != nil {
		return q, err
	}
	if q.To, err = parseTimeParam(v, "to"); err != nil {
		return q, err
	}
	if q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) {
		return q, errors.New(`"from" and "to" are required, "from" before "to"`)
	}
	n := 0
	if s := v.Get("bucket"); s != "" {
		if n, err = strconv.Atoi(s); err != nil || !slices.Contains(flowBuckets, n) {
			return q, fmt.Errorf("bucket must be one of 60, 300, 900, 3600, 7200, 21600, 86400 or 604800 seconds, not %q", s)
		}
	} else {
		span := q.To.Sub(q.From)
		n = flowBuckets[len(flowBuckets)-1]
		for _, b := range flowBuckets {
			if span/(time.Duration(b)*time.Second) <= 1000 {
				n = b
				break
			}
		}
	}
	if q.To.Sub(q.From)/(time.Duration(n)*time.Second) > 1000 {
		return q, errors.New("bucket gives more than 1,000 buckets; pick a larger one")
	}
	q.Bucket = time.Duration(n) * time.Second
	q.Metric = "bytes"
	if m := v.Get("metric"); m != "" {
		if m != "bytes" && m != "flows" && m != "packets" {
			return q, fmt.Errorf("metric must be bytes, flows or packets, not %q", m)
		}
		q.Metric = m
	}
	return q, nil
}
