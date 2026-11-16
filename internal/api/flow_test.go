package api

import (
	"context"
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// The fake backend's flows: docs/api.md's examples. The flow routes are
// tested against a real server in internal/server.

func (b *fakeBackend) FlowState(context.Context) (FlowState, error) {
	days := 4.8
	at := ts("2026-11-16T09:58:01Z")
	return FlowState{Enabled: true, Budget: FlowBudget{Bytes: 8589934592, UsedBytes: 5100000000, EstimatedDays: &days},
		Exporters: []FlowExporter{{DeviceID: "10.1.0.1", LastSeen: &at, Domains: []FlowDomain{{ID: 1, Sampling: 1000, Templates: 6, LastTemplate: &at}},
			RecordsPerSec: 1180.5, Counts24h: FlowCounts{Records: 101000000, Late: 120, SequenceGaps: 3}, ClockSkewMS: 210,
			TimeSource: "exporter"}}}, nil
}

func (b *fakeBackend) FlowTop(_ context.Context, r FlowTopRequest) (FlowTopPage, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flowTops = append(b.flowTops, r)
	at := ts("2026-11-16T09:00:02Z")
	return FlowTopPage{By: r.By, Metric: r.Metric, From: r.From, To: r.To, Total: FlowTopTotal{Flows: 10, Bytes: 100},
		Rows:     []FlowTopRow{{Key: "10.20.0.5", Label: "10.20.0.5", Flows: 4, Bytes: 31, Share: 0.31, First: &at, Last: &at}},
		Progress: &FlowProgress{BlocksDone: 1, BlocksTotal: 1, RecordsDone: 10, RecordsTotal: 10, CompleteFrom: r.From}}, nil
}

func (b *fakeBackend) FlowTimeline(_ context.Context, q FlowTimelineQuery) (FlowTimeline, error) {
	return FlowTimeline{Devices: []FlowTimelineDevice{{DeviceID: "10.1.0.1", Points: []FlowTimelinePoint{{Start: q.From, Bytes: 5}}}}}, nil
}

func (b *fakeBackend) FlowTemplates(_ context.Context, id string) (FlowTemplates, error) {
	if id != "10.1.0.1" {
		return FlowTemplates{}, ErrNotFound
	}
	return FlowTemplates{DeviceID: id, Domains: []FlowTemplateDomain{{ID: 1, Templates: []FlowTemplate{{ID: 256, Received: ts("2026-11-16T09:58:01Z"),
		Fields: []FlowTemplateField{{PEN: 0, ID: 8, Name: "sourceIPv4Address", Length: 4}}}}}}}, nil
}

func TestParseFlowSearch(t *testing.T) {
	v, _ := url.ParseQuery("type=flow&src=10.20.0.0/16&dst_port=443,8000-8100&proto=tcp&status=ok&fw_event=denied")
	r, err := ParseSearch(v)
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "flow" || r.Flow.Get("src") != "10.20.0.0/16" || r.Flow.Get("status") != "ok" || r.Trap != nil {
		t.Fatalf("%+v", r)
	}
	if f, err := r.Flow.Filter(); err != nil || len(f.DstPort) != 2 {
		t.Fatalf("filter %+v %v", f, err)
	}
	for bad, msg := range map[string]string{
		"type=flow&q=x":            errFlowNoText,
		"type=flow&exclude=x":      "exclude: flows have no text",
		"type=flow&severities=3":   "severities: not a filter for flows.",
		"type=flow&trap_oid=1.3.6": "trap_oid: not a filter for flows.",
		"type=flow&kinds=if":       "kinds: not a filter for flows.",
		"src=10.0.0.1":             "src: not a filter for syslog.",
		"type=trap&dst_port=443":   "dst_port: not a filter for SNMP traps.",
		"type=flow&src=nope":       `src: "nope" isn't an IP address`,
		"type=flow&port=99999":     `port: "99999" isn't a port`,
		"type=flow&status=gone":    `status: "gone" is not one of ok, late, no_template, malformed.`,
	} {
		v, _ := url.ParseQuery(bad)
		if _, err := ParseSearch(v); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v, want %q", bad, err, msg)
		}
	}
	// Traps keep their status filter.
	if _, err := ParseSearch(url.Values{"type": {"trap"}, "status": {"ok"}}); err != nil {
		t.Errorf("trap status: %v", err)
	}
	sv, _ := url.ParseQuery("type=flow&metric=bytes")
	if s, err := ParseSummary(sv); err != nil || s.Metric != "bytes" {
		t.Errorf("summary metric: %+v %v", s.Metric, err)
	}
	if s, _ := ParseSummary(url.Values{"type": {"flow"}}); s.Metric != "flows" {
		t.Errorf("default metric %q", s.Metric)
	}
	if _, err := ParseSummary(url.Values{"metric": {"bytes"}}); err == nil {
		t.Error("metric without type=flow")
	}
}

func TestParseFlowTop(t *testing.T) {
	v, _ := url.ParseQuery("by=dst_port&fw_event=denied&top=500&from=2026-11-16T09:00:00Z&to=2026-11-16T10:00:00Z")
	r, err := ParseFlowTop(v)
	if err != nil {
		t.Fatal(err)
	}
	if r.By != "dst_port" || r.Metric != "flows" || r.Top != 100 || r.Type != "flow" || r.BudgetMS != 2000 {
		t.Fatalf("%+v", r)
	}
	if r, _ := ParseFlowTop(url.Values{}); r.By != "src" || r.Metric != "bytes" || r.Top != 10 {
		t.Fatalf("defaults %+v", r)
	}
	for bad, msg := range map[string]string{"by=host": "by must be one of", "metric=lines": "metric must be one of",
		"top=0": "top must be", "q=x": errFlowNoText, "type=syslog": "top-N is for flows", "budget_ms=x": "budget_ms"} {
		v, _ := url.ParseQuery(bad)
		if _, err := ParseFlowTop(v); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v, want %q", bad, err, msg)
		}
	}
}

func TestFlowRoutes(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "GET", srv.url("/api/flows"), "")
	if r.code != 200 || !strings.Contains(string(r.body), `"estimated_days":4.8`) || !strings.Contains(string(r.body), `"sequence_gaps":3`) {
		t.Fatalf("%d %s", r.code, r.body)
	}
	r = do(t, c, "GET", srv.url("/api/flows/top?by=conversation&metric=packets"), "")
	if r.code != 200 || !strings.Contains(string(r.body), `"by":"conversation"`) || !strings.Contains(string(r.body), `"rows":[{"key":"10.20.0.5"`) {
		t.Fatalf("%d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/flows/top?by=nope"), ""), 400, "by must be one of")
	r = do(t, c, "GET", srv.url("/api/flows/timeline?from=2026-11-16T09:00:00Z&to=2026-11-16T10:00:00Z"), "")
	if r.code != 200 || !strings.Contains(string(r.body), `"more":0`) {
		t.Fatalf("%d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/flows/timeline?from=2026-11-16T09:00:00Z&to=2026-11-16T10:00:00Z&bucket=7"), ""), 400, "bucket must be")
	wantError(t, do(t, c, "GET", srv.url("/api/flows/timeline"), ""), 400, "required")
	r = do(t, c, "GET", srv.url("/api/flows/templates?device=10.1.0.1"), "")
	if r.code != 200 || !strings.Contains(string(r.body), `"name":"sourceIPv4Address"`) {
		t.Fatalf("%d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/flows/templates?device=10.9.9.9"), ""), 404, "No flow exporter")
	wantError(t, do(t, c, "GET", srv.url("/api/flows/templates"), ""), 400, "device is required")
	wantError(t, do(t, c, "GET", srv.url("/api/search?type=flow&q=x"), ""), 400, errFlowNoText)
}

func TestFlowExportBodies(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "POST", srv.url("/api/exports"), `{"devices": ["10.1.0.1"], "from": "2026-11-16T09:00:00Z", "to": "2026-11-16T10:00:00Z",
		"types": ["flow"], "src": ["10.20.0.0/16"], "status": ["ok"], "flow_formats": ["csv"]}`)
	if r.code != 202 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	b := srv.b
	b.mu.Lock()
	got := b.exportReqs[len(b.exportReqs)-1]
	b.mu.Unlock()
	if got.Type != "flow" || got.Flow.Get("src") != "10.20.0.0/16" || got.Flow.Get("status") != "ok" || len(got.FlowFormats) != 1 {
		t.Fatalf("%+v", got)
	}
	for body, msg := range map[string]string{
		`"types": ["flow"], "flow_formats": ["pcap"]`:      `flow_formats: "pcap" isn't csv or ipfix.`,
		`"types": ["flow"], "flow_formats": []`:            "flow_formats: name csv",
		`"types": ["flow"], "q": "x"`:                      errFlowNoText,
		`"types": ["flow", "syslog"], "src": ["10.0.0.1"]`: "Filters apply to one data type",
		`"types": ["syslog"], "dst": ["10.0.0.1"]`:         "dst: not a filter for syslog.",
		`"types": ["flow"], "dst_port": ["x"]`:             `dst_port: "x" isn't a port`,
	} {
		wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"devices": ["10.1.0.1"], "from": "2026-11-16T09:00:00Z",
			"to": "2026-11-16T10:00:00Z", `+body+`}`), 400, msg)
	}
	wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "at": "2026-11-14T09:42:00Z", "active_devices": true,
		"src": ["10.0.0.1"]}`), 400, "src: a bundle takes no filters")
	if r := do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "at": "2026-11-14T09:42:00Z", "active_devices": true,
		"flow_formats": ["ipfix"]}`); r.code != 202 {
		t.Errorf("bundle with flow_formats: %d %s", r.code, r.body)
	}
}

func TestSavedSearchFlow(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "POST", srv.url("/api/saved-searches"), `{"name": "Denied", "type": "flow", "query": {"fw_event": ["denied"],
		"status": ["ok"], "range": {"last": "1h"}}}`)
	if r.code != 201 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	var ss SavedSearch
	if err := json.Unmarshal(r.body, &ss); err != nil {
		t.Fatal(err)
	}
	fr := ss.Query.FilterOf("flow")
	if ss.Type != "flow" || fr.Flow.Get("fw_event") != "denied" || fr.Flow.Get("status") != "ok" {
		t.Fatalf("%s %+v", r.body, fr.Flow)
	}
	for body, key := range map[string]string{
		`{"name": "x", "type": "flow", "query": {"q": "x"}}`:              "query.q",
		`{"name": "x", "type": "flow", "query": {"severities": [3]}}`:     "query.severities",
		`{"name": "x", "type": "syslog", "query": {"src": ["10.0.0.1"]}}`: "query.src",
		`{"name": "x", "type": "flow", "query": {"src": ["nope"]}}`:       "query.src",
	} {
		r := do(t, c, "POST", srv.url("/api/saved-searches"), body)
		if r.code != 400 || !strings.Contains(string(r.body), `"`+key+`"`) {
			t.Errorf("%s: %d %s", body, r.code, r.body)
		}
	}
}

// A flow result: every column, null where the record has none.
func TestFlowResultJSON(t *testing.T) {
	rec := &flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasDstPort | flow.HasProto | flow.HasBytes |
		flow.HasFwEvent | flow.HasTCPFlags,
		Start: ts("2026-11-16T09:30:11.2Z").UnixMilli(), End: ts("2026-11-16T09:31:01.95Z").UnixMilli(),
		Src: netip.MustParseAddr("10.20.0.5"), Dst: netip.MustParseAddr("198.51.100.7"), DstPort: 443, Proto: 6, Bytes: 2210444,
		Sampling: 1000, FwEvent: flow.FwDeleted, TCPFlags: 0x13, Domain: 1, Extras: []flow.Extra{{PEN: 32473, ID: 1, Value: []byte{10, 11}}}}
	b, err := json.Marshal(SearchLine{Received: ts("2026-11-16T09:31:02.004Z"), DeviceID: "10.1.0.1", Type: "flow", Ref: "r1", Flow: rec})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"type":"flow"`, `"start":"2026-11-16T09:30:11.200Z"`, `"src_port":null`, `"proto":6`,
		`"proto_name":"tcp"`, `"bytes_scaled":2210444000`, `"packets_scaled":null`, `"fw_event":"deleted"`, `"tcp_flags":"SAF"`,
		`"extras":[{"pen":32473,"id":1,"hex":"0a0b"}]`, `"rule_id":""`, `"time_source":"exporter"`, `"status":"ok"`, `"event_time":null`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	if strings.Contains(string(b), `"raw"`) {
		t.Errorf("a flow result has no raw: %s", b)
	}
	_ = time.Second
}
