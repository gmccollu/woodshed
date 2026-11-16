package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// flowServer starts a server with the flow listener on two free ports.
func flowServer(t *testing.T, edit func(*config.Config)) (*running, int, int) {
	t.Helper()
	dir := t.TempDir()
	nf, ix := freeUDP(t), freeUDP(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.Flow.Enabled = true
		c.Listeners.Flow.Addr = "127.0.0.1"
		c.Listeners.Flow.NetFlowPort, c.Listeners.Flow.IPFIXPort = nf, ix
		c.Listeners.Flow.RuleIDIEs = []string{loadgen.RuleIE(loadgen.ProtoIPFIX).String()}
		if edit != nil {
			edit(c)
		}
	})
	return start(t, cfgPath), nf, ix
}

// waitFlows waits until the summary counts want flow records in the window
// (stored, flushed and indexed), or fails.
func waitFlows(t *testing.T, r *running, q string, want int64) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var got int64
	for time.Now().Before(deadline) {
		var p api.SummaryPage
		if code := r.do(t, "GET", "/api/search/summary?type=flow&fields=proto&histogram=false&budget_ms=10000&"+q, nil, &p); code != 200 {
			t.Fatalf("summary: %d", code)
		}
		if got = p.Matched; got == want && !p.Partial {
			return
		}
		if got > want {
			t.Fatalf("%s: %d flows, want %d", q, got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s: %d flows, want %d", q, got, want)
}

// Flows end to end, in process: IPFIX event records and NetFlow v5 from the
// generator to stored records, exactly once by sequence number; the flow
// state, top-N (denied sources by flows), search paging, the timeline and the
// templates; both ports read every version.
func TestFlowsEndToEndInProcess(t *testing.T) {
	r, nf, ix := flowServer(t, nil)
	ctx := context.Background()
	var mu sync.Mutex
	sent := map[uint64]flow.Record{}
	log := func(es []loadgen.Expected) {
		mu.Lock()
		for _, e := range es {
			sent[e.Seq] = e.Record
		}
		mu.Unlock()
	}
	run := "0badc0de"
	res, err := loadgen.SendFlows(ctx, loadgen.FlowOptions{Proto: loadgen.ProtoIPFIX, Addr: fmt.Sprintf("127.0.0.1:%d", ix), Count: 3000,
		Rate: 20000, Events: true, Domains: 2, Sampling: 100, SampledDomains: 1, RunID: run}, log)
	if err != nil || res.Records != 3000 {
		t.Fatalf("send: %+v %v", res, err)
	}
	// NetFlow v5 on the IPFIX port: any version on either port.
	if _, err := loadgen.SendFlows(ctx, loadgen.FlowOptions{Proto: loadgen.ProtoNetFlow5, Addr: fmt.Sprintf("127.0.0.1:%d", ix), Count: 300,
		Rate: 20000, RunID: "00001234", FirstSeq: 100000}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := loadgen.SendFlows(ctx, loadgen.FlowOptions{Proto: loadgen.ProtoNetFlow9, Addr: fmt.Sprintf("127.0.0.1:%d", nf), Count: 600,
		Rate: 20000, RunID: "00005678", FirstSeq: 200000}, nil); err != nil {
		t.Fatal(err)
	}
	waitFlows(t, r, "", 3900)

	// Every IPFIX record once, by run and sequence number, through paging.
	seen := map[uint64]int{}
	denied := 0
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 100 {
			t.Fatal("no end")
		}
		v := url.Values{"type": {"flow"}, "limit": {"700"}}
		if cursor != "" {
			v.Set("cursor", cursor)
		}
		var raw struct {
			Results []struct {
				DeviceID string          `json:"device_id"`
				Type     string          `json:"type"`
				Fields   json.RawMessage `json:"fields"`
			} `json:"results"`
			NextCursor string `json:"next_cursor"`
		}
		code, _, body := r.doRaw(t, "GET", "/api/search?"+v.Encode(), nil)
		if code != 200 || json.Unmarshal(body, &raw) != nil {
			t.Fatalf("search: %d %s", code, body)
		}
		for _, x := range raw.Results {
			var f struct {
				FwEvent *string `json:"fw_event"`
				RuleID  string  `json:"rule_id"`
				Extras  []struct {
					PEN uint32 `json:"pen"`
					ID  uint16 `json:"id"`
					Hex string `json:"hex"`
				} `json:"extras"`
			}
			if err := json.Unmarshal(x.Fields, &f); err != nil || x.Type != "flow" || x.DeviceID != "127.0.0.1" {
				t.Fatalf("result %s %v", x.Fields, err)
			}
			var rec flow.Record
			for _, e := range f.Extras {
				b := make([]byte, len(e.Hex)/2)
				fmt.Sscanf(e.Hex, "%x", &b)
				rec.Extras = append(rec.Extras, flow.Extra{PEN: e.PEN, ID: e.ID, Value: b})
			}
			if tag, seq, ok := loadgen.FlowSeq(&rec); ok && loadgen.MatchRun(tag, run) {
				seen[seq]++
				if f.FwEvent != nil && *f.FwEvent == "denied" {
					denied++
				}
				if f.RuleID == "" {
					t.Fatalf("no rule_id from the configured IE: %s", x.Fields)
				}
			}
		}
		if raw.NextCursor == "" {
			break
		}
		cursor = raw.NextCursor
	}
	mu.Lock()
	if len(seen) != len(sent) {
		t.Fatalf("%d IPFIX records found, %d sent", len(seen), len(sent))
	}
	wantDenied := 0
	for s, rec := range sent {
		if seen[s] != 1 {
			t.Fatalf("seq %d seen %d times", s, seen[s])
		}
		if rec.Is(flow.HasFwEvent) && rec.FwEvent == flow.FwDenied {
			wantDenied++
		}
	}
	mu.Unlock()
	if denied != wantDenied || denied == 0 {
		t.Fatalf("denied %d, want %d", denied, wantDenied)
	}

	// Top denied sources: flows by default, and the total is every denied event.
	var top api.FlowTopPage
	if code := r.do(t, "GET", "/api/flows/top?by=src&fw_event=denied&budget_ms=10000", nil, &top); code != 200 {
		t.Fatalf("top: %d", code)
	}
	if top.Metric != "flows" || top.Total.Flows != int64(wantDenied) || len(top.Rows) == 0 || top.Partial ||
		top.Progress == nil || top.Progress.BlocksDone != top.Progress.BlocksTotal {
		t.Fatalf("top denied %+v", top)
	}
	var st api.FlowState
	if code := r.do(t, "GET", "/api/flows", nil, &st); code != 200 || !st.Enabled || len(st.Exporters) != 1 {
		t.Fatalf("flows: %d %+v", code, st)
	}
	e := st.Exporters[0]
	if e.DeviceID != "127.0.0.1" || e.Counts24h.Records != 3900 || len(e.Domains) < 2 || st.Budget.Bytes <= 0 || st.Budget.UsedBytes <= 0 {
		t.Fatalf("exporter %+v budget %+v", e, st.Budget)
	}
	sampled := false
	for _, d := range e.Domains {
		sampled = sampled || d.Sampling == 100
	}
	if !sampled {
		t.Fatalf("no sampled domain: %+v", e.Domains)
	}
	var tpl api.FlowTemplates
	if code := r.do(t, "GET", "/api/flows/templates?device=127.0.0.1", nil, &tpl); code != 200 || len(tpl.Domains) == 0 ||
		len(tpl.Domains[0].Templates) == 0 || len(tpl.Domains[0].Templates[0].Fields) == 0 {
		t.Fatalf("templates %d %+v", code, tpl)
	}
	now := time.Now().UTC()
	var tl api.FlowTimeline
	q := url.Values{"from": {now.Add(-2 * time.Hour).Format(time.RFC3339)}, "to": {now.Add(time.Hour).Format(time.RFC3339)}}
	if code := r.do(t, "GET", "/api/flows/timeline?"+q.Encode(), nil, &tl); code != 200 || len(tl.Devices) != 1 {
		t.Fatalf("timeline %d %+v", code, tl)
	}
	var flows int64
	for _, p := range tl.Devices[0].Points {
		flows += p.Flows
	}
	if flows != 3900 {
		t.Fatalf("timeline flows %d", flows)
	}
	// The unfiltered histogram comes from flow_minute; a filtered one from the scan.
	var sum api.SummaryPage
	r.do(t, "GET", "/api/search/summary?type=flow&fields=none&bucket=60&"+q.Encode(), nil, &sum)
	if sum.Histogram == nil || sum.Histogram.Source != "index" || sum.Matched != 3900 {
		t.Fatalf("index histogram %+v %d", sum.Histogram, sum.Matched)
	}
	r.do(t, "GET", "/api/search/summary?type=flow&fw_event=denied&bucket=60&budget_ms=10000&"+q.Encode(), nil, &sum)
	if sum.Histogram == nil || sum.Histogram.Source != "scan" || sum.Matched != int64(wantDenied) || sum.Progress == nil {
		t.Fatalf("scan histogram %+v %d", sum.Histogram, sum.Matched)
	}
	// The listeners show in the status.
	var status api.Status
	r.do(t, "GET", "/api/status", nil, &status)
	n := 0
	for _, l := range status.Listeners {
		if (l.Proto == "netflow" && l.Port == nf || l.Proto == "ipfix" && l.Port == ix) && l.OK {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("listeners %+v", status.Listeners)
	}
	// A device with flows lists the type, and its records.
	var devs api.DevicePage
	r.do(t, "GET", "/api/devices", nil, &devs)
	if len(devs.Devices) != 1 || devs.Devices[0].LinesByType["flow"] != 3900 {
		t.Fatalf("devices %+v", devs.Devices)
	}
}

// Settings: listeners.flow and flow_budget_bytes round trip; turning the
// listener off stops both sockets.
func TestFlowSettings(t *testing.T) {
	r, _, _ := flowServer(t, nil)
	var st api.Settings
	r.do(t, "GET", "/api/settings", nil, &st)
	if st.Listeners.Flow == nil || !st.Listeners.Flow.Enabled || st.Listeners.Flow.TemplateTimeout != "30m" ||
		st.Storage.FlowBudgetBytes == nil || *st.Storage.FlowBudgetBytes != 0 {
		t.Fatalf("settings %+v %+v", st.Listeners.Flow, st.Storage)
	}
	st.Listeners.Flow.Enabled = false
	st.Listeners.Flow.RuleIDIEs = []string{"32473:7"}
	two := int64(2 << 30)
	st.Storage.FlowBudgetBytes = &two
	var out api.Settings
	if code := r.do(t, "PUT", "/api/settings", st, &out); code != 200 {
		t.Fatalf("put: %d", code)
	}
	if out.Listeners.Flow.Enabled || out.Listeners.Flow.RuleIDIEs[0] != "32473:7" || *out.Storage.FlowBudgetBytes != two {
		t.Fatalf("saved %+v", out.Listeners.Flow)
	}
	if a := r.srv.be.ln.Load().FlowAddrs(); len(a) != 0 {
		t.Fatalf("still listening: %v", a)
	}
	if b := r.srv.be.store.FlowBudget(); b != two {
		t.Fatalf("budget %d", b)
	}
	st.Listeners.Flow.RuleIDIEs = []string{"x"}
	var verr struct {
		Errors map[string]string `json:"errors"`
	}
	if code := r.do(t, "PUT", "/api/settings", st, &verr); code != 400 || verr.Errors["listeners.flow.rule_id_ies[0]"] == "" {
		t.Fatalf("bad rule ie: %d %+v", code, verr)
	}
}
