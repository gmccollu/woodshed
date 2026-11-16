package api

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestParseSearch11(t *testing.T) {
	r, err := ParseSearch(url.Values{"type": {"syslog"}, "syntax": {"terms"}, "facilities": {"0, 4,unknown,4"},
		"exclude_devices": {"10.1.0.9,"}, "exclude_app": {"kernel, %FW-*"}, "exclude_host": {"lab-01"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "syslog" || !r.Terms || !slices.Equal(r.Facilities.Values, []int{0, 4, Unknown}) || !slices.Equal(r.ExcludeDevices, []string{"10.1.0.9"}) ||
		!slices.Equal(r.ExcludeApp, []string{"kernel", "%FW-*"}) || !slices.Equal(r.ExcludeHost, []string{"lab-01"}) {
		t.Errorf("%+v", r)
	}
	if r, _ := ParseSearch(url.Values{}); r.Type != "syslog" || r.Terms || !r.Facilities.All() {
		t.Errorf("defaults %+v", r)
	}
	if r, _ := ParseSearch(url.Values{"facilities": {"none"}}); !r.Facilities.None {
		t.Errorf("none %+v", r.Facilities)
	}
	for bad, msg := range map[string]string{
		"type=sflow":              `type: unknown data type "sflow".`,
		"type=trap&severities=3":  `severities: not a filter for SNMP traps.`,
		"trap_oid=linkDown":       `trap_oid: not a filter for syslog.`,
		"type=trap&pdus=get":      `pdus: "get" is not one of v1trap, trap, inform, unexpected (or none on its own).`,
		"type=trap&trap_oid=nope": `trap_oid: "nope" is not a name in the loaded MIBs.`,
		"syntax=lucene":           `syntax must be text or terms`,
		"syntax=terms&regex=true": errTermsRegex,
		"facilities=24":           `facilities: "24"`,
		"facilities=none,3":       `none can't be combined`,
		"facilities=-1":           `facilities: "-1"`,
	} {
		v, _ := url.ParseQuery(bad)
		if _, err := ParseSearch(v); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v, want %q", bad, err, msg)
		}
	}
}

func TestFacilitiesJSON(t *testing.T) {
	for in, want := range map[string]string{`[0, 23, "unknown"]`: `[0,23,"unknown"]`, `[]`: `[]`, `null`: `[]`, `["none"]`: `["none"]`, `[4, 4]`: `[4]`} {
		var f Facilities
		if err := json.Unmarshal([]byte(in), &f); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if b, _ := json.Marshal(f); string(b) != want {
			t.Errorf("%s: %s, want %s", in, b, want)
		}
	}
	for _, bad := range []string{`[24]`, `[-1]`, `["none", 1]`, `"4"`, `[true]`, `["4,5"]`} {
		var f Facilities
		if err := json.Unmarshal([]byte(bad), &f); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestSummaryAndSchemaRoutes(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "GET", srv.url("/api/search/summary?q=deny&syntax=terms&facilities=4&exclude_host=x&fields=host,app&top=99&bucket=60&budget_ms=50000&cursor=k"), "")
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	req := srv.b.summaries[0]
	if req.Q != "deny" || !req.Terms || !slices.Equal(req.Facilities.Values, []int{4}) || !slices.Equal(req.ExcludeHost, []string{"x"}) ||
		!slices.Equal(req.Fields, []string{"host", "app"}) || req.Top != 50 || req.Bucket != 60 || req.BudgetMS != 10000 || req.Cursor != "k" || !req.Histogram {
		t.Errorf("%+v", req)
	}
	body := string(r.body)
	for _, want := range []string{`"type":"syslog"`, `"counted_from":"2026-11-13T14:00:00Z"`, `"count":812`, `"count":null`, `"source":"index"`, `"distinct_capped":false`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
	// Defaults; fields=none; histogram=false leaves the histogram out.
	do(t, c, "GET", srv.url("/api/search/summary"), "")
	if req := srv.b.summaries[1]; req.Fields != nil || req.Top != 10 || req.BudgetMS != 2000 || !req.Histogram {
		t.Errorf("defaults %+v", req)
	}
	r = do(t, c, "GET", srv.url("/api/search/summary?fields=none&histogram=false"), "")
	if req := srv.b.summaries[2]; req.Fields == nil || len(req.Fields) != 0 || req.Histogram {
		t.Errorf("fields=none %+v", req)
	}
	if strings.Contains(string(r.body), `"histogram"`) {
		t.Errorf("histogram=false: %s", r.body)
	}
	for _, bad := range []string{"top=0", "bucket=x", "budget_ms=0", "histogram=maybe", "type=sflow", "syntax=terms&regex=true"} {
		wantError(t, do(t, c, "GET", srv.url("/api/search/summary?"+bad), ""), 400, "")
	}
	srv.b.mu.Lock()
	srv.b.searchErr = &RequestError{Msg: "This summary expired; start it again."}
	srv.b.mu.Unlock()
	wantError(t, do(t, c, "GET", srv.url("/api/search/summary?cursor=old"), ""), 400, "expired")

	r = do(t, c, "GET", srv.url("/api/search/schema"), "")
	if r.code != 200 || !strings.Contains(string(r.body), `"exclude_param":"exclude_devices","domain":null`) ||
		!strings.Contains(string(r.body), `"domain":[{"value":"0","label":"emerg"}`) {
		t.Errorf("%d %s", r.code, r.body)
	}
}

func TestSavedSearchRoutes(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "GET", srv.url("/api/saved-searches"), "")
	var list []map[string]any
	if err := json.Unmarshal(r.body, &list); err != nil || len(list) != 1 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	q := list[0]["query"].(map[string]any)
	if q["range"].(map[string]any)["last"] != "1h" || len(list[0]["missing_devices"].([]any)) != 1 || q["order"] != "desc" {
		t.Errorf("%s", r.body)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/saved-searches?type=sflow"), ""), 400, "unknown data type")

	// Create: 201 with an ETag, defaults filled in.
	r = do(t, c, "POST", srv.url("/api/saved-searches"), `{"name": "  Auth failures ", "query": {"q": "fail", "syntax": "terms",
		"severities": [3, "unknown"], "facilities": [4], "app": ["sshd", " "], "range": {"from": "2026-11-13T00:00:00Z", "to": "2026-11-13T02:00:00+01:00"}}}`)
	if r.code != 201 || r.header.Get("ETag") == "" {
		t.Fatalf("%d %s", r.code, r.body)
	}
	var ss SavedSearch
	json.Unmarshal(r.body, &ss)
	m := r.json(t)
	if ss.Name != "Auth failures" || ss.Type != "syslog" || !strings.Contains(string(r.body), `"range":{"from":"2026-11-13T00:00:00Z","to":"2026-11-13T01:00:00Z"}`) {
		t.Errorf("%s", r.body)
	}
	if !strings.Contains(string(r.body), `"facilities":[4]`) || !strings.Contains(string(r.body), `"app":["sshd"]`) || !strings.Contains(string(r.body), `"exclude_devices":[]`) {
		t.Errorf("%s", r.body)
	}
	id := m["id"].(string)
	etag := r.header.Get("ETag")

	// Validation errors are dotted keys.
	for body, key := range map[string]string{
		`{"name": "", "query": {}}`:                                           "name",
		`{"name": "` + strings.Repeat("x", 81) + `"}`:                         "name",
		`{"query": {}}`:                                                       "name",
		`{"name": "x", "type": "sflow"}`:                                      "type",
		`{"name": "x", "query": {"syntax": "terms", "regex": true}}`:          "query.syntax",
		`{"name": "x", "query": {"range": {"last": "0m"}}}`:                   "query.range.last",
		`{"name": "x", "query": {"range": {"last": "401d"}}}`:                 "query.range.last",
		`{"name": "x", "query": {"range": {"last": "90s"}}}`:                  "query.range.last",
		`{"name": "x", "query": {"range": {"from": "2026-11-13T00:00:00Z"}}}`: "query.range.to",
		`{"name": "x", "query": {"range": {"last": "1h", "from": "x"}}}`:      "query.range",
		`{"name": "x", "query": {"severities": [9]}}`:                         "query.severities",
		`{"name": "x", "query": {"facilities": ["x"]}}`:                       "query.facilities",
		`{"name": "x", "query": {"order": "up"}}`:                             "query.order",
		`{"name": "x", "query": {"group": "HQ", "ungrouped": true}}`:          "query.ungrouped",
		`{"name": "x", "query": {"q": "bad("}}`:                               "query.q",
		`{"name": "x", "query": {"nope": 1}}`:                                 "query",
	} {
		r := do(t, c, "POST", srv.url("/api/saved-searches"), body)
		if r.code != 400 {
			t.Errorf("%s: %d %s", body, r.code, r.body)
			continue
		}
		errs, _ := r.json(t)["errors"].(map[string]any)
		if _, ok := errs[key]; !ok {
			t.Errorf("%s: errors %v, want key %s", body, errs, key)
		}
	}
	// Lists hold at most 1,000 items; the body is at most 64 KiB.
	many := `["` + strings.Repeat(`a","`, 1000) + `a"]`
	if r := do(t, c, "POST", srv.url("/api/saved-searches"), `{"name": "x", "query": {"app": `+many+`}}`); r.code != 400 ||
		!strings.Contains(string(r.body), "query.app") {
		t.Errorf("1,001 items: %d %s", r.code, r.body)
	}
	if r := do(t, c, "POST", srv.url("/api/saved-searches"), `{"name": "x", "query": {"q": "`+strings.Repeat("x", 65<<10)+`"}}`); r.code != 413 {
		t.Errorf("65 KiB: %d", r.code)
	}
	// A name in use, ignoring case.
	wantError(t, do(t, c, "POST", srv.url("/api/saved-searches"), `{"name": "edge DENIES"}`), 409, `A saved search named "edge DENIES" already exists.`)

	// Read, update with If-Match, stale If-Match, delete.
	r = do(t, c, "GET", srv.url("/api/saved-searches/"+id), "")
	if r.code != 200 || r.header.Get("ETag") != etag {
		t.Fatalf("%d %s %s", r.code, r.header.Get("ETag"), etag)
	}
	r = do(t, c, "PUT", srv.url("/api/saved-searches/"+id), `{"name": "Auth", "query": {"q": "fail"}}`, "If-Match: "+etag)
	if r.code != 200 || r.header.Get("ETag") == etag || r.json(t)["name"] != "Auth" {
		t.Fatalf("%d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "PUT", srv.url("/api/saved-searches/"+id), `{"name": "Auth2"}`, "If-Match: "+etag), 409, "changed since you loaded it")
	if r := do(t, c, "PUT", srv.url("/api/saved-searches/"+id), `{"name": "Auth3"}`); r.code != 200 {
		t.Errorf("PUT without If-Match: %d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "PUT", srv.url("/api/saved-searches/ss_99999999"), `{"name": "x"}`), 404, "No saved search")
	wantError(t, do(t, c, "GET", srv.url("/api/saved-searches/ss_123456789"), ""), 404, "")
	wantError(t, do(t, c, "GET", srv.url("/api/saved-searches/ss_xyz"), ""), 404, "No saved search")
	if r := do(t, c, "DELETE", srv.url("/api/saved-searches/"+id), ""); r.code != 204 {
		t.Errorf("delete %d", r.code)
	}
	wantError(t, do(t, c, "DELETE", srv.url("/api/saved-searches/"+id), ""), 404, "No saved search")

	// The 201st is refused.
	for i := 0; ; i++ {
		r := do(t, c, "POST", srv.url("/api/saved-searches"), `{"name": "s`+strings.Repeat("x", i%3)+string(rune('A'+i%26))+strings.Repeat("y", i/26)+`"}`)
		if r.code == 409 {
			wantError(t, r, 409, "There are already 200 saved searches; delete one first.")
			break
		}
		if r.code != 201 || i > 300 {
			t.Fatalf("%d: %d %s", i, r.code, r.body)
		}
	}
}

func TestExportBody11(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	base := `"devices": ["10.1.0.1"], "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"`
	r := do(t, c, "POST", srv.url("/api/exports"), `{`+base+`, "type": "syslog", "syntax": "terms", "q": "a OR b", "facilities": [4, "unknown"],
		"exclude_devices": ["10.1.0.9", " "], "exclude_app": ["kernel"], "exclude_host": ["lab-01"]}`)
	if r.code != 202 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	req := srv.b.exportReqs[0]
	if !req.Terms || req.Type != "syslog" || !slices.Equal(req.Facilities.Values, []int{4, Unknown}) || !slices.Equal(req.ExcludeDevices, []string{"10.1.0.9"}) ||
		!slices.Equal(req.ExcludeApp, []string{"kernel"}) || !slices.Equal(req.ExcludeHost, []string{"lab-01"}) {
		t.Errorf("%+v", req)
	}
	for _, bad := range []string{`"type": "sflow"`, `"syntax": "x"`, `"syntax": "terms", "regex": true`, `"facilities": [30]`} {
		wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{`+base+`, `+bad+`}`), 400, "")
	}
}
