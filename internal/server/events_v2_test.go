package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// Events v2 through the real backend: the summary, the schema, saved searches
// and an export with the 1.1 filters.
func TestEventsV2InProcess(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, writeConfig(t, dir, port, 0, nil))
	run := loadgen.NewRunID()
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", port), Proto: "tcp", Count: 300, RunID: run, Rate: 5000, Message: "probe link down",
	}); err != nil {
		t.Fatal(err)
	}
	tag := loadgen.SeqTag(run)
	var page searchPage
	waitFor(t, "300 results", func() bool {
		page = searchPage{}
		r.do(t, "GET", "/api/search?limit=5000&syntax=terms&q="+url.QueryEscape(`"`+tag+`" link`), nil, &page)
		return len(page.Results) == 300
	})

	// The summary: every field, exact, complete.
	var sum api.SummaryPage
	q := "/api/search/summary?syntax=terms&q=" + url.QueryEscape(`"`+tag+`" NOT `+tag+`1`)
	for cursor := ""; ; {
		sum = api.SummaryPage{}
		path := q
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		if code := r.do(t, "GET", path, nil, &sum); code != 200 {
			t.Fatalf("summary %d", code)
		}
		if cursor = sum.NextCursor; cursor == "" {
			break
		}
	}
	if sum.Matched != 300-111 || sum.Histogram == nil || sum.Histogram.Source != "scan" || len(sum.Fields) != 5 || !sum.CountedFrom.Equal(sum.From) {
		t.Fatalf("summary %+v", sum)
	}
	for _, f := range sum.Fields {
		var n int64
		for _, v := range f.Values {
			n += v.Count
		}
		if n+f.Other+f.None != sum.Matched {
			t.Errorf("%s: %d + %d + %d != %d", f.Key, n, f.Other, f.None, sum.Matched)
		}
	}
	// The unfiltered histogram comes from the index.
	var idx api.SummaryPage
	r.do(t, "GET", "/api/search/summary?fields=none", nil, &idx)
	if idx.Histogram == nil || idx.Histogram.Source != "index" || idx.NextCursor != "" {
		t.Errorf("index histogram %+v", idx.Histogram)
	}
	var schema struct{ Types []api.SearchType }
	if r.do(t, "GET", "/api/search/schema", nil, &schema); len(schema.Types) != 4 || len(schema.Types[0].Fields) != 5 ||
		len(schema.Types[0].Fields[2].Domain) != 25 {
		t.Errorf("schema %+v", schema)
	}

	// Saved searches: missing devices are listed, never dropped; a bad query is refused per key.
	var ss api.SavedSearch
	body := map[string]any{"name": "Probe", "query": map[string]any{"q": tag + " NOT x", "syntax": "terms",
		"devices": []string{"127.0.0.1", "192.0.2.99"}, "range": map[string]string{"last": "1h"}}}
	if code := r.do(t, "POST", "/api/saved-searches", body, &ss); code != 201 {
		t.Fatalf("create %d", code)
	}
	if len(ss.MissingDevices) != 1 || ss.MissingDevices[0] != "192.0.2.99" || len(ss.Query.Devices) != 2 || ss.Query.Range.Last != "1h" {
		t.Errorf("saved %+v", ss)
	}
	var list []api.SavedSearch
	if r.do(t, "GET", "/api/saved-searches", nil, &list); len(list) != 1 || list[0].ID != ss.ID {
		t.Errorf("list %+v", list)
	}
	var verr struct{ Errors map[string]string }
	body["name"] = "Bad"
	body["query"] = map[string]any{"q": `"open`, "syntax": "terms", "exclude": "a OR", "facilities": []any{4}}
	if code := r.do(t, "POST", "/api/saved-searches", body, &verr); code != 400 ||
		verr.Errors["query.q"] != "Unclosed quote starting at character 1." || verr.Errors["query.exclude"] != `"OR" at character 3 needs a term on both sides.` {
		t.Errorf("validation %d %+v", code, verr)
	}
	body["query"] = map[string]any{"group": "nobody"}
	body["name"] = "Empty group"
	if code := r.do(t, "POST", "/api/saved-searches", body, &ss); code != 201 || !ss.MissingGroup {
		t.Errorf("missing group %d %+v", code, ss)
	}
	var clash map[string]string
	body["name"] = "PROBE"
	if code := r.do(t, "POST", "/api/saved-searches", body, &clash); code != 409 || !strings.Contains(clash["error"], `"PROBE" already exists`) {
		t.Errorf("clash %d %v", code, clash)
	}

	// Export with the 1.1 filters: the zip holds what the search showed, and the manifest says how.
	from := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	exp := map[string]any{"all_devices": true, "from": from, "to": to, "syntax": "terms", "q": `"` + tag + `" NOT ` + tag + `1`,
		"facilities": []any{1, 16, "unknown"}, "exclude_devices": []string{"192.0.2.99"}, "exclude_app": []string{"nothing-here"}}
	var created map[string]string
	if code := r.do(t, "POST", "/api/exports", exp, &created); code != 202 {
		t.Fatalf("create export %d %v", code, created)
	}
	var info api.ExportInfo
	waitFor(t, "export ready", func() bool {
		r.do(t, "GET", "/api/exports/"+created["id"], nil, &info)
		return info.State == "ready" || info.State == "failed"
	})
	if info.Lines != 300-111 { // loadgen sends <134>: local0 (16), info
		t.Errorf("exported %d lines", info.Lines)
	}
	if info.Filters.Syntax != "terms" || info.Filters.Type != "syslog" || len(info.Filters.Facilities.Values) != 3 || len(info.Filters.ExcludeDevices) != 1 {
		t.Errorf("filters %+v", info.Filters)
	}
	resp, err := http.Get(r.base + "/api/exports/" + created["id"] + "/download")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	var man struct {
		Lines   int64
		Request struct{ Filters map[string]any }
	}
	var readme string
	for _, f := range zr.File {
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		switch f.Name {
		case "manifest.json":
			json.Unmarshal(b, &man)
		case "README.txt":
			readme = string(b)
		}
	}
	fl := man.Request.Filters
	if man.Lines != info.Lines || fl["syntax"] != "terms" || fl["type"] != "syslog" || fmt.Sprint(fl["facilities"]) != "[1 16 unknown]" ||
		fmt.Sprint(fl["exclude_devices"]) != "[192.0.2.99]" || fmt.Sprint(fl["exclude_app"]) != "[nothing-here]" || fmt.Sprint(fl["exclude_host"]) != "[]" {
		t.Errorf("manifest %d lines (info %d) %v", man.Lines, info.Lines, fl)
	}
	for _, want := range []string{"Facilities: 1, 16, unknown", "boolean terms", "Devices left out: 192.0.2.99", "Program/tag left out: nothing-here"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README lacks %q:\n%s", want, readme)
		}
	}
	// The export holds exactly what the search with the same filters returns.
	var sp searchPage
	r.do(t, "GET", "/api/search?limit=5000&syntax=terms&facilities=1,16,unknown&exclude_devices=192.0.2.99&exclude_app=nothing-here&from="+
		url.QueryEscape(from)+"&to="+url.QueryEscape(to)+"&q="+url.QueryEscape(`"`+tag+`" NOT `+tag+`1`), nil, &sp)
	if int64(len(sp.Results)) != info.Lines {
		t.Errorf("search %d, export %d", len(sp.Results), info.Lines)
	}
}
