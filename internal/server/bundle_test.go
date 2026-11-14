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

// The incident bundle through the real backend (docs/api.md "Exports", kind
// "bundle"): the entry's echo, the zip and its name, and the active devices.
func TestBundleInProcess(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, writeConfig(t, dir, port, 0, nil))
	run := loadgen.NewRunID()
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", port), Proto: "tcp", Count: 40, RunID: run, Rate: 5000, Message: "probe bundle",
	}); err != nil {
		t.Fatal(err)
	}
	tag := loadgen.SeqTag(run)
	waitFor(t, "40 results", func() bool {
		var page searchPage
		r.do(t, "GET", "/api/search?limit=5000&q="+url.QueryEscape(tag), nil, &page)
		return len(page.Results) == 40
	})
	now := time.Now().UTC()
	q := url.Values{"active_from": {now.Add(-10 * time.Minute).Format(time.RFC3339Nano)}, "active_to": {now.Add(time.Second).Format(time.RFC3339Nano)}}
	for _, sort := range []string{"rate", "name"} {
		var page api.DevicePage
		if code := r.do(t, "GET", "/api/devices?sort="+sort+"&"+q.Encode(), nil, &page); code != 200 || page.Total != 1 ||
			len(page.Devices) != 1 || page.Devices[0].ID != "127.0.0.1" {
			t.Errorf("active (%s): %d %+v", sort, code, page)
		}
	}
	q = url.Values{"active_from": {now.Add(-2 * time.Hour).Format(time.RFC3339Nano)}, "active_to": {now.Add(-time.Hour).Format(time.RFC3339Nano)}}
	for _, sort := range []string{"rate", "name"} {
		var page api.DevicePage
		if code := r.do(t, "GET", "/api/devices?sort="+sort+"&"+q.Encode(), nil, &page); code != 200 || page.Total != 0 || len(page.Devices) != 0 {
			t.Errorf("an hour ago (%s): %d %+v", sort, code, page)
		}
	}

	body := map[string]any{"kind": "bundle", "at": now.Format(time.RFC3339Nano), "before": "10m", "after": "5m", "active_devices": true}
	var est api.ExportEstimate
	if code := r.do(t, "POST", "/api/exports/estimate", body, &est); code != 200 || est.Lines < 40 {
		t.Fatalf("estimate %d %+v", code, est)
	}
	var created map[string]string
	if code := r.do(t, "POST", "/api/exports", body, &created); code != 202 {
		t.Fatalf("create %d", code)
	}
	var info api.ExportInfo
	waitFor(t, "bundle ready", func() bool {
		r.do(t, "GET", "/api/exports/"+created["id"], nil, &info)
		return info.State == "ready"
	})
	var raw struct{ Filters map[string]any }
	r.do(t, "GET", "/api/exports/"+created["id"], nil, &raw)
	f := raw.Filters
	if f["kind"] != "bundle" || f["before"] != "10m" || f["after"] != "5m" || f["active_devices"] != true ||
		fmt.Sprint(f["types"]) != "[syslog]" || f["at"] == nil {
		t.Errorf("filters %v", f)
	}
	if info.From.Sub(now.Add(-10*time.Minute)).Abs() > time.Millisecond {
		t.Errorf("from %v", info.From)
	}
	if info.To.After(time.Now()) || !info.To.Before(now.Add(5*time.Minute)) {
		t.Errorf("to %v isn't cut at now", info.To)
	}
	resp, err := http.Get(r.base + "/api/exports/" + created["id"] + "/download")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="woodshed-bundle-`) ||
		!strings.HasSuffix(cd, now.Format("-20060102T150405Z")+`.zip"`) {
		t.Errorf("name %q", cd)
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	var readme string
	var man struct {
		Kind    string
		Summary []struct {
			DeviceID string `json:"device_id"`
			Types    map[string]struct {
				Lines int64 `json:"lines"`
			} `json:"types"`
		}
	}
	for _, zf := range zr.File {
		rc, _ := zf.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		switch zf.Name {
		case "README.txt":
			readme = string(b)
		case "manifest.json":
			json.Unmarshal(b, &man)
		}
	}
	if !strings.HasPrefix(readme, "Incident bundle around ") || !strings.Contains(readme, "\n127.0.0.1\n  Syslog       40 messages, first ") {
		t.Errorf("README:\n%s", readme)
	}
	if man.Kind != "bundle" || len(man.Summary) != 1 || man.Summary[0].Types["syslog"].Lines != 40 {
		t.Errorf("manifest %+v", man)
	}
	// Nothing in the window: a 400 that says so.
	old := map[string]any{"kind": "bundle", "at": now.Add(-48 * time.Hour).Format(time.RFC3339), "active_devices": true}
	var e struct{ Error string }
	if code := r.do(t, "POST", "/api/exports", old, &e); code != 400 || !strings.HasPrefix(e.Error, "No device stored anything between ") {
		t.Errorf("empty window: %d %q", code, e.Error)
	}
}
