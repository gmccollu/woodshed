package api

import (
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// The incident bundle's body (docs/api.md "Exports", kind "bundle") and
// GET /api/devices?active_from&active_to.

func TestBundleBody(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "at": "2026-11-14T09:42:00.250Z", "before": "1h", "after": "0s",
		"active_devices": true, "devices": [], "group": "", "ungrouped": false, "types": []}`)
	if r.code != 202 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	req := srv.b.exportReqs[0]
	if req.Kind != "bundle" || !req.At.Equal(time.Date(2026, 11, 14, 9, 42, 0, 250e6, time.UTC)) || req.Before != time.Hour || req.After != 0 ||
		!req.ActiveDevices || req.Types != nil || !req.From.IsZero() || !req.To.IsZero() {
		t.Errorf("request %+v", req)
	}
	// Defaults: 30 min before, 10 after; named devices and types kept.
	r = do(t, c, "POST", srv.url("/api/exports/estimate"), `{"kind": "bundle", "at": "2026-11-14T04:42:00-05:00", "devices": ["10.1.0.1", " "],
		"types": ["trap", "syslog", "trap"]}`)
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	req = srv.b.exportReqs[1]
	if req.Before != 30*time.Minute || req.After != 10*time.Minute || !slices.Equal(req.Devices, []string{"10.1.0.1"}) ||
		!slices.Equal(req.Types, []string{"trap", "syslog"}) || req.At.Location() != time.UTC || req.At.Hour() != 9 {
		t.Errorf("defaults %+v", req)
	}
	base := `"kind": "bundle", "at": "2026-11-14T09:42:00Z", "active_devices": true`
	for _, c2 := range []struct{ extra, msg string }{
		{`"from": "2026-11-14T09:00:00Z"`, `from: a bundle's window is at, before and after`},
		{`"to": "2026-11-14T09:00:00Z"`, `to: a bundle's window`},
		{`"q": "x"`, "q: a bundle takes no filters"},
		{`"severities": [3]`, "severities: a bundle takes no filters"},
		{`"facilities": ["unknown"]`, "facilities: a bundle takes no filters"},
		{`"app": ["sshd"]`, "app: a bundle takes no filters"},
		{`"exclude_host": ["x"]`, "exclude_host: a bundle takes no filters"},
		{`"syntax": "terms"`, "syntax: a bundle takes no filters"},
		{`"regex": true`, "regex: a bundle takes no filters"},
		{`"trap_oid": ["linkDown"]`, "trap_oid: a bundle takes no filters"},
		{`"generic": [0]`, "generic: a bundle takes no filters"},
		{`"all_devices": true`, "all_devices: a bundle takes active_devices"},
		{`"exclude_devices": ["10.1.0.9"]`, "exclude_devices: a bundle takes active_devices"},
		{`"before": "5x"`, `before: "5x" isn't a duration`},
		{`"after": "-1m"`, `after: "-1m" isn't a duration`},
		{`"types": ["flow"]`, `types: unknown data type "flow"`},
	} {
		wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{`+base+`, `+c2.extra+`}`), 400, c2.msg)
	}
	wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "active_devices": true}`), 400, "at is required")
	wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "at": "yesterday", "active_devices": true}`), 400,
		`at must be an RFC 3339 time, not "yesterday".`)
	// A plain export doesn't take the bundle's fields.
	wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"devices": ["10.1.0.1"], "from": "2026-11-10T00:00:00Z",
		"to": "2026-11-10T06:00:00Z", "at": "2026-11-10T01:00:00Z"}`), 400, `at, before, after and active_devices are for kind "bundle".`)
	wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"kind": "zip"}`), 400, `kind must be "export" or "bundle", not "zip".`)
}

func TestBundleDownloadName(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "at": "2026-11-14T09:42:00Z", "active_devices": true}`)
	if r.code != 202 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	id := r.json(t)["id"].(string)
	srv.b.mu.Lock()
	e := srv.b.exports[id]
	e.State, e.Filename = "ready", "woodshed-bundle-host-20261114T094200Z.zip"
	srv.b.exports[id] = e
	srv.b.zip = []byte("PK\x03\x04 pretend zip")
	srv.b.mu.Unlock()
	r = do(t, c, "GET", srv.url("/api/exports/"+id+"/download"), "")
	if r.code != 200 || r.header.Get("Content-Disposition") != `attachment; filename="woodshed-bundle-host-20261114T094200Z.zip"` {
		t.Errorf("download %d %v", r.code, r.header)
	}
}

func TestBundleEchoNormalized(t *testing.T) {
	at := time.Date(2026, 11, 14, 4, 42, 0, 0, time.FixedZone("x", -5*3600))
	e := ExportInfo{Filters: ExportFilters{Kind: "bundle", At: &at, Before: "30m", After: "10m", ActiveDevices: true}}
	e.normalize()
	if e.Filters.Types == nil || len(e.Filters.Types) != 0 || e.Filters.At.Location() != time.UTC || e.Filters.Type != "syslog" {
		t.Errorf("%+v", e.Filters)
	}
	var plain ExportInfo
	plain.normalize()
	if !slices.Equal(plain.Filters.Types, []string{"syslog"}) || plain.Filters.Kind != "export" || plain.Filters.At != nil {
		t.Errorf("plain %+v", plain.Filters)
	}
}

func TestDeviceQueryActive(t *testing.T) {
	q, err := ParseDeviceQuery(url.Values{"active_from": {"2026-11-14T09:12:00Z"}, "active_to": {"2026-11-14T09:52:00Z"}, "hidden": {"exclude"}})
	if err != nil || !q.ActiveFrom.Equal(time.Date(2026, 11, 14, 9, 12, 0, 0, time.UTC)) || q.ActiveTo.Sub(q.ActiveFrom) != 40*time.Minute {
		t.Fatalf("%+v %v", q, err)
	}
	for _, c := range []struct {
		v   url.Values
		msg string
	}{
		{url.Values{"active_from": {"2026-11-14T09:12:00Z"}}, "go together"},
		{url.Values{"active_to": {"2026-11-14T09:12:00Z"}}, "go together"},
		{url.Values{"active_from": {"2026-11-14T09:12:00Z"}, "active_to": {"2026-11-14T09:12:00Z"}}, "must be before"},
		{url.Values{"active_from": {"9:12"}, "active_to": {"2026-11-14T09:12:00Z"}}, "RFC 3339"},
	} {
		if _, err := ParseDeviceQuery(c.v); err == nil || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%v: %v, want %q", c.v, err, c.msg)
		}
	}
	srv := startServer(t, nil, UIConfig{})
	wantError(t, do(t, httpClient(), "GET", srv.url("/api/devices?active_from=2026-11-14T09:12:00Z"), ""), 400, "active_from and active_to go together")
}
