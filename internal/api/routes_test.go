package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// ---- docs/api.md examples ----

// stripComments removes // comments outside JSON strings.
func stripComments(s string) string {
	var b strings.Builder
	inStr, esc := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			b.WriteByte(c)
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		if c == '/' && i+1 < len(s) && s[i+1] == '/' {
			for i < len(s) && s[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// docExamples returns the ```json block after each "`GET <route>`" heading
// line in docs/api.md, keyed by route.
func docExamples(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api.md")
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout may convert the doc to CRLF; the parser expects LF.
	doc := strings.ReplaceAll(string(raw), "\r\n", "\n")
	out := map[string]any{}
	// A route line starting "`GET /api/x`" owns the next ```json block, unless
	// another route line comes first.
	heads := regexp.MustCompile("(?m)^`GET (/api/[a-z/-]+)[`?]").FindAllStringSubmatchIndex(doc, -1)
	for i, h := range heads {
		route := doc[h[2]:h[3]]
		rest := doc[h[1]:]
		if i+1 < len(heads) {
			rest = doc[h[1]:heads[i+1][0]]
		}
		start := strings.Index(rest, "```json\n")
		if start < 0 {
			continue
		}
		body := rest[start+len("```json\n"):]
		end := strings.Index(body, "\n```")
		if end < 0 {
			t.Fatalf("unterminated example for %s", route)
		}
		var v any
		if err := json.Unmarshal([]byte(stripComments(body[:end])), &v); err != nil {
			t.Fatalf("docs/api.md example for %s isn't JSON: %v", route, err)
		}
		out[route] = v
	}
	if m := regexp.MustCompile("`GET /api/groups` → `(\\[.*?\\])`").FindStringSubmatch(doc); m != nil {
		var v any
		if err := json.Unmarshal([]byte(m[1]), &v); err != nil {
			t.Fatalf("groups example: %v", err)
		}
		out["/api/groups"] = v
	}
	// One-line examples: "`GET /api/rejected` → `[...]`".
	if m := regexp.MustCompile("`GET /api/rejected` → `(\\[.*?\\])`").FindStringSubmatch(doc); m != nil {
		var v any
		if err := json.Unmarshal([]byte(m[1]), &v); err != nil {
			t.Fatalf("rejected example: %v", err)
		}
		out["/api/rejected"] = v
	}
	// "`GET /api/storage/estimate?retention_bytes=N` → `{...}`", "…" for values
	// the doc doesn't give (any kind).
	if m := regexp.MustCompile("`GET /api/storage/estimate\\?retention_bytes=N` → `(\\{.*?\\})`").FindStringSubmatch(doc); m != nil {
		var v any
		if err := json.Unmarshal([]byte(strings.ReplaceAll(m[1], "…", "null")), &v); err != nil {
			t.Fatalf("storage estimate example: %v", err)
		}
		out["/api/storage/estimate"] = v
	}
	// Key lists: "`GET /api/storage/history` → `[{"time", "file", ...: "age|cap|low_disk"}]`".
	if m := regexp.MustCompile("`GET /api/storage/history` → `\\[\\{(.*?)\\}\\]`").FindStringSubmatch(doc); m != nil {
		obj := map[string]any{}
		for _, k := range regexp.MustCompile(`"([a-z_]+)"(?:\s*:\s*"[^"]*")?`).FindAllStringSubmatch(m[1], -1) {
			obj[k[1]] = nil // type unknown
		}
		out["/api/storage/history"] = []any{obj}
	}
	return out
}

func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "bool"
	}
	return fmt.Sprintf("%T", v)
}

func keys(m map[string]any) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// sameShape checks that got has the doc example's shape: the same object keys
// (optional ones may be missing), the same kinds where the example isn't null,
// and array elements shaped like the example's elements.
func sameShape(t *testing.T, where string, doc, got any, optional map[string]bool) {
	t.Helper()
	if doc == nil {
		return // null in the doc: nullable, or a key list without types
	}
	if jsonKind(doc) != jsonKind(got) {
		if jsonKind(got) == "null" && optional[where] {
			return
		}
		t.Errorf("%s: kind %s, doc has %s", where, jsonKind(got), jsonKind(doc))
		return
	}
	switch d := doc.(type) {
	case map[string]any:
		g := got.(map[string]any)
		for k := range d {
			if _, ok := g[k]; !ok && !optional[where+"."+k] {
				t.Errorf("%s: missing key %q", where, k)
			}
		}
		for k := range g {
			if _, ok := d[k]; !ok {
				t.Errorf("%s: extra key %q (doc keys %v)", where, k, keys(d))
			}
		}
		for k, dv := range d {
			if gv, ok := g[k]; ok {
				sameShape(t, where+"."+k, dv, gv, optional)
			}
		}
	case []any:
		g := got.([]any)
		if len(d) == 0 || len(g) == 0 {
			return
		}
		// Elements may differ in optional keys (listeners[].holder): compare each
		// got element against the doc element with the most keys.
		elem := d[0]
		for _, e := range d {
			if m, ok := e.(map[string]any); ok {
				if em, ok := elem.(map[string]any); ok && len(m) > len(em) {
					elem = e
				}
			}
		}
		for i, gv := range g {
			sameShape(t, fmt.Sprintf("%s[%d]", where, i), elem, gv, optional)
		}
	}
}

func TestRoutesMatchDocExamples(t *testing.T) {
	examples := docExamples(t)
	for _, route := range []string{"/api/status", "/api/stats", "/api/devices", "/api/groups", "/api/settings", "/api/rejected", "/api/storage/history", "/api/storage/estimate",
		"/api/search/schema", "/api/search/summary", "/api/saved-searches", "/api/tls", "/api/tls/failures",
		"/api/poll", "/api/poll/targets", "/api/poll/series"} {
		if _, ok := examples[route]; !ok {
			t.Fatalf("no example for %s in docs/api.md", route)
		}
	}
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	if len(examples) < 8 {
		t.Fatalf("found only %d examples in docs/api.md: %v", len(examples), keys(examples))
	}
	optional := map[string]bool{
		"/api/status.listeners[].holder": true, // omitted when the OS doesn't say
	}
	for route, doc := range examples {
		if route == "/api/search" {
			continue // its own test (TestSearchRoutes) checks the example
		}
		path := route
		if route == "/api/storage/estimate" {
			path += "?retention_bytes=21474836480"
		}
		if route == "/api/poll/series" {
			path += "?device=10.1.0.1&series=in_bps"
		}
		r := do(t, c, "GET", srv.url(path), "")
		if r.code != http.StatusOK {
			t.Errorf("%s: %d %s", route, r.code, r.body)
			continue
		}
		if ct := r.header.Get("Content-Type"); ct != "application/json; charset=utf-8" {
			t.Errorf("%s: Content-Type %q", route, ct)
		}
		var got any
		if err := json.Unmarshal(r.body, &got); err != nil {
			t.Fatalf("%s: %v", route, err)
		}
		if route == "/api/devices" {
			// The example shows the devices; the body pages them.
			page, _ := got.(map[string]any)
			if _, ok := page["total"].(float64); !ok || len(page) != 2 {
				t.Errorf("/api/devices: %s", r.body)
			}
			got = page["devices"]
		}
		// Normalise listener paths for the optional map.
		opt := map[string]bool{}
		for k, v := range optional {
			opt[k] = v
		}
		if route == "/api/status" {
			for i := range 4 {
				opt[fmt.Sprintf("/api/status.listeners[%d].holder", i)] = true
			}
		}
		if route == "/api/search/summary" {
			for i := range 4 {
				opt[fmt.Sprintf("/api/search/summary.histogram.buckets[%d].count", i)] = true // null: not counted yet
			}
		}
		sameShape(t, route, doc, got, opt)
	}
}

func TestStatusNormalized(t *testing.T) {
	b := newFakeBackend()
	est := time.FixedZone("EST", -5*3600)
	b.status.StartedAt = time.Date(2026, 11, 10, 15, 0, 0, 0, est)
	b.status.FirstMessageAt = nil
	b.status.HostIPs = nil
	b.status.Listeners = nil
	b.status.Banners = []Banner{
		{Kind: "low_disk", Level: "warn", Text: "w1"},
		{Kind: "x", Level: "info", Text: "i1"},
		{Kind: "listener_bind", Level: "error", Text: "e1", Action: "retry_listeners"},
		{Kind: "low_disk", Level: "warn", Text: "w2"},
		{Kind: "writes_paused", Level: "error", Text: "e2"},
	}
	srv := startServer(t, b, UIConfig{})
	r := do(t, httpClient(), "GET", srv.url("/api/status"), "")
	m := r.json(t)
	if m["started_at"] != "2026-11-10T20:00:00Z" {
		t.Errorf("started_at %v, want UTC", m["started_at"])
	}
	if v, ok := m["first_message_at"]; !ok || v != nil {
		t.Errorf("first_message_at %v (present %v), want null", v, ok)
	}
	for _, k := range []string{"host_ips", "listeners"} {
		if a, ok := m[k].([]any); !ok || len(a) != 0 {
			t.Errorf("%s = %v, want []", k, m[k])
		}
	}
	var order []string
	for _, bn := range m["banners"].([]any) {
		order = append(order, bn.(map[string]any)["text"].(string))
	}
	if want := []string{"e1", "e2", "w1", "w2", "i1"}; !slices.Equal(order, want) {
		t.Errorf("banner order %v, want %v", order, want)
	}
	first := m["banners"].([]any)[0].(map[string]any)
	if first["kind"] != "listener_bind" || first["action"] != "retry_listeners" {
		t.Errorf("banner fields %v", first)
	}
}

func TestStatsNulls(t *testing.T) {
	b := newFakeBackend()
	b.stats.Sparkline = nil
	srv := startServer(t, b, UIConfig{})
	m := do(t, httpClient(), "GET", srv.url("/api/stats"), "").json(t)
	if v, ok := m["kernel_dropped_24h"]; !ok || v != nil {
		t.Errorf("kernel_dropped_24h = %v, want null", v)
	}
	if a, ok := m["sparkline"].([]any); !ok || len(a) != 0 {
		t.Errorf("sparkline = %v, want []", m["sparkline"])
	}
	n := int64(42)
	b.mu.Lock()
	b.stats.KernelDropped24h = &n
	b.mu.Unlock()
	m = do(t, httpClient(), "GET", srv.url("/api/stats"), "").json(t)
	if m["kernel_dropped_24h"] != float64(42) {
		t.Errorf("kernel_dropped_24h = %v, want 42", m["kernel_dropped_24h"])
	}
}

func TestRejectedSortedAndCapped(t *testing.T) {
	b := newFakeBackend()
	b.rejected = nil
	for i := range 250 {
		b.rejected = append(b.rejected, RejectedSender{IP: fmt.Sprintf("198.51.100.%d", i), Count24h: int64(i % 50), LastSeen: ts("2026-11-10T00:00:00Z").Add(time.Duration(i) * time.Second),
			Reason: []string{"allowlist", "per_source"}[i%2]})
	}
	srv := startServer(t, b, UIConfig{})
	r := do(t, httpClient(), "GET", srv.url("/api/rejected"), "")
	var got []RejectedSender
	if err := json.Unmarshal(r.body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != MaxRejected {
		t.Fatalf("%d entries, want %d", len(got), MaxRejected)
	}
	for i := 1; i < len(got); i++ {
		a, c := got[i-1], got[i]
		if a.Count24h < c.Count24h || (a.Count24h == c.Count24h && a.LastSeen.Before(c.LastSeen)) {
			t.Fatalf("not sorted at %d: %+v then %+v", i, a, c)
		}
	}
	for _, g := range got {
		if g.Reason != "allowlist" && g.Reason != "per_source" {
			t.Fatalf("reason %q not passed through", g.Reason)
		}
	}
	if got[0].Count24h != 49 {
		t.Errorf("first count %d, want 49", got[0].Count24h)
	}
	// Empty list is [], not null.
	b.mu.Lock()
	b.rejected = nil
	b.mu.Unlock()
	if r := do(t, httpClient(), "GET", srv.url("/api/rejected"), ""); strings.TrimSpace(string(r.body)) != "[]" {
		t.Errorf("empty rejected = %s", r.body)
	}
}

func TestDevicesListIncludesHidden(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	var got DevicePage
	r := do(t, httpClient(), "GET", srv.url("/api/devices"), "")
	if err := json.Unmarshal(r.body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Total != 3 || len(got.Devices) != 3 || got.Devices[0].MsgsPerMin != 36720 || !got.Devices[2].Hidden {
		t.Errorf("devices %+v", got)
	}
}

func TestDevicesPaging(t *testing.T) {
	b := newFakeBackend()
	b.devices, b.order = map[string]Device{}, nil
	for i := 0; i < 2500; i++ {
		d := Device{ID: fmt.Sprintf("10.0.%d.%d", i/250, i%250), MsgsPerMin: int64(i % 97), Group: []string{"HQ", "", "lab"}[i%3],
			Hidden: i%10 == 0, Name: fmt.Sprintf("dev-%04d", 2500-i), LastHeard: ts("2026-11-10T00:00:00Z").Add(time.Duration(i) * time.Second)}
		d.IP = d.ID
		b.devices[d.ID] = d
		b.order = append(b.order, d.ID)
	}
	srv := startServer(t, b, UIConfig{})
	c := httpClient()
	get := func(q string) DevicePage {
		t.Helper()
		var p DevicePage
		r := do(t, c, "GET", srv.url("/api/devices?"+q), "")
		if r.code != 200 {
			t.Fatalf("%s: %d %s", q, r.code, r.body)
		}
		json.Unmarshal(r.body, &p)
		return p
	}
	if p := get(""); p.Total != 2500 || len(p.Devices) != 200 || p.Devices[0].MsgsPerMin != 96 {
		t.Errorf("default: total %d, %d devices, first rate %d", p.Total, len(p.Devices), p.Devices[0].MsgsPerMin)
	}
	// The dashboard strip.
	p := get("sort=rate&limit=30")
	for i := 1; i < len(p.Devices); i++ {
		if p.Devices[i].MsgsPerMin > p.Devices[i-1].MsgsPerMin {
			t.Fatal("not busiest first")
		}
	}
	if len(p.Devices) != 30 {
		t.Errorf("limit 30: %d", len(p.Devices))
	}
	// Pages tile the list with no gaps or repeats.
	seen := map[string]bool{}
	for off := 0; ; off += 333 {
		p := get(fmt.Sprintf("sort=name&limit=333&offset=%d", off))
		for _, d := range p.Devices {
			if seen[d.ID] {
				t.Fatalf("repeat %s", d.ID)
			}
			seen[d.ID] = true
		}
		if len(p.Devices) < 333 {
			break
		}
	}
	if len(seen) != 2500 {
		t.Errorf("paged %d", len(seen))
	}
	if p := get("sort=name&limit=1"); p.Devices[0].Name != "dev-0001" {
		t.Errorf("by name: %s", p.Devices[0].Name)
	}
	if p := get("sort=last_heard&limit=1"); p.Devices[0].ID != "10.0.9.249" {
		t.Errorf("newest heard: %s", p.Devices[0].ID)
	}
	if p := get("limit=5000"); len(p.Devices) != 1000 {
		t.Errorf("limit clamp: %d", len(p.Devices))
	}
	if p := get("offset=9999"); len(p.Devices) != 0 || p.Total != 2500 {
		t.Errorf("past the end: %+v", p.Total)
	}
	if p := get("hidden=only"); p.Total != 250 {
		t.Errorf("hidden=only %d", p.Total)
	}
	if p := get("hidden=exclude&group=HQ"); p.Total != 750 {
		t.Errorf("exclude+HQ %d", p.Total)
	}
	if p := get("ungrouped=true"); p.Total != 833 {
		t.Errorf("ungrouped %d", p.Total)
	}
	if p := get("q=DEV-000"); p.Total != 9 {
		t.Errorf("q by name %d", p.Total)
	}
	if p := get("q=10.0.3.1"); p.Total != 111 { // 10.0.3.1, .10-.19, .100-.199
		t.Errorf("q by ip %d", p.Total)
	}
	for _, bad := range []string{"limit=0", "limit=x", "offset=-1", "sort=size", "hidden=yes", "group=HQ&ungrouped=true", "ungrouped=maybe"} {
		wantError(t, do(t, c, "GET", srv.url("/api/devices?"+bad), ""), 400, "")
	}
}

func TestPatchDevice(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	u := srv.url("/api/devices/10.1.0.1")

	cases := []struct {
		body      string
		wantName  string
		wantGroup string
		wantHide  bool
	}{
		{`{"name": "fw-a"}`, "fw-a", "HQ", false},
		{`{"group": "Branch"}`, "fw-a", "Branch", false},
		{`{"hidden": true}`, "fw-a", "Branch", true},
		{`{}`, "fw-a", "Branch", true},
		{`{"name": "", "group": "", "hidden": false}`, "", "", false},
		{`{"name": "fw-b", "hidden": null}`, "fw-b", "", false},
	}
	for _, tc := range cases {
		r := do(t, c, "PATCH", u, tc.body)
		if r.code != 200 {
			t.Fatalf("%s: %d %s", tc.body, r.code, r.body)
		}
		var d Device
		if err := json.Unmarshal(r.body, &d); err != nil {
			t.Fatal(err)
		}
		if d.ID != "10.1.0.1" || d.Name != tc.wantName || d.Group != tc.wantGroup || d.Hidden != tc.wantHide {
			t.Errorf("%s: got %+v", tc.body, d)
		}
	}
	// The backend got only the fields that were sent.
	srv.b.mu.Lock()
	p := srv.b.patches[0]
	srv.b.mu.Unlock()
	if p.Name == nil || p.Group != nil || p.Hidden != nil {
		t.Errorf("first patch passed %+v, want only name", p)
	}

	// IPv6 device ids work in the path.
	if r := do(t, c, "PATCH", srv.url("/api/devices/fd00_1__5"), `{"hidden": false}`); r.code != 200 {
		t.Errorf("ipv6 id: %d %s", r.code, r.body)
	}

	wantError(t, do(t, c, "PATCH", srv.url("/api/devices/192.0.2.99"), `{"name": "x"}`), 404, "No device")
	wantError(t, do(t, c, "PATCH", u, `{"nmae": "x"}`), 400, "unknown field")
	wantError(t, do(t, c, "PATCH", u, `{"name": `), 400, "Invalid JSON")
	wantError(t, do(t, c, "PATCH", u, `{"name": "a"} {"x":1}`), 400, "")
	wantError(t, do(t, c, "PATCH", u, `{"name": 5}`), 400, "")
	wantError(t, do(t, c, "PATCH", u, `{"name": "bad\u0007name"}`), 400, "control")
	wantError(t, do(t, c, "PATCH", u, `{"group": "`+strings.Repeat("g", maxLabel+1)+`"}`), 400, "At most")
	wantError(t, do(t, c, "PATCH", u, ""), 400, "empty")
	wantError(t, do(t, c, "PATCH", u, `{"name":"x"}`, "Content-Type: text/plain"), 415, "")
	wantError(t, do(t, c, "PATCH", u, `{"name":"`+strings.Repeat("x", maxBody)+`"}`), 413, "")
	wantError(t, do(t, c, "GET", u, ""), 405, "")
}

func TestSettings(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "GET", srv.url("/api/settings"), "")
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	var s Settings
	if err := json.Unmarshal(r.body, &s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(r.body), `"allowlist":[]`) {
		t.Errorf("allowlist should be [], got %s", r.body)
	}

	s.Quiet.QuietAfterSeconds = 600
	s.Listeners.Allowlist = []string{"10.0.0.0/8"}
	body, _ := json.Marshal(s)
	r = do(t, c, "PUT", srv.url("/api/settings"), string(body))
	if r.code != 200 {
		t.Fatalf("PUT: %d %s", r.code, r.body)
	}
	var saved Settings
	_ = json.Unmarshal(r.body, &saved)
	if saved.Quiet.QuietAfterSeconds != 600 || saved.Listeners.Allowlist[0] != "10.0.0.0/8" {
		t.Errorf("saved %+v", saved)
	}

	// Validation errors pass through unchanged.
	fields := map[string]string{"listeners.udp.port": "Must be 1–65535.", "listeners.allowlist[2]": "Not an IP or CIDR.", "storage.data_dir": "Read-only in v1."}
	srv.b.mu.Lock()
	srv.b.saveErr = &ValidationError{Fields: fields}
	srv.b.mu.Unlock()
	r = do(t, c, "PUT", srv.url("/api/settings"), string(body))
	if r.code != 400 {
		t.Fatalf("invalid PUT: %d %s", r.code, r.body)
	}
	var eb struct {
		Error  string            `json:"error"`
		Errors map[string]string `json:"errors"`
	}
	if err := json.Unmarshal(r.body, &eb); err != nil {
		t.Fatal(err)
	}
	if eb.Error == "" || len(eb.Errors) != len(fields) {
		t.Fatalf("400 body %s", r.body)
	}
	for k, v := range fields {
		if eb.Errors[k] != v {
			t.Errorf("errors[%q] = %q, want %q", k, eb.Errors[k], v)
		}
	}

	// Other backend errors are a 500 with {"error"}.
	srv.b.mu.Lock()
	srv.b.saveErr = errors.New("disk full")
	srv.b.mu.Unlock()
	wantError(t, do(t, c, "PUT", srv.url("/api/settings"), string(body)), 500, "disk full")

	// LAN mode without a password is refused before the backend sees it.
	srv.b.mu.Lock()
	srv.b.saveErr = nil
	srv.b.mu.Unlock()
	s.UI.LANMode = true
	body, _ = json.Marshal(s)
	r = do(t, c, "PUT", srv.url("/api/settings"), string(body))
	if r.code != 400 || !strings.Contains(string(r.body), `"ui.lan_mode"`) {
		t.Fatalf("LAN without password: %d %s", r.code, r.body)
	}
	srv.b.mu.Lock()
	lan := srv.b.settings.UI.LANMode
	srv.b.mu.Unlock()
	if lan {
		t.Error("LAN mode was saved without a password")
	}
	wantError(t, do(t, c, "PUT", srv.url("/api/settings"), `{"bogus": 1}`), 400, "unknown field")
	wantError(t, do(t, c, "POST", srv.url("/api/settings"), string(body)), 405, "")
}

func TestStorageHistoryAndRetry(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "GET", srv.url("/api/storage/history"), "")
	if r.code != 200 || !strings.Contains(string(r.body), `"reason":"age"`) {
		t.Fatalf("history %d %s", r.code, r.body)
	}
	r = do(t, c, "POST", srv.url("/api/listeners/retry"), "")
	if r.code != 204 || len(r.body) != 0 {
		t.Fatalf("retry %d %q", r.code, r.body)
	}
	srv.b.mu.Lock()
	n := srv.b.retries
	srv.b.mu.Unlock()
	if n != 1 {
		t.Errorf("retries = %d", n)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/listeners/retry"), ""), 405, "")
}

func TestBackendErrorIs500(t *testing.T) {
	b := newFakeBackend()
	b.statusErr = errors.New("index closed")
	srv := startServer(t, b, UIConfig{})
	wantError(t, do(t, httpClient(), "GET", srv.url("/api/status"), ""), 500, "index closed")
}

func TestUnknownRoutesAndMethods(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	wantError(t, do(t, c, "GET", srv.url("/api/nope"), ""), 404, "No such API route")
	wantError(t, do(t, c, "GET", srv.url("/api"), ""), 404, "")
	r := do(t, c, "DELETE", srv.url("/api/status"), "")
	wantError(t, r, 405, "")
	if r.header.Get("Allow") != "GET" {
		t.Errorf("Allow %q", r.header.Get("Allow"))
	}
	r = do(t, c, "PUT", srv.url("/api/exports"), "")
	if r.header.Get("Allow") != "GET, POST" {
		t.Errorf("Allow %q", r.header.Get("Allow"))
	}
	wantError(t, do(t, c, "POST", srv.url("/index.html"), ""), 405, "")
}

func TestHealthz(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	r := do(t, httpClient(), "GET", srv.url("/healthz"), "")
	if r.code != 200 || strings.TrimSpace(string(r.body)) != `{"ok":true}` {
		t.Fatalf("%d %s", r.code, r.body)
	}
}

func TestLivePassthrough(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	req, _ := http.NewRequest("GET", srv.url("/api/live?devices=10.1.0.1,10.1.0.2&group=HQ&min_severity=4&q=text"), nil)
	req.Header.Set("Accept", "text/event-stream")
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("%d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	if res.Header.Get("Content-Security-Policy") == "" {
		t.Error("no CSP on the stream")
	}
	br := bufio.NewReader(res.Body)
	ev, _ := br.ReadString('\n')
	data, _ := br.ReadString('\n')
	if ev != "event: message\n" || !strings.HasPrefix(data, "data: ") {
		t.Fatalf("stream %q %q", ev, data)
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(data, "data: ")), &msg); err != nil {
		t.Fatal(err)
	}
	if msg["raw"] != "<134>query=devices=10.1.0.1,10.1.0.2&group=HQ&min_severity=4&q=text" {
		t.Errorf("query not passed through: %v", msg["raw"])
	}

	// A restart (mode or port change) ends the open stream.
	old := srv.State()
	srv.Reconfigure(UIConfig{})
	done := make(chan error, 1)
	go func() {
		_, err := br.ReadString('\n')
		for err == nil {
			_, err = br.ReadString('\n')
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stream still open after a restart")
	}
	srv.waitRestart(t, false, old)
}

func TestGroups(t *testing.T) {
	b := newFakeBackend()
	b.devices, b.order = map[string]Device{}, nil
	for _, d := range []Device{{ID: "a", Group: "lab"}, {ID: "b", Group: "HQ"}, {ID: "c", Group: "HQ"}, {ID: "d", Group: "HQ", Hidden: true},
		{ID: "e"}, {ID: "f", Group: "dmz", Hidden: true}} {
		b.devices[d.ID] = d
		b.order = append(b.order, d.ID)
	}
	srv := startServer(t, b, UIConfig{})
	r := do(t, httpClient(), "GET", srv.url("/api/groups"), "")
	if r.code != 200 || strings.TrimSpace(string(r.body)) != `[{"name":"HQ","devices":2},{"name":"lab","devices":1}]` {
		t.Errorf("%d %s", r.code, r.body)
	}
	b.devices, b.order = map[string]Device{}, nil
	if r := do(t, httpClient(), "GET", srv.url("/api/groups"), ""); strings.TrimSpace(string(r.body)) != "[]" {
		t.Errorf("no groups: %s", r.body)
	}
}

func TestPatchBlockedAndFilter(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "PATCH", srv.url("/api/devices/10.1.0.2"), `{"blocked": true}`)
	if r.code != 200 || !strings.Contains(string(r.body), `"blocked":true`) || !strings.Contains(string(r.body), `"status":"blocked"`) {
		t.Fatalf("%d %s", r.code, r.body)
	}
	if p := srv.b.patches[len(srv.b.patches)-1]; p.Blocked == nil || !*p.Blocked || p.Name != nil {
		t.Errorf("patch %+v", p)
	}
	var page DevicePage
	json.Unmarshal(do(t, c, "GET", srv.url("/api/devices?blocked=only"), "").body, &page)
	if page.Total != 1 || page.Devices[0].ID != "10.1.0.2" {
		t.Errorf("only %+v", page)
	}
	json.Unmarshal(do(t, c, "GET", srv.url("/api/devices?blocked=exclude"), "").body, &page)
	if page.Total != 2 {
		t.Errorf("exclude %d", page.Total)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/devices?blocked=sure"), ""), 400, "blocked")
	wantError(t, do(t, c, "PATCH", srv.url("/api/devices/10.1.0.2"), `{"blocked": "yes"}`), 400, "")
}

func TestStorageEstimate(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	for _, q := range []string{"", "?retention_bytes=", "?retention_bytes=abc", "?retention_bytes=1.5", "?retention_bytes=1073741823", "?retention_bytes=-1"} {
		if r := do(t, c, "GET", srv.url("/api/storage/estimate"+q), ""); r.code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", q, r.code, r.body)
		}
	}
	m := do(t, c, "GET", srv.url("/api/storage/estimate?retention_bytes=4722786304"), "").json(t)
	if d, _ := m["estimated_days"].(float64); d < 1.99 || d > 2.01 || m["bytes_per_day"] != float64(2361393152) || m["compression_ratio"] != 9.2 {
		t.Errorf("%v", m)
	}
	if r := do(t, c, "POST", srv.url("/api/storage/estimate?retention_bytes=4722786304"), ""); r.code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", r.code)
	}
}
