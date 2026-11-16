package api

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseSearch(t *testing.T) {
	r, err := ParseSearch(url.Values{"q": {"Link"}, "regex": {"true"}, "case": {"1"}, "devices": {"10.1.0.1, 10.1.0.2,,"},
		"group": {"HQ"}, "from": {"2026-11-10T00:00:00Z"}, "to": {"2026-11-10T01:00:00.5+01:00"}, "order": {"asc"},
		"limit": {"9000"}, "cursor": {"c"}, "severities": {"3,unknown,3"}, "min_severity": {"7"},
		"app": {" sshd,%FW-6-*,, "}, "host": {"edge-fw-01"}, "exclude": {" keepalive "}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.App, []string{"sshd", "%FW-6-*"}) || !slices.Equal(r.Host, []string{"edge-fw-01"}) || r.Exclude != " keepalive " {
		t.Errorf("app/host/exclude %+v", r)
	}
	if !r.Regex || !r.Case || !r.Asc || r.Limit != 5000 || r.Cursor != "c" || len(r.Devices) != 2 || r.Group != "HQ" ||
		!r.To.Equal(time.Date(2026, 11, 10, 0, 0, 0, 5e8, time.UTC)) || !slices.Equal(r.Severities.Values, []int{3, Unknown}) {
		t.Errorf("%+v", r)
	}
	r, _ = ParseSearch(url.Values{"min_severity": {"2"}})
	if !slices.Equal(r.Severities.Values, []int{0, 1, 2, Unknown}) || r.Limit != 500 || r.Asc || r.App != nil || r.Host != nil || r.Exclude != "" {
		t.Errorf("min_severity: %+v", r)
	}
	r, _ = ParseSearch(url.Values{"severities": {"none"}, "min_severity": {"5"}})
	if !r.Severities.None {
		t.Errorf("none: %+v", r.Severities)
	}
	r, _ = ParseSearch(url.Values{"severities": {""}})
	if !r.Severities.All() {
		t.Errorf("empty: %+v", r.Severities)
	}
	for _, bad := range []url.Values{
		{"severities": {"8"}}, {"severities": {"none,3"}}, {"severities": {"warn"}}, {"min_severity": {"9"}},
		{"severities": {"3"}, "min_severity": {"x"}}, {"regex": {"yes"}}, {"case": {"2"}}, {"ungrouped": {"maybe"}},
		{"group": {"HQ"}, "ungrouped": {"true"}}, {"from": {"yesterday"}}, {"to": {"2026-11-10"}},
		{"from": {"2026-11-10T01:00:00Z"}, "to": {"2026-11-10T01:00:00Z"}}, {"order": {"newest"}},
		{"limit": {"0"}}, {"limit": {"-3"}}, {"limit": {"lots"}},
	} {
		if _, err := ParseSearch(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestSeveritiesJSON(t *testing.T) {
	for in, want := range map[string]string{`[0, 1, "unknown"]`: `[0,1,"unknown"]`, `[]`: `[]`, `null`: `[]`, `["none"]`: `["none"]`, `[7, 7]`: `[7]`} {
		var s Severities
		if err := json.Unmarshal([]byte(in), &s); err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got, _ := json.Marshal(s); string(got) != want {
			t.Errorf("%s → %s, want %s", in, got, want)
		}
	}
	for _, bad := range []string{`[8]`, `["none", 1]`, `"3"`, `[{"a":1}]`, `[-1]`, `["warn"]`} {
		var s Severities
		if err := json.Unmarshal([]byte(bad), &s); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

// docBlock returns the first ```json block after a heading in docs/api.md.
func docBlock(t *testing.T, heading string) any {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(doc, "\n## "+heading+"\n")
	if i < 0 {
		t.Fatalf("no %q section", heading)
	}
	rest := doc[i:]
	s := strings.Index(rest, "```json\n")
	e := strings.Index(rest[s+8:], "\n```")
	var v any
	if err := json.Unmarshal([]byte(stripComments(rest[s+8:s+8+e])), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSearchRoutes(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "GET", srv.url("/api/search?q=conn&severities=3,unknown&order=asc&limit=10&cursor=abc&app=sshd,%25FW-*&host=a&exclude=x"), "")
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	var got any
	json.Unmarshal(r.body, &got)
	sameShape(t, "/api/search", docBlock(t, "Search"), got, map[string]bool{"/api/search.results[1].severity": true}) // null: unknown
	body := string(r.body)
	for _, want := range []string{`"received":"2026-11-10T20:41:07.112Z"`, `"received":"2026-11-10T20:41:06.000Z"`,
		`"severity":null`, `"severity":6`, `�`, `"next_cursor":"next"`, `"partial":false`,
		`"app":"%FW-6-1","host":"edge-fw-01"`, `"app":"","host":""`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s in %s", want, body)
		}
	}
	req := srv.b.searches[0]
	if req.Q != "conn" || !req.Asc || req.Limit != 10 || req.Cursor != "abc" || !slices.Equal(req.Severities.Values, []int{3, Unknown}) ||
		!slices.Equal(req.App, []string{"sshd", "%FW-*"}) || !slices.Equal(req.Host, []string{"a"}) || req.Exclude != "x" {
		t.Errorf("request %+v", req)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/search?severities=banana"), ""), 400, "banana")
	srv.b.mu.Lock()
	srv.b.searchErr = &RequestError{Msg: "error parsing regexp: missing closing ): `(`"}
	srv.b.mu.Unlock()
	wantError(t, do(t, c, "GET", srv.url("/api/search?q=(&regex=true"), ""), 400, "error parsing regexp")

	// Context.
	r = do(t, c, "GET", srv.url("/api/context?ref=r1&before=7&after=900"), "")
	if r.code != 200 || !strings.Contains(string(r.body), `"raw":"r1 7 500"`) || !strings.Contains(string(r.body), `"at_start":true,"at_end":false`) {
		t.Fatalf("%d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/context"), ""), 400, "ref")
	wantError(t, do(t, c, "GET", srv.url("/api/context?ref=x&before=-1"), ""), 400, "before")
	srv.b.mu.Lock()
	srv.b.contextErr = ErrNotFound
	srv.b.mu.Unlock()
	wantError(t, do(t, c, "GET", srv.url("/api/context?ref=gone"), ""), 404, "gone")
}

func TestExportRoutes(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	body := `{"devices": ["10.1.0.1"], "group": "", "ungrouped": false, "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z",
		"severities": [0, 1, "unknown"], "q": "link", "regex": false, "case": true, "app": ["sshd", " ", "%FW-6-*"], "host": ["web-01"],
		"exclude": "keepalive"}`
	r := do(t, c, "POST", srv.url("/api/exports"), body)
	if r.code != 202 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	id := r.json(t)["id"].(string)
	req := srv.b.exportReqs[0]
	if req.Q != "link" || !req.Case || !slices.Equal(req.Severities.Values, []int{0, 1, Unknown}) || !req.From.Equal(ts("2026-11-10T00:00:00Z")) ||
		!slices.Equal(req.App, []string{"sshd", "%FW-6-*"}) || !slices.Equal(req.Host, []string{"web-01"}) || req.Exclude != "keepalive" {
		t.Errorf("request %+v", req)
	}
	r = do(t, c, "POST", srv.url("/api/exports/estimate"), body)
	if r.code != 200 || strings.TrimSpace(string(r.body)) != `{"lines":123456,"bytes":45678901,"files":12}` {
		t.Errorf("estimate %d %s", r.code, r.body)
	}
	r = do(t, c, "GET", srv.url("/api/exports"), "")
	var list []map[string]any
	if err := json.Unmarshal(r.body, &list); err != nil || len(list) != 1 {
		t.Fatalf("%s", r.body)
	}
	for _, k := range []string{"id", "created", "devices", "from", "to", "state", "progress", "lines", "size_bytes", "error", "ready_at", "expires_at", "filters"} {
		if _, ok := list[0][k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	if len(list[0]) != 13 {
		t.Errorf("keys %v", list[0])
	}
	f, _ := json.Marshal(list[0]["filters"])
	if string(f) != `{"app":["sshd","%FW-6-*"],"case":true,"exclude":"keepalive","exclude_app":[],"exclude_devices":[],"exclude_host":[],"facilities":[],"group":"","host":["web-01"],"kind":"export","q":"link","regex":false,"severities":[0,1,"unknown"],"syntax":"text","type":"syslog","types":["syslog"],"ungrouped":false}` {
		t.Errorf("filters %s", f)
	}
	if list[0]["ready_at"] != nil {
		t.Errorf("ready_at %v", list[0]["ready_at"])
	}
	r = do(t, c, "GET", srv.url("/api/exports/"+id), "")
	if r.code != 200 || r.json(t)["state"] != "queued" {
		t.Errorf("%d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "GET", srv.url("/api/exports/"+id+"/download"), ""), 409, "")

	// Ready: the zip with its name.
	srv.b.mu.Lock()
	e := srv.b.exports[id]
	e.State = "ready"
	srv.b.exports[id] = e
	srv.b.zip = []byte("PK\x03\x04 pretend zip")
	srv.b.mu.Unlock()
	r = do(t, c, "GET", srv.url("/api/exports/"+id+"/download"), "")
	if r.code != 200 || string(r.body) != "PK\x03\x04 pretend zip" || r.header.Get("Content-Type") != "application/zip" ||
		r.header.Get("Content-Disposition") != `attachment; filename="woodshed-20261110T000000Z-20261110T060000Z.zip"` {
		t.Errorf("download %d %q %v", r.code, r.body, r.header)
	}
	r = do(t, c, "GET", srv.url("/api/exports/"+id+"/download"), "", "Range: bytes=0-1")
	if r.code != 206 || string(r.body) != "PK" {
		t.Errorf("range %d %q", r.code, r.body)
	}
	srv.b.mu.Lock()
	e.State = "expired"
	srv.b.exports[id] = e
	srv.b.mu.Unlock()
	wantError(t, do(t, c, "GET", srv.url("/api/exports/"+id+"/download"), ""), 404, "expired")

	r = do(t, c, "DELETE", srv.url("/api/exports/"+id), "")
	if r.code != 204 {
		t.Errorf("delete %d %s", r.code, r.body)
	}
	wantError(t, do(t, c, "DELETE", srv.url("/api/exports/"+id), ""), 404, "")
	wantError(t, do(t, c, "GET", srv.url("/api/exports/"+id), ""), 404, "")
	wantError(t, do(t, c, "GET", srv.url("/api/exports/..%2f..%2fetc/download"), ""), 404, "")
	wantError(t, do(t, c, "GET", srv.url("/api/exports/estimate"), ""), 405, "")

	for _, bad := range []struct{ body, msg string }{
		{`{"devices": ["10.1.0.1"], "to": "2026-11-10T06:00:00Z"}`, `"from" is required`},
		{`{"devices": ["10.1.0.1"], "from": "x", "to": "2026-11-10T06:00:00Z"}`, "RFC 3339"},
		{`{"devices": ["10.1.0.1"], "from": "2026-11-10T07:00:00Z", "to": "2026-11-10T06:00:00Z"}`, "before"},
		{`{"from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"}`, "at least one device"},
		{`{"devices": [" "], "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"}`, "at least one device"},
		{`{"group": "HQ", "ungrouped": true, "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"}`, "alternatives"},
		{`{"all_devices": true, "devices": ["a"], "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"}`, "all_devices"},
		{`{"all_devices": false, "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"}`, "at least one device"},
		{`{"devices": ["a"], "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z", "severities": [9]}`, "severit"},
		{`{"devices": ["a"], "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z", "path": "/etc"}`, "unknown field"},
		{`{"devices": ["a"], "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z", "app": "sshd"}`, "app"},
	} {
		for _, route := range []string{"/api/exports", "/api/exports/estimate"} {
			wantError(t, do(t, c, "POST", srv.url(route), bad.body), 400, bad.msg)
		}
	}
	if r := do(t, c, "POST", srv.url("/api/exports/estimate"), `{"all_devices": true, "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"}`); r.code != 200 {
		t.Errorf("estimate all_devices: %d %s", r.code, r.body)
	}
	if last := srv.b.exportReqs[len(srv.b.exportReqs)-1]; !last.AllDevices || len(last.Devices) != 0 {
		t.Errorf("all_devices not passed: %+v", last)
	}
	srv.b.mu.Lock()
	srv.b.exportErr = &RequestError{Msg: "No device matches the selection."}
	srv.b.mu.Unlock()
	wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"group": "nope", "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"}`), 400, "No device")
}

func TestDocListsExportFields(t *testing.T) {
	raw, _ := os.ReadFile("../../docs/api.md")
	m := regexp.MustCompile("`GET /api/exports` → `\\[\\{([^`]*)\\}\\]`").FindStringSubmatch(strings.ReplaceAll(string(raw), "\n", " "))
	if m == nil {
		t.Fatal("no export list in docs/api.md")
	}
	for _, k := range []string{"id", "created", "devices", "from", "to", "state", "progress", "lines", "size_bytes", "error", "ready_at", "expires_at", "filters"} {
		if !strings.Contains(m[1], `"`+k+`"`) {
			t.Errorf("docs/api.md doesn't list %s", k)
		}
	}
}

// TestShutdownDoesNotWaitForSilentConnections: a client that connects and
// never sends a request (a browser's speculative preconnect) used to hold
// shutdown for ~5 s, until net/http treated the new connection as idle.
func TestShutdownDoesNotWaitForSilentConnections(t *testing.T) {
	for _, lan := range []bool{false, true} {
		var srv *testServer
		if lan {
			srv = lanServer(t, "correct horse battery")
		} else {
			srv = startServer(t, nil, UIConfig{})
		}
		addr := srv.State().Addr
		var conns []net.Conn
		for i := 0; i < 3; i++ {
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			conns = append(conns, c)
		}
		// And one idle keep-alive connection after a request.
		cl := httpClient()
		if lan {
			cl = tlsClient(t, srv.dataDir)
		}
		do(t, cl, "GET", srv.url("/healthz"), "")
		time.Sleep(50 * time.Millisecond)
		t0 := time.Now()
		srv.stop()
		// Under 3 s: well short of net/http's 5 s grace for new connections, which
		// is what this guards; 1 s was within one Shutdown idle-poll step (~1 s) of
		// a delayed sweep on a busy runner.
		if d := time.Since(t0); d > 3*time.Second {
			t.Errorf("lan=%v: shutdown took %v with silent connections open", lan, d)
		}
		// The silent connections were closed by the server.
		for _, c := range conns {
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			var b [1]byte
			if _, err := c.Read(b[:]); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("lan=%v: a silent connection is still open (%v)", lan, err)
			}
		}
	}
}

// A silent connection made just before shutdown (it may be accepted after the
// first sweep of quiet connections) doesn't hold shutdown for net/http's 5 s
// either. It raced on CI: "stopping the UI server" took 5.001 s.
func TestShutdownRightAfterSilentConnect(t *testing.T) {
	for i := 0; i < 20; i++ {
		srv := startServer(t, nil, UIConfig{})
		c, err := net.Dial("tcp", srv.State().Addr)
		if err != nil {
			t.Fatal(err)
		}
		t0 := time.Now()
		srv.stop()
		c.Close()
		if d := time.Since(t0); d > 3*time.Second { // the failure was 5 s (net/http's grace); see above for 3 s
			t.Fatalf("round %d: shutdown took %v with a just-made silent connection", i, d)
		}
	}
}
