package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/setuphelper"
)

func TestSetupFamilies(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	r := do(t, httpClient(), "GET", srv.url("/api/setup/families"), "")
	if r.code != http.StatusOK {
		t.Fatalf("%d %s", r.code, r.body)
	}
	var fs []setuphelper.Family
	if err := json.Unmarshal(r.body, &fs); err != nil {
		t.Fatal(err)
	}
	if len(fs) != 6 || fs[0].ID != "line-cli" || fs[2].ID != "rsyslog" || fs[2].Verification != setuphelper.Tested {
		t.Errorf("families %+v", fs)
	}
	if r := do(t, httpClient(), "POST", srv.url("/api/setup/families"), "{}"); r.code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", r.code)
	}
}

func TestSetupSnippet(t *testing.T) {
	b := newFakeBackend()
	// A stored community and a v3 user's passphrase must never reach a snippet.
	b.settings.Listeners.SNMP = &SNMPListenerSettings{Enabled: true, Addr: "0.0.0.0", Port: 1162, Communities: []string{"stored-community-value"}}
	b.settings.UI.ExtraHostnames = []string{"logs.example.net"}
	b.settings.Listeners.TLS = TLSListenerSettings{Addr: "0.0.0.0", Port: 6514}
	srv := startServer(t, b, UIConfig{})
	c := httpClient()
	post := func(body string) (int, map[string]any) {
		r := do(t, c, "POST", srv.url("/api/setup/snippet"), body)
		var m map[string]any
		json.Unmarshal(r.body, &m)
		if strings.Contains(string(r.body), "stored-community-value") {
			t.Errorf("a stored secret in %s", r.body)
		}
		return r.code, m
	}

	// Filled from the live settings: the trap port, the host's first address,
	// the TLS certificate's names and the UI's extra host names.
	code, m := post(`{"family": "net-snmp", "what": "trap", "transport": "v2c"}`)
	if code != 200 || !strings.Contains(m["text"].(string), "trap2sink udp:10.1.0.50:1162 <COMMUNITY>") || m["verification"] != "tested" {
		t.Fatalf("%d %v", code, m)
	}
	addrs, _ := json.Marshal(m["addresses"])
	if string(addrs) != `["10.1.0.50","fd00::50","logs-01","logs.example.net"]` {
		t.Errorf("addresses %s", addrs)
	}
	code, m = post(`{"family": "rsyslog", "what": "syslog", "transport": "tls", "address": "logs-01"}`)
	if code != 200 || !strings.Contains(m["text"].(string), `StreamDriverPermittedPeers="logs-01"`) || !strings.Contains(m["text"].(string), `port="6514"`) {
		t.Errorf("%d %v", code, m)
	}
	// The contract's keys, and a placeholder list.
	for _, k := range []string{"text", "notes", "placeholders", "verification", "parts", "does", "check", "reference", "addresses"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %q in %v", k, m)
		}
	}
	// TLS listener off in the settings: a note says so first.
	code, m = post(`{"family": "line-cli", "what": "syslog", "transport": "tls"}`)
	notes, _ := json.Marshal(m["notes"])
	if code != 200 || !strings.Contains(string(notes), "TLS syslog listener is off") || !strings.Contains(string(notes), setuphelper.ReferenceOnlyNote) {
		t.Errorf("%d notes %s", code, notes)
	}

	// Errors are 400 with the field.
	for _, c := range []struct{ body, field string }{
		{`{"family": "vendor-x", "what": "syslog"}`, "family"},
		{`{"family": "rsyslog", "what": "syslog", "address": "a;b"}`, "address"},
		{`{"family": "rsyslog", "what": "syslog", "severity": "loud"}`, "severity"},
	} {
		code, m := post(c.body)
		errs, _ := m["errors"].(map[string]any)
		if code != 400 || errs[c.field] == nil || m["error"] == "" {
			t.Errorf("%s: %d %v", c.body, code, m)
		}
	}
	if code, _ := post(`{"family": "rsyslog", "what": "syslog", "community": "x"}`); code != 400 {
		t.Errorf("an unknown field (a secret) was accepted: %d", code)
	}

	// GET with query parameters gives the same snippet; type= is what=.
	q := url.Values{"family": {"net-snmp"}, "type": {"poll"}, "transport": {"v3"}, "v3_user": {"monitor"}, "agent_port": {"1161"}}
	r := do(t, c, "GET", srv.url("/api/setup/snippet?"+q.Encode()), "")
	var g map[string]any
	json.Unmarshal(r.body, &g)
	if r.code != 200 || !strings.Contains(g["text"].(string), "agentAddress udp:1161,udp6:1161") || !strings.Contains(g["text"].(string), "rouser monitor priv") {
		t.Errorf("GET: %d %s", r.code, r.body)
	}
	if r := do(t, c, "GET", srv.url("/api/setup/snippet?family=net-snmp&what=poll&agent_port=x"), ""); r.code != 400 {
		t.Errorf("bad agent_port: %d", r.code)
	}
	if r := do(t, c, "PUT", srv.url("/api/setup/snippet"), "{}"); r.code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", r.code)
	}
}
