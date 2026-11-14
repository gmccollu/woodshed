package server

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

// The UI's exact request bodies against a real server (a 1.2 lab bug: the
// SNMP-user form sent a body the mock accepted and the server refused). The
// bodies come from web/src/lib/fixtures/ui-requests.json, which the web tests
// regenerate from the forms' own body builders and fail on any drift; the mock
// replays the same file. Every step must get a 2xx here, and the resources the
// 1.3 forms edit round-trip GET -> PUT.

type uiStep struct {
	Name     string          `json:"name"`
	Method   string          `json:"method"`
	Path     string          `json:"path"`
	Body     json.RawMessage `json:"body"`
	MergeGet string          `json:"merge_get"`
	IfMatch  bool            `json:"if_match"`
	EtagGet  string          `json:"etag_get"`
	Capture  string          `json:"capture"`
}

// deepMerge merges patch into base as the UI's settings form does: objects
// merge, arrays and scalars replace.
func deepMerge(base, patch any) any {
	bm, ok1 := base.(map[string]any)
	pm, ok2 := patch.(map[string]any)
	if !ok1 || !ok2 {
		return patch
	}
	for k, v := range pm {
		bm[k] = deepMerge(bm[k], v)
	}
	return bm
}

func TestUIRequestBodiesAgainstServer(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "fixtures", "ui-requests.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Steps []uiStep `json:"steps"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	if len(fx.Steps) < 8 {
		t.Fatalf("only %d steps", len(fx.Steps))
	}
	// The agents the targets point at, with the fixture's test credentials.
	u := snmp.User{Name: "monitor", Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128, AuthPass: []byte("fixture-auth-pass"),
		PrivPass: []byte("fixture-priv-pass"), Level: snmp.AuthPriv}
	a1, err := agenttest.Start(agenttest.Options{Community: "fixture-community", Interfaces: pollIfs()})
	if err != nil {
		t.Fatal(err)
	}
	defer a1.Close()
	a2, err := agenttest.Start(agenttest.Options{Users: []snmp.User{u}, Interfaces: pollIfs()})
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	dir := t.TempDir()
	r := startPolling(t, writeConfig(t, dir, freePort(t), 0, func(*config.Config) {}), nil)

	vars := map[string]string{"{agent_port}": strconv.Itoa(int(a1.Addr().Port())), "{agent_v3_port}": strconv.Itoa(int(a2.Addr().Port()))}
	subst := func(s string) string {
		for k, v := range vars {
			s = strings.ReplaceAll(s, k, v)
		}
		return s
	}
	// Ports are numbers: a quoted "{agent_port}" becomes the bare number.
	substBody := func(b json.RawMessage) []byte {
		s := string(b)
		for _, k := range []string{"{agent_port}", "{agent_v3_port}"} {
			s = strings.ReplaceAll(s, `"`+k+`"`, vars[k])
		}
		return []byte(subst(s))
	}
	for _, st := range fx.Steps {
		path := subst(st.Path)
		var body []byte
		if len(st.Body) > 0 {
			body = substBody(st.Body)
		}
		if st.MergeGet != "" {
			code, _, got := r.doRaw(t, "GET", subst(st.MergeGet), nil)
			if code != 200 {
				t.Fatalf("%s: GET %s: %d", st.Name, st.MergeGet, code)
			}
			var base, patch any
			if err := json.Unmarshal(got, &base); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &patch); err != nil {
				t.Fatal(err)
			}
			// What the settings form drops from GET before it PUTs.
			if l, ok := base.(map[string]any)["listeners"].(map[string]any); ok {
				if tls, ok := l["tls"].(map[string]any); ok {
					delete(tls, "password_set")
				}
			}
			body, _ = json.Marshal(deepMerge(base, patch))
		}
		var hdr []string
		if st.IfMatch {
			code, h, _ := r.doRaw(t, "GET", subst(st.EtagGet), nil)
			if code != 200 || h.Get("ETag") == "" {
				t.Fatalf("%s: no ETag from %s (%d)", st.Name, st.EtagGet, code)
			}
			hdr = []string{"If-Match", h.Get("ETag")}
		}
		code, _, resp := r.doRaw(t, st.Method, path, body, hdr...)
		if code < 200 || code > 299 {
			t.Errorf("%s: %s %s -> %d %s\nbody: %s", st.Name, st.Method, path, code, resp, body)
			continue
		}
		if st.Capture != "" {
			var created struct{ ID string }
			if err := json.Unmarshal(resp, &created); err != nil || created.ID == "" {
				t.Fatalf("%s: no id in %s", st.Name, resp)
			}
			vars["{"+st.Capture+"}"] = created.ID
		}
		if strings.HasPrefix(st.Name, "poll_test") {
			var res struct {
				Exit string `json:"exit"`
			}
			json.Unmarshal(resp, &res)
			if res.Exit != "ok" && res.Exit != "partial" {
				t.Errorf("%s: the test poll answered %s", st.Name, resp)
			}
		}
		// Nothing a form sends comes back.
		for _, secret := range []string{"fixture-community", "fixture-auth-pass", "fixture-priv-pass"} {
			if bytes.Contains(resp, []byte(secret)) {
				t.Errorf("%s: the response holds a secret", st.Name)
			}
		}
	}

	// GET -> PUT round trips: Settings (whole object, with its ETag) and a
	// poll target (its GET body, with its ETag).
	code, h, set := r.doRaw(t, "GET", "/api/settings", nil)
	if code != 200 {
		t.Fatal(code)
	}
	if code, _, b := r.doRaw(t, "PUT", "/api/settings", set, "If-Match", h.Get("ETag")); code != 200 {
		t.Errorf("settings round trip: %d %s", code, b)
	}
	var tgt map[string]any
	if code := r.do(t, "POST", "/api/poll/targets", map[string]any{"address": "127.0.0.1", "port": a1.Addr().Port(),
		"community": "fixture-community"}, &tgt); code != 201 {
		t.Fatalf("re-add: %d", code)
	}
	id := tgt["id"].(string)
	code, h, got := r.doRaw(t, "GET", "/api/poll/targets/"+id, nil)
	if code != 200 {
		t.Fatal(code)
	}
	if code, _, b := r.doRaw(t, "PUT", "/api/poll/targets/"+id, got, "If-Match", h.Get("ETag")); code != 200 {
		t.Errorf("poll target round trip: %d %s", code, b)
	}
	var after map[string]any
	r.do(t, "GET", "/api/poll/targets/"+id, nil, &after)
	if after["community_set"] != true {
		t.Errorf("the round trip lost the community: %v", after)
	}
}
