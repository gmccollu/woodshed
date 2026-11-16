package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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
	syslogPort := freePort(t)
	r := startPolling(t, writeConfig(t, dir, syslogPort, 0, func(*config.Config) {}), nil)
	// A device 127.0.0.1 for the export and bundle bodies (they name it).
	sendSyslog(t, syslogPort, "<134>fixture device")
	deadline := time.Now().Add(30 * time.Second)
	for {
		var devs struct{ Total int }
		if r.do(t, "GET", "/api/devices?q=127.0.0.1", nil, &devs); devs.Total == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fixture device never showed up")
		}
		time.Sleep(20 * time.Millisecond)
	}

	vars := map[string]string{"{agent_port}": strconv.Itoa(int(a1.Addr().Port())), "{agent_v3_port}": strconv.Itoa(int(a2.Addr().Port())),
		"{flow_netflow_port}": strconv.Itoa(freeUDP(t)), "{flow_ipfix_port}": strconv.Itoa(freeUDP(t)),
		// A bundle's moment can't be in the future.
		"{at}": time.Now().UTC().Add(-30 * time.Minute).Truncate(time.Second).Format(time.RFC3339)}
	subst := func(s string) string {
		for k, v := range vars {
			s = strings.ReplaceAll(s, k, v)
		}
		return s
	}
	// Ports are numbers: a quoted "{agent_port}" becomes the bare number.
	substBody := func(b json.RawMessage) []byte {
		s := string(b)
		for _, k := range []string{"{agent_port}", "{agent_v3_port}", "{flow_netflow_port}", "{flow_ipfix_port}"} {
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

	// GET -> PUT round trips: an SNMP v3 user (its GET entry, read-only
	// fields and all; the passphrases are kept), Settings (whole object, with
	// its ETag) and a poll target (its GET body, with its ETag).
	var users []map[string]any
	if code := r.do(t, "GET", "/api/snmp/users", nil, &users); code != 200 || len(users) == 0 {
		t.Fatalf("users: %d %v", code, users)
	}
	ub, _ := json.Marshal(users[0])
	if code, _, b := r.doRaw(t, "PUT", "/api/snmp/users/"+users[0]["name"].(string), ub); code != 200 {
		t.Errorf("SNMP user round trip: %d %s", code, b)
	}
	var after0 []map[string]any
	r.do(t, "GET", "/api/snmp/users", nil, &after0)
	if len(after0) == 0 || after0[0]["auth_set"] != true || after0[0]["priv_set"] != true {
		t.Errorf("the user round trip lost a passphrase: %v", after0)
	}
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

// sendSyslog sends one UDP syslog message to 127.0.0.1:port.
func sendSyslog(t *testing.T, port int, msg string) {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
}
