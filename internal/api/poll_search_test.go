package api

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

// type=poll in the search, export and saved-search APIs (docs/api.md "Poll
// lines in search", SPEC §12.3).

func TestParseSearchPoll(t *testing.T) {
	r, err := ParseSearch(url.Values{"type": {"poll"}, "kinds": {"if,restart"}, "ifs": {"Eth3, 7"}, "oper": {"down"},
		"poll_status": {"ok"}, "reboot": {"1,?"}})
	if err != nil {
		t.Fatal(err)
	}
	if r.Type != "poll" || r.Poll == nil || r.Trap != nil || !slices.Equal(r.Poll.Kinds, []string{"if", "restart"}) ||
		!slices.Equal(r.Poll.Ifs, []string{"eth3", "7"}) || !slices.Equal(r.Poll.Reboot, []string{"1", "?"}) {
		t.Errorf("%+v %+v", r, r.Poll)
	}
	if r, _ := ParseSearch(url.Values{"type": {"poll"}}); r.Poll != nil {
		t.Errorf("no filters: %+v", r.Poll)
	}
	for bad, msg := range map[string]string{
		"type=poll&severities=3":   `severities: not a filter for SNMP polls.`,
		"type=poll&trap_oid=x":     `trap_oid: not a filter for SNMP polls.`,
		"type=poll&status=ok":      `status: not a filter for SNMP polls.`,
		"type=poll&app=sshd":       `app: not a filter for SNMP polls.`,
		"kinds=if":                 `kinds: not a filter for syslog.`,
		"type=trap&poll_status=ok": `poll_status: not a filter for SNMP traps.`,
		"type=poll&kinds=flow":     `kinds: "flow" is not one of sys, if, oid, status, restart, info (or none on its own).`,
		"type=poll&reboot=2":       `reboot: "2" is not one of 1, 0, ?`,
	} {
		v, _ := url.ParseQuery(bad)
		if _, err := ParseSearch(v); err == nil || !strings.Contains(err.Error(), msg) {
			t.Errorf("%s: %v, want %q", bad, err, msg)
		}
	}
}

func TestPollResultJSON(t *testing.T) {
	l := SearchLine{Received: time.Date(2026, 11, 15, 10, 0, 0, 131e6, time.UTC), DeviceID: "10.1.0.1", Type: "poll", Ref: "r1",
		Raw: []byte(`kind=if cycle=1042 if=3 name="eth3" oper=up in_bps=81234567`)}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"received":"2026-11-15T10:00:00.131Z","device_id":"10.1.0.1","type":"poll","ref":"r1","raw":"kind=if cycle=1042 if=3 name=\"eth3\" oper=up in_bps=81234567",` +
		`"fields":{"kind":"if","cycle":1042,"if":"eth3","oper":"up","status":"ok","reboot":"","values":{"if":"3","in_bps":"81234567","name":"eth3"}}}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestPollListsJSON(t *testing.T) {
	var pl PollLists
	if err := json.Unmarshal([]byte(`{"kinds": ["status"], "poll_status": ["timeout"], "ifs": ["eth1", 7]}`), &pl); err != nil {
		t.Fatal(err)
	}
	f, err := pl.Filter()
	if err != nil || f == nil || f.Kinds[0] != "status" || f.Status[0] != "timeout" || f.Ifs[1] != "7" {
		t.Fatalf("%+v %v", f, err)
	}
	if back := PollListsOf(f); !slices.Equal(back.PollStatus, []string{"timeout"}) || !slices.Equal(back.Ifs, []string{"eth1", "7"}) {
		t.Errorf("%+v", back)
	}
	if err := json.Unmarshal([]byte(`{"kinds": ["flow"]}`), &pl); err != nil {
		t.Fatal(err)
	}
	if _, err := pl.Filter(); err == nil {
		t.Error("kinds flow accepted")
	}
}

func TestExportBodyPoll(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	base := `"devices": ["10.1.0.1"], "from": "2026-11-10T00:00:00Z", "to": "2026-11-10T06:00:00Z"`
	r := do(t, c, "POST", srv.url("/api/exports"), `{`+base+`, "types": ["poll"], "kinds": ["if"], "oper": ["down"]}`)
	if r.code != 202 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	req := srv.b.exportReqs[0]
	if req.Type != "poll" || req.Poll == nil || !slices.Equal(req.Poll.Kinds, []string{"if"}) || req.Trap != nil {
		t.Errorf("%+v", req)
	}
	for bad, msg := range map[string]string{
		`"types": ["poll"], "severities": [3]`:         "severities: not a filter for SNMP polls.",
		`"types": ["poll"], "pdus": ["trap"]`:          "pdus: not a filter for SNMP polls.",
		`"types": ["trap"], "kinds": ["if"]`:           "kinds: not a filter for SNMP traps.",
		`"types": ["poll", "syslog"], "kinds": ["if"]`: "Filters apply to one data type",
		`"types": ["poll"], "kinds": ["flow"]`:         `kinds: "flow"`,
	} {
		wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{`+base+`, `+bad+`}`), 400, msg)
	}
	// A bundle takes no poll filters.
	wantError(t, do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "at": "2026-11-14T09:42:00Z", "active_devices": true,
		"types": ["poll"], "kinds": ["if"]}`), 400, "kinds: a bundle takes no filters")
	if r := do(t, c, "POST", srv.url("/api/exports"), `{"kind": "bundle", "at": "2026-11-14T09:42:00Z", "active_devices": true,
		"types": ["poll", "trap"]}`); r.code != 202 {
		t.Errorf("bundle with poll: %d %s", r.code, r.body)
	}
}

func TestSavedSearchPoll(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	r := do(t, c, "POST", srv.url("/api/saved-searches"), `{"name": "Restarts", "type": "poll", "query": {"kinds": ["restart"], "reboot": ["1"],
		"range": {"last": "7d"}}}`)
	if r.code != 201 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	var ss SavedSearch
	if err := json.Unmarshal(r.body, &ss); err != nil {
		t.Fatal(err)
	}
	if ss.Type != "poll" || !slices.Equal(ss.Query.PollLists.Kinds, []string{"restart"}) {
		t.Errorf("%s", r.body)
	}
	fr := ss.Query.FilterOf("poll")
	if fr.Poll == nil || !slices.Equal(fr.Poll.Reboot, []string{"1"}) || fr.Trap != nil {
		t.Errorf("FilterOf %+v", fr.Poll)
	}
	for body, key := range map[string]string{
		`{"name": "x", "type": "poll", "query": {"severities": [3]}}`:    "query.severities",
		`{"name": "x", "type": "poll", "query": {"pdus": ["trap"]}}`:     "query.pdus",
		`{"name": "x", "type": "trap", "query": {"kinds": ["if"]}}`:      "query.kinds",
		`{"name": "x", "type": "poll", "query": {"oper": ["sideways"]}}`: "query.oper",
	} {
		r := do(t, c, "POST", srv.url("/api/saved-searches"), body)
		if r.code != 400 || !strings.Contains(string(r.body), `"`+key+`"`) {
			t.Errorf("%s: %d %s", body, r.code, r.body)
		}
	}
}
