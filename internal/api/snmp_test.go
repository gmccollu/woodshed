package api

import (
	"context"
	"strings"
	"sync"
	"testing"
)

// fakeSNMP is the fake backend's SNMP side (kept apart from fakeBackend's
// fields so the shared helpers don't change).
type fakeSNMP struct {
	mu       sync.Mutex
	state    SNMPState
	users    map[string]SNMPUser
	failures []SNMPFailure
	reloads  int
}

var fakeSNMPOf sync.Map // *fakeBackend -> *fakeSNMP

func (b *fakeBackend) snmp() *fakeSNMP {
	if v, ok := fakeSNMPOf.Load(b); ok {
		return v.(*fakeSNMP)
	}
	fs := &fakeSNMP{
		state: SNMPState{Enabled: true, Port: 162, Engine: SNMPEngine{ID: "8000000005a1b2c3d4e5f60718", Boots: 12, Time: 86400},
			Counts24h: SNMPCounts{Received: 15230, InformsAnswered: 212, ByStatus: map[string]int64{"ok": 15201, "malformed": 4, "auth_failed": 25}},
			MIBs:      SNMPMIBs{Dir: "/var/lib/woodshed/mibs", Files: 41, Names: 18234, LoadedAt: ts("2026-11-14T08:00:03Z")}},
		users: map[string]SNMPUser{},
		failures: []SNMPFailure{{IP: "198.51.100.7", Count24h: 25, LastSeen: ts("2026-11-14T09:10:00Z"), Status: "auth_failed",
			Detail: "user monitor: wrong digest (sha-256)", DeviceID: "198.51.100.7"}},
	}
	v, _ := fakeSNMPOf.LoadOrStore(b, fs)
	return v.(*fakeSNMP)
}

func (b *fakeBackend) SNMP(context.Context) (SNMPState, error) {
	f := b.snmp()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

func (b *fakeBackend) ReloadMIBs(context.Context) (SNMPMIBs, error) {
	f := b.snmp()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloads++
	return f.state.MIBs, nil
}

func (b *fakeBackend) SNMPFailures(context.Context) ([]SNMPFailure, error) {
	f := b.snmp()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.failures, nil
}

func (b *fakeBackend) SNMPUsers(context.Context) ([]SNMPUser, error) {
	f := b.snmp()
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []SNMPUser
	for _, u := range f.users {
		out = append(out, u)
	}
	return out, nil
}

func fakeUser(in SNMPUserInput) SNMPUser {
	return SNMPUser{Name: in.Name, Auth: in.Auth, Priv: in.Priv, Level: "authPriv", KeyExt: "draft",
		AuthSet: in.AuthPass != "", PrivSet: in.PrivPass != "", Stored: "passphrase", Readable: true}
}

func (b *fakeBackend) CreateSNMPUser(_ context.Context, in SNMPUserInput) (SNMPUser, error) {
	f := b.snmp()
	f.mu.Lock()
	defer f.mu.Unlock()
	if in.Name == "" {
		return SNMPUser{}, &ValidationError{Fields: map[string]string{"name": "is required"}}
	}
	if _, ok := f.users[in.Name]; ok {
		return SNMPUser{}, ErrSNMPUserExists
	}
	u := fakeUser(in)
	f.users[in.Name] = u
	return u, nil
}

func (b *fakeBackend) UpdateSNMPUser(_ context.Context, name string, in SNMPUserInput) (SNMPUser, error) {
	f := b.snmp()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[name]; !ok {
		return SNMPUser{}, ErrNotFound
	}
	u := fakeUser(in)
	f.users[name] = u
	return u, nil
}

func (b *fakeBackend) DeleteSNMPUser(_ context.Context, name string) error {
	f := b.snmp()
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[name]; !ok {
		return ErrNotFound
	}
	delete(f.users, name)
	return nil
}

func TestSNMPRoutes(t *testing.T) {
	b := newFakeBackend()
	srv := startServer(t, b, UIConfig{})
	c := httpClient()

	m := do(t, c, "GET", srv.url("/api/snmp"), "").json(t)
	if m["engine"].(map[string]any)["id"] != "8000000005a1b2c3d4e5f60718" || m["firewall"].(map[string]any)["state"] != "unknown" {
		t.Fatalf("GET /api/snmp: %v", m)
	}
	if errs, ok := m["mibs"].(map[string]any)["errors"].([]any); !ok || errs == nil {
		t.Fatalf("mibs.errors must be a list: %v", m["mibs"])
	}
	if r := do(t, c, "POST", srv.url("/api/snmp/mibs/reload"), ""); r.code != 200 || b.snmp().reloads != 1 {
		t.Fatalf("reload: %d %s", r.code, r.body)
	}
	if r := do(t, c, "GET", srv.url("/api/snmp/failures"), ""); r.code != 200 || !strings.Contains(string(r.body), "wrong digest") {
		t.Fatalf("failures: %d %s", r.code, r.body)
	}

	body := `{"name":"monitor","auth":"sha-256","auth_pass":"0123456789","priv":"aes-128","priv_pass":"abcdefghij","key_ext":"draft","engine_ids":[]}`
	r := do(t, c, "POST", srv.url("/api/snmp/users"), body)
	if r.code != 201 || strings.Contains(string(r.body), "0123456789") || !strings.Contains(string(r.body), `"auth_set":true`) {
		t.Fatalf("create: %d %s", r.code, r.body)
	}
	if r := do(t, c, "POST", srv.url("/api/snmp/users"), body); r.code != 409 {
		t.Fatalf("duplicate: %d %s", r.code, r.body)
	}
	if r := do(t, c, "POST", srv.url("/api/snmp/users"), `{"name":""}`); r.code != 400 || !strings.Contains(string(r.body), `"name"`) {
		t.Fatalf("invalid: %d %s", r.code, r.body)
	}
	if r := do(t, c, "GET", srv.url("/api/snmp/users"), ""); r.code != 200 || !strings.Contains(string(r.body), `"engine_ids":[]`) {
		t.Fatalf("list: %d %s", r.code, r.body)
	}
	if r := do(t, c, "PUT", srv.url("/api/snmp/users/monitor"), body); r.code != 200 {
		t.Fatalf("put: %d %s", r.code, r.body)
	}
	if r := do(t, c, "PUT", srv.url("/api/snmp/users/nobody"), body); r.code != 404 {
		t.Fatalf("put unknown: %d %s", r.code, r.body)
	}
	if r := do(t, c, "DELETE", srv.url("/api/snmp/users/monitor"), ""); r.code != 204 {
		t.Fatalf("delete: %d %s", r.code, r.body)
	}
	if r := do(t, c, "DELETE", srv.url("/api/snmp/users/monitor"), ""); r.code != 404 {
		t.Fatalf("delete again: %d %s", r.code, r.body)
	}
}
