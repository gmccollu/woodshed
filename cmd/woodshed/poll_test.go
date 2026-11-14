package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

func TestPollTestCLI(t *testing.T) {
	a, err := agenttest.Start(agenttest.Options{Community: "cli-community-test", SysName: "edge-fw-01",
		Interfaces: []agenttest.Interface{{Index: 1, Name: "eth1", SpeedMbps: 1000}}})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	dir := t.TempDir()
	cf := filepath.Join(dir, "community")
	if err := os.WriteFile(cf, []byte("cli-community-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(int(a.Addr().Port()))
	code, out, errOut := runCLI("poll", "test", "127.0.0.1", "--port", port, "--community-file", cf, "--preset", "system-info,interfaces")
	if code != 0 || !strings.Contains(out, "edge-fw-01") || !strings.Contains(out, "1 interfaces, 64-bit counters; 1 would be polled") ||
		!strings.Contains(out, "Everything answered.") {
		t.Errorf("exit %d\n%s%s", code, out, errOut)
	}
	// HOST-RESOURCES missing: answered, partial (4); --json has the API's shape.
	code, out, _ = runCLI("poll", "test", "--port", port, "--community-file", cf, "--json", "127.0.0.1")
	var res struct {
		Exit  string
		Steps []struct{ Step string }
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil || code != 4 || res.Exit != "partial" {
		t.Errorf("exit %d %v\n%s", code, err, out)
	}
	// The community from the environment; a wrong one gets no answer (1).
	t.Setenv(envSNMPCommunity, "wrong-community")
	if code, out, _ := runCLI("poll", "test", "127.0.0.1", "--port", port, "--timeout", "200ms", "--retries", "0"); code != 1 ||
		!strings.Contains(out, "No answer") {
		t.Errorf("wrong community: %d\n%s", code, out)
	}
	// v3 with a wrong passphrase: 3.
	u := snmp.User{Name: "monitor", Auth: snmp.AuthSHA256, AuthPass: []byte("cli-auth-pass-test"), Level: snmp.AuthNoPriv}
	b, err := agenttest.Start(agenttest.Options{Users: []snmp.User{u}})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pf := filepath.Join(dir, "auth")
	os.WriteFile(pf, []byte("not-the-passphrase"), 0o600)
	if code, out, _ := runCLI("poll", "test", "127.0.0.1", "--port", strconv.Itoa(int(b.Addr().Port())), "--version", "3",
		"--v3-user", "monitor", "--auth", "sha-256", "--auth-pass-file", pf, "--preset", "system-info"); code != 3 {
		t.Errorf("v3 wrong pass: %d\n%s", code, out)
	}
	// Usage errors: 2.
	for _, args := range [][]string{{"poll", "test"}, {"poll", "test", "edge.example"}, {"poll", "test", "127.0.0.1", "--version", "3"},
		{"poll", "test", "127.0.0.1", "--preset", "bogus"}, {"poll"}} {
		if code, _, _ := runCLI(args...); code != 2 {
			t.Errorf("%v: %d", args, code)
		}
	}
	os.Unsetenv(envSNMPCommunity)
	if code, _, errOut := runCLI("poll", "test", "127.0.0.1"); code != 2 || !strings.Contains(errOut, "a community is needed") {
		t.Errorf("no community: %d %s", code, errOut)
	}
}

func TestStatusPollRows(t *testing.T) {
	var b bytes.Buffer
	w := &tabw{w: &b}
	now := time.Date(2026, 11, 15, 10, 0, 4, 0, time.UTC)
	last := now.Add(-4 * time.Second)
	rs := &server.RunState{Poll: &server.RunStatePoll{Targets: 12, Answering: 11, LastCycle: &last,
		NotAnswering: []server.RunStatePollTarget{{DeviceID: "10.1.0.9", Address: "10.1.0.9", Since: now.Add(-58 * time.Minute)}}}}
	statusPollRows(w, config.Default(), rs, now)
	want := "12 devices: 11 answering, 1 not answering since " + now.Add(-58*time.Minute).Local().Format("15:04") + " (10.1.0.9); last cycle 4 s ago"
	if !strings.Contains(b.String(), "Polling") || !strings.Contains(b.String(), want) {
		t.Errorf("got %q, want %q", b.String(), want)
	}
	b.Reset()
	statusPollRows(w, config.Default(), &server.RunState{}, now)
	if b.Len() != 0 {
		t.Errorf("a row without targets: %q", b.String())
	}
}
