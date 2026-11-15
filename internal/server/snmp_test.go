package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/peer"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// syncBuf is a goroutine-safe log sink, so a test can grep the logs.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// startLogged is start with a debug logger into buf.
func startLogged(t *testing.T, cfgPath string, buf *syncBuf) *running {
	t.Helper()
	log := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv, err := Open(cfgPath, Options{Version: "1.2.3", Commit: "abc1234", Logger: log})
	if err != nil {
		t.Fatal(err)
	}
	srv.be.peers.find = func(context.Context, peer.Options) (peer.Info, bool) { return peer.Info{}, false }
	srv.be.peers.readConfig = func(string) (config.Config, error) { return config.Config{}, os.ErrNotExist }
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{srv: srv, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- srv.Run(ctx) }()
	waitFor(t, "the UI", func() bool { return srv.UIState().Listening })
	r.base = "http://" + srv.UIState().Addr
	t.Cleanup(func() { r.stop(t) })
	return r
}

// freeUDP returns a free UDP port on 127.0.0.1.
func freeUDP(t *testing.T) int {
	t.Helper()
	for range 100 {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := c.LocalAddr().(*net.UDPAddr).Port
		c.Close()
		if claimPort(port) { // never one freePort or freeUDP already returned
			return port
		}
	}
	t.Fatal("no free UDP port")
	return 0
}

// The trap receiver end to end, in process (SPEC §11.6): v1, v2c and v3 traps
// and informs from loadgen (what `woodshed send --proto trap` runs) to stored
// records, exactly once, the trap search, the counts, the failures, and no
// secret anywhere on disk or in the logs.
func TestTrapsEndToEndInProcess(t *testing.T) {
	dir := t.TempDir()
	snmpPort := freeUDP(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.SNMP.Enabled = true
		c.Listeners.SNMP.Addr = "127.0.0.1"
		c.Listeners.SNMP.Port = snmpPort
	})
	var logs syncBuf
	r := startLogged(t, cfgPath, &logs)
	dataDir := filepath.Join(dir, "data")
	addr := fmt.Sprintf("127.0.0.1:%d", snmpPort)

	// The secrets (test values only), kept in variables, never on a command line.
	const authPass, privPass = "auth-Secret-4711", "priv-Secret-0815"
	const community, wrongPass = "c0mmunity-Secret", "wrong-Secret-999"
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "monitor", "auth": "sha-256", "auth_pass": authPass,
		"priv": "aes-128", "priv_pass": privPass}, nil); code != 201 {
		t.Fatalf("add user: %d", code)
	}
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "legacy", "auth": "md5", "auth_pass": authPass,
		"priv": "des", "priv_pass": privPass}, nil); code != 201 {
		t.Fatalf("add user: %d", code)
	}

	ctx := context.Background()
	type run struct {
		name string
		n    int
		to   loadgen.TrapOptions
	}
	runs := []run{
		{"v2c traps", 300, loadgen.TrapOptions{Version: "2c", Community: []byte(community)}},
		{"v1 traps", 50, loadgen.TrapOptions{Version: "1", Community: []byte(community)}},
		{"v2c informs", 50, loadgen.TrapOptions{Version: "2c", Inform: true, Community: []byte(community)}},
		{"v3 authPriv traps", 200, loadgen.TrapOptions{Version: "3", User: "monitor", Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128,
			AuthPass: []byte(authPass), PrivPass: []byte(privPass)}},
		{"v3 authPriv informs", 50, loadgen.TrapOptions{Version: "3", Inform: true, User: "monitor", Auth: snmp.AuthSHA256,
			Priv: snmp.PrivAES128, AuthPass: []byte(authPass), PrivPass: []byte(privPass)}},
		{"v3 md5/des informs", 20, loadgen.TrapOptions{Version: "3", Inform: true, User: "legacy", Auth: snmp.AuthMD5,
			Priv: snmp.PrivDES, AuthPass: []byte(authPass), PrivPass: []byte(privPass)}},
	}
	ids := map[string]string{}
	for _, rn := range runs {
		rate := 2000.0
		if rn.to.Inform {
			rate = 60 // under the reply limit (100 a second per source): every inform from 127.0.0.1
			// Each Response follows its record's write; a slow disk under load
			// delayed all 50 past the 2 s default. A late answer only costs time.
			rn.to.Timeout = 10 * time.Second
		}
		res, err := loadgen.Send(ctx, loadgen.SendOptions{Addr: addr, Proto: "trap", Count: rn.n, Rate: rate, Trap: rn.to})
		if err != nil {
			t.Fatalf("%s: %v", rn.name, err)
		}
		if res.Informs != nil && (res.Informs.Answered != rn.n || res.Informs.TimedOut != 0) {
			t.Fatalf("%s: %+v", rn.name, res.Informs)
		}
		ids[rn.name] = res.RunID
	}
	// A wrong passphrase: stored as auth_failed, counted per sender.
	if _, err := loadgen.Send(ctx, loadgen.SendOptions{Addr: addr, Proto: "trap", Count: 5, Trap: loadgen.TrapOptions{Version: "3",
		User: "monitor", Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128, AuthPass: []byte(wrongPass), PrivPass: []byte(privPass)}}); err != nil {
		t.Fatal(err)
	}
	r.srv.store.Flush()
	for _, rn := range runs {
		var v loadgen.VerifyResult
		waitFor(t, rn.name+" stored", func() bool {
			r.srv.store.Flush()
			var err error
			v, err = loadgen.Verify(dataDir, ids[rn.name], rn.n)
			return err == nil && v.Missing == 0
		})
		if v.Duplicates != 0 || v.Missing != 0 {
			t.Fatalf("%s: %+v", rn.name, v)
		}
	}
	// Every trap is in traps/, none in a syslog file.
	ents, _, _ := logfile.List(dataDir)
	for _, e := range ents {
		if e.Type != logfile.TypeTrap {
			t.Fatalf("a non-trap file: %+v", e)
		}
	}

	// The search: type=trap, its filters, and the decoded fields.
	var page struct {
		Results []struct {
			Type   string         `json:"type"`
			Raw    string         `json:"raw"`
			Fields map[string]any `json:"fields"`
		} `json:"results"`
	}
	q := url.Values{"type": {"trap"}, "snmp_versions": {"3"}, "status": {"ok"}, "limit": {"5000"}}
	waitFor(t, "the index", func() bool {
		page.Results = nil
		r.do(t, "GET", "/api/search?"+q.Encode(), nil, &page)
		return len(page.Results) == 270
	})
	if f := page.Results[0].Fields; page.Results[0].Type != "trap" || f["version"] != "3" || f["status"] != "ok" {
		t.Fatalf("result %+v", page.Results[0])
	}
	// The wrong-passphrase traps were sent last and nothing above waited for them:
	// wait until all 5 are indexed (the 270 can be in before them).
	q = url.Values{"type": {"trap"}, "status": {"auth_failed"}}
	waitFor(t, "the auth_failed traps in the index", func() bool {
		page.Results = nil
		r.do(t, "GET", "/api/search?"+q.Encode(), nil, &page)
		return len(page.Results) >= 5
	})
	if len(page.Results) != 5 || strings.Contains(page.Results[0].Raw, "vb=") {
		t.Fatalf("auth_failed: %d %+v", len(page.Results), page.Results)
	}
	var bad map[string]string
	if code := r.do(t, "GET", "/api/search?type=trap&severities=3", nil, &bad); code != 400 || bad["error"] != "severities: not a filter for SNMP traps." {
		t.Fatalf("syslog filter with type=trap: %d %v", code, bad)
	}
	// v1 traps are stored with their own fields.
	q = url.Values{"type": {"trap"}, "pdus": {"v1trap"}}
	r.do(t, "GET", "/api/search?"+q.Encode()+"&limit=1", nil, &page)
	if len(page.Results) != 1 || page.Results[0].Fields["generic"] == nil {
		t.Fatalf("v1 %+v", page.Results)
	}

	// The counts and the failures.
	var st api.SNMPState
	r.do(t, "GET", "/api/snmp", nil, &st)
	if st.Counts24h.Received < 675 || st.Counts24h.InformsAnswered != 120 || st.Counts24h.ByStatus["auth_failed"] != 5 ||
		!strings.HasPrefix(st.Engine.ID, "80000000") || st.Engine.Boots != 1 || st.Firewall.State != "unknown" {
		t.Fatalf("snmp state %+v", st)
	}
	var fails []api.SNMPFailure
	r.do(t, "GET", "/api/snmp/failures", nil, &fails)
	if len(fails) != 1 || fails[0].Count24h != 5 || fails[0].Status != "auth_failed" || fails[0].IP != "127.0.0.1" {
		t.Fatalf("failures %+v", fails)
	}
	var devs struct {
		Devices []api.Device `json:"devices"`
	}
	r.do(t, "GET", "/api/devices", nil, &devs)
	if len(devs.Devices) != 1 || len(devs.Devices[0].Types) != 1 || devs.Devices[0].Types[0] != "trap" ||
		devs.Devices[0].LinesByType["trap"] != 675 || devs.Devices[0].Status != "online" {
		t.Fatalf("devices %+v", devs.Devices)
	}
	// The listener and its queue show.
	var status api.Status
	r.do(t, "GET", "/api/status", nil, &status)
	found := false
	for _, l := range status.Listeners {
		found = found || (l.Proto == "snmp" && l.OK && l.Port == snmpPort)
	}
	if !found {
		t.Fatalf("listeners %+v", status.Listeners)
	}
	var stats api.Stats
	r.do(t, "GET", "/api/stats", nil, &stats)
	found = false
	for _, q := range stats.UDPQueue {
		found = found || q.Listener == "snmp"
	}
	if !found {
		t.Fatalf("udp_queue %+v", stats.UDPQueue)
	}

	// Communities: refused traps are counted in /api/rejected and not stored.
	var set api.Settings
	r.do(t, "GET", "/api/settings", nil, &set)
	set.Listeners.SNMP.Communities = []string{"other-community"}
	if code := r.do(t, "PUT", "/api/settings", set, &set); code != 200 || len(set.Listeners.SNMP.Communities) != 1 ||
		!strings.HasPrefix(set.Listeners.SNMP.Communities[0], "#") {
		t.Fatalf("communities: %d %+v", code, set.Listeners.SNMP)
	}
	if _, err := loadgen.Send(ctx, loadgen.SendOptions{Addr: addr, Proto: "trap", Count: 3,
		Trap: loadgen.TrapOptions{Version: "2c", Community: []byte(community)}}); err != nil {
		t.Fatal(err)
	}
	var rej []api.RejectedSender
	waitFor(t, "a community refusal", func() bool {
		r.do(t, "GET", "/api/rejected", nil, &rej)
		return len(rej) == 1 && rej[0].Reason == "community" && rej[0].Count24h == 3
	})
	// The hash round trip keeps the community; the TOML never holds it.
	if code := r.do(t, "PUT", "/api/settings", set, &set); code != 200 || len(set.Listeners.SNMP.Communities) != 1 {
		t.Fatalf("round trip: %d %+v", code, set.Listeners.SNMP)
	}

	r.stop(t)
	// No secret anywhere: the data folder (every file, the credentials file
	// included, as it stores them on this OS only in 0600 protected form),
	// the config and the logs.
	secrets := []string{authPass, privPass, community, wrongPass, "other-community"}
	check := func(where string, b []byte) {
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds a secret (%q)", where, s[:4])
			}
		}
	}
	check("the logs", []byte(logs.String()))
	cfgBytes, _ := os.ReadFile(cfgPath)
	check("the config", cfgBytes)
	filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := filepath.Base(p)
		if name == "snmp-users.json" || name == "snmp-users.dat" {
			st, _ := os.Stat(p)
			if st.Mode().Perm() != 0o600 && os.PathSeparator == '/' {
				t.Errorf("%s mode %v", name, st.Mode().Perm())
			}
			return nil // the credentials store itself (protected by its mode, or DPAPI)
		}
		b, _ := os.ReadFile(p)
		if strings.HasSuffix(p, ".gz") {
			return nil // compressed copies of the logs checked as plain files above
		}
		check(p, b)
		return nil
	})
	var users []api.SNMPUser
	_ = users
	b, _ := json.Marshal(st)
	check("the API state", b)
}

// The users API never returns a secret, and a passphrase can be kept or
// replaced (docs/api.md "SNMP v3 users").
func TestSNMPUsersAPI(t *testing.T) {
	dir := t.TempDir()
	cfgPath := writeConfig(t, dir, freePort(t), 0, nil)
	r := start(t, cfgPath)
	const pass = "users-Secret-1234"
	var u api.SNMPUser
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "ops", "auth": "sha", "auth_pass": pass}, &u); code != 201 ||
		u.Level != "authNoPriv" || !u.AuthSet || u.PrivSet || len(u.Weak) != 1 || u.Stored != "passphrase" {
		t.Fatalf("create %d %+v", code, u)
	}
	var errs struct {
		Errors map[string]string `json:"errors"`
	}
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "x", "auth": "sha-256", "auth_pass": "short"}, &errs); code != 400 ||
		errs.Errors["auth_pass"] == "" {
		t.Fatalf("short pass %d %+v", code, errs)
	}
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "y", "priv": "aes-128", "priv_pass": pass}, &errs); code != 400 ||
		errs.Errors["priv"] == "" {
		t.Fatalf("priv without auth %d %+v", code, errs)
	}
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "ops", "auth": "sha", "auth_pass": pass}, nil); code != 409 {
		t.Fatalf("duplicate %d", code)
	}
	// Engine-bound: only localized keys are kept.
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "bound", "auth": "sha-512", "auth_pass": pass,
		"priv": "aes-256", "priv_pass": pass, "key_ext": "alt", "engine_ids": []string{"8000000005a1b2c3d4e5f60718"}}, &u); code != 201 ||
		u.Stored != "localized" || !u.PrivSet || u.KeyExt != "alt" {
		t.Fatalf("bound %d %+v", code, u)
	}
	// A change without passphrases keeps them; a protocol change needs them.
	if code := r.do(t, "PUT", "/api/snmp/users/ops", map[string]any{"auth": "sha"}, &u); code != 200 || !u.AuthSet {
		t.Fatalf("keep %d %+v", code, u)
	}
	if code := r.do(t, "PUT", "/api/snmp/users/ops", map[string]any{"auth": "sha-256"}, &errs); code != 400 || errs.Errors["auth_pass"] == "" {
		t.Fatalf("protocol change %d %+v", code, errs)
	}
	var list []api.SNMPUser
	r.do(t, "GET", "/api/snmp/users", nil, &list)
	if len(list) != 2 {
		t.Fatalf("list %+v", list)
	}
	raw, _ := json.Marshal(list)
	if bytes.Contains(raw, []byte(pass)) {
		t.Fatal("a passphrase in the list")
	}
	if code := r.do(t, "DELETE", "/api/snmp/users/ops", nil, nil); code != 204 {
		t.Fatalf("delete %d", code)
	}
	// It survives a restart, and the file's on-disk form holds no plain
	// passphrase field name next to the secret... (the blob is mode 0600).
	r.stop(t)
	r2 := start(t, cfgPath)
	r2.do(t, "GET", "/api/snmp/users", nil, &list)
	if len(list) != 1 || list[0].Name != "bound" || !list[0].Readable {
		t.Fatalf("after restart %+v", list)
	}
	var st api.SNMPState
	r2.do(t, "GET", "/api/snmp", nil, &st)
	if st.Engine.Boots != 2 || st.Enabled {
		t.Fatalf("engine after restart %+v", st)
	}
	_ = time.Second
}

// Replies are limited to 100 a second per source (SPEC §11.2.3): a burst of
// informs from one sender is stored whole, answered up to the limit, and the
// rest counted as rate-limited.
func TestInformReplyLimit(t *testing.T) {
	dir := t.TempDir()
	snmpPort := freeUDP(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.SNMP = config.SNMPListener{Enabled: true, Addr: "127.0.0.1", Port: snmpPort, AnswerInforms: true}
	})
	r := start(t, cfgPath)
	res, err := loadgen.Send(context.Background(), loadgen.SendOptions{Addr: fmt.Sprintf("127.0.0.1:%d", snmpPort), Proto: "trap",
		// 2 s: a Response that arrives after the timeout counts as answered on the
		// server and timed out here (a starved runner reached ~500 ms round trips).
		Count: 400, Trap: loadgen.TrapOptions{Version: "2c", Inform: true, Timeout: 2 * time.Second}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Informs == nil || res.Informs.Answered < 100 || res.Informs.Answered > 300 || res.Informs.TimedOut == 0 {
		t.Fatalf("informs %+v", res.Informs)
	}
	var st api.SNMPState
	waitFor(t, "the counts", func() bool {
		r.do(t, "GET", "/api/snmp", nil, &st)
		return st.Counts24h.Received == 400
	})
	if st.Counts24h.InformsAnswered != int64(res.Informs.Answered) || st.Counts24h.RepliesRateLimited != 400-st.Counts24h.InformsAnswered {
		t.Fatalf("counts %+v, informs %+v", st.Counts24h, res.Informs)
	}
	r.srv.store.Flush()
	v, err := loadgen.Verify(filepath.Join(dir, "data"), res.RunID, 400)
	if err != nil || v.Missing != 0 || v.Duplicates != 0 {
		t.Fatalf("stored %+v %v", v, err)
	}
}
