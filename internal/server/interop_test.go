package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// TestServerInterop is SPEC §11.6's interoperability check against the real
// server: net-snmp's command-line tools send traps and informs to a running
// Woodshed (server.Open and Run, the SNMP listener, its queue, the receiver
// and the store), with v3 users added through /api/snmp/users, for every
// combination the tools offer, as traps and as informs. Each one must be
// stored once with status ok and found by the trap search; each inform's tool
// must exit 0 (its Response arrived). A wrong passphrase and an unknown user
// are stored with their status and counted in /api/snmp/failures.
//
// It runs only with WOODSHED_SNMP_INTEROP=1 (the CI job "snmp interop"
// installs the distribution's snmp package). Secrets go in a temporary
// snmp.conf, never on a command line. WOODSHED_SNMP_INTEROP_REQUIRE lists the
// protocols that must be offered. The summary goes to $GITHUB_STEP_SUMMARY.
func TestServerInterop(t *testing.T) {
	if os.Getenv("WOODSHED_SNMP_INTEROP") == "" {
		t.Skip("set WOODSHED_SNMP_INTEROP=1 to run against net-snmp's tools")
	}
	for _, tool := range []string{"snmptrap", "snmpinform"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s isn't on PATH", tool)
		}
	}
	dir := t.TempDir()
	snmpPort := freeUDP(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.SNMP = config.SNMPListener{Enabled: true, Addr: "127.0.0.1", Port: snmpPort, AnswerInforms: true}
	})
	r := start(t, cfgPath)
	addr := fmt.Sprintf("udp:127.0.0.1:%d", snmpPort)

	// The tools' secrets: fixed test values, in a temporary snmp.conf.
	const community, authPass, privPass = "interop-community", "interop-auth-pass", "interop-priv-pass"
	conf := filepath.Join(dir, "conf")
	os.MkdirAll(conf, 0o700)
	os.MkdirAll(filepath.Join(dir, "persist"), 0o700)
	os.WriteFile(filepath.Join(conf, "snmp.conf"), []byte(fmt.Sprintf("defCommunity %s\ndefAuthPassphrase %s\ndefPrivPassphrase %s\n",
		community, authPass, privPass)), 0o600)
	env := append(os.Environ(), "SNMPCONFPATH="+conf, "SNMP_PERSISTENT_DIR="+filepath.Join(dir, "persist"), "HOME="+dir, "MIBS=", "MIBDIRS="+dir)
	tool := func(name string, args ...string) ([]byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	offered := map[string]string{} // protocol -> the tools' spelling
	offers := func(flag string, names ...string) string {
		key := flag + strings.Join(names, "/")
		if v, ok := offered[key]; ok {
			return v
		}
		offered[key] = ""
		for _, n := range names {
			args := []string{"-v", "3", "-u", "probe", "-e", "80000000050102030405060708", "-l", "authNoPriv", "-a", n}
			if flag == "-x" {
				args = []string{"-v", "3", "-u", "probe", "-e", "80000000050102030405060708", "-l", "authPriv", "-a", "SHA", "-x", n}
			}
			out, err := tool("snmptrap", append(args, "udp:127.0.0.1:9", "", "1.3.6.1.4.1.32473.1.0.1")...)
			if err == nil && !bytes.Contains(bytes.ToLower(out), []byte("invalid")) {
				offered[key] = n
				break
			}
		}
		return offered[key]
	}
	type combo struct {
		auth, priv, ext string // ours
		a, x            []string
	}
	auths := []struct {
		ours  string
		tools []string
	}{{"none", nil}, {"md5", []string{"MD5"}}, {"sha", []string{"SHA"}}, {"sha-224", []string{"SHA-224"}}, {"sha-256", []string{"SHA-256"}},
		{"sha-384", []string{"SHA-384"}}, {"sha-512", []string{"SHA-512"}}}
	privs := []struct {
		ours, ext string
		tools     []string
	}{{"none", "", nil}, {"des", "", []string{"DES"}}, {"aes-128", "", []string{"AES"}}, {"aes-192", "draft", []string{"AES-192", "AES192"}},
		{"aes-192", "alt", []string{"AES-192-C", "AES192C"}}, {"aes-256", "draft", []string{"AES-256", "AES256"}},
		{"aes-256", "alt", []string{"AES-256-C", "AES256C"}}}
	var combos []combo
	var skipped, passed []string
	for _, a := range auths {
		for _, p := range privs {
			if a.ours == "none" && p.ours != "none" {
				continue
			}
			combos = append(combos, combo{auth: a.ours, priv: p.ours, ext: p.ext, a: a.tools, x: p.tools})
		}
	}
	required := map[string]bool{}
	for _, p := range strings.Split(os.Getenv("WOODSHED_SNMP_INTEROP_REQUIRE"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			required[p] = true
		}
	}
	name := func(c combo) string {
		n := c.auth + "-" + c.priv
		if c.ext == "alt" {
			n += "-alt"
		}
		return n
	}
	seq := 0
	expect := func(what, tag string, want map[string]string) {
		t.Helper()
		q := url.Values{"type": {"trap"}, "q": {tag + `"`}, "limit": {"10"}}
		var page struct {
			Results []struct {
				Fields map[string]any `json:"fields"`
			} `json:"results"`
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			r.srv.store.Flush()
			page.Results = nil
			r.do(t, "GET", "/api/search?"+q.Encode(), nil, &page)
			if len(page.Results) > 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if len(page.Results) != 1 {
			t.Errorf("%s: %d records with %s", what, len(page.Results), tag)
			return
		}
		for k, v := range want {
			if fmt.Sprint(page.Results[0].Fields[k]) != v {
				t.Errorf("%s: %s = %v, want %s", what, k, page.Results[0].Fields[k], v)
			}
		}
		passed = append(passed, what)
	}
	send := func(what string, want map[string]string, argv ...string) {
		t.Helper()
		seq++
		tag := fmt.Sprintf("seq=interop:%d", seq)
		out, err := tool(argv[0], append(argv[1:], "1.3.6.1.4.1.32473.1.1.1.0", "s", tag)...)
		if err != nil {
			if strings.Contains(what, "des") && argv[0] == "snmptrap" {
				skipped = append(skipped, what+" (the tools' DES failed: "+strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]+")")
				return
			}
			t.Errorf("%s: %s exited with %v: %s", what, argv[0], err, out)
			return
		}
		expect(what, tag, want)
	}

	send("v1 trap", map[string]string{"version": "1", "pdu": "v1trap", "status": "ok"},
		"snmptrap", "-v", "1", addr, "1.3.6.1.4.1.32473.1", "127.0.0.1", "6", "17", "")
	send("v2c trap", map[string]string{"version": "2c", "pdu": "trap", "status": "ok", "trap_oid": "1.3.6.1.4.1.32473.1.0.1"},
		"snmptrap", "-v", "2c", addr, "", "1.3.6.1.4.1.32473.1.0.1")
	send("v2c inform", map[string]string{"version": "2c", "pdu": "inform", "status": "ok"},
		"snmpinform", "-v", "2c", "-r", "1", "-t", "3", addr, "", "1.3.6.1.4.1.32473.1.0.1")

	for _, c := range combos {
		args := []string{"-u", name(c)}
		level := "noAuthNoPriv"
		ok := true
		if c.auth != "none" {
			n := offers("-a", c.a...)
			if n == "" {
				ok = false
				skipped = append(skipped, name(c)+" (the tools lack "+c.auth+")")
				if required[c.auth] {
					t.Errorf("WOODSHED_SNMP_INTEROP_REQUIRE: the tools don't offer %s", c.auth)
				}
			}
			args, level = append(args, "-a", n), "authNoPriv"
		}
		if ok && c.priv != "none" {
			n := offers("-x", c.x...)
			if n == "" {
				ok = false
				key := c.priv
				if c.ext == "alt" {
					key += "-alt"
				}
				skipped = append(skipped, name(c)+" (the tools lack "+key+")")
				if required[key] {
					t.Errorf("WOODSHED_SNMP_INTEROP_REQUIRE: the tools don't offer %s", key)
				}
			}
			args, level = append(args, "-x", n), "authPriv"
		}
		if !ok {
			continue
		}
		in := map[string]any{"name": name(c), "auth": c.auth, "priv": c.priv}
		if c.auth != "none" {
			in["auth_pass"] = authPass
		}
		if c.priv != "none" {
			in["priv_pass"] = privPass
		}
		if c.ext != "" {
			in["key_ext"] = c.ext
		}
		if code := r.do(t, "POST", "/api/snmp/users", in, nil); code != 201 {
			t.Fatalf("add user %s: %d", name(c), code)
		}
		args = append([]string{"-l", level}, args...)
		want := map[string]string{"version": "3", "status": "ok", "cred": name(c)}
		trapArgs := append([]string{"snmptrap", "-v", "3", "-e", hex.EncodeToString(snmp.NewEngineID())}, args...)
		send(name(c)+" trap", want, append(trapArgs, addr, "", "1.3.6.1.4.1.32473.1.0.1")...)
		informArgs := append([]string{"snmpinform", "-v", "3", "-r", "1", "-t", "3"}, args...)
		send(name(c)+" inform", want, append(informArgs, addr, "", "1.3.6.1.4.1.32473.1.0.1")...)
	}

	// Failures: a wrong passphrase and an unknown user.
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "wrongpass", "auth": "sha", "auth_pass": "a-different-passphrase"}, nil); code != 201 {
		t.Fatalf("add user: %d", code)
	}
	for _, f := range []struct{ user, status string }{{"wrongpass", "auth_failed"}, {"nobody", "unknown_user"}} {
		if out, err := tool("snmptrap", "-v", "3", "-e", hex.EncodeToString(snmp.NewEngineID()), "-u", f.user, "-l", "authNoPriv", "-a", "SHA",
			addr, "", "1.3.6.1.4.1.32473.1.0.1"); err != nil {
			t.Fatalf("%s: %v %s", f.user, err, out)
		}
		var page struct {
			Results []any `json:"results"`
		}
		waitFor(t, f.status, func() bool {
			r.srv.store.Flush()
			r.do(t, "GET", "/api/search?type=trap&status="+f.status, nil, &page)
			return len(page.Results) == 1
		})
		passed = append(passed, f.status)
	}
	var fails []api.SNMPFailure
	r.do(t, "GET", "/api/snmp/failures", nil, &fails)
	if len(fails) != 1 || fails[0].Count24h != 2 {
		t.Errorf("failures %+v", fails)
	}

	var b strings.Builder
	ver, _ := tool("snmptrap", "--version")
	fmt.Fprintf(&b, "### SNMP interop against the server (%s)\n\n%d cases passed, %d skipped.\n\n", strings.TrimSpace(string(ver)), len(passed), len(skipped))
	for _, s := range skipped {
		fmt.Fprintf(&b, "- skipped: %s\n", s)
	}
	t.Log("\n" + b.String())
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0); err == nil {
			f.WriteString(b.String())
			f.Close()
		}
	}
}
