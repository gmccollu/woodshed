//go:build !windows

package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/setuphelper"
)

// TestSetupSnippets is the setup helper's "Tested" level (SPEC §13.5,
// §13.11 #5): every snippet a template marked Tested generates is applied to
// the real open-source tool against a real running server, and the data must
// arrive exactly once:
//
//   - rsyslog: syslog over UDP, TCP and TLS (Woodshed's own CA, downloaded
//     from /api/tls/ca.pem, as <CA-FILE>);
//   - net-snmp: snmpd's own coldStart trap and snmptrap's test trap, v2c and
//     v3 (the v3 user added through /api/snmp/users);
//   - net-snmp: snmpd answering Woodshed's poller, v2c and v3;
//   - softflowd: flows, only once the flow listener exists (feat-flows).
//
// Each snippet comes from the server's own POST /api/setup/snippet, so it's
// filled from the live settings. The test writes each "file" part where the
// tool reads it (in a temporary folder), fills the placeholders the way a
// user would, and runs the "command" parts. It never runs as root, binds only
// high ports on loopback, and stops every process it starts by PID.
//
// It runs only with WOODSHED_SETUP_INTEROP=1 (the CI job "setup-snippets"
// installs rsyslog, its TLS driver, snmpd, snmp and softflowd).
// WOODSHED_SETUP_INTEROP_ONLY=net-snmp,rsyslog limits it to some families (for
// a machine with only some of the tools); WOODSHED_SETUP_INTEROP_REQUIRE=sha-256
// fails instead of falling back to SHA-1 when the tools lack SHA-256.
func TestSetupSnippets(t *testing.T) {
	if os.Getenv("WOODSHED_SETUP_INTEROP") == "" {
		t.Skip("set WOODSHED_SETUP_INTEROP=1 to apply the Tested setup snippets to rsyslog, net-snmp and softflowd")
	}
	only := map[string]bool{}
	for _, f := range strings.Split(os.Getenv("WOODSHED_SETUP_INTEROP_ONLY"), ",") {
		if f = strings.TrimSpace(f); f != "" {
			only[f] = true
		}
	}
	var summary []string
	for _, c := range setupInteropCases {
		name := c.family + "/" + c.what + "/" + c.transport
		t.Run(name, func(t *testing.T) {
			if len(only) > 0 && !only[c.family] {
				t.Skip("not in WOODSHED_SETUP_INTEROP_ONLY")
			}
			if c.skip != "" {
				summary = append(summary, "- skipped "+name+": "+c.skip)
				t.Skip(c.skip)
			}
			note := setupRunners[c.family+"/"+c.what](t, c.transport)
			summary = append(summary, "- passed "+name+note)
		})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "### Setup snippets applied to the real tools\n\n%s\n", strings.Join(summary, "\n"))
	t.Log("\n" + b.String())
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0); err == nil {
			f.WriteString(b.String())
			f.Close()
		}
	}
}

// setupCase is one snippet CI applies. A case with skip set isn't applied
// (and so doesn't make its template Tested).
type setupCase struct {
	family, what, transport string
	skip                    string
}

const skipNoFlow = "the flow listener isn't on this branch yet; enable the softflowd cases (and mark softflowd-flow.tmpl tested) when feat-flows merges"

// setupInteropCases: one line per case, in a form internal/setuphelper's
// TestNoVendorNames also reads (family: "…", what: "…", transport: "…").
var setupInteropCases = []setupCase{
	{family: "rsyslog", what: "syslog", transport: "udp"},
	{family: "rsyslog", what: "syslog", transport: "tcp"},
	{family: "rsyslog", what: "syslog", transport: "tls"},
	{family: "net-snmp", what: "trap", transport: "v2c"},
	{family: "net-snmp", what: "trap", transport: "v3"},
	{family: "net-snmp", what: "poll", transport: "v2c"},
	{family: "net-snmp", what: "poll", transport: "v3"},
	{family: "softflowd", what: "flow", transport: "v9", skip: skipNoFlow},
	{family: "softflowd", what: "flow", transport: "ipfix", skip: skipNoFlow},
}

// flowListenerExists reports whether this build's config has a flow
// listener (it arrives with feat-flows).
func flowListenerExists() bool {
	_, ok := reflect.TypeOf(config.Listeners{}).FieldByName("Flow")
	return ok
}

// setupRunners apply one family and data type's snippet; each returns a note
// for the summary.
var setupRunners = map[string]func(t *testing.T, transport string) string{
	"rsyslog/syslog": runRsyslog,
	"net-snmp/trap":  runSnmpTrap,
	"net-snmp/poll":  runSnmpPoll,
	"softflowd/flow": func(t *testing.T, _ string) string {
		if !flowListenerExists() {
			t.Skip(skipNoFlow)
		}
		t.Fatal("the flow listener exists now: write the softflowd case (softflowd -r a fixed pcap, or -i lo with traffic, to the flow listener)")
		return ""
	},
}

// The tools' test secrets: fixed values, written into the tools' config files
// in the test's folder, never on a command line.
const (
	setupCommunity = "setup-interop-community"
	setupAuthPass  = "setup-interop-auth-pass"
	setupPrivPass  = "setup-interop-priv-pass"
	setupUser      = "setupuser"
)

// setupEnv is one case's running server and folder.
type setupEnv struct {
	r        *running
	dir      string
	snmpPort int
}

func newSetupEnv(t *testing.T) *setupEnv {
	t.Helper()
	dir := t.TempDir()
	snmpPort, tlsPort := freeUDP(t), freePort(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: tlsPort}
		c.Listeners.SNMP = config.SNMPListener{Enabled: true, Addr: "127.0.0.1", Port: snmpPort, AnswerInforms: true}
	})
	return &setupEnv{r: start(t, cfgPath), dir: dir, snmpPort: snmpPort}
}

// snippet asks the server for one snippet.
func (e *setupEnv) snippet(t *testing.T, req map[string]any) setuphelper.Snippet {
	t.Helper()
	b, _ := json.Marshal(req)
	code, _, body := e.r.doRaw(t, "POST", "/api/setup/snippet", b)
	if code != 200 {
		t.Fatalf("POST /api/setup/snippet %s: %d %s", b, code, body)
	}
	var s setuphelper.Snippet
	if err := json.Unmarshal(body, &s); err != nil {
		t.Fatal(err)
	}
	if s.Verification != setuphelper.Tested {
		t.Fatalf("%s %s %s isn't marked tested (%s)", s.Family, s.What, s.Transport, s.Verification)
	}
	for _, secret := range []string{setupCommunity, setupAuthPass, setupPrivPass} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("the snippet holds a stored secret: %s", body)
		}
	}
	t.Logf("snippet %s %s %s:\n%s", s.Family, s.What, s.Transport, s.Text)
	return s
}

// part returns the snippet's part of that kind whose path or title contains key.
func part(t *testing.T, s setuphelper.Snippet, kind, key string) setuphelper.Part {
	t.Helper()
	for _, p := range s.Parts {
		if p.Kind == kind && (strings.Contains(p.Path, key) || strings.Contains(p.Title, key)) {
			return p
		}
	}
	t.Fatalf("no %s part %q in %+v", kind, key, s.Parts)
	return setuphelper.Part{}
}

// fill replaces the placeholders as a user would; any left over fails.
func fill(t *testing.T, text string, values map[string]string) string {
	t.Helper()
	for k, v := range values {
		text = strings.ReplaceAll(text, k, v)
	}
	if m := placeholderRe.FindString(text); m != "" {
		t.Fatalf("placeholder %s is left in:\n%s", m, text)
	}
	return text
}

var placeholderRe = regexp.MustCompile(`<[A-Z][A-Z0-9-]*>`)

// count is how many records of typ match the search.
func (e *setupEnv) count(t *testing.T, typ string, q url.Values) int {
	t.Helper()
	q.Set("type", typ)
	q.Set("limit", "50")
	var page struct {
		Results []json.RawMessage `json:"results"`
	}
	e.r.srv.store.Flush()
	if code := e.r.do(t, "GET", "/api/search?"+q.Encode(), nil, &page); code != 200 {
		t.Fatalf("search %s: %d", q.Encode(), code)
	}
	return len(page.Results)
}

// exactlyOnce waits until exactly one record matches, then checks that no
// second copy turns up while the sender keeps running (a retry, a
// duplicate send).
func (e *setupEnv) exactlyOnce(t *testing.T, what, typ string, q url.Values) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	n := 0
	for {
		if n = e.count(t, typ, q); n >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if n != 1 {
		t.Fatalf("%s: %d records, want exactly 1", what, n)
	}
	time.Sleep(3 * time.Second)
	if n = e.count(t, typ, q); n != 1 {
		t.Fatalf("%s: %d records after 3 s more, want exactly 1", what, n)
	}
}

// proc is a tool the test started; stop ends it by PID.
type toolProc struct {
	cmd  *exec.Cmd
	log  string
	done chan struct{}
}

func startProc(t *testing.T, log string, env []string, name string, args ...string) *toolProc {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Env = env
	f, err := os.Create(log + ".out")
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	p := &toolProc{cmd: cmd, log: log, done: make(chan struct{})}
	go func() { cmd.Wait(); f.Close(); close(p.done) }()
	t.Cleanup(func() {
		p.stop()
		if t.Failed() {
			for _, l := range []string{log, log + ".out"} {
				if b, err := os.ReadFile(l); err == nil && len(b) > 0 {
					t.Logf("%s:\n%s", filepath.Base(l), b)
				}
			}
		}
	})
	return p
}

func (p *toolProc) stop() {
	select {
	case <-p.done:
		return
	default:
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
}

func (p *toolProc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func tool(t *testing.T, name string, extra ...string) string {
	t.Helper()
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range append(extra, "/usr/sbin", "/usr/local/sbin", "/sbin") {
		if p := filepath.Join(d, name); fileExists(p) {
			return p
		}
	}
	t.Fatalf("%s isn't installed (the CI job installs it)", name)
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// udpHeld waits until something holds the UDP port on 127.0.0.1.
func udpHeld(t *testing.T, port int, p *toolProc) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if p.exited() {
			t.Fatalf("%s exited at start", filepath.Base(p.cmd.Path))
		}
		c, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			return
		}
		c.Close()
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nothing listens on UDP %d", port)
}

// ---- rsyslog ----

func runRsyslog(t *testing.T, transport string) string {
	bin := tool(t, "rsyslogd")
	e := newSetupEnv(t)
	s := e.snippet(t, map[string]any{"family": "rsyslog", "what": "syslog", "transport": transport, "address": "127.0.0.1"})
	values := map[string]string{}
	if transport == "tls" {
		code, _, pem := e.r.doRaw(t, "GET", "/api/tls/ca.pem", nil)
		if code != 200 {
			t.Fatalf("ca.pem: %d", code)
		}
		ca := filepath.Join(e.dir, "woodshed-ca.pem")
		os.WriteFile(ca, pem, 0o644)
		values["<CA-FILE>"] = ca
	}
	file := part(t, s, setuphelper.PartFile, "/etc/rsyslog.d/")
	snippetFile := filepath.Join(e.dir, filepath.Base(file.Path))
	if err := os.WriteFile(snippetFile, []byte(fill(t, file.Text, values)), 0o644); err != nil {
		t.Fatal(err)
	}
	// The harness's own rsyslog.conf: a work folder, a UDP input on loopback
	// for the test message, and the snippet, included as the distribution's
	// rsyslog.conf includes /etc/rsyslog.d/*.conf.
	work := filepath.Join(e.dir, "work")
	os.MkdirAll(work, 0o755)
	inPort := freeUDP(t)
	conf := filepath.Join(e.dir, "rsyslog.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf("global(workDirectory=%q)\nmodule(load=\"imudp\")\ninput(type=\"imudp\" address=\"127.0.0.1\" port=\"%d\")\ninclude(file=%q)\n",
		work, inPort, snippetFile)), 0o644)
	env := append(os.Environ(), "HOME="+e.dir)
	// The snippet's own check first: rsyslogd -N1.
	if out, err := exec.Command(bin, "-N1", "-f", conf).CombinedOutput(); err != nil {
		t.Fatalf("rsyslogd -N1 refused the snippet: %v\n%s", err, out)
	}
	p := startProc(t, filepath.Join(e.dir, "rsyslogd.log"), env, bin, "-n", "-f", conf, "-i", filepath.Join(e.dir, "rsyslogd.pid"))
	udpHeld(t, inPort, p)

	token := fmt.Sprintf("wsetup-%s-%d", transport, time.Now().UnixNano())
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", inPort))
	if err != nil {
		t.Fatal(err)
	}
	// user.info, as the snippet's logger test does (logger writes to the system's own socket).
	fmt.Fprintf(c, "<14>%s setup-test woodshed-test: Test message for Woodshed %s", time.Now().Format(time.Stamp), token)
	c.Close()
	e.exactlyOnce(t, "rsyslog "+transport, "syslog", url.Values{"q": {token}})
	ver, _ := exec.Command(bin, "-v").CombinedOutput()
	return " (" + strings.SplitN(strings.TrimSpace(string(ver)), "\n", 2)[0] + ")"
}

// ---- net-snmp ----

// snmpEnv is a folder for net-snmp's tools: SNMPCONFPATH replaces the whole
// search path, so neither the system's nor the user's own files are read.
func snmpEnv(dir string) (env []string, confDir, home string) {
	confDir, home = filepath.Join(dir, "snmpd"), filepath.Join(dir, "home")
	persist := filepath.Join(dir, "persist")
	for _, d := range []string{confDir, filepath.Join(home, ".snmp"), persist} {
		os.MkdirAll(d, 0o700)
	}
	env = append(os.Environ(), "SNMP_PERSISTENT_DIR="+persist, "HOME="+home, "MIBS=", "MIBDIRS="+dir,
		"SNMPCONFPATH="+confDir+string(os.PathListSeparator)+filepath.Join(home, ".snmp")+string(os.PathListSeparator)+persist)
	return env, confDir, home
}

// v3Auth is the v3 authentication protocol to test: the snippet's default
// (SHA-256) when the tools have it, else SHA-1.
func v3Auth(t *testing.T, env []string) (auth, note string) {
	t.Helper()
	cmd := exec.Command(tool(t, "snmptrap", "/usr/bin"), "-v", "3", "-u", "probe", "-l", "authNoPriv", "-a", "SHA-256", "-A", "probe-passphrase",
		"udp:127.0.0.1:9", "", "1.3.6.1.4.1.32473.1.0.1")
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil && !bytes.Contains(bytes.ToLower(out), []byte("invalid")) {
		return "sha-256", ""
	}
	if strings.Contains(os.Getenv("WOODSHED_SETUP_INTEROP_REQUIRE"), "sha-256") {
		t.Fatalf("WOODSHED_SETUP_INTEROP_REQUIRE: these tools lack SHA-256: %s", out)
	}
	return "sha", " (SHA-1: these tools lack SHA-256)"
}

func (e *setupEnv) addUser(t *testing.T, auth string) {
	t.Helper()
	in := map[string]any{"name": setupUser, "auth": auth, "priv": "aes-128", "auth_pass": setupAuthPass, "priv_pass": setupPrivPass}
	if code := e.r.do(t, "POST", "/api/snmp/users", in, nil); code != 201 {
		t.Fatalf("add user: %d", code)
	}
}

var snmpSecrets = map[string]string{"<COMMUNITY>": setupCommunity, "<AUTH-PASSPHRASE>": setupAuthPass, "<PRIV-PASSPHRASE>": setupPrivPass}

func runSnmpTrap(t *testing.T, transport string) string {
	snmpd, snmptrap := tool(t, "snmpd"), tool(t, "snmptrap", "/usr/bin")
	e := newSetupEnv(t)
	env, confDir, home := snmpEnv(e.dir)
	req := map[string]any{"family": "net-snmp", "what": "trap", "transport": transport, "address": "127.0.0.1"}
	note := ""
	if transport == "v3" {
		var auth string
		auth, note = v3Auth(t, env)
		req["v3_user"], req["auth"] = setupUser, auth
		e.addUser(t, auth)
	}
	s := e.snippet(t, req)
	if !strings.Contains(s.Text, fmt.Sprintf("udp:127.0.0.1:%d", e.snmpPort)) {
		t.Fatalf("the snippet doesn't use the server's trap port %d", e.snmpPort)
	}
	// snmpd.conf: the snippet, plus the harness's agent address (the default,
	// UDP 161, needs root); snmp.conf for snmptrap, from the snippet.
	agentPort := freeUDP(t)
	conf := fmt.Sprintf("agentAddress udp:127.0.0.1:%d\n%s", agentPort, fill(t, part(t, s, setuphelper.PartFile, "snmpd.conf").Text, snmpSecrets))
	os.WriteFile(filepath.Join(confDir, "snmpd.conf"), []byte(conf), 0o600)
	os.WriteFile(filepath.Join(home, ".snmp", "snmp.conf"), []byte(fill(t, part(t, s, setuphelper.PartFile, "snmp.conf").Text, snmpSecrets)), 0o600)

	// snmpd sends coldStart when it starts.
	p := startProc(t, filepath.Join(e.dir, "snmpd.log"), env, snmpd, "-f", "-Lf", filepath.Join(e.dir, "snmpd.log"), "-p", filepath.Join(e.dir, "snmpd.pid"))
	udpHeld(t, agentPort, p)
	e.exactlyOnce(t, "snmpd's coldStart ("+transport+")", "trap", url.Values{"trap_oid": {"1.3.6.1.6.3.1.1.5.1"}})

	// The snippet's test trap, run as written (by a shell, for its $(hostname)).
	cmdText := part(t, s, setuphelper.PartCommand, "test trap").Text
	sh := exec.Command("sh", "-c", strings.Replace(cmdText, "snmptrap ", snmptrap+" ", 1))
	sh.Env = env
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("the test trap command failed: %v\n%s", err, out)
	}
	e.exactlyOnce(t, "snmptrap's test trap ("+transport+")", "trap", url.Values{"q": {"Test trap for Woodshed"}})
	// Each with the version (and, for v3, the user) the snippet set up.
	var page struct {
		Results []struct {
			Fields map[string]any `json:"fields"`
		} `json:"results"`
	}
	e.r.do(t, "GET", "/api/search?type=trap&limit=50", nil, &page)
	for _, r := range page.Results {
		if r.Fields["status"] != "ok" || (transport == "v3" && r.Fields["cred"] != setupUser) || (transport == "v2c" && r.Fields["version"] != "2c") {
			t.Errorf("a trap stored as %v", r.Fields)
		}
	}
	return note
}

func runSnmpPoll(t *testing.T, transport string) string {
	snmpd := tool(t, "snmpd")
	e := newSetupEnv(t)
	env, confDir, _ := snmpEnv(e.dir)
	agentPort := freeUDP(t)
	req := map[string]any{"family": "net-snmp", "what": "poll", "transport": transport, "address": "127.0.0.1", "agent_port": agentPort}
	note := ""
	auth := ""
	if transport == "v3" {
		auth, note = v3Auth(t, env)
		req["v3_user"], req["auth"] = setupUser, auth
	}
	s := e.snippet(t, req)
	os.WriteFile(filepath.Join(confDir, "snmpd.conf"), []byte(fill(t, part(t, s, setuphelper.PartFile, "snmpd.conf").Text, snmpSecrets)), 0o600)
	p := startProc(t, filepath.Join(e.dir, "snmpd.log"), env, snmpd, "-f", "-Lf", filepath.Join(e.dir, "snmpd.log"), "-p", filepath.Join(e.dir, "snmpd.pid"))
	udpHeld(t, agentPort, p)

	// The shortest interval (30 s), so the first cycle comes soon.
	target := map[string]any{"address": "127.0.0.1", "port": agentPort, "version": "2c", "community": setupCommunity, "interval_s": 30}
	if transport == "v3" {
		e.addUser(t, auth)
		target = map[string]any{"address": "127.0.0.1", "port": agentPort, "version": "3", "v3_user": setupUser, "interval_s": 30}
	}
	var created struct {
		ID string `json:"id"`
	}
	if code := e.r.do(t, "POST", "/api/poll/targets", target, &created); code != 201 {
		t.Fatalf("add poll target: %d", code)
	}
	// The form's Test poll, then the first scheduled cycle.
	var res struct {
		Exit  string `json:"exit"`
		Steps []struct {
			Name   string `json:"name"`
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"steps"`
	}
	b, _ := json.Marshal(map[string]any{"id": created.ID})
	code, _, body := e.r.doRaw(t, "POST", "/api/poll/test", b)
	json.Unmarshal(body, &res)
	if code != 200 || (res.Exit != "ok" && res.Exit != "partial") {
		t.Fatalf("test poll: %d %s", code, body)
	}
	var st struct {
		State struct {
			Status  string `json:"status"`
			SysName string `json:"sys_name"`
		} `json:"state"`
	}
	// A new target's first cycle comes within one interval.
	deadline := time.Now().Add(90 * time.Second)
	for {
		e.r.do(t, "GET", "/api/poll/targets/"+created.ID, nil, &st)
		if st.State.Status == "ok" || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st.State.Status != "ok" {
		t.Fatalf("the target's state after 90 s: %+v", st.State)
	}
	if st.State.SysName == "" {
		t.Errorf("polled, but no sysName: %+v", st.State)
	}
	return note
}

// TestSetupTestedTemplatesHaveCI: nothing is labelled Tested without a CI
// test that applies it (SPEC §13.11 #5). Every transport of every template
// marked tested has a case above that isn't skipped and has a runner, and
// the CI workflow has the "setup-snippets" job that runs TestSetupSnippets
// with the tools installed. It runs everywhere, without the tools.
func TestSetupTestedTemplatesHaveCI(t *testing.T) {
	ts, err := setuphelper.Templates()
	if err != nil {
		t.Fatal(err)
	}
	applied := map[string]bool{}
	for _, c := range setupInteropCases {
		key := c.family + "/" + c.what + "/" + c.transport
		if _, ok := setupRunners[c.family+"/"+c.what]; !ok {
			t.Errorf("case %s has no runner", key)
		}
		found := false
		for _, tm := range ts {
			found = found || tm.Family == c.family && tm.What == c.what && slices.Contains(tm.Transports, c.transport)
		}
		if !found {
			t.Errorf("case %s has no template", key)
		}
		if c.skip == "" {
			applied[key] = true
		}
	}
	tested := 0
	for _, tm := range ts {
		if tm.Verification != setuphelper.Tested {
			continue
		}
		for _, tr := range tm.Transports {
			tested++
			if !applied[tm.Family+"/"+tm.What+"/"+tr] {
				t.Errorf("%s is marked tested, but no CI case applies its %s snippet", tm.File, tr)
			}
		}
	}
	if tested == 0 {
		t.Error("no template is marked tested")
	}
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	ci := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(ci, "\n  setup-snippets:\n")
	if i < 0 {
		t.Fatal(`.github/workflows/ci.yml has no "setup-snippets" job`)
	}
	job := ci[i+1:]
	if j := regexp.MustCompile(`\n  [a-z][a-z0-9-]*:\n`).FindStringIndex(job[1:]); j != nil {
		job = job[:j[0]+1]
	}
	for _, want := range []string{"runs-on: ubuntu-", `WOODSHED_SETUP_INTEROP: "1"`, "-run '^TestSetupSnippets$'", "./internal/server/",
		"rsyslog", "rsyslog-gnutls", "snmpd", " snmp", "softflowd"} {
		if !strings.Contains(job, want) {
			t.Errorf("the setup-snippets job lacks %q", want)
		}
	}
}
