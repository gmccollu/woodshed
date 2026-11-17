//go:build !windows

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
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
//   - softflowd: flow v9 and IPFIX, replaying the flow interop test's
//     synthetic pcap (writePcap) with -r in place of the snippet's -i, each
//     flow stored once with the pcap's packet and byte counts.
//
// Each snippet comes from the server's own POST /api/setup/snippet, so it's
// filled from the live settings. The test writes each "file" part where the
// tool reads it (in a temporary folder), fills the placeholders the way a
// user would, and runs the "command" parts. It never runs as root, binds only
// high ports on loopback, and stops every process it starts by PID.
//
// It runs only with WOODSHED_SETUP_INTEROP=1 (the CI job "setup-snippets"
// installs rsyslog, its TLS driver, snmpd, snmp and softflowd; the pcap is
// written in Go, so no capture tool is needed).
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
		if c.variant != "" {
			name += "/" + c.variant
		}
		t.Run(name, func(t *testing.T) {
			if len(only) > 0 && !only[c.family] {
				t.Skip("not in WOODSHED_SETUP_INTEROP_ONLY")
			}
			if c.skip != "" {
				summary = append(summary, "- skipped "+name+": "+c.skip)
				t.Skip(c.skip)
			}
			note := setupRunners[c.family+"/"+c.what](t, c)
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
// (and so doesn't make its template Tested). variant is "" (the defaults over
// IPv4), "ipv6" (Woodshed on ::1, the snippet for ::1), "choices"
// (non-default choices: severity and facility, or SHA-1 and a user name) or
// "full-queue" (rsyslog with Woodshed down until the queue fills).
type setupCase struct {
	family, what, transport string
	variant                 string
	skip                    string
}

// setupInteropCases: one line per case, in a form internal/setuphelper's
// TestNoVendorNames also reads (family: "…", what: "…", transport: "…").
var setupInteropCases = []setupCase{
	{family: "rsyslog", what: "syslog", transport: "udp"},
	{family: "rsyslog", what: "syslog", transport: "tcp"},
	{family: "rsyslog", what: "syslog", transport: "tls"},
	{family: "rsyslog", what: "syslog", transport: "tcp", variant: "ipv6"},
	{family: "rsyslog", what: "syslog", transport: "udp", variant: "choices"},
	{family: "rsyslog", what: "syslog", transport: "tcp", variant: "full-queue"},
	{family: "rsyslog", what: "syslog", transport: "tls", variant: "full-queue"},
	{family: "net-snmp", what: "trap", transport: "v2c"},
	{family: "net-snmp", what: "trap", transport: "v3"},
	{family: "net-snmp", what: "trap", transport: "v2c", variant: "ipv6"},
	{family: "net-snmp", what: "trap", transport: "v3", variant: "choices"},
	{family: "net-snmp", what: "poll", transport: "v2c"},
	{family: "net-snmp", what: "poll", transport: "v3"},
	{family: "net-snmp", what: "poll", transport: "v2c", variant: "ipv6"},
	{family: "net-snmp", what: "poll", transport: "v3", variant: "choices"},
	{family: "softflowd", what: "flow", transport: "v9"},
	{family: "softflowd", what: "flow", transport: "ipfix"},
	{family: "softflowd", what: "flow", transport: "ipfix", variant: "ipv6"},
}

// caseAddr is the address Woodshed listens on, and the snippet sends to.
func caseAddr(c setupCase) string {
	if c.variant == "ipv6" {
		return "::1"
	}
	return "127.0.0.1"
}

// hostPort is net.JoinHostPort for a port number.
func hostPort(addr string, port int) string { return net.JoinHostPort(addr, fmt.Sprint(port)) }

// setupRunners apply one family and data type's snippet; each returns a note
// for the summary.
var setupRunners = map[string]func(t *testing.T, c setupCase) string{
	"rsyslog/syslog": runRsyslog,
	"net-snmp/trap":  runSnmpTrap,
	"net-snmp/poll":  runSnmpPoll,
	"softflowd/flow": runSoftflowd,
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
	r                 *running
	dir, cfgPath      string
	snmpPort, tcpPort int
}

// newSetupEnv starts a server whose syslog, TLS and trap listeners are on
// addr (127.0.0.1 or ::1).
func newSetupEnv(t *testing.T, addr string) *setupEnv {
	t.Helper()
	dir := t.TempDir()
	snmpPort, tlsPort, port := freeUDP(t), freePort(t), freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, func(c *config.Config) {
		c.Listeners.UDP.Addr, c.Listeners.TCP.Addr = addr, addr
		c.Listeners.TLS = config.TLSListener{Enabled: true, Addr: addr, Port: tlsPort}
		c.Listeners.SNMP = config.SNMPListener{Enabled: true, Addr: addr, Port: snmpPort, AnswerInforms: true}
	})
	return &setupEnv{r: start(t, cfgPath), dir: dir, cfgPath: cfgPath, snmpPort: snmpPort, tcpPort: port}
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

func runRsyslog(t *testing.T, c setupCase) string {
	bin := tool(t, "rsyslogd")
	addr := caseAddr(c)
	e := newSetupEnv(t, addr)
	req := map[string]any{"family": "rsyslog", "what": "syslog", "transport": c.transport, "address": addr}
	if c.variant == "choices" {
		req["severity"], req["facility"] = "warning", "local4"
	}
	s := e.snippet(t, req)
	values := map[string]string{}
	if c.transport == "tls" {
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
	// for the test messages, a local file every message goes to (the "local
	// logging" a full queue mustn't hold up), and the snippet, included as the
	// distribution's rsyslog.conf includes /etc/rsyslog.d/*.conf.
	work := filepath.Join(e.dir, "work")
	os.MkdirAll(work, 0o755)
	inPort := freeUDP(t)
	local := filepath.Join(e.dir, "local.log")
	conf := filepath.Join(e.dir, "rsyslog.conf")
	os.WriteFile(conf, []byte(fmt.Sprintf("global(workDirectory=%q)\nmodule(load=\"imudp\")\ninput(type=\"imudp\" address=\"127.0.0.1\" port=\"%d\")\n"+
		"*.* action(type=\"omfile\" file=%q)\ninclude(file=%q)\n", work, inPort, local, snippetFile)), 0o644)
	env := append(os.Environ(), "HOME="+e.dir)
	// The snippet's own check first: rsyslogd -N1.
	if out, err := exec.Command(bin, "-N1", "-f", conf).CombinedOutput(); err != nil {
		t.Fatalf("rsyslogd -N1 refused the snippet: %v\n%s", err, out)
	}
	if c.variant == "full-queue" {
		e.r.stop(t) // Woodshed is down from the start
	}
	p := startProc(t, filepath.Join(e.dir, "rsyslogd.log"), env, bin, "-n", "-f", conf, "-i", filepath.Join(e.dir, "rsyslogd.pid"))
	udpHeld(t, inPort, p)
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", inPort))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// pri is facility*8 + severity: 14 user.info, 164 local4.warning.
	send := func(pri int, text string) {
		fmt.Fprintf(conn, "<%d>%s setup-test woodshed-test: %s", pri, time.Now().Format(time.Stamp), text)
	}
	token := func(what string) string {
		return fmt.Sprintf("wsetup-%s-%s-%d", c.transport, what, time.Now().UnixNano())
	}

	switch c.variant {
	case "choices":
		// local4.warning and above only: local4.info and user.err stay local.
		want, low, other := token("want"), token("info"), token("user")
		send(166, "too low "+low)
		send(11, "other facility "+other)
		send(164, "Test message for Woodshed "+want)
		e.exactlyOnce(t, "rsyslog local4.warning", "syslog", url.Values{"q": {want}})
		for _, x := range []string{low, other} {
			if n := e.count(t, "syslog", url.Values{"q": {x}}); n != 0 {
				t.Errorf("%s was forwarded (%d), but the snippet's filter is local4.warning", x, n)
			}
		}
	case "full-queue":
		// More than the queue holds (10,000), through logger when it's there,
		// paced so loopback UDP keeps them all. With queue.timeoutEnqueue="0"
		// the overflow is dropped for Woodshed at once; without it each one
		// would hold every action for 2 s and local logging would stall.
		const n = 15000
		lines := make([]string, n)
		for i := range lines {
			lines[i] = fmt.Sprintf("fill %d", i)
		}
		pushed := time.Now()
		if lg, err := exec.LookPath("logger"); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			cmd := exec.CommandContext(ctx, lg, "--udp", "--server", "127.0.0.1", "--port", fmt.Sprint(inPort), "-p", "user.info", "-t", "setup-test")
			in, _ := cmd.StdinPipe()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			for i, l := range lines {
				fmt.Fprintln(in, l)
				if i%100 == 99 {
					time.Sleep(time.Millisecond)
				}
			}
			in.Close()
			if err := cmd.Wait(); err != nil {
				t.Fatalf("logger: %v (blocked: %v)", err, ctx.Err() != nil)
			}
			cancel()
		} else {
			for i, l := range lines {
				send(14, l)
				if i%100 == 99 {
					time.Sleep(time.Millisecond)
				}
			}
		}
		marker := token("local")
		send(14, "local marker "+marker)
		deadline := time.Now().Add(30 * time.Second)
		var got []byte
		for time.Now().Before(deadline) {
			got, _ = os.ReadFile(local)
			if bytes.Contains(got, []byte(marker)) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if !bytes.Contains(got, []byte(marker)) {
			t.Fatalf("local logging stalled with Woodshed down: no marker after 30 s (%d lines written)", bytes.Count(got, []byte("\n")))
		}
		if m := bytes.Count(got, []byte("fill ")); m <= 10000 {
			t.Fatalf("only %d of %d messages reached the local file", m, n)
		}
		t.Logf("%d messages pushed and written locally in %v with Woodshed down", n, time.Since(pushed).Round(time.Millisecond))
		// Woodshed back: later messages arrive (rsyslog retries every 30 s).
		e.r = start(t, e.cfgPath)
		after := token("after")
		send(14, "Test message for Woodshed "+after)
		deadline = time.Now().Add(150 * time.Second)
		for e.count(t, "syslog", url.Values{"q": {after}}) == 0 && time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
		}
		e.exactlyOnce(t, "rsyslog after Woodshed came back", "syslog", url.Values{"q": {after}})
	default:
		tok := token("msg")
		send(14, "Test message for Woodshed "+tok) // user.info, as the snippet's logger test sends
		e.exactlyOnce(t, "rsyslog "+c.transport+" "+addr, "syslog", url.Values{"q": {tok}})
	}
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

func (e *setupEnv) addUser(t *testing.T, name, auth string) {
	t.Helper()
	in := map[string]any{"name": name, "auth": auth, "priv": "aes-128", "auth_pass": setupAuthPass, "priv_pass": setupPrivPass}
	if code := e.r.do(t, "POST", "/api/snmp/users", in, nil); code != 201 {
		t.Fatalf("add user: %d", code)
	}
}

var snmpSecrets = map[string]string{"<COMMUNITY>": setupCommunity, "<AUTH-PASSPHRASE>": setupAuthPass, "<PRIV-PASSPHRASE>": setupPrivPass}

// v3For is the v3 user and protocol a case sends: the defaults (SHA-256 when
// the tools have it), or for "choices" SHA-1 and a user name of its own.
func v3For(t *testing.T, c setupCase, env []string) (user, auth, note string) {
	if c.variant == "choices" {
		return "choiceuser", "sha", " (SHA-1, user choiceuser)"
	}
	auth, note = v3Auth(t, env)
	return setupUser, auth, note
}

// netSNMPAddr is the snippet's transport address for addr and port.
func netSNMPAddr(addr string, port int) string {
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("udp6:[%s]:%d", addr, port)
	}
	return fmt.Sprintf("udp:%s:%d", addr, port)
}

func runSnmpTrap(t *testing.T, c setupCase) string {
	snmpd, snmptrap := tool(t, "snmpd"), tool(t, "snmptrap", "/usr/bin")
	addr := caseAddr(c)
	e := newSetupEnv(t, addr)
	env, confDir, home := snmpEnv(e.dir)
	req := map[string]any{"family": "net-snmp", "what": "trap", "transport": c.transport, "address": addr}
	note, user := "", ""
	if c.transport == "v3" {
		var auth string
		user, auth, note = v3For(t, c, env)
		req["v3_user"], req["auth"] = user, auth
		e.addUser(t, user, auth)
	}
	s := e.snippet(t, req)
	if want := netSNMPAddr(addr, e.snmpPort); !strings.Contains(s.Text, want) {
		t.Fatalf("the snippet doesn't send to %s", want)
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
	e.exactlyOnce(t, "snmpd's coldStart ("+c.transport+")", "trap", url.Values{"trap_oid": {"1.3.6.1.6.3.1.1.5.1"}})

	// The snippet's test trap, run as written (by a shell, for its $(hostname)).
	cmdText := part(t, s, setuphelper.PartCommand, "test trap").Text
	sh := exec.Command("sh", "-c", strings.Replace(cmdText, "snmptrap ", snmptrap+" ", 1))
	sh.Env = env
	if out, err := sh.CombinedOutput(); err != nil {
		t.Fatalf("the test trap command failed: %v\n%s", err, out)
	}
	e.exactlyOnce(t, "snmptrap's test trap ("+c.transport+")", "trap", url.Values{"q": {"Test trap for Woodshed"}})
	// Each with the version (and, for v3, the user) the snippet set up.
	var page struct {
		Results []struct {
			Fields map[string]any `json:"fields"`
		} `json:"results"`
	}
	e.r.do(t, "GET", "/api/search?type=trap&limit=50", nil, &page)
	for _, r := range page.Results {
		if r.Fields["status"] != "ok" || (c.transport == "v3" && r.Fields["cred"] != user) || (c.transport == "v2c" && r.Fields["version"] != "2c") {
			t.Errorf("a trap stored as %v", r.Fields)
		}
	}
	return note
}

// distroSnmpdConf is an snmpd.conf as distributions ship it: the agent on
// loopback only. The poll snippet's instructions are to replace its
// agentaddress line and add the rest; leaving the line would also keep port
// 161, which this unprivileged test can't bind, so snmpd wouldn't start.
const distroSnmpdConf = `# As shipped: listen on loopback only.
agentaddress 127.0.0.1,[::1]
sysLocation lab rack 3
sysContact admin@example.net
`

// applySnmpdParts edits base as the poll snippet's parts say: a part titled
// "Replace the existing agentaddress line" replaces it (every agentaddress
// line goes), the others are added at the end.
func applySnmpdParts(t *testing.T, base string, s setuphelper.Snippet) string {
	t.Helper()
	conf := base
	replaced := false
	for _, p := range s.Parts {
		if p.Kind != setuphelper.PartFile || !strings.HasSuffix(p.Path, "snmpd.conf") {
			continue
		}
		text := fill(t, p.Text, snmpSecrets)
		if strings.HasPrefix(p.Title, "Replace the existing agentaddress line") {
			var kept []string
			for _, l := range strings.Split(conf, "\n") {
				if f := strings.Fields(l); len(f) > 0 && strings.EqualFold(f[0], "agentaddress") {
					if !replaced {
						kept = append(kept, strings.TrimRight(text, "\n"))
						replaced = true
					}
					continue
				}
				kept = append(kept, l)
			}
			conf = strings.Join(kept, "\n")
			if !replaced {
				conf += text
				replaced = true
			}
			continue
		}
		conf += text
	}
	if !replaced {
		t.Fatal("the poll snippet has no agentaddress line to put in place of the distribution's")
	}
	if n := strings.Count(strings.ToLower(conf), "agentaddress"); n != 1 {
		t.Fatalf("%d agentaddress lines after applying the snippet:\n%s", n, conf)
	}
	return conf
}

func runSnmpPoll(t *testing.T, c setupCase) string {
	snmpd := tool(t, "snmpd")
	addr := caseAddr(c)
	e := newSetupEnv(t, addr)
	env, confDir, _ := snmpEnv(e.dir)
	agentPort := freeUDP(t)
	req := map[string]any{"family": "net-snmp", "what": "poll", "transport": c.transport, "address": addr, "agent_port": agentPort}
	note, user, auth := "", "", ""
	if c.transport == "v3" {
		user, auth, note = v3For(t, c, env)
		req["v3_user"], req["auth"] = user, auth
	}
	s := e.snippet(t, req)
	if c.variant == "ipv6" && !strings.Contains(s.Text, "rocommunity6 <COMMUNITY> ::1") {
		t.Fatalf("an IPv6 address needs rocommunity6:\n%s", s.Text)
	}
	os.WriteFile(filepath.Join(confDir, "snmpd.conf"), []byte(applySnmpdParts(t, distroSnmpdConf, s)), 0o600)
	p := startProc(t, filepath.Join(e.dir, "snmpd.log"), env, snmpd, "-f", "-Lf", filepath.Join(e.dir, "snmpd.log"), "-p", filepath.Join(e.dir, "snmpd.pid"))
	udpHeld(t, agentPort, p)

	// The shortest interval (30 s), so the first cycle comes soon.
	target := map[string]any{"address": addr, "port": agentPort, "version": "2c", "community": setupCommunity, "interval_s": 30}
	if c.transport == "v3" {
		e.addUser(t, user, auth)
		target = map[string]any{"address": addr, "port": agentPort, "version": "3", "v3_user": user, "interval_s": 30}
	}
	var created struct {
		ID string `json:"id"`
	}
	if code := e.r.do(t, "POST", "/api/poll/targets", target, &created); code != 201 {
		t.Fatalf("add poll target: %d", code)
	}
	// The form's Test poll, then the first scheduled cycle.
	var res struct {
		Exit string `json:"exit"`
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

// ---- softflowd ----

// runSoftflowd applies the softflowd snippet to a server whose flow listener
// is on, from its own settings (POST /api/setup/snippet picks the port per
// version). On a CI runner there's no traffic to watch, so the snippet's
// "-i <INTERFACE>" becomes "-r <the synthetic pcap>" and "-d" keeps softflowd
// in the foreground until the file is done; every other option is the
// snippet's own.
func runSoftflowd(t *testing.T, c setupCase) string {
	transport := c.transport
	bin := tool(t, "softflowd")
	addr := caseAddr(c)
	r, flowPort, ipfixPort := flowServer(t, func(cf *config.Config) { cf.Listeners.Flow.Addr = addr })
	e := &setupEnv{r: r, dir: t.TempDir()}
	s := e.snippet(t, map[string]any{"family": "softflowd", "what": "flow", "transport": transport, "address": addr})
	port, ver := flowPort, uint8(flow.V9)
	if transport == "ipfix" {
		port, ver = ipfixPort, flow.IPFIX
	}
	cmdText := strings.TrimSpace(part(t, s, setuphelper.PartCommand, "Run softflowd").Text)
	if want := "-n " + hostPort(addr, port) + " "; !strings.Contains(cmdText, want) || !strings.Contains(cmdText, "-i <INTERFACE>") {
		t.Fatalf("the snippet doesn't send to the server's %s port %d: %s", transport, port, cmdText)
	}
	pcap := filepath.Join(e.dir, "synthetic.pcap")
	want := writePcap(t, pcap, time.Now().Add(-10*time.Minute).Truncate(time.Second))
	args := strings.Fields(strings.Replace(cmdText, "-i <INTERFACE>", "-r "+pcap, 1))
	if args[0] != "softflowd" {
		t.Fatalf("the command doesn't start with softflowd: %s", cmdText)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, append(args[1:], "-d")...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s -d: %v\n%s", strings.Join(args, " "), err, out)
	}
	var total uint64
	for _, f := range want {
		total += f.packets
	}
	// Exactly once: every flow with the pcap's own counts (a duplicate would
	// double them), the same after 3 s more, and no record of another version.
	check := func() (map[tuple]*pcapFlow, uint64, int) {
		r.srv.be.store.Flush()
		all := storedByVersion(t, r)
		got := all[ver]
		var n uint64
		for _, f := range got {
			n += f.packets
		}
		return got, n, len(all)
	}
	deadline := time.Now().Add(45 * time.Second)
	got, n, versions := check()
	for n < total && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		got, n, versions = check()
	}
	time.Sleep(3 * time.Second)
	got, n, versions = check()
	if n != total || versions != 1 || len(got) != len(want) {
		flowDiag(t, r, netip.MustParseAddr(addr), func(dst string) *exec.Cmd {
			a := slices.Clone(args[1:])
			for i := range a {
				if a[i] == "-n" && i+1 < len(a) {
					a[i+1] = dst
				}
			}
			return exec.Command(bin, append(a, "-d")...)
		})
		t.Fatalf("%s: %d packets in %d flows (%d versions) stored, the pcap has %d packets in %d flows", transport, n, len(got), versions, total, len(want))
	}
	for _, f := range want {
		if g := got[f.tuple]; g == nil || g.packets != f.packets || g.bytes != f.bytes {
			t.Errorf("%s %v: stored %+v, the pcap has %d packets, %d bytes", transport, f.tuple, g, f.packets, f.bytes)
		}
	}
	ver2, _ := exec.Command(bin, "-h").CombinedOutput()
	return " (" + strings.SplitN(strings.TrimSpace(string(ver2)), "\n", 2)[0] + ")"
}
