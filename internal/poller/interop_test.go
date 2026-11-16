package poller

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// TestPollInterop polls the distribution's net-snmp snmpd (SPEC §12.8): on a
// high port on loopback, with a generated snmpd.conf holding the community and
// the v3 users (secrets in the file, never on a command line), it polls v1,
// v2c, and v3 at noAuthNoPriv, each auth with noPriv, each priv with SHA-256,
// and MD5 with DES; checks discovery, real loopback counters with traffic, and
// HOST-RESOURCES; then restarts snmpd and expects a restart marker (with
// engineBoots up for v3).
//
// It runs only with WOODSHED_SNMP_POLL_INTEROP=1 and snmpd on PATH (the CI job
// "snmp-poll-interop" installs it; net-snmp is never a dependency). Protocols
// the build lacks are skipped and listed; WOODSHED_SNMP_POLL_INTEROP_REQUIRE
// ("sha-256,aes-128,…", and "engineboots" for the restart's boots) makes a
// missing one a failure.
func TestPollInterop(t *testing.T) {
	if os.Getenv("WOODSHED_SNMP_POLL_INTEROP") == "" {
		t.Skip("set WOODSHED_SNMP_POLL_INTEROP=1 to poll net-snmp's snmpd")
	}
	bin, err := exec.LookPath("snmpd")
	if err != nil {
		for _, p := range []string{"/usr/sbin/snmpd", "/usr/local/sbin/snmpd"} {
			if _, err := os.Stat(p); err == nil {
				bin = p
			}
		}
	}
	if bin == "" {
		t.Fatal("snmpd isn't on PATH")
	}
	d := newSnmpd(t, bin)
	var skipped, passed []string
	required := map[string]bool{}
	for _, p := range strings.Split(os.Getenv("WOODSHED_SNMP_POLL_INTEROP_REQUIRE"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			required[p] = true
		}
	}
	defer func() {
		summary := fmt.Sprintf("snmp poll interop (%s): %d passed: %s\nskipped: %s\n", d.version, len(passed),
			strings.Join(passed, ", "), strings.Join(skipped, "; "))
		t.Log(summary)
		if f := os.Getenv("GITHUB_STEP_SUMMARY"); f != "" {
			if fh, err := os.OpenFile(f, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644); err == nil {
				fmt.Fprintf(fh, "### SNMP poll interop\n\n```\n%s```\n", summary)
				fh.Close()
			}
		}
	}()

	// Traffic on loopback while polling, so the counters move.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		c, err := net.Dial("udp", "127.0.0.1:9")
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 1000)
		for {
			select {
			case <-stop:
				return
			default:
			}
			c.Write(buf)
			time.Sleep(time.Millisecond)
		}
	}()

	for _, c := range d.combos {
		name := c.name
		if !d.supported(c) {
			if required[c.authName] || required[c.privName] {
				t.Errorf("%s: required, but this snmpd lacks it", name)
			}
			skipped = append(skipped, name+" (not in this snmpd)")
			continue
		}
		ls, err := d.poll(t, c, 2)
		if err != "" && c.priv == snmp.PrivDES && !required["des"] {
			skipped = append(skipped, name+" (DES failed in this build: "+err+")")
			continue
		}
		if err != "" {
			t.Errorf("%s: %s", name, err)
			continue
		}
		if msg := checkInteropLines(ls); msg != "" {
			t.Errorf("%s: %s", name, msg)
			continue
		}
		passed = append(passed, name)
	}

	// A restart of snmpd: a restart marker; for v3 engineBoots went up too.
	restartCombo := d.byName("v3 sha-256/aes-128")
	if !d.supported(restartCombo) {
		restartCombo = d.byName("v3 sha")
	}
	for _, c := range []interopCombo{d.combos[1], restartCombo} {
		if c.name == "" || !d.supported(c) {
			continue
		}
		h := d.harness(t, c)
		h.cycle()
		before := fmt.Sprintf("%s boots %d", h.p.States()["pt_1"].EngineID, h.st.sess.Engine().Boots)
		d.restart(t)
		time.Sleep(6 * time.Second)
		ls := h.cycle()
		if len(ls) == 1 && ls[0].rec.Kind == pollrec.KindStatus {
			ls = h.cycle() // the first request after a restart may race the new snmpd's start
		}
		r := find(ls, pollrec.KindRestart, nil)
		switch {
		case r == nil:
			t.Errorf("%s: no restart marker after an snmpd restart: %+v", c.name, ls)
		case c.version == "3" && !strings.Contains(r.Value("source"), "engineBoots") && d.agentBoots(c) <= 1:
			// This build didn't raise its own engineBoots (net-snmp 5.6 on macOS
			// doesn't keep it across a restart): nothing for the poller to see.
			if required["engineboots"] {
				t.Errorf("%s: required, but snmpd didn't raise engineBoots across the restart", c.name)
			}
			skipped = append(skipped, c.name+" engineBoots (this snmpd didn't raise it)")
			passed = append(passed, c.name+" restart (sysUpTime)")
		case c.version == "3" && !strings.Contains(r.Value("source"), "engineBoots"):
			persisted, _ := os.ReadFile(filepath.Join(d.dir, "persist", "snmpd.conf"))
			t.Errorf("%s: engineBoots didn't go up: %+v (engine %s, then %s; persisted state:\n%s)", c.name, r, before,
				fmt.Sprintf("%s boots %d", h.p.States()["pt_1"].EngineID, h.st.sess.Engine().Boots), redactPersist(persisted))
		case r.Value("reboot") == "1":
			t.Errorf("%s: an snmpd restart called a reboot: %+v", c.name, r)
		default:
			passed = append(passed, c.name+" restart")
		}
	}
}

// checkInteropLines checks one combination's two cycles.
func checkInteropLines(ls []line) string {
	sys := find(ls, pollrec.KindSys, func(r *pollrec.Record) bool { return r.Cycle == 2 })
	if sys == nil || sys.Value("uptime") == "" {
		return fmt.Sprintf("no sys line with uptime: %+v", ls)
	}
	if runtime.GOOS == "linux" && (sys.Value("hr_uptime") == "" || sys.Value("mem_total") == "") {
		return fmt.Sprintf("no HOST-RESOURCES uptime or memory: %+v", sys)
	}
	lo := find(ls, pollrec.KindIf, func(r *pollrec.Record) bool {
		return r.Cycle == 2 && (strings.HasPrefix(r.Value("name"), "lo"))
	})
	if lo == nil {
		return "no loopback interface line"
	}
	if lo.Value("in_octets") == "" || lo.Value("in_bps") == "" {
		return fmt.Sprintf("loopback without counters or a rate: %+v", lo)
	}
	if v, ok := lo.Float("in_bps"); !ok || v <= 0 {
		return fmt.Sprintf("loopback rate %q with traffic on it", lo.Value("in_bps"))
	}
	return ""
}

type interopCombo struct {
	name, version, user string
	auth                snmp.AuthProtocol
	priv                snmp.PrivProtocol
	authName, privName  string // our names, for REQUIRE
	nsAuth, nsPriv      string // net-snmp's
}

type snmpd struct {
	bin, dir, conf, logFile string
	port                    int
	cmd                     *exec.Cmd
	combos                  []interopCombo
	version                 string
	env                     []string
}

const (
	interopComm     = "poll-interop-community"
	interopAuthPass = "poll-interop-auth-pass"
	interopPrivPass = "poll-interop-priv-pass"
)

func newSnmpd(t *testing.T, bin string) *snmpd {
	t.Helper()
	dir := t.TempDir()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	d := &snmpd{bin: bin, dir: dir, conf: filepath.Join(dir, "snmpd.conf"), logFile: filepath.Join(dir, "snmpd.log"), port: port}
	if err := os.MkdirAll(filepath.Join(dir, "persist"), 0o700); err != nil {
		t.Fatal(err)
	}
	// SNMPCONFPATH replaces the whole search path, the persistent folder
	// included, so it's listed too: without it snmpd writes engineBoots there at
	// stop but never reads it back, and boots never rise across a restart.
	persist := filepath.Join(dir, "persist")
	d.env = append(os.Environ(), "SNMP_PERSISTENT_DIR="+persist, "SNMPCONFPATH="+dir+string(os.PathListSeparator)+persist, "HOME="+dir,
		"MIBS=", "MIBDIRS="+dir)
	out, _ := exec.Command(bin, "-v").CombinedOutput()
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(l, "version:") {
			d.version = strings.TrimSpace(l)
		}
	}
	add := func(c interopCombo) { d.combos = append(d.combos, c) }
	add(interopCombo{name: "v1", version: "1"})
	add(interopCombo{name: "v2c", version: "2c"})
	add(interopCombo{name: "v3 noAuthNoPriv", version: "3", user: "u-none"})
	for _, a := range []struct {
		p      snmp.AuthProtocol
		ns     string
		suffix string
	}{{snmp.AuthMD5, "MD5", "md5"}, {snmp.AuthSHA1, "SHA", "sha"}, {snmp.AuthSHA224, "SHA-224", "sha-224"}, {snmp.AuthSHA256, "SHA-256", "sha-256"},
		{snmp.AuthSHA384, "SHA-384", "sha-384"}, {snmp.AuthSHA512, "SHA-512", "sha-512"}} {
		add(interopCombo{name: "v3 " + a.suffix, version: "3", user: "u-" + a.suffix, auth: a.p, authName: a.suffix, nsAuth: a.ns})
	}
	for _, p := range []struct {
		p      snmp.PrivProtocol
		ns     string
		suffix string
	}{{snmp.PrivDES, "DES", "des"}, {snmp.PrivAES128, "AES", "aes-128"}, {snmp.PrivAES192, "AES192", "aes-192"}, {snmp.PrivAES256, "AES256", "aes-256"}} {
		add(interopCombo{name: "v3 sha-256/" + p.suffix, version: "3", user: "u-sha256-" + p.suffix, auth: snmp.AuthSHA256, priv: p.p,
			authName: "sha-256", privName: p.suffix, nsAuth: "SHA-256", nsPriv: p.ns})
	}
	add(interopCombo{name: "v3 md5/des", version: "3", user: "u-md5-des", auth: snmp.AuthMD5, priv: snmp.PrivDES, authName: "md5",
		privName: "des", nsAuth: "MD5", nsPriv: "DES"})

	var b strings.Builder
	// A fixed engine ID (some builds make a random one at each start), so a
	// restart is the same engine with engineBoots up.
	fmt.Fprintf(&b, "agentaddress udp:127.0.0.1:%d\nengineID woodshed-poll-interop\nrocommunity %s 127.0.0.1\n", port, interopComm)
	for _, c := range d.combos {
		if c.version != "3" {
			continue
		}
		switch {
		case c.auth == snmp.AuthNone:
			fmt.Fprintf(&b, "createUser %s\nrouser %s noauth\n", c.user, c.user)
		case c.priv == snmp.PrivNone:
			fmt.Fprintf(&b, "createUser %s %s %s\nrouser %s auth\n", c.user, c.nsAuth, interopAuthPass, c.user)
		default:
			fmt.Fprintf(&b, "createUser %s %s %s %s %s\nrouser %s priv\n", c.user, c.nsAuth, interopAuthPass, c.nsPriv, interopPrivPass, c.user)
		}
	}
	if err := os.WriteFile(d.conf, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	d.start(t)
	t.Cleanup(func() { d.stop() })
	return d
}

func (d *snmpd) start(t *testing.T) {
	t.Helper()
	// No -C: with SNMPCONFPATH set to the test's folder, snmpd reads only its
	// snmpd.conf there and its own persistent folder (where engineBoots is kept
	// across a restart), never the system's config.
	d.cmd = exec.Command(d.bin, "-f", "-Lf", d.logFile, "-p", filepath.Join(d.dir, "snmpd.pid"))
	d.cmd.Env = d.env
	if err := d.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait until it answers.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		res := StandaloneTest(context.Background(), Settings{Address: "127.0.0.1", Port: d.port, Version: "2c", TimeoutMS: 300,
			Presets: []string{config.PresetSystemInfo}, Interfaces: Interfaces{All: true}}, []byte(interopComm), nil)
		if res.Exit == ExitOK {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	log, _ := os.ReadFile(d.logFile)
	t.Fatalf("snmpd didn't answer on port %d; its log:\n%s", d.port, log)
}

func (d *snmpd) stop() {
	if d.cmd != nil && d.cmd.Process != nil {
		d.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { d.cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			d.cmd.Process.Kill()
			<-done
		}
		d.cmd = nil
	}
}

func (d *snmpd) restart(t *testing.T) {
	d.stop()
	d.start(t)
}

func (d *snmpd) byName(n string) interopCombo {
	for _, c := range d.combos {
		if c.name == n {
			return c
		}
	}
	return interopCombo{}
}

// supported reports whether this snmpd has the user's protocols. SHA-2 and
// AES-192/256 came in net-snmp 5.8; an older snmpd accepts their createUser
// lines without a word and then fails or ignores the requests, so it's decided
// by the version.
func (d *snmpd) supported(c interopCombo) bool {
	if c.version != "3" || c.auth == snmp.AuthNone {
		return true
	}
	var major, minor int
	fmt.Sscanf(strings.TrimSpace(strings.TrimPrefix(d.version, "NET-SNMP version:")), "%d.%d", &major, &minor)
	if major > 5 || (major == 5 && minor >= 8) {
		return true
	}
	return (c.auth == snmp.AuthMD5 || c.auth == snmp.AuthSHA1) && (c.priv == snmp.PrivNone || c.priv == snmp.PrivDES || c.priv == snmp.PrivAES128)
}

func (d *snmpd) settings(c interopCombo) Settings {
	s := defaultSettings()
	s.Port, s.Version, s.V3User, s.TimeoutMS, s.Retries = d.port, c.version, c.user, 2000, 1
	return s
}

func (d *snmpd) user(c interopCombo) *snmp.User {
	if c.version != "3" {
		return nil
	}
	u := snmp.User{Name: c.user, Auth: c.auth, Priv: c.priv}
	if c.auth != snmp.AuthNone {
		u.AuthPass = []byte(interopAuthPass)
	}
	if c.priv != snmp.PrivNone {
		u.PrivPass = []byte(interopPrivPass)
	}
	u.Level = u.MaxLevel()
	return &u
}

// harness polls snmpd with the real clock.
func (d *snmpd) harness(t *testing.T, c interopCombo) *harness {
	t.Helper()
	sink := &memSink{}
	creds := &memCreds{comm: map[string][]byte{"pt_1": []byte(interopComm)}, users: map[string]snmp.User{}}
	if u := d.user(c); u != nil {
		creds.users[u.Name] = *u
	}
	p := New(Options{Sink: sink, Creds: creds})
	t.Cleanup(p.Close)
	p.SetTargets([]Target{{ID: "pt_1", Settings: d.settings(c)}})
	p.mu.Lock()
	st := p.targets["pt_1"]
	p.mu.Unlock()
	st.mu.Lock()
	st.nextDue = time.Now().Add(1000 * time.Hour)
	st.mu.Unlock()
	return &harness{t: t, p: p, sink: sink, st: st}
}

// poll runs n cycles 6 s apart and returns their lines.
func (d *snmpd) poll(t *testing.T, c interopCombo, n int) ([]line, string) {
	h := d.harness(t, c)
	var all []line
	for i := 0; i < n; i++ {
		if i > 0 {
			time.Sleep(6 * time.Second) // snmpd caches ifTable for a few seconds
		}
		ls := h.cycle()
		if len(ls) == 1 && ls[0].rec.Kind == pollrec.KindStatus {
			return nil, ls[0].rec.Value("status") + ": " + ls[0].rec.Value("detail")
		}
		all = append(all, ls...)
	}
	return all, ""
}

// redactPersist keeps only snmpd's engine lines of its persistent file (never
// the users' keys).
func redactPersist(b []byte) string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "engineBoots") || strings.HasPrefix(l, "oldEngineID") || strings.HasPrefix(l, "setserialno") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// agentBoots is snmpd's engineBoots now, from a fresh discovery.
func (d *snmpd) agentBoots(c interopCombo) int64 {
	res := StandaloneTest(context.Background(), d.settings(c), nil, d.user(c))
	for _, st := range res.Steps {
		if st.Step == "discovery" {
			var boots int64
			if i := strings.Index(st.Detail, "boots "); i >= 0 {
				fmt.Sscanf(st.Detail[i+6:], "%d", &boots)
			}
			return boots
		}
	}
	return 0
}
