package snmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestInterop sends traps and informs with net-snmp's command-line tools to a
// test listener built on this codec (SPEC §11.6): v1 and v2c, v2c informs, and
// v3 traps and informs at every level and protocol combination the tools offer.
// It runs only with WOODSHED_SNMP_INTEROP=1 and snmptrap on PATH (the CI job
// "snmp interop" installs the distribution's snmp package; net-snmp is never a
// dependency).
//
// Passphrases and the community go in a temporary snmp.conf (the tools'
// defCommunity, defAuthPassphrase and defPrivPassphrase), never on the command
// line. They're fixed test values, so the datagrams the run logs for the
// AES-192/256 key-extension cases are reproducible vectors.
//
// WOODSHED_SNMP_INTEROP_REQUIRE lists protocols that must be offered (for
// example "md5,sha,aes-128"); a missing one fails the test instead of skipping
// its cases. The support matrix and the skips are logged, and appended to
// $GITHUB_STEP_SUMMARY when it's set.
func TestInterop(t *testing.T) {
	if os.Getenv("WOODSHED_SNMP_INTEROP") == "" {
		t.Skip("set WOODSHED_SNMP_INTEROP=1 to run against net-snmp's tools")
	}
	for _, tool := range []string{"snmptrap", "snmpinform"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Fatalf("%s isn't on PATH", tool)
		}
	}
	h := newInteropHarness(t)
	defer h.summary(t)

	// v1 and v2c.
	h.run(t, "v1 trap", StatusOK, []string{"snmptrap", "-v", "1", h.addr, testEnterprise.String(), "127.0.0.1", "6", "17", ""}, V1, nil)
	h.run(t, "v2c trap", StatusOK, []string{"snmptrap", "-v", "2c", h.addr, "", testTrapOID.String()}, V2c, nil)
	h.run(t, "v2c inform", StatusOK, []string{"snmpinform", "-v", "2c", "-r", "1", "-t", "3", h.addr, "", testTrapOID.String()}, V2c, nil)

	// v3: every combination, as a trap and as an inform.
	for _, c := range allCombos() {
		args, ok := h.v3Args(t, c, c.name())
		if !ok {
			continue
		}
		eid := hex.EncodeToString(NewEngineID())
		h.run(t, c.name()+" trap", StatusOK, append([]string{"snmptrap", "-v", "3", "-e", eid}, append(args, h.addr, "", testTrapOID.String())...), V3, &c)
		h.run(t, c.name()+" inform", StatusOK, append([]string{"snmpinform", "-v", "3", "-r", "1", "-t", "3"}, append(args, h.addr, "", testTrapOID.String())...), V3, &c)
	}

	// Failures: a wrong passphrase, an unknown user, and an inform outside the time window.
	sha := combo{auth: AuthSHA1}
	if args, ok := h.v3Args(t, sha, "wrongpass"); ok {
		h.run(t, "wrong passphrase", StatusAuthFailed, append([]string{"snmptrap", "-v", "3", "-e", hex.EncodeToString(NewEngineID())}, append(args, h.addr, "", testTrapOID.String())...), V3, nil)
		args, _ = h.v3Args(t, sha, "nobody")
		h.run(t, "unknown user", StatusUnknownUser, append([]string{"snmptrap", "-v", "3", "-e", hex.EncodeToString(NewEngineID())}, append(args, h.addr, "", testTrapOID.String())...), V3, nil)
		// An inform with Woodshed's engine ID but the wrong boots and time (-Z):
		// stored as not_in_time, answered with an authenticated Report, and the
		// tool's retry after resyncing is stored and answered.
		args, _ = h.v3Args(t, sha, sha.name())
		eid := hex.EncodeToString(h.u.Engine().ID)
		tag := h.run(t, "inform outside the time window", StatusNotInTime,
			append([]string{"snmpinform", "-v", "3", "-r", "2", "-t", "3", "-e", eid, "-Z", "9,99999"}, append(args, h.addr, "", testTrapOID.String())...), V3, nil)
		h.expectTag(t, "the retry after the Report", tag)
	}
}

// expectTag checks that a message with the tag was stored with status ok.
func (h *interopHarness) expectTag(t *testing.T, name, tag string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		for _, m := range h.msgs {
			if m.Status == StatusOK && hasTag(m, tag) {
				h.mu.Unlock()
				h.passed = append(h.passed, name)
				return
			}
		}
		h.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("%s: no ok message with %s", name, tag)
}

// Fixed interop test values (not secrets).
const (
	interopCommunity = "interop-community"
	interopAuthPass  = "interop-auth-pass"
	interopPrivPass  = "interop-priv-pass"
)

type interopHarness struct {
	addr    string
	conf    string // the snmp.conf folder
	env     []string
	u       *USM
	mu      sync.Mutex
	msgs    []*Message
	seq     int
	support map[string]bool
	skipped []string
	passed  []string
	vectors []string
	// replyErrs are replies the listener couldn't build (reported at the end,
	// not from its goroutine).
	replyErrs []string
}

func newInteropHarness(t *testing.T) *interopHarness {
	dir := t.TempDir()
	conf := filepath.Join(dir, "conf")
	if err := os.MkdirAll(filepath.Join(dir, "persist"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("defCommunity %s\ndefAuthPassphrase %s\ndefPrivPassphrase %s\n", interopCommunity, interopAuthPass, interopPrivPass)
	if err := os.WriteFile(filepath.Join(conf, "snmp.conf"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &interopHarness{conf: conf, support: map[string]bool{}}
	// Only our snmp.conf, our persistent folder, and no MIB loading.
	h.env = append(os.Environ(), "SNMPCONFPATH="+conf, "SNMP_PERSISTENT_DIR="+filepath.Join(dir, "persist"), "HOME="+dir, "MIBS=", "MIBDIRS="+dir)

	var users []User
	for _, c := range allCombos() {
		users = append(users, interopUser(c, c.name(), interopAuthPass))
	}
	users = append(users, interopUser(combo{auth: AuthSHA1}, "wrongpass", "a-different-passphrase"))
	h.u = NewUSM(&Engine{ID: NewEngineID(), Boots: 1, Start: time.Now()})
	if err := h.u.SetUsers(users); err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	h.addr = "udp:" + c.LocalAddr().String()
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			now := time.Now()
			m := Decode(append([]byte(nil), buf[:n]...), h.u, now)
			if !m.Discovery {
				h.mu.Lock()
				h.msgs = append(h.msgs, m)
				h.mu.Unlock()
			}
			rep, err := h.u.Reply(m, now)
			if err != nil {
				h.mu.Lock()
				h.replyErrs = append(h.replyErrs, fmt.Sprintf("reply to %v (%v %q): %v", m.Reply, m.Status, m.Err, err))
				h.mu.Unlock()
				continue
			}
			if rep != nil {
				c.WriteToUDP(rep, from)
			}
		}
	}()
	required := os.Getenv("WOODSHED_SNMP_INTEROP_REQUIRE")
	for _, p := range strings.Split(required, ",") {
		if p = strings.TrimSpace(p); p != "" {
			if !h.offers(t, p) {
				t.Fatalf("WOODSHED_SNMP_INTEROP_REQUIRE: the tools don't offer %s", p)
			}
		}
	}
	return h
}

func interopUser(c combo, name, authPass string) User {
	u := User{Name: name, Level: c.level(), Auth: c.auth, Priv: c.priv, KeyExt: c.ext}
	if c.auth != AuthNone {
		u.AuthPass = []byte(authPass)
	}
	if c.priv != PrivNone {
		u.PrivPass = []byte(interopPrivPass)
	}
	return u
}

// netsnmpAuth and netsnmpPriv are the tools' names, most recent spelling first.
func netsnmpAuth(a AuthProtocol) []string {
	return map[AuthProtocol][]string{AuthMD5: {"MD5"}, AuthSHA1: {"SHA"}, AuthSHA224: {"SHA-224"}, AuthSHA256: {"SHA-256"}, AuthSHA384: {"SHA-384"}, AuthSHA512: {"SHA-512"}}[a]
}

func netsnmpPriv(p PrivProtocol, ext KeyExt) []string {
	switch p {
	case PrivDES:
		return []string{"DES"}
	case PrivAES128:
		return []string{"AES"}
	case PrivAES192:
		if ext == KeyExtAlt {
			return []string{"AES-192-C", "AES192C"}
		}
		return []string{"AES-192", "AES192"}
	case PrivAES256:
		if ext == KeyExtAlt {
			return []string{"AES-256-C", "AES256C"}
		}
		return []string{"AES-256", "AES256"}
	}
	return nil
}

// offers reports whether the tools accept a protocol, by name ("sha-256",
// "aes-192", "aes-192-alt"), probing once with a trap to a closed port.
func (h *interopHarness) offers(t *testing.T, name string) bool {
	if v, ok := h.support[name]; ok {
		return v
	}
	var flagArgs [][]string
	if a, err := ParseAuthProtocol(name); err == nil && a != AuthNone {
		for _, n := range netsnmpAuth(a) {
			flagArgs = append(flagArgs, []string{"-l", "authNoPriv", "-a", n})
		}
	} else {
		ext := KeyExtDraft
		base := name
		if strings.HasSuffix(name, "-alt") {
			ext, base = KeyExtAlt, strings.TrimSuffix(name, "-alt")
		}
		p, err := ParsePrivProtocol(base)
		if err != nil {
			t.Fatalf("unknown protocol %q", name)
		}
		for _, n := range netsnmpPriv(p, ext) {
			flagArgs = append(flagArgs, []string{"-l", "authPriv", "-a", "SHA", "-x", n})
		}
	}
	h.support[name] = false
	for _, fa := range flagArgs {
		args := append([]string{"-v", "3", "-u", "probe", "-e", "8000000005" + "0102030405060708"}, fa...)
		args = append(args, "udp:127.0.0.1:9", "", testTrapOID.String())
		out, err := h.output("snmptrap", args...)
		if err == nil && !bytes.Contains(bytes.ToLower(out), []byte("invalid")) {
			h.support[name] = true
			h.support[name+"="+fa[len(fa)-1]] = true
			break
		}
	}
	return h.support[name]
}

// spelling is the tools' accepted name for a protocol offers found.
func (h *interopHarness) spelling(names []string, key string) string {
	for _, n := range names {
		if h.support[key+"="+n] {
			return n
		}
	}
	return names[0]
}

// v3Args are the -u/-l/-a/-x arguments for a combination, or false (logged as a
// skip) when the tools don't offer one of its protocols.
func (h *interopHarness) v3Args(t *testing.T, c combo, user string) ([]string, bool) {
	args := []string{"-u", user, "-l", c.level().String()}
	if c.auth != AuthNone {
		key := c.auth.String()
		if !h.offers(t, key) {
			h.skipped = append(h.skipped, c.name()+" (the tools lack "+key+")")
			return nil, false
		}
		args = append(args, "-a", h.spelling(netsnmpAuth(c.auth), key))
	}
	if c.priv != PrivNone {
		key := c.priv.String()
		if (c.priv == PrivAES192 || c.priv == PrivAES256) && c.ext == KeyExtAlt {
			key += "-alt"
		}
		if !h.offers(t, key) {
			h.skipped = append(h.skipped, c.name()+" (the tools lack "+key+")")
			return nil, false
		}
		args = append(args, "-x", h.spelling(netsnmpPriv(c.priv, c.ext), key))
	}
	return args, true
}

// output runs one of the tools with the harness's environment (bounded, so a
// hang can't stall the job) and returns its combined output.
func (h *interopHarness) output(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = h.env
	return cmd.CombinedOutput()
}

// run sends one trap or inform (the command gets a seq varbind appended) and
// checks what the listener stored.
func (h *interopHarness) run(t *testing.T, name string, want Status, argv []string, v Version, c *combo) (tag string) {
	t.Helper()
	h.seq++
	tag = fmt.Sprintf("seq=interop:%d", h.seq)
	argv = append(argv, testEnterprise.String()+".1.1.0", "s", tag)
	h.mu.Lock()
	start := len(h.msgs)
	h.mu.Unlock()
	out, err := h.output(argv[0], argv[1:]...)
	inform := argv[0] == "snmpinform"
	if err != nil {
		if c != nil && c.priv == PrivDES && !inform {
			// Some builds list DES but can't run it (OpenSSL without the legacy
			// provider); a working DES is covered by woodshed send instead.
			h.skipped = append(h.skipped, name+" (the tools' DES failed: "+firstLineOf(out)+")")
			return tag
		}
		t.Errorf("%s: %s exited with %v: %s", name, argv[0], err, out)
		return tag
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		msgs := h.msgs[start:]
		h.mu.Unlock()
		for _, m := range msgs {
			if want == StatusOK && !hasTag(m, tag) {
				continue
			}
			if want != StatusOK && m.Status != want {
				continue
			}
			h.check(t, name, m, want, v, c, inform)
			return tag
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.mu.Lock()
	var got []string
	for _, m := range h.msgs[start:] {
		got = append(got, fmt.Sprintf("%v %q", m.Status, m.Err))
	}
	h.mu.Unlock()
	t.Errorf("%s: nothing with %s arrived (got %v); %s output: %s", name, want, got, argv[0], out)
	return tag
}

func hasTag(m *Message, tag string) bool {
	if m.PDU == nil {
		return false
	}
	for _, vb := range m.PDU.Varbinds {
		if vb.Value.Kind == KindOctetString && string(vb.Value.Bytes) == tag {
			return true
		}
	}
	return false
}

func (h *interopHarness) check(t *testing.T, name string, m *Message, want Status, v Version, c *combo, inform bool) {
	t.Helper()
	if m.Status != want || m.Version != v {
		t.Errorf("%s: %v v%s %q", name, m.Status, m.Version, m.Err)
		return
	}
	if want == StatusOK {
		wantPDU := PDUTrap
		switch {
		case inform:
			wantPDU = PDUInform
		case v == V1:
			wantPDU = PDUV1Trap
		}
		if m.PDU.Type != wantPDU {
			t.Errorf("%s: PDU %s", name, m.PDU.Type)
		}
		if v != V3 && string(m.Community) != interopCommunity {
			t.Errorf("%s: community %q", name, m.Community)
		}
		if n := m.PDU.Notification(); v == V1 && !n.TrapOID.Equal(append(append(OID{}, testEnterprise...), 0, 17)) || v != V1 && !n.TrapOID.Equal(testTrapOID) {
			t.Errorf("%s: trap OID %s", name, n.TrapOID)
		}
		if c != nil && (m.Level != c.level() || string(m.User) != c.name()) {
			t.Errorf("%s: level %s user %q", name, m.Level, m.User)
		}
		// The AES-192/256 cases with a short auth key exercise the key extension:
		// log the datagram, a vector for both methods.
		if c != nil && (c.priv == PrivAES192 || c.priv == PrivAES256) && (c.auth == AuthMD5 || c.auth == AuthSHA1) && !inform {
			h.vectors = append(h.vectors, fmt.Sprintf("%s: engine %x, datagram %x", c.name(), m.EngineID, m.Raw))
		}
	}
	rec, err := ParseRecord(FormatRecord(nil, m, RecordOptions{Names: BuiltinMIBs()}))
	if err != nil || rec.Status != want.String() {
		t.Errorf("%s: record %v %+v", name, err, rec)
	}
	h.passed = append(h.passed, name)
}

func firstLineOf(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

func (h *interopHarness) summary(t *testing.T) {
	h.mu.Lock()
	for _, e := range h.replyErrs {
		t.Error(e)
	}
	h.mu.Unlock()
	var b strings.Builder
	out, _ := h.output("snmptrap", "--version")
	fmt.Fprintf(&b, "### SNMP interop (%s)\n\n", strings.TrimSpace(string(out)))
	fmt.Fprintf(&b, "%d cases passed, %d skipped.\n\n", len(h.passed), len(h.skipped))
	var offered, missing []string
	for _, p := range []string{"md5", "sha", "sha-224", "sha-256", "sha-384", "sha-512", "des", "aes-128", "aes-192", "aes-192-alt", "aes-256", "aes-256-alt"} {
		if v, ok := h.support[p]; ok && v {
			offered = append(offered, p)
		} else if ok {
			missing = append(missing, p)
		}
	}
	fmt.Fprintf(&b, "Offered by the tools: %s. Not offered: %s.\n\n", strings.Join(offered, ", "), strings.Join(missing, ", "))
	for _, s := range h.skipped {
		fmt.Fprintf(&b, "- skipped: %s\n", s)
	}
	t.Log("\n" + b.String())
	for _, v := range h.vectors {
		t.Logf("key-extension vector (passphrases %q / %q): %s", interopAuthPass, interopPrivPass, v)
	}
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0); err == nil {
			f.WriteString(b.String())
			f.Close()
		}
	}
}
