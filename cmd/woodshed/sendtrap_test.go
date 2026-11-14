package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// snmpSink is a codec-based trap receiver that answers informs.
type snmpSink struct {
	port int
	mu   sync.Mutex
	got  []*snmp.Message
}

func newSNMPSink(t *testing.T, users ...snmp.User) *snmpSink {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	u := snmp.NewUSM(&snmp.Engine{ID: snmp.NewEngineID(), Boots: 1, Start: time.Now()})
	if err := u.SetUsers(users); err != nil {
		t.Fatal(err)
	}
	s := &snmpSink{port: c.LocalAddr().(*net.UDPAddr).Port}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			m := snmp.Decode(append([]byte(nil), buf[:n]...), u, time.Now())
			if !m.Discovery {
				s.mu.Lock()
				s.got = append(s.got, m)
				s.mu.Unlock()
			}
			if rep, err := u.Reply(m, time.Now()); err == nil && rep != nil {
				c.WriteToUDP(rep, from)
			}
		}
	}()
	return s
}

func (s *snmpSink) wait(n int) []*snmp.Message {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		if len(s.got) >= n {
			defer s.mu.Unlock()
			return append([]*snmp.Message(nil), s.got...)
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*snmp.Message(nil), s.got...)
}

func TestSendTrapCLI(t *testing.T) {
	s := newSNMPSink(t)
	var out, errb bytes.Buffer
	code := realMain([]string{"send", "--proto", "trap", "--port", strconv.Itoa(s.port), "--count", "3", "--run", "cli1", "--trap-oid", "linkDown"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "Sent 3 traps (SNMPv2c)") || !strings.Contains(out.String(), `"seq=cli1:"`) {
		t.Errorf("output: %s", out.String())
	}
	msgs := s.wait(3)
	if len(msgs) != 3 || msgs[0].Status != snmp.StatusOK || string(msgs[0].Community) != "public" {
		t.Fatalf("received %d: %+v", len(msgs), msgs)
	}
	if n := msgs[0].PDU.Notification(); n.TrapOID.String() != "1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("trap OID %s", n.TrapOID)
	}

	// A community from the environment.
	t.Setenv(envSNMPCommunity, "from-env")
	out.Reset()
	if code := realMain([]string{"send", "--proto", "trap", "--snmp-version", "1", "--port", strconv.Itoa(s.port)}, &out, &errb); code != 0 {
		t.Fatalf("v1: exit %d: %s", code, errb.String())
	}
	if msgs := s.wait(4); len(msgs) != 4 || string(msgs[3].Community) != "from-env" || msgs[3].Version != snmp.V1 {
		t.Errorf("v1 from env: %+v", msgs[len(msgs)-1])
	}
}

func TestSendTrapCLIv3(t *testing.T) {
	dir := t.TempDir()
	authFile, privFile := filepath.Join(dir, "auth"), filepath.Join(dir, "priv")
	// Test passphrases, generated for the test.
	os.WriteFile(authFile, []byte("cli-auth-passphrase\n"), 0o600)
	os.WriteFile(privFile, []byte("cli-priv-passphrase\r\n"), 0o600)
	s := newSNMPSink(t, snmp.User{Name: "monitor", Level: snmp.AuthPriv, Auth: snmp.AuthSHA256, Priv: snmp.PrivAES256, KeyExt: snmp.KeyExtAlt,
		AuthPass: []byte("cli-auth-passphrase"), PrivPass: []byte("cli-priv-passphrase")})
	var out, errb bytes.Buffer
	args := []string{"send", "--proto", "trap", "--port", strconv.Itoa(s.port), "--snmp-version", "3", "--user", "monitor",
		"--auth", "sha-256", "--priv", "aes-256", "--key-ext", "alt", "--auth-pass-file", authFile, "--priv-pass-file", privFile, "--count", "4", "--inform", "--varbinds", "10"}
	if code := realMain(args, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "4 answered, 0 timed out; round trip p50") || !strings.Contains(out.String(), "authPriv sha-256/aes-256 (alt key extension)") {
		t.Errorf("output: %s", out.String())
	}
	if msgs := s.wait(4); len(msgs) != 4 || msgs[0].Status != snmp.StatusOK || len(msgs[0].PDU.Varbinds) != 12 {
		t.Errorf("received %+v", msgs)
	}
	if strings.Contains(out.String()+errb.String(), "cli-auth-passphrase") {
		t.Error("a passphrase in the output")
	}
}

func TestSendTrapCLIErrors(t *testing.T) {
	t.Setenv(envSNMPAuthPass, "")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--proto", "trap", "--community", "public"}, "not defined: -community"}, // never on the command line
		{[]string{"--proto", "trap", "--auth-pass", "x"}, "not defined: -auth-pass"},
		{[]string{"--proto", "udp", "--snmp-version", "3"}, "--snmp-version: only for --proto trap"},
		{[]string{"--proto", "trap", "--size", "300"}, "--size: not for --proto trap"},
		{[]string{"--proto", "trap", "--snmp-version", "3"}, "needs --user"},
		{[]string{"--proto", "trap", "--snmp-version", "3", "--user", "u", "--auth", "sha"}, "WOODSHED_SNMP_AUTH_PASS"},
		{[]string{"--proto", "trap", "--snmp-version", "3", "--user", "u", "--priv", "des"}, "--priv needs --auth"},
		{[]string{"--proto", "trap", "--user", "u"}, "for --snmp-version 3"},
		{[]string{"--proto", "trap", "--snmp-version", "1", "--inform"}, "no informs"},
		{[]string{"--proto", "trap", "--trap-oid", "noSuchName"}, "neither a numeric OID"},
		{[]string{"--proto", "trap", "--auth", "sha-3", "--snmp-version", "3", "--user", "u"}, "unknown authentication protocol"},
		{[]string{"--proto", "trap", "--engine-id", "12", "--snmp-version", "3", "--user", "u"}, "--engine-id"},
		{[]string{"--proto", "trap", "--varbinds", "0"}, "--varbinds"},
		{[]string{"--proto", "trap", "--snmp-version", "3", "--user", "u", "--community-file", "x"}, "for --snmp-version 1 and 2c"},
	} {
		var out, errb bytes.Buffer
		code := realMain(append([]string{"send"}, tc.args...), &out, &errb)
		if code == 0 || !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: exit %d, %q; want %q", tc.args, code, firstLine(errb.String()), tc.want)
		}
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
