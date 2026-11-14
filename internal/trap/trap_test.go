package trap

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/snmp"
)

var src = netip.MustParseAddr("192.0.2.7")

func TestLimiter(t *testing.T) {
	l := limiter{per: map[netip.Addr]*bucket{}, perSource: ReplyPerSource, all: ReplyTotal}
	now := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	n := 0
	for i := 0; i < 500; i++ {
		if l.allow(src, now) {
			n++
		}
	}
	if n != ReplyPerSource {
		t.Fatalf("one source in one instant: %d replies", n)
	}
	// Many sources share the total.
	n = 0
	for i := 0; i < 2000; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, byte(i / 250), byte(i % 250)})
		if l.allow(a, now) {
			n++
		}
	}
	if n != ReplyTotal-ReplyPerSource {
		t.Fatalf("many sources: %d replies", n)
	}
	// A second later each refills.
	if !l.allow(src, now.Add(time.Second)) {
		t.Fatal("no refill")
	}
}

func TestDedup(t *testing.T) {
	var d dedup
	d.seen = map[string]time.Time{}
	now := time.Now()
	if d.check("a", now) || !d.check("a", now.Add(30*time.Second)) || d.check("a", now.Add(100*time.Second)) || d.check("b", now) {
		t.Fatal("dedup")
	}
}

func openRcv(t *testing.T, dir string, write func(model.Message) error) *Receiver {
	t.Helper()
	if write == nil {
		write = func(model.Message) error { return nil }
	}
	r, err := Open(Options{DataDir: dir, Write: write}, Settings{AnswerInforms: true})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The credentials file: secrets never in its public part, mode 0600, and it
// survives a reopen; engine-bound users keep only localized keys.
func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	r := openRcv(t, dir, nil)
	const pass = "creds-Secret-77"
	if _, err := r.PutUser(api.SNMPUserInput{Name: "a", Auth: "sha-256", AuthPass: pass, Priv: "aes-256", PrivPass: pass, KeyExt: "alt"}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PutUser(api.SNMPUserInput{Name: "b", Auth: "sha", AuthPass: pass, EngineIDs: []string{"80000000050102030405060708"}}, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.SetCommunities([]string{"comm-Secret"}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, CredFileName())
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
	var f credFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	pub, _ := json.Marshal(f.Users)
	if bytes.Contains(pub, []byte(pass)) || bytes.Contains(b, []byte(pass)) || bytes.Contains(b, []byte("comm-Secret")) {
		t.Fatal("a secret in the clear in the file")
	}
	// Engine-bound: no passphrase kept, keys for the engine and Woodshed's own.
	if len(r.creds.secrets.Users["b"].AuthPass) != 0 || len(r.creds.secrets.Users["b"].Keys) != 2 {
		t.Fatalf("bound user %+v", r.creds.secrets.Users["b"])
	}
	r2 := openRcv(t, dir, nil)
	us := r2.Users()
	if len(us) != 2 || !us[0].Readable || !us[0].AuthSet || !us[0].PrivSet || us[1].Stored != "localized" {
		t.Fatalf("reopened %+v", us)
	}
	if h := r2.Communities(); len(h) != 1 || h[0] != snmp.CommunityHash([]byte("comm-Secret")) {
		t.Fatalf("communities %v", h)
	}
	// A hash sent back keeps the community; an unknown hash is an error.
	if err := r2.SetCommunities([]string{h0(r2), "another-one"}); err != nil {
		t.Fatal(err)
	}
	if len(r2.creds.secrets.Communities) != 2 || r2.creds.secrets.Communities[0] != "comm-Secret" {
		t.Fatalf("kept %v", r2.creds.secrets.Communities)
	}
	if err := r2.SetCommunities([]string{"#00000000"}); err == nil {
		t.Fatal("an unknown hash")
	}
	// A secrets blob that doesn't decrypt keeps the names (Windows: another account).
	f.Secrets = "bm90LWpzb24=" // base64 of "not-json"
	nb, _ := json.Marshal(f)
	os.WriteFile(p, nb, 0o600)
	r3 := openRcv(t, dir, nil)
	if us := r3.Users(); len(us) != 2 || us[0].Readable || r3.UnreadableUsers() != 2 {
		t.Fatalf("unreadable %+v", us)
	}
}

func h0(r *Receiver) string { return r.Communities()[0] }

// The engine file: boots go up at every open, the ID stays, an override
// doesn't replace it.
func TestEngineBoots(t *testing.T) {
	dir := t.TempDir()
	a := openRcv(t, dir, nil).Engine()
	b := openRcv(t, dir, nil).Engine()
	if a.ID != b.ID || a.Boots != 1 || b.Boots != 2 || !strings.HasPrefix(a.ID, "8000000005") {
		t.Fatalf("%+v %+v", a, b)
	}
	r, err := Open(Options{DataDir: dir, Write: func(model.Message) error { return nil }}, Settings{EngineID: "80000000050102030405"})
	if err != nil {
		t.Fatal(err)
	}
	if e := r.Engine(); e.ID != "80000000050102030405" || e.Boots != 3 {
		t.Fatalf("override %+v", e)
	}
	if err := r.Apply(Settings{}); err != nil || r.Engine().ID != a.ID {
		t.Fatalf("back to the stored ID: %+v %v", r.Engine(), err)
	}
	if st, _ := os.Stat(filepath.Join(dir, snmp.EngineFile)); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("engine file mode %v", st.Mode().Perm())
	}
}

// The MIB folder: the default is created; errors are listed.
func TestMIBFolder(t *testing.T) {
	dir := t.TempDir()
	r := openRcv(t, dir, nil)
	if m := r.MIBs(); m.Dir != filepath.Join(dir, "mibs") || len(m.Errors) != 0 || m.Names == 0 {
		t.Fatalf("%+v", m)
	}
	os.WriteFile(filepath.Join(dir, "mibs", "BROKEN-MIB.mib"), []byte("BROKEN-MIB DEFINITIONS ::= BEGIN\n x OBJECT IDENTIFIER ::= {\n"), 0o640)
	os.WriteFile(filepath.Join(dir, "mibs", "EXAMPLE-MIB.mib"), []byte(`EXAMPLE-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM SNMPv2-SMI;
example OBJECT IDENTIFIER ::= { enterprises 32473 }
exampleTraps OBJECT IDENTIFIER ::= { example 1 0 }
exampleUp NOTIFICATION-TYPE STATUS current DESCRIPTION "x" ::= { exampleTraps 1 }
END
`), 0o640)
	m := r.ReloadMIBs()
	if m.Files != 2 || len(m.Errors) != 1 || m.Errors[0].File != "BROKEN-MIB.mib" {
		t.Fatalf("%+v", m)
	}
	// A missing folder the user named is an error, and nothing is created.
	missing := filepath.Join(dir, "nope")
	r.Apply(Settings{AnswerInforms: true, MIBDir: missing})
	if m := r.MIBs(); len(m.Errors) == 0 {
		t.Fatalf("missing folder %+v", m)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("created the user's folder")
	}
}

// Statuses and failures per sender.
func TestFailuresAndCounts(t *testing.T) {
	var mu sync.Mutex
	var stored []string
	r := openRcv(t, t.TempDir(), func(m model.Message) error {
		mu.Lock()
		stored = append(stored, string(m.Raw))
		mu.Unlock()
		return nil
	})
	now := time.Now()
	for _, raw := range [][]byte{{0x30, 0x03, 0x02, 0x01}, []byte("junk")} {
		r.Handle(packet(raw, now))
	}
	if c := r.Counts(); c.Received != 2 || c.ByStatus["malformed"] != 2 {
		t.Fatalf("counts %+v", c)
	}
	f := r.Failures()
	if len(f) != 1 || f[0].Count24h != 2 || f[0].Status != "malformed" || f[0].IP != src.String() {
		t.Fatalf("failures %+v", f)
	}
	if len(stored) != 2 || !strings.Contains(stored[0], "status=malformed") {
		t.Fatalf("stored %q", stored)
	}
}
