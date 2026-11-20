package api

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestIdentityKeepsOnlyStableAddresses(t *testing.T) {
	a := func(iface, ip string) ifaceAddr { return ifaceAddr{iface: iface, ip: netip.MustParseAddr(ip)} }
	addrs := []ifaceAddr{
		a("eth0", "192.0.2.10"),
		a("eth0", "2001:db8::211:22ff:fe33:4455"),  // EUI-64: stable
		a("eth0", "2001:db8::8d3c:a1f2:7e01:9b44"), // privacy-looking
		a("eth0", "fe80::211:22ff:fe33:4455"),      // link-local
		a("eth0", "169.254.7.7"),                   // IPv4 link-local
		a("docker0", "172.17.0.1"),                 // container bridge
		a("br-1a2b3c", "172.18.0.1"),
		a("veth9f2", "fd00:abc::1"),
		a("utun3", "198.51.100.77"),         // VPN tunnel
		a("vEthernet (WSL)", "172.29.16.1"), // Hyper-V switch
		a("lo", "127.0.0.1"),
	}
	ips := func(id hostIdentity) []string {
		var out []string
		for _, ip := range id.IPs {
			out = append(out, ip.String())
		}
		return out
	}
	// Without the OS's flags (macOS, Windows): only EUI-64 IPv6.
	id := identityFrom("Box", nil, addrs, nil)
	if got := strings.Join(ips(id), " "); got != "127.0.0.1 192.0.2.10 ::1 2001:db8::211:22ff:fe33:4455" {
		t.Errorf("no flags: %s", got)
	}
	if !slices.Equal(id.Names, []string{"box", "box.local", "localhost"}) {
		t.Errorf("names %v", id.Names)
	}
	// With Linux's flags: stable privacy addresses count, temporary, deprecated
	// and tentative ones don't.
	stable := netip.MustParseAddr("2001:db8::8d3c:a1f2:7e01:9b44")
	flags := map[netip.Addr]uint32{
		netip.MustParseAddr("2001:db8::211:22ff:fe33:4455"): 0,
		stable: 0x80, // IFA_F_PERMANENT
	}
	temp := a("eth0", "2001:db8::dead:beef:1:2")
	flags[temp.ip] = ifaTemporary
	depr := a("eth0", "2001:db8::aaaa:1")
	flags[depr.ip] = ifaDeprecated
	id = identityFrom("box", nil, append(slices.Clone(addrs), temp, depr), flags)
	if got := strings.Join(ips(id), " "); got != "127.0.0.1 192.0.2.10 ::1 2001:db8::211:22ff:fe33:4455 2001:db8::8d3c:a1f2:7e01:9b44" {
		t.Errorf("with flags: %s", got)
	}
}

func TestParseIfInet6(t *testing.T) {
	in := "20010db8000000000211 bad line\n" +
		"20010db8000000000000deadbeef0001 02 40 00 01   eth0\n" +
		"20010db8000000000211_22fffe334455 02 40 00 80 eth0\n" +
		"fe800000000000000211_22fffe334455 02 40 20 80 eth0\n"
	in = strings.ReplaceAll(in, "_", "")
	got := parseIfInet6(bufio.NewScanner(strings.NewReader(in)))
	if len(got) != 3 || got[netip.MustParseAddr("2001:db8::dead:beef:1")] != 1 ||
		got[netip.MustParseAddr("2001:db8::211:22ff:fe33:4455")] != 0x80 {
		t.Errorf("%v", got)
	}
}

// TestCertKeyStableAcrossRegeneration: a new stable address regenerates the
// certificate with the same key, and the fingerprint follows the certificate.
func TestCertKeyStableAcrossRegeneration(t *testing.T) {
	dir := t.TempDir()
	clock := newFakeClock()
	id := hostIdentity{Names: []string{"box", "localhost"}, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
	gens := 0
	cs := &certSource{dataDir: dir, now: clock.Now, identity: func() (hostIdentity, error) { return id, nil },
		onGenerate: func(string) { gens++ }}
	c1, err := cs.load()
	if err != nil {
		t.Fatal(err)
	}
	fp1 := cs.fingerprint()
	sum := sha256.Sum256(c1.Certificate[0])
	if fp1 != certFingerprint(c1.Certificate[0]) || len(fp1) != 95 || !strings.HasPrefix(fp1, fmt.Sprintf("%02X:", sum[0])) {
		t.Errorf("fingerprint %q", fp1)
	}
	// Same identity a minute later: nothing regenerated.
	clock.Add(2 * certRecheck)
	cs.load()
	if gens != 1 {
		t.Fatalf("regenerated without a change (%d)", gens)
	}
	// A new stable address: regenerated, same key.
	id.IPs = append(id.IPs, netip.MustParseAddr("192.0.2.10"))
	clock.Add(2 * certRecheck)
	c2, err := cs.load()
	if err != nil || gens != 2 {
		t.Fatalf("not regenerated: %d %v", gens, err)
	}
	k1, k2 := c1.PrivateKey.(*ecdsa.PrivateKey), c2.PrivateKey.(*ecdsa.PrivateKey)
	if !k1.PublicKey.Equal(&k2.PublicKey) {
		t.Error("the key changed on regeneration")
	}
	if fp2 := cs.fingerprint(); fp2 == fp1 || fp2 == "" {
		t.Errorf("fingerprint didn't follow the certificate: %s", fp2)
	}
	// A fresh source (a restart) reads the files and keeps the key.
	cs2 := &certSource{dataDir: dir, now: clock.Now, identity: func() (hostIdentity, error) { return id, nil }}
	c3, err := cs2.load()
	if err != nil || !c3.PrivateKey.(*ecdsa.PrivateKey).PublicKey.Equal(&k1.PublicKey) {
		t.Errorf("after restart: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, KeyFile)); err != nil {
		t.Fatal(err)
	}
}

func TestStatusShowsCertFingerprint(t *testing.T) {
	local := startServer(t, nil, UIConfig{})
	var st map[string]any
	json.Unmarshal(do(t, httpClient(), "GET", local.url("/api/status"), "").body, &st)
	if fp, ok := st["ui_cert_fingerprint"]; !ok || fp != "" {
		t.Errorf("localhost mode: %v", fp)
	}
	srv := lanServer(t, "password-123")
	c := tlsClient(t, srv.dataDir)
	login(t, srv, c, "password-123")
	json.Unmarshal(do(t, c, "GET", srv.url("/api/status"), "").body, &st)
	conn, err := tls.Dial("tcp", srv.State().Addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // reading the served cert
	if err != nil {
		t.Fatal(err)
	}
	served := certFingerprint(conn.ConnectionState().PeerCertificates[0].Raw)
	conn.Close()
	if st["ui_cert_fingerprint"] != served || srv.State().CertFingerprint != served {
		t.Errorf("status %v, state %q, served %q", st["ui_cert_fingerprint"], srv.State().CertFingerprint, served)
	}
}

// ui_addrs lists the certificate's addresses without loopback, IPv4 first, in
// both modes (Settings shows https://<addr>:<port>/ before LAN mode is on, too).
func TestStatusShowsUIAddrs(t *testing.T) {
	id := func() (hostIdentity, error) {
		return identityFrom("testhost", nil, []ifaceAddr{
			{iface: "eth0", ip: netip.MustParseAddr("fd00::50")},
			{iface: "eth0", ip: netip.MustParseAddr("10.1.0.50")},
			{iface: "docker0", ip: netip.MustParseAddr("172.17.0.1")},
			{iface: "eth0", ip: netip.MustParseAddr("fe80::1")},
		}, map[netip.Addr]uint32{netip.MustParseAddr("fd00::50"): 0}), nil
	}
	srv := startServer(t, nil, UIConfig{}, func(o *Options) { o.identity = id })
	var st map[string]any
	json.Unmarshal(do(t, httpClient(), "GET", srv.url("/api/status"), "").body, &st)
	got, _ := json.Marshal(st["ui_addrs"])
	if string(got) != `["10.1.0.50","fd00::50"]` {
		t.Errorf("ui_addrs %s", got)
	}
	none := startServer(t, nil, UIConfig{}, func(o *Options) { o.identity = testIdentity })
	json.Unmarshal(do(t, httpClient(), "GET", none.url("/api/status"), "").body, &st)
	if a, ok := st["ui_addrs"].([]any); !ok || len(a) != 0 {
		t.Errorf("loopback only: ui_addrs %v, want []", st["ui_addrs"])
	}
}
