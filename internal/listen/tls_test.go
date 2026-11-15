package listen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

// testCA makes Woodshed's own CA and leaf in a temp folder.
func testCA(t *testing.T) (*tlscert.Manager, *x509.CertPool) {
	t.Helper()
	m := tlscert.New(tlscert.Options{DataDir: t.TempDir(), Identity: func() (tlscert.Identity, error) {
		return tlscert.Identity{Host: "logs-01", Primary: "logs-01.example.net",
			Names: []string{"localhost", "logs-01", "logs-01.example.net"},
			IPs:   []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, nil
	}})
	if _, err := m.Load(true); err != nil {
		t.Fatal(err)
	}
	der, err := m.CADER()
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return m, pool
}

// ecdsaCert is a self-signed ECDSA P-256 server certificate (a user's own).
func ecdsaCert(t *testing.T) *tls.Certificate {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func tlsConfig(legacy bool) config.Listeners {
	return config.Listeners{TLS: config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: 0, AllowLegacyTLS: legacy}}
}

func startTLS(t *testing.T, cfg config.Listeners, mod func(*Options)) (*Server, *collector, *x509.CertPool) {
	t.Helper()
	m, pool := testCA(t)
	s, c, _ := start(t, cfg, func(o *Options) {
		o.TLSCertificate = m.Certificate
		if mod != nil {
			mod(o)
		}
	})
	return s, c, pool
}

func tlsAddr(t *testing.T, s *Server) string {
	t.Helper()
	ap, ok := s.TLSAddr()
	if !ok {
		t.Fatalf("TLS not running: %+v", s.Status().Listeners)
	}
	return ap.String()
}

// client is a sender's config: it trusts the CA (unless insecure) and names
// one of the certificate's DNS names.
func client(pool *x509.CertPool) *tls.Config {
	return &tls.Config{RootCAs: pool, ServerName: "logs-01.example.net"}
}

func failureOf(s *Server, ip string) (TLSFailure, int64) {
	st, ok := s.TLSSenderStats(netip.MustParseAddr(ip))
	if !ok || st.LastFailure == nil {
		return TLSFailure{}, 0
	}
	return *st.LastFailure, st.Failures24h
}

// Every allowed version and suite connects; refused: 1.0/1.1 without the flag,
// static-RSA suites, CBC-only at 1.2. With the flag, 1.0 and 1.1 with ECDHE CBC.
func TestTLSHandshakeMatrix(t *testing.T) {
	type tc struct {
		name    string
		legacy  bool
		ecdsa   bool
		min     uint16
		max     uint16
		suites  []uint16
		ok      bool
		reason  string
		version string
	}
	cases := []tc{
		{name: "1.3", min: tls.VersionTLS13, max: tls.VersionTLS13, ok: true, version: "TLS 1.3"},
		{name: "1.2 default", min: tls.VersionTLS12, max: tls.VersionTLS12, ok: true, version: "TLS 1.2"},
		{name: "1.0 off", min: tls.VersionTLS10, max: tls.VersionTLS10, suites: tlsSuitesLegacy, reason: TLSVersion},
		{name: "1.1 off", min: tls.VersionTLS11, max: tls.VersionTLS11, suites: tlsSuitesLegacy, reason: TLSVersion},
		{name: "1.0 legacy", legacy: true, min: tls.VersionTLS10, max: tls.VersionTLS10,
			suites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}, ok: true, version: "TLS 1.0"},
		{name: "1.1 legacy", legacy: true, min: tls.VersionTLS11, max: tls.VersionTLS11,
			suites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}, ok: true, version: "TLS 1.1"},
		{name: "static RSA", min: tls.VersionTLS12, max: tls.VersionTLS12,
			suites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_CBC_SHA}, reason: TLSCipher},
		{name: "static RSA legacy", legacy: true, min: tls.VersionTLS10, max: tls.VersionTLS12,
			suites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA}, reason: TLSCipher},
		{name: "1.2 CBC only", min: tls.VersionTLS12, max: tls.VersionTLS12,
			suites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA}, reason: TLSCipher},
		{name: "3DES", legacy: true, min: tls.VersionTLS10, max: tls.VersionTLS12,
			suites: []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA}, reason: TLSCipher},
	}
	for _, s := range tlsSuites12[:3] {
		cases = append(cases, tc{name: tls.CipherSuiteName(s), min: tls.VersionTLS12, max: tls.VersionTLS12,
			suites: []uint16{s}, ok: true, version: "TLS 1.2"})
	}
	for _, s := range tlsSuites12[3:] {
		cases = append(cases, tc{name: tls.CipherSuiteName(s), ecdsa: true, min: tls.VersionTLS12, max: tls.VersionTLS12,
			suites: []uint16{s}, ok: true, version: "TLS 1.2"})
	}
	servers := map[[2]bool]*Server{}
	pools := map[[2]bool]*x509.CertPool{}
	get := func(legacy, ec bool) (*Server, *x509.CertPool) {
		k := [2]bool{legacy, ec}
		if servers[k] == nil {
			if ec {
				cert := ecdsaCert(t)
				s, _, _ := start(t, tlsConfig(legacy), func(o *Options) {
					o.TLSCertificate = func() (*tls.Certificate, error) { return cert, nil }
				})
				servers[k] = s
			} else {
				servers[k], _, pools[k] = startTLS(t, tlsConfig(legacy), nil)
			}
		}
		return servers[k], pools[k]
	}
	for _, c := range cases {
		s, pool := get(c.legacy, c.ecdsa)
		cfg := client(pool)
		if c.ecdsa {
			cfg = &tls.Config{InsecureSkipVerify: true}
		}
		cfg.MinVersion, cfg.MaxVersion, cfg.CipherSuites = c.min, c.max, c.suites
		before := s.Status().TLSHandshakeFailed
		conn, err := tls.Dial("tcp", tlsAddr(t, s), cfg)
		if c.ok {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
				continue
			}
			if v := tls.VersionName(conn.ConnectionState().Version); v != c.version {
				t.Errorf("%s: version %s", c.name, v)
			}
			if len(c.suites) == 1 && conn.ConnectionState().CipherSuite != c.suites[0] {
				t.Errorf("%s: suite %s", c.name, tls.CipherSuiteName(conn.ConnectionState().CipherSuite))
			}
			conn.Close()
			continue
		}
		if err == nil {
			conn.Close()
			t.Errorf("%s: connected, want refused", c.name)
			continue
		}
		// The counter rises before the failure record is stored, so wait for the record itself.
		waitFor(t, c.name+" failure", func() bool {
			f, _ := failureOf(s, "127.0.0.1")
			return s.Status().TLSHandshakeFailed > before && f.Reason == c.reason // earlier cases leave their own record
		})
		if f, _ := failureOf(s, "127.0.0.1"); f.Reason != c.reason {
			t.Errorf("%s: reason %q (%s), want %q", c.name, f.Reason, f.Detail, c.reason)
		}
	}
}

// No SNI, a wrong SNI and ALPN all connect (the certificate is the same); a
// client checking a DNS name from the SANs against the downloaded CA connects,
// and one checking a name that isn't there fails, counted as cert_rejected.
func TestTLSNamesAndTrust(t *testing.T) {
	s, c, pool := startTLS(t, tlsConfig(false), nil)
	addr := tlsAddr(t, s)
	for _, cfg := range []*tls.Config{
		{InsecureSkipVerify: true},                           // no SNI
		{InsecureSkipVerify: true, ServerName: "other.test"}, // wrong SNI
		{InsecureSkipVerify: true, NextProtos: []string{"syslog", "h2"}},
		{RootCAs: pool, ServerName: "logs-01.example.net"},
		{RootCAs: pool, ServerName: "localhost"},
	} {
		conn, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			t.Errorf("%+v: %v", cfg.ServerName, err)
			continue
		}
		if p := conn.ConnectionState().NegotiatedProtocol; p != "" {
			t.Errorf("ALPN negotiated %q", p)
		}
		if conn.ConnectionState().DidResume {
			t.Error("resumed")
		}
		fmt.Fprintf(conn, "<13>hello %s\n", cfg.ServerName)
		conn.Close()
	}
	c.wait(t, 5)

	_, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool, ServerName: "not-there.example.net"})
	if err == nil {
		t.Fatal("a name that isn't in the certificate verified")
	}
	waitFor(t, "the failure", func() bool { f, _ := failureOf(s, "127.0.0.1"); return f.Reason != "" })
	if f, n := failureOf(s, "127.0.0.1"); f.Reason != TLSCertRejected || n != 1 || !strings.Contains(f.Detail, "bad certificate") {
		t.Errorf("failure %+v (%d)", f, n)
	}
	st, _ := s.TLSSenderStats(netip.MustParseAddr("127.0.0.1"))
	if st.Connections24h != 5 || st.Version != "TLS 1.3" || st.Cipher == "" || !st.Delivered {
		t.Errorf("stats %+v", st)
	}
}

// Failure reasons: plain syslog to the TLS port, an untrusted CA, a version
// mismatch, a timeout and a close mid-handshake.
func TestTLSFailureReasons(t *testing.T) {
	s, _, _ := startTLS(t, tlsConfig(false), func(o *Options) { o.HandshakeTimeout = 300 * time.Millisecond })
	addr := tlsAddr(t, s)
	expect := func(what, reason, detail string) {
		t.Helper()
		var f TLSFailure
		waitFor(t, what, func() bool { f, _ = failureOf(s, "127.0.0.1"); return f.Reason == reason })
		if !strings.Contains(f.Detail, detail) {
			t.Errorf("%s: detail %q, want %q", what, f.Detail, detail)
		}
	}

	plain, _ := net.Dial("tcp", addr)
	fmt.Fprintf(plain, "<13>plain syslog to the TLS port\n")
	expect("plain", TLSNotTLS, "TLS handshake")
	if !closedByServer(plain, 2*time.Second) {
		t.Error("plain connection not closed")
	}
	plain.Close()

	if _, err := tls.Dial("tcp", addr, &tls.Config{ServerName: "logs-01.example.net", RootCAs: x509.NewCertPool()}); err == nil {
		t.Fatal("untrusted CA connected")
	}
	expect("untrusted CA", TLSCertRejected, "certificate") // Go clients say bad_certificate, others unknown_ca

	tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11})
	expect("version", TLSVersion, "unsupported versions")

	stall, _ := net.Dial("tcp", addr)
	expect("timeout", TLSTimeout, "no complete handshake within 300ms")
	if !closedByServer(stall, 2*time.Second) {
		t.Error("stalled handshake not closed")
	}
	stall.Close()

	half, _ := net.Dial("tcp", addr)
	half.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x40, 0x01}) // a ClientHello's first bytes, then nothing
	half.Close()
	expect("closed", TLSClosed, "")

	fs := s.TLSFailures()
	if len(fs) != 1 || fs[0].IP != "127.0.0.1" || fs[0].Failures24h != 5 || fs[0].Delivered {
		t.Errorf("failures %+v", fs)
	}
}

// The TCP listener's framing table, over TLS.
func TestTLSFraming(t *testing.T) {
	cfg := tlsConfig(false)
	cfg.MaxMessageBytes = 64
	s, c, pool := startTLS(t, cfg, nil)
	conn, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
	if err != nil {
		t.Fatal(err)
	}
	long := "<14>" + strings.Repeat("y", 100)
	stream := "<13>lf one\n" +
		"<13>crlf two\r\n" +
		"123 not a count\n" +
		"15 <13>octet three" +
		"\n\n" +
		long + "\n" +
		"<13>nul five\x00" +
		"<13>tail without newline"
	for i := 0; i < len(stream); i += 7 { // records straddle frames
		if _, err := conn.Write([]byte(stream[i:min(i+7, len(stream))])); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close()
	got := c.wait(t, 7)
	want := []string{"<13>lf one", "<13>crlf two", "123 not a count", "<13>octet three", long[:64], "<13>nul five", "<13>tail without newline"}
	for i, w := range want {
		if string(got[i].Raw) != w {
			t.Errorf("[%d] %q, want %q", i, got[i].Raw, w)
		}
		if got[i].Truncated != (i == 4) {
			t.Errorf("[%d] truncated = %v", i, got[i].Truncated)
		}
		if got[i].Sender != netip.MustParseAddr("127.0.0.1") {
			t.Errorf("[%d] sender %v", i, got[i].Sender)
		}
	}
	// A final message with no LF and no close_notify (a plain FIN) is kept too.
	raw, _ := net.Dial("tcp", tlsAddr(t, s))
	tc := tls.Client(raw, client(pool))
	tc.Write([]byte("<13>one\n<13>last without LF or close_notify"))
	raw.Close()
	got = c.wait(t, 9)
	if string(got[8].Raw) != "<13>last without LF or close_notify" {
		t.Errorf("last %q", got[8].Raw)
	}
}

// Four parallel connections from one sender all deliver (order across them
// isn't kept), and TCP and TLS share the per-source limit.
func TestTLSParallelAndSharedPool(t *testing.T) {
	cfg := tlsConfig(false)
	cfg.TCP = config.Listener{Enabled: true, Addr: "127.0.0.1", Port: 0}
	cfg.TCPMaxConnsPerSource = 6
	s, c, pool := startTLS(t, cfg, nil)
	var conns []net.Conn
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		conn, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				fmt.Fprintf(conn, "<13>conn %d msg %d\n", i, j)
			}
		}(i)
	}
	wg.Wait()
	c.wait(t, 200)
	waitFor(t, "4 conns", func() bool { return s.Status().TCPConns == 4 })

	// 2 TCP connections take the per-source limit (6) with the 4 TLS ones; the next
	// TLS one, whose handshake completes, is refused at the pool.
	for i := 0; i < 2; i++ {
		tc, err := net.Dial("tcp", tcpAddr(t, s))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(tc, "<13>tcp %d\n", i)
		conns = append(conns, tc)
	}
	c.wait(t, 202)
	waitFor(t, "6 conns", func() bool { return s.Status().TCPConns == 6 })
	extra, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
	if err != nil {
		t.Fatal(err)
	}
	if !closedByServer(extra, 3*time.Second) {
		t.Error("a 7th connection from the sender wasn't refused")
	}
	extra.Close()
	if st := s.Status(); st.TCPConnsPerSourceRefused != 1 || st.TCPConns != 6 {
		t.Errorf("status %+v", st)
	}
	for _, c := range conns {
		c.Close()
	}
	waitFor(t, "all closed", func() bool { return s.Status().TCPConns == 0 })
}

// Handshakes don't take slots: with every handshake slot held by stalled
// handshakes from 300 addresses, established senders keep working, MaxConns
// isn't touched, one address can't hold more than 8, and stalled ones are closed
// at the timeout.
func TestTLSHandshakeLimits(t *testing.T) {
	s, c, pool := startTLS(t, tlsConfig(false), func(o *Options) {
		o.MaxConns = 2
		o.HandshakeTimeout = 1500 * time.Millisecond
	})
	est, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
	if err != nil {
		t.Fatal(err)
	}
	defer est.Close()
	fmt.Fprintf(est, "<13>before\n")
	c.wait(t, 1)

	s.mu.Lock()
	tl := s.tls
	s.mu.Unlock()
	var fars []net.Conn
	for i := 0; i < 300; i++ {
		near, far := net.Pipe()
		fars = append(fars, far)
		tl.handshake(near, netip.AddrFrom4([4]byte{198, 51, byte(i / 250), byte(1 + i%250)}))
	}
	defer func() {
		for _, f := range fars {
			f.Close()
		}
	}()
	st := s.Status()
	if st.TLSHandshakes != DefaultMaxHandshakes || st.TLSHandshakesBusy != 300-DefaultMaxHandshakes || st.TCPConns != 1 {
		t.Errorf("after 300 stalled: in progress %d, busy %d, conns %d", st.TLSHandshakes, st.TLSHandshakesBusy, st.TCPConns)
	}
	fmt.Fprintf(est, "<13>during\n")
	c.wait(t, 2)
	waitFor(t, "the stalled handshakes' timeout", func() bool { return s.Status().TLSHandshakes == 0 })
	if f, _ := failureOf(s, "198.51.0.1"); f.Reason != TLSTimeout {
		t.Errorf("stalled: %+v", f)
	}
	if f, _ := failureOf(s, "198.51.1.50"); f.Reason != TLSBusy {
		t.Errorf("over the limit: %+v", f)
	}

	// One address: at most 8 at once.
	for i := 0; i < 20; i++ {
		near, far := net.Pipe()
		fars = append(fars, far)
		tl.handshake(near, netip.MustParseAddr("203.0.113.9"))
	}
	if st := s.Status(); st.TLSHandshakes != DefaultMaxHandshakesPerAddr {
		t.Errorf("one address holds %d handshakes", st.TLSHandshakes)
	}
	if _, n := failureOf(s, "203.0.113.9"); n != 12 {
		t.Errorf("busy from one address: %d", n)
	}
	// A new sender still connects (the pool has room).
	other, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
}

// countingConn counts the bytes read from the server.
type countingConn struct {
	net.Conn
	mu sync.Mutex
	n  int
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.n += n
	c.mu.Unlock()
	return n, err
}

func (c *countingConn) read() int { c.mu.Lock(); defer c.mu.Unlock(); return c.n }

// After the server closes a connection it writes nothing back (no close_notify,
// and no session tickets after the handshake): these senders never read.
func TestTLSCloseWritesNothing(t *testing.T) {
	s, c, pool := startTLS(t, tlsConfig(false), nil)
	raw, err := net.Dial("tcp", tlsAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	cc := &countingConn{Conn: raw}
	conn := tls.Client(cc, client(pool))
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "<13>x\n")
	c.wait(t, 1)
	after := cc.read()
	s.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read after the server closed: %v", err)
	}
	if n := cc.read() - after; n != 0 {
		t.Errorf("the server wrote %d bytes after the handshake (close_notify or tickets)", n)
	}
}

// Reconfigure: TLS turned on and off live; a TLS change leaves TCP running;
// without a certificate the listener reports an error instead of binding.
func TestTLSReconfigure(t *testing.T) {
	cfg := loopback(0, 0)
	m, pool := testCA(t)
	var mu sync.Mutex
	var cert func() (*tls.Certificate, error) = m.Certificate
	s, c, ev := start(t, cfg, func(o *Options) {
		o.TLSCertificate = func() (*tls.Certificate, error) { mu.Lock(); defer mu.Unlock(); return cert() }
	})
	tcp, _ := net.Dial("tcp", tcpAddr(t, s))
	defer tcp.Close()
	fmt.Fprintf(tcp, "<13>tcp\n")
	c.wait(t, 1)

	cfg.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: 0}
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	conn, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(conn, "<13>tls\n")
	fmt.Fprintf(tcp, "<13>tcp still\n")
	c.wait(t, 3)
	conn.Close()
	ls := s.Status().Listeners
	if len(ls) != 3 || ls[2].Proto != "tls" || !ls[2].OK {
		t.Errorf("listeners %+v", ls)
	}
	if _, ok := ev.find(KindStart); !ok {
		t.Error("no start event")
	}

	cfg.TLS.Enabled = false
	s.Reconfigure(cfg)
	if _, ok := s.TLSAddr(); ok {
		t.Error("TLS still running")
	}
	mu.Lock()
	cert = func() (*tls.Certificate, error) { return nil, errors.New("no certificate yet") }
	mu.Unlock()
	cfg.TLS.Enabled = true
	s.Reconfigure(cfg)
	ls = s.Status().Listeners
	if len(ls) != 3 || ls[2].OK || !strings.Contains(ls[2].Error, "certificate") {
		t.Errorf("without a certificate: %+v", ls)
	}
	mu.Lock()
	cert = m.Certificate
	mu.Unlock()
	if st := s.Retry(); !st.Listeners[2].OK {
		t.Errorf("after Retry: %+v", st.Listeners[2])
	}
}

func TestClassifyHandshake(t *testing.T) {
	for _, c := range []struct {
		err  error
		want string
	}{
		{&net.OpError{Op: "read", Err: errors.New("connection reset by peer")}, TLSClosed},
		{io.EOF, TLSClosed},
		{fmt.Errorf("tls: client offered only unsupported versions: [301]"), TLSVersion},
		{fmt.Errorf("tls: no cipher suite supported by both client and server; client offered: [9c]"), TLSCipher},
		{errors.New("something new"), TLSOther},
	} {
		if got, _ := classifyHandshake(c.err); got != c.want {
			t.Errorf("%v: %s, want %s", c.err, got, c.want)
		}
	}
}

// Close is prompt with idle TCP and TLS connections and a stalled handshake
// open, whatever the idle timeout (24 h) and handshake timeout: it closes them
// all at once rather than waiting for a read deadline.
func TestCloseWithIdleTCPAndTLSIsPrompt(t *testing.T) {
	cfg := tlsConfig(false)
	cfg.TCP = config.Listener{Enabled: true, Addr: "127.0.0.1", Port: 0}
	s, c, pool := startTLS(t, cfg, func(o *Options) { o.HandshakeTimeout = time.Minute })
	tcp, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	fmt.Fprintf(tcp, "<13>tcp\n")
	tc, err := tls.Dial("tcp", tlsAddr(t, s), client(pool))
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	fmt.Fprintf(tc, "<13>tls\n")
	stalled, err := net.Dial("tcp", tlsAddr(t, s)) // a handshake that never starts
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	c.wait(t, 2)
	waitFor(t, "2 conns and a handshake", func() bool { st := s.Status(); return st.TCPConns == 2 && st.TLSHandshakes == 1 })
	t0 := time.Now()
	s.Close()
	if d := time.Since(t0); d > time.Second {
		t.Errorf("Close took %v with idle connections open", d)
	}
	for name, conn := range map[string]net.Conn{"tcp": tcp, "tls": tc, "handshake": stalled} {
		if !closedByServer(conn, time.Second) {
			t.Errorf("%s connection still open after Close", name)
		}
	}
}
