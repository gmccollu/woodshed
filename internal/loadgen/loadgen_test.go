package loadgen

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type sink struct {
	mu   sync.Mutex
	msgs []model.Message
}

func (s *sink) add(m model.Message) { s.mu.Lock(); s.msgs = append(s.msgs, m); s.mu.Unlock() }
func (s *sink) n() int              { s.mu.Lock(); defer s.mu.Unlock(); return len(s.msgs) }

// caFile is the last TLS listener's CA certificate (PEM).
var caFile string

func startListener(t *testing.T, proto string) (*listen.Server, *sink, string) {
	t.Helper()
	k := &sink{}
	ln := config.Listener{Enabled: true, Addr: "127.0.0.1"}
	var cfg config.Listeners
	opts := listen.Options{Sink: k.add, Logger: quiet}
	switch proto {
	case "udp":
		cfg.UDP = ln
	case "tls":
		cfg.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1"}
		m := tlscert.New(tlscert.Options{DataDir: t.TempDir(), Identity: func() (tlscert.Identity, error) {
			return tlscert.Identity{Host: "localhost", Names: []string{"localhost"}, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, nil
		}})
		if _, err := m.Load(true); err != nil {
			t.Fatal(err)
		}
		pem, _ := m.CAPEM()
		caFile = filepath.Join(t.TempDir(), "ca.pem")
		os.WriteFile(caFile, pem, 0o600)
		opts.TLSCertificate = m.Certificate
	default:
		cfg.TCP = ln
	}
	srv, err := listen.Start(cfg, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	ap, ok := srv.UDPAddr()
	switch proto {
	case "tcp":
		ap, ok = srv.TCPAddr()
	case "tls":
		ap, ok = srv.TLSAddr()
	}
	if !ok {
		t.Fatal("listener not running")
	}
	return srv, k, ap.String()
}

func waitN(t *testing.T, k *sink, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for k.n() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if k.n() < n {
		t.Fatalf("received %d of %d", k.n(), n)
	}
}

func TestSendFramings(t *testing.T) {
	for _, tc := range []struct{ proto, framing string }{{"udp", ""}, {"tcp", "lf"}, {"tcp", "octet"}, {"tls", "lf"}, {"tls", "octet"}} {
		t.Run(tc.proto+"-"+tc.framing, func(t *testing.T) {
			_, k, addr := startListener(t, tc.proto)
			o := SendOptions{Addr: addr, Proto: tc.proto, Framing: tc.framing, Count: 500, Size: 300, RunID: "r1", FirstSeq: 10}
			if tc.proto == "tls" {
				cfg, err := ClientTLSConfig(caFile, "", false) // checks 127.0.0.1 against the IP SAN
				if err != nil {
					t.Fatal(err)
				}
				o.TLS = cfg
			}
			res, err := Send(context.Background(), o)
			if err != nil || res.Sent != 500 {
				t.Fatalf("Send: %+v %v", res, err)
			}
			waitN(t, k, 500)
			k.mu.Lock()
			defer k.mu.Unlock()
			for i, m := range k.msgs {
				want := fmt.Sprintf("seq=r1:%d", 10+i)
				if !strings.Contains(string(m.Raw), want+" ") {
					t.Fatalf("[%d] %q lacks %q", i, m.Raw, want)
				}
				if len(m.Raw) != 300 || m.Severity != 6 || m.Hostname != DefaultHostname || m.App != "woodshed" {
					t.Fatalf("[%d] len %d parsed %+v", i, len(m.Raw), m)
				}
				if strings.ContainsAny(string(m.Raw), "\n\r") {
					t.Fatalf("framing leaked into the message: %q", m.Raw)
				}
			}
		})
	}
}

func TestSendRate(t *testing.T) {
	_, k, addr := startListener(t, "udp")
	res, err := Send(context.Background(), SendOptions{Addr: addr, Rate: 2000, Duration: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if res.Sent != 1000 || res.Elapsed < 450*time.Millisecond || res.Elapsed > 1500*time.Millisecond {
		t.Errorf("sent %d in %v", res.Sent, res.Elapsed)
	}
	waitN(t, k, 1000)
}

func TestSendErrors(t *testing.T) {
	ctx := context.Background()
	for _, o := range []SendOptions{
		{}, {Addr: "127.0.0.1:1", Proto: "sctp", Count: 1}, {Addr: "127.0.0.1:1", Framing: "crlf", Count: 1},
		{Addr: "127.0.0.1:1"}, {Addr: "127.0.0.1:1", Count: 1, RunID: "a:b"},
		{Addr: "127.0.0.1:1", Proto: "tls", Count: 1}, // no TLS config
	} {
		if _, err := Send(ctx, o); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
	// Nothing listening on TCP: a dial error. Port 1 (tcpmux) is never served on a test machine; reusing a UDP
	// listener's port number for TCP flaked on Windows, where another parallel test can hold that TCP port.
	if _, err := Send(ctx, SendOptions{Addr: "127.0.0.1:1", Proto: "tcp", Count: 1}); err == nil {
		t.Error("TCP send to a closed port succeeded")
	}
}

func writeLog(t *testing.T, dir, dev string, lines ...string) {
	t.Helper()
	p := filepath.Join(dir, logfile.LogsDir, dev, "2026-11-10.log")
	os.MkdirAll(filepath.Dir(p), 0o750)
	var b []byte
	for i, l := range lines {
		b = logfile.AppendLine(b, time.Date(2026, 11, 10, 1, 0, i, 0, time.UTC), netip.MustParseAddr(dev), []byte(l))
	}
	if err := os.WriteFile(p, b, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestVerify(t *testing.T) {
	dir := t.TempDir()
	// 0..4 sent; 2 missing, 3 twice, plus a foreign line and an out-of-range seq.
	writeLog(t, dir, "192.0.2.1", "<134>1 - h woodshed - - - seq=run1:0 pad", "<134>1 - h woodshed - - - seq=run1:3", "other device text")
	writeLog(t, dir, "192.0.2.2", "<134>1 - h woodshed - - - seq=run1:1 x", "<134>1 - h woodshed - - - seq=run1:3 y",
		"<134>1 - h woodshed - - - seq=run1:4", "seq=run1:99", "seq=run2:2")
	v, err := Verify(dir, "run1", 5)
	if err != nil {
		t.Fatal(err)
	}
	if v.Received != 4 || v.Missing != 1 || v.Duplicates != 1 || v.Foreign != 3 || v.LogBytes == 0 {
		t.Errorf("%+v", v)
	}
}

func TestBenchSmall(t *testing.T) {
	for _, tc := range []struct{ proto, framing string }{{"udp", ""}, {"tcp", "lf"}, {"tcp", "octet"}, {"tls", "lf"}, {"tls", "octet"}} {
		t.Run(tc.proto+"-"+tc.framing, func(t *testing.T) {
			res, err := Bench(context.Background(), BenchOptions{Proto: tc.proto, Framing: tc.framing, Rate: 2000, Duration: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			t.Log("\n" + res.String())
			if !res.OK() || res.Sent != 2000 || res.Received != 2000 || res.Stored != 2000 || res.Listened != 2000 {
				t.Errorf("%+v", res)
			}
			if _, err := os.Stat(res.DataDir); !os.IsNotExist(err) {
				t.Errorf("temp data dir left behind: %v", err)
			}
		})
	}
}

func TestBenchKeepDataDir(t *testing.T) {
	dir := t.TempDir()
	res, err := Bench(context.Background(), BenchOptions{Rate: 1000, Duration: 200 * time.Millisecond, DataDir: dir})
	if err != nil || !res.OK() {
		t.Fatalf("%+v %v", res, err)
	}
	files, _, _ := logfile.List(dir)
	if len(files) != 1 || res.LogBytes == 0 {
		t.Errorf("files %+v", files)
	}
	// A second run in the same dir counts the first run's lines as foreign.
	res2, err := Bench(context.Background(), BenchOptions{Rate: 1000, Duration: 200 * time.Millisecond, DataDir: dir})
	if err != nil || !res2.OK() || res2.Foreign != res.Sent {
		t.Fatalf("second run %+v %v", res2, err)
	}
}

func TestClientTLSConfig(t *testing.T) {
	if _, err := ClientTLSConfig("", "", false); err == nil {
		t.Error("no CA and not insecure accepted")
	}
	if c, err := ClientTLSConfig("", "", true); err != nil || !c.InsecureSkipVerify {
		t.Errorf("insecure: %v", err)
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := ClientTLSConfig(bad, "", false); err == nil {
		t.Error("a file without a certificate accepted")
	}
	if _, err := ClientTLSConfig(filepath.Join(dir, "missing.pem"), "", false); err == nil {
		t.Error("a missing file accepted")
	}
}
