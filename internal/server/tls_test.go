package server

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

var tlsFiles = []string{tlscert.CAFile, tlscert.CAKeyFile, tlscert.CertFile, tlscert.KeyFile}

func readTLSFiles(t *testing.T, dataDir string) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, f := range tlsFiles {
		b, err := os.ReadFile(filepath.Join(dataDir, f))
		if err != nil {
			t.Fatal(err)
		}
		out[f] = b
	}
	return out
}

func get(t *testing.T, r *running, path string) (int, []byte, http.Header) {
	t.Helper()
	resp, err := http.Get(r.base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func bannerKinds(bs []api.Banner) []string {
	var out []string
	for _, b := range bs {
		out = append(out, b.Kind)
	}
	return out
}

// TLS off by default makes no key files; turning it on in Settings makes the CA
// and the certificate before the PUT returns, and a message sent over TLS with
// the downloaded CA is stored. Renew keeps the CA; a restart and a new host name
// change nothing (the banner only).
func TestTLSEndToEnd(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	tlsPort := freePort(t)
	cfgPath := writeConfig(t, dir, port, 0, func(c *config.Config) {
		c.Listeners.TLS.Addr, c.Listeners.TLS.Port = "127.0.0.1", tlsPort
	})
	dataDir := filepath.Join(dir, "data")
	r := start(t, cfgPath)

	for _, f := range tlsFiles {
		if _, err := os.Stat(filepath.Join(dataDir, f)); !os.IsNotExist(err) {
			t.Errorf("%s exists before TLS was turned on", f)
		}
	}
	var ts api.TLSState
	r.do(t, "GET", "/api/tls", nil, &ts)
	if ts.Enabled || ts.CA != nil || ts.Cert != nil || ts.Source != "woodshed" || ts.Port != tlsPort {
		t.Errorf("before: %+v", ts)
	}
	if code, _, _ := get(t, r, "/api/tls/ca.pem"); code != 404 {
		t.Errorf("ca.pem before: %d", code)
	}
	var renew api.TLSState
	if code := r.do(t, "POST", "/api/tls/renew", map[string]bool{"new_ca": false}, nil); code != 409 {
		t.Errorf("renew before TLS was on: %d", code)
	}

	// Turn it on in Settings.
	var set api.Settings
	r.do(t, "GET", "/api/settings", nil, &set)
	if set.Listeners.TLS.Enabled || set.Listeners.TLS.Port != tlsPort {
		t.Fatalf("settings tls %+v", set.Listeners.TLS)
	}
	set.Listeners.TLS.Enabled = true
	if code := r.do(t, "PUT", "/api/settings", set, nil); code != 200 {
		t.Fatalf("PUT: %d", code)
	}
	files := readTLSFiles(t, dataDir)
	r.do(t, "GET", "/api/tls", nil, &ts)
	if !ts.Enabled || ts.CA == nil || ts.Cert == nil || !ts.CA.NotAfter.Equal(tlscert.Cap) || ts.Firewall.State != fwrule.StateUnknown {
		t.Fatalf("after: %+v", ts)
	}
	var st api.Status
	r.do(t, "GET", "/api/status", nil, &st)
	if len(st.Listeners) != 3 || st.Listeners[2].Proto != "tls" || !st.Listeners[2].OK || st.Listeners[2].Port != tlsPort {
		t.Fatalf("listeners %+v", st.Listeners)
	}

	// The downloaded CA (PEM and DER are the same certificate) verifies the server.
	code, caPEM, hdr := get(t, r, "/api/tls/ca.pem")
	blk, _ := pem.Decode(caPEM)
	if code != 200 || blk == nil || !bytes.Equal(caPEM, files[tlscert.CAFile]) || hdr.Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("ca.pem: %d %v", code, hdr)
	}
	if _, der, _ := get(t, r, "/api/tls/ca.der"); !bytes.Equal(der, blk.Bytes) {
		t.Error("ca.der isn't the PEM's certificate")
	}
	if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "woodshed-ca.pem")
	os.WriteFile(caFile, caPEM, 0o600)
	tcfg, err := loadgen.ClientTLSConfig(caFile, "localhost", false)
	if err != nil {
		t.Fatal(err)
	}
	run := loadgen.NewRunID()
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", tlsPort), Proto: "tls", TLS: tcfg, Count: 50, RunID: run,
	}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "50 messages in the index", func() bool {
		var page api.DevicePage
		r.do(t, "GET", "/api/devices", nil, &page)
		return len(page.Devices) == 1 && page.Devices[0].TotalMsgs == 50 && page.Devices[0].TLS != nil
	})

	// Plain syslog to the TLS port: a not_tls failure, listed with the device.
	c, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", tlsPort))
	fmt.Fprintf(c, "<13>plain\n")
	var fails []api.TLSFailure
	waitFor(t, "the failure", func() bool {
		r.do(t, "GET", "/api/tls/failures", nil, &fails)
		return len(fails) == 1
	})
	c.Close()
	if f := fails[0]; f.IP != "127.0.0.1" || f.Reason != "not_tls" || f.DeviceID != "127.0.0.1" || f.Count24h != 1 {
		t.Errorf("failure %+v", f)
	}
	var page api.DevicePage
	r.do(t, "GET", "/api/devices", nil, &page)
	if d := page.Devices[0].TLS; d == nil || d.Connections24h != 1 || d.Version != "TLS 1.3" || d.Failures24h != 1 ||
		d.LastFailure == nil || d.LastFailure.Reason != "not_tls" || d.LastConnected == nil {
		t.Errorf("device tls %+v", d)
	}

	// The legacy banner, and none of the others.
	set.Listeners.TLS.AllowLegacyTLS = true
	r.do(t, "PUT", "/api/settings", set, nil)
	r.do(t, "GET", "/api/status", nil, &st)
	if k := bannerKinds(hostBanners(st.Banners)); !slices.Equal(k, []string{"tls_legacy"}) {
		t.Errorf("banners %v", k)
	}

	// Renew: same CA, new leaf, an event with both fingerprints.
	old := ts.Cert.SHA256
	if code := r.do(t, "POST", "/api/tls/renew", map[string]bool{"new_ca": false}, &renew); code != 200 {
		t.Fatalf("renew: %d", code)
	}
	after := readTLSFiles(t, dataDir)
	if !bytes.Equal(after[tlscert.CAFile], files[tlscert.CAFile]) || bytes.Equal(after[tlscert.CertFile], files[tlscert.CertFile]) ||
		renew.Cert.SHA256 == old || renew.CA.SHA256 != ts.CA.SHA256 {
		t.Errorf("renew: CA kept %v, leaf changed %v", bytes.Equal(after[tlscert.CAFile], files[tlscert.CAFile]), renew.Cert.SHA256 != old)
	}
	evs, _ := r.srv.be.idx.Events(context.Background(), time.Time{}, time.Time{}, 100)
	var tlsEvents []string
	for _, e := range evs {
		if e.Kind == index.KindTLS {
			tlsEvents = append(tlsEvents, e.Text)
		}
	}
	if len(tlsEvents) != 2 || !strings.Contains(strings.Join(tlsEvents, "\n"), old+" → "+renew.Cert.SHA256) {
		t.Errorf("TLS events %q", tlsEvents)
	}
	// The sender keeps working with the same CA.
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{
		Addr: fmt.Sprintf("127.0.0.1:%d", tlsPort), Proto: "tls", TLS: tcfg, Count: 5, RunID: run, FirstSeq: 50,
	}); err != nil {
		t.Fatalf("send after renew: %v", err)
	}

	// A new host name raises tls_cert_names and changes no file; nor does a restart.
	set.Listeners.TLS.AllowLegacyTLS = false
	set.UI.ExtraHostnames = []string{"edge-logs.example.net"}
	if code := r.do(t, "PUT", "/api/settings", set, nil); code != 200 {
		t.Fatalf("PUT hostnames: %d", code)
	}
	waitFor(t, "the names banner", func() bool {
		r.do(t, "GET", "/api/status", nil, &st)
		return slices.Contains(bannerKinds(st.Banners), "tls_cert_names")
	})
	for _, b := range st.Banners {
		if b.Kind == "tls_cert_names" && (!strings.Contains(b.Text, "edge-logs.example.net") || b.Action != "tls_renew") {
			t.Errorf("banner %+v", b)
		}
	}
	r.stop(t)
	r = start(t, cfgPath)
	r.do(t, "GET", "/api/status", nil, &st)
	if len(st.Listeners) != 3 || !st.Listeners[2].OK {
		t.Errorf("after restart: %+v", st.Listeners)
	}
	for f, b := range readTLSFiles(t, dataDir) {
		if !bytes.Equal(b, after[f]) {
			t.Errorf("%s changed without an explicit action", f)
		}
	}
	// The run-state file is written shortly after a (re)start, not before the API answers: wait for it.
	var rs RunState
	waitFor(t, "the run-state file with TLS", func() bool {
		rs, err = ReadState(dataDir)
		return err == nil && rs.TLS != nil && rs.TLS.CertSHA256 == renew.Cert.SHA256
	})
	if err != nil || rs.TLS == nil || rs.TLS.CASHA256 != ts.CA.SHA256 || rs.TLS.CertSHA256 != renew.Cert.SHA256 || !rs.TLS.Enabled {
		t.Errorf("run state tls %+v (%v)", rs.TLS, err)
	}

	// Replace CA via the API, then turn TLS off: the files stay.
	if code := r.do(t, "POST", "/api/tls/renew", map[string]bool{"new_ca": true}, &renew); code != 200 || renew.CA.SHA256 == ts.CA.SHA256 {
		t.Errorf("replace CA: %d", code)
	}
	r.do(t, "GET", "/api/settings", nil, &set)
	set.Listeners.TLS.Enabled = false
	r.do(t, "PUT", "/api/settings", set, nil)
	r.do(t, "GET", "/api/status", nil, &st)
	if len(st.Listeners) != 2 {
		t.Errorf("TLS still listed: %+v", st.Listeners)
	}
	readTLSFiles(t, dataDir)
}

// A user's own certificate: no CA download, renew is a 409, a bad pair is a 400
// on both keys.
func TestTLSUserCertificate(t *testing.T) {
	dir := t.TempDir()
	// A pair made with Woodshed's own code, in another folder.
	newPair := func() (certPath, keyPath string) {
		d := t.TempDir()
		m := tlscert.New(tlscert.Options{DataDir: d, Identity: func() (tlscert.Identity, error) {
			return tlscert.Identity{Host: "localhost", Names: []string{"localhost"}}, nil
		}})
		if _, err := m.Load(true); err != nil {
			t.Fatal(err)
		}
		return filepath.Join(d, tlscert.CertFile), filepath.Join(d, tlscert.KeyFile)
	}
	certPath, keyPath := newPair()
	tlsPort := freePort(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: tlsPort, CertFile: certPath, KeyFile: keyPath}
	})
	r := start(t, cfgPath)
	var ts api.TLSState
	r.do(t, "GET", "/api/tls", nil, &ts)
	if ts.Source != "file" || ts.CA != nil || ts.Cert == nil {
		t.Errorf("state %+v", ts)
	}
	if code, body, _ := get(t, r, "/api/tls/ca.pem"); code != 404 || !strings.Contains(string(body), "whoever issued it") {
		t.Errorf("ca.pem: %d %s", code, body)
	}
	if code := r.do(t, "POST", "/api/tls/renew", map[string]bool{"new_ca": false}, nil); code != 409 {
		t.Errorf("renew: %d", code)
	}
	for _, f := range tlsFiles {
		if _, err := os.Stat(filepath.Join(dir, "data", f)); !os.IsNotExist(err) {
			t.Errorf("%s made in the data folder for a user certificate", f)
		}
	}
	// A mismatched pair.
	var set api.Settings
	r.do(t, "GET", "/api/settings", nil, &set)
	_, set.Listeners.TLS.KeyFile = newPair()
	var errBody struct {
		Errors map[string]string `json:"errors"`
	}
	if code := r.do(t, "PUT", "/api/settings", set, &errBody); code != 400 ||
		!strings.Contains(errBody.Errors["listeners.tls.cert_file"], "match") || !strings.Contains(errBody.Errors["listeners.tls.key_file"], "match") {
		t.Errorf("mismatched pair: %d %v", code, errBody.Errors)
	}
}

// `woodshed tls renew` leaves a request; the service carries it out at start
// (as its own account), records it and removes the request.
func TestTLSRenewRequestAtStart(t *testing.T) {
	dir := t.TempDir()
	tlsPort := freePort(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: tlsPort}
	})
	dataDir := filepath.Join(dir, "data")
	r := start(t, cfgPath)
	before := readTLSFiles(t, dataDir)
	r.stop(t)

	if err := WriteTLSRenewRequest(dataDir, false); err != nil {
		t.Fatal(err)
	}
	r = start(t, cfgPath)
	after := readTLSFiles(t, dataDir)
	if !bytes.Equal(before[tlscert.CAFile], after[tlscert.CAFile]) || bytes.Equal(before[tlscert.CertFile], after[tlscert.CertFile]) {
		t.Error("the request wasn't a same-CA renewal")
	}
	if _, err := os.Stat(filepath.Join(dataDir, TLSRenewRequestFile)); !os.IsNotExist(err) {
		t.Error("the request is still there")
	}
	evs, _ := r.srv.be.idx.Events(context.Background(), time.Time{}, time.Time{}, 100)
	n := 0
	for _, e := range evs {
		if e.Kind == index.KindTLS && strings.Contains(e.Text, "Renewed") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d renew events", n)
	}
}

// The Windows rule's state is the installed service's only (TLS decision 4): a
// portable copy or `woodshed run` reports "unknown" and shows no banner, whatever
// rule the host has; the service reports what it reads, with the command.
func TestTLSFirewallStateOnlyForService(t *testing.T) {
	cfg := config.Default()
	cfg.Listeners.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: 6514}
	b := &backend{now: time.Now, log: quiet, tlsc: newTLSSide(t.TempDir(), cfg.Listeners.TLS, time.Now, func() []string { return nil })}
	reads := 0
	b.tlsc.fwCheck = func(port int) string { reads++; return fwrule.StateDisabled }
	for _, service := range []bool{false, true} {
		b.isService = service
		ts := b.tlsState(cfg)
		kinds := bannerKinds(b.tlsBanners(cfg, time.Now()))
		if !service && (ts.Firewall.State != fwrule.StateUnknown || ts.Firewall.Command != "" || slices.Contains(kinds, "tls_firewall") || reads != 0) {
			t.Errorf("not the service: firewall %+v, banners %v, reads %d", ts.Firewall, kinds, reads)
		}
		if service && (ts.Firewall.State != fwrule.StateDisabled || ts.Firewall.Command != "woodshed tls on" || !slices.Contains(kinds, "tls_firewall")) {
			t.Errorf("the service: firewall %+v, banners %v", ts.Firewall, kinds)
		}
	}
}

// A host name added in Settings shows in the certificate status as soon as
// the PUT returns, even with the status read all the while (the run-state
// writer and the UI do). The save used to recheck the names before the new
// config was in place, so a status read in between cached the old names for
// identityRecheck (1 min): the tls_cert_names banner stayed away (seen on a
// starved runner in TestTLSEndToEnd).
func TestExtraHostnameSeenWhileStatusIsRead(t *testing.T) {
	dir := t.TempDir()
	tlsPort := freePort(t)
	r := start(t, writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.TLS = config.TLSListener{Enabled: true, Addr: "127.0.0.1", Port: tlsPort}
	}))
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				r.srv.be.tlsc.certs.Status()
			}
		}
	}()
	defer func() { close(stop); <-done }()
	var set api.Settings
	r.do(t, "GET", "/api/settings", nil, &set)
	for i := range 30 {
		name := fmt.Sprintf("edge-%d.example.net", i)
		set.UI.ExtraHostnames = []string{name}
		if code := r.do(t, "PUT", "/api/settings", set, &set); code != 200 {
			t.Fatalf("PUT %d", code)
		}
		if missing := r.srv.be.tlsc.certs.Status().MissingNames; !slices.Contains(missing, name) {
			t.Fatalf("round %d: right after the PUT, missing names %v lack %s", i, missing, name)
		}
	}
}
