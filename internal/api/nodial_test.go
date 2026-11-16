package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Woodshed makes no outbound connections (SPEC §1, §5). Two checks: no
// non-test file in this package refers to a client-side network API, and
// exercising every route with the default transport and resolver hooked records
// no dial or lookup.

// forbidden lists client-side identifiers by import path.
var forbidden = map[string][]string{
	"net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer",
		"LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS", "LookupPort", "LookupSRV", "LookupTXT",
		"Resolver", "DefaultResolver"},
	"net/http":             {"Get", "Head", "Post", "PostForm", "Client", "DefaultClient", "Transport", "DefaultTransport", "NewRequest", "NewRequestWithContext"},
	"crypto/tls":           {"Dial", "DialWithDialer", "Dialer", "Client"},
	"net/http/httputil":    {"NewSingleHostReverseProxy", "ReverseProxy"},
	"net/smtp":             nil, // any use
	"net/rpc":              nil,
	"os/exec":              nil,
	"net/http/cookiejar":   nil,
	"golang.org/x/net/...": nil,
}

// sendMethods are datagram sends on an unconnected socket (no Dial needed);
// keep them in step with internal/updatecheck's allowlist test.
var sendMethods = map[string]bool{"WriteToUDP": true, "WriteToUDPAddrPort": true, "WriteMsgUDP": true, "WriteMsgUDPAddrPort": true}

func TestNoClientNetworkAPIs(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		checked++
		local := map[string]string{} // local name -> import path
		for _, imp := range file.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(p, "golang.org/x/net") {
				t.Errorf("%s imports %s", f, p)
			}
			if names, ok := forbidden[p]; ok && names == nil {
				t.Errorf("%s imports %s", f, p)
			}
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			local[name] = p
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sendMethods[sel.Sel.Name] {
				t.Errorf("%s: sends a datagram with .%s", fset.Position(sel.Pos()), sel.Sel.Name)
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			p, ok := local[id.Name]
			if !ok {
				return true
			}
			for _, bad := range forbidden[p] {
				if sel.Sel.Name == bad {
					t.Errorf("%s: uses %s.%s (client-side network API)", fset.Position(sel.Pos()), p, bad)
				}
			}
			return true
		})
	}
	if checked < 5 {
		t.Fatalf("checked only %d files", checked)
	}
}

// recordingTransport fails and counts every round trip.
type recordingTransport struct{ n atomic.Int64 }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.n.Add(1)
	return nil, fmt.Errorf("outbound request to %s blocked by test", req.URL.Host)
}

func TestNoHandlerDialsOut(t *testing.T) {
	rt := &recordingTransport{}
	var lookups atomic.Int64
	oldTransport, oldResolver := http.DefaultTransport, net.DefaultResolver
	http.DefaultTransport = rt
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		lookups.Add(1)
		return nil, errors.New("DNS blocked by test")
	}}
	t.Cleanup(func() { http.DefaultTransport, net.DefaultResolver = oldTransport, oldResolver })

	// The test's own client gets its own transport.
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}, Jar: jar}

	// Exercise every route in localhost mode, with the real host identity so
	// certificate generation runs as in production.
	srv := startServer(t, nil, UIConfig{}, func(o *Options) { o.identity = localIdentity })
	for _, rq := range []struct{ method, path, body string }{
		{"GET", "/", ""}, {"GET", "/devices", ""}, {"GET", "/assets/index-BHAE32ir.js", ""},
		{"GET", "/healthz", ""}, {"GET", "/api/status", ""}, {"GET", "/api/stats", ""},
		{"GET", "/api/rejected", ""}, {"GET", "/api/devices", ""},
		{"PATCH", "/api/devices/10.1.0.1", `{"name":"n"}`}, {"PATCH", "/api/devices/none", `{}`},
		{"POST", "/api/listeners/retry", ""}, {"GET", "/api/settings", ""},
		{"GET", "/api/storage/history", ""}, {"GET", "/api/search", ""}, {"GET", "/api/context", ""},
		{"GET", "/api/exports", ""}, {"POST", "/api/exports", `{}`}, {"GET", "/api/exports/x/download", ""},
		{"GET", "/api/session", ""}, {"POST", "/api/login", `{"password":"x"}`}, {"POST", "/api/logout", ""},
		{"GET", "/api/updates", ""}, {"POST", "/api/updates/check", ""}, {"POST", "/api/updates/dismiss", `{"version":"1.2.0"}`},
		{"PUT", "/api/updates", `{"check":"ask"}`},
		{"PUT", "/api/password", `{"new":"password-123"}`},
	} {
		do(t, c, rq.method, srv.url(rq.path), rq.body)
	}
	// The first password turned on require_login_local: log in.
	login(t, srv, c, "password-123")
	srv.b.mu.Lock()
	s := srv.b.settings
	srv.b.mu.Unlock()
	body, _ := json.Marshal(s)
	do(t, c, "PUT", srv.url("/api/settings"), string(body))

	// Live tail: open and close.
	req, _ := http.NewRequest("GET", srv.url("/api/live"), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	if res, err := c.Do(req.WithContext(ctx)); err == nil {
		res.Body.Close()
	}
	cancel()

	// Switch to LAN mode (certificate generation with the real identity, login).
	old := srv.State()
	s.UI.LANMode, s.UI.Port = true, 0
	body, _ = json.Marshal(s)
	do(t, c, "PUT", srv.url("/api/settings"), string(body))
	srv.waitRestart(t, true, old)
	if _, err := os.Stat(filepath.Join(srv.dataDir, CertFile)); err != nil {
		t.Fatal(err)
	}
	tc := tlsClient(t, srv.dataDir)
	do(t, tc, "POST", srv.url("/api/login"), `{"password":"password-123"}`)
	do(t, tc, "GET", srv.url("/api/status"), "")
	do(t, tc, "GET", srv.url("/api/session"), "")
	do(t, httpClient2(), "GET", "http://"+srv.State().Addr+"/", "") // the redirect server

	if n := rt.n.Load(); n != 0 {
		t.Errorf("%d outbound HTTP requests through the default transport", n)
	}
	if n := lookups.Load(); n != 0 {
		t.Errorf("%d DNS lookups through the default resolver", n)
	}
}

// httpClient2 is httpClient with its own transport (the default one is hooked).
func httpClient2() *http.Client {
	c := httpClient()
	c.Transport = &http.Transport{}
	return c
}
