package updatecheck_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// The same client-side network and process APIs internal/api's
// TestNoClientNetworkAPIs forbids there (keep the two lists in step).
var forbidden = map[string][]string{
	"net": {"Dial", "DialTimeout", "DialTCP", "DialUDP", "DialIP", "DialUnix", "Dialer",
		"LookupHost", "LookupIP", "LookupAddr", "LookupCNAME", "LookupMX", "LookupNS", "LookupPort", "LookupSRV", "LookupTXT",
		"Resolver", "DefaultResolver"},
	"net/http":           {"Get", "Head", "Post", "PostForm", "Client", "DefaultClient", "Transport", "DefaultTransport", "NewRequest", "NewRequestWithContext"},
	"crypto/tls":         {"Dial", "DialWithDialer", "Dialer", "Client"},
	"net/http/httputil":  {"NewSingleHostReverseProxy", "ReverseProxy"},
	"net/smtp":           nil, // any use
	"net/rpc":            nil,
	"os/exec":            nil,
	"net/http/cookiejar": nil,
}

// sendMethods are the datagram sends that need no Dial: a method call on an
// unconnected UDP socket, which can send to any address. A package that calls
// them sends packets on its own, so it's on the allowlist too (SPEC §12.4).
var sendMethods = map[string]bool{"WriteToUDP": true, "WriteToUDPAddrPort": true, "WriteMsgUDP": true, "WriteMsgUDPAddrPort": true}

// allowed are the packages (directories from the module root) that may use
// them, and why. Adding one is a reviewed change (SPEC §10.2).
var allowed = map[string]string{
	"internal/updatecheck":        "the opt-in update check: the only package that connects to a host Woodshed picks itself",
	"internal/updatecheck/uctest": "test support for the update check (local servers only); imported only by tests",
	"internal/poller":             "SNMP polls to the devices the user configured",
	"internal/snmp/agenttest":     "test support for the poller (a test SNMP agent answering on loopback); imported only by tests",
	"internal/loadgen":            "woodshed send and bench: send to the address the user gives",
	"internal/peer":               "loopback to another Woodshed on this machine",
	"internal/listen":             "OS helpers (who holds a port), and SNMP inform Responses and Reports on the trap socket",
	"internal/service":            "OS helpers (the service manager)",
	"internal/fwrule":             "OS helpers (the host firewall's own programs: netsh, ufw, firewall-cmd); no network",
	"cmd/woodshed":                "the command line: OS helpers, and woodshed status asking the local server",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

// goFiles lists every non-test .go file in the module by package directory.
func goFiles(t *testing.T, root string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", "testdata", "vendor", ".git", "dist":
				return filepath.SkipDir
			}
			// The repo's top-level tmp/ is gitignored scratch space (copies of
			// old trees live there), not part of the module that ships.
			if rel, _ := filepath.Rel(root, p); filepath.ToSlash(rel) == "tmp" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			rel = filepath.ToSlash(rel)
			out[rel] = append(out[rel], p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestClientNetworkAllowlist: only the allowlisted packages use the client-side
// network and process APIs, and every allowlisted package still does (a stale
// entry would let a new use slip in unnoticed).
func TestClientNetworkAllowlist(t *testing.T) {
	root := moduleRoot(t)
	pkgs := goFiles(t, root)
	if len(pkgs) < 15 {
		t.Fatalf("found only %d packages under %s", len(pkgs), root)
	}
	fset := token.NewFileSet()
	users := map[string][]string{} // package -> what it uses
	for dir, files := range pkgs {
		for _, f := range files {
			file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			local := map[string]string{}
			for _, imp := range file.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if names, ok := forbidden[p]; ok && names == nil || strings.HasPrefix(p, "golang.org/x/net") {
					users[dir] = append(users[dir], fset.Position(imp.Pos()).String()+" imports "+p)
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
					users[dir] = append(users[dir], fset.Position(sel.Pos()).String()+" sends with ."+sel.Sel.Name)
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				if p, ok := local[id.Name]; ok && slices.Contains(forbidden[p], sel.Sel.Name) {
					users[dir] = append(users[dir], fset.Position(sel.Pos()).String()+" uses "+p+"."+sel.Sel.Name)
				}
				return true
			})
		}
	}
	for dir, uses := range users {
		if _, ok := allowed[dir]; !ok {
			t.Errorf("%s uses client-side network or process APIs and isn't on the allowlist (SPEC §10.2):\n  %s",
				dir, strings.Join(uses, "\n  "))
		}
	}
	for dir := range allowed {
		if len(users[dir]) == 0 {
			t.Errorf("%s is on the allowlist but no longer uses those APIs: remove it", dir)
		}
	}
}

// TestReleasesHostOnlyHere: the releases host appears in no other package's
// code, and uctest is imported only by tests.
func TestReleasesHostOnlyHere(t *testing.T) {
	root := moduleRoot(t)
	fset := token.NewFileSet()
	for dir, files := range goFiles(t, root) {
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if dir != "internal/updatecheck" && strings.Contains(string(b), "gmccollu.github.io") {
				t.Errorf("%s names the releases host; use updatecheck.URL", f)
			}
			file, err := parser.ParseFile(fset, f, b, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if strings.HasSuffix(p, "/internal/updatecheck/uctest") {
					t.Errorf("%s imports uctest outside a test", f)
				}
				if strings.HasSuffix(p, "/internal/snmp/agenttest") {
					t.Errorf("%s imports the test SNMP agent outside a test", f)
				}
			}
		}
	}
}
