package setuphelper

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// go test ./internal/setuphelper -update rewrites testdata/golden/.
var update = flag.Bool("update", false, "rewrite the golden files")

// sample is the server every golden file is rendered for: documentation
// addresses and names only.
func sample() Server {
	return Server{
		HostIPs:   []string{"192.0.2.10", "2001:db8::10"},
		Names:     []string{"logs-01.example.net", "logs-01"},
		TLSNames:  []string{"localhost", "logs-01", "logs-01.example.net", "logs-01.local"},
		TLSSource: "woodshed",
		CASHA256:  "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89",
		UDP:       Listener{Enabled: true, Addr: "0.0.0.0", Port: 514},
		TCP:       Listener{Enabled: true, Addr: "0.0.0.0", Port: 514},
		TLS:       Listener{Enabled: true, Addr: "0.0.0.0", Port: 6514},
		Trap:      Listener{Enabled: true, Addr: "0.0.0.0", Port: 162},
	}
}

// goldenCase is one golden file: a request against a server.
type goldenCase struct {
	name string
	srv  Server
	req  Request
}

func goldenCases(t *testing.T) []goldenCase {
	t.Helper()
	var cs []goldenCase
	// Every family, data type and transport with the default choices.
	for _, f := range Families() {
		for _, w := range f.What {
			for _, tr := range f.Transports[w] {
				cs = append(cs, goldenCase{name: f.ID + "-" + w + "-" + tr, srv: sample(), req: Request{Family: f.ID, What: w, Transport: tr}})
			}
		}
	}
	off := sample()
	off.TLS.Enabled, off.Trap.Enabled = false, false
	bound := sample()
	bound.UDP.Addr = "192.0.2.20"
	noTLS := sample()
	noTLS.TLSNames, noTLS.TLSSource, noTLS.CASHA256 = nil, "", ""
	flow := sample()
	flow.Flow = &FlowListener{Enabled: true, Addr: "0.0.0.0", FlowPort: 2056, IPFIXPort: 4740}
	flowOff := sample()
	flowOff.Flow = &FlowListener{Addr: "0.0.0.0", FlowPort: 2055, IPFIXPort: 4739}
	ipfixOnly := sample()
	ipfixOnly.Flow = &FlowListener{Enabled: true, Addr: "0.0.0.0", IPFIXPort: 4739}
	cs = append(cs,
		goldenCase{"choices-line-cli-syslog-tcp", sample(), Request{Family: "line-cli", What: "syslog", Transport: "tcp", Severity: "warning",
			Facility: "local5", SourceInterface: "Vlan10"}},
		goldenCase{"choices-set-cli-syslog-udp", sample(), Request{Family: "set-cli", What: "syslog", Severity: "debug", Facility: "local3"}},
		goldenCase{"choices-rsyslog-syslog-tls-name", sample(), Request{Family: "rsyslog", What: "syslog", Transport: "tls",
			Address: "logs-01.example.net", Facility: "local4", Severity: "notice"}},
		goldenCase{"choices-rsyslog-syslog-tls-no-cert-yet", noTLS, Request{Family: "rsyslog", What: "syslog", Transport: "tls"}},
		goldenCase{"choices-net-snmp-trap-v3-ipv6", sample(), Request{Family: "net-snmp", What: "trap", Transport: "v3", Address: "2001:db8::10",
			V3User: "monitor", Auth: "sha"}},
		goldenCase{"choices-net-snmp-poll-v2c-port", sample(), Request{Family: "net-snmp", What: "poll", Transport: "v2c", AgentPort: 1161}},
		goldenCase{"choices-net-snmp-poll-v3-ipv6", sample(), Request{Family: "net-snmp", What: "poll", Transport: "v3", Address: "2001:db8::10",
			V3User: "monitor"}},
		goldenCase{"choices-softflowd-flow-ipfix-iface", sample(), Request{Family: "softflowd", What: "flow", Transport: "ipfix", Interface: "eth1"}},
		goldenCase{"choices-line-cli-flow-listener", flow, Request{Family: "line-cli", What: "flow", Transport: "ipfix", SourceInterface: "Loopback0"}},
		goldenCase{"flow-listener-off-softflowd-v9", flowOff, Request{Family: "softflowd", What: "flow", Transport: "v9"}},
		// The flow port is off: v9 goes to the IPFIX port, which takes every version.
		goldenCase{"flow-ipfix-port-only-line-cli-v9", ipfixOnly, Request{Family: "line-cli", What: "flow", Transport: "v9"}},
		goldenCase{"listener-off-web-ui-syslog-tls", off, Request{Family: "web-ui", What: "syslog", Transport: "tls"}},
		goldenCase{"listener-off-line-cli-trap", off, Request{Family: "line-cli", What: "trap"}},
		goldenCase{"bound-line-cli-syslog-udp", bound, Request{Family: "line-cli", What: "syslog", Transport: "udp"}},
		goldenCase{"bound-other-address", bound, Request{Family: "line-cli", What: "syslog", Transport: "udp", Address: "192.0.2.10"}},
		goldenCase{"no-addresses", Server{UDP: Listener{Enabled: true, Port: 514}}, Request{Family: "web-ui", What: "syslog"}},
	)
	return cs
}

func dump(s Snippet) string {
	var b strings.Builder
	fmt.Fprintf(&b, "family: %s\nwhat: %s\ntransport: %s\naddress: %s\nverification: %s\n", s.Family, s.What, s.Transport, s.Address, s.Verification)
	if s.CheckedOn != "" {
		fmt.Fprintf(&b, "checked_on: %s\n", s.CheckedOn)
	}
	fmt.Fprintf(&b, "reference: %s\ndoes: %s\ncheck: %s\nplaceholders: %s\naddresses: %s\n", s.Reference, s.Does, s.Check,
		strings.Join(s.Placeholders, " "), strings.Join(s.Addresses, " "))
	b.WriteString("notes:\n")
	for _, n := range s.Notes {
		fmt.Fprintf(&b, "- %s\n", n)
	}
	for _, p := range s.Parts {
		fmt.Fprintf(&b, "---- part %s %q: %s\n%s", p.Kind, p.Path, p.Title, p.Text)
	}
	b.WriteString("==== text\n" + s.Text)
	return b.String()
}

func TestGolden(t *testing.T) {
	dir := filepath.Join("testdata", "golden")
	if *update {
		os.RemoveAll(dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, c := range goldenCases(t) {
		t.Run(c.name, func(t *testing.T) {
			s, err := Generate(c.srv, c.req)
			if err != nil {
				t.Fatal(err)
			}
			got := dump(s)
			path := filepath.Join(dir, c.name+".golden")
			seen[c.name+".golden"] = true
			if *update {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run go test ./internal/setuphelper -update)", err)
			}
			if got != strings.ReplaceAll(string(want), "\r\n", "\n") {
				t.Errorf("%s differs from the golden file; if the change is meant, run go test ./internal/setuphelper -update and review the diff.\n--- got\n%s", path, got)
			}
		})
	}
	if !*update {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !seen[e.Name()] {
				t.Errorf("stale golden file %s (run with -update)", e.Name())
			}
		}
	}
}

func TestEveryTemplateRenders(t *testing.T) {
	ts, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 15 {
		t.Errorf("%d templates, want 15", len(ts))
	}
	for _, tm := range ts {
		for _, tr := range tm.Transports {
			s, err := Generate(sample(), Request{Family: tm.Family, What: tm.What, Transport: tr})
			if err != nil {
				t.Errorf("%s %s: %v", tm.File, tr, err)
				continue
			}
			if s.Does == "" || s.Check == "" || len(s.Parts) == 0 || s.Text == "" {
				t.Errorf("%s %s: empty does, check, parts or text: %+v", tm.File, tr, s)
			}
			for _, p := range s.Parts {
				if p.Title == "" || strings.TrimSpace(p.Text) == "" {
					t.Errorf("%s %s: an empty part %+v", tm.File, tr, p)
				}
				if p.Kind == PartFile && p.Path == "" {
					t.Errorf("%s %s: a file part without a path", tm.File, tr)
				}
			}
			if strings.Contains(s.Text, "<no value>") || strings.Contains(s.Text, "{{") {
				t.Errorf("%s %s: unfilled template text:\n%s", tm.File, tr, s.Text)
			}
			// Reference-only snippets say so, in the contract's words.
			if (tm.Verification == Reference) != slices.Contains(s.Notes, ReferenceOnlyNote) {
				t.Errorf("%s %s: verification %s, notes %q", tm.File, tr, tm.Verification, s.Notes)
			}
		}
	}
}

// The TCP warning is on every TCP and TLS syslog snippet for network devices
// (every family but rsyslog), and nowhere else.
func TestTCPWarning(t *testing.T) {
	for _, f := range Families() {
		for _, w := range f.What {
			for _, tr := range f.Transports[w] {
				s, err := Generate(sample(), Request{Family: f.ID, What: w, Transport: tr})
				if err != nil {
					t.Fatal(err)
				}
				want := w == WhatSyslog && tr != "udp" && f.ID != "rsyslog"
				if got := slices.Contains(s.Notes, TCPWarning); got != want {
					t.Errorf("%s %s %s: TCP warning %v, want %v", f.ID, w, tr, got, want)
				}
			}
		}
	}
	if !strings.Contains(TCPWarning, "permit traffic when the log host is down") {
		t.Error("the warning lost the option's name")
	}
}

// Server holds no secret, and the snippets' secrets are placeholders.
func TestSecretsArePlaceholders(t *testing.T) {
	for _, f := range Families() {
		for _, w := range f.What {
			for _, tr := range f.Transports[w] {
				s, _ := Generate(sample(), Request{Family: f.ID, What: w, Transport: tr})
				switch {
				case tr == "v2c" && !slices.Contains(s.Placeholders, "<COMMUNITY>"):
					t.Errorf("%s %s v2c: no <COMMUNITY>", f.ID, w)
				case tr == "v3" && (!slices.Contains(s.Placeholders, "<AUTH-PASSPHRASE>") || !slices.Contains(s.Placeholders, "<PRIV-PASSPHRASE>")):
					t.Errorf("%s %s v3: placeholders %v", f.ID, w, s.Placeholders)
				}
				for _, ph := range s.Placeholders {
					if !strings.Contains(s.Text, ph) {
						t.Errorf("%s %s %s: placeholder %s not in the text", f.ID, w, tr, ph)
					}
				}
			}
		}
	}
}

func TestFamilies(t *testing.T) {
	fs := Families()
	var got []string
	for _, f := range fs {
		got = append(got, f.ID+":"+strings.Join(f.What, ",")+":"+f.Verification)
	}
	want := []string{"line-cli:syslog,trap,poll,flow:reference", "set-cli:syslog,trap,poll:reference", "rsyslog:syslog:tested",
		"net-snmp:trap,poll:tested", "softflowd:flow:tested", "web-ui:syslog,trap,poll,flow:reference"}
	if !slices.Equal(got, want) {
		t.Errorf("families\n got %v\nwant %v", got, want)
	}
	for _, f := range fs {
		for _, w := range f.What {
			if len(f.Transports[w]) == 0 || f.Choices[w] == nil {
				t.Errorf("%s %s: transports %v choices %v", f.ID, w, f.Transports[w], f.Choices[w])
			}
		}
		if f.Label == "" || f.Reference == "" || len(f.Notes) == 0 {
			t.Errorf("%s: %+v", f.ID, f)
		}
	}
}

func TestRequestErrors(t *testing.T) {
	for _, c := range []struct {
		req   Request
		field string
	}{
		{Request{Family: "nope", What: "syslog"}, "family"},
		{Request{Family: "rsyslog", What: "nope"}, "what"},
		{Request{Family: "rsyslog", What: "trap"}, "what"},
		{Request{Family: "rsyslog", What: "syslog", Transport: "v3"}, "transport"},
		{Request{Family: "rsyslog", What: "syslog", Address: "a b"}, "address"},
		{Request{Family: "rsyslog", What: "syslog", Address: `x"; rm -rf /`}, "address"},
		{Request{Family: "rsyslog", What: "syslog", Address: "fe80::1%eth0"}, "address"},
		{Request{Family: "rsyslog", What: "syslog", Address: "999.1.1.1"}, "address"},
		{Request{Family: "rsyslog", What: "syslog", Severity: "loud"}, "severity"},
		{Request{Family: "rsyslog", What: "syslog", Facility: "kern"}, "facility"},
		{Request{Family: "rsyslog", What: "syslog", SourceInterface: "eth0"}, "source_interface"},
		{Request{Family: "line-cli", What: "syslog", SourceInterface: "eth0\nlogging host 198.51.100.1"}, "source_interface"},
		{Request{Family: "net-snmp", What: "trap", Transport: "v2c", V3User: "monitor"}, "v3_user"},
		{Request{Family: "net-snmp", What: "trap", Transport: "v3", V3User: "a user"}, "v3_user"},
		{Request{Family: "net-snmp", What: "trap", Transport: "v3", Auth: "md5"}, "auth"},
		{Request{Family: "net-snmp", What: "trap", Transport: "v3", Priv: "des"}, "priv"},
		{Request{Family: "net-snmp", What: "poll", AgentPort: 70000}, "agent_port"},
		{Request{Family: "net-snmp", What: "trap", AgentPort: 1161}, "agent_port"},
		{Request{Family: "softflowd", What: "flow", Interface: "eth0 -n 198.51.100.1:9"}, "interface"},
	} {
		_, err := Generate(sample(), c.req)
		var e *Error
		if !errors.As(err, &e) || e.Field != c.field {
			t.Errorf("%+v: %v, want an error on %s", c.req, err, c.field)
		}
	}
}

func TestDefaults(t *testing.T) {
	s, err := Generate(sample(), Request{Family: "rsyslog", What: "syslog"})
	if err != nil {
		t.Fatal(err)
	}
	if s.Transport != "udp" || s.Address != "192.0.2.10" || !strings.Contains(s.Text, "*.info") {
		t.Errorf("defaults: %+v", s)
	}
	// The first transport whose listener is on.
	srv := sample()
	srv.UDP.Enabled = false
	if s, _ := Generate(srv, Request{Family: "rsyslog", What: "syslog"}); s.Transport != "tcp" {
		t.Errorf("with UDP off: %s", s.Transport)
	}
	// A listener bound to one address offers that one first.
	srv = sample()
	srv.TCP.Addr = "192.0.2.30"
	if s, _ := Generate(srv, Request{Family: "rsyslog", What: "syslog", Transport: "tcp"}); s.Address != "192.0.2.30" || s.Addresses[0] != "192.0.2.30" {
		t.Errorf("bound: %s %v", s.Address, s.Addresses)
	}
	// Loopback only when there's nothing else.
	srv = Server{HostIPs: nil, Names: []string{"localhost"}, UDP: Listener{Enabled: true, Addr: "127.0.0.1", Port: 514}}
	if s, _ := Generate(srv, Request{Family: "rsyslog", What: "syslog"}); s.Address != "127.0.0.1" {
		t.Errorf("loopback: %s %v", s.Address, s.Addresses)
	}
	// IPv6 is bracketed where a port follows, and an IPv4-mapped address is unmapped.
	if s, _ := Generate(sample(), Request{Family: "softflowd", What: "flow", Address: "2001:db8::10"}); !strings.Contains(s.Text, "-n [2001:db8::10]:2055") {
		t.Errorf("IPv6: %s", s.Text)
	}
	if s, _ := Generate(sample(), Request{Family: "rsyslog", What: "syslog", Address: "::ffff:192.0.2.10"}); s.Address != "192.0.2.10" {
		t.Errorf("mapped: %s", s.Address)
	}
	// TLS checks a name on the certificate: the address itself when it's one,
	// else the first that isn't localhost.
	if s, _ := Generate(sample(), Request{Family: "rsyslog", What: "syslog", Transport: "tls"}); !strings.Contains(s.Text, `StreamDriverPermittedPeers="logs-01"`) {
		t.Errorf("TLS name for an IP: %s", s.Text)
	}
	if s, _ := Generate(sample(), Request{Family: "rsyslog", What: "syslog", Transport: "tls", Address: "LOGS-01.example.net."}); !strings.Contains(s.Text, `StreamDriverPermittedPeers="logs-01.example.net"`) {
		t.Errorf("TLS name for a name: %s", s.Text)
	}
}

// A template header that breaks the rules is refused at load.
func TestTemplateHeaders(t *testing.T) {
	body := "{{define \"does\"}}x{{end}}{{define \"parts\"}}\n@@part cli - t\nx\n{{end}}{{define \"notes\"}}{{end}}{{define \"check\"}}x{{end}}"
	head := func(lines ...string) string { return "{{/*\n" + strings.Join(lines, "\n") + "\n*/}}\n" + body }
	ok := []string{"family: rsyslog", "what: syslog", "transports: udp", "reference: r"}
	for _, c := range []struct {
		name, src string
	}{
		{"rsyslog-syslog.tmpl", head(append(ok, "verification: sure")...)},
		{"rsyslog-syslog.tmpl", head(append(ok, "verification: lab_checked")...)},
		{"rsyslog-syslog.tmpl", head(append(ok, "verification: tested", "checked_on: 2026-11-16")...)},
		{"rsyslog-syslog.tmpl", head("family: rsyslog", "what: syslog", "transports: v3", "reference: r", "verification: tested")},
		{"rsyslog-syslog.tmpl", head("family: rsyslog", "what: syslog", "transports: udp", "verification: tested")},
		{"rsyslog-trap.tmpl", head(append(ok, "verification: tested")...)},
		{"rsyslog-syslog.tmpl", body},
	} {
		if _, err := parseTemplate(c.name, c.src); err == nil {
			t.Errorf("accepted:\n%s", c.src)
		}
	}
	if tm, err := parseTemplate("rsyslog-syslog.tmpl", head(append(ok, "verification: lab_checked", "checked_on: 2026-11-16")...)); err != nil || tm.CheckedOn != "2026-11-16" {
		t.Errorf("lab_checked: %v %+v", err, tm)
	}
}
