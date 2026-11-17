// Package setuphelper generates the configuration a device needs to send its
// syslog, traps and flows to Woodshed, or to let Woodshed poll it (SPEC §13.5,
// docs/api.md "Setup helper").
//
// The snippets are grouped in families named by syntax, never by vendor or
// product: a line-oriented CLI, a hierarchical set-style CLI, Linux rsyslog,
// net-snmp's snmpd and snmptrap, softflowd, and a web-UI checklist. Each
// family and data type is one template in templates/, with a header naming
// the family, the public reference it follows and its verification level.
//
// A snippet is filled from this Woodshed's own settings (Server: its
// addresses, the names on its TLS certificate, its ports and which listeners
// are on) and the user's choices (Request). Secrets are always placeholders
// (<COMMUNITY>, <AUTH-PASSPHRASE>): Server has no field that could hold one,
// so no stored secret can reach a snippet. Generating one changes nothing.
//
// The package is pure: no I/O beyond its embedded templates.
package setuphelper

import (
	"bytes"
	"cmp"
	"embed"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"text/template"
)

// Verification levels (SPEC §13.5).
const (
	// Tested: CI applies the snippet to the real open-source tool against a
	// real Woodshed and checks the data arrives.
	Tested = "tested"
	// LabChecked: applied by hand on lab gear, on the date in the header.
	LabChecked = "lab_checked"
	// Reference: the commands follow common, documented syntax, but nothing
	// runs them.
	Reference = "reference"
)

// ReferenceOnlyNote is shown next to every Reference-only snippet (SPEC
// §13.11 #5).
const ReferenceOnlyNote = "Reference only: not tested on a device; check your device's documentation."

// TCPWarning is the 1.1 warning (SPEC §10.3.9), on every TCP and TLS syslog
// snippet for network devices.
const TCPWarning = "Before you turn on TCP or TLS logging on a firewall: some firewalls block traffic through them when a TCP or TLS syslog server can't be reached, or its certificate fails, unless a \"permit traffic when the log host is down\" option is set. Check that option first, or use UDP."

// Data types ("what").
const (
	WhatSyslog = "syslog"
	WhatTrap   = "trap"
	WhatPoll   = "poll"
	WhatFlow   = "flow"
)

// whatOrder is the order data types are listed in.
var whatOrder = []string{WhatSyslog, WhatTrap, WhatPoll, WhatFlow}

// transports per data type, the first being the default.
var transports = map[string][]string{
	WhatSyslog: {"udp", "tcp", "tls"},
	WhatTrap:   {"v2c", "v3"},
	WhatPoll:   {"v2c", "v3"},
	WhatFlow:   {"v9", "ipfix"},
}

// Choice names (Request fields), as the API and the UI spell them.
const (
	ChoiceSourceInterface = "source_interface"
	ChoiceInterface       = "interface"
	ChoiceSeverity        = "severity"
	ChoiceFacility        = "facility"
	ChoiceV3User          = "v3_user"
	ChoiceAuth            = "auth"
	ChoicePriv            = "priv"
	ChoiceAgentPort       = "agent_port"
)

// Family is one syntax family (GET /api/setup/families).
type Family struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// What lists the data types the family has templates for.
	What []string `json:"what"`
	// Verification is the family's lowest level across its templates.
	Verification string `json:"verification"`
	// CheckedOn is the date of a lab check (lab_checked only).
	CheckedOn string `json:"checked_on,omitempty"`
	Reference string `json:"reference"`
	// Transports per data type, the default first; every data type is a key,
	// [] for the ones the family has no template for.
	Transports map[string][]string `json:"transports"`
	// Choices per data type: the Request fields that change its snippet
	// (every data type is a key, like Transports).
	Choices map[string][]string `json:"choices"`
	// Notes about the family as a whole.
	Notes []string `json:"notes"`
}

// family is a family's fixed description; its templates fill in the rest.
type family struct {
	id, label, reference string
	notes                []string
	// choices per data type (the v3 ones are added for v3 transports by the page).
	choices map[string][]string
}

var v3Choices = []string{ChoiceV3User, ChoiceAuth, ChoicePriv}

// families in the order the page lists them.
var families = []family{
	{id: "line-cli", label: "Line-oriented CLI (global configuration mode)", reference: "the device's own documentation",
		notes: []string{
			"For devices configured with one command per line in a global configuration mode (`logging host …`, `snmp-server host …`).",
			"Only lines that are the same on most such devices are given as text; keywords that differ are placeholders (<TCP-OPTION>, <SHA-256-KEYWORD>) to fill in from the device's documentation.",
			"No flow template: flow export commands differ too much between devices of this style to give one that's useful. Use the web UI checklist's values (collector address, port, version, active and inactive timeouts, template refresh) with your device's documentation.",
		},
		choices: map[string][]string{
			WhatSyslog: {ChoiceSourceInterface, ChoiceSeverity, ChoiceFacility},
			WhatTrap:   {ChoiceSourceInterface, ChoiceV3User, ChoiceAuth, ChoicePriv},
			WhatPoll:   {ChoiceV3User, ChoiceAuth, ChoicePriv},
		}},
	{id: "set-cli", label: "Hierarchical set-style CLI", reference: "the device's own documentation; RFC 3413 and RFC 3415 for the SNMPv3 structure",
		notes: []string{
			"For devices configured with `set` statements in a hierarchy, applied with `commit` (`set system syslog host …`).",
			"No flow template: flow export statements differ too much between set-style devices to give one that's useful. Use the web UI checklist's values with your device's documentation.",
		},
		choices: map[string][]string{
			WhatSyslog: {ChoiceSeverity, ChoiceFacility},
			WhatTrap:   {ChoiceV3User, ChoiceAuth, ChoicePriv},
			WhatPoll:   {ChoiceV3User, ChoiceAuth, ChoicePriv},
		}},
	{id: "rsyslog", label: "Linux: rsyslog", reference: "rsyslog documentation: the omfwd action and the gtls network stream driver",
		notes: []string{"For Linux and other Unix-like machines that run rsyslog, the usual system logger on many distributions."},
		choices: map[string][]string{
			WhatSyslog: {ChoiceSeverity, ChoiceFacility},
		}},
	{id: "net-snmp", label: "Linux: net-snmp `snmpd` and `snmptrap`", reference: "net-snmp manual pages: snmpd.conf(5), snmp.conf(5), snmptrap(1)",
		notes: []string{"For machines that run net-snmp's agent (snmpd), or send traps with its snmptrap tool."},
		choices: map[string][]string{
			WhatTrap: {ChoiceV3User, ChoiceAuth, ChoicePriv},
			WhatPoll: {ChoiceAgentPort, ChoiceV3User, ChoiceAuth, ChoicePriv},
		}},
	{id: "softflowd", label: "Linux: softflowd", reference: "softflowd(8) manual page",
		notes: []string{"softflowd watches a network interface and exports the flows it sees, for machines that have no flow export of their own."},
		choices: map[string][]string{
			WhatFlow: {ChoiceInterface},
		}},
	{id: "web-ui", label: "Web UI checklist", reference: "the device's own documentation",
		notes: []string{"For appliances configured through a web page: the fields to fill in and their values, in the order most pages ask for them. Field names differ between devices."},
		choices: map[string][]string{
			WhatSyslog: {ChoiceSeverity, ChoiceFacility},
			WhatTrap:   {ChoiceV3User, ChoiceAuth, ChoicePriv},
			WhatPoll:   {ChoiceV3User, ChoiceAuth, ChoicePriv},
		}},
}

// Severities, most severe first: the RFC 5424 keyword, then how the
// families spell it.
type severity struct {
	Name string // RFC 5424 / rsyslog keyword
	Num  int
	Line string // line-oriented CLI keyword
	Set  string // set-style CLI keyword
	Word string // for people
}

var severities = []severity{
	{"emerg", 0, "emergencies", "emergency", "emergency"},
	{"alert", 1, "alerts", "alert", "alert"},
	{"crit", 2, "critical", "critical", "critical"},
	{"err", 3, "errors", "error", "error"},
	{"warning", 4, "warnings", "warning", "warning"},
	{"notice", 5, "notifications", "notice", "notice"},
	{"info", 6, "informational", "info", "informational"},
	{"debug", 7, "debugging", "any", "debug"},
}

// Severities returns the severity choices, most severe first.
func Severities() []string {
	out := make([]string, len(severities))
	for i, s := range severities {
		out[i] = s.Name
	}
	return out
}

// Facilities returns the facility choices ("" is the device's default).
func Facilities() []string {
	return []string{"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"}
}

// v3 protocols offered: the ones most devices and net-snmp share.
// Placeholder stands for the device's own keyword (line-oriented CLIs spell
// these differently: sha-256, sha256, sha2-256).
type authProto struct {
	ID, Label, NetSNMP, Placeholder, Set string
}

var auths = []authProto{
	{"sha-256", "SHA-256", "SHA-256", "<SHA-256-KEYWORD>", "authentication-sha256"},
	{"sha", "SHA-1", "SHA", "<SHA-1-KEYWORD>", "authentication-sha"},
}

type privProto struct {
	ID, Label, NetSNMP, Placeholder, Set string
}

var privs = []privProto{
	{"aes-128", "AES-128", "AES", "<AES-128-KEYWORD>", "privacy-aes128"},
}

// AuthChoices and PrivChoices are the v3 protocol choices, the default first.
func AuthChoices() []string { return ids(auths, func(a authProto) string { return a.ID }) }

// PrivChoices: see AuthChoices.
func PrivChoices() []string { return ids(privs, func(p privProto) string { return p.ID }) }

func ids[T any](s []T, f func(T) string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = f(v)
	}
	return out
}

// Listener is one of this Woodshed's listeners.
type Listener struct {
	Enabled bool
	Addr    string // the bind address ("0.0.0.0" or "::" for every address)
	Port    int
}

// FlowListener is the flow collector's listener (2.0).
type FlowListener struct {
	Enabled bool
	Addr    string
	// FlowPort is listeners.flow.flow_port (flow v5 and v9 by default) and
	// IPFIXPort listeners.flow.ipfix_port; 0 is off. Either port accepts
	// every version.
	FlowPort  int
	IPFIXPort int
}

// Default flow ports (SPEC §13.1).
const (
	DefaultFlowPort  = 2055
	DefaultIPFIXPort = 4739
)

// Server is what a snippet needs to know about this Woodshed. It never holds
// a secret.
type Server struct {
	// HostIPs are this machine's addresses devices could send to (IPv4 first).
	HostIPs []string
	// Names are DNS names for this machine: the TLS certificate's, then
	// ui.extra_hostnames.
	Names []string
	// TLSNames are the DNS names on the TLS certificate ([] before TLS was
	// first turned on).
	TLSNames []string
	// TLSSource is "woodshed" (its own CA), "file" (the user's own
	// certificate) or "" (TLS never turned on).
	TLSSource string
	// CASHA256 is the CA certificate's SHA-256 fingerprint, when known.
	CASHA256 string

	UDP, TCP, TLS Listener
	// Trap is the SNMP trap receiver.
	Trap Listener
	// Flow is nil when this build has no flow listener.
	Flow *FlowListener
}

// Request is one snippet's choices (POST /api/setup/snippet).
type Request struct {
	Family    string `json:"family"`
	What      string `json:"what"`
	Transport string `json:"transport,omitempty"`
	// Address is Woodshed's address as the device should use it; "" is the
	// first of Addresses.
	Address string `json:"address,omitempty"`
	// SourceInterface is the device's interface its packets should leave
	// from (CLI families; "" leaves the line out).
	SourceInterface string `json:"source_interface,omitempty"`
	// Interface is the interface softflowd watches.
	Interface string `json:"interface,omitempty"`
	// Severity is the lowest severity to send (RFC 5424 keyword; "" is info).
	Severity string `json:"severity,omitempty"`
	// Facility is local0..local7, or "" for the device's default (rsyslog:
	// every facility).
	Facility string `json:"facility,omitempty"`
	// V3User is the SNMPv3 user name ("" is a placeholder).
	V3User string `json:"v3_user,omitempty"`
	Auth   string `json:"auth,omitempty"`
	Priv   string `json:"priv,omitempty"`
	// AgentPort is the port the device's SNMP agent listens on (polling;
	// absent is 161; 0 or more than 65535 is an error).
	AgentPort *int `json:"agent_port,omitempty"`
}

// Part is one piece of a snippet: a file to add to, commands to run, lines
// to enter at a device's prompt, or fields to fill in.
type Part struct {
	// Kind is "file", "command", "cli" or "steps".
	Kind string `json:"kind"`
	// Path is the file's usual location (kind "file"), else "".
	Path  string `json:"path"`
	Title string `json:"title"`
	Text  string `json:"text"`
}

// Part kinds.
const (
	PartFile    = "file"
	PartCommand = "command"
	PartCLI     = "cli"
	PartSteps   = "steps"
)

// Snippet is the body of POST /api/setup/snippet.
type Snippet struct {
	Family       string `json:"family"`
	What         string `json:"what"`
	Transport    string `json:"transport"`
	Address      string `json:"address"`
	Verification string `json:"verification"`
	CheckedOn    string `json:"checked_on,omitempty"`
	// VerificationDetail says, for a Tested snippet, what CI applies and
	// what it can't.
	VerificationDetail string `json:"verification_detail,omitempty"`
	Reference          string `json:"reference"`
	// Does is a short "what this does" line.
	Does string `json:"does"`
	// Text is every part, for one Copy.
	Text  string `json:"text"`
	Parts []Part `json:"parts"`
	// Notes come first for anything that needs action before the snippet
	// works (a listener that's off).
	Notes []string `json:"notes"`
	// Check says how to see that it worked.
	Check string `json:"check"`
	// Placeholders are the values the user fills in, in order of first use.
	Placeholders []string `json:"placeholders"`
	// Addresses are this Woodshed's addresses the page offers.
	Addresses []string `json:"addresses"`
}

// Error is a request the helper can't generate a snippet for.
type Error struct {
	Field string // the Request field (JSON name)
	Msg   string
}

func (e *Error) Error() string { return e.Field + ": " + e.Msg }

func badField(field, format string, a ...any) error {
	return &Error{Field: field, Msg: fmt.Sprintf(format, a...)}
}

// ---- templates ----

//go:embed templates/*.tmpl
var templateFS embed.FS

// Template is one template's header.
type Template struct {
	File         string
	Family       string
	What         string
	Transports   []string
	Reference    string
	Verification string
	CheckedOn    string
	// CI says what CI applies, for a tested template (and what it can't).
	CI string
	// Source is the template file's text.
	Source string

	tmpl *template.Template
}

var (
	loaded   []*Template
	loadErr  error
	headerRe = regexp.MustCompile(`(?s)\A\{\{/\*\n(.*?)\n\*/\}\}\n`)
	dateRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
)

func init() { loaded, loadErr = load() }

// Templates returns every template, by family order then data type.
func Templates() ([]*Template, error) { return loaded, loadErr }

func load() ([]*Template, error) {
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, err
	}
	var out []*Template
	for _, e := range entries {
		b, err := templateFS.ReadFile("templates/" + e.Name())
		if err != nil {
			return nil, err
		}
		t, err := parseTemplate(e.Name(), string(b))
		if err != nil {
			return nil, fmt.Errorf("setuphelper: %s: %w", e.Name(), err)
		}
		out = append(out, t)
	}
	order := map[string]int{}
	for i, f := range families {
		order[f.id] = i
	}
	slices.SortFunc(out, func(a, b *Template) int {
		return cmp.Or(cmp.Compare(order[a.Family], order[b.Family]),
			cmp.Compare(slices.Index(whatOrder, a.What), slices.Index(whatOrder, b.What)))
	})
	for i := 1; i < len(out); i++ {
		if out[i].Family == out[i-1].Family && out[i].What == out[i-1].What {
			return nil, fmt.Errorf("setuphelper: two templates for %s %s", out[i].Family, out[i].What)
		}
	}
	return out, nil
}

func parseTemplate(name, src string) (*Template, error) {
	m := headerRe.FindStringSubmatch(src)
	if m == nil {
		return nil, fmt.Errorf("no header comment")
	}
	t := &Template{File: name, Source: src}
	for _, line := range strings.Split(m[1], "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("header line %q has no colon", line)
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "family":
			t.Family = v
		case "what":
			t.What = v
		case "transports":
			for _, s := range strings.Split(v, ",") {
				t.Transports = append(t.Transports, strings.TrimSpace(s))
			}
		case "reference":
			t.Reference = v
		case "verification":
			t.Verification = v
		case "checked_on":
			t.CheckedOn = v
		case "ci":
			t.CI = v
		default:
			return nil, fmt.Errorf("unknown header key %q", k)
		}
	}
	if familyByID(t.Family) == nil {
		return nil, fmt.Errorf("unknown family %q", t.Family)
	}
	all, ok := transports[t.What]
	if !ok {
		return nil, fmt.Errorf("unknown data type %q", t.What)
	}
	if want := strings.TrimSuffix(name, ".tmpl"); want != t.Family+"-"+t.What {
		return nil, fmt.Errorf("file name should be %s-%s.tmpl", t.Family, t.What)
	}
	if len(t.Transports) == 0 {
		return nil, fmt.Errorf("no transports")
	}
	for _, tr := range t.Transports {
		if !slices.Contains(all, tr) {
			return nil, fmt.Errorf("transport %q isn't one of %v", tr, all)
		}
	}
	if t.Reference == "" {
		return nil, fmt.Errorf("no reference")
	}
	if (t.Verification == Tested) != (t.CI != "") {
		return nil, fmt.Errorf("a tested template says what CI applies (ci:), and only a tested one")
	}
	switch t.Verification {
	case Tested, Reference:
		if t.CheckedOn != "" {
			return nil, fmt.Errorf("checked_on goes with lab_checked only")
		}
	case LabChecked:
		if !dateRe.MatchString(t.CheckedOn) {
			return nil, fmt.Errorf("lab_checked needs checked_on: YYYY-MM-DD")
		}
	default:
		return nil, fmt.Errorf("verification %q isn't tested, lab_checked or reference", t.Verification)
	}
	tm, err := template.New(name).Option("missingkey=error").Parse(src)
	if err != nil {
		return nil, err
	}
	for _, block := range []string{"does", "parts", "notes", "check"} {
		if tm.Lookup(block) == nil {
			return nil, fmt.Errorf("no {{define %q}} block", block)
		}
	}
	t.tmpl = tm
	return t, nil
}

func familyByID(id string) *family {
	for i := range families {
		if families[i].id == id {
			return &families[i]
		}
	}
	return nil
}

func lookup(familyID, what string) *Template {
	for _, t := range loaded {
		if t.Family == familyID && t.What == what {
			return t
		}
	}
	return nil
}

var levelRank = map[string]int{Reference: 0, LabChecked: 1, Tested: 2}

// Families lists every family with its templates' data types and levels.
func Families() []Family {
	out := []Family{}
	for _, f := range families {
		fam := Family{ID: f.id, Label: f.label, Reference: f.reference, What: []string{}, Transports: map[string][]string{},
			Choices: map[string][]string{}, Notes: slices.Clone(f.notes), Verification: Tested}
		for _, w := range whatOrder {
			fam.Transports[w], fam.Choices[w] = []string{}, []string{}
		}
		for _, t := range loaded {
			if t.Family != f.id {
				continue
			}
			fam.What = append(fam.What, t.What)
			fam.Transports[t.What] = slices.Clone(t.Transports)
			fam.Choices[t.What] = append([]string{}, f.choices[t.What]...)
			if levelRank[t.Verification] < levelRank[fam.Verification] {
				fam.Verification = t.Verification
			}
			if t.Verification == LabChecked && t.CheckedOn > fam.CheckedOn {
				fam.CheckedOn = t.CheckedOn
			}
		}
		if fam.Verification != LabChecked {
			fam.CheckedOn = ""
		}
		if len(fam.What) > 0 {
			out = append(out, fam)
		}
	}
	return out
}

// ---- generating ----

// sanitized is s with only values a snippet can take: IP addresses
// (unmapped) and host names that match hostnameRe. Wildcard certificate names
// ("*.example.net"), and anything with a quote, space or newline, are dropped,
// so nothing from a certificate or the config can add text to a snippet.
func (s Server) sanitized() Server {
	ips := func(in []string) []string {
		var out []string
		for _, a := range in {
			if ip, err := netip.ParseAddr(a); err == nil && ip.Zone() == "" {
				if v := ip.Unmap().String(); !slices.Contains(out, v) {
					out = append(out, v)
				}
			}
		}
		return out
	}
	names := func(in []string) []string {
		var out []string
		for _, n := range in {
			if ip, err := netip.ParseAddr(n); err == nil {
				if ip.Zone() == "" && !slices.Contains(out, ip.Unmap().String()) {
					out = append(out, ip.Unmap().String())
				}
				continue
			}
			if isHostname(n) {
				if v := strings.TrimSuffix(strings.ToLower(n), "."); !slices.Contains(out, v) {
					out = append(out, v)
				}
			}
		}
		return out
	}
	s.HostIPs = ips(s.HostIPs)
	s.Names = names(s.Names)
	var tls []string
	for _, n := range s.TLSNames {
		if isHostname(n) {
			tls = append(tls, strings.TrimSuffix(strings.ToLower(n), "."))
		}
	}
	s.TLSNames = tls
	unmap := func(l *Listener) {
		if ip, err := netip.ParseAddr(l.Addr); err == nil {
			l.Addr = ip.Unmap().String()
		}
	}
	unmap(&s.UDP)
	unmap(&s.TCP)
	unmap(&s.TLS)
	unmap(&s.Trap)
	if s.Flow != nil {
		f := *s.Flow
		if ip, err := netip.ParseAddr(f.Addr); err == nil {
			f.Addr = ip.Unmap().String()
		}
		s.Flow = &f
	}
	return s
}

// isHostname reports whether n is a host name a snippet can carry: letters,
// digits, hyphens and dots, at least one letter or hyphen, at most 253.
func isHostname(n string) bool {
	return len(n) <= 253 && hostnameRe.MatchString(n) && strings.ContainsAny(n, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-")
}

// quoteOrEmpty is s quoted, or "an empty value" for "".
func quoteOrEmpty(s string) string {
	if s == "" {
		return "an empty value"
	}
	return fmt.Sprintf("%q", s)
}

// Addresses is the list the page offers, the default first: the listener's
// own address when it's bound to one, else this machine's IPs, then its
// names. Loopback addresses come last, and only when there's nothing else.
func (s Server) Addresses(bound string) []string {
	s = s.sanitized()
	var out, loop []string
	add := func(a string) {
		if a == "" || slices.Contains(out, a) || slices.Contains(loop, a) {
			return
		}
		if ip, err := netip.ParseAddr(a); err == nil && ip.IsLoopback() || a == "localhost" {
			loop = append(loop, a)
			return
		}
		out = append(out, a)
	}
	if ip, err := netip.ParseAddr(bound); err == nil && !ip.IsUnspecified() && ip.Zone() == "" {
		add(ip.Unmap().String())
	}
	for _, a := range s.HostIPs {
		add(a)
	}
	for _, a := range s.Names {
		add(a)
	}
	if len(out) == 0 {
		out = loop
	}
	return out
}

// The choices' patterns, in a syntax Go and JavaScript share (the UI's mock
// validates with the same ones, from the generated fixture). hostname is
// matched ignoring case.
const (
	hostnamePattern  = `^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))*\.?$`
	interfacePattern = `^[A-Za-z0-9][A-Za-z0-9/._:@-]{0,63}$`
	userPattern      = `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`
)

// Patterns are the choices' patterns (hostname ignoring case).
func Patterns() map[string]string {
	return map[string]string{"hostname": hostnamePattern, "interface": interfacePattern, "user": userPattern}
}

var (
	hostnameRe  = regexp.MustCompile(`(?i)` + hostnamePattern)
	interfaceRe = regexp.MustCompile(interfacePattern)
	userRe      = regexp.MustCompile(userPattern)
	placeRe     = regexp.MustCompile(`<[A-Z][A-Z0-9-]*>`)
)

// tdata is what a template sees.
type tdata struct {
	Family    string
	What      string
	Transport string
	// Address is Woodshed's address; IsIPv6 says how to bracket it.
	Address string
	IsIPv6  bool
	IsName  bool
	Port    int
	// TLSName is the name a TLS client should check (a DNS name on the
	// certificate), or a placeholder.
	TLSName      string
	TLSNameKnown bool
	TLSOwnCA     bool
	CASHA256     string

	Severity        severity
	Facility        string
	SourceInterface string
	Interface       string
	V3User          string
	Auth            authProto
	Priv            privProto
	AgentPort       int
}

// HostPort is address:port, with IPv6 in brackets.
func (d tdata) HostPort() string {
	if d.IsIPv6 {
		return "[" + d.Address + "]:" + fmt.Sprint(d.Port)
	}
	return d.Address + ":" + fmt.Sprint(d.Port)
}

// NetSNMPAddr is net-snmp's transport address: udp:host:port or udp6:[host]:port.
func (d tdata) NetSNMPAddr() string {
	if d.IsIPv6 {
		return "udp6:" + d.HostPort()
	}
	return "udp:" + d.HostPort()
}

// Generate makes one snippet.
func Generate(s Server, r Request) (Snippet, error) {
	if loadErr != nil {
		return Snippet{}, loadErr
	}
	f := familyByID(r.Family)
	if f == nil {
		return Snippet{}, badField("family", "%q isn't a setup family (%s)", r.Family, strings.Join(familyIDs(), ", "))
	}
	if _, ok := transports[r.What]; !ok {
		return Snippet{}, badField("what", "%q isn't syslog, trap, poll or flow", r.What)
	}
	t := lookup(r.Family, r.What)
	if t == nil {
		return Snippet{}, badField("what", "the %s family has no %s snippet (it has %s)", f.label, r.What, strings.Join(familyWhat(r.Family), ", "))
	}
	d := tdata{Family: r.Family, What: r.What, Transport: r.Transport}
	if d.Transport == "" {
		d.Transport = defaultTransport(s, r.What, t.Transports)
	}
	if !slices.Contains(t.Transports, d.Transport) {
		return Snippet{}, badField("transport", "%q isn't one of %s for %s", d.Transport, strings.Join(t.Transports, ", "), r.What)
	}
	// The v3 choices apply to the v3 transport only.
	allowed := slices.DeleteFunc(slices.Clone(f.choices[r.What]), func(c string) bool {
		return !isV3(d.Transport) && slices.Contains(v3Choices, c)
	})
	given := map[string]bool{ChoiceSourceInterface: r.SourceInterface != "", ChoiceInterface: r.Interface != "",
		ChoiceSeverity: r.Severity != "", ChoiceFacility: r.Facility != "", ChoiceV3User: r.V3User != "", ChoiceAuth: r.Auth != "",
		ChoicePriv: r.Priv != "", ChoiceAgentPort: r.AgentPort != nil}
	for _, c := range []string{ChoiceSourceInterface, ChoiceInterface, ChoiceSeverity, ChoiceFacility, ChoiceV3User, ChoiceAuth, ChoicePriv, ChoiceAgentPort} {
		if given[c] && !slices.Contains(allowed, c) {
			return Snippet{}, badField(c, "doesn't apply to %s %s (%s)", r.Family, r.What, d.Transport)
		}
	}

	s = s.sanitized()
	lst, listenerName := s.listenerFor(r.What, d.Transport)
	addrs := s.Addresses(lst.Addr)
	d.Address = r.Address
	if d.Address == "" {
		if len(addrs) > 0 {
			d.Address = addrs[0] // valid: Addresses keeps only IPs and host names
		} else {
			d.Address = "<WOODSHED-ADDRESS>"
		}
	}
	if d.Address != "<WOODSHED-ADDRESS>" || r.Address != "" {
		ip, err := netip.ParseAddr(d.Address)
		switch {
		case err == nil && ip.Zone() == "":
			ip = ip.Unmap()
			d.Address, d.IsIPv6 = ip.String(), ip.Is6()
		case err == nil:
			return Snippet{}, badField("address", "an address with a zone (%%) can't go in a device's configuration")
		case isHostname(d.Address):
			d.Address, d.IsName = strings.TrimSuffix(strings.ToLower(d.Address), "."), true
		default:
			return Snippet{}, badField("address", "%s isn't an IP address or a host name", quoteOrEmpty(d.Address))
		}
	}
	d.Port = lst.Port

	if r.What == WhatSyslog {
		d.Severity = severities[6]
		if r.Severity != "" {
			i := slices.IndexFunc(severities, func(s severity) bool { return s.Name == r.Severity })
			if i < 0 {
				return Snippet{}, badField("severity", "%q isn't one of %s", r.Severity, strings.Join(Severities(), ", "))
			}
			d.Severity = severities[i]
		}
		if r.Facility != "" && !slices.Contains(Facilities(), r.Facility) {
			return Snippet{}, badField("facility", "%q isn't local0 to local7", r.Facility)
		}
		d.Facility = r.Facility
	}
	if r.SourceInterface != "" && !interfaceRe.MatchString(r.SourceInterface) {
		return Snippet{}, badField("source_interface", "%q isn't an interface name (letters, digits and / . _ : @ -, at most 64)", r.SourceInterface)
	}
	d.SourceInterface = r.SourceInterface
	if r.Interface != "" && !interfaceRe.MatchString(r.Interface) {
		return Snippet{}, badField("interface", "%q isn't an interface name (letters, digits and / . _ : @ -, at most 64)", r.Interface)
	}
	d.Interface = cmp.Or(r.Interface, "<INTERFACE>")
	if isV3(d.Transport) {
		if r.V3User != "" && !userRe.MatchString(r.V3User) {
			return Snippet{}, badField("v3_user", "%q isn't a user name (letters, digits and . _ -, at most 32)", r.V3User)
		}
		d.V3User = cmp.Or(r.V3User, "<V3-USER>")
		d.Auth = auths[0]
		if r.Auth != "" {
			i := slices.IndexFunc(auths, func(a authProto) bool { return a.ID == r.Auth })
			if i < 0 {
				return Snippet{}, badField("auth", "%q isn't one of %s", r.Auth, strings.Join(AuthChoices(), ", "))
			}
			d.Auth = auths[i]
		}
		d.Priv = privs[0]
		if r.Priv != "" {
			i := slices.IndexFunc(privs, func(p privProto) bool { return p.ID == r.Priv })
			if i < 0 {
				return Snippet{}, badField("priv", "%q isn't one of %s", r.Priv, strings.Join(PrivChoices(), ", "))
			}
			d.Priv = privs[i]
		}
	}
	d.AgentPort = 161
	if r.AgentPort != nil {
		if *r.AgentPort < 1 || *r.AgentPort > 65535 {
			return Snippet{}, badField("agent_port", "must be 1 to 65535")
		}
		d.AgentPort = *r.AgentPort
	}

	if d.Transport == "tls" {
		d.TLSOwnCA = s.TLSSource != "file"
		d.CASHA256 = s.CASHA256
		switch {
		case d.IsName && slices.Contains(s.TLSNames, d.Address):
			d.TLSName, d.TLSNameKnown = d.Address, true
		case d.IsName && len(s.TLSNames) == 0:
			// No certificate yet (or none with names): the address is the
			// name to check, but nothing says it's on the certificate.
			d.TLSName = d.Address
		default:
			for _, n := range s.TLSNames {
				if n != "localhost" {
					d.TLSName, d.TLSNameKnown = n, true
					break
				}
			}
			if d.TLSName == "" && slices.Contains(s.TLSNames, "localhost") {
				d.TLSName, d.TLSNameKnown = "localhost", true
			}
			if d.TLSName == "" {
				d.TLSName = "<WOODSHED-TLS-NAME>"
			}
		}
	}

	render := func(block string) (string, error) {
		var b bytes.Buffer
		if err := t.tmpl.ExecuteTemplate(&b, block, d); err != nil {
			return "", fmt.Errorf("setuphelper: %s %s: %w", t.File, block, err)
		}
		return b.String(), nil
	}
	sn := Snippet{Family: r.Family, What: r.What, Transport: d.Transport, Address: d.Address, Verification: t.Verification,
		CheckedOn: t.CheckedOn, VerificationDetail: t.CI, Reference: t.Reference, Addresses: addrs, Notes: []string{}, Parts: []Part{}}
	if sn.Addresses == nil {
		sn.Addresses = []string{}
	}
	does, err := render("does")
	if err != nil {
		return Snippet{}, err
	}
	sn.Does = oneLine(does)
	check, err := render("check")
	if err != nil {
		return Snippet{}, err
	}
	sn.Check = oneLine(check)
	parts, err := render("parts")
	if err != nil {
		return Snippet{}, err
	}
	if sn.Parts, err = splitParts(parts); err != nil {
		return Snippet{}, fmt.Errorf("setuphelper: %s: %w", t.File, err)
	}
	notes, err := render("notes")
	if err != nil {
		return Snippet{}, err
	}

	// Notes: what must happen first, then the reference-only line, the TCP
	// warning, and the template's own.
	if listenerName != "" && !lst.Enabled {
		sn.Notes = append(sn.Notes, listenerOffNote(r.What, d.Transport, listenerName, s.Flow == nil))
	}
	if b := lst.Addr; r.Address != "" && !d.IsName && b != "" && b != "0.0.0.0" && b != "::" && b != d.Address {
		sn.Notes = append(sn.Notes, fmt.Sprintf("Woodshed's %s listener is bound to %s only, so it won't hear a device that sends to %s.", listenerName, b, d.Address))
	}
	if t.Verification == Reference {
		sn.Notes = append(sn.Notes, ReferenceOnlyNote)
	}
	if t.Verification == LabChecked {
		sn.Notes = append(sn.Notes, "Lab-checked on "+t.CheckedOn+": applied by hand on lab equipment, not in CI.")
	}
	if r.What == WhatSyslog && (d.Transport == "tcp" || d.Transport == "tls") && r.Family != "rsyslog" {
		sn.Notes = append(sn.Notes, TCPWarning)
	}
	for _, n := range strings.Split(notes, "\n") {
		if n = strings.TrimSpace(n); n != "" {
			sn.Notes = append(sn.Notes, n)
		}
	}

	var all []string
	for _, p := range sn.Parts {
		head := p.Title
		if p.Path != "" {
			head = p.Path + ": " + head
		}
		comment := "# "
		switch p.Kind {
		case PartCLI:
			comment = "! "
		case PartSteps:
			comment = ""
		}
		all = append(all, comment+head+"\n"+p.Text)
	}
	sn.Text = strings.Join(all, "\n")
	sn.Placeholders = []string{}
	for _, ph := range placeRe.FindAllString(sn.Text, -1) {
		if !slices.Contains(sn.Placeholders, ph) {
			sn.Placeholders = append(sn.Placeholders, ph)
		}
	}
	return sn, nil
}

func isV3(transport string) bool { return transport == "v3" }

func familyIDs() []string { return ids(families, func(f family) string { return f.id }) }

func familyWhat(id string) []string {
	var out []string
	for _, t := range loaded {
		if t.Family == id {
			out = append(out, t.What)
		}
	}
	return out
}

// defaultTransport is the first of the template's transports whose listener
// is on, else its first.
func defaultTransport(s Server, what string, ts []string) string {
	for _, tr := range ts {
		if l, name := s.listenerFor(what, tr); name == "" || l.Enabled {
			return tr
		}
	}
	return ts[0]
}

// listenerFor is the listener a snippet sends to, and its name for notes
// ("" for polling, where Woodshed sends).
func (s Server) listenerFor(what, transport string) (Listener, string) {
	switch what {
	case WhatSyslog:
		switch transport {
		case "tcp":
			return s.TCP, "TCP syslog"
		case "tls":
			return s.TLS, "TLS syslog"
		}
		return s.UDP, "UDP syslog"
	case WhatTrap:
		return s.Trap, "SNMP trap"
	case WhatFlow:
		if s.Flow == nil {
			port := DefaultFlowPort
			if transport == "ipfix" {
				port = DefaultIPFIXPort
			}
			return Listener{Port: port}, "flow"
		}
		// Each port accepts every version: a version's usual port when it's
		// on, else the other one.
		f := *s.Flow
		port := cmp.Or(f.FlowPort, f.IPFIXPort)
		if transport == "ipfix" {
			port = cmp.Or(f.IPFIXPort, f.FlowPort)
		}
		if port == 0 {
			return Listener{Addr: f.Addr, Port: DefaultFlowPort}, "flow"
		}
		return Listener{Enabled: f.Enabled, Addr: f.Addr, Port: port}, "flow"
	}
	return Listener{Enabled: true}, ""
}

func listenerOffNote(what, transport, name string, noFlow bool) string {
	switch {
	case what == WhatFlow && noFlow:
		return "This Woodshed doesn't receive flows yet, so nothing will arrive. The port is the flow listener's default."
	case what == WhatFlow:
		return "Woodshed's flow listener is off: turn it on in Settings → Flows (or `woodshed flow on`, as an administrator) first."
	case what == WhatTrap:
		return "Woodshed's SNMP trap listener is off: turn it on in Settings → Listeners (or `woodshed snmp on`) first."
	case transport == "tls":
		return "Woodshed's TLS syslog listener is off: turn it on in Settings → Listeners (or `woodshed tls on`) first."
	}
	return "Woodshed's " + name + " listener is off: turn it on in Settings → Listeners first."
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// partRe is a part's marker line in a rendered "parts" block:
// @@part <kind> <path or -> <title>.
var partRe = regexp.MustCompile(`^@@part (file|command|cli|steps) (\S+) (.+)$`)

func splitParts(s string) ([]Part, error) {
	var out []Part
	var cur *Part
	var body []string
	flush := func() {
		if cur != nil {
			cur.Text = strings.Trim(strings.Join(body, "\n"), "\n") + "\n"
			if strings.TrimSpace(cur.Text) != "" {
				out = append(out, *cur)
			}
		}
		body = nil
	}
	for _, line := range strings.Split(s, "\n") {
		if m := partRe.FindStringSubmatch(line); m != nil {
			flush()
			cur = &Part{Kind: m[1], Path: m[2], Title: strings.TrimSpace(m[3])}
			if cur.Path == "-" {
				cur.Path = ""
			}
			continue
		}
		if strings.HasPrefix(line, "@@") {
			return nil, fmt.Errorf("bad part marker %q", line)
		}
		if cur == nil {
			if strings.TrimSpace(line) != "" {
				return nil, fmt.Errorf("text before the first @@part: %q", line)
			}
			continue
		}
		body = append(body, strings.TrimRight(line, " \t"))
	}
	flush()
	if len(out) == 0 {
		return nil, fmt.Errorf("no parts")
	}
	return out, nil
}
