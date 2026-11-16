package setuphelper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The setup helper stays vendor-neutral (SPEC §13.5): no company, product or
// OS name of a firewall, router, switch, appliance or log product in a
// template, a family label or note, a rendered snippet, the setup page or its
// docs. The list lives here, in a test, so it never appears in anything a user
// reads. Matching is case-insensitive on word boundaries. Open-source tools
// the families name as such (rsyslog, net-snmp, softflowd) are allowed, and
// so is "Linux".
var denyList = []string{
	// Network and security vendors.
	"cisco", "juniper", "palo alto", "paloalto", "fortinet", "check point", "checkpoint", "sonicwall", "sophos", "watchguard",
	"barracuda", "forcepoint", "huawei", "h3c", "hpe", "hewlett", "aruba", "arista", "extreme networks", "brocade", "ruckus",
	"mikrotik", "ubiquiti", "netgear", "tp-link", "d-link", "zyxel", "meraki", "nokia", "alcatel", "ericsson", "dell", "force10",
	"f5", "citrix", "netscaler", "a10 networks", "radware", "riverbed", "silver peak", "velocloud", "zscaler",
	"cloudflare", "akamai", "allied telesis", "edgecore", "cumulus", "mellanox", "nvidia", "lenovo", "ibm", "oracle", "vmware",
	"broadcom", "microsoft", "apple", "google", "amazon", "aws", "azure", "gcp", "synology", "qnap", "draytek", "teltonika",
	"peplink", "cradlepoint", "sierra wireless", "avaya", "infoblox", "gigamon", "netscout", "solarwinds", "paessler", "zabbix",
	// Network and security OS and product names.
	"ios", "ios-xe", "ios-xr", "iosxe", "nx-os", "nxos", "asa", "ftd", "firepower", "catalyst", "nexus", "junos", "srx", "pan-os",
	"panos", "fortios", "fortigate", "gaia", "sonicos", "eos", "edgeos", "edgerouter", "unifi", "routeros", "vyos", "vyatta",
	"pfsense", "opnsense", "openwrt", "dd-wrt", "comware", "procurve", "aos-cx", "arubaos", "ftos", "os10", "big-ip", "tmos",
	"nsx", "esxi", "srlinux", "sr os", "timos", "exos", "voss", "icx", "fastiron", "dnos", "smartzone",
	// Log and monitoring products.
	"splunk", "graylog", "papertrail", "loggly", "sumo logic", "datadog", "logrhythm", "qradar", "arcsight", "kiwi", "syslog-ng",
	"elastic", "kibana", "logstash", "nagios", "prtg", "librenms", "observium", "cacti", "ntopng", "nfdump", "nfsen",
	// Desktop and server OS names (Woodshed's own platforms appear elsewhere, never in a device snippet).
	"windows", "macos", "os x", "solaris", "aix", "hp-ux", "freebsd", "openbsd", "netbsd", "ubuntu", "debian", "red hat",
	"redhat", "rhel", "centos", "fedora", "suse", "alpine", "almalinux", "rocky linux",
}

// denyAnywhere are names caught anywhere in a word, not only as whole words,
// so identifiers and enum values built from them fail too. The trademarked
// flow-protocol name is one (owner, 2026-11-16): the helper says "flow v9
// (RFC 3954)" and "IPFIX (RFC 7011)" instead.
var denyAnywhere = []string{"net" + "flow"} // in pieces: internal/repocheck bans the word in tracked files

var denyRe = func() *regexp.Regexp {
	parts := make([]string, len(denyList))
	for i, w := range denyList {
		parts[i] = regexp.QuoteMeta(w)
	}
	return regexp.MustCompile(`(?i)(^|[^a-z0-9])(` + strings.Join(parts, "|") + `)($|[^a-z0-9])`)
}()

func denied(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if m := denyRe.FindStringSubmatch(line); m != nil {
			out = append(out, m[2]+" in: "+strings.TrimSpace(line))
		}
		for _, w := range denyAnywhere {
			if strings.Contains(strings.ToLower(line), w) {
				out = append(out, w+" in: "+strings.TrimSpace(line))
			}
		}
	}
	return out
}

// TestDenyListSelf: the list works (a hit on each kind, no hit on the
// families' own words).
func TestDenyListSelf(t *testing.T) {
	for _, s := range []string{"logging host for Cisco", "a JunOS box", "FortiGate", "PAN-OS 11", "Windows Server", "send to Splunk", "Net" + "Flow v9", "transport net" + "flow9", "export-protocol net" + "flow-v9"} {
		if len(denied(s)) == 0 {
			t.Errorf("not caught: %q", s)
		}
	}
	for _, s := range []string{"Linux: rsyslog", "Linux: net-snmp `snmpd` and `snmptrap`", "softflowd", "positions", "videos",
		"Settings → SNMP", "aes 128", "a basic check"} {
		if got := denied(s); len(got) > 0 {
			t.Errorf("false hit on %q: %v", s, got)
		}
	}
}

// TestNoVendorNames runs the deny list over every template, the families'
// labels and notes, every snippet for every family, data type and transport
// (with choices set, so optional lines render too), the setup page and its
// docs. It also fails a template marked Tested whose family has no CI test
// that applies it (the CI side is checked in internal/server's
// TestSetupTestedTemplatesHaveCI, which names each case).
func TestNoVendorNames(t *testing.T) {
	ts, err := Templates()
	if err != nil {
		t.Fatal(err)
	}
	for _, tm := range ts {
		for _, hit := range denied(tm.Source) {
			t.Errorf("template %s: %s", tm.File, hit)
		}
	}
	b, _ := json.Marshal(Families())
	for _, hit := range denied(string(b)) {
		t.Errorf("families: %s", hit)
	}
	srvs := []Server{sample()}
	noTLS := sample()
	noTLS.TLSNames, noTLS.TLSSource, noTLS.TLS.Enabled, noTLS.Trap.Enabled = nil, "", false, false
	srvs = append(srvs, noTLS)
	n := 0
	for _, srv := range srvs {
		for _, f := range Families() {
			for _, w := range f.What {
				for _, tr := range f.Transports[w] {
					for _, choices := range []bool{false, true} {
						r := Request{Family: f.ID, What: w, Transport: tr}
						if choices {
							for _, c := range f.Choices[w] {
								switch c {
								case ChoiceSourceInterface:
									r.SourceInterface = "eth1"
								case ChoiceInterface:
									r.Interface = "eth1"
								case ChoiceSeverity:
									r.Severity = "warning"
								case ChoiceFacility:
									r.Facility = "local4"
								case ChoiceV3User:
									if tr == "v3" {
										r.V3User = "monitor"
									}
								case ChoiceAgentPort:
									r.AgentPort = 1161
								}
							}
						}
						s, err := Generate(srv, r)
						if err != nil {
							t.Fatalf("%+v: %v", r, err)
						}
						n++
						j, _ := json.Marshal(s)
						for _, hit := range denied(string(j)) {
							t.Errorf("snippet %s %s %s: %s", f.ID, w, tr, hit)
						}
					}
				}
			}
		}
	}
	if n < 50 {
		t.Errorf("only %d snippets checked", n)
	}
	// A template marked Tested needs a CI case that applies each of its
	// transports: internal/server's setupInteropCases, read from its source
	// (a case with a skip reason doesn't count).
	src, err := os.ReadFile(filepath.Join("..", "server", "setup_interop_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	caseRe := regexp.MustCompile(`(?m)^\s*\{family: "([a-z-]+)", what: "([a-z]+)", transport: "([a-z0-9]+)"(, skip: [A-Za-z"]+)?\},`)
	applied := map[string]bool{}
	for _, m := range caseRe.FindAllStringSubmatch(string(src), -1) {
		if m[4] == "" {
			applied[m[1]+"-"+m[2]+"-"+m[3]] = true
		}
	}
	if len(applied) == 0 {
		t.Fatal("no CI cases found in internal/server/setup_interop_test.go")
	}
	for _, tm := range ts {
		for _, tr := range tm.Transports {
			if tm.Verification == Tested && !applied[tm.Family+"-"+tm.What+"-"+tr] {
				t.Errorf("%s is marked tested, but no CI case applies its %s snippet", tm.File, tr)
			}
		}
	}

	// The setup page and its docs.
	root := filepath.Join("..", "..")
	page, err := os.ReadFile(filepath.Join(root, "web", "src", "pages", "DeviceSetup.svelte"))
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range denied(string(page)) {
		t.Errorf("DeviceSetup.svelte: %s", hit)
	}
	for _, d := range []struct{ file, from, to string }{
		{"docs/user-guide.md", "### Setting up devices", "\n#"},
		{"FAQ.md", "## Why no vendor-specific instructions?", "\n#"},
	} {
		raw, err := os.ReadFile(filepath.Join(root, d.file))
		if err != nil {
			t.Fatal(err)
		}
		s := strings.ReplaceAll(string(raw), "\r\n", "\n")
		i := strings.Index(s, d.from)
		if i < 0 {
			t.Fatalf("%s: no %q section", d.file, d.from)
		}
		sec := s[i:]
		if j := strings.Index(sec[len(d.from):], d.to); j >= 0 {
			sec = sec[:len(d.from)+j]
		}
		for _, hit := range denied(sec) {
			t.Errorf("%s %q: %s", d.file, d.from, hit)
		}
	}
}
