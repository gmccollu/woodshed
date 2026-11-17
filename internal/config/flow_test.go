package config

import (
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
)

func TestFlowDefaultsOffAndValid(t *testing.T) {
	c := testConfig(t)
	if c.Listeners.Flow.Enabled {
		t.Fatal("the flow listener must be off by default (SPEC §13.1)")
	}
	if got := c.Storage.FlowBudget(); got != c.Storage.RetentionBytes*40/100 {
		t.Fatalf("budget %d, want 40 %% of %d", got, c.Storage.RetentionBytes)
	}
	c.Listeners.Flow.Enabled = true
	for _, goos := range []string{"darwin", "linux", "windows"} {
		if errs := c.validate(goos, nil); errs != nil {
			t.Errorf("%s: enabled default flow config invalid: %v", goos, errs)
		}
	}
}

func TestFlowValidation(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c *Config)
		key  string
	}{
		{"both ports off", func(c *Config) { c.Listeners.Flow.FlowPort, c.Listeners.Flow.IPFIXPort = 0, 0 }, "listeners.flow.flow_port"},
		{"same ports", func(c *Config) { c.Listeners.Flow.IPFIXPort = c.Listeners.Flow.FlowPort }, "listeners.flow.flow_port"},
		{"port out of range", func(c *Config) { c.Listeners.Flow.IPFIXPort = 70000 }, "listeners.flow.ipfix_port"},
		{"syslog port", func(c *Config) { c.Listeners.Flow.FlowPort = c.Listeners.UDP.Port }, "listeners.flow.flow_port"},
		{"trap port", func(c *Config) { c.Listeners.Flow.IPFIXPort = c.Listeners.SNMP.Port }, "listeners.flow.ipfix_port"},
		{"bad addr", func(c *Config) { c.Listeners.Flow.Addr = "nope" }, "listeners.flow.addr"},
		{"timeout short", func(c *Config) { c.Listeners.Flow.TemplateTimeout = FlowDuration(30 * time.Second) }, "listeners.flow.template_timeout"},
		{"timeout long", func(c *Config) { c.Listeners.Flow.TemplateTimeout = FlowDuration(25 * time.Hour) }, "listeners.flow.template_timeout"},
		{"rule ie", func(c *Config) { c.Listeners.Flow.RuleIDIEs = []string{"32473:7", "x"} }, "listeners.flow.rule_id_ies[1]"},
		{"rule ie id too big", func(c *Config) { c.Listeners.Flow.RuleIDIEs = []string{"1:40000"} }, "listeners.flow.rule_id_ies[0]"},
		{"v9 type too big", func(c *Config) { c.Listeners.Flow.RuleIDIEs = []string{"0:40003", "0:65536"} }, "listeners.flow.rule_id_ies[1]"},
		{"rule ies count", func(c *Config) {
			c.Listeners.Flow.RuleIDIEs = strings.Split("1:1,1:2,1:3,1:4,1:5,1:6,1:7,1:8,1:9", ",")
		}, "listeners.flow.rule_id_ies"},
		{"budget small", func(c *Config) { c.Storage.FlowBudgetBytes = 1 << 20 }, "storage.flow_budget_bytes"},
		{"budget over 90%", func(c *Config) { c.Storage.FlowBudgetBytes = c.Storage.RetentionBytes * 95 / 100 }, "storage.flow_budget_bytes"},
	}
	for _, tc := range cases {
		c := testConfig(t)
		c.Listeners.Flow.Enabled = true
		tc.mod(&c)
		errs := c.validate("linux", nil)
		if _, ok := errs[tc.key]; !ok {
			t.Errorf("%s: want an error on %s, got %v", tc.name, tc.key, errs)
		}
	}
	c := testConfig(t)
	c.Storage.FlowBudgetBytes = 2 << 30
	if errs := c.validate("linux", nil); errs != nil {
		t.Errorf("a 2 GiB budget is valid: %v", errs)
	}
	if c.Storage.FlowBudget() != 2<<30 {
		t.Errorf("FlowBudget %d", c.Storage.FlowBudget())
	}
}

func TestFlowTOMLRoundTripAnd13Compat(t *testing.T) {
	// A 1.3 file has no [listeners.flow] and no flow_budget_bytes.
	var c Config
	if err := toml.Unmarshal([]byte("[listeners.udp]\nenabled = true\naddr = \"0.0.0.0\"\nport = 514\n"), &c); err != nil {
		t.Fatal(err)
	}
	c.Normalize()
	if c.Listeners.Flow.Enabled || c.Listeners.Flow.TemplateTimeout != FlowDuration(DefaultTemplateTimeout) ||
		c.Listeners.Flow.PendingBytes != DefaultFlowPendingBytes || c.Listeners.Flow.RuleIDIEs == nil {
		t.Fatalf("1.3 file: %+v", c.Listeners.Flow)
	}
	d := Default()
	d.Listeners.Flow.RuleIDIEs = []string{"32473:7"}
	b, err := toml.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "template_timeout = '30m'") && !strings.Contains(string(b), `template_timeout = "30m"`) {
		t.Errorf("template_timeout not written compactly:\n%s", b)
	}
	var back Config
	if err := toml.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Listeners.Flow.TemplateTimeout != d.Listeners.Flow.TemplateTimeout || back.Listeners.Flow.RuleIDIEs[0] != "32473:7" {
		t.Errorf("round trip: %+v", back.Listeners.Flow)
	}
}

func TestShortDuration(t *testing.T) {
	for d, want := range map[time.Duration]string{30 * time.Minute: "30m", time.Hour: "1h", 90 * time.Minute: "1h30m", 45 * time.Second: "45s", 24 * time.Hour: "24h"} {
		if got := ShortDuration(d); got != want {
			t.Errorf("%v: %q, want %q", d, got, want)
		}
	}
}

// rule_id_ies entries: IPFIX enterprise IEs (15-bit IDs), and with
// enterprise number 0 IANA IEs or flow v9 field types (16-bit, the vendor
// range 32768–65535 included).
func TestParseRuleIDIE(t *testing.T) {
	for _, x := range []struct {
		in  string
		pen uint32
		id  uint16
	}{
		{"32473:3", 32473, 3}, {" 9:12001 ", 9, 12001}, {"4294967295:32767", 4294967295, 32767}, {"0:40003", 0, 40003},
		{"0:32768", 0, 32768}, {"0:65535", 0, 65535}, {"0:7", 0, 7}, {"0 : 40001", 0, 40001},
	} {
		if pen, id, ok := ParseRuleIDIE(x.in); !ok || pen != x.pen || id != x.id {
			t.Errorf("%q: %d %d %v", x.in, pen, id, ok)
		}
	}
	for _, in := range []string{"", "x", "40003", ":40003", "0:", "32473:32768", "1:40003", "0:65536", "4294967296:1", "-1:3",
		"0:-1", "v9:40003", "0x0:40003", "0:40003:1", "+0:40003", "0:4e4"} {
		if pen, id, ok := ParseRuleIDIE(in); ok {
			t.Errorf("%q parsed as %d:%d", in, pen, id)
		}
	}
	c := testConfig(t)
	c.Listeners.Flow.RuleIDIEs = []string{"0:40003", "32473:3"}
	if errs := c.Validate(nil); len(errs) != 0 {
		t.Fatalf("v9 and IPFIX entries: %v", errs)
	}
}
