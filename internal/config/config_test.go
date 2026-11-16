package config

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func testConfig(t *testing.T) Config {
	c := Default()
	c.Storage.DataDir = t.TempDir()
	return c
}

func TestDefaultIsValid(t *testing.T) {
	c := testConfig(t)
	for _, goos := range []string{"darwin", "linux", "windows"} {
		if errs := c.validate(goos, nil); errs != nil {
			t.Errorf("%s: default config invalid: %v", goos, errs)
		}
	}
	if c.Listeners.UDPRcvbufBytes != 32<<20 || c.Listeners.MaxMessageBytes != 64<<10 {
		t.Errorf("tuning defaults: %+v", c.Listeners)
	}
}

func TestJSONShapeMatchesSettings(t *testing.T) {
	c := Default()
	c.Storage.DataDir = "/data"
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	// docs/api.md, GET /api/settings.
	want := `{"listeners":{"udp":{"enabled":true,"addr":"0.0.0.0","port":514},"tcp":{"enabled":true,"addr":"0.0.0.0","port":514},` +
		`"tls":{"enabled":false,"addr":"0.0.0.0","port":6514,"allow_legacy_tls":false,"cert_file":"","key_file":""},` +
		`"snmp":{"enabled":false,"addr":"0.0.0.0","port":162,"answer_informs":true,"communities":[],"mib_dir":"","engine_id":""},` +
		`"flow":{"enabled":false,"addr":"0.0.0.0","netflow_port":2055,"ipfix_port":4739,"template_timeout":"30m","rule_id_ies":[]},"allowlist":[],"blocklist":[],` +
		`"max_devices":10000,"new_device_burst":5000,"new_devices_per_minute":200},` +
		`"storage":{"data_dir":"/data","retention_days":30,"retention_bytes":21474836480,"part_bytes":104857600,"flow_budget_bytes":0},` +
		`"ui":{"lan_mode":false,"port":8514,"cert_file":"","key_file":"","require_login_local":false,"extra_hostnames":[],"trusted_hosts":[]},"quiet":{"quiet_after_seconds":300,"offline_after_seconds":3600},"updates":{"check":"ask"},` +
		`"poll":{"interval_s":60,"timeout_ms":2000,"retries":1,"concurrency":32,"max_interfaces":64,"max_targets":500,"presets":["system","system-info","interfaces"]}}`
	if string(b) != want {
		t.Errorf("JSON:\n got %s\nwant %s", b, want)
	}
}

func TestJSONPutKeepsFileOnlyFields(t *testing.T) {
	cur := Default()
	cur.Listeners.UDPRcvbufBytes = 8 << 20
	next := cur.Clone()
	if err := json.Unmarshal([]byte(`{"listeners":{"udp":{"enabled":true,"addr":"::","port":5514},"tcp":{"enabled":false,"addr":"0.0.0.0","port":514},"allowlist":null}}`), &next); err != nil {
		t.Fatal(err)
	}
	next.Normalize()
	if next.Listeners.UDPRcvbufBytes != 8<<20 || next.Listeners.UDP.Port != 5514 || next.Listeners.Allowlist == nil {
		t.Errorf("after PUT decode: %+v", next.Listeners)
	}
}

func TestLoadCreatesDefaults(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "etc", "woodshed")
	path := filepath.Join(dir, FileName)
	def := testConfig(t)
	c, created, err := LoadOrCreate(path, def)
	if err != nil || !created {
		t.Fatalf("LoadOrCreate: created=%v err=%v", created, err)
	}
	if !reflect.DeepEqual(c, def) {
		t.Errorf("created config differs from defaults:\n%+v\n%+v", c, def)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o640 {
			t.Errorf("file mode %v, want 0640", fi.Mode().Perm())
		}
		di, _ := os.Stat(dir)
		if di.Mode().Perm()&^0o750 != 0 {
			t.Errorf("dir mode %v, want at most 0750", di.Mode().Perm())
		}
	}
	// Loading it again reads the same thing, and doesn't recreate it.
	c2, created, err := LoadOrCreate(path, def)
	if err != nil || created {
		t.Fatalf("second load: created=%v err=%v", created, err)
	}
	if !reflect.DeepEqual(c, c2) {
		t.Errorf("round trip differs:\n%+v\n%+v", c, c2)
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{"[listeners.udp]", "udp_rcvbuf_bytes = 33554432", "max_message_bytes = 65536", "allowlist = []", "# "} {
		if !strings.Contains(string(b), want) {
			t.Errorf("file lacks %q:\n%s", want, b)
		}
	}
}

func TestLoadPartialFileTakesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("[listeners.udp]\nport = 5514\n[storage]\nretention_days = 7\nfuture_key = 1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Listeners.UDP.Port != 5514 || c.Storage.RetentionDays != 7 {
		t.Errorf("file values not read: %+v", c)
	}
	if !c.Listeners.UDP.Enabled || c.Listeners.UDP.Addr != DefaultListenAddr || c.Listeners.TCP.Port != 514 ||
		c.Storage.PartBytes != DefaultPartBytes || c.UI.Port != DefaultUIPort || c.Listeners.Allowlist == nil {
		t.Errorf("missing keys didn't take defaults: %+v", c)
	}
}

func TestLoadSyntaxError(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	os.WriteFile(path, []byte("[listeners\nport = \n"), 0o640)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("want an error naming the file, got %v", err)
	}
}

func TestSaveAtomicReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	c := testConfig(t)
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	c.Listeners.Allowlist = []string{"192.0.2.0/24", "2001:db8::1"}
	c.Quiet.QuietAfterSeconds = 60
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, c) {
		t.Errorf("after save:\n%+v\nwant\n%+v", got, c)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("leftover files: %v", ents)
	}
}

func TestValidateRules(t *testing.T) {
	base := testConfig(t)
	cases := []struct {
		name string
		goos string
		mod  func(c *Config)
		want map[string]string // key -> message substring
	}{
		{"port range", "linux", func(c *Config) { c.Listeners.UDP.Port = 0; c.Listeners.TCP.Port = 70000 },
			map[string]string{"listeners.udp.port": "between 1 and 65535", "listeners.tcp.port": "between 1 and 65535"}},
		{"udp and tcp share a port", "linux", func(c *Config) { c.Listeners.UDP.Port = 5514; c.Listeners.TCP.Port = 5514 }, nil},
		{"ui equals tcp", "linux", func(c *Config) { c.UI.Port = 514 }, map[string]string{"ui.port": "syslog listener"}},
		{"ui equals udp", "linux", func(c *Config) { c.Listeners.UDP.Port = 8514 }, map[string]string{"ui.port": "syslog listener"}},
		{"ui range", "linux", func(c *Config) { c.UI.Port = -1 }, map[string]string{"ui.port": "between"}},
		{"bad addr", "linux", func(c *Config) { c.Listeners.TCP.Addr = "localhost" }, map[string]string{"listeners.tcp.addr": "IP address"}},
		{"allowlist", "linux", func(c *Config) {
			c.Listeners.Allowlist = []string{"192.0.2.1", "198.51.100.0/24", "nope", "2001:db8::/32", "203.0.113.0/33"}
		}, map[string]string{"listeners.allowlist[2]": "IP address or a CIDR", "listeners.allowlist[4]": "CIDR"}},
		{"retention", "linux", func(c *Config) { c.Storage.RetentionDays = 0; c.Storage.RetentionBytes = 1<<30 - 1 },
			map[string]string{"storage.retention_days": "at least 1", "storage.retention_bytes": "1 GiB"}},
		{"retention minimum ok", "linux", func(c *Config) { c.Storage.RetentionDays = 1; c.Storage.RetentionBytes = 1 << 30 }, nil},
		{"part too small", "linux", func(c *Config) { c.Storage.PartBytes = 1<<20 - 1 }, map[string]string{"storage.part_bytes": "1 MiB"}},
		{"part too big", "linux", func(c *Config) { c.Storage.PartBytes = 1<<30 + 1 }, map[string]string{"storage.part_bytes": "1 GiB"}},
		{"part bounds ok", "linux", func(c *Config) { c.Storage.PartBytes = 1 << 30 }, nil},
		{"quiet >= offline", "linux", func(c *Config) { c.Quiet.QuietAfterSeconds = 3600 }, map[string]string{"quiet.quiet_after_seconds": "less than"}},
		{"data dir relative", "linux", func(c *Config) { c.Storage.DataDir = "rel/dir" }, map[string]string{"storage.data_dir": "absolute"}},
		{"data dir empty", "linux", func(c *Config) { c.Storage.DataDir = "" }, map[string]string{"storage.data_dir": "required"}},
		{"darwin specific addr below 1024", "darwin", func(c *Config) { c.Listeners.UDP.Addr = "192.0.2.10" },
			map[string]string{"listeners.udp.addr": "on macOS, port 514"}},
		{"darwin specific addr below 1024 v6", "darwin", func(c *Config) { c.Listeners.TCP.Addr = "::1" },
			map[string]string{"listeners.tcp.addr": "allowlist"}},
		{"darwin wildcard v6 below 1024", "darwin", func(c *Config) { c.Listeners.TCP.Addr = "::" }, nil},
		{"darwin specific addr high port", "darwin", func(c *Config) { c.Listeners.UDP.Addr = "127.0.0.1"; c.Listeners.UDP.Port = 5514 }, nil},
		{"darwin disabled listener", "darwin", func(c *Config) { c.Listeners.UDP.Addr = "127.0.0.1"; c.Listeners.UDP.Enabled = false }, nil},
		{"linux specific addr below 1024", "linux", func(c *Config) { c.Listeners.UDP.Addr = "127.0.0.1" }, nil},
		{"file-only knobs", "linux", func(c *Config) { c.Listeners.MaxMessageBytes = 100; c.Listeners.UDPRcvbufBytes = -1 },
			map[string]string{"listeners.max_message_bytes": "between", "listeners.udp_rcvbuf_bytes": "between"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base.Clone()
			tc.mod(&c)
			got := c.validate(tc.goos, nil)
			if len(got) != len(tc.want) {
				t.Fatalf("errors %v, want keys %v", got, tc.want)
			}
			for k, sub := range tc.want {
				if !strings.Contains(got[k], sub) {
					t.Errorf("%s: %q, want it to contain %q (all: %v)", k, got[k], sub, got)
				}
			}
		})
	}
}

func TestValidateDataDirReadOnly(t *testing.T) {
	prev := testConfig(t)
	c := prev.Clone()
	if errs := c.Validate(&prev); errs != nil {
		t.Fatalf("unchanged: %v", errs)
	}
	c.Storage.DataDir = filepath.Join(prev.Storage.DataDir, "other")
	errs := c.Validate(&prev)
	if len(errs) != 1 || !strings.Contains(errs["storage.data_dir"], "can't be changed") {
		t.Fatalf("got %v", errs)
	}
	if errs.Err() == nil || !strings.Contains(errs.Error(), "storage.data_dir") {
		t.Errorf("Error(): %v", errs)
	}
	var none Errors
	if none.Err() != nil {
		t.Error("empty Errors.Err() should be nil")
	}
}

func TestPrefixes(t *testing.T) {
	l := Listeners{Allowlist: []string{"192.0.2.7", " 198.51.100.9/24 ", "2001:db8::1", "::ffff:203.0.113.0/120"}}
	ps, err := l.Prefixes()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.7/32", "198.51.100.0/24", "2001:db8::1/128", "203.0.113.0/24"}
	for i, p := range ps {
		if p.String() != want[i] {
			t.Errorf("[%d] %s, want %s", i, p, want[i])
		}
	}
	if _, err := (Listeners{Allowlist: []string{"bad"}}).Prefixes(); err == nil {
		t.Error("bad entry accepted")
	}
}

func TestPaths(t *testing.T) {
	none := func(string) string { return "" }
	cases := []struct {
		goos      string
		getenv    func(string) string
		cfg, data string
	}{
		{"linux", none, "/etc/woodshed/woodshed.toml", "/var/lib/woodshed"},
		{"darwin", none, "/Library/Application Support/Woodshed/woodshed.toml", "/Library/Application Support/Woodshed"},
		{"windows", none, `C:\ProgramData\Woodshed\woodshed.toml`, `C:\ProgramData\Woodshed`},
		{"windows", func(k string) string {
			if k == "ProgramData" {
				return `D:\PD\`
			}
			return ""
		}, `D:\PD\Woodshed\woodshed.toml`, `D:\PD\Woodshed`},
	}
	for _, tc := range cases {
		c, d := pathsFor(tc.goos, tc.getenv)
		if c != tc.cfg || d != tc.data {
			t.Errorf("%s: %q %q, want %q %q", tc.goos, c, d, tc.cfg, tc.data)
		}
	}
	if DefaultDataDir() == "" || DefaultConfigPath() == "" {
		t.Error("empty default path")
	}
}

func TestValidateCertPair(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(cert, []byte("x"), 0o600)
	os.WriteFile(key, []byte("x"), 0o600)
	cases := []struct {
		name      string
		cert, key string
		want      map[string]string
	}{
		{"both empty", "", "", nil},
		{"both set", cert, key, nil},
		{"cert only", cert, "", map[string]string{"ui.key_file": "required when cert_file"}},
		{"key only", "", key, map[string]string{"ui.cert_file": "required when key_file"}},
		{"relative", "cert.pem", key, map[string]string{"ui.cert_file": "absolute"}},
		{"missing", cert, filepath.Join(dir, "nope.pem"), map[string]string{"ui.key_file": "is not a readable key file"}},
		{"directory", dir, key, map[string]string{"ui.cert_file": "is not a readable certificate file"}},
	}
	// A missing file and a directory read the same (nothing about existence or
	// permissions leaks to the UI).
	missing, directory := testConfig(t), testConfig(t)
	missing.UI.CertFile, missing.UI.KeyFile = filepath.Join(dir, "nope.pem"), key
	directory.UI.CertFile, directory.UI.KeyFile = dir, key
	if a, b := missing.validate("linux", nil)["ui.cert_file"], directory.validate("linux", nil)["ui.cert_file"]; a != b || a == "" {
		t.Errorf("missing %q vs directory %q", a, b)
	}
	for _, tc := range cases {
		c := testConfig(t)
		c.UI.CertFile, c.UI.KeyFile = tc.cert, tc.key
		got := c.validate("linux", nil)
		if len(got) != len(tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
			continue
		}
		for k, sub := range tc.want {
			if !strings.Contains(got[k], sub) {
				t.Errorf("%s: %s = %q, want %q", tc.name, k, got[k], sub)
			}
		}
	}
}

// Read never creates the file (it's used on another Woodshed's config).
func TestReadDoesNotCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", FileName)
	if _, err := Read(path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Read created %s", filepath.Dir(path))
	}
	os.MkdirAll(filepath.Dir(path), 0o750)
	os.WriteFile(path, []byte("[listeners.udp]\nport = 15514\n[ui]\nport = 18514\n"), 0o640)
	c, err := Read(path)
	if err != nil || c.Listeners.UDP.Port != 15514 || !c.Listeners.UDP.Enabled || c.Listeners.TCP.Port != DefaultSyslogPort || c.UI.Port != 18514 {
		t.Errorf("read %+v %v", c.Listeners, err)
	}
}

// A 1.0 config has no [updates]: it means "ask" (SPEC §10.2). A pre-seeded
// value loads as written, and anything else fails validation on updates.check.
func TestUpdatesCheck(t *testing.T) {
	dir := t.TempDir()
	load := func(body string) Config {
		t.Helper()
		p := filepath.Join(dir, "w.toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := Load(p)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if c := load("[quiet]\nquiet_after_seconds = 60\n"); c.Updates.Check != UpdateCheckAsk {
		t.Errorf("no [updates]: %q, want ask", c.Updates.Check)
	}
	if c := load("[updates]\n"); c.Updates.Check != UpdateCheckAsk {
		t.Errorf("empty [updates]: %q, want ask", c.Updates.Check)
	}
	for _, v := range []string{"on", "off", "ask"} {
		c := load("[updates]\ncheck = \"" + v + "\"\n")
		if c.Updates.Check != v {
			t.Errorf("check = %q loaded as %q", v, c.Updates.Check)
		}
		c.Storage.DataDir = dir
		if errs := c.Validate(nil); errs != nil {
			t.Errorf("check = %q: %v", v, errs)
		}
	}
	for _, v := range []string{"", "yes", "On", "true"} {
		c := Default()
		c.Updates.Check = v
		if errs := c.Validate(nil); errs["updates.check"] == "" {
			t.Errorf("check = %q accepted: %v", v, errs)
		}
	}
	// Saved and read back.
	c := Default()
	c.Updates.Check = UpdateCheckOff
	p := filepath.Join(dir, "saved.toml")
	if err := Save(p, c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "[updates]") || !strings.Contains(string(b), "check = 'off'") && !strings.Contains(string(b), `check = "off"`) {
		t.Errorf("saved file:\n%s", b)
	}
	if got, _ := Load(p); got.Updates.Check != UpdateCheckOff {
		t.Errorf("read back %q", got.Updates.Check)
	}
}
