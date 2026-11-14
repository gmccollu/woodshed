package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A 1.2 file (no [poll]) loads with the poller's defaults (SPEC §12.9).
func TestPollDefaultsFromOldFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "woodshed.toml")
	if err := os.WriteFile(p, []byte("[storage]\ndata_dir = \""+filepath.ToSlash(t.TempDir())+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.Poll, DefaultPoll()) {
		t.Errorf("poll %+v", c.Poll)
	}
	if err := os.WriteFile(p, []byte("[poll]\nretries = 0\npresets = []\ninterval_s = 30\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Poll.Retries != 0 || len(c.Poll.Presets) != 0 || c.Poll.IntervalS != 30 || c.Poll.Concurrency != 32 {
		t.Errorf("poll %+v", c.Poll)
	}
}

func TestPollValidation(t *testing.T) {
	bad := map[string]func(*Poll){
		"poll.interval_s":     func(p *Poll) { p.IntervalS = 29 },
		"poll.timeout_ms":     func(p *Poll) { p.TimeoutMS = 10001 },
		"poll.retries":        func(p *Poll) { p.Retries = 6 },
		"poll.concurrency":    func(p *Poll) { p.Concurrency = 0 },
		"poll.max_interfaces": func(p *Poll) { p.MaxInterfaces = 1025 },
		"poll.max_targets":    func(p *Poll) { p.MaxTargets = 5001 },
		"poll.presets[1]":     func(p *Poll) { p.Presets = []string{"system", "bogus"} },
	}
	for key, f := range bad {
		c := testConfig(t)
		f(&c.Poll)
		errs := c.validate("linux", nil)
		if _, ok := errs[key]; !ok || len(errs) != 1 {
			t.Errorf("%s: %v", key, errs)
		}
	}
}
