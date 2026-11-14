package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUDPQueueLimits(t *testing.T) {
	c := testConfig(t)
	if c.Listeners.UDPQueueMessages != 100000 || c.Listeners.UDPQueueBytes != 64<<20 {
		t.Errorf("defaults %d %d", c.Listeners.UDPQueueMessages, c.Listeners.UDPQueueBytes)
	}
	path := filepath.Join(t.TempDir(), FileName)
	if err := Save(path, c); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "udp_queue_messages = 100000") || !strings.Contains(string(b), "udp_queue_bytes = 67108864") {
		t.Errorf("file:\n%s", b)
	}
	// A 1.1 file (neither key) gets the defaults; set values are kept.
	os.WriteFile(path, []byte("[listeners]\ntcp_frame_timeout = \"90s\"\n"), 0o640)
	if got, err := Load(path); err != nil || got.Listeners.UDPQueueMessages != DefaultUDPQueueMessages ||
		got.Listeners.UDPQueueBytes != DefaultUDPQueueBytes {
		t.Errorf("missing keys: %+v %v", got.Listeners, err)
	}
	os.WriteFile(path, []byte("[listeners]\nudp_queue_messages = 5000\nudp_queue_bytes = 2097152\n"), 0o640)
	if got, err := Load(path); err != nil || got.Listeners.UDPQueueMessages != 5000 || got.Listeners.UDPQueueBytes != 2<<20 {
		t.Errorf("set keys: %+v %v", got.Listeners, err)
	}

	for _, tc := range []struct {
		msgs  int
		bytes int64
		bad   []string
	}{
		{1000, 1 << 20, nil},
		{2000000, 1 << 30, nil},
		{999, 1<<20 - 1, []string{"listeners.udp_queue_messages", "listeners.udp_queue_bytes"}},
		{2000001, 1<<30 + 1, []string{"listeners.udp_queue_messages", "listeners.udp_queue_bytes"}},
		{-1, -1, []string{"listeners.udp_queue_messages", "listeners.udp_queue_bytes"}},
	} {
		c := testConfig(t)
		c.Listeners.UDPQueueMessages, c.Listeners.UDPQueueBytes = tc.msgs, tc.bytes
		errs := c.validate("linux", nil)
		if len(errs) != len(tc.bad) {
			t.Errorf("%d/%d: errors %v, want %v", tc.msgs, tc.bytes, errs, tc.bad)
		}
		for _, k := range tc.bad {
			if !strings.Contains(errs[k], "between") {
				t.Errorf("%d/%d: %s = %q", tc.msgs, tc.bytes, k, errs[k])
			}
		}
	}
}

// The queue limits are file-only: they're not in the settings object.
func TestUDPQueueNotInSettingsJSON(t *testing.T) {
	c := testConfig(t)
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "udp_queue") {
		t.Errorf("settings JSON has the queue limits: %s", b)
	}
}
