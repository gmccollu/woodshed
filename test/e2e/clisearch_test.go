package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// cliSearch runs the real binary's `woodshed search` on dataDir.
func cliSearch(t *testing.T, dataDir string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(binary, append([]string{"search", "--data", dataDir}, args...)...)
	var o, e bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &e
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), o.String(), e.String()
	}
	if err != nil {
		t.Fatal(err)
	}
	return 0, o.String(), e.String()
}

// TestCLISearch runs `woodshed search` (SPEC §11.4) against a running
// instance's data folder, then against the same folder with the instance
// stopped: every message sent is found once, the JSON results are the API's,
// and the exit codes hold.
func TestCLISearch(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	cfgPath, dataDir := writeConfig(t, dir, syslogPort, uiPort)
	p := startWoodshed(t, cfgPath, dataDir, uiPort)

	const per = 1500
	run := loadgen.NewRunID()
	tag := loadgen.SeqTag(run)
	for i, proto := range []string{"udp", "tcp"} {
		if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort),
			Proto: proto, Count: per, Rate: 5000, RunID: run, FirstSeq: i * per, Message: "cli search probe"}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the last message to be searchable", 20*time.Second, func() bool {
		var pg searchPage
		p.getJSON("/api/search?"+url.Values{"q": {tag + fmt.Sprint(2*per-1) + " "}}.Encode(), &pg)
		return len(pg.Results) == 1
	})

	var pg searchPage // the API's first page, to compare --json with
	p.getJSON("/api/search?"+url.Values{"q": {tag}, "order": {"asc"}, "limit": {"50"}}.Encode(), &pg)
	check := func(when string) {
		t.Helper()
		// Every message once, in order, both ways.
		for _, order := range []string{"asc", "desc"} {
			code, out, errOut := cliSearch(t, dataDir, "--order", order, "--raw", tag)
			if code != 0 {
				t.Fatalf("%s %s: exit %d %s", when, order, code, errOut)
			}
			seen := map[string]bool{}
			for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
				i := strings.Index(l, tag)
				if i < 0 {
					t.Fatalf("%s: line without the tag: %q", when, l)
				}
				s := strings.Fields(l[i+len(tag):])[0]
				if seen[s] {
					t.Fatalf("%s %s: %s twice", when, order, s)
				}
				seen[s] = true
			}
			if len(seen) != 2*per {
				t.Fatalf("%s %s: %d distinct messages, want %d", when, order, len(seen), 2*per)
			}
			if !strings.HasPrefix(errOut, fmt.Sprintf("%d matches, ", 2*per)) {
				t.Fatalf("%s: summary %q", when, errOut)
			}
		}
		// --count, an exact tag, no match, a usage error.
		if code, out, _ := cliSearch(t, dataDir, "--count", tag); code != 0 || out != fmt.Sprintf("%d\n", 2*per) {
			t.Fatalf("%s: --count %d %q", when, code, out)
		}
		if code, out, _ := cliSearch(t, dataDir, tag+"1234 "); code != 0 || strings.Count(out, "\n") != 1 ||
			!strings.Contains(out, " 127.0.0.1 <134>1 ") {
			t.Fatalf("%s: one message: %d %q", when, code, out)
		}
		if code, _, _ := cliSearch(t, dataDir, "no such text "+run); code != 1 {
			t.Fatalf("%s: no match exit %d", when, code)
		}
		if code, _, errOut := cliSearch(t, dataDir, "--regex", "("); code != 2 || !strings.Contains(errOut, "error parsing regexp") {
			t.Fatalf("%s: bad regex %d %q", when, code, errOut)
		}
		// The JSON results are the API's first page, result for result.
		code, out, _ := cliSearch(t, dataDir, "--json", "--limit", "50", tag)
		if code != 0 {
			t.Fatalf("%s: --json exit %d", when, code)
		}
		sc := bufio.NewScanner(strings.NewReader(out))
		i := 0
		for ; sc.Scan(); i++ {
			var r struct {
				searchResult
				Type       string `json:"type"`
				DeviceName string `json:"device_name"`
			}
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			if i >= len(pg.Results) || r.searchResult.Ref != pg.Results[i].Ref || r.Raw != pg.Results[i].Raw || r.Type != "syslog" {
				t.Fatalf("%s: JSON result %d differs from the API's: %s", when, i, sc.Text())
			}
		}
		if i != 50 {
			t.Fatalf("%s: %d JSON results", when, i)
		}
	}
	check("running")
	p.stop()
	check("stopped")
	// With the service stopped the index has no -wal or -shm, and the searches
	// created none (SPEC §11.4: nothing is created in the data folder).
	for _, sfx := range []string{"-wal", "-shm"} {
		if _, err := os.Stat(filepath.Join(dataDir, index.FileName+sfx)); err == nil {
			t.Fatalf("index.db%s exists after searching a stopped instance's folder", sfx)
		}
	}
	p = startWoodshed(t, cfgPath, dataDir, uiPort)
	defer p.stop()
	check("restarted")
}
