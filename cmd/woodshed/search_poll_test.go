package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// writePolls adds poll records for dev to the data folder dir: a sys and an
// if line per minute for n minutes from at, and a restart at the middle one.
func writePolls(t *testing.T, dir string, at time.Time, n int) {
	t.Helper()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	now := at
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Manual: true, Clock: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	w := func(when time.Time, r pollrec.Record) {
		now = when
		if err := st.WriteType(logfile.TypePoll, model.Message{Received: when, Sender: fxDevs[0], Raw: pollrec.Format(r)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		when := at.Add(time.Duration(i) * time.Minute)
		c := uint64(i + 1)
		w(when, pollrec.New(pollrec.KindSys, c).Uint("uptime", uint64(i*6000)).Uint("cpu", 5).Uint("interval_s", 60).Record())
		w(when, pollrec.New(pollrec.KindIf, c).Uint("if", 1).Str("name", "eth1").Str("oper", "up").Uint("in_bps", 1000).Record())
		if i == n/2 {
			w(when, pollrec.New(pollrec.KindRestart, c).Str("reboot", "?").Uint("uptime", 10).Uint("prev_uptime", 99).Str("source", "sysUpTime").Record())
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	idx.Close()
}

// woodshed search --type poll (SPEC §12.3, §12.7): the poll lines, with the
// poll fields as --field, and the API's poll JSON.
func TestSearchPolls(t *testing.T) {
	f := newSearchFixture(t)
	writePolls(t, f.dir, fxNow.Add(-2*time.Hour), 10)

	code, out, errOut := runSearch(t, f.dir, "--type", "poll", "--field", "kind=restart", "--last", "7d")
	if code != 0 || strings.Count(out, "\n") != 1 || !strings.Contains(out, " kind=restart cycle=6 reboot=? ") {
		t.Fatalf("restarts: %d %q %s", code, out, errOut)
	}
	if code, out, _ := runSearch(t, f.dir, "--type", "poll", "--count", "--last", "24h"); code != 0 || out != "21\n" {
		t.Fatalf("count %d %q", code, out)
	}
	if code, out, _ := runSearch(t, f.dir, "--type", "poll", "--count", "--not-field", "kind=sys", "--field", "if=eth1"); code != 0 || out != "10\n" {
		t.Fatalf("if=eth1 %d %q", code, out)
	}
	if code, out, _ := runSearch(t, f.dir, "--type", "poll", "--count", "oper=up"); code != 0 || out != "10\n" {
		t.Fatalf("q oper=up %d %q", code, out)
	}
	code, out, _ = runSearch(t, f.dir, "--type", "poll", "--json", "--field", "reboot=?", "--last", "24h")
	if code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("json: %d %q", code, out)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatal(err)
	}
	fields, _ := obj["fields"].(map[string]any)
	if obj["type"] != "poll" || fields["kind"] != "restart" || fields["reboot"] != "?" || obj["device_name"] == nil {
		t.Fatalf("json object %v", obj)
	}
	// Other types' filters are usage errors; syslog is untouched by polls.
	if code, _, errOut := runSearch(t, f.dir, "--type", "poll", "--severities", "3"); code != exitUsage || !strings.Contains(errOut, "not a filter for SNMP polls") {
		t.Fatalf("severities: %d %s", code, errOut)
	}
	if code, _, errOut := runSearch(t, f.dir, "--field", "kind=sys"); code != exitUsage || !strings.Contains(errOut, "kind") {
		t.Fatalf("syslog with kind: %d %s", code, errOut)
	}
	if code, out, _ := runSearch(t, f.dir, "--count", "--last", "7d", "kind=sys"); code != 1 || out != "0\n" {
		t.Fatalf("syslog found polls: %d %q", code, out)
	}
}

// woodshed bundle --types poll: the CSVs and the Polls lines.
func TestBundlePolls(t *testing.T) {
	f := newBundleFixture(t)
	writePolls(t, f.dir, time.Date(2026, 11, 14, 9, 20, 0, 0, time.UTC), 20)
	out := filepath.Join(t.TempDir(), "p.zip")
	code, stdout, stderr := runBundle(t, time.UTC, "--data", f.dir, "--at", "2026-11-14T09:42:00Z", "--types", "poll,trap", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	files, names := readZipFile(t, out)
	if _, ok := files["poll/192.0.2.1/system.csv"]; !ok {
		t.Fatalf("no system.csv in %v", names)
	}
	if _, ok := files["poll/192.0.2.1/interfaces.csv"]; !ok {
		t.Fatalf("no interfaces.csv in %v", names)
	}
	readme := string(files["README.txt"])
	if !strings.Contains(readme, "  Polls        20 of 20 cycles answered (60 s)") ||
		!strings.Contains(readme, "(poll: sysUpTime reset; the device may have rebooted; coldStart trap)") {
		t.Fatalf("README:\n%s", readme)
	}
	if !strings.Contains(stdout, "reboots 1") {
		t.Errorf("stdout %s", stdout)
	}
}
