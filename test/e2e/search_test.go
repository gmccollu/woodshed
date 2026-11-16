package e2e

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/loadgen"
)

type searchResult struct {
	Received string `json:"received"`
	DeviceID string `json:"device_id"`
	Severity *int   `json:"severity"`
	Raw      string `json:"raw"`
	Ref      string `json:"ref"`
}

type searchPage struct {
	Results      []searchResult `json:"results"`
	NextCursor   string         `json:"next_cursor"`
	ScannedBytes int64          `json:"scanned_bytes"`
	ScannedFiles int            `json:"scanned_files"`
	ElapsedMS    int64          `json:"elapsed_ms"`
	Partial      bool           `json:"partial"`
}

// TestSearchContextExport runs the real binary: messages sent over UDP and TCP
// are found by their sequence tags, pages concatenate to the whole run, context
// works around a hit, and an export downloads with a manifest whose checksums
// match the files.
func TestSearchContextExport(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	cfgPath, dataDir := writeConfig(t, dir, syslogPort, uiPort)
	p := startWoodshed(t, cfgPath, dataDir, uiPort)

	const per = 2000
	run := loadgen.NewRunID()
	tag := loadgen.SeqTag(run)
	for i, proto := range []string{"udp", "tcp"} {
		if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort),
			Proto: proto, Count: per, Rate: 5000, RunID: run, FirstSeq: i * per, Message: "e2e Link DOWN probe"}); err != nil {
			t.Fatal(err)
		}
	}
	search := func(q url.Values) searchPage {
		t.Helper()
		var pg searchPage
		p.getJSON("/api/search?"+q.Encode(), &pg)
		return pg
	}
	// The last UDP and the last TCP message: UDP goes through its own drainer, so
	// the TCP run's last can be stored before the UDP run's last.
	waitFor(t, "the last messages to be searchable", 20*time.Second, func() bool {
		return len(search(url.Values{"q": {tag + fmt.Sprint(2*per-1) + " "}}).Results) == 1 &&
			len(search(url.Values{"q": {tag + fmt.Sprint(per-1) + " "}}).Results) == 1
	})
	// One message by its exact tag.
	hit := search(url.Values{"q": {tag + "1234 "}})
	if len(hit.Results) != 1 || !strings.Contains(hit.Results[0].Raw, tag+"1234 e2e Link DOWN probe") ||
		hit.Results[0].Severity == nil || *hit.Results[0].Severity != 6 || hit.Results[0].DeviceID != "127.0.0.1" {
		t.Fatalf("hit %+v", hit)
	}
	// Every message, a page at a time, in both orders.
	for _, order := range []string{"desc", "asc"} {
		q := url.Values{"q": {"link down probe"}, "order": {order}, "limit": {"333"}}
		seen := map[string]bool{}
		var last string
		pages := 0
		for {
			pg := search(q)
			pages++
			for _, r := range pg.Results {
				if seen[r.Ref] {
					t.Fatalf("%s: repeated %s", order, r.Raw)
				}
				seen[r.Ref] = true
				if last != "" && (order == "desc" && r.Received > last || order == "asc" && r.Received < last) {
					t.Fatalf("%s: out of order", order)
				}
				last = r.Received
			}
			if pg.NextCursor == "" {
				break
			}
			q.Set("cursor", pg.NextCursor)
		}
		if len(seen) != 2*per {
			t.Fatalf("%s: %d results over %d pages, want %d", order, len(seen), pages, 2*per)
		}
		t.Logf("%s: %d results in %d pages", order, len(seen), pages)
	}
	if n := len(search(url.Values{"q": {tag}, "severities": {"none"}}).Results); n != 0 {
		t.Errorf("severities=none returned %d", n)
	}
	if n := len(search(url.Values{"q": {tag}, "severities": {"6"}, "limit": {"5000"}}).Results); n != 2*per {
		t.Errorf("severities=6 returned %d", n)
	}
	if code, b := p.do("GET", "/api/search?regex=true&q=(", nil); code != 400 || !strings.Contains(string(b), "error parsing regexp") {
		t.Errorf("bad regex: %d %s", code, b)
	}

	// Context around the hit.
	var cp struct {
		Lines    []searchResult `json:"lines"`
		HitIndex int            `json:"hit_index"`
		AtStart  bool           `json:"at_start"`
		AtEnd    bool           `json:"at_end"`
	}
	p.getJSON("/api/context?before=5&after=5&ref="+url.QueryEscape(hit.Results[0].Ref), &cp)
	if len(cp.Lines) != 11 || cp.HitIndex != 5 || cp.Lines[5].Ref != hit.Results[0].Ref || cp.AtStart || cp.AtEnd {
		t.Fatalf("context %+v", cp)
	}

	// Groups: the device in "lab" is listed with its count.
	if code, b := p.do("PATCH", "/api/devices/127.0.0.1", map[string]any{"group": "lab"}); code != 200 {
		t.Fatalf("patch: %d %s", code, b)
	}
	var groups []map[string]any
	p.getJSON("/api/groups", &groups)
	if len(groups) != 1 || groups[0]["name"] != "lab" || num(groups[0]["devices"]) != 1 {
		t.Errorf("groups %v", groups)
	}

	// Export everything (all_devices) and check the zip.
	now := time.Now().UTC()
	body := map[string]any{"all_devices": true, "from": now.Add(-time.Hour).Format(time.RFC3339),
		"to": now.Add(time.Minute).Format(time.RFC3339), "q": tag}
	code, b := p.do("POST", "/api/exports", body)
	if code != 202 {
		t.Fatalf("create export: %d %s", code, b)
	}
	var created struct{ ID string }
	json.Unmarshal(b, &created)
	var info map[string]any
	waitFor(t, "the export", 30*time.Second, func() bool {
		p.getJSON("/api/exports/"+created.ID, &info)
		if info["state"] == "failed" {
			t.Fatalf("export failed: %v", info["error"])
		}
		return info["state"] == "ready"
	})
	resp, err := http.Get(p.base + "/api/exports/" + created.ID + "/download")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if cd := resp.Header.Get("Content-Disposition"); !strings.HasPrefix(cd, `attachment; filename="woodshed-`) {
		t.Errorf("Content-Disposition %q", cd)
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		contents[f.Name], err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
	}
	var man struct {
		Lines int64 `json:"lines"`
		Files []struct {
			Path   string `json:"path"`
			Lines  int64  `json:"lines"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
		Gaps []any `json:"gaps"`
	}
	if err := json.Unmarshal(contents["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if man.Lines != 2*per || len(man.Files) == 0 {
		t.Fatalf("manifest %+v", man)
	}
	for _, f := range man.Files {
		sum := sha256.Sum256(contents[f.Path])
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("%s: checksum mismatch", f.Path)
		}
		if n := bytes.Count(contents[f.Path], []byte("\n")); int64(n) != f.Lines {
			t.Errorf("%s: %d lines, manifest says %d", f.Path, n, f.Lines)
		}
	}
	if !bytes.Contains(contents["woodshed-events.log"], []byte(" info start ")) {
		t.Errorf("events log:\n%s", contents["woodshed-events.log"])
	}
	t.Logf("export: %d bytes, %d lines, %d gaps", len(zb), man.Lines, len(man.Gaps))

	// Shutdown with a silent connection open stays fast.
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", uiPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p.stop()
	// Measured by the server's own log ("shutting down" to "stopped cleanly"), not
	// the wall clock: on a busy Windows arm64 runner the Ctrl-Break alone took 3.5 s
	// to arrive, while the shutdown itself took 0.2 s.
	if d, ok := shutdownTook(p.logPath); !ok {
		t.Error("no shutdown lines in the log")
	} else if d > 3*time.Second {
		t.Errorf("shutdown took %v with an idle connection open", d)
	}
}

// shutdownTook reads the last "shutting down" and "stopped cleanly" times from a
// woodshed log.
func shutdownTook(logPath string) (time.Duration, bool) {
	b, err := os.ReadFile(logPath)
	if err != nil {
		return 0, false
	}
	var start, end time.Time
	for _, line := range strings.Split(string(b), "\n") {
		ts, ok := strings.CutPrefix(line, "time=")
		if !ok {
			continue
		}
		f := strings.Fields(ts)
		if len(f) == 0 {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, f[0])
		if err != nil {
			continue
		}
		switch {
		case strings.Contains(line, `msg="shutting down"`):
			start = at
		case strings.Contains(line, `msg="stopped cleanly"`):
			end = at
		}
	}
	if start.IsZero() || end.IsZero() || end.Before(start) {
		return 0, false
	}
	return end.Sub(start), true
}
