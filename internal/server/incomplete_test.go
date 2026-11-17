package server

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
)

// An octet-counted frame cut short by its sender, end to end (2.0): the stored
// line's marker, search (API JSON), the live tail, /api/stats, an export and an
// incident bundle all show it as incomplete, and it isn't counted as truncated.
// A complete frame and a last line without its LF stay unmarked.
func TestIncompleteFrameEndToEnd(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, writeConfig(t, dir, port, 0, nil))
	const tag = "e2eincomplete"
	whole := "<13>host app: " + tag + " whole"
	short := "<13>host app: " + tag + " short"
	noLF := "<13>host app: " + tag + " no LF"
	for _, data := range []string{
		fmt.Sprintf("%d %s", len(whole), whole),
		fmt.Sprintf("%d %s", len(short)+41, short), // 41 bytes never arrive
		"<13>host app: x\n" + noLF,
	} {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		c.Close() // the sender's FIN, mid-frame for the second
	}

	// Search: exactly the three, and only the short one marked.
	var results []map[string]any
	waitFor(t, "3 results", func() bool {
		var page struct{ Results []map[string]any }
		r.do(t, "GET", "/api/search?limit=100&q="+tag, nil, &page)
		results = page.Results
		return len(page.Results) == 3
	})
	byRaw := map[string]map[string]any{}
	for _, res := range results {
		byRaw[res["raw"].(string)] = res
	}
	if s := byRaw[short]; s == nil || s["incomplete"] != true || s["frame_arrived"] != float64(len(short)) ||
		s["frame_length"] != float64(len(short)+41) || s["truncated"] != nil || s["severity"] != float64(5) {
		t.Errorf("short result %v", s)
	}
	for _, raw := range []string{whole, noLF} {
		res := byRaw[raw]
		if res == nil {
			t.Fatalf("no result %q in %v", raw, results)
		}
		for _, k := range []string{"incomplete", "truncated", "frame_arrived", "frame_length"} {
			if _, ok := res[k]; ok {
				t.Errorf("%q has %s: %v", raw, k, res)
			}
		}
	}

	// The live tail replays it with the same fields.
	live := readLive(t, r.base+"/api/live?q="+tag, 3)
	if s := live[short]; s == nil || s["incomplete"] != true || s["frame_length"] != float64(len(short)+41) {
		t.Errorf("live %v", live)
	}
	if w := live[whole]; w == nil || w["incomplete"] != nil {
		t.Errorf("live whole %v", w)
	}

	// /api/stats: one incomplete frame on the TCP listener, nothing truncated.
	var st api.Stats
	waitFor(t, "the stats", func() bool {
		r.do(t, "GET", "/api/stats", nil, &st)
		return len(st.TCPFrames) == 1 && st.TCPFrames[0].Incomplete == 1
	})
	if f := st.TCPFrames[0]; f.Listener != "tcp" || f.Port != port || f.FrameTimeouts != 0 || st.Truncated24h != 0 {
		t.Errorf("stats %+v %+v", st.TCPFrames, st)
	}

	// An export and a bundle hold the lines as stored: the marker included.
	now := time.Now().UTC()
	marked := " " + `\#incomplete=` + fmt.Sprintf("%d/%d", len(short), len(short)+41)
	for _, body := range []map[string]any{
		{"all_devices": true, "from": now.Add(-time.Hour).Format(time.RFC3339), "to": now.Add(time.Minute).Format(time.RFC3339), "q": tag},
		{"kind": "bundle", "at": now.Format(time.RFC3339Nano), "before": "10m", "after": "5m", "active_devices": true},
	} {
		lines := exportLines(t, r, body)
		var got []string
		for _, l := range lines {
			if strings.Contains(l, tag) {
				got = append(got, l)
			}
		}
		if len(got) != 3 {
			t.Fatalf("%v: %d lines with the tag: %q", body["kind"], len(got), got)
		}
		n := 0
		for _, l := range got {
			switch {
			case strings.HasSuffix(l, short+marked):
				n++
			case strings.HasSuffix(l, " 127.0.0.1 "+whole), strings.HasSuffix(l, " 127.0.0.1 "+noLF):
			default:
				t.Errorf("%v: line %q", body["kind"], l)
			}
		}
		if n != 1 {
			t.Errorf("%v: %d marked lines, want 1: %q", body["kind"], n, got)
		}
	}
}

// readLive reads n message events from an SSE URL, keyed by raw.
func readLive(t *testing.T, u string, n int) map[string]map[string]any {
	t.Helper()
	req, _ := http.NewRequest("GET", u, nil)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]map[string]any{}
	sc := bufio.NewScanner(resp.Body)
	event := ""
	for len(out) < n && sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: ") && (event == "" || event == "message"):
			var m map[string]any
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &m); err != nil {
				t.Fatalf("live data %q: %v", line, err)
			}
			out[m["raw"].(string)] = m
		case line == "":
			event = ""
		}
	}
	if len(out) < n {
		t.Fatalf("live: %d messages, want %d (%v)", len(out), n, sc.Err())
	}
	return out
}

// exportLines creates an export from body, waits for it and returns the lines
// of its logs/ files.
func exportLines(t *testing.T, r *running, body map[string]any) []string {
	t.Helper()
	var created map[string]string
	if code := r.do(t, "POST", "/api/exports", body, &created); code != 202 {
		t.Fatalf("create %d %v", code, created)
	}
	var info api.ExportInfo
	waitFor(t, "export ready", func() bool {
		r.do(t, "GET", "/api/exports/"+created["id"], nil, &info)
		return info.State == "ready" || info.State == "failed"
	})
	if info.State != "ready" {
		t.Fatalf("export %+v", info)
	}
	resp, err := http.Get(r.base + "/api/exports/" + url.PathEscape(created["id"]) + "/download")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, f := range zr.File {
		if !strings.Contains(f.Name, "logs/") {
			continue
		}
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		lines = append(lines, strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")...)
	}
	return lines
}
