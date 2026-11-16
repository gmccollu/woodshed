package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// flowLog is one line of `woodshed send --log`.
type flowLog struct {
	Seq      uint64 `json:"seq"`
	Domain   uint32 `json:"domain"`
	Start    string `json:"start"`
	End      string `json:"end"`
	Src      string `json:"src"`
	SumBytes uint64 `json:"sum_bytes"`
	Sampling uint32 `json:"sampling"`
	FwEvent  string `json:"fw_event"`
}

func readFlowLog(t *testing.T, path string) []flowLog {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []flowLog
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l flowLog
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("log line %q: %v", sc.Text(), err)
		}
		out = append(out, l)
	}
	return out
}

// TestFlowsEndToEnd (SPEC §13.8) runs the real binary: IPFIX from `woodshed
// send` in three phases (event-style records, two domains, one sampled 1 in
// 100), then searches, top-N and the summary through the API and the command
// line, and a bundle around the middle phase: its flows.ipfix holds exactly
// the generator's records whose flow time overlaps the window, by sequence
// number, the CSV has as many rows, the README's top talkers match a count
// from the generator's own log, and the sampling note is there.
func TestFlowsEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	dir := t.TempDir()
	syslogPort, uiPort := pickPorts(t)
	ipfixPort := freeUDPPort(t, syslogPort, uiPort)
	cfgPath, dataDir := writeConfig(t, dir, syslogPort, uiPort)
	c, err := config.Read(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c.Listeners.Flow.Enabled, c.Listeners.Flow.Addr = true, "127.0.0.1"
	c.Listeners.Flow.NetFlowPort, c.Listeners.Flow.IPFIXPort = 0, ipfixPort
	c.Listeners.Flow.RuleIDIEs = []string{loadgen.RuleIE(loadgen.ProtoIPFIX).String()}
	if err := config.Save(cfgPath, c); err != nil {
		t.Fatal(err)
	}
	p := startWoodshed(t, cfgPath, dataDir, uiPort)
	defer p.stop()

	run := loadgen.NewRunID()[:8]
	var all []flowLog
	sent := 0
	phase := func(name string, n int) {
		t.Helper()
		logPath := filepath.Join(dir, name+".ndjson")
		out, err := exec.Command(binary, "send", "--proto", "ipfix", "--host", "127.0.0.1", "--port", fmt.Sprint(ipfixPort),
			"--count", fmt.Sprint(n), "--rate", "5000", "--run", run, "--first-seq", fmt.Sprint(sent), "--events",
			"--domains", "2", "--sampling", "100", "--sampled-domains", "1", "--log", logPath).CombinedOutput()
		if err != nil {
			t.Fatalf("send %s: %v\n%s", name, err, out)
		}
		all = append(all, readFlowLog(t, logPath)...)
		sent += n
		want := int64(sent)
		waitFor(t, name+" flows stored", 30*time.Second, func() bool {
			// The index histogram's total: every record stored and indexed.
			var h struct {
				Histogram struct {
					Buckets []struct{ Count *int64 }
				}
			}
			p.getJSON("/api/search/summary?type=flow&fields=none&bucket=3600", &h)
			var n int64
			for _, b := range h.Histogram.Buckets {
				if b.Count != nil {
					n += *b.Count
				}
			}
			return n == want
		})
	}
	phase("before", 600)
	time.Sleep(1200 * time.Millisecond)
	w0 := time.Now().UTC().Truncate(time.Millisecond)
	phase("middle", 900)
	time.Sleep(1200 * time.Millisecond)
	w1 := time.Now().UTC().Truncate(time.Millisecond)
	phase("after", 600)

	// What overlaps [w0, w1) by flow time, from the generator's own log.
	ms := func(s string) int64 {
		tm, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatalf("time %q: %v", s, err)
		}
		return tm.UnixMilli()
	}
	want := map[uint64]bool{}
	talkers := map[string]uint64{}
	denied := 0
	for _, l := range all {
		end := ms(l.End)
		start := min(ms(l.Start), end)
		if end >= w0.UnixMilli() && start < w1.UnixMilli() {
			want[l.Seq] = true
			talkers[l.Src] += l.SumBytes
			if l.FwEvent == "denied" {
				denied++
			}
		}
	}
	if len(want) == 0 || denied == 0 {
		t.Fatalf("nothing in the window (%d records, %d denied)", len(want), denied)
	}
	type kv struct {
		k string
		v uint64
	}
	var tops []kv
	for k, v := range talkers {
		if v > 0 {
			tops = append(tops, kv{k, v})
		}
	}
	sort.Slice(tops, func(i, j int) bool { return tops[i].v > tops[j].v || tops[i].v == tops[j].v && tops[i].k < tops[j].k })

	q := url.Values{"from": {w0.Format(time.RFC3339Nano)}, "to": {w1.Format(time.RFC3339Nano)}}
	// The API: the summary's count, top denied sources and top talkers.
	var sum struct{ Matched int64 }
	p.getJSON("/api/search/summary?type=flow&fields=proto&histogram=false&budget_ms=10000&"+q.Encode(), &sum)
	if sum.Matched != int64(len(want)) {
		t.Fatalf("summary %d, want %d", sum.Matched, len(want))
	}
	var top struct {
		Rows []struct {
			Key   string
			Bytes int64
		}
		Total struct{ Flows int64 }
	}
	p.getJSON("/api/flows/top?by=src&budget_ms=10000&"+q.Encode(), &top)
	if len(top.Rows) == 0 || top.Rows[0].Key != tops[0].k || uint64(top.Rows[0].Bytes) != tops[0].v {
		t.Fatalf("top talkers %+v, want %+v", top.Rows, tops[:min(3, len(tops))])
	}
	p.getJSON("/api/flows/top?by=src&fw_event=denied&budget_ms=10000&"+q.Encode(), &top)
	if top.Total.Flows != int64(denied) {
		t.Fatalf("denied %d, want %d", top.Total.Flows, denied)
	}

	// The command line (read-only, beside the running service).
	out, err := exec.Command(binary, "search", "--data", dataDir, "--type", "flow", "--from", w0.Format(time.RFC3339Nano),
		"--to", w1.Format(time.RFC3339Nano), "--count").Output()
	if err != nil || strings.TrimSpace(string(out)) != fmt.Sprint(len(want)) {
		t.Fatalf("woodshed search --count: %v %q, want %d", err, out, len(want))
	}
	out, err = exec.Command(binary, "flows", "top", "--data", dataDir, "--by", "src", "--from", w0.Format(time.RFC3339Nano),
		"--to", w1.Format(time.RFC3339Nano), "--json").Output()
	var cliTop struct {
		Rows []struct{ Key string }
	}
	if err != nil || json.Unmarshal(out, &cliTop) != nil || len(cliTop.Rows) == 0 || cliTop.Rows[0].Key != tops[0].k {
		t.Fatalf("woodshed flows top: %v %s", err, out)
	}

	// The bundle around the middle phase.
	half := w1.Sub(w0) / 2
	at := w0.Add(half)
	body := map[string]any{"kind": "bundle", "at": at.Format(time.RFC3339Nano), "before": fmt.Sprintf("%dms", half.Milliseconds()),
		"after": fmt.Sprintf("%dms", (w1.Sub(w0) - half).Milliseconds()), "active_devices": true}
	code, b := p.do("POST", "/api/exports", body)
	if code != 202 {
		t.Fatalf("bundle %d %s", code, b)
	}
	var created struct{ ID string }
	json.Unmarshal(b, &created)
	var info struct {
		State   string
		Error   string
		Filters struct{ Types []string }
	}
	waitFor(t, "the bundle", 60*time.Second, func() bool {
		p.getJSON("/api/exports/"+created.ID, &info)
		return info.State == "ready" || info.State == "failed"
	})
	if info.State != "ready" || !strings.Contains(strings.Join(info.Filters.Types, ","), "flow") {
		t.Fatalf("bundle %+v", info)
	}
	resp, err := http.Get(p.base + "/api/exports/" + created.ID + "/download")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	zpath := filepath.Join(dir, "bundle.zip")
	os.WriteFile(zpath, zb, 0o600)
	files, _ := unzipAll(t, zpath)
	ipfix, csv := files["flows/127.0.0.1/flows.ipfix"], files["flows/127.0.0.1/flows.csv"]
	if len(ipfix) == 0 || len(csv) == 0 {
		var names []string
		for n := range files {
			names = append(names, n)
		}
		t.Fatalf("no flow files in %v", names)
	}
	got := map[uint64]int{}
	n := 0
	if err := flow.ReadFile(bytes.NewReader(ipfix), flow.FileReadOptions{}, func(r *flow.Record) {
		n++
		if tag, seq, ok := loadgen.FlowSeq(r); ok && loadgen.MatchRun(tag, run) {
			got[seq]++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || n != len(want) {
		t.Fatalf("flows.ipfix: %d records, %d of the run, want %d", n, len(got), len(want))
	}
	for s := range want {
		if got[s] != 1 {
			t.Fatalf("seq %d in flows.ipfix %d times", s, got[s])
		}
	}
	if rows := bytes.Count(csv, []byte("\r\n")) - 1; rows != len(want) {
		t.Fatalf("flows.csv: %d rows, want %d", rows, len(want))
	}
	readme := string(files["README.txt"])
	pct := func(v uint64) string {
		var tot uint64
		for _, x := range tops {
			tot += x.v
		}
		return fmt.Sprintf("%s %.0f %%", tops[0].k, 100*float64(v)/float64(tot))
	}
	for _, s := range []string{"\n  Flows        ", "top talkers by bytes: " + pct(tops[0].v), "sampled 1 in 100 on domain",
		"firewall events: ", "denied"} {
		if !strings.Contains(readme, s) {
			t.Errorf("README lacks %q:\n%s", s, readme)
		}
	}
}
