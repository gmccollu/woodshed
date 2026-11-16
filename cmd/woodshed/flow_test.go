package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/store"
)

// writeFlows stores n flow records for fxDevs[0] in the data folder dir,
// received a second apart from at, every third one a denied event, and
// closes the store (so every segment has its footer).
func writeFlows(t *testing.T, dir string, at time.Time, n int) {
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
	for i := 0; i < n; i++ {
		now = at.Add(time.Duration(i) * time.Second)
		ms := now.UnixMilli()
		r := &flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto |
			flow.HasBytes | flow.HasPackets, Received: ms, Start: ms - 1000, End: ms,
			Src: netip.AddrFrom4([4]byte{10, 20, 0, byte(i % 4)}), Dst: netip.MustParseAddr("198.51.100.7"), SrcPort: uint16(40000 + i),
			DstPort: []uint16{443, 53}[i%2], Proto: []uint8{6, 17}[i%2], Bytes: 1000, Packets: 2, Sampling: 1}
		if i%3 == 0 {
			r.Has |= flow.HasFwEvent
			r.FwEvent = flow.FwDenied
		}
		if err := st.WriteFlows(fxDevs[0], store.FlowBatch{Received: now, Records: []*flow.Record{r}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	idx.Close()
}

// woodshed search --type flow (SPEC §13.7): the flow filters as flags, CSV
// rows, --json, --count; q refused.
func TestSearchFlows(t *testing.T) {
	f := newSearchFixture(t)
	writeFlows(t, f.dir, fxNow.Add(-3*time.Hour), 60)

	code, out, errOut := runSearch(t, f.dir, "--type", "flow", "--last", "24h")
	lines := strings.Split(strings.TrimRight(out, "\r\n"), "\r\n")
	if code != 0 || len(lines) != 61 || !strings.HasPrefix(lines[0], "device,start,end,event_time,src,") || !strings.Contains(errOut, "60 flow records") {
		t.Fatalf("all: %d %d lines %q %s", code, len(lines), lines[0], errOut)
	}
	if !strings.HasPrefix(lines[1], fxDevs[0].String()+",") {
		t.Fatalf("row %q", lines[1])
	}
	if code, out, _ := runSearch(t, f.dir, "--type", "flow", "--dst-port", "443", "--proto", "tcp", "--count"); code != 0 || out != "30\n" {
		t.Fatalf("dst-port: %d %q", code, out)
	}
	if code, out, _ := runSearch(t, f.dir, "--type", "flow", "--field", "fw_event=denied", "--count"); code != 0 || out != "20\n" {
		t.Fatalf("denied: %d %q", code, out)
	}
	if code, out, _ := runSearch(t, f.dir, "--type", "flow", "--src", "10.20.0.1", "--count"); code != 0 || out != "15\n" {
		t.Fatalf("src: %d %q", code, out)
	}
	code, out, _ = runSearch(t, f.dir, "--type", "flow", "--json", "--limit", "2", "--order", "desc")
	var res struct {
		Type   string `json:"type"`
		Fields struct {
			DstPort int `json:"dst_port"`
		} `json:"fields"`
	}
	if code != 0 || strings.Count(out, "\n") != 2 || json.Unmarshal([]byte(strings.Split(out, "\n")[0]), &res) != nil || res.Type != "flow" {
		t.Fatalf("json: %d %q", code, out)
	}
	if code, _, errOut := runSearch(t, f.dir, "--type", "flow", "link down"); code != 2 || !strings.Contains(errOut, "flows have no text") {
		t.Fatalf("q: %d %q", code, errOut)
	}
	if code, _, errOut := runSearch(t, f.dir, "--dst-port", "443"); code != 2 || !strings.Contains(errOut, "not a filter for syslog") {
		t.Fatalf("flow flag on syslog: %d %q", code, errOut)
	}
	if code, out, _ := runSearch(t, f.dir, "--type", "flow", "--src", "192.0.2.99", "--count"); code != 1 || out != "0\n" {
		t.Fatalf("none: %d %q", code, out)
	}
}

// woodshed flows top: the top-N table and JSON.
func TestFlowsTop(t *testing.T) {
	f := newSearchFixture(t)
	writeFlows(t, f.dir, fxNow.Add(-3*time.Hour), 60)
	searchNow = func() time.Time { return fxNow }
	defer func() { searchNow = time.Now }()
	code, out, errOut := runCLI("flows", "top", "--data", f.dir, "--by", "dst-port", "--last", "24h")
	if code != 0 || !strings.Contains(out, "tcp/443") || !strings.Contains(out, "udp/53") || !strings.Contains(out, "60 flows") {
		t.Fatalf("top: %d %q %q", code, out, errOut)
	}
	code, out, _ = runCLI("flows", "top", "--data", f.dir, "--by", "src", "--fw-event", "denied", "--last", "24h", "--json")
	var p struct {
		Metric string `json:"metric"`
		Total  struct {
			Flows int64 `json:"flows"`
		} `json:"total"`
		Rows []struct{ Key string } `json:"rows"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &p) != nil || p.Metric != "flows" || p.Total.Flows != 20 || len(p.Rows) == 0 {
		t.Fatalf("denied: %d %q", code, out)
	}
	if code, _, errOut := runCLI("flows", "top", "--data", f.dir, "--by", "nope"); code != 2 || !strings.Contains(errOut, "by must be") {
		t.Fatalf("bad by: %d %q", code, errOut)
	}
	if code, _, _ := runCLI("flows"); code != 2 {
		t.Fatal("bare flows")
	}
}

// woodshed flow on|off|status, on Linux: the config, the firewall (ufw),
// one port off.
func TestFlowCommandLinux(t *testing.T) {
	defer noService()
	fw := withFirewall(t, "linux")
	cfgPath, dataDir := testConfig(t, nil)
	code, out, errOut := runCLI("flow", "on", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Turned the flow listener on (flow UDP 2055, IPFIX UDP 4739)") ||
		!strings.Contains(out, "2055/udp") || !strings.Contains(out, "4739/udp") {
		t.Fatalf("on: %d %q %q", code, out, errOut)
	}
	if c := loadCfg(t, cfgPath); !c.Listeners.Flow.Enabled {
		t.Fatal("not enabled")
	}
	for _, rf := range []string{fwrule.FlowPortRecordFile, fwrule.FlowIPFIXRecordFile} {
		if _, err := os.Stat(filepath.Join(dataDir, rf)); err != nil {
			t.Errorf("record %s: %v", rf, err)
		}
	}
	if code, out, _ := runCLI("flow", "on", "--ipfix-port", "0", "--config", cfgPath); code != 0 || !strings.Contains(out, "(flow UDP 2055)") {
		t.Fatalf("ipfix off: %d %q", code, out)
	}
	if code, out, _ := runCLI("flow", "status", "--config", cfgPath); code != 0 || !strings.Contains(out, "on, flow UDP 2055; template timeout 30m") {
		t.Fatalf("status: %d %q", code, out)
	}
	code, out, _ = runCLI("flow", "off", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "Turned the flow listener off") || !strings.Contains(strings.Join(fw.calls, "\n"), "ufw delete allow 2055/udp") {
		t.Fatalf("off: %d %q %v", code, out, fw.calls)
	}
	if code, _, errOut := runCLI("flow", "on", "--flow-port", "0", "--ipfix-port", "0", "--config", cfgPath); code != 1 ||
		!strings.Contains(errOut, "listeners.flow.flow_port") {
		t.Fatalf("both off: %d %q", code, errOut)
	}
	if code, _, _ := runCLI("flow", "sideways", "--config", cfgPath); code != 2 {
		t.Fatal("bad mode")
	}
}

// The Flows row of `woodshed status` and the exporter rows of `flow status`.
func TestFlowStatusRows(t *testing.T) {
	days := 4.8
	fs := &api.FlowState{Enabled: true, Budget: api.FlowBudget{Bytes: 8 << 30, UsedBytes: 2 << 30, EstimatedDays: &days},
		Exporters: []api.FlowExporter{{DeviceID: "10.1.0.1", RecordsPerSec: 1180.5, Domains: []api.FlowDomain{{ID: 1, Sampling: 1000, Templates: 6}},
			Counts24h: api.FlowCounts{Records: 100, SequenceGaps: 3}, TimeSource: "received", ClockSkewMS: 4000000}}}
	var b strings.Builder
	statusFlowRows(&tabw{w: &b}, &server.RunState{Flows: fs})
	if got := b.String(); !strings.Contains(got, "Flows:      on; 1 exporter, 1180 records/s; budget 25 % used (2.0 GiB of 8.0 GiB)") {
		t.Fatalf("status row %q", got)
	}
	b.Reset()
	flowStateRows(&tabw{w: &b}, fs)
	for _, want := range []string{"about 4.8 days", "10.1.0.1: 1180.5 records/s; domain 1: 6 templates, 1 in 1000", "3 sequence gaps",
		"its clock is 4000000 ms off"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("flow status lacks %q:\n%s", want, b.String())
		}
	}
	b.Reset()
	statusFlowRows(&tabw{w: &b}, &server.RunState{})
	if b.Len() != 0 {
		t.Fatalf("no flows: %q", b.String())
	}
}
