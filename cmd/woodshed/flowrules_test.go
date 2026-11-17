package main

import (
	"bytes"
	"encoding/csv"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store"
)

// writeRawV9Flows stores, for fxDevs[0] in one hour's segment, a flow v9 data
// set that arrived before its template (kept raw) and then the template with
// one record decoded live. Both carry rule ID 77 in vendor-range type 40003;
// the live one was decoded with rule_id_ies "0:40003", so only the raw one
// needs the config to get its rule_id when it's decoded on read.
func writeRawV9Flows(t *testing.T, dir string, at time.Time) {
	t.Helper()
	tmpl := []flow.TemplateField{{ID: 8, Length: 4}, {ID: 12, Length: 4}, {ID: 7, Length: 2}, {ID: 11, Length: 2}, {ID: 4, Length: 1},
		{ID: 233, Length: 1}, {ID: 323, Length: 8}, {ID: 40003, Length: 4}}
	rec := func(sport uint16) flow.Values {
		return flow.Values{}.Addr(netip.MustParseAddr("203.0.113.50")).Addr(netip.MustParseAddr("10.20.0.5")).U16(sport).U16(23).U8(6).
			U8(flow.FwDenied).U64(uint64(at.UnixMilli())).U32(77)
	}
	from := netip.AddrPortFrom(fxDevs[0], 2055)
	c := flow.NewCollector(flow.Options{RuleIDIEs: []flow.IEKey{{ID: 40003}}, PendingBytes: 1, PendingPerExporter: 1})
	var recs []*flow.Record
	var raws []*flow.RawSet
	emit := func(r *flow.Record) { x := *r; recs = append(recs, &x) }
	raw := func(r *flow.RawSet) { x := *r; raws = append(raws, &x) }
	b := flow.NewBuilder(flow.V9)
	b.Data(256, rec(40001))
	c.Decode(flow.Packet{Data: b.Message(flow.Header{ExportTime: uint32(at.Unix()), Seq: 1, Domain: 1, SysUptime: 1000}), From: from,
		Received: at}, emit, raw)
	b.Template(256, tmpl)
	b.Data(256, rec(40002))
	c.Decode(flow.Packet{Data: b.Message(flow.Header{ExportTime: uint32(at.Unix()), Seq: 2, Domain: 1, SysUptime: 2000}), From: from,
		Received: at.Add(time.Second)}, emit, raw)
	if len(raws) != 1 || len(recs) != 1 || recs[0].RuleID != "77" {
		t.Fatalf("setup: %d raw, %d records %+v", len(raws), len(recs), recs)
	}
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
	if err := st.WriteFlows(fxDevs[0], store.FlowBatch{Received: at, Raw: raws}); err != nil {
		t.Fatal(err)
	}
	now = at.Add(time.Second)
	if err := st.WriteFlows(fxDevs[0], store.FlowBatch{Received: now, Records: recs}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	idx.Close()
}

// `woodshed search --type flow`, `flows top` and `woodshed bundle` decode raw
// sets on read with the config's rule_id_ies, as the service does: --config
// when given, else the data folder's own woodshed.toml (a portable copy).
func TestCLIFlowsRuleIDIEsOnRead(t *testing.T) {
	dir := t.TempDir()
	at := fxNow.Add(-2 * time.Hour)
	writeRawV9Flows(t, dir, at)
	searchNow = func() time.Time { return fxNow }
	t.Cleanup(func() { searchNow = time.Now })

	count := func(args ...string) string {
		t.Helper()
		code, out, errOut := runCLI(append([]string{"search", "--type", "flow", "--last", "24h", "--field", "rule_id=77", "--count"}, args...)...)
		if code > 1 {
			t.Fatalf("search %v: %d %q", args, code, errOut)
		}
		return strings.TrimSpace(out)
	}
	// No config: the raw set decodes on read without a rule ID.
	if got := count("--data", dir); got != "1" {
		t.Fatalf("no config: %s with rule 77, want 1", got)
	}
	cfg := config.Default()
	cfg.Storage.DataDir = dir
	cfg.Listeners.Flow.RuleIDIEs = []string{"0:40003"}
	// --config given (it's elsewhere, and names the folder).
	other := filepath.Join(t.TempDir(), "woodshed.toml")
	if err := config.Save(other, cfg); err != nil {
		t.Fatal(err)
	}
	if got := count("--config", other); got != "2" {
		t.Fatalf("--config: %s with rule 77, want 2", got)
	}
	// The folder's own config (a portable copy), with --data.
	if err := config.Save(filepath.Join(dir, config.FileName), cfg); err != nil {
		t.Fatal(err)
	}
	if got := count("--data", dir); got != "2" {
		t.Fatalf("the folder's config: %s with rule 77, want 2", got)
	}
	code, out, errOut := runCLI("flows", "top", "--data", dir, "--by", "rule_id", "--metric", "flows", "--last", "24h")
	if code != 0 || !strings.Contains(out, "77") {
		t.Fatalf("flows top by rule_id: %d %q %q", code, out, errOut)
	}
	// By bytes, the rule's denied events carry none: no row, and the last
	// line says so (lab, 2.0.0-rc1: it was a row at 0 bytes).
	code, out, _ = runCLI("flows", "top", "--data", dir, "--by", "rule_id", "--last", "24h")
	if code != 0 || strings.Contains(out, "77") || !strings.Contains(out, "; 1 with 0 bytes not shown\n") {
		t.Fatalf("flows top by rule_id, bytes: %d %q", code, out)
	}
	zipPath := filepath.Join(t.TempDir(), "b.zip")
	code, _, errOut = runCLI("bundle", "--data", dir, "--at", at.Format(time.RFC3339), "--before", "10m", "--after", "10m", "--out", zipPath)
	if code != 0 {
		t.Fatalf("bundle: %d %q", code, errOut)
	}
	files, _ := readZipFile(t, zipPath)
	var csvb []byte
	for name, b := range files {
		if strings.HasSuffix(name, "/flows.csv") {
			csvb = b
		}
	}
	rows, err := csv.NewReader(bytes.NewReader(csvb)).ReadAll()
	if err != nil || len(rows) != 3 {
		t.Fatalf("bundle flows.csv: %v, %d rows", err, len(rows))
	}
	col := -1
	for i, h := range rows[0] {
		if h == "rule_id" {
			col = i
		}
	}
	for _, r := range rows[1:] {
		if r[col] != "77" {
			t.Fatalf("bundle row without its rule ID: %v", r)
		}
	}
}
