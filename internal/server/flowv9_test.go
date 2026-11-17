package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// Flow v9 event records with the generator's vendor-range types (rule IDs in
// 40003), end to end: rule_id_ies "0:40003" fills rule_id at decode, rule_id
// filters and ranks, and a bundle's flows.csv and flows.ipfix carry it. An
// IPFIX run of the same flows (same seed; rule IDs in 32473:3) exports the
// same columns and rule IDs. Our reader gives back every stored record and
// field from flows.ipfix; with tshark on PATH (the CI job "flow-interop"
// sets WOODSHED_FLOW_INTEROP=1, which makes it required), tshark reads every
// record of it too, nothing malformed (SPEC §13.4, decided (build, 2026-11-17)).
func TestFlowV9VendorRuleIDEndToEnd(t *testing.T) {
	v9Rule, ixRule := loadgen.RuleIE(loadgen.ProtoFlowV9), loadgen.RuleIE(loadgen.ProtoIPFIX)
	if v9Rule.String() != "0:40003" {
		t.Fatalf("the v9 rule IE is %s", v9Rule)
	}
	r, nf, ix := flowServer(t, func(c *config.Config) { c.Listeners.Flow.RuleIDIEs = []string{v9Rule.String(), ixRule.String()} })
	ctx := context.Background()
	const n = 1500
	const v9Run, ixRun = "00009009", "0000f1f0"
	sent := map[string]map[uint64]flow.Record{v9Run: {}, ixRun: {}}
	for _, x := range []struct {
		proto, run string
		port       int
	}{{loadgen.ProtoFlowV9, v9Run, nf}, {loadgen.ProtoIPFIX, ixRun, ix}} {
		if _, err := loadgen.SendFlows(ctx, loadgen.FlowOptions{Proto: x.proto, Addr: fmt.Sprintf("127.0.0.1:%d", x.port), Count: n,
			Rate: 20000, Events: true, RunID: x.run, Seed: 7}, func(es []loadgen.Expected) {
			for _, e := range es {
				sent[x.run][e.Seq] = e.Record
			}
		}); err != nil {
			t.Fatal(err)
		}
	}
	waitFlows(t, r, "", 2*n)

	// The templates name the IEs Woodshed knows and leave the rest "" (shown as
	// pen:id): the v9 vendor-range types as {0, 40003}, the enterprise IEs too.
	var tpl api.FlowTemplates
	if code := r.do(t, "GET", "/api/flows/templates?device=127.0.0.1", nil, &tpl); code != 200 {
		t.Fatalf("templates: %d", code)
	}
	names := map[flow.IEKey]string{}
	for _, d := range tpl.Domains {
		for _, tp := range d.Templates {
			for _, f := range tp.Fields {
				names[flow.IEKey{PEN: f.PEN, ID: f.ID}] = f.Name
			}
		}
	}
	for k, want := range map[flow.IEKey]string{v9Rule: "", ixRule: "", {ID: 40001}: "", {ID: 8}: "sourceIPv4Address"} {
		if got, ok := names[k]; !ok || got != want {
			t.Errorf("template field %s: name %q (present %v), want %q", k, got, ok, want)
		}
	}

	// Decode and store: every v9 record has the rule ID it was sent with.
	stored := map[string]map[uint64]flow.Record{v9Run: {}, ixRun: {}}
	byRule := map[string]int64{}
	q := flowquery.Query{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour)}
	if err := r.srv.be.flows.eng.Each(ctx, q, func(_ string, rec *flow.Record) error {
		run, seq, ok := loadgen.FlowSeq(rec)
		if !ok || sent[run] == nil {
			return fmt.Errorf("a record of no run: %+v", rec)
		}
		c := *rec
		c.Extras = append([]flow.Extra(nil), rec.Extras...)
		stored[run][seq] = c
		byRule[rec.RuleID]++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for run, recs := range sent {
		if len(stored[run]) != n {
			t.Fatalf("run %s: %d stored, %d sent", run, len(stored[run]), n)
		}
		for seq, want := range recs {
			got := stored[run][seq]
			if !got.Is(flow.HasRuleID) || got.RuleID != want.RuleID {
				t.Fatalf("run %s seq %d: rule_id %q, sent %q", run, seq, got.RuleID, want.RuleID)
			}
		}
	}
	// Comparable: the same flows from v9 and IPFIX carry the same columns and
	// rule IDs, and the generator's fields at the same lengths.
	for seq, a := range stored[v9Run] {
		b := stored[ixRun][seq]
		if s, w := flowCSVish(&a), flowCSVish(&b); s != w {
			t.Fatalf("seq %d: v9 and IPFIX differ:\n v9    %s\n IPFIX %s", seq, s, w)
		}
		if la, lb := extraLens(&a), extraLens(&b); la != lb {
			t.Fatalf("seq %d: generator fields v9 %s, IPFIX %s", seq, la, lb)
		}
	}

	// Query: rule_id filters and ranks.
	var top api.FlowTopPage
	if code := r.do(t, "GET", "/api/flows/top?by=rule_id&budget_ms=10000", nil, &top); code != 200 || top.Partial || len(top.Rows) == 0 {
		t.Fatalf("top by rule_id: %d %+v", code, top)
	}
	for _, row := range top.Rows {
		if row.Key == "" || row.Flows != byRule[row.Key] {
			t.Fatalf("top by rule_id: %+v, stored %v", row, byRule)
		}
	}
	key := top.Rows[0].Key
	var sum api.SummaryPage
	if code := r.do(t, "GET", "/api/search/summary?type=flow&fields=rule_id&histogram=false&budget_ms=10000&rule_id="+url.QueryEscape(key),
		nil, &sum); code != 200 || sum.Matched != byRule[key] || sum.Partial {
		t.Fatalf("rule_id=%s: %d matched, want %d (%d)", key, sum.Matched, byRule[key], code)
	}

	// The bundle: flows.csv has every rule ID; flows.ipfix gives back every
	// stored record and field.
	now := time.Now().UTC()
	body := map[string]any{"kind": "bundle", "at": now.Format(time.RFC3339Nano), "before": "30m", "after": "0s", "active_devices": true}
	var created map[string]string
	if code := r.do(t, "POST", "/api/exports", body, &created); code != 202 {
		t.Fatalf("bundle: %d", code)
	}
	var info api.ExportInfo
	waitFor(t, "bundle ready", func() bool {
		r.do(t, "GET", "/api/exports/"+created["id"], nil, &info)
		return info.State == "ready" || info.State == "failed"
	})
	if info.State != "ready" {
		t.Fatalf("bundle %+v", info)
	}
	_, _, zb := r.doRaw(t, "GET", "/api/exports/"+created["id"]+"/download", nil)
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	rows, err := csv.NewReader(bytes.NewReader(files["flows/127.0.0.1/flows.csv"])).ReadAll()
	if err != nil || len(rows) != 2*n+1 {
		t.Fatalf("flows.csv: %v, %d rows", err, len(rows))
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	csvRules := map[string]int64{}
	for _, row := range rows[1:] {
		csvRules[row[col["rule_id"]]]++
	}
	if !reflect.DeepEqual(csvRules, byRule) {
		t.Fatalf("flows.csv rule IDs %v, stored %v", csvRules, byRule)
	}
	ipfix := files["flows/127.0.0.1/flows.ipfix"]
	read := 0
	if err := flow.ReadFile(bytes.NewReader(ipfix), flow.FileReadOptions{RuleIDIEs: []flow.IEKey{v9Rule, ixRule}}, func(rec *flow.Record) {
		read++
		run, seq, ok := loadgen.FlowSeq(rec)
		want, found := stored[run][seq]
		if !ok || !found {
			t.Fatalf("flows.ipfix: a record of no run: %+v", rec)
		}
		if g, w := fileComparable(rec), fileComparable(&want); !reflect.DeepEqual(g, w) {
			t.Fatalf("flows.ipfix run %s seq %d:\n got %+v\nwant %+v", run, seq, g, w)
		}
	}); err != nil {
		t.Fatal(err)
	}
	if read != 2*n {
		t.Fatalf("flows.ipfix: %d records read back, %d stored", read, 2*n)
	}

	tshark, err := exec.LookPath("tshark")
	if err != nil {
		if os.Getenv("WOODSHED_FLOW_INTEROP") == "1" {
			t.Fatal("tshark isn't on PATH")
		}
		t.Log("tshark isn't on PATH: flows.ipfix checked with our reader only")
		return
	}
	path := filepath.Join(t.TempDir(), "flows.ipfix")
	if err := os.WriteFile(path, ipfix, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tshark, "-r", path, "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=;",
		"-e", "cflow.srcaddr", "-e", "cflow.dstaddr", "-e", "cflow.srcport", "-e", "cflow.dstport", "-e", "cflow.protocol").CombinedOutput()
	if err != nil {
		t.Fatalf("tshark: %v\n%s", err, out)
	}
	fromTshark, fromCSV := map[string]int{}, map[string]int{}
	tupleKey := func(src, dst, sp, dp, proto string) string {
		return strings.Join([]string{src, dst, sp, dp, proto}, " ")
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) != 5 || cols[0] == "" {
			continue // a frame of templates or options only
		}
		parts := make([][]string, 5)
		for i := range cols {
			parts[i] = strings.Split(cols[i], ";")
		}
		for j := range parts[0] {
			if j >= len(parts[4]) {
				break
			}
			fromTshark[tupleKey(parts[0][j], parts[1][j], parts[2][j], parts[3][j], parts[4][j])]++
		}
	}
	for _, row := range rows[1:] {
		fromCSV[tupleKey(row[col["src"]], row[col["dst"]], row[col["src_port"]], row[col["dst_port"]], row[col["proto"]])]++
	}
	if fmt.Sprint(sortedCounts(fromTshark)) != fmt.Sprint(sortedCounts(fromCSV)) {
		t.Errorf("tshark and flows.csv disagree:\n tshark %v\n csv    %v", sortedCounts(fromTshark), sortedCounts(fromCSV))
	}
	bad, err := exec.Command(tshark, "-r", path, "-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number").CombinedOutput()
	if err != nil || strings.TrimSpace(string(bad)) != "" {
		t.Errorf("tshark: malformed frames in flows.ipfix: %v %q", err, bad)
	}
}

// flowCSVish is a record's columns without its times (two runs send at
// different times) and decode details.
func flowCSVish(r *flow.Record) string {
	c := *r
	c.Start, c.End, c.EventTime, c.Received, c.Has = 0, 0, 0, 0, c.Has&^(flow.HasStart|flow.HasEnd|flow.HasEventTime)
	c.Status, c.ExporterPort, c.Version, c.TemplateID, c.Template, c.Extras = 0, 0, 0, 0, nil, nil
	return fmt.Sprintf("%+v", c)
}

// extraLens is the generator's fields' lengths: run, sequence, rule.
func extraLens(r *flow.Record) string {
	var out []string
	for _, e := range r.Extras {
		out = append(out, strconv.Itoa(len(e.Value)))
	}
	return strings.Join(out, ",")
}

// fileComparable is what an IPFIX file carries of a record (SPEC §13.4: not
// the decode status, exporter port, version or template).
func fileComparable(r *flow.Record) flow.Record {
	c := *r
	c.Status, c.ExporterPort, c.Version, c.TemplateID, c.Template = 0, 0, 0, 0, nil
	if len(c.Extras) == 0 {
		c.Extras = nil
	}
	return c
}
