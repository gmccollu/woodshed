package server

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// A restart mid-stream (SPEC §13.10 decision 83; lab, 2.0.0-rc1: /api/flows
// had no exporters after a restart and the next records waited for a
// template): the exporter's last 24 hours come back from the stored counts,
// gap included, and records sent right after the restart, with no template
// since, decode at once from the templates the newest segment kept.
func TestFlowRestartKeepsCountsAndTemplates(t *testing.T) {
	dir := t.TempDir()
	nf, ix := freeUDP(t), freeUDP(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.Flow.Enabled = true
		c.Listeners.Flow.Addr = "127.0.0.1"
		c.Listeners.Flow.FlowPort, c.Listeners.Flow.IPFIXPort = nf, ix
	})
	// One exporter socket for both runs: an exporter keeps its address and
	// port across Woodshed's restart.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	to := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ix}
	// Templates in the first packet only.
	g, err := loadgen.NewFlowGen(loadgen.FlowOptions{Proto: loadgen.ProtoIPFIX, Count: 1 << 20, RecordsPerPacket: 10,
		TemplateEvery: 1 << 20, RunID: "0000aaaa"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	send := func(n int, skip int) int {
		recs := 0
		for i := 0; i < n; i++ {
			pkt, exp := g.Next(time.Now())
			if i == skip {
				continue // lost on the way: a sequence gap of 10 records
			}
			if _, err := conn.WriteToUDP(pkt, to); err != nil {
				t.Fatal(err)
			}
			recs += len(exp)
			time.Sleep(time.Millisecond)
		}
		return recs
	}
	exporter := func(r *running) api.FlowExporter {
		t.Helper()
		var st api.FlowState
		if code := r.do(t, "GET", "/api/flows", nil, &st); code != 200 || len(st.Exporters) != 1 {
			t.Fatalf("flows: %d %+v", code, st)
		}
		return st.Exporters[0]
	}

	r := start(t, cfgPath)
	first := send(20, 5)
	waitFlows(t, r, "", int64(first))
	before := exporter(r)
	if before.Counts24h.SequenceGaps != 1 || before.Counts24h.Records != int64(first) {
		t.Fatalf("before the restart: %+v", before.Counts24h)
	}
	r.stop(t)

	r = start(t, cfgPath)
	after := exporter(r)
	if after.Counts24h.SequenceGaps != 1 || after.Counts24h.Records != int64(first) || after.Counts24h.NoTemplate != 0 {
		t.Fatalf("after the restart, before any data: %+v", after.Counts24h)
	}
	if len(after.Domains) == 0 || after.Domains[0].Templates == 0 {
		t.Fatalf("templates not restored: %+v", after.Domains)
	}
	second := send(10, -1)
	waitFlows(t, r, "", int64(first+second))
	got := exporter(r)
	if got.Counts24h.Records != int64(first+second) || got.Counts24h.NoTemplate != 0 || got.Counts24h.SequenceGaps != 1 ||
		got.PendingBytes != 0 {
		t.Fatalf("after the restart: %+v pending %d", got.Counts24h, got.PendingBytes)
	}
	// The window's gap is in the bundle too (decision 82).
	var page api.SummaryPage
	if code := r.do(t, "GET", fmt.Sprintf("/api/search/summary?type=flow&fields=status&budget_ms=10000"), nil, &page); code != 200 {
		t.Fatalf("summary %d", code)
	}
	for _, f := range page.Fields {
		for _, v := range f.Values {
			if v.Value == "no_template" {
				t.Fatalf("records stored undecoded after the restart: %+v", f)
			}
		}
	}
}
