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
// had no exporters after a restart): the exporter's last 24 hours come back
// from the stored counts, gap included, with "last seen" its last flow
// datagram (not a later syslog message from the same address). No template
// is restored: the exporter changed its layout while Woodshed was down, and
// the data that came before its new template waited and decoded with the new
// layout.
func TestFlowRestartKeepsCountsNotTemplates(t *testing.T) {
	dir := t.TempDir()
	nf, ix, sp := freeUDP(t), freeUDP(t), freePort(t)
	cfgPath := writeConfig(t, dir, sp, 0, func(c *config.Config) {
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
	gen := func(o loadgen.FlowOptions) *loadgen.FlowGen {
		o.Proto, o.Count, o.RecordsPerPacket = loadgen.ProtoIPFIX, 1<<20, 10
		g, err := loadgen.NewFlowGen(o, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	send := func(g *loadgen.FlowGen, n int, skip int, gap time.Duration) int {
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
			time.Sleep(gap)
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
	fields := func(r *running) int {
		var tpl api.FlowTemplates
		if code := r.do(t, "GET", "/api/flows/templates?device=127.0.0.1", nil, &tpl); code != 200 {
			t.Fatalf("templates %d", code)
		}
		n := 0
		for _, d := range tpl.Domains {
			for _, x := range d.Templates {
				n = max(n, len(x.Fields))
			}
		}
		return n
	}

	r := start(t, cfgPath)
	first := send(gen(loadgen.FlowOptions{TemplateEvery: 1 << 20, Sampling: 100, RunID: "0000aaaa"}), 20, 5, time.Millisecond)
	waitFlows(t, r, "", int64(first))
	before := exporter(r)
	oldFields := fields(r)
	if before.Counts24h.SequenceGaps != 1 || before.Counts24h.Records != int64(first) || before.LastSeen == nil || oldFields == 0 {
		t.Fatalf("before the restart: %+v fields %d", before, oldFields)
	}
	// A syslog message from the same address moves the device's last_heard, not the exporter's last seen.
	time.Sleep(1100 * time.Millisecond)
	sc, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", sp))
	if err != nil {
		t.Fatal(err)
	}
	sc.Write([]byte("<13>1 2026-11-17T12:00:00Z h app - - - hello"))
	sc.Close()
	time.Sleep(300 * time.Millisecond)
	r.stop(t)

	r = start(t, cfgPath)
	after := exporter(r)
	if after.Counts24h.SequenceGaps != 1 || after.Counts24h.Records != int64(first) || after.Counts24h.NoTemplate != 0 {
		t.Fatalf("after the restart, before any data: %+v", after.Counts24h)
	}
	if after.LastSeen == nil || after.LastSeen.After(before.LastSeen.Add(500*time.Millisecond)) {
		t.Fatalf("last seen %v, the last flow datagram was at %v", after.LastSeen, before.LastSeen)
	}
	if len(after.Domains) == 0 {
		t.Fatal("no domain after the restart")
	}
	for _, d := range after.Domains {
		if d.Templates != 0 || d.LastTemplate != nil {
			t.Fatalf("a template restored into the decoder: %+v", after.Domains)
		}
		// The rate before the restart is shown, not applied.
		if d.Sampling != 0 || d.LastKnownSampling != 100 {
			t.Fatalf("sampling restored into the decoder, or not shown: %+v", after.Domains)
		}
	}
	// The exporter's new layout (two more fields); its data comes before its template.
	second := send(gen(loadgen.FlowOptions{EnterpriseIEs: 2, TemplateFirstDelay: 300 * time.Millisecond, RunID: "0000bbbb"}), 40, -1, 15*time.Millisecond)
	waitFlows(t, r, "", int64(first+second))
	got := exporter(r)
	if got.Counts24h.Records != int64(first+second) || got.Counts24h.NoTemplate != 0 || got.Counts24h.Late == 0 || got.PendingBytes != 0 {
		t.Fatalf("after the restart: %+v pending %d", got.Counts24h, got.PendingBytes)
	}
	if nf := fields(r); nf != oldFields+2 {
		t.Fatalf("template fields %d, want the new layout's %d", nf, oldFields+2)
	}
}
