package server

import (
	"context"
	"fmt"
	"net/url"
	"testing"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// /api/search/summary's matched is the window's count for every combination
// of fields (none or one) × histogram (on or off) × filter (none or one), for
// flows and, as a regression check, syslog and traps. Flows with fields=none,
// histogram=false and a filter used to return 0 without scanning.
func TestSummaryMatchedEveryCombination(t *testing.T) {
	dir := t.TempDir()
	syslogPort, snmpPort := freePort(t), freeUDP(t)
	nf, ix := freeUDP(t), freeUDP(t)
	r := start(t, writeConfig(t, dir, syslogPort, 0, func(c *config.Config) {
		c.Listeners.SNMP.Enabled, c.Listeners.SNMP.Addr, c.Listeners.SNMP.Port = true, "127.0.0.1", snmpPort
		c.Listeners.Flow.Enabled, c.Listeners.Flow.Addr = true, "127.0.0.1"
		c.Listeners.Flow.FlowPort, c.Listeners.Flow.IPFIXPort = nf, ix
	}))
	ctx := context.Background()

	// Syslog: 150 "link down", 50 "link up" (TCP, so none is lost).
	for _, x := range []struct {
		n   int
		msg string
	}{{150, "probe link down"}, {50, "probe link up"}} {
		if _, err := loadgen.Send(ctx, loadgen.SendOptions{Addr: fmt.Sprintf("127.0.0.1:%d", syslogPort), Proto: "tcp", Count: x.n,
			Rate: 5000, Message: x.msg}); err != nil {
			t.Fatal(err)
		}
	}
	// Traps: 60 v2c and 40 v1.
	for _, x := range []struct {
		n   int
		ver string
	}{{60, "2c"}, {40, "1"}} {
		if _, err := loadgen.Send(ctx, loadgen.SendOptions{Addr: fmt.Sprintf("127.0.0.1:%d", snmpPort), Proto: "trap", Count: x.n,
			Rate: 2000, Trap: loadgen.TrapOptions{Version: x.ver, Community: []byte("public")}}); err != nil {
			t.Fatal(err)
		}
	}
	// Flows: 600 IPFIX event records; the denied ones from the generator's log.
	denied := int64(0)
	if _, err := loadgen.SendFlows(ctx, loadgen.FlowOptions{Proto: loadgen.ProtoIPFIX, Addr: fmt.Sprintf("127.0.0.1:%d", ix), Count: 600,
		Rate: 20000, Events: true}, func(es []loadgen.Expected) {
		for _, e := range es {
			if e.Record.Is(flow.HasFwEvent) && e.Record.FwEvent == flow.FwDenied {
				denied++
			}
		}
	}); err != nil {
		t.Fatal(err)
	}
	if denied == 0 {
		t.Fatal("the generator sent no denied records")
	}

	matched := func(q string) int64 {
		t.Helper()
		var p api.SummaryPage
		cursor := ""
		for range 100 {
			u := q + "&budget_ms=10000"
			if cursor != "" {
				u += "&cursor=" + url.QueryEscape(cursor)
			}
			if code := r.do(t, "GET", u, nil, &p); code != 200 {
				t.Fatalf("%s: %d", q, code)
			}
			if cursor = p.NextCursor; !p.Partial || cursor == "" {
				return p.Matched
			}
		}
		t.Fatalf("%s: no end", q)
		return 0
	}
	types := []struct {
		typ, field, filter string
		all, filtered      int64
	}{
		{"flow", "proto", "fw_event=denied", 600, denied},
		{"syslog", "severity", "q=" + url.QueryEscape("link up"), 200, 50},
		{"trap", "pdu", "snmp_versions=1", 100, 40},
	}
	// Everything stored and indexed first (the unfiltered scan count).
	for _, ty := range types {
		waitFor(t, ty.typ+" stored", func() bool {
			r.srv.store.Flush()
			return matched("/api/search/summary?type="+ty.typ+"&fields="+ty.field+"&histogram=false") == ty.all
		})
	}
	for _, ty := range types {
		for _, fields := range []string{"none", ty.field} {
			for _, hist := range []string{"true", "false"} {
				for _, filtered := range []bool{false, true} {
					q := "/api/search/summary?type=" + ty.typ + "&fields=" + fields + "&histogram=" + hist
					want := ty.all
					if filtered {
						q += "&" + ty.filter
						want = ty.filtered
					}
					if got := matched(q); got != want {
						t.Errorf("%s: matched %d, want %d", q, got, want)
					}
				}
			}
		}
	}
}
