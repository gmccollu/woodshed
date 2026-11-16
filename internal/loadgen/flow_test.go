package loadgen

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

var flowT0 = time.Date(2026, 11, 16, 9, 30, 0, 123e6, time.UTC)

// sameColumns compares what the generator expected with what the collector
// decoded: every column, the domain, sampling, rule_id and extras.
func sameColumns(got, want *flow.Record) bool {
	g, w := *got, *want
	for _, r := range []*flow.Record{&g, &w} {
		r.Received, r.Template, r.TemplateID, r.ExporterPort, r.Version, r.Status, r.TimeSource, r.Extras = 0, nil, 0, 0, 0, 0, 0, nil
	}
	return reflect.DeepEqual(g, w) && slices.EqualFunc(got.Extras, want.Extras, func(a, b flow.Extra) bool {
		return a.PEN == b.PEN && a.ID == b.ID && bytes.Equal(a.Value, b.Value)
	})
}

// decodeRun generates o's packets at a fixed clock and decodes them,
// checking every record against what the generator says it sent.
func decodeRun(t *testing.T, o FlowOptions, step time.Duration) (map[uint64]flow.Record, *flow.Collector) {
	t.Helper()
	g, err := NewFlowGen(o, flowT0)
	if err != nil {
		t.Fatal(err)
	}
	c := flow.NewCollector(flow.Options{RuleIDIEs: []flow.IEKey{RuleIE(o.Proto)}})
	from := netip.MustParseAddrPort("192.0.2.1:40000")
	want := map[uint64]flow.Record{}
	got := map[uint64]flow.Record{}
	now := flowT0
	for !g.Done() {
		pkt, exp := g.Next(now)
		for _, e := range exp {
			want[e.Seq] = e.Record
		}
		c.Decode(flow.Packet{Data: pkt, From: from, Received: now.Add(time.Millisecond)}, func(r *flow.Record) {
			run, seq, ok := FlowSeq(r)
			if !ok || !MatchRun(run, g.Options().RunID) {
				t.Fatalf("record without the run's sequence: %+v", r)
			}
			if _, dup := got[seq]; dup {
				t.Fatalf("seq %d twice", seq)
			}
			got[seq] = *r
		}, func(rs *flow.RawSet) { t.Fatalf("raw set %+v", rs) })
		now = now.Add(step)
	}
	if len(got) != len(want) || len(want) != g.Options().Count {
		t.Fatalf("decoded %d of %d (count %d)", len(got), len(want), g.Options().Count)
	}
	for seq, w := range want {
		r := got[seq]
		if !sameColumns(&r, &w) {
			t.Fatalf("seq %d:\n got %+v\nwant %+v", seq, r, w)
		}
	}
	return got, c
}

func TestFlowGenDecodes(t *testing.T) {
	for _, o := range []FlowOptions{
		{Proto: ProtoFlowV5, Count: 95, RunID: "0a0b0c0d"},
		{Proto: ProtoFlowV5, Count: 60, Sampling: 100, RecordsPerPacket: 7},
		{Proto: ProtoFlowV9, Count: 200, Domains: 3, Sampling: 100, SampledDomains: 1, EnterpriseIEs: 2},
		{Proto: ProtoIPFIX, Count: 300, Domains: 2, Sampling: 1000, TemplateEvery: 3},
		{Proto: ProtoIPFIX, Count: 100, Biflow: true},
		{Proto: ProtoFlowV9, Count: 300, Events: true},
		{Proto: ProtoIPFIX, Count: 400, Events: true, DenyRatio: 0.3, Domains: 2},
		{Proto: ProtoIPFIX, Count: 200, Events: true, Biflow: true},
	} {
		got, c := decodeRun(t, o, 37*time.Millisecond)
		var denied, sampled int
		for _, r := range got {
			if r.FwEvent == flow.FwDenied {
				denied++
			}
			if r.Sampling > 1 {
				sampled++
			}
		}
		if o.Events && denied == 0 {
			t.Errorf("%+v: no denied records", o)
		}
		if o.Sampling > 0 && sampled == 0 {
			t.Errorf("%+v: no sampled records", o)
		}
		for _, st := range c.Stats(flowT0) {
			if st.Counts.SequenceGaps != 0 || st.Counts.Duplicates != 0 || st.Counts.Malformed != 0 {
				t.Errorf("%+v: counts %+v", o, st.Counts)
			}
		}
	}
}

// TestFlowGenEventSums: a connection's created record carries no counts,
// its update part of the final totals, and only the deleted record adds to
// sums (with --biflow, the deltas add up to the same totals).
func TestFlowGenEventSums(t *testing.T) {
	for _, biflow := range []bool{false, true} {
		g, err := NewFlowGen(FlowOptions{Proto: ProtoIPFIX, Count: 2000, Events: true, Biflow: biflow}, flowT0)
		if err != nil {
			t.Fatal(err)
		}
		// A connection is its 5-tuple and start; a reused tuple after a
		// deleted record is a new connection.
		type key struct {
			src, dst     netip.Addr
			sport, dport uint16
			start        int64
		}
		added := map[key]uint64{}  // what the connection's records add to sums
		deltas := map[key]uint64{} // biflow: deltas so far
		deleted := 0
		now := flowT0
		for !g.Done() {
			_, exp := g.Next(now)
			for _, e := range exp {
				r := &e.Record
				if r.FwEvent == flow.FwDenied {
					if r.SumBytes() != 0 || r.Is(flow.HasBytes|flow.HasInitiatorBytes) {
						t.Fatalf("a denied record with counts: %+v", r)
					}
					continue
				}
				k := key{r.Src, r.Dst, r.SrcPort, r.DstPort, r.Start}
				added[k] += r.SumBytes()
				deltas[k] += r.Bytes
				switch r.FwEvent {
				case flow.FwCreated:
					if r.InitiatorBytes != 0 || r.Bytes != 0 {
						t.Fatalf("created with counts: %+v", r)
					}
				case flow.FwDeleted:
					deleted++
					want := r.InitiatorBytes
					if biflow {
						want = deltas[k]
					}
					if added[k] != want {
						t.Fatalf("biflow %v: connection %v adds %d, its totals are %d", biflow, k, added[k], want)
					}
					delete(added, k)
					delete(deltas, k)
				}
			}
			now = now.Add(time.Millisecond)
		}
		if deleted == 0 {
			t.Fatal("no connection closed")
		}
	}
}

func TestFlowTemplateFirstDelay(t *testing.T) {
	g, err := NewFlowGen(FlowOptions{Proto: ProtoIPFIX, Count: 90, TemplateFirstDelay: 2 * time.Second}, flowT0)
	if err != nil {
		t.Fatal(err)
	}
	c := flow.NewCollector(flow.Options{})
	from := netip.MustParseAddrPort("192.0.2.1:40000")
	var late, ok int
	now := flowT0
	for !g.Done() {
		pkt, _ := g.Next(now)
		c.Decode(flow.Packet{Data: pkt, From: from, Received: now}, func(r *flow.Record) {
			if r.Status == flow.StatusLate {
				late++
			} else {
				ok++
			}
		}, nil)
		now = now.Add(time.Second)
	}
	// Packets at 0 s and 1 s waited; the one at 2 s brought the templates.
	if late != 60 || ok != 30 {
		t.Errorf("late %d ok %d", late, ok)
	}
}

func TestFlowOptionsErrors(t *testing.T) {
	for _, o := range []FlowOptions{
		{Proto: "flow-v7"},
		{Proto: ProtoFlowV5, RecordsPerPacket: 31},
		{Proto: ProtoFlowV5, Events: true},
		{Proto: ProtoFlowV9, Biflow: true},
		{Proto: ProtoIPFIX, RunID: "xyz"},
		{Proto: ProtoIPFIX, DenyRatio: 2},
	} {
		if _, err := NewFlowGen(o, flowT0); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

// TestSendFlows sends over UDP to a socket of the test's own and decodes
// what arrives: every sequence number exactly once.
func TestSendFlows(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.SetReadBuffer(4 << 20)
	const n = 3000
	type pkt struct {
		b    []byte
		from netip.AddrPort
	}
	got := make(chan pkt, 1024)
	go func() {
		buf := make([]byte, 65536)
		for {
			k, from, err := ln.ReadFromUDPAddrPort(buf)
			if err != nil {
				close(got)
				return
			}
			got <- pkt{append([]byte(nil), buf[:k]...), from}
		}
	}()
	var sentRecs int
	res, err := SendFlows(context.Background(), FlowOptions{Proto: ProtoIPFIX, Addr: ln.LocalAddr().String(), Count: n,
		Rate: 20000, Domains: 2}, func(e []Expected) { sentRecs += len(e) })
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != n || sentRecs != n {
		t.Fatalf("sent %d (logged %d)", res.Records, sentRecs)
	}
	c := flow.NewCollector(flow.Options{})
	seen := map[uint64]bool{}
	for len(seen) < n {
		select {
		case p := <-got:
			c.Decode(flow.Packet{Data: p.b, From: p.from, Received: time.Now()}, func(r *flow.Record) {
				run, seq, ok := FlowSeq(r)
				if !ok || run != res.RunID || seen[seq] {
					t.Fatalf("run %q seq %d ok %v (dup %v)", run, seq, ok, seen[seq])
				}
				seen[seq] = true
			}, func(rs *flow.RawSet) { t.Fatalf("raw %+v", rs) })
		case <-time.After(10 * time.Second):
			// Loopback UDP can drop under load; the sequence gaps say so.
			var gaps int64
			for _, st := range c.Stats(time.Now()) {
				gaps += st.Counts.LostEstimate
			}
			t.Fatalf("got %d of %d records; the collector counted %d lost", len(seen), n, gaps)
		}
	}
	for i := range uint64(n) {
		if !seen[i] {
			t.Fatalf("seq %d missing", i)
		}
	}
}
