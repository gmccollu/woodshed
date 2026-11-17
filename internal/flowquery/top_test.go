package flowquery

import (
	"net/netip"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

func TestTopBySrcBytesAndScaled(t *testing.T) {
	top, err := NewTop("src", "bytes")
	if err != nil {
		t.Fatal(err)
	}
	add := func(src string, bytes uint64, sampling uint32) {
		r := rec()
		r.Src, r.Bytes, r.Sampling = netip.MustParseAddr(src), bytes, sampling
		top.Add(r)
	}
	add("10.0.0.1", 100, 1000)
	add("10.0.0.1", 50, 0)
	add("10.0.0.2", 120, 1)
	rows := top.Rows(10)
	if len(rows) != 2 || rows[0].Key != "10.0.0.1" || rows[0].Bytes != 150 || rows[0].BytesScaled != 100000 ||
		rows[0].Unknown != 1 || rows[1].Bytes != 120 || rows[1].BytesScaled != 120 || rows[1].Unknown != 0 {
		t.Fatalf("rows %+v", rows)
	}
	if top.Total.Bytes != 270 || top.Total.Flows != 3 || top.Approx() {
		t.Fatalf("total %+v", top.Total)
	}
}

// Event records: created and denied add nothing to sums; deleted's totals
// do (SPEC §13.2.1); connections count deleted and denied.
func TestTopNoDoubleCount(t *testing.T) {
	top, _ := NewTop("fw_event", "bytes")
	mk := func(ev uint8, bytes uint64) *flow.Record {
		return &flow.Record{Has: flow.HasFwEvent | flow.HasInitiatorBytes | flow.HasResponderBytes | flow.HasSrc | flow.HasDst,
			FwEvent: ev, InitiatorBytes: bytes, ResponderBytes: bytes * 2, Sampling: 1,
			Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2")}
	}
	for _, r := range []*flow.Record{mk(flow.FwCreated, 10), mk(flow.FwUpdate, 50), mk(flow.FwDeleted, 100), mk(flow.FwDenied, 0)} {
		top.Add(r)
	}
	if top.Total.Bytes != 100 || top.Total.Flows != 4 || top.Total.Connections != 2 {
		t.Fatalf("total %+v", top.Total)
	}
	conv, _ := NewTop("conversation", "bytes")
	for _, r := range []*flow.Record{mk(flow.FwCreated, 10), mk(flow.FwDeleted, 100)} {
		conv.Add(r)
	}
	if rows := conv.Rows(1); rows[0].Bytes != 300 || rows[0].Key != "10.0.0.1 ↔ 10.0.0.2" {
		t.Fatalf("conversation %+v", rows)
	}
	// A delta exporter: every record adds.
	d, _ := NewTop("src", "bytes")
	r := rec()
	r.Has |= flow.HasFwEvent
	r.FwEvent = flow.FwCreated
	d.Add(r)
	if d.Total.Bytes != 1000 {
		t.Fatalf("delta counters add on any record: %+v", d.Total)
	}
}

// Past the exact limit, the rest go to the space-saving table, the heavy
// hitter still ranks first, and the response is approximate.
func TestTopApprox(t *testing.T) {
	top, _ := NewTopWith("src", "flows", TopOptions{MaxKeys: 100})
	heavy := netip.MustParseAddr("192.0.2.200")
	for i := 0; i < 50000; i++ {
		r := rec()
		r.Src = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		top.Add(r)
		if i%5 == 0 {
			r.Src = heavy
			top.Add(r)
		}
	}
	rows := top.Rows(3)
	if !top.Approx() || rows[0].Key != heavy.String() || rows[0].Flows < 10000 {
		t.Fatalf("approx %v rows %+v", top.Approx(), rows)
	}
	if top.Total.Flows != 60000 {
		t.Fatalf("total %d", top.Total.Flows)
	}
}

func TestTopKeys(t *testing.T) {
	a, _ := NewTop("dst_port", "packets")
	r := rec()
	a.Add(r)
	a.Add(r)
	r2 := rec()
	r2.Proto, r2.DstPort = 17, 53
	a.Add(r2)
	rows := a.Rows(10)
	if len(rows) != 2 || rows[0].Key != "tcp/443" || rows[0].Packets != 20 || rows[1].Key != "udp/53" {
		t.Fatalf("rows %+v", rows)
	}
	if _, err := NewTop("nope", "bytes"); err == nil {
		t.Fatal("bad by")
	}
	if _, err := NewTop("src", "nope"); err == nil {
		t.Fatal("bad metric")
	}
	inIf, _ := NewTop("in_if", "flows")
	inIf.Add(rec())
	if rows := inIf.Rows(1); rows[0].Key != "3" || rows[0].Label != "eth3" {
		t.Fatalf("in_if %+v", rows)
	}
}

// A key with none of the metric is never a row (a denied-only source in a
// top by bytes): it's counted as left out, and the totals still hold its
// records (lab, 2.0.0-rc1).
func TestTopLeavesOutZeroMetric(t *testing.T) {
	top, _ := NewTop("src", "bytes")
	add := func(src string, bytes uint64, ev uint8) {
		r := rec()
		r.Src, r.Bytes = netip.MustParseAddr(src), bytes
		if ev != 0 {
			r.Has |= flow.HasFwEvent
			r.FwEvent = ev
		}
		top.Add(r)
	}
	add("10.0.0.1", 100, 0)
	add("10.0.0.2", 0, 0)
	add("203.0.113.5", 0, flow.FwDenied) // a denied event carries no bytes
	add("10.0.0.3", 40, 0)
	rows, zero := top.RowsZero(10)
	if len(rows) != 2 || rows[0].Key != "10.0.0.1" || rows[1].Key != "10.0.0.3" || zero != 2 {
		t.Fatalf("rows %+v zero %d", rows, zero)
	}
	if top.Total.Flows != 4 || top.Total.Bytes != 140 {
		t.Fatalf("total %+v", top.Total)
	}
	// Fewer rows asked for: the count is still every zero key.
	if rows, zero := top.RowsZero(1); len(rows) != 1 || zero != 2 {
		t.Fatalf("top 1: %+v %d", rows, zero)
	}
	// Ranked by flows, every key has some: nothing left out.
	byFlows, _ := NewTop("src", "flows")
	for _, s := range []string{"10.0.0.1", "203.0.113.5"} {
		r := rec()
		r.Src, r.Bytes = netip.MustParseAddr(s), 0
		byFlows.Add(r)
	}
	if rows, zero := byFlows.RowsZero(10); len(rows) != 2 || zero != 0 {
		t.Fatalf("by flows: %+v %d", rows, zero)
	}
	// Only zero keys: no rows at all.
	none, _ := NewTop("fw_event", "bytes")
	r := rec()
	r.Has |= flow.HasFwEvent
	r.FwEvent, r.Bytes = flow.FwDenied, 0
	none.Add(r)
	if rows, zero := none.RowsZero(10); rows != nil || zero != 1 {
		t.Fatalf("only zero: %+v %d", rows, zero)
	}
	if got := ZeroOmittedText(1234, "bytes"); got != "1,234 with 0 bytes not shown" {
		t.Fatalf("text %q", got)
	}
	if ZeroOmittedText(0, "bytes") != "" || ZeroOmittedText(2, "flows") != "2 with 0 flow records not shown" {
		t.Fatal("text")
	}
}
