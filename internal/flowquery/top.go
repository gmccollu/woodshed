package flowquery

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Top-N keys and metrics (docs/api.md, GET /api/flows/top).
var (
	ByKeys  = []string{"src", "dst", "conversation", "dst_port", "src_port", "proto", "in_if", "out_if", "post_nat_src", "post_nat_dst", "fw_event", "rule_id"}
	Metrics = []string{"bytes", "packets", "flows", "connections"}
)

// DefaultExactKeys is how many distinct keys a top-N counts exactly (in all
// its workers) before it turns approximate (SPEC §13.3, agg.go).
const DefaultExactKeys = 1_000_000

// FlowStart and FlowEnd are a record's flow-time range (the received time for
// a record that has none, which the decoder never stores, but a raw-decoded
// record may lack).
func FlowStart(r *flow.Record) int64 {
	if r.Is(flow.HasStart) {
		return r.Start
	}
	if r.Is(flow.HasEnd) {
		return r.End
	}
	return r.Received
}

// FlowEnd: see FlowStart.
func FlowEnd(r *flow.Record) int64 {
	if r.Is(flow.HasEnd) {
		return r.End
	}
	return FlowStart(r)
}

// Overlaps reports whether a record's [start, end] overlaps [from, to)
// (unix ms; to 0 is open).
func Overlaps(r *flow.Record, from, to int64) bool {
	return FlowEnd(r) >= from && (to == 0 || FlowStart(r) < to)
}

// key is one top-N key.
type key struct {
	a, b netip.Addr
	n    uint64
	s    string
	ok   bool // the record has the key's column
}

// keyOf returns a record's key for by.
func keyOf(by string, r *flow.Record) key {
	switch by {
	case "src":
		return key{a: r.Src, ok: r.Is(flow.HasSrc)}
	case "dst":
		return key{a: r.Dst, ok: r.Is(flow.HasDst)}
	case "conversation":
		a, b := r.Src, r.Dst
		if b.Less(a) {
			a, b = b, a
		}
		return key{a: a, b: b, ok: r.Is(flow.HasSrc) && r.Is(flow.HasDst)}
	case "dst_port":
		return key{n: uint64(r.Proto)<<16 | uint64(r.DstPort), ok: r.Is(flow.HasDstPort)}
	case "src_port":
		return key{n: uint64(r.Proto)<<16 | uint64(r.SrcPort), ok: r.Is(flow.HasSrcPort)}
	case "proto":
		return key{n: uint64(r.Proto), ok: r.Is(flow.HasProto)}
	case "in_if":
		return key{n: uint64(r.InIf), s: r.InIfName, ok: r.Is(flow.HasInIf)}
	case "out_if":
		return key{n: uint64(r.OutIf), s: r.OutIfName, ok: r.Is(flow.HasOutIf)}
	case "post_nat_src":
		return key{a: r.PostNATSrc, ok: r.Is(flow.HasPostNATSrc)}
	case "post_nat_dst":
		return key{a: r.PostNATDst, ok: r.Is(flow.HasPostNATDst)}
	case "fw_event":
		return key{n: uint64(r.FwEvent), ok: r.Is(flow.HasFwEvent)}
	case "rule_id":
		return key{s: r.RuleID, ok: r.Is(flow.HasRuleID)}
	}
	return key{}
}

// KeyCols are the columns a top-N by by reads, beyond the counters.
func KeyCols(by string) uint64 {
	switch by {
	case "src":
		return flow.HasSrc
	case "dst":
		return flow.HasDst
	case "conversation":
		return flow.HasSrc | flow.HasDst
	case "dst_port":
		return flow.HasDstPort | flow.HasProto
	case "src_port":
		return flow.HasSrcPort | flow.HasProto
	case "proto":
		return flow.HasProto
	case "in_if":
		return flow.HasInIf | flow.HasInIfName
	case "out_if":
		return flow.HasOutIf | flow.HasOutIfName
	case "post_nat_src":
		return flow.HasPostNATSrc
	case "post_nat_dst":
		return flow.HasPostNATDst
	case "fw_event":
		return flow.HasFwEvent
	case "rule_id":
		return flow.HasRuleID
	}
	return 0
}

// CounterCols are the columns the sums read (the no-double-count rule needs
// the event and the totals bit too).
const CounterCols = flow.HasBytes | flow.HasPackets | flow.HasInitiatorBytes | flow.HasInitiatorPackets |
	flow.HasResponderBytes | flow.HasResponderPackets | flow.HasRevBytes | flow.HasRevPackets | flow.HasFwEvent |
	flow.HasTotals | flow.HasStart | flow.HasEnd

// keyLabel is a key's display form: the key and its label.
func keyLabel(by string, k key) (string, string) {
	switch by {
	case "src", "dst", "post_nat_src", "post_nat_dst":
		s := k.a.String()
		return s, s
	case "conversation":
		s := k.a.String() + " ↔ " + k.b.String()
		return s, s
	case "dst_port", "src_port":
		s := flow.ProtoName(uint8(k.n>>16)) + "/" + strconv.FormatUint(k.n&0xffff, 10)
		return s, s
	case "proto":
		return strconv.FormatUint(k.n, 10), flow.ProtoName(uint8(k.n))
	case "in_if", "out_if":
		l := k.s
		if l == "" {
			l = strconv.FormatUint(k.n, 10)
		}
		return strconv.FormatUint(k.n, 10), l
	case "fw_event":
		return flow.FwEventName(uint8(k.n)), flow.FwEventName(uint8(k.n))
	case "rule_id":
		return k.s, k.s
	}
	return "", ""
}

// Sums are counts behind a row or a total.
type Sums struct {
	Flows, Connections         int64
	Bytes, Packets             int64
	BytesScaled, PacketsScaled int64
	// Unknown counts records with unknown sampling (scaled sums are then a
	// lower bound).
	Unknown     int64
	First, Last int64 // flow times, unix ms (0 when none)
}

// add counts one record. conv uses both directions' counters.
func (s *Sums) add(r *flow.Record, conv bool) {
	var b, p uint64
	if conv {
		b, p = r.ConvBytes(), r.ConvPackets()
	} else {
		b, p = r.SumBytes(), r.SumPackets()
	}
	s.Flows++
	if r.IsConnection() {
		s.Connections++
	}
	s.Bytes += int64(b)
	s.Packets += int64(p)
	// A record with unknown sampling adds nothing to the scaled sums, which
	// are then a lower bound (as the segments' and flow_minute's totals).
	if r.Sampling > 0 {
		s.BytesScaled += int64(b) * int64(r.Sampling)
		s.PacketsScaled += int64(p) * int64(r.Sampling)
	} else {
		s.Unknown++
	}
	st, en := FlowStart(r), FlowEnd(r)
	if s.First == 0 || st < s.First {
		s.First = st
	}
	if en > s.Last {
		s.Last = en
	}
}

// addMetric adds v to the counter metric ranks by.
func (s *Sums) addMetric(metric string, v int64) {
	switch metric {
	case "packets":
		s.Packets += v
	case "flows":
		s.Flows += v
	case "connections":
		s.Connections += v
	default:
		s.Bytes += v
	}
}

func (s *Sums) merge(o *Sums) {
	s.Flows += o.Flows
	s.Connections += o.Connections
	s.Bytes += o.Bytes
	s.Packets += o.Packets
	s.BytesScaled += o.BytesScaled
	s.PacketsScaled += o.PacketsScaled
	s.Unknown += o.Unknown
	if o.First != 0 && (s.First == 0 || o.First < s.First) {
		s.First = o.First
	}
	if o.Last > s.Last {
		s.Last = o.Last
	}
}

// Metric returns the sums' value for a metric.
func (s *Sums) Metric(m string) int64 {
	switch m {
	case "packets":
		return s.Packets
	case "flows":
		return s.Flows
	case "connections":
		return s.Connections
	}
	return s.Bytes
}

// Top aggregates records by one key (agg.go). Not safe for concurrent use;
// the engine's workers share one aggregation instead.
type Top struct {
	By, Metric string
	Total      Sums
	conv       bool
	agg        aggregator
	l          local
}

// DefaultPoolBytes is a standalone Top's pool when TopOptions names none.
const DefaultPoolBytes = 128 << 20

// TopOptions configure a standalone Top.
type TopOptions struct {
	MaxKeys int   // exact keys at most (default DefaultExactKeys)
	Pool    *Pool // shared with other Tops (default: its own of DefaultPoolBytes)
	// Small keeps the approximate tables small (1,024 entries), for a few
	// rows (a bundle README's top 3s).
	Small bool
}

// NewTop starts a top-N by by, ranked by metric.
func NewTop(by, metric string) (*Top, error) { return NewTopWith(by, metric, TopOptions{}) }

// NewTopWith starts a top-N with options.
func NewTopWith(by, metric string, o TopOptions) (*Top, error) {
	if !contains(ByKeys, by) {
		return nil, fmt.Errorf("by: %q isn't one of %v", by, ByKeys)
	}
	if !contains(Metrics, metric) {
		return nil, fmt.Errorf("metric: %q isn't one of %v", metric, Metrics)
	}
	if o.MaxKeys <= 0 {
		o.MaxKeys = DefaultExactKeys
	}
	if o.Pool == nil {
		o.Pool = NewPool(DefaultPoolBytes)
	}
	size := querySize
	if o.Small {
		size = smallSize
	}
	a := newAggregator(by, metric, aggOptions{maxKeys: o.MaxKeys, pool: o.Pool, size: size})
	return &Top{By: by, Metric: metric, conv: by == "conversation", agg: a, l: a.newLocal()}, nil
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Add counts a record (already filtered and in the window).
func (t *Top) Add(r *flow.Record) {
	t.Total.add(r, t.conv)
	t.l.add(r)
}

// Approx reports whether some keys were counted approximately.
func (t *Top) Approx() bool {
	t.l.flush()
	return t.agg.approx()
}

// ErrorBound is the most a key that isn't in the approximate tables can
// have of the metric (0 while exact).
func (t *Top) ErrorBound() int64 {
	t.l.flush()
	return t.agg.errorBound()
}

// Keys is the number of distinct keys counted exactly.
func (t *Top) Keys() int {
	t.l.flush()
	return t.agg.keys()
}

// Free returns the Top's pool bytes; it's unusable after.
func (t *Top) Free() { t.agg.free() }

// Row is one top-N row.
type Row struct {
	Key, Label string
	Sums
	// Approx: the row comes from an approximate table. Its ranked metric is
	// an upper bound, at most Err over; its other counts cover the records
	// since the key entered the table (lower bounds).
	Approx bool
	Err    int64
}

// Rows returns the top n rows by the metric, ties by key.
func (t *Top) Rows(n int) []Row {
	t.l.flush()
	return t.agg.rows(n)
}
