package flowquery

import (
	"container/heap"
	"fmt"
	"net/netip"
	"sort"
	"strconv"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Top-N keys and metrics (docs/api.md, GET /api/flows/top).
var (
	ByKeys  = []string{"src", "dst", "conversation", "dst_port", "src_port", "proto", "in_if", "out_if", "post_nat_src", "post_nat_dst", "fw_event", "rule_id"}
	Metrics = []string{"bytes", "packets", "flows", "connections"}
)

// DefaultExactKeys is how many distinct keys a top-N counts exactly before it
// switches to a space-saving top-K for the rest (SPEC §13.3).
const DefaultExactKeys = 1_000_000

// spaceSavingSize is the space-saving table's size past the exact limit.
const spaceSavingSize = 10_000

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
	if r.Sampling > 0 {
		s.BytesScaled += int64(b) * int64(r.Sampling)
		s.PacketsScaled += int64(p) * int64(r.Sampling)
	} else {
		s.Unknown++
		s.BytesScaled += int64(b)
		s.PacketsScaled += int64(p)
	}
	st, en := FlowStart(r), FlowEnd(r)
	if s.First == 0 || st < s.First {
		s.First = st
	}
	if en > s.Last {
		s.Last = en
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

// Top aggregates records by one key. Not safe for concurrent use: merge
// per-goroutine Tops with Merge.
type Top struct {
	By, Metric string
	MaxExact   int
	Total      Sums
	exact      map[key]*Sums
	ss         *spaceSaving
}

// NewTop starts a top-N by by, ranked by metric.
func NewTop(by, metric string) (*Top, error) {
	if !contains(ByKeys, by) {
		return nil, fmt.Errorf("by: %q isn't one of %v", by, ByKeys)
	}
	if !contains(Metrics, metric) {
		return nil, fmt.Errorf("metric: %q isn't one of %v", metric, Metrics)
	}
	return &Top{By: by, Metric: metric, MaxExact: DefaultExactKeys, exact: map[key]*Sums{}}, nil
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
	conv := t.By == "conversation"
	t.Total.add(r, conv)
	k := keyOf(t.By, r)
	if !k.ok {
		return
	}
	if s := t.exact[k]; s != nil {
		s.add(r, conv)
		return
	}
	if len(t.exact) < t.MaxExact {
		s := &Sums{}
		s.add(r, conv)
		t.exact[k] = s
		return
	}
	if t.ss == nil {
		t.ss = newSpaceSaving(spaceSavingSize, t.Metric)
	}
	var s Sums
	s.add(r, conv)
	t.ss.add(k, &s)
}

// Merge adds o's counts into t (same by and metric).
func (t *Top) Merge(o *Top) {
	t.Total.merge(&o.Total)
	for k, s := range o.exact {
		if x := t.exact[k]; x != nil {
			x.merge(s)
			continue
		}
		if len(t.exact) < t.MaxExact {
			c := *s
			t.exact[k] = &c
			continue
		}
		if t.ss == nil {
			t.ss = newSpaceSaving(spaceSavingSize, t.Metric)
		}
		t.ss.add(k, s)
	}
	if o.ss != nil {
		if t.ss == nil {
			t.ss = newSpaceSaving(spaceSavingSize, t.Metric)
		}
		for _, e := range o.ss.items {
			t.ss.add(e.k, &e.s)
		}
	}
}

// Approx reports whether the key count passed the exact limit.
func (t *Top) Approx() bool { return t.ss != nil }

// Keys is the number of distinct keys counted exactly.
func (t *Top) Keys() int { return len(t.exact) }

// Row is one top-N row.
type Row struct {
	Key, Label string
	Sums
}

// Rows returns the top n rows by the metric, ties by key.
func (t *Top) Rows(n int) []Row {
	rows := make([]Row, 0, len(t.exact))
	for k, s := range t.exact {
		kk, l := keyLabel(t.By, k)
		rows = append(rows, Row{Key: kk, Label: l, Sums: *s})
	}
	if t.ss != nil {
		for _, e := range t.ss.items {
			kk, l := keyLabel(t.By, e.k)
			rows = append(rows, Row{Key: kk, Label: l, Sums: e.s})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].Metric(t.Metric), rows[j].Metric(t.Metric)
		if a != b {
			return a > b
		}
		return rows[i].Key < rows[j].Key
	})
	if len(rows) > n {
		rows = rows[:n]
	}
	return rows
}

// spaceSaving is a space-saving top-K (Metwally et al.): a full table
// replaces its smallest entry, which the newcomer inherits as its count.
type spaceSaving struct {
	metric string
	max    int
	items  []*ssItem
	pos    map[key]*ssItem
}

type ssItem struct {
	k   key
	s   Sums
	idx int
}

func newSpaceSaving(n int, metric string) *spaceSaving {
	return &spaceSaving{metric: metric, max: n, pos: map[key]*ssItem{}}
}

func (h *spaceSaving) Len() int { return len(h.items) }
func (h *spaceSaving) Less(i, j int) bool {
	return h.items[i].s.Metric(h.metric) < h.items[j].s.Metric(h.metric)
}
func (h *spaceSaving) Swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.items[i].idx, h.items[j].idx = i, j
}
func (h *spaceSaving) Push(x any) {
	it := x.(*ssItem)
	it.idx = len(h.items)
	h.items = append(h.items, it)
}
func (h *spaceSaving) Pop() any {
	it := h.items[len(h.items)-1]
	h.items = h.items[:len(h.items)-1]
	return it
}

func (h *spaceSaving) add(k key, s *Sums) {
	if it := h.pos[k]; it != nil {
		it.s.merge(s)
		heap.Fix(h, it.idx)
		return
	}
	if len(h.items) < h.max {
		it := &ssItem{k: k, s: *s}
		heap.Push(h, it)
		h.pos[k] = it
		return
	}
	min := h.items[0]
	delete(h.pos, min.k)
	inherited := min.s
	min.k = k
	min.s = *s
	// The newcomer inherits the evicted count as its possible overestimate.
	min.s.Flows += inherited.Flows
	min.s.Connections += inherited.Connections
	min.s.Bytes += inherited.Bytes
	min.s.Packets += inherited.Packets
	min.s.BytesScaled += inherited.BytesScaled
	min.s.PacketsScaled += inherited.PacketsScaled
	min.s.Unknown += inherited.Unknown
	h.pos[k] = min
	heap.Fix(h, 0)
}
