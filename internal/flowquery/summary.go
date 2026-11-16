package flowquery

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
)

// The flow summary (SPEC §13.3, docs/api.md "Summary"): the field panel's
// values, counting flows with their bytes beside them, and the scan
// histogram (flows, bytes or packets per bucket) for a filtered window.

// FieldKeys are the flow field panel's keys, in order (the schema's, after
// device).
var FieldKeys = []string{"proto", "dst_port", "src_port", "src", "dst", "in_if", "out_if", "fw_event", "nat_event", "rule_id",
	"domain", "sampled", "status"}

// MaxDistinct is how many values a field tracks before new ones count as other.
const MaxDistinct = 10000

// fieldValue is a record's value of a field: the filter value, its label,
// and whether the record has it.
func fieldValue(key string, r *flow.Record) (string, string, bool) {
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	switch key {
	case "proto":
		n := flow.ProtoName(r.Proto)
		return n, n, r.Is(flow.HasProto)
	case "dst_port":
		return u(uint64(r.DstPort)), flow.ProtoName(r.Proto) + "/" + u(uint64(r.DstPort)), r.Is(flow.HasDstPort)
	case "src_port":
		return u(uint64(r.SrcPort)), flow.ProtoName(r.Proto) + "/" + u(uint64(r.SrcPort)), r.Is(flow.HasSrcPort)
	case "src":
		return r.Src.String(), r.Src.String(), r.Is(flow.HasSrc)
	case "dst":
		return r.Dst.String(), r.Dst.String(), r.Is(flow.HasDst)
	case "in_if":
		l := r.InIfName
		if l == "" {
			l = u(uint64(r.InIf))
		}
		return u(uint64(r.InIf)), l, r.Is(flow.HasInIf)
	case "out_if":
		l := r.OutIfName
		if l == "" {
			l = u(uint64(r.OutIf))
		}
		return u(uint64(r.OutIf)), l, r.Is(flow.HasOutIf)
	case "fw_event":
		n := flow.FwEventName(r.FwEvent)
		return n, n, r.Is(flow.HasFwEvent)
	case "nat_event":
		n := flow.NatEventName(r.NatEvent)
		return n, n, r.Is(flow.HasNatEvent)
	case "rule_id":
		return r.RuleID, r.RuleID, r.Is(flow.HasRuleID) && r.RuleID != ""
	case "domain":
		return u(uint64(r.Domain)), u(uint64(r.Domain)), true
	case "sampled":
		v := SampledValue(r.Sampling)
		return v, v, true
	case "status":
		v := r.Status.String()
		return v, v, true
	}
	return "", "", false
}

// fieldCols are the columns the panel's fields read.
func fieldCols(keys []string) flowseg.Cols {
	var c flowseg.Cols
	for _, k := range keys {
		switch k {
		case "proto":
			c |= flowseg.Cols(flow.HasProto)
		case "dst_port":
			c |= flowseg.Cols(flow.HasDstPort | flow.HasProto)
		case "src_port":
			c |= flowseg.Cols(flow.HasSrcPort | flow.HasProto)
		case "src":
			c |= flowseg.Cols(flow.HasSrc)
		case "dst":
			c |= flowseg.Cols(flow.HasDst)
		case "in_if":
			c |= flowseg.Cols(flow.HasInIf | flow.HasInIfName)
		case "out_if":
			c |= flowseg.Cols(flow.HasOutIf | flow.HasOutIfName)
		case "fw_event":
			c |= flowseg.Cols(flow.HasFwEvent)
		case "nat_event":
			c |= flowseg.Cols(flow.HasNatEvent)
		case "rule_id":
			c |= flowseg.Cols(flow.HasRuleID)
		case "domain":
			c |= flowseg.ColDomain
		case "sampled":
			c |= flowseg.ColSampling
		case "status":
			c |= flowseg.ColStatus
		}
	}
	return c
}

// ValueCount is one field value's counts.
type ValueCount struct {
	Value, Label       string
	Count              int64 // flows
	Bytes, BytesScaled int64
}

// FieldCount is one field's counts.
type FieldCount struct {
	Key            string
	Values         []ValueCount
	Other, None    int64
	Distinct       int
	DistinctCapped bool
}

// Bucket is a scan histogram bucket.
type Bucket struct {
	Flows, Bytes, Packets, BytesScaled int64
}

type valAcc struct {
	label              string
	count, bytes, scal int64
}

type fieldAcc struct {
	vals        map[string]*valAcc
	other, none int64
	capped      bool
}

// summaryAcc is a summary's running counts.
type summaryAcc struct {
	fields  []string
	accs    []*fieldAcc
	hist    bool
	bucket  int64
	origin  int64
	buckets map[int64]*Bucket
	matched int64
}

func newSummaryAcc(fields []string, hist bool, bucket, origin int64) *summaryAcc {
	a := &summaryAcc{fields: fields, hist: hist, bucket: bucket, origin: origin, buckets: map[int64]*Bucket{}}
	for range fields {
		a.accs = append(a.accs, &fieldAcc{vals: map[string]*valAcc{}})
	}
	return a
}

func (a *summaryAcc) bucketOf(t int64) int64 {
	return a.origin + floorDiv(t-a.origin, a.bucket)*a.bucket
}

func floorDiv(x, y int64) int64 {
	q := x / y
	if x%y != 0 && (x < 0) != (y < 0) {
		q--
	}
	return q
}

func (a *summaryAcc) add(r *flow.Record) {
	a.matched++
	b, sb := int64(r.SumBytes()), int64(0)
	if r.Sampling > 0 {
		sb = b * int64(r.Sampling)
	}
	for i, k := range a.fields {
		fa := a.accs[i]
		v, l, ok := fieldValue(k, r)
		if !ok {
			fa.none++
			continue
		}
		va := fa.vals[v]
		if va == nil {
			if len(fa.vals) >= MaxDistinct {
				fa.other++
				fa.capped = true
				continue
			}
			va = &valAcc{label: l}
			fa.vals[v] = va
		}
		va.count++
		va.bytes += b
		va.scal += sb
	}
	if !a.hist {
		return
	}
	// The flow_minute rule (flowseg): a record counts once, in its end's
	// bucket; its bytes and packets spread evenly over the minutes it covers.
	start, end := flowseg.EffectiveTimes(r)
	em, sm := floorDiv(end, 60000)*60000, floorDiv(start, 60000)*60000
	if em-sm >= flowseg.MaxSpreadMinutes*60000 {
		sm = em - (flowseg.MaxSpreadMinutes-1)*60000
	}
	n := (em-sm)/60000 + 1
	last := a.at(a.bucketOf(end))
	last.Flows++
	p := int64(r.SumPackets())
	if b == 0 && p == 0 {
		return
	}
	for m := sm; m <= em; m += 60000 {
		share := func(v int64) int64 {
			q := v / n
			if m == em {
				q += v % n
			}
			return q
		}
		bk := a.at(a.bucketOf(m))
		bk.Bytes += share(b)
		bk.Packets += share(p)
		bk.BytesScaled += share(sb)
	}
}

func (a *summaryAcc) at(k int64) *Bucket {
	b := a.buckets[k]
	if b == nil {
		b = &Bucket{}
		a.buckets[k] = b
	}
	return b
}

func (a *summaryAcc) merge(o *summaryAcc) {
	a.matched += o.matched
	for i, fa := range o.accs {
		x := a.accs[i]
		x.none += fa.none
		x.other += fa.other
		x.capped = x.capped || fa.capped
		for v, va := range fa.vals {
			y := x.vals[v]
			if y == nil {
				if len(x.vals) >= MaxDistinct {
					x.other += va.count
					x.capped = true
					continue
				}
				y = &valAcc{label: va.label}
				x.vals[v] = y
			}
			y.count += va.count
			y.bytes += va.bytes
			y.scal += va.scal
		}
	}
	for k, b := range o.buckets {
		x := a.at(k)
		x.Flows += b.Flows
		x.Bytes += b.Bytes
		x.Packets += b.Packets
		x.BytesScaled += b.BytesScaled
	}
}

func (a *summaryAcc) result(top int) []FieldCount {
	out := make([]FieldCount, len(a.fields))
	for i, k := range a.fields {
		fa := a.accs[i]
		fc := FieldCount{Key: k, None: fa.none, Other: fa.other, Distinct: len(fa.vals), DistinctCapped: fa.capped}
		for v, va := range fa.vals {
			fc.Values = append(fc.Values, ValueCount{Value: v, Label: va.label, Count: va.count, Bytes: va.bytes, BytesScaled: va.scal})
		}
		sort.Slice(fc.Values, func(x, y int) bool {
			if fc.Values[x].Count != fc.Values[y].Count {
				return fc.Values[x].Count > fc.Values[y].Count
			}
			return fc.Values[x].Value < fc.Values[y].Value
		})
		closed := k == "fw_event" || k == "nat_event" || k == "sampled" || k == "status"
		if !closed && len(fc.Values) > top {
			for _, v := range fc.Values[top:] {
				fc.Other += v.Count
			}
			fc.Values = fc.Values[:top]
		}
		out[i] = fc
	}
	return out
}

// SummaryQuery is a summary's parameters beyond the window.
type SummaryQuery struct {
	Fields    []string // the panel's keys (nil: none)
	Top       int
	Histogram bool
	Bucket    time.Duration
	Origin    time.Time // buckets start at Origin + k × Bucket
}

// SummaryResult is a summary's answer (running totals).
type SummaryResult struct {
	Fields   []FieldCount
	Buckets  map[int64]Bucket // by bucket start (unix ms); scanned buckets only
	Matched  int64
	Progress Progress
	Partial  bool
	Cursor   string
}

// Summary counts the field panel and the scan histogram for the window.
func (e *Engine) Summary(ctx context.Context, q Query, sq SummaryQuery, budget time.Duration, cursor string) (SummaryResult, error) {
	key := q.key("summary", sq.Fields, sq.Histogram, sq.Bucket, sq.Origin.UnixMilli())
	bucket := max(sq.Bucket.Milliseconds(), 1)
	var st *state
	if cursor != "" {
		var err error
		if st, err = e.takeState(cursor, key); err != nil {
			return SummaryResult{}, err
		}
	} else {
		p, err := e.planFor(ctx, &q, false)
		if err != nil {
			return SummaryResult{}, err
		}
		st = e.newState(key, p)
		st.sum = newSummaryAcc(sq.Fields, sq.Histogram, bucket, sq.Origin.UnixMilli())
	}
	f := q.filter()
	extra := fieldCols(sq.Fields) | flowseg.Cols(CounterCols) | flowseg.ColSampling
	cols := colsFor(f, extra)
	// Per-worker counts for the whole request, merged once at its end.
	accs := make([]*summaryAcc, e.o.Workers)
	for i := range accs {
		accs[i] = newSummaryAcc(sq.Fields, sq.Histogram, bucket, sq.Origin.UnixMilli())
	}
	deadline := time.Now().Add(budget)
	rd := &readers{p: st.plan}
	defer rd.close()
	for first := true; st.done < len(st.plan.blocks) && (first || time.Now().Before(deadline)); first = false {
		hi := min(st.done+e.wave(), len(st.plan.blocks))
		if err := e.scan(ctx, st.plan, rd, st.done, hi, f, cols, func(w int, _ *planned, _ int, r *flow.Record) { accs[w].add(r) }); err != nil {
			return SummaryResult{}, err
		}
		for _, b := range st.plan.blocks[st.done:hi] {
			st.recsDone += int64(b.rows)
		}
		st.done = hi
	}
	for _, a := range accs {
		st.sum.merge(a)
	}
	res := SummaryResult{Fields: st.sum.result(max(sq.Top, 1)), Matched: st.sum.matched, Buckets: map[int64]Bucket{},
		Progress: Progress{BlocksDone: int64(st.done), BlocksTotal: int64(len(st.plan.blocks)), RecordsDone: st.recsDone,
			RecordsTotal: st.plan.rows, CompleteFrom: st.plan.frontier(st.done)}}
	for k, b := range st.sum.buckets {
		res.Buckets[k] = *b
	}
	if st.done < len(st.plan.blocks) {
		res.Partial = true
		e.saveState(st)
		res.Cursor = st.id
	}
	return res, nil
}
