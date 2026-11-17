package server

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/export"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// isFlowRef reports whether a /api/context ref is a flow result's.
func isFlowRef(ref string) bool {
	b, err := base64.RawURLEncoding.DecodeString(ref)
	return err == nil && strings.Contains(string(b), "/"+logfile.FlowDir+"/") && strings.HasSuffix(strings.SplitN(string(b), "|", 2)[0], ".wsf")
}

// closeFlows stops the collector's expiry loop.
func (b *backend) closeFlows() {
	if b.flows != nil {
		b.flows.close()
	}
}

// noteFirstMessage records the first message's time (flows count too).
func (b *backend) noteFirstMessage(at time.Time) {
	if b.firstMsg.Load() == 0 {
		b.firstMsg.CompareAndSwap(0, at.UnixMilli())
	}
}

// The flow collector (SPEC §13): the listener's drainer hands each datagram
// to the collector (templates, options data, the pending buffer), whose
// records and raw sets go to the store's segment writer for the exporter;
// the query engine reads the segments for the API.

// flowSide is the collector and its rates.
type flowSide struct {
	mu   sync.Mutex // serializes Decode and Expire (one goroutine at a time)
	coll *flow.Collector
	eng  *flowquery.Engine

	lastExpire time.Time
	rates      flowRates
	fwCheck    func(nf, ix int) []fwrule.FlowRuleState
	fwMu       sync.Mutex
	fwAt       time.Time
	fwRules    []fwrule.FlowRuleState // the rules that aren't ok, as of fwAt

	stop chan struct{}
	done chan struct{}

	metaMu sync.Mutex
	metaV  map[netip.Addr]uint64 // the metadata version last given to the store, per exporter
}

// metaVersion records v as an exporter's metadata version and reports whether
// it's new.
func (fs *flowSide) metaVersion(addr netip.Addr, v uint64) bool {
	fs.metaMu.Lock()
	defer fs.metaMu.Unlock()
	if fs.metaV == nil {
		fs.metaV = map[netip.Addr]uint64{}
	}
	if fs.metaV[addr] == v {
		return false
	}
	fs.metaV[addr] = v
	return true
}

// flowRates counts records per exporter per second over the last minute.
type flowRates struct {
	mu  sync.Mutex
	per map[string]*[60]struct{ sec, n int64 }
}

func (r *flowRates) add(id string, at time.Time, n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.per == nil {
		r.per = map[string]*[60]struct{ sec, n int64 }{}
	}
	ring := r.per[id]
	if ring == nil {
		ring = &[60]struct{ sec, n int64 }{}
		r.per[id] = ring
	}
	s := at.Unix()
	b := &ring[s%60]
	if b.sec != s {
		b.sec, b.n = s, 0
	}
	b.n += n
}

// perSec is the exporter's records a second over the last 60 s.
func (r *flowRates) perSec(id string, now time.Time) float64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	ring := r.per[id]
	if ring == nil {
		return 0
	}
	var n int64
	s := now.Unix()
	for _, b := range ring {
		if b.sec > s-60 && b.sec <= s {
			n += b.n
		}
	}
	return float64(n) / 60
}

func ruleIEs(l config.FlowListener) []flow.IEKey {
	var out []flow.IEKey
	for _, s := range l.RuleIDIEs {
		if pen, id, ok := config.ParseRuleIDIE(s); ok {
			out = append(out, flow.IEKey{PEN: pen, ID: id})
		}
	}
	return out
}

// openFlows sets up the collector and the query engine (whether or not the
// listener is on: segments on disk are searchable either way).
func (b *backend) openFlows(cfg config.Config) {
	l := cfg.Listeners.Flow
	fs := &flowSide{
		coll: flow.NewCollector(flow.Options{TemplateTimeout: time.Duration(l.TemplateTimeout), PendingBytes: int(l.PendingBytes),
			RuleIDIEs: ruleIEs(l), Clock: b.now}),
		stop: make(chan struct{}), done: make(chan struct{}),
	}
	fs.eng = flowquery.New(flowquery.Options{DataDir: cfg.Storage.DataDir, Index: b.idx, Logger: b.log, RuleIDIEs: ruleIEs(l),
		Open: func(ids []string) []flowquery.OpenSegment {
			snaps := b.store.OpenFlowList(ids)
			out := make([]flowquery.OpenSegment, len(snaps))
			for i, s := range snaps {
				out[i] = flowquery.OpenSegment{DeviceID: s.DeviceID, Rel: s.Rel, Path: s.Path, Snap: s.Snap}
			}
			return out
		}})
	fs.fwCheck = func(nf, ix int) []fwrule.FlowRuleState { return fwrule.FlowWindowsStates(fwrule.Exec, nf, ix) }
	b.flows = fs
	go fs.expireLoop(b)
}

// expireLoop moves data that waited too long for its template to the raw
// sections even when no datagrams arrive.
func (fs *flowSide) expireLoop(b *backend) {
	defer close(fs.done)
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-fs.stop:
			return
		case <-t.C:
			fs.mu.Lock()
			fs.expireLocked(b, b.now(), true)
			fs.mu.Unlock()
		}
	}
}

func (fs *flowSide) close() {
	select {
	case <-fs.stop:
	default:
		close(fs.stop)
	}
	<-fs.done
}

// expireLocked runs the collector's Expire at most once a second (fs.mu held).
func (fs *flowSide) expireLocked(b *backend, now time.Time, force bool) {
	if !force && now.Sub(fs.lastExpire) < time.Second {
		return
	}
	fs.lastExpire = now
	byExp := map[netip.Addr][]*flow.RawSet{}
	fs.coll.Expire(now, func(rs *flow.RawSet) { byExp[rs.Exporter] = append(byExp[rs.Exporter], rs) })
	for addr, raws := range byExp {
		if !addr.IsValid() {
			continue
		}
		if err := b.store.WriteFlows(addr, store.FlowBatch{Received: now, Raw: raws}); err != nil && !errors.Is(err, store.ErrPaused) {
			b.log.Debug("flows: storing expired pending data failed", "exporter", addr, "err", err)
		}
	}
}

// flowHandle is the listener's Flow handler: one datagram, in arrival order.
func (b *backend) flowHandle(p *listen.FlowPacket) {
	fs := b.flows
	addr := p.From.Addr().Unmap()
	var recs []*flow.Record
	var raws []*flow.RawSet
	fs.mu.Lock()
	fs.coll.Decode(flow.Packet{Data: p.Data, From: p.From, Received: p.Received}, func(r *flow.Record) {
		c := *r
		recs = append(recs, &c)
	}, func(rs *flow.RawSet) { raws = append(raws, rs) })
	fs.expireLocked(b, p.Received, false)
	fs.mu.Unlock()
	if len(recs) == 0 && len(raws) == 0 {
		return
	}
	// Raw sets name their exporter; a datagram's are its sender's.
	var mine []*flow.RawSet
	for _, rs := range raws {
		if rs.Exporter.IsValid() && rs.Exporter != addr {
			_ = b.store.WriteFlows(rs.Exporter, store.FlowBatch{Received: p.Received, Raw: []*flow.RawSet{rs}})
			continue
		}
		mine = append(mine, rs)
	}
	batch := store.FlowBatch{Received: p.Received, Size: len(p.Data), Records: recs, Raw: mine}
	// The exporter's metadata (sampling, interface names, options kept raw)
	// goes into its segment's template table when it changed.
	if blob, v := fs.coll.Metadata(addr); v != 0 && fs.metaVersion(addr, v) {
		batch.Meta = blob
	}
	err := b.store.WriteFlows(addr, batch)
	if err == nil {
		fs.rates.add(model.DeviceID(addr), p.Received, int64(len(recs)))
		b.noteFirstMessage(p.Received)
	}
}

// flowQueueDrop counts the flow queue's drops for the exporter.
func (b *backend) flowQueueDrop(from netip.Addr, at time.Time, n int64) {
	b.store.DropQueuedFlows(from, at, n)
}

// applyFlowSettings applies a settings save's flow listener settings to the
// collector (the listener itself is Reconfigure's) and the budget.
func (b *backend) applyFlowSettings(cur, next config.Config) {
	if b.flows == nil {
		return
	}
	c, n := cur.Listeners.Flow, next.Listeners.Flow
	if c.TemplateTimeout != n.TemplateTimeout || strings.Join(c.RuleIDIEs, ",") != strings.Join(n.RuleIDIEs, ",") {
		b.flows.coll.SetOptions(time.Duration(n.TemplateTimeout), ruleIEs(n))
		b.flows.eng.SetRuleIDIEs(ruleIEs(n))
	}
}

// flowBudgetLimit is the store's FlowBudgetBytes for a config value (0, the
// default share, is -1 to SetLimits).
func flowBudgetLimit(v int64) int64 {
	if v == 0 {
		return -1
	}
	return v
}

// ---- GET /api/flows ----

func (b *backend) FlowState(ctx context.Context) (api.FlowState, error) {
	cfg := b.config()
	now := b.now()
	st := api.FlowState{Enabled: cfg.Listeners.Flow.Enabled,
		Budget: api.FlowBudget{Bytes: b.store.FlowBudget(), UsedBytes: b.store.FlowBytes()}}
	var rate float64
	for _, es := range b.flows.coll.Stats(now) {
		id := model.DeviceID(es.Addr)
		e := api.FlowExporter{DeviceID: id, PendingBytes: es.PendingBytes, ClockSkewMS: es.ClockSkewMs, TimeSource: es.TimeSource,
			RecordsPerSec: b.flows.rates.perSec(id, now),
			Counts24h: api.FlowCounts{Records: es.Counts24h.Records, Late: es.Counts24h.Late, NoTemplate: es.Counts24h.NoTemplate,
				Malformed: es.Counts24h.Malformed, SequenceGaps: es.Counts24h.SequenceGaps, Duplicates: es.Counts24h.Duplicates},
			TimeOffsets24h: apiOffsets(es.TimeOffsets24h), TimeOffsets1h: apiOffsets(es.TimeOffsets1h)}
		if !es.LastHeard.IsZero() {
			t := es.LastHeard.UTC()
			e.LastSeen = &t
		}
		for _, d := range es.Domains {
			fd := api.FlowDomain{ID: d.ID, Sampling: d.Sampling, Templates: d.Templates, SeqMode: d.SeqMode}
			if !d.LastTemplate.IsZero() {
				t := d.LastTemplate.UTC()
				fd.LastTemplate = &t
			}
			e.Domains = append(e.Domains, fd)
		}
		rate += e.RecordsPerSec
		st.Exporters = append(st.Exporters, e)
	}
	sort.Slice(st.Exporters, func(i, j int) bool { return st.Exporters[i].DeviceID < st.Exporters[j].DeviceID })
	if days, ok := b.flowDays(ctx, rate, st.Budget); ok {
		st.Budget.EstimatedDays = &days
	}
	return st, nil
}

func apiOffsets(o flow.TimeOffsets) api.FlowTimeOffsets {
	return api.FlowTimeOffsets{Ahead: o.Ahead, Behind: o.Behind, MaxAheadMS: o.MaxAheadMs, MaxBehindMS: o.MaxBehindMs}
}

// flowDays estimates how many days of flows the budget holds at the current
// rate: bytes per record on disk times records a second.
func (b *backend) flowDays(ctx context.Context, rate float64, bud api.FlowBudget) (float64, bool) {
	if rate <= 0 || bud.UsedBytes <= 0 {
		return 0, false
	}
	_, recs, err := b.idx.FlowSegmentsCount(ctx, nil, time.Time{}, time.Time{})
	if err != nil || recs == 0 {
		return 0, false
	}
	perDay := float64(bud.UsedBytes) / float64(recs) * rate * 86400
	return float64(bud.Bytes) / perDay, true
}

// ---- GET /api/flows/templates ----

func (b *backend) FlowTemplates(ctx context.Context, id string) (api.FlowTemplates, error) {
	for _, es := range b.flows.coll.Stats(b.now()) {
		if model.DeviceID(es.Addr) != id {
			continue
		}
		out := api.FlowTemplates{DeviceID: id}
		byDom := map[uint32]int{}
		for _, t := range b.flows.coll.Templates(es.Addr) {
			i, ok := byDom[t.Domain]
			if !ok {
				i = len(out.Domains)
				byDom[t.Domain] = i
				out.Domains = append(out.Domains, api.FlowTemplateDomain{ID: t.Domain})
			}
			ft := api.FlowTemplate{ID: t.ID, Options: t.Options, Received: t.Received.UTC()}
			for _, f := range t.Fields {
				// "" for an IE Woodshed has no name for (docs/api.md; the UI shows those
				// as pen:id and offers them as rule ID fields), not IEName's "pen:id".
				name := f.Name
				if name == (flow.IEKey{PEN: f.PEN, ID: f.ID}).String() {
					name = ""
				}
				ft.Fields = append(ft.Fields, api.FlowTemplateField{PEN: f.PEN, ID: f.ID, Name: name, Length: f.Length})
			}
			out.Domains[i].Templates = append(out.Domains[i].Templates, ft)
		}
		sort.Slice(out.Domains, func(i, j int) bool { return out.Domains[i].ID < out.Domains[j].ID })
		return out, nil
	}
	return api.FlowTemplates{}, api.ErrNotFound
}

// ---- queries ----

// flowQuery is the engine query of a request: the device selection, the
// range (default the last 24 h) and the flow filter.
func (b *backend) flowQuery(ctx context.Context, r api.SearchRequest) (flowquery.Query, error) {
	to := r.To
	if to.IsZero() {
		to = b.now().UTC()
	}
	from := r.From
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}
	if !from.Before(to) {
		return flowquery.Query{}, &api.RequestError{Msg: `"from" must be before "to".`}
	}
	devs, err := b.search.ResolveDevices(ctx, r.Devices, r.Group, r.Ungrouped, r.ExcludeDevices)
	if err != nil {
		return flowquery.Query{}, err
	}
	if devs == nil {
		devs = []string{}
	}
	f, err := r.Flow.Filter()
	if err != nil {
		return flowquery.Query{}, &api.RequestError{Msg: err.Error()}
	}
	return flowquery.Query{DeviceIDs: devs, From: from, To: to, Filter: f, DefaultRange: r.From.IsZero() && r.To.IsZero()}, nil
}

func flowErr(err error) error {
	switch {
	case errors.Is(err, flowquery.ErrExpired), errors.Is(err, flowquery.ErrCursor):
		return &api.RequestError{Msg: err.Error()}
	}
	return err
}

func toAPIProgress(p flowquery.Progress) *api.FlowProgress {
	return &api.FlowProgress{BlocksDone: p.BlocksDone, BlocksTotal: p.BlocksTotal, RecordsDone: p.RecordsDone,
		RecordsTotal: p.RecordsTotal, CompleteFrom: p.CompleteFrom.UTC()}
}

func msTime(ms int64) *time.Time {
	if ms == 0 {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}

func (b *backend) FlowTop(ctx context.Context, r api.FlowTopRequest) (api.FlowTopPage, error) {
	start := time.Now()
	q, err := b.flowQuery(ctx, r.SearchRequest)
	if err != nil {
		return api.FlowTopPage{}, err
	}
	res, err := b.flows.eng.Top(ctx, q, r.By, r.Metric, r.Top, time.Duration(r.BudgetMS)*time.Millisecond, r.Cursor)
	if err != nil {
		return api.FlowTopPage{}, flowErr(err)
	}
	return ToAPITop(r.By, r.Metric, q, res, time.Since(start)), nil
}

// ToAPITop is a top-N result as /api/flows/top shows it (`woodshed flows top` too).
func ToAPITop(by, metric string, q flowquery.Query, res flowquery.TopResult, took time.Duration) api.FlowTopPage {
	t := res.Total
	page := api.FlowTopPage{By: by, Metric: metric, From: q.From, To: q.To, Approx: res.Approx, ErrorBound: res.ErrorBound,
		Partial:    res.Partial,
		NextCursor: res.Cursor, Progress: toAPIProgress(res.Progress), ElapsedMS: took.Milliseconds(),
		Total: api.FlowTopTotal{Flows: t.Flows, Connections: t.Connections, Bytes: t.Bytes, Packets: t.Packets,
			BytesScaled: t.BytesScaled, PacketsScaled: t.PacketsScaled, ScaledComplete: t.Unknown == 0}}
	tot := t.Metric(metric)
	var rowsFlows, rowsBytes int64
	for _, row := range res.Rows {
		share := 0.0
		if tot > 0 {
			share = float64(row.Metric(metric)) / float64(tot)
		}
		page.Rows = append(page.Rows, api.FlowTopRow{Key: row.Key, Label: row.Label, Flows: row.Flows, Connections: row.Connections,
			Bytes: row.Bytes, Packets: row.Packets, BytesScaled: row.BytesScaled, PacketsScaled: row.PacketsScaled,
			ScaledLowerBound: row.Unknown > 0, Share: share, First: msTime(row.First), Last: msTime(row.Last),
			Approx: row.Approx, MaxError: row.Err})
		rowsFlows += row.Flows
		rowsBytes += row.Bytes
	}
	page.Other = api.FlowTopOther{Flows: max(t.Flows-rowsFlows, 0), Bytes: max(t.Bytes-rowsBytes, 0)}
	return page
}

func (b *backend) flowSearch(ctx context.Context, r api.SearchRequest) (api.SearchPage, error) {
	start := time.Now()
	q, err := b.flowQuery(ctx, r)
	if err != nil {
		return api.SearchPage{}, err
	}
	limit := r.Limit
	if limit <= 0 {
		limit = 500
	}
	res, err := b.flows.eng.Search(ctx, q, limit, r.Asc, r.Cursor, 10*time.Second)
	if err != nil {
		return api.SearchPage{}, flowErr(err)
	}
	page := api.SearchPage{NextCursor: res.Cursor, Partial: res.Partial, ElapsedMS: time.Since(start).Milliseconds()}
	for i := range res.Hits {
		h := &res.Hits[i]
		rec := h.Record
		page.Results = append(page.Results, api.SearchLine{Received: time.UnixMilli(rec.Received).UTC(), DeviceID: h.DeviceID,
			Type: datatype.Flow, Ref: h.Ref(), Flow: &rec})
	}
	return page, nil
}

// flowSummary is /api/search/summary for type=flow: the index histogram
// (flow_minute) when unfiltered, otherwise the scan's, and the field panel.
func (b *backend) flowSummary(ctx context.Context, r api.SummaryRequest) (api.SummaryPage, error) {
	start := time.Now()
	q, err := b.flowQuery(ctx, r.SearchRequest)
	if err != nil {
		return api.SummaryPage{}, err
	}
	bucket, err := search.PickBucket(time.Duration(r.Bucket)*time.Second, q.From, q.To)
	if err != nil {
		return api.SummaryPage{}, requestError(err)
	}
	origin := search.BucketOrigin(bucket)
	fields := r.Fields
	if fields == nil {
		fields = flowquery.FieldKeys
	}
	for _, k := range fields {
		if !contains(flowquery.FieldKeys, k) {
			return api.SummaryPage{}, &api.RequestError{Msg: fmt.Sprintf("fields: %q isn't a flow field (%s).", k,
				strings.Join(flowquery.FieldKeys, ", "))}
		}
	}
	indexHist := r.Histogram && q.Filter.Empty() && bucket >= time.Minute
	scanHist := r.Histogram && !indexHist
	page := api.SummaryPage{Type: datatype.Flow, From: q.From, To: q.To}
	// matched is always the window's count: from the index histogram when that's
	// what was asked for with no fields, otherwise from a scan (fields=none with
	// histogram=false, or with a filter, still counts; it used to return 0).
	if len(fields) > 0 || !indexHist {
		res, err := b.flows.eng.Summary(ctx, q, flowquery.SummaryQuery{Fields: fields, Top: r.Top, Histogram: scanHist,
			Bucket: bucket, Origin: origin}, time.Duration(r.BudgetMS)*time.Millisecond, r.Cursor)
		if err != nil {
			return api.SummaryPage{}, flowErr(err)
		}
		page.Matched, page.Partial, page.NextCursor = res.Matched, res.Partial, res.Cursor
		page.Progress = toAPIProgress(res.Progress)
		page.CountedFrom = res.Progress.CompleteFrom
		for _, fc := range res.Fields {
			sf := api.SummaryField{Key: fc.Key, Label: flowFieldLabel(fc.Key), Other: fc.Other, None: fc.None, Distinct: fc.Distinct,
				DistinctCapped: fc.DistinctCapped}
			for _, v := range fc.Values {
				bb, bs := v.Bytes, v.BytesScaled
				sf.Values = append(sf.Values, api.SummaryValue{Value: v.Value, Label: v.Label, Count: v.Count,
					Filterable: !strings.Contains(v.Value, ","), Bytes: &bb, BytesScaled: &bs})
			}
			page.Fields = append(page.Fields, sf)
		}
		if scanHist {
			page.Histogram = flowHistogram("scan", bucket, q, r.Metric, func(k int64) (api.SummaryBucket, bool) {
				bk, ok := res.Buckets[k]
				if !ok {
					return api.SummaryBucket{}, false
				}
				return flowBucket(r.Metric, index.FlowBucket{Records: bk.Flows, Bytes: bk.Bytes, Packets: bk.Packets, BytesScaled: bk.BytesScaled}), true
			}, res.Partial, res.Progress.CompleteFrom)
		}
	} else {
		page.CountedFrom = q.From
	}
	if indexHist {
		m, err := b.idx.FlowMinuteBuckets(ctx, q.DeviceIDs, q.From.UnixMilli(), q.To.UnixMilli(), origin.UnixMilli(), bucket.Milliseconds(), false)
		if err != nil {
			return api.SummaryPage{}, err
		}
		all := m[""]
		var matched int64
		page.Histogram = flowHistogram("index", bucket, q, r.Metric, func(k int64) (api.SummaryBucket, bool) {
			fb, ok := all[k]
			if ok {
				matched += fb.Records
			}
			return flowBucket(r.Metric, fb), true
		}, false, q.From)
		if len(fields) == 0 {
			page.Matched = matched
		}
	}
	page.ElapsedMS = time.Since(start).Milliseconds()
	return page, nil
}

func flowBucket(metric string, fb index.FlowBucket) api.SummaryBucket {
	n := fb.Records
	switch metric {
	case "bytes":
		n = fb.Bytes
	case "packets":
		n = fb.Packets
	}
	bb, bs := fb.Bytes, fb.BytesScaled
	return api.SummaryBucket{Count: &n, Bytes: &bb, BytesScaled: &bs}
}

// flowHistogram lays out the buckets from the window's first to its last
// (counts for buckets wholly before complete_from of a partial scan are null).
func flowHistogram(source string, bucket time.Duration, q flowquery.Query, metric string, get func(int64) (api.SummaryBucket, bool),
	partial bool, completeFrom time.Time) *api.SummaryHistogram {
	size := bucket.Milliseconds()
	h := &api.SummaryHistogram{BucketSeconds: int64(bucket / time.Second), Source: source}
	first := q.From.UnixMilli() - modFloor(q.From.UnixMilli(), size)
	for k := first; k < q.To.UnixMilli(); k += size {
		bk, ok := get(k)
		if !ok {
			if partial && k+size <= completeFrom.UnixMilli() {
				bk = api.SummaryBucket{}
			} else {
				zero := int64(0)
				z1, z2 := int64(0), int64(0)
				bk = api.SummaryBucket{Count: &zero, Bytes: &z1, BytesScaled: &z2}
			}
		}
		bk.Start = time.UnixMilli(k).UTC()
		h.Buckets = append(h.Buckets, bk)
	}
	return h
}

func modFloor(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}

func flowFieldLabel(key string) string {
	for _, f := range datatype.Get(datatype.Flow).Fields() {
		if f.Key == key {
			return f.Label
		}
	}
	return key
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- GET /api/flows/timeline ----

func (b *backend) FlowTimeline(ctx context.Context, q api.FlowTimelineQuery) (api.FlowTimeline, error) {
	devs, err := b.search.ResolveDevices(ctx, q.Devices, q.Group, q.Ungrouped, nil)
	if err != nil {
		return api.FlowTimeline{}, err
	}
	size := q.Bucket.Milliseconds()
	from, to := q.From.UnixMilli(), q.To.UnixMilli()
	first := from - modFloor(from, size)
	m, err := b.idx.FlowMinuteBuckets(ctx, devs, first, to, first, size, true)
	if err != nil {
		return api.FlowTimeline{}, err
	}
	type dev struct {
		id    string
		bytes int64
	}
	var ds []dev
	for id, bk := range m {
		var n int64
		for _, v := range bk {
			n += v.Bytes
		}
		ds = append(ds, dev{id, n})
	}
	sort.Slice(ds, func(i, j int) bool {
		if ds[i].bytes != ds[j].bytes {
			return ds[i].bytes > ds[j].bytes
		}
		return ds[i].id < ds[j].id
	})
	out := api.FlowTimeline{}
	for i, d := range ds {
		if i >= 4 {
			out.More = len(ds) - 4
			break
		}
		td := api.FlowTimelineDevice{DeviceID: d.id}
		for k := first; k < to; k += size {
			fb := m[d.id][k]
			td.Points = append(td.Points, api.FlowTimelinePoint{Start: time.UnixMilli(k).UTC(), Bytes: fb.Bytes,
				BytesScaled: fb.BytesScaled, Flows: fb.Records, Packets: fb.Packets})
		}
		out.Devices = append(out.Devices, td)
	}
	return out, nil
}

// ---- banners ----

// flowBanners are SPEC §13's banners: the budget holds less than a day, data
// waiting for (or stored raw for lack of) a template, an exporter clock more
// than an hour off, and on Windows a flow firewall rule that's off.
func (b *backend) flowBanners(ctx context.Context, cfg config.Config, now time.Time, goos string) []api.Banner {
	if b.flows == nil {
		return nil
	}
	var out []api.Banner
	var rate float64
	var waiting, clock []string
	var offTime []flowTimeOff
	for _, es := range b.flows.coll.Stats(now) {
		id := model.DeviceID(es.Addr)
		rate += b.flows.rates.perSec(id, now)
		// Data waiting for its template over 10 minutes, or stored raw for lack
		// of one in the last 24 h.
		if es.Counts24h.NoTemplate > 0 || (!es.PendingOldest.IsZero() && now.Sub(es.PendingOldest) > 10*time.Minute) {
			waiting = append(waiting, id)
		}
		if es.TimeSource == flow.TimeReceived.String() {
			clock = append(clock, id)
		}
		if o := es.TimeOffsets1h; o.Ahead >= flow.TimeBannerMin || o.Behind >= flow.TimeBannerMin {
			offTime = append(offTime, flowTimeOff{id, o})
		}
	}
	if rate > 0 {
		bud := api.FlowBudget{Bytes: b.store.FlowBudget(), UsedBytes: b.store.FlowBytes()}
		if days, ok := b.flowDays(ctx, rate, bud); ok && days < 1 {
			out = append(out, api.Banner{Kind: "flow_budget", Level: "info", Text: fmt.Sprintf(
				"Flows arrive at %.0f records a second, so their budget of %s holds about %.0f hours of them. Raise storage.flow_budget_bytes "+
					"(Settings → Flows) to keep more.", rate, formatBytes(bud.Bytes), days*24)})
		}
	}
	if len(waiting) > 0 {
		sort.Strings(waiting)
		out = append(out, api.Banner{Kind: "flow_templates", Level: "warn", Text: fmt.Sprintf(
			"Flow data from %s is waiting for its template (over 10 minutes) or was kept undecoded without one. The exporter "+
				"resends templates on its own schedule; until then its records can't be read (they're kept raw).", strings.Join(waiting, ", "))})
	}
	if len(clock) > 0 {
		sort.Strings(clock)
		out = append(out, api.Banner{Kind: "flow_clock", Level: "warn", Text: fmt.Sprintf(
			"The clock of %s is more than an hour off: its flows use the time they arrived instead. Set the exporter's clock (NTP).",
			strings.Join(clock, ", "))})
	}
	if len(offTime) > 0 {
		out = append(out, api.Banner{Kind: "flow_time", Level: "warn", Text: flowTimeText(offTime)})
	}
	if goos == "windows" && cfg.Listeners.Flow.Enabled {
		l := cfg.Listeners.Flow
		if text := flowFirewallText(b.flowFirewall(l.FlowPort, l.IPFIXPort, now)); text != "" {
			out = append(out, api.Banner{Kind: "flow_firewall", Level: "warn", Text: text})
		}
	}
	return out
}

// flowTimeOff is an exporter past the flow_time banner's threshold.
type flowTimeOff struct {
	id string
	o  flow.TimeOffsets
}

// flowTimeText is the flow_time banner: exporters with at least
// flow.TimeBannerMin records ahead (or behind) in the last hour, each with its
// largest offset that hour.
func flowTimeText(offs []flowTimeOff) string {
	sort.Slice(offs, func(i, j int) bool { return offs[i].id < offs[j].id })
	ways := func(o flow.TimeOffsets) (ahead, behind string) {
		if o.Ahead >= flow.TimeBannerMin {
			ahead = "up to " + flow.OffsetText(o.MaxAheadMs) + " ahead"
		}
		if o.Behind >= flow.TimeBannerMin {
			behind = "up to " + flow.OffsetText(o.MaxBehindMs) + " behind"
		}
		return ahead, behind
	}
	const tail = " They're kept as sent, at their own times."
	if len(offs) == 1 {
		var when string
		switch a, b := ways(offs[0].o); {
		case a != "" && b != "":
			when = a + " of, or " + b + ","
		case a != "":
			when = a + " of"
		default:
			when = b
		}
		return fmt.Sprintf("Flow records from %s have times %s when they arrived: the exporter's clock or uptime is probably wrong.",
			offs[0].id, when) + tail
	}
	const most = 5
	var parts []string
	for _, x := range offs[:min(most, len(offs))] {
		a, b := ways(x.o)
		parts = append(parts, x.id+" ("+strings.Trim(a+", "+b, ", ")+")")
	}
	list := strings.Join(parts, ", ")
	if len(offs) > most {
		list += fmt.Sprintf(" and %d more", len(offs)-most)
	}
	return "Flow records from " + list + " have times far from when they arrived: the exporters' clocks or uptimes are probably wrong." + tail
}

// flowFirewall reads the Windows rules' state, at most once a minute.
func (b *backend) flowFirewall(nf, ix int, now time.Time) []fwrule.FlowRuleState {
	fs := b.flows
	fs.fwMu.Lock()
	defer fs.fwMu.Unlock()
	if !fs.fwAt.IsZero() && now.Sub(fs.fwAt) < time.Minute {
		return fs.fwRules
	}
	fs.fwRules = fs.fwCheck(nf, ix)
	fs.fwAt = now
	return fs.fwRules
}

// flowFirewallText is the flow_firewall banner for the rules that aren't ok,
// naming every one whose state is known to be wrong ("" when none is).
func flowFirewallText(rules []fwrule.FlowRuleState) string {
	var bad []fwrule.FlowRuleState
	for _, r := range rules {
		if r.State != fwrule.StateOK && r.State != fwrule.StateUnknown {
			bad = append(bad, r)
		}
	}
	state := func(s string) string { return strings.ReplaceAll(s, "_", " ") }
	const tail = ", so exporters can't reach the flow listener. Run `woodshed flow on` as an administrator."
	switch {
	case len(bad) == 0:
		return ""
	case len(bad) == 1:
		return fmt.Sprintf("The Windows firewall rule %q is %s", bad[0].Rule, state(bad[0].State)) + tail
	}
	names := make([]string, len(bad))
	same := true
	for i, r := range bad {
		names[i] = strconv.Quote(r.Rule)
		same = same && r.State == bad[0].State
	}
	if same {
		return fmt.Sprintf("The Windows firewall rules %s are %s", strings.Join(names, " and "), state(bad[0].State)) + tail
	}
	for i, r := range bad {
		names[i] += " (" + state(r.State) + ")"
	}
	return "The Windows firewall rules " + strings.Join(names, " and ") + " are off or wrong" + tail
}

// flowStats is the collector's last-24-hour sequence gaps for an exporter,
// for bundle summaries (nil when it hasn't heard from it).
func (b *backend) flowStats(deviceID string) *export.FlowStats {
	for _, es := range b.flows.coll.Stats(b.now()) {
		if model.DeviceID(es.Addr) == deviceID {
			return &export.FlowStats{SequenceGaps: es.Counts24h.SequenceGaps, LostEstimate: es.Counts24h.LostEstimate,
				TimeOffsets: es.TimeOffsets24h}
		}
	}
	return nil
}
