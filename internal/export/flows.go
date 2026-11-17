package export

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"hash"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
)

// Flows in exports and bundles (SPEC §13.4). Per device, under flows/:
//   - flows.csv: one row per record in the window (FlowCSVColumns);
//   - flows.ipfix: the same records as an IPFIX file (RFC 5655, flow.FileWriter);
//   - raw.txt: the window's raw sets (data that never met its template, and
//     malformed packets), one per line, when there are any.
// flow_formats picks csv, ipfix or both (the default). A zip holds at most
// MaxFlowRecords records per device; more is a 400 at estimate and at build.

// MaxFlowRecords is the most flow records one zip holds per device.
const MaxFlowRecords = 20_000_000

// maxFlowRecords is MaxFlowRecords, lowered by tests.
var maxFlowRecords int64 = MaxFlowRecords

// Bytes per record for the estimate (decided (build, 2026-11-16)): measured
// on the export tests' fixture, uncompressed: a CSV row is 205 bytes for a
// plain flow and 242 for an event with NAT, an IPFIX record 92–95.
const (
	csvBytesPerRecord   = 225
	ipfixBytesPerRecord = 95
)

// FlowCSVColumns is flows.csv's header (SPEC §13.4).
var FlowCSVColumns = []string{"start", "end", "event_time", "src", "src_port", "dst", "dst_port", "proto", "tcp_flags",
	"packets", "bytes", "sampling", "packets_scaled", "bytes_scaled", "in_if", "in_if_name", "out_if", "out_if_name",
	"domain", "fw_event", "nat_event", "post_nat_src", "post_nat_src_port", "post_nat_dst", "post_nat_dst_port",
	"initiator_bytes", "responder_bytes", "initiator_packets", "responder_packets", "rev_bytes", "rev_packets", "rule_id",
	"tos", "src_as", "dst_as", "next_hop", "time_source", "status", "received"}

// FlowFormats are flow_formats' values; nil means both.
const (
	FlowCSV   = "csv"
	FlowIPFIX = "ipfix"
)

func flowMS(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

// FlowCSVRow is a record's flows.csv row: empty cells for what it doesn't
// carry, times RFC 3339 UTC with milliseconds, proto as a number, tcp flags
// as letters, events by name, scaled counts only when sampling is known.
func FlowCSVRow(r *flow.Record) []string {
	u := func(bit uint64, v uint64) string {
		if !r.Is(bit) {
			return ""
		}
		return strconv.FormatUint(v, 10)
	}
	t := func(bit uint64, ms int64) string {
		if !r.Is(bit) {
			return ""
		}
		return flowMS(ms)
	}
	a := func(bit uint64, v fmt.Stringer) string {
		if !r.Is(bit) {
			return ""
		}
		return v.String()
	}
	s := func(bit uint64, v string) string {
		if !r.Is(bit) {
			return ""
		}
		return v
	}
	var ps, bs string
	if r.Sampling > 0 {
		if r.Is(flow.HasPackets) {
			ps = strconv.FormatUint(r.Packets*uint64(r.Sampling), 10)
		}
		if r.Is(flow.HasBytes) {
			bs = strconv.FormatUint(r.Bytes*uint64(r.Sampling), 10)
		}
	}
	var flags, fw, nat string
	if r.Is(flow.HasTCPFlags) {
		flags = flow.TCPFlagLetters(r.TCPFlags)
	}
	if r.Is(flow.HasFwEvent) {
		fw = flow.FwEventName(r.FwEvent)
	}
	if r.Is(flow.HasNatEvent) {
		nat = flow.NatEventName(r.NatEvent)
	}
	return []string{
		t(flow.HasStart, r.Start), t(flow.HasEnd, r.End), t(flow.HasEventTime, r.EventTime),
		a(flow.HasSrc, r.Src), u(flow.HasSrcPort, uint64(r.SrcPort)), a(flow.HasDst, r.Dst), u(flow.HasDstPort, uint64(r.DstPort)),
		u(flow.HasProto, uint64(r.Proto)), flags, u(flow.HasPackets, r.Packets), u(flow.HasBytes, r.Bytes),
		strconv.FormatUint(uint64(r.Sampling), 10), ps, bs,
		u(flow.HasInIf, uint64(r.InIf)), s(flow.HasInIfName, r.InIfName), u(flow.HasOutIf, uint64(r.OutIf)), s(flow.HasOutIfName, r.OutIfName),
		strconv.FormatUint(uint64(r.Domain), 10), fw, nat,
		a(flow.HasPostNATSrc, r.PostNATSrc), u(flow.HasPostNATSrcPort, uint64(r.PostNATSrcPort)),
		a(flow.HasPostNATDst, r.PostNATDst), u(flow.HasPostNATDstPort, uint64(r.PostNATDstPort)),
		u(flow.HasInitiatorBytes, r.InitiatorBytes), u(flow.HasResponderBytes, r.ResponderBytes),
		u(flow.HasInitiatorPackets, r.InitiatorPackets), u(flow.HasResponderPackets, r.ResponderPackets),
		u(flow.HasRevBytes, r.RevBytes), u(flow.HasRevPackets, r.RevPackets), s(flow.HasRuleID, r.RuleID),
		u(flow.HasToS, uint64(r.ToS)), u(flow.HasSrcAS, uint64(r.SrcAS)), u(flow.HasDstAS, uint64(r.DstAS)),
		a(flow.HasNextHop, r.NextHop), r.TimeSource.String(), r.Status.String(), flowMS(r.Received),
	}
}

// flowFormats is the request's formats (both by default).
func flowFormats(f Filters) []string {
	if len(f.FlowFormats) == 0 {
		return []string{FlowCSV, FlowIPFIX}
	}
	return f.FlowFormats
}

// flowFilter compiles the request's flow filter (nil when it has none, or
// when flows aren't its only type).
func (r Request) flowFilter() (*flowquery.Filter, error) {
	if len(r.Flow) == 0 {
		return nil, nil
	}
	ts := r.TypesOrSyslog()
	if len(ts) != 1 || ts[0] != datatype.Flow {
		return nil, nil
	}
	f, err := flowquery.Parse(func(k string) string { return r.Flow[k] })
	if err != nil {
		return nil, &RequestError{Msg: err.Error()}
	}
	return f, nil
}

func (b *builder) flowQuery(r Request, devs []string) (flowquery.Query, error) {
	f, err := r.flowFilter()
	return flowquery.Query{DeviceIDs: devs, From: r.From, To: r.To, Filter: f}, err
}

// flowEngine is the flow query engine, or nil (no flows in this build's
// zips: the server hasn't set it).
func (b *builder) flowEngine() *flowquery.Engine {
	if b.flows == nil {
		return nil
	}
	return b.flows()
}

// countFlows counts each device's flow records in the request, and returns
// the 400 for one over the cap.
func (b *builder) countFlows(ctx context.Context, r Request, devs []string) (map[string]int64, error) {
	eng := b.flowEngine()
	if eng == nil {
		return map[string]int64{}, nil
	}
	q, err := b.flowQuery(r, devs)
	if err != nil {
		return nil, err
	}
	n, err := eng.Count(ctx, q)
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		if err := capError(d, n[d]); err != nil {
			return n, err
		}
	}
	return n, nil
}

func capError(dev string, n int64) error {
	if n > maxFlowRecords {
		return &RequestError{Msg: fmt.Sprintf("Too many flow records for one zip (%s for %s); narrow the window or add a flow filter.",
			datatype.Thousands(n), dev)}
	}
	return nil
}

// TypeEstimate is one data type's share of an export estimate: lines for
// the line types, records for flows, and the bytes of what the zip would
// hold (uncompressed).
type TypeEstimate struct {
	Lines   int64
	Records int64
	Bytes   int64
}

// flowEstimate is the flows' estimate: the records (exact, from the
// segments) and the bytes of the formats asked for.
func (b *builder) flowEstimate(ctx context.Context, r Request, devs []string) (TypeEstimate, error) {
	n, err := b.countFlows(ctx, r, devs)
	if err != nil {
		return TypeEstimate{}, err
	}
	var est TypeEstimate
	for _, v := range n {
		est.Records += v
	}
	for _, f := range flowFormats(r.Filters) {
		switch f {
		case FlowCSV:
			est.Bytes += est.Records * csvBytesPerRecord
		case FlowIPFIX:
			est.Bytes += est.Records * ipfixBytesPerRecord
		}
	}
	return est, nil
}

// estimateByType is the estimate of each of the request's types.
func (b *builder) estimateByType(ctx context.Context, r Request, devs []string) (map[string]TypeEstimate, error) {
	out := map[string]TypeEstimate{}
	for _, t := range r.TypesOrSyslog() {
		if t == datatype.Flow {
			e, err := b.flowEstimate(ctx, r, devs)
			if err != nil {
				return nil, err
			}
			out[t] = e
			continue
		}
		e, err := b.eng.Estimate(ctx, devs, r.typeFilter(t))
		if err != nil {
			return nil, err
		}
		out[t] = TypeEstimate{Lines: e.Lines, Bytes: e.Bytes}
	}
	return out, nil
}

// EstimateByType is POST /api/exports/estimate's by_type: each type's
// lines (or flow records) and bytes. A device over the flow cap is a
// *RequestError.
func (m *Manager) EstimateByType(ctx context.Context, r Request) (map[string]TypeEstimate, error) {
	devs, err := m.resolve(ctx, &r)
	if err != nil {
		return nil, err
	}
	return m.estimateByType(ctx, r, devs)
}

// EstimateByType is Manager.EstimateByType for a plan (woodshed bundle).
func (p *Plan) EstimateByType(ctx context.Context) (map[string]TypeEstimate, error) {
	req := Request{Devices: p.Info.Named, From: p.Info.From, To: p.Info.To, Filters: p.Info.Filters}
	return p.b.estimateByType(ctx, req, p.Info.Devices)
}

// hashWriter writes to the zip and hashes and counts what it writes.
type hashWriter struct {
	zw  *zipWriter
	sum hash.Hash
	n   int64
}

func (h *hashWriter) Write(p []byte) (int, error) {
	n, err := h.zw.Write(p)
	h.sum.Write(p[:n])
	h.n += int64(n)
	return n, err
}

// writeFlows writes one device's flow files and, for a bundle, fills fs.
func (b *builder) writeFlows(ctx context.Context, zw *zipWriter, dev string, req Request, fs *flowCount, res *buildResult,
	files *[]ManifestFile, exportedAt time.Time) error {
	eng := b.flowEngine()
	if eng == nil {
		return nil
	}
	q, err := b.flowQuery(req, []string{dev})
	if err != nil {
		return err
	}
	folder := FolderOf(datatype.Flow) + "/" + dev + "/"
	formats := flowFormats(req.Filters)
	for i, format := range formats {
		var hw *hashWriter
		var mf ManifestFile
		var cw *csv.Writer
		var fw *flow.FileWriter
		var n int64
		open := func(first int64) error {
			name := folder + "flows.csv"
			if format == FlowIPFIX {
				name = folder + "flows.ipfix"
			}
			if err := zw.create(name, -1); err != nil {
				return err
			}
			hw = &hashWriter{zw: zw, sum: sha256.New()}
			mf = ManifestFile{Path: name, DeviceID: dev, First: time.UnixMilli(first).UTC()}
			if format == FlowCSV {
				cw = csv.NewWriter(hw)
				cw.UseCRLF = true
				return cw.Write(FlowCSVColumns)
			}
			fw = flow.NewFileWriter(hw, flow.FileOptions{Version: b.version, ExportTime: exportedAt})
			return nil
		}
		err := eng.Each(ctx, q, func(_ string, r *flow.Record) error {
			if hw == nil {
				if err := open(r.Received); err != nil {
					return err
				}
			}
			if n++; n > maxFlowRecords {
				return capError(dev, n)
			}
			if b.testHookLine != nil {
				b.testHookLine()
			}
			var err error
			if cw != nil {
				err = cw.Write(FlowCSVRow(r))
			} else {
				err = fw.Write(r)
			}
			if err != nil {
				return err
			}
			mf.Lines++
			last := time.UnixMilli(r.Received).UTC()
			if last.After(mf.Last) {
				mf.Last = last
			}
			if last.Before(mf.First) {
				mf.First = last
			}
			if i == 0 {
				res.lines++
				if fs != nil {
					fs.add(r)
				}
			}
			return nil
		})
		if err == nil && hw != nil {
			if cw != nil {
				cw.Flush()
				err = cw.Error()
			} else {
				err = fw.Close()
			}
		}
		if err != nil {
			return err
		}
		if hw != nil {
			mf.Bytes = hw.n
			mf.SHA256 = fmt.Sprintf("%x", hw.sum.Sum(nil))
			*files = append(*files, mf)
		}
	}
	// raw.txt: the window's raw sets (by received time), one per line:
	//   <received, RFC 3339 UTC ms> <status> <version> domain=<id> template=<id> <base64 of the set's bytes>
	var raw *hashWriter
	var rmf ManifestFile
	var line []byte
	err = eng.Raw(ctx, flowquery.Query{DeviceIDs: []string{dev}, From: req.From, To: req.To}, func(_ string, rs *flow.RawSet) error {
		if fs != nil {
			fs.raw(rs)
		}
		if raw == nil {
			name := folder + "raw.txt"
			if err := zw.create(name, -1); err != nil {
				return err
			}
			raw = &hashWriter{zw: zw, sum: sha256.New()}
			rmf = ManifestFile{Path: name, DeviceID: dev, First: time.UnixMilli(rs.Received).UTC()}
		}
		line = line[:0]
		line = append(line, flowMS(rs.Received)...)
		line = fmt.Appendf(line, " %s v%d domain=%d template=%d ", rs.Status, rs.Version, rs.Domain, rs.TemplateID)
		line = base64.StdEncoding.AppendEncode(line, rs.Data)
		line = append(line, '\n')
		if _, err := raw.Write(line); err != nil {
			return err
		}
		rmf.Lines++
		rmf.Last = time.UnixMilli(rs.Received).UTC()
		return nil
	})
	if err != nil {
		return err
	}
	if raw != nil {
		rmf.Bytes, rmf.SHA256 = raw.n, fmt.Sprintf("%x", raw.sum.Sum(nil))
		*files = append(*files, rmf)
	}
	return ctx.Err()
}

// ---- the bundle's flow summary ----

// FlowStats are what only the running collector knows about an exporter:
// its sequence gaps and the records they stand for, and the records whose
// flow time was far from when they arrived (the last 24 h).
type FlowStats struct {
	SequenceGaps, LostEstimate int64
	TimeOffsets                flow.TimeOffsets
}

// KeyShare is a top-N entry with its share of the total.
type KeyShare struct {
	Key   string  `json:"key"`
	Share float64 `json:"share"`
}

// KeyCount is a top-N entry with its count.
type KeyCount struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

// DomainSampling is a domain's sampling rates in the window (0: unknown).
type DomainSampling struct {
	Domain   uint32   `json:"domain"`
	Sampling []uint32 `json:"sampling"`
}

// FwEventCounts counts the firewall events.
type FwEventCounts struct {
	Created int64 `json:"created"`
	Deleted int64 `json:"deleted"`
	Denied  int64 `json:"denied"`
}

// FlowSummary is a device's flows in a bundle (manifest.json "summary"
// entries' "flow", docs/api.md; the README's Flows block).
type FlowSummary struct {
	Records           int64            `json:"records"`
	Domains           int              `json:"domains"`
	Sampling          []DomainSampling `json:"sampling"`
	Bytes             int64            `json:"bytes"`
	BytesScaled       int64            `json:"bytes_scaled"`
	Packets           int64            `json:"packets"`
	PacketsScaled     int64            `json:"packets_scaled"`
	ScaledComplete    bool             `json:"scaled_complete"`
	TopTalkers        []KeyShare       `json:"top_talkers"`
	TopDstPorts       []KeyShare       `json:"top_dst_ports"`
	TopConversations  []KeyShare       `json:"top_conversations"`
	FwEvents          FwEventCounts    `json:"fw_events"`
	TopDeniedSources  []KeyCount       `json:"top_denied_sources"`
	TopDeniedPorts    []KeyCount       `json:"top_denied_ports"`
	NATConnections    int64            `json:"nat_connections"`
	TopPostNATSources []KeyShare       `json:"top_post_nat_sources"`
	// SequenceGaps and LostEstimate are the running collector's (the last
	// 24 h); null when the bundle was built without it (woodshed bundle).
	SequenceGaps *int64 `json:"sequence_gaps"`
	LostEstimate *int64 `json:"lost_estimate"`
	NoTemplate   int64  `json:"no_template"`
	Malformed    int64  `json:"malformed"`
	// TimeOffsets counts the window's records whose end was more than 1 h
	// after they arrived or more than 24 h before (SPEC §13.10 decision 70);
	// TimeOffsets24h is the running collector's count over the last 24 h,
	// which includes records the window doesn't hold because their own times
	// are elsewhere (null without it).
	TimeOffsets    flow.TimeOffsets  `json:"time_offsets"`
	TimeOffsets24h *flow.TimeOffsets `json:"time_offsets_24h"`
}

// topN is how many entries each summary list keeps.
const topN = 3

// flowCount accumulates a device's flow summary while its records are
// written (one pass for the files and the summary).
type flowCount struct {
	records     int64
	first, last int64
	domains     map[uint32]map[uint32]bool
	talkers     *flowquery.Top // by src, bytes
	ports       *flowquery.Top // by dst_port, bytes
	convs       *flowquery.Top // by conversation, bytes
	denSrc      *flowquery.Top // denied, by src, flows
	denPort     *flowquery.Top // denied, by dst_port, flows
	nat         *flowquery.Top // NAT creates, by post_nat_src, flows
	fw          FwEventCounts
	noTemplate  int64
	malformed   int64
	off         flow.TimeOffsets
}

// summaryPoolBytes bounds a bundle's summary top-N tables, every device's
// together (past it they turn approximate; the README shows top 3s).
const summaryPoolBytes = 64 << 20

func newFlowCount(pool *flowquery.Pool) *flowCount {
	mk := func(by, metric string) *flowquery.Top {
		t, _ := flowquery.NewTopWith(by, metric, flowquery.TopOptions{Pool: pool, Small: true})
		return t
	}
	return &flowCount{domains: map[uint32]map[uint32]bool{}, talkers: mk("src", "bytes"), ports: mk("dst_port", "bytes"),
		convs: mk("conversation", "bytes"), denSrc: mk("src", "flows"), denPort: mk("dst_port", "flows"), nat: mk("post_nat_src", "flows")}
}

func (c *flowCount) add(r *flow.Record) {
	if c.records == 0 || r.Received < c.first {
		c.first = r.Received
	}
	if r.Received > c.last {
		c.last = r.Received
	}
	c.records++
	c.off.Add(flow.TimeOffset(r))
	d := c.domains[r.Domain]
	if d == nil {
		d = map[uint32]bool{}
		c.domains[r.Domain] = d
	}
	d[r.Sampling] = true
	c.talkers.Add(r)
	c.ports.Add(r)
	c.convs.Add(r)
	if r.Is(flow.HasFwEvent) {
		switch r.FwEvent {
		case flow.FwCreated:
			c.fw.Created++
		case flow.FwDeleted:
			c.fw.Deleted++
		case flow.FwDenied:
			c.fw.Denied++
			c.denSrc.Add(r)
			c.denPort.Add(r)
		}
	}
	if r.Is(flow.HasNatEvent) && flow.NATCreate(r.NatEvent) {
		c.nat.Add(r)
	}
}

func (c *flowCount) raw(rs *flow.RawSet) {
	switch rs.Status {
	case flow.StatusNoTemplate:
		c.noTemplate++
	case flow.StatusMalformed:
		c.malformed++
	}
}

func shares(t *flowquery.Top, metric string) []KeyShare {
	out := []KeyShare{}
	tot := t.Total.Metric(metric)
	if tot <= 0 {
		return out
	}
	for _, r := range t.Rows(topN) {
		if r.Metric(metric) <= 0 {
			break // rows are by the metric: the rest are 0 too
		}
		out = append(out, KeyShare{Key: r.Key, Share: math.Round(float64(r.Metric(metric))/float64(tot)*1e4) / 1e4})
	}
	return out
}

func counts(t *flowquery.Top) []KeyCount {
	out := []KeyCount{}
	for _, r := range t.Rows(topN) {
		out = append(out, KeyCount{Key: r.Key, Count: r.Flows})
	}
	return out
}

// summary is the accumulated FlowSummary; stats may be nil (not known).
func (c *flowCount) summary(stats *FlowStats) *FlowSummary {
	tot := c.talkers.Total
	s := &FlowSummary{Records: c.records, Domains: len(c.domains), Sampling: []DomainSampling{}, Bytes: tot.Bytes,
		BytesScaled: tot.BytesScaled, Packets: tot.Packets, PacketsScaled: tot.PacketsScaled, ScaledComplete: tot.Unknown == 0,
		TopTalkers: shares(c.talkers, "bytes"), TopDstPorts: shares(c.ports, "bytes"), TopConversations: shares(c.convs, "bytes"),
		FwEvents: c.fw, TopDeniedSources: counts(c.denSrc), TopDeniedPorts: counts(c.denPort), NATConnections: c.nat.Total.Flows,
		TopPostNATSources: shares(c.nat, "flows"), NoTemplate: c.noTemplate, Malformed: c.malformed, TimeOffsets: c.off}
	for d, rates := range c.domains {
		ds := DomainSampling{Domain: d}
		for r := range rates {
			ds.Sampling = append(ds.Sampling, r)
		}
		slices.Sort(ds.Sampling)
		s.Sampling = append(s.Sampling, ds)
	}
	sort.Slice(s.Sampling, func(i, j int) bool { return s.Sampling[i].Domain < s.Sampling[j].Domain })
	if stats != nil {
		g, l := stats.SequenceGaps, stats.LostEstimate
		s.SequenceGaps, s.LostEstimate = &g, &l
		o := stats.TimeOffsets
		s.TimeOffsets24h = &o
	}
	return s
}

// humanBytes is a byte count in decimal units, as the README shows them:
// "312 B", "18.2 GB", "1.9 TB".
func humanBytes(n int64) string {
	return humanUnits(n, []string{" B", " kB", " MB", " GB", " TB", " PB", " EB"})
}

// humanCount is a count in decimal units: "980", "21.4 M", "2.1 G".
func humanCount(n int64) string {
	if n < 1_000_000 {
		return datatype.Thousands(n)
	}
	return humanUnits(n, []string{"", " k", " M", " G", " T", " P", " E"})
}

func humanUnits(n int64, units []string) string {
	v, i := float64(n), 0
	for v >= 1000 && i < len(units)-1 {
		v /= 1000
		i++
	}
	if i == 0 {
		return strconv.FormatInt(n, 10) + units[0]
	}
	if v >= 100 {
		return strconv.FormatFloat(v, 'f', 0, 64) + units[i]
	}
	return strconv.FormatFloat(v, 'f', 1, 64) + units[i]
}

func pct(share float64) string {
	return strconv.FormatInt(int64(math.Round(share*100)), 10) + " %"
}

func joinShares(ks []KeyShare) string {
	var p []string
	for _, k := range ks {
		p = append(p, k.Key+" "+pct(k.Share))
	}
	return strings.Join(p, ", ")
}

func joinCounts(ks []KeyCount) string {
	var p []string
	for _, k := range ks {
		p = append(p, k.Key+" "+datatype.Thousands(k.Count))
	}
	return strings.Join(p, ", ")
}

// samplingWords is the sampling per domain: "sampled 1 in 1,000 on domain
// 1, unsampled on domain 2".
func samplingWords(ds []DomainSampling) string {
	var parts []string
	for _, d := range ds {
		var rates []string
		for _, r := range d.Sampling {
			switch r {
			case 0:
				rates = append(rates, "sampling unknown")
			case 1:
				rates = append(rates, "unsampled")
			default:
				rates = append(rates, "sampled 1 in "+datatype.Thousands(int64(r)))
			}
		}
		w := strings.Join(rates, " and ")
		if len(ds) > 1 {
			w += " on domain " + strconv.FormatUint(uint64(d.Domain), 10)
		}
		parts = append(parts, w)
	}
	return strings.Join(parts, ", ")
}

// anySampled reports whether a known rate above 1 appears.
func anySampled(ds []DomainSampling) bool {
	for _, d := range ds {
		for _, r := range d.Sampling {
			if r > 1 {
				return true
			}
		}
	}
	return false
}

// flowReadme is the README's Flows block (SPEC §13.4): what follows the
// "Flows" label, one line each.
func flowReadme(s *FlowSummary) []string {
	plural := func(n int, one, many string) string {
		if n == 1 {
			return one
		}
		return many
	}
	lines := []string{fmt.Sprintf("%s records from %d observation %s; %s", datatype.Thousands(s.Records), s.Domains,
		plural(s.Domains, "domain", "domains"), samplingWords(s.Sampling))}
	approx := func(scaled int64, f func(int64) string) string {
		if !anySampled(s.Sampling) {
			return ""
		}
		ge := "≈ "
		if !s.ScaledComplete {
			ge = "≥ "
		}
		return " (" + ge + f(scaled) + " scaled)"
	}
	lines = append(lines, fmt.Sprintf("bytes %s exported%s, packets %s%s", humanBytes(s.Bytes), approx(s.BytesScaled, humanBytes),
		humanCount(s.Packets), approx(s.PacketsScaled, humanCount)))
	if len(s.TopTalkers) > 0 {
		lines = append(lines, "top talkers by bytes: "+joinShares(s.TopTalkers))
	}
	if len(s.TopDstPorts) > 0 {
		lines = append(lines, "top destination ports: "+joinShares(s.TopDstPorts))
	}
	if len(s.TopConversations) > 0 {
		lines = append(lines, "top conversations: "+joinShares(s.TopConversations[:1]))
	}
	if fw := s.FwEvents; fw.Created+fw.Deleted+fw.Denied > 0 {
		lines = append(lines, fmt.Sprintf("firewall events: %s created, %s deleted, %s denied", datatype.Thousands(fw.Created),
			datatype.Thousands(fw.Deleted), datatype.Thousands(fw.Denied)))
	}
	if len(s.TopDeniedSources) > 0 {
		l := "top denied sources: " + joinCounts(s.TopDeniedSources[:min(2, len(s.TopDeniedSources))])
		if len(s.TopDeniedPorts) > 0 {
			l += "; top denied ports: " + joinCounts(s.TopDeniedPorts[:min(2, len(s.TopDeniedPorts))])
		}
		lines = append(lines, l)
	}
	if s.NATConnections > 0 {
		l := fmt.Sprintf("NAT: %s translated connections", datatype.Thousands(s.NATConnections))
		if len(s.TopPostNATSources) > 0 {
			l += "; top post-NAT sources: " + joinShares(s.TopPostNATSources[:1])
		}
		lines = append(lines, l)
	}
	if l := timeOffLine(s); l != "" {
		lines = append(lines, l)
	}
	gaps := "sequence gaps not known (only the running service counts them)"
	if s.SequenceGaps != nil {
		gaps = fmt.Sprintf("sequence gaps %s (≈ %s records lost before Woodshed, last 24 h)", datatype.Thousands(*s.SequenceGaps),
			datatype.Thousands(*s.LostEstimate))
	}
	lines = append(lines, fmt.Sprintf("%s; waiting for a template %s; malformed %s", gaps, datatype.Thousands(s.NoTemplate),
		datatype.Thousands(s.Malformed)))
	return lines
}

// timeOffLine is the README's line for records whose flow time was far from
// when they arrived, in the window and (from the running collector) the last
// 24 h; "" when there are none.
func timeOffLine(s *FlowSummary) string {
	words := func(o flow.TimeOffsets) string {
		var ws []string
		if o.Ahead > 0 {
			ws = append(ws, fmt.Sprintf("%s ahead (up to %s)", datatype.Thousands(o.Ahead), flow.OffsetText(o.MaxAheadMs)))
		}
		if o.Behind > 0 {
			ws = append(ws, fmt.Sprintf("%s behind (up to %s)", datatype.Thousands(o.Behind), flow.OffsetText(o.MaxBehindMs)))
		}
		return strings.Join(ws, ", ")
	}
	var parts []string
	if s.TimeOffsets.Any() {
		parts = append(parts, words(s.TimeOffsets)+" in this window")
	}
	if o := s.TimeOffsets24h; o != nil && o.Any() {
		parts = append(parts, words(*o)+" in the last 24 h")
	}
	if len(parts) == 0 {
		return ""
	}
	return "times off arrival: " + strings.Join(parts, "; ") + "; kept at their own times, so a window around their arrival misses them " +
		"(the exporter's clock or uptime is probably wrong)"
}

// flowFilterLines describes a flow export's filter for README.txt.
func flowFilterLines(f map[string]string) []string {
	var keys []string
	for k := range f {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []string
	for _, k := range keys {
		out = append(out, "Flows, "+k+": "+f[k])
	}
	return out
}

// flowReadmeFiles is README.txt's part about the flows folder.
func flowReadmeFiles(info Info) string {
	if !slices.Contains(info.Filters.TypesOrSyslog(), datatype.Flow) {
		return ""
	}
	var b bytes.Buffer
	formats := flowFormats(info.Filters)
	if slices.Contains(formats, FlowCSV) {
		b.WriteString(`flows/<device>/flows.csv
    The flow records Woodshed stored from each exporter in the window (flow
    time: a record is in when its start-to-end overlaps the window), one row
    per record, CSV with a header row (UTF-8, RFC 4180, CRLF). Columns:
        ` + strings.Join(FlowCSVColumns, ",") + `
    Times are UTC, RFC 3339 with milliseconds. An empty cell means the record
    didn't carry that field. proto is the protocol number, tcp_flags the set
    flags as letters (S A F R P U E C), fw_event and nat_event by name.
    sampling is 1 (unsampled), N (1 in N) or 0 (unknown); the *_scaled
    columns multiply by it and are empty when it's unknown. Enterprise and
    other fields without a column aren't in the CSV; the IPFIX file has them.

`)
	}
	if slices.Contains(formats, FlowIPFIX) {
		b.WriteString(`flows/<device>/flows.ipfix
    The same records as an IPFIX file (RFC 5655), for flow tools: one
    observation domain per original domain, templates carrying every field
    the records had, enterprise fields included; flow v5 and v9 records
    are written as their IPFIX fields. Woodshed wrote it from stored records
    (an options record in each domain says so); it wasn't captured off the
    wire. Not carried: the decode status, the exporter's source port and the
    original template IDs.

`)
	}
	b.WriteString(`flows/<device>/raw.txt
    Only when there are any: flow data stored undecoded in the window, data
    whose template never arrived (no_template) and malformed packets, one per
    line: <received> <status> v<version> domain=<id> template=<id> <base64>.

`)
	return b.String()
}

// FlowCSVHeader is flows.csv's header row's columns (`woodshed search
// --type flow` prints the same).
func FlowCSVHeader() []string { return slices.Clone(FlowCSVColumns) }

// AppendFlowCSVRow appends a record's flows.csv row to dst: RFC 4180 quoting,
// CRLF at the end.
func AppendFlowCSVRow(dst []byte, r *flow.Record) []byte {
	var b bytes.Buffer
	cw := csv.NewWriter(&b)
	cw.UseCRLF = true
	_ = cw.Write(FlowCSVRow(r))
	cw.Flush()
	return append(dst, b.Bytes()...)
}
