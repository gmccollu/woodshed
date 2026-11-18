package server

import (
	"context"
	"net/netip"
	"path/filepath"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
)

// flowRestore is what the stored data says about each exporter heard in the
// last 24 hours, for the collector at start (SPEC §13.10 decision 83): its
// counts by hour (and its times off arrival by 5 minutes for the last hour)
// from type_stats, when it last stored a flow datagram, and the newest
// segment's sampling rates from its footer, shown as "last known" only.
// Nothing that shapes a stored record (templates, sampling, system init
// times, interface names) is applied: data after a restart waits for the
// exporter's own.
//
// It runs before the listener starts, so it's bounded: restoreBudget for the
// whole, the index queries first, then one footer read per exporter while
// the budget lasts (an exporter past it is restored without its last known rates). A
// failure leaves an exporter (or everything) out: the collector then starts
// empty, as before.
func (b *backend) flowRestore(dataDir string) []flow.Restored {
	if b.idx == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), restoreBudget)
	defer cancel()
	now := b.now()
	hours, err := b.idx.FlowCountBuckets(ctx, now.Add(-24*time.Hour), now.Add(time.Minute), time.Hour)
	if err != nil {
		b.log.Warn("flows: the last 24 hours' counts couldn't be read; they start from 0", "err", err)
		return nil
	}
	fives, _ := b.idx.FlowCountBuckets(ctx, now.Add(-time.Hour), now.Add(time.Minute), 5*time.Minute)
	byDev := map[string]*flow.Restored{}
	var order []string
	get := func(id string) *flow.Restored {
		r := byDev[id]
		if r == nil {
			r = &flow.Restored{}
			byDev[id] = r
			order = append(order, id)
		}
		return r
	}
	for _, h := range hours {
		r := get(h.DeviceID)
		r.Hours = append(r.Hours, flow.RestoreBucket{At: h.Start.UnixMilli(), Counts: collectorCounts(h), Off: offsetsOf(h.FlowCounts)})
	}
	for _, f := range fives {
		if r := byDev[f.DeviceID]; r != nil {
			r.Fives = append(r.Fives, flow.RestoreBucket{At: f.Start.UnixMilli(), Off: offsetsOf(f.FlowCounts)})
		}
	}
	out := make([]flow.Restored, 0, len(order))
	skipped := 0
	for _, id := range order {
		r := byDev[id]
		dev, err := b.idx.Device(ctx, id)
		if err != nil || dev.IP == "" {
			continue
		}
		addr, err := netip.ParseAddr(dev.IP)
		if err != nil || model.DeviceID(addr) != id {
			continue
		}
		r.Addr = addr
		rel, last, err := b.idx.NewestFlowSegment(ctx, id)
		if err != nil {
			continue
		}
		r.LastHeard = last.UnixMilli()
		if rel != "" && ctx.Err() == nil {
			if rd, err := flowseg.Open(filepath.Join(dataDir, filepath.FromSlash(rel))); err == nil {
				r.Meta = rd.Footer().Meta
				rd.Close()
			}
		} else if rel != "" {
			skipped++
		}
		out = append(out, *r)
	}
	if skipped > 0 {
		b.log.Warn("flows: restoring exporters' last known sampling ran out of time; the rest show none until their next options data", "exporters", skipped)
	}
	return out
}

// restoreBudget bounds flowRestore at start.
var restoreBudget = 10 * time.Second

// collectorCounts is a stored bucket as the collector counts it (records are
// the stored ones).
func collectorCounts(h index.FlowCountBucket) flow.Counts {
	return flow.Counts{Records: h.Records, Late: h.Late, NoTemplate: h.NoTemplate, Malformed: h.Malformed,
		SequenceGaps: h.SeqGaps, LostEstimate: h.SeqLost, Duplicates: h.Duplicates}
}

func offsetsOf(c index.FlowCounts) flow.TimeOffsets {
	return flow.TimeOffsets{Ahead: c.Ahead, Behind: c.Behind, MaxAheadMs: c.MaxAheadMs, MaxBehindMs: c.MaxBehindMs}
}
