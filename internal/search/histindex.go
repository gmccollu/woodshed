package search

import (
	"context"
	"math"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
)

// The histogram's index source (SPEC §10.1.2): for a query that filters only
// by devices and time, the counts come from the stats and the files'
// checkpoints, and no log file is opened.
//
//   - A bucket (clipped to [from, to)) that is whole minutes and starts in the
//     last 24 h comes from the per-minute stats; one that is whole hours and
//     starts in the last 7 days from the minute and hourly stats together.
//   - Anything else comes from the checkpoints: the lines between two
//     checkpoints (and between the last one and the file's last received time)
//     are spread evenly over that time. A bucket that only part of such a
//     stretch falls into is approximate.
//   - Per device, stats from before its oldest remaining file are left out
//     (search finds nothing there), and the bucket holding that file's start
//     comes from the checkpoints.

const (
	minuteMs = int64(time.Minute / time.Millisecond)
	hourMs   = int64(time.Hour / time.Millisecond)
)

type hsrc int

const (
	srcCheckpoints hsrc = iota
	srcMinute
	srcHour
)

func (e *Engine) indexHistogram(ctx context.Context, st *sumState) ([]Bucket, error) {
	now := e.now().UnixMilli()
	n := st.nb
	type hb struct {
		a, z   int64 // the bucket clipped to [from, to)
		src    hsrc
		sum    float64
		approx bool
	}
	bs := make([]hb, n)
	minA, minZ, hrA, hrZ := int64(math.MaxInt64), int64(math.MinInt64), int64(math.MaxInt64), int64(math.MinInt64)
	for i := range bs {
		s := st.origin + int64(i)*st.bucketMs
		a, z := max(s, st.fromMs), min(s+st.bucketMs, st.toMs)
		b := &bs[i]
		b.a, b.z = a, z
		switch {
		case st.bucketMs >= hourMs && a%hourMs == 0 && z%hourMs == 0 && a >= now-int64(index.StatsRetention/time.Millisecond):
			b.src = srcHour
			hrA, hrZ = min(hrA, a), max(hrZ, z)
		case a%minuteMs == 0 && z%minuteMs == 0 && a >= now-int64(index.MinuteRetention/time.Millisecond):
			b.src = srcMinute
			minA, minZ = min(minA, a), max(minZ, z)
		default:
			b.src = srcCheckpoints
		}
	}
	idxOf := func(t int64) int { return int((bucketStart(t, st.bucketMs) - st.origin) / st.bucketMs) }

	oldest, err := e.idx.OldestFilesOf(ctx, st.dt.Name(), st.devs)
	if err != nil {
		return nil, err
	}
	// Each device's stats count from cutoff on; the bucket holding its oldest
	// file's start (straddle) comes from that device's checkpoints.
	cutoffs := map[string]int64{}
	straddle := map[string]int{}
	for _, d := range st.devs {
		o, ok := oldest[d]
		if !ok {
			continue // no files: search finds nothing
		}
		if o <= st.fromMs {
			cutoffs[d] = st.fromMs
			continue
		}
		if o >= st.toMs {
			continue
		}
		k := idxOf(o)
		straddle[d] = k
		cutoffs[d] = st.origin + int64(k+1)*st.bucketMs
	}
	for _, q := range []struct {
		src    hsrc
		a, z   int64
		minute bool
	}{{srcMinute, minA, minZ, true}, {srcHour, hrA, hrZ, false}} {
		if q.a >= q.z {
			continue
		}
		sums, err := e.idx.StatsBucketsOf(ctx, st.dt.Name(), cutoffs, q.minute, q.a, q.z, st.origin, st.bucketMs)
		if err != nil {
			return nil, err
		}
		for i, v := range sums {
			if i >= 0 && int(i) < n && bs[i].src == q.src {
				bs[i].sum += float64(v)
			}
		}
	}

	// The checkpoint part: per device, the buckets that need it.
	need := map[string][]bool{}
	var cpA, cpZ int64 = math.MaxInt64, math.MinInt64
	for _, d := range st.devs {
		if _, ok := oldest[d]; !ok {
			continue
		}
		var m []bool
		mark := func(i int) {
			if m == nil {
				m = make([]bool, n)
			}
			m[i] = true
			cpA, cpZ = min(cpA, bs[i].a), max(cpZ, bs[i].z)
		}
		k, strad := straddle[d]
		for i := range bs {
			if strad && i < k {
				continue // before the device's oldest file
			}
			if bs[i].src == srcCheckpoints || (strad && i == k) {
				mark(i)
			}
		}
		if m != nil {
			need[d] = m
		}
	}
	if len(need) > 0 {
		devs := make([]string, 0, len(need))
		for d := range need {
			devs = append(devs, d)
		}
		spans, err := e.idx.FilesInRangeOf(ctx, st.dt.Name(), devs, time.UnixMilli(cpA), time.UnixMilli(cpZ))
		if err != nil {
			return nil, err
		}
		ids := make([]int64, len(spans))
		for i, sp := range spans {
			ids[i] = sp.ID
		}
		cps, err := e.idx.CheckpointsFor(ctx, ids)
		if err != nil {
			return nil, err
		}
		for _, sp := range spans {
			m := need[sp.DeviceID]
			if m == nil || sp.Lines <= 0 {
				continue
			}
			spread(sp.File, cps[sp.ID], func(t0, t1 int64, lines float64) {
				// Lines received in [t0, t1), spread evenly.
				if t1 <= t0 {
					if t0 >= st.fromMs && t0 < st.toMs {
						if i := idxOf(t0); m[i] {
							bs[i].sum += lines
						}
					}
					return
				}
				lo, hi := max(t0, st.fromMs), min(t1, st.toMs)
				if lo >= hi {
					return
				}
				for i := idxOf(lo); i < n && bs[i].a < hi; i++ {
					if !m[i] {
						continue
					}
					ov := min(hi, bs[i].z) - max(lo, bs[i].a)
					if ov <= 0 {
						continue
					}
					bs[i].sum += lines * float64(ov) / float64(t1-t0)
					if ov < t1-t0 {
						bs[i].approx = true
					}
				}
			})
		}
	}
	out := make([]Bucket, n)
	for i := range bs {
		v := int64(math.Round(bs[i].sum))
		out[i] = Bucket{Start: time.UnixMilli(st.origin + int64(i)*st.bucketMs).UTC(), Count: &v, Approx: bs[i].approx}
	}
	return out, nil
}

// spread calls fn for each stretch of a file between checkpoints: the lines
// in it and the received times [t0, t1) they are taken to span. A file's
// checkpoints start at its first line; the last stretch runs to its last
// received time.
func spread(f index.File, cps []index.Checkpoint, fn func(t0, t1 int64, lines float64)) {
	last := f.LastReceived.UnixMilli() + 1
	if len(cps) == 0 {
		fn(f.FirstReceived.UnixMilli(), last, float64(f.Lines))
		return
	}
	if cps[0].Line > 0 {
		fn(f.FirstReceived.UnixMilli(), cps[0].Received.UnixMilli(), float64(cps[0].Line))
	}
	for i, c := range cps {
		endLine, endT := f.Lines, last
		if i+1 < len(cps) {
			endLine, endT = cps[i+1].Line, cps[i+1].Received.UnixMilli()
		}
		if n := endLine - c.Line; n > 0 {
			fn(c.Received.UnixMilli(), max(endT, c.Received.UnixMilli()), float64(n))
		}
	}
}
