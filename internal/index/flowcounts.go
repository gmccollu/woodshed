package index

import (
	"context"
	"database/sql"
	"time"
)

// FlowCounts are the flow collector's per-exporter counts for a minute (or an
// hour) by received time, kept in type_stats beside the stored records'
// msgs and bytes (SPEC §13.10 decisions 82 and 83): the sequence gaps and the
// records they stand for, duplicates, late-decoded records, raw sets by
// status, and the records whose flow time was far from their arrival. They
// are what the collector saw, not derived from the segments, so Reindex keeps
// them; they roll up into type_stats_hourly and are pruned like the other
// stats (index.MinuteRetention, index.StatsRetention).
type FlowCounts struct {
	Late       int64 // records decoded after their template arrived
	NoTemplate int64 // raw sets whose template never came
	Malformed  int64 // raw sets that didn't parse
	SeqGaps    int64 // sequence gaps: loss between the exporter and Woodshed
	SeqLost    int64 // the records those gaps stand for (an estimate for flow v9)
	Duplicates int64 // sequence numbers seen twice
	// Ahead and Behind count records whose end was far after or before
	// their arrival (flow.TimeOffset); the Max fields are the largest
	// offsets, in ms (maxima, not sums, when buckets merge).
	Ahead, Behind           int64
	MaxAheadMs, MaxBehindMs int64
}

// Add adds o to c (the maxima take the larger).
func (c *FlowCounts) Add(o FlowCounts) {
	c.Late += o.Late
	c.NoTemplate += o.NoTemplate
	c.Malformed += o.Malformed
	c.SeqGaps += o.SeqGaps
	c.SeqLost += o.SeqLost
	c.Duplicates += o.Duplicates
	c.Ahead += o.Ahead
	c.Behind += o.Behind
	c.MaxAheadMs = max(c.MaxAheadMs, o.MaxAheadMs)
	c.MaxBehindMs = max(c.MaxBehindMs, o.MaxBehindMs)
}

// flowCountsMigration (8 -> 9) adds the flow counts to both stats tables.
// flow_counted is 1 on rows written since, so a reader can tell "no gaps"
// from "not counted" (rows from 2.0.0-rc1 have 0).
const flowCountsMigration = `
ALTER TABLE type_stats ADD COLUMN late INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN no_template INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN malformed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN seq_gaps INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN seq_lost INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN duplicates INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN off_ahead INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN off_behind INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN off_max_ahead_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN off_max_behind_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats ADD COLUMN flow_counted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN late INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN no_template INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN malformed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN seq_gaps INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN seq_lost INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN duplicates INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN off_ahead INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN off_behind INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN off_max_ahead_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN off_max_behind_ms INTEGER NOT NULL DEFAULT 0;
ALTER TABLE type_stats_hourly ADD COLUMN flow_counted INTEGER NOT NULL DEFAULT 0;
`

// flowCountCols are the flow count columns' aggregates over a set of
// type_stats or type_stats_hourly rows (in FlowCounts' order), then the
// number of rows and of rows without flow counts.
const flowCountCols = `COALESCE(sum(late),0), COALESCE(sum(no_template),0), COALESCE(sum(malformed),0), COALESCE(sum(seq_gaps),0),
	COALESCE(sum(seq_lost),0), COALESCE(sum(duplicates),0), COALESCE(sum(off_ahead),0), COALESCE(sum(off_behind),0),
	COALESCE(max(off_max_ahead_ms),0), COALESCE(max(off_max_behind_ms),0), COALESCE(sum(msgs),0), count(*),
	COALESCE(sum(flow_counted = 0),0)`

func flowCountDest(c *FlowCounts, msgs, rows, uncounted *int64) []any {
	return []any{&c.Late, &c.NoTemplate, &c.Malformed, &c.SeqGaps, &c.SeqLost, &c.Duplicates, &c.Ahead, &c.Behind,
		&c.MaxAheadMs, &c.MaxBehindMs, msgs, rows, uncounted}
}

// FlowWindowCounts are a device's flow counts over a window (FlowCountsIn).
type FlowWindowCounts struct {
	FlowCounts
	Records int64 // records stored (msgs)
	// From and To are the span the counts cover: the window widened to whole
	// minutes, its start widened to the hour when hourly buckets (minutes
	// older than MinuteRetention) are in it (ByHour), and its start moved up
	// to the retention cutoff when the window starts before it (Partial).
	From, To time.Time
	ByHour   bool
	Partial  bool
	// Known: the span has buckets and every one has flow counts. Otherwise
	// Reason is FlowGapsNotKept (the whole window is older than
	// StatsRetention), FlowGapsNothingReceived (no datagram arrived in it)
	// or FlowGapsNotCounted (part of it written by 2.0.0-rc1).
	Known  bool
	Reason string
}

// FlowWindowCounts reasons.
const (
	FlowGapsNotKept         = "not_kept"
	FlowGapsNothingReceived = "nothing_received"
	FlowGapsNotCounted      = "not_counted"
)

// FlowCountsIn sums deviceID's flow counts over [from, to) by received time.
// A bucket counts when it starts in the span: minutes from from's minute,
// hours from from's hour (a minute lives in only one of the two tables).
// kept is the stats retention cutoff (now - StatsRetention; zero: none):
// buckets before its hour may be pruned, so a window that starts earlier is
// counted from there only (Partial), and one that ends by then isn't known.
func (d *DB) FlowCountsIn(ctx context.Context, deviceID string, from, to, kept time.Time) (FlowWindowCounts, error) {
	out := FlowWindowCounts{From: from.UTC().Truncate(time.Minute), To: to.UTC()}
	if t := out.To.Truncate(time.Minute); t.Before(out.To) {
		out.To = t.Add(time.Minute)
	}
	hourLo := from.UTC().Truncate(time.Hour)
	if !kept.IsZero() {
		k := kept.UTC().Truncate(time.Hour) // the prune keeps every hour from this one
		if !out.To.After(k) {
			out.Reason = FlowGapsNotKept
			return out, nil
		}
		if hourLo.Before(k) {
			out.Partial = true
			hourLo = k
			if out.From.Before(k) {
				out.From = k
			}
		}
	}
	var rows, uncounted int64
	for _, q := range []struct {
		table, col string
		lo         time.Time
	}{{"type_stats", "minute", out.From}, {"type_stats_hourly", "hour", hourLo}} {
		var c FlowCounts
		var msgs, n, un int64
		var lo, hi sql.NullInt64
		err := d.db.QueryRowContext(ctx, `SELECT `+flowCountCols+`, min(`+q.col+`), max(`+q.col+`) FROM `+q.table+
			` WHERE device_id = ? AND type = ? AND `+q.col+` >= ? AND `+q.col+` < ?`, deviceID, TypeFlow, ms(q.lo), ms(to)).
			Scan(append(flowCountDest(&c, &msgs, &n, &un), &lo, &hi)...)
		if err != nil {
			return out, err
		}
		if n == 0 {
			continue
		}
		out.FlowCounts.Add(c)
		out.Records += msgs
		rows += n
		uncounted += un
		if q.table == "type_stats_hourly" && lo.Valid {
			// An hourly bucket covers its whole hour: the span starts at the
			// window's hour, and ends at the last bucket's end if later.
			out.ByHour = true
			out.From = hourLo
			if t := tm(hi.Int64).Add(time.Hour); t.After(out.To) {
				out.To = t
			}
		}
	}
	switch {
	case uncounted > 0:
		out.Reason = FlowGapsNotCounted
	case rows == 0 && out.Partial:
		out.Reason = FlowGapsNotKept
	case rows == 0:
		out.Reason = FlowGapsNothingReceived
	default:
		out.Known = true
	}
	return out, nil
}

// FlowCountBucket is one device's flow counts for one bucket (FlowCountBuckets).
type FlowCountBucket struct {
	DeviceID string
	Start    time.Time
	Records  int64
	FlowCounts
}

// FlowCountBuckets returns every flow device's counts over [from, to) in
// buckets of bucket (a divisor of an hour, or an hour), from the minute
// buckets and, for hours already rolled up, the hourly ones (bucketed by
// their hour). Rows without flow counts (2.0.0-rc1) add only their records.
// The flow collector restores its 24-hour counts from it at start.
func (d *DB) FlowCountBuckets(ctx context.Context, from, to time.Time, bucket time.Duration) ([]FlowCountBucket, error) {
	b := bucket.Milliseconds()
	if b <= 0 {
		b = time.Hour.Milliseconds()
	}
	var out []FlowCountBucket
	for _, q := range []struct {
		table, col string
		lo         int64
		b          int64
	}{{"type_stats", "minute", ms(from.UTC().Truncate(time.Minute)), b}, {"type_stats_hourly", "hour", ms(from.UTC().Truncate(time.Hour)), max(b, time.Hour.Milliseconds())}} {
		rows, err := d.db.QueryContext(ctx, `SELECT device_id, (`+q.col+` / ?) * ?, `+flowCountCols+` FROM `+q.table+
			` WHERE type = ? AND `+q.col+` >= ? AND `+q.col+` < ? GROUP BY device_id, `+q.col+` / ? ORDER BY device_id, 2`,
			q.b, q.b, TypeFlow, q.lo, ms(to), q.b)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var fb FlowCountBucket
			var start, n, un int64
			if err := rows.Scan(append([]any{&fb.DeviceID, &start}, flowCountDest(&fb.FlowCounts, &fb.Records, &n, &un)...)...); err != nil {
				rows.Close()
				return nil, err
			}
			fb.Start = tm(start)
			out = append(out, fb)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// NewestFlowSegment is deviceID's flow segment that started receiving last:
// its path (the files row's, relative to the data folder; "" when it has
// none) and when it last received something (the exporter's last flow
// datagram stored, unlike the device's last_heard, which every type moves).
func (d *DB) NewestFlowSegment(ctx context.Context, deviceID string) (string, time.Time, error) {
	var p string
	var last int64
	err := d.db.QueryRowContext(ctx, `SELECT path, last_received FROM files WHERE type = ? AND device_id = ?
		ORDER BY first_received DESC, id DESC LIMIT 1`, TypeFlow, deviceID).Scan(&p, &last)
	if err == sql.ErrNoRows {
		return "", time.Time{}, nil
	}
	return p, tm(last), err
}
