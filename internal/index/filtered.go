package index

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// The severity filter's counts (SPEC §13.10 decision 86): syslog messages a
// device sent that weren't stored because they were less severe than the
// filter kept, per device, minute and severity, in the stats tables beside
// msgs (columns filtered_<severity>). They roll up into stats_hourly and are
// pruned like the other stats (MinuteRetention, StatsRetention). They are
// what the listeners saw, not derived from the files, so Reindex keeps them.

// SevCounts are message counts by severity (0 emerg … 7 debug).
type SevCounts [8]int64

// Total is the sum over every severity.
func (c SevCounts) Total() int64 {
	var n int64
	for _, v := range c {
		n += v
	}
	return n
}

// Add adds o to c.
func (c *SevCounts) Add(o SevCounts) {
	for i, v := range o {
		c[i] += v
	}
}

// sevNames name the filtered_* columns, by severity.
var sevNames = [8]string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

func filteredCols(prefix string) []string {
	out := make([]string, len(sevNames))
	for i, n := range sevNames {
		out[i] = prefix + "filtered_" + n
	}
	return out
}

// filteredAny is the partial indexes' condition, and the queries': a bucket
// with any filtered message. It must be written exactly so in both for
// SQLite to use the index; the queries name it (INDEXED BY), since without
// ANALYZE statistics the planner would take the primary key, which reads
// every minute of a device that has none.
var filteredAny = "(" + strings.Join(filteredCols(""), " + ") + ") > 0"

// filteredMigration (9 -> 10) adds the filtered counts to both syslog stats
// tables, and partial indexes holding only the buckets that have any (most
// devices have none, so reading a page's counts costs nothing for them).
var filteredMigration = func() string {
	var b strings.Builder
	for _, t := range []string{"stats", "stats_hourly"} {
		for _, c := range filteredCols("") {
			b.WriteString("ALTER TABLE " + t + " ADD COLUMN " + c + " INTEGER NOT NULL DEFAULT 0;\n")
		}
	}
	b.WriteString("CREATE INDEX stats_filtered ON stats (device_id, minute) WHERE " + filteredAny + ";\n")
	b.WriteString("CREATE INDEX stats_hourly_filtered ON stats_hourly (device_id, hour) WHERE " + filteredAny + ";\n")
	return b.String()
}()

// filteredSums are the columns' sums, in severity order.
var filteredSums = func() string {
	cols := filteredCols("")
	for i, c := range cols {
		cols[i] = "COALESCE(sum(" + c + "),0)"
	}
	return strings.Join(cols, ", ")
}()

func sevDest(c *SevCounts) []any {
	out := make([]any, len(c))
	for i := range c {
		out[i] = &c[i]
	}
	return out
}

// FilteredCounts returns each device's filtered counts over [from, to) (zero
// times are unbounded), with the bucket edges of Counts (statsUnion): minute
// buckets from from's minute, hourly ones from its hour. deviceIDs nil means
// every device (RefusedDeviceID included: messages from senders the device
// limits didn't admit); devices with none are absent.
func (d *DB) FilteredCounts(ctx context.Context, deviceIDs []string, from, to time.Time) (map[string]SevCounts, error) {
	d.filteredReads.Add(1)
	fromMin, fromHour := ms(from.UTC().Truncate(time.Minute)), ms(from.UTC().Truncate(time.Hour))
	if from.IsZero() {
		fromMin, fromHour = 0, 0
	}
	toMs := int64(1<<62 - 1)
	if !to.IsZero() {
		toMs = ms(to)
	}
	devWhere, devArgs := "", []any(nil)
	if deviceIDs != nil {
		if len(deviceIDs) == 0 {
			return map[string]SevCounts{}, nil
		}
		in, a := inList(deviceIDs)
		devWhere, devArgs = ` AND device_id IN `+in, a
	}
	cols := strings.Join(filteredCols(""), ", ")
	q := `SELECT device_id, ` + filteredSums + ` FROM (
		SELECT device_id, ` + cols + ` FROM stats INDEXED BY stats_filtered WHERE ` + filteredAny + devWhere + ` AND minute >= ? AND minute < ?
		UNION ALL
		SELECT device_id, ` + cols + ` FROM stats_hourly INDEXED BY stats_hourly_filtered WHERE ` + filteredAny + devWhere + ` AND hour >= ? AND hour < ?)
		GROUP BY device_id`
	args := append(append([]any{}, devArgs...), fromMin, toMs)
	args = append(append(args, devArgs...), fromHour, toMs)
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SevCounts{}
	for rows.Next() {
		var id string
		var c SevCounts
		if err := rows.Scan(append([]any{&id}, sevDest(&c)...)...); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

// FilteredTotal sums every device's filtered counts over [from, now), like
// FilteredCounts (RefusedDeviceID included).
func (d *DB) FilteredTotal(ctx context.Context, from time.Time) (SevCounts, error) {
	d.filteredReads.Add(1)
	var c SevCounts
	err := d.db.QueryRowContext(ctx, `SELECT `+filteredSums+` FROM (
		SELECT `+strings.Join(filteredCols(""), ", ")+` FROM stats INDEXED BY stats_filtered WHERE `+filteredAny+` AND minute >= ?
		UNION ALL
		SELECT `+strings.Join(filteredCols(""), ", ")+` FROM stats_hourly INDEXED BY stats_hourly_filtered WHERE `+filteredAny+` AND hour >= ?)`,
		ms(from.UTC().Truncate(time.Minute)), ms(from.UTC().Truncate(time.Hour))).Scan(sevDest(&c)...)
	return c, err
}

// FilteredWindow is a device's filtered counts over a window (FilteredIn).
type FilteredWindow struct {
	SevCounts
	// From and To are the span the counts cover: the window widened to whole
	// minutes, its start widened to the hour when hourly buckets are in it
	// (ByHour), and moved up to the stats retention cutoff when the window
	// starts before it (Partial). NotKept: the whole window is older than the
	// stats kept, so nothing is known.
	From, To time.Time
	ByHour   bool
	Partial  bool
	NotKept  bool
}

// FilteredIn sums deviceID's filtered counts over [from, to) by received
// time, with the bucket edges of FlowCountsIn: a bucket counts when it starts
// in the span. kept is the stats retention cutoff (now - StatsRetention;
// zero: none).
func (d *DB) FilteredIn(ctx context.Context, deviceID string, from, to, kept time.Time) (FilteredWindow, error) {
	d.filteredReads.Add(1)
	out := FilteredWindow{From: from.UTC().Truncate(time.Minute), To: to.UTC()}
	if t := out.To.Truncate(time.Minute); t.Before(out.To) {
		out.To = t.Add(time.Minute)
	}
	hourLo := from.UTC().Truncate(time.Hour)
	if !kept.IsZero() {
		k := kept.UTC().Truncate(time.Hour)
		if !out.To.After(k) {
			out.NotKept = true
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
	// One statement, so a rollup between reading the minutes and the hours
	// can't count a bucket twice (or not at all).
	rows, err := d.db.QueryContext(ctx, `SELECT 0, `+filteredSums+`, count(*), max(minute) FROM stats INDEXED BY stats_filtered`+
		` WHERE `+filteredAny+` AND device_id = ? AND minute >= ? AND minute < ?
		UNION ALL
		SELECT 1, `+filteredSums+`, count(*), max(hour) FROM stats_hourly INDEXED BY stats_hourly_filtered`+
		` WHERE `+filteredAny+` AND device_id = ? AND hour >= ? AND hour < ?`,
		deviceID, ms(out.From), ms(to), deviceID, ms(hourLo), ms(to))
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var hourly int
		var c SevCounts
		var n int64
		var hi sql.NullInt64
		if err := rows.Scan(append(append([]any{&hourly}, sevDest(&c)...), &n, &hi)...); err != nil {
			return out, err
		}
		if n == 0 {
			continue
		}
		out.SevCounts.Add(c)
		if hourly == 1 {
			out.ByHour = true
			out.From = hourLo
			if t := tm(hi.Int64).Add(time.Hour); t.After(out.To) {
				out.To = t
			}
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}

// FilteredByHour returns each device's filtered counts per unix hour from
// from's hour on (minute buckets summed into their hour), in one statement so
// a rollup can't move a bucket between the two tables mid-read. The store
// seeds its running 24-hour totals from it at Open.
func (d *DB) FilteredByHour(ctx context.Context, from time.Time) (map[string]map[int64]SevCounts, error) {
	fromHour := ms(from.UTC().Truncate(time.Hour))
	cols := strings.Join(filteredCols(""), ", ")
	d.filteredReads.Add(1)
	rows, err := d.db.QueryContext(ctx, `SELECT device_id, h, `+filteredSums+` FROM (
		SELECT device_id, (minute / 3600000) * 3600000 AS h, `+cols+` FROM stats INDEXED BY stats_filtered WHERE `+filteredAny+` AND minute >= ?
		UNION ALL
		SELECT device_id, hour AS h, `+cols+` FROM stats_hourly INDEXED BY stats_hourly_filtered WHERE `+filteredAny+` AND hour >= ?)
		GROUP BY device_id, h`, fromHour, fromHour)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[int64]SevCounts{}
	for rows.Next() {
		var id string
		var h int64
		var c SevCounts
		if err := rows.Scan(append([]any{&id, &h}, sevDest(&c)...)...); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[int64]SevCounts{}
		}
		out[id][h/3600000] = c
	}
	return out, rows.Err()
}

// FilteredReads counts the queries over the filtered counts since Open, for
// tests that a path stays off the index.
func (d *DB) FilteredReads() int64 { return d.filteredReads.Load() }

// The severity filter the server last ran with, in index_meta (keys
// "sevf.default" and "sevf.device:<address>", values the level + 1), so a
// start can record a change made while it was stopped (the CLI, a hand
// edit) as an event.
const (
	sevfDefaultKey = "sevf.default"
	sevfDevicePfx  = "sevf.device:"
)

// SeverityFilterState is the filter recorded by RecordSeverityFilter.
type SeverityFilterState struct {
	Default  int
	ByDevice map[string]int // by address
}

// RecordedSeverityFilter returns the last recorded filter; ok is false when
// none was ever recorded (an index from before 2.1's first start).
func (d *DB) RecordedSeverityFilter(ctx context.Context) (st SeverityFilterState, ok bool, err error) {
	rows, err := d.db.QueryContext(ctx, `SELECT key, value FROM index_meta WHERE key = ? OR (key >= ? AND key < ?)`,
		sevfDefaultKey, sevfDevicePfx, sevfDevicePfx+"\xff")
	if err != nil {
		return st, false, err
	}
	defer rows.Close()
	st.ByDevice = map[string]int{}
	for rows.Next() {
		var k string
		var v int64
		if err := rows.Scan(&k, &v); err != nil {
			return st, false, err
		}
		if k == sevfDefaultKey {
			st.Default, ok = int(v-1), true
		} else {
			st.ByDevice[strings.TrimPrefix(k, sevfDevicePfx)] = int(v - 1)
		}
	}
	return st, ok, rows.Err()
}

// RecordSeverityFilter replaces the recorded filter with st.
func (d *DB) RecordSeverityFilter(ctx context.Context, st SeverityFilterState) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM index_meta WHERE key = ? OR (key >= ? AND key < ?)`,
		sevfDefaultKey, sevfDevicePfx, sevfDevicePfx+"\xff"); err != nil {
		return err
	}
	put := func(k string, level int) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO index_meta (key, value) VALUES (?, ?)`, k, int64(level+1))
		return err
	}
	if err := put(sevfDefaultKey, st.Default); err != nil {
		return err
	}
	for a, l := range st.ByDevice {
		if err := put(sevfDevicePfx+a, l); err != nil {
			return err
		}
	}
	return tx.Commit()
}
