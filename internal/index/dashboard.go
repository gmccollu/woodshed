package index

import (
	"context"
	"time"
)

// DropCounts returns the truncated and dropped message counts over [from, now)
// for all devices (the refused-senders bucket included), with the same edges as
// Counts. It reads only buckets with any drops or truncations (partial indexes),
// so the dashboard doesn't sum a day of per-minute buckets for every device.
func (d *DB) DropCounts(ctx context.Context, from time.Time) (truncated, dropped int64, err error) {
	fromMin, fromHour := ms(from.UTC().Truncate(time.Minute)), ms(from.UTC().Truncate(time.Hour))
	err = d.db.QueryRowContext(ctx, `SELECT COALESCE(sum(t), 0), COALESCE(sum(dr), 0) FROM (
		SELECT sum(truncated) AS t, sum(dropped) AS dr FROM stats WHERE minute >= ? AND (dropped > 0 OR truncated > 0)
		UNION ALL
		SELECT sum(truncated), sum(dropped) FROM stats_hourly WHERE hour >= ? AND (dropped > 0 OR truncated > 0)
		UNION ALL
		SELECT sum(truncated), sum(dropped) FROM type_stats WHERE minute >= ? AND (dropped > 0 OR truncated > 0)
		UNION ALL
		SELECT sum(truncated), sum(dropped) FROM type_stats_hourly WHERE hour >= ? AND (dropped > 0 OR truncated > 0))`,
		fromMin, fromHour, fromMin, fromHour).Scan(&truncated, &dropped)
	return truncated, dropped, err
}

// StatusCounts counts the non-hidden devices by last-heard time: online when
// heard at or after onlineSince, quiet when at or after quietSince, offline
// otherwise (never heard included). It reads only the devices table.
func (d *DB) StatusCounts(ctx context.Context, onlineSince, quietSince time.Time) (online, quiet, offline int, err error) {
	err = d.db.QueryRowContext(ctx, `SELECT COALESCE(sum(last_heard >= ?), 0), COALESCE(sum(last_heard < ? AND last_heard >= ?), 0),
		COALESCE(sum(last_heard < ?), 0) FROM devices WHERE hidden = 0`, ms(onlineSince), ms(onlineSince), ms(quietSince), ms(quietSince)).
		Scan(&online, &quiet, &offline)
	return online, quiet, offline, err
}

// DeviceIDs returns every device's ID, sorted (cheap: the primary key only).
func (d *DB) DeviceIDs(ctx context.Context) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT id FROM devices ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DevicesByID returns the devices with these IDs, in the order given (unknown
// IDs are skipped), with RecentMsgs summed over [rateFrom, rateTo) (a zero
// rateTo is unbounded). It's the costly half of a page (bytes on disk, the
// rate), so callers pick the page's IDs first.
func (d *DB) DevicesByID(ctx context.Context, ids []string, rateFrom, rateTo time.Time) ([]Device, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	to := int64(1<<62 - 1)
	if !rateTo.IsZero() {
		to = ms(rateTo)
	}
	in, idArgs := inList(ids)
	rows, err := d.db.QueryContext(ctx, `SELECT `+deviceCols+`,
		(SELECT COALESCE(sum(s.msgs), 0) FROM stats s WHERE s.device_id = d.id AND s.minute >= ? AND s.minute < ?) +
		(SELECT COALESCE(sum(s.msgs), 0) FROM type_stats s WHERE s.device_id = d.id AND s.minute >= ? AND s.minute < ?)
		FROM devices d WHERE d.id IN `+in, append([]any{ms(rateFrom.Truncate(time.Minute)), to, ms(rateFrom.Truncate(time.Minute)), to}, idArgs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := make(map[string]Device, len(ids))
	for rows.Next() {
		var dv Device
		var hidden int
		var first, last int64
		if err := rows.Scan(&dv.ID, &dv.IP, &dv.Name, &dv.Group, &hidden, &first, &last, &dv.TotalMsgs, &dv.TotalBytes,
			&dv.BytesOnDisk, &dv.RecentMsgs); err != nil {
			return nil, err
		}
		dv.Hidden = hidden != 0
		dv.FirstSeen, dv.LastHeard = tm(first), tm(last)
		byID[dv.ID] = dv
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(ids))
	for _, id := range ids {
		if dv, ok := byID[id]; ok {
			out = append(out, dv)
		}
	}
	return out, nil
}
