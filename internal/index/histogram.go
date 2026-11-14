package index

import (
	"context"
	"encoding/json"
)

// Reads for the Events histogram's index source (SPEC §10.1.2): per-device
// stats summed into time buckets, each device's oldest remaining file, and the
// checkpoints of many files at once.

// OldestFiles is OldestFilesOf for syslog.
func (d *DB) OldestFiles(ctx context.Context, deviceIDs []string) (map[string]int64, error) {
	return d.OldestFilesOf(ctx, TypeSyslog, deviceIDs)
}

// OldestFilesOf returns, for each of deviceIDs that has files of the type, the
// lowest FirstReceived (Unix ms) of any of them.
func (d *DB) OldestFilesOf(ctx context.Context, typ string, deviceIDs []string) (map[string]int64, error) {
	out := map[string]int64{}
	if len(deviceIDs) == 0 {
		return out, nil
	}
	in, args := inList(deviceIDs)
	rows, err := d.db.QueryContext(ctx, `SELECT device_id, min(first_received) FROM files WHERE type = ? AND device_id IN `+in+
		` GROUP BY device_id`, append([]any{fileType(typ)}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var first int64
		if err := rows.Scan(&id, &first); err != nil {
			return nil, err
		}
		out[id] = first
	}
	return out, rows.Err()
}

// StatsBuckets sums the stored-message counts (msgs) of stats rows into
// buckets of size ms starting at origin: a row starting at s goes into bucket
// (s-origin)/size. Only rows of the devices in cutoffs count, and only those
// starting in [fromMs, toMs) and at or after the device's cutoff (Unix ms).
// With minuteOnly, only the per-minute table is read; otherwise both the
// minute and hourly tables (a message lives in exactly one row of the two).
func (d *DB) StatsBuckets(ctx context.Context, cutoffs map[string]int64, minuteOnly bool, fromMs, toMs, origin, size int64) (map[int64]int64, error) {
	return d.StatsBucketsOf(ctx, TypeSyslog, cutoffs, minuteOnly, fromMs, toMs, origin, size)
}

// StatsBucketsOf is StatsBuckets for one data type: syslog reads the stats
// tables, any other type its rows of type_stats (SPEC §11.1).
func (d *DB) StatsBucketsOf(ctx context.Context, typ string, cutoffs map[string]int64, minuteOnly bool, fromMs, toMs, origin, size int64) (map[int64]int64, error) {
	if t := fileType(typ); t != TypeSyslog {
		return d.typeStatsBuckets(ctx, t, cutoffs, minuteOnly, fromMs, toMs, origin, size)
	}
	out := map[int64]int64{}
	if len(cutoffs) == 0 || fromMs >= toMs || size <= 0 {
		return out, nil
	}
	b, err := json.Marshal(cutoffs)
	if err != nil {
		return nil, err
	}
	q := `SELECT (s.minute - ?) / ?, sum(s.msgs) FROM json_each(?) j JOIN stats s ON s.device_id = j.key
		WHERE s.minute >= ? AND s.minute < ? AND s.minute >= j.value GROUP BY 1`
	args := []any{origin, size, string(b), fromMs, toMs}
	if !minuteOnly {
		q = `SELECT (start - ?) / ?, sum(msgs) FROM (
			SELECT s.minute AS start, s.msgs AS msgs FROM json_each(?) j JOIN stats s ON s.device_id = j.key
				WHERE s.minute >= ? AND s.minute < ? AND s.minute >= j.value
			UNION ALL
			SELECT h.hour AS start, h.msgs AS msgs FROM json_each(?) j JOIN stats_hourly h ON h.device_id = j.key
				WHERE h.hour >= ? AND h.hour < ? AND h.hour >= j.value) GROUP BY 1`
		args = []any{origin, size, string(b), fromMs, toMs, string(b), fromMs, toMs}
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var i, n int64
		if err := rows.Scan(&i, &n); err != nil {
			return nil, err
		}
		out[i] += n
	}
	return out, rows.Err()
}

func (d *DB) typeStatsBuckets(ctx context.Context, typ string, cutoffs map[string]int64, minuteOnly bool, fromMs, toMs, origin, size int64) (map[int64]int64, error) {
	out := map[int64]int64{}
	if len(cutoffs) == 0 || fromMs >= toMs || size <= 0 {
		return out, nil
	}
	b, err := json.Marshal(cutoffs)
	if err != nil {
		return nil, err
	}
	q := `SELECT (s.minute - ?) / ?, sum(s.msgs) FROM json_each(?) j JOIN type_stats s ON s.device_id = j.key AND s.type = ?
		WHERE s.minute >= ? AND s.minute < ? AND s.minute >= j.value GROUP BY 1`
	args := []any{origin, size, string(b), typ, fromMs, toMs}
	if !minuteOnly {
		q = `SELECT (start - ?) / ?, sum(msgs) FROM (
			SELECT s.minute AS start, s.msgs AS msgs FROM json_each(?) j JOIN type_stats s ON s.device_id = j.key AND s.type = ?
				WHERE s.minute >= ? AND s.minute < ? AND s.minute >= j.value
			UNION ALL
			SELECT h.hour AS start, h.msgs AS msgs FROM json_each(?) j JOIN type_stats_hourly h ON h.device_id = j.key AND h.type = ?
				WHERE h.hour >= ? AND h.hour < ? AND h.hour >= j.value) GROUP BY 1`
		args = []any{origin, size, string(b), typ, fromMs, toMs, string(b), typ, fromMs, toMs}
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var i, n int64
		if err := rows.Scan(&i, &n); err != nil {
			return nil, err
		}
		out[i] += n
	}
	return out, rows.Err()
}

// DeviceTypes returns, per device, the data types it has files of and their
// stored lines (Device.Types, lines_by_type).
func (d *DB) DeviceTypes(ctx context.Context, deviceIDs []string) (map[string]map[string]int64, error) {
	out := map[string]map[string]int64{}
	q := `SELECT device_id, type, sum(lines) FROM files`
	var args []any
	if deviceIDs != nil {
		if len(deviceIDs) == 0 {
			return out, nil
		}
		in, a := inList(deviceIDs)
		q += ` WHERE device_id IN ` + in
		args = a
	}
	rows, err := d.db.QueryContext(ctx, q+` GROUP BY device_id, type`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, typ string
		var n int64
		if err := rows.Scan(&id, &typ, &n); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]int64{}
		}
		out[id][typ] = n
	}
	return out, rows.Err()
}

// HasType reports whether any file of the type is indexed.
func (d *DB) HasType(ctx context.Context, typ string) (bool, error) {
	var n int
	err := d.db.QueryRowContext(ctx, `SELECT count(*) FROM (SELECT 1 FROM files WHERE type = ? LIMIT 1)`, fileType(typ)).Scan(&n)
	return n > 0, err
}

// CheckpointsFor returns the checkpoints of each of fileIDs, in offset order.
// Files without checkpoints are absent.
func (d *DB) CheckpointsFor(ctx context.Context, fileIDs []int64) (map[int64][]Checkpoint, error) {
	out := map[int64][]Checkpoint{}
	if len(fileIDs) == 0 {
		return out, nil
	}
	b, err := json.Marshal(fileIDs)
	if err != nil {
		return nil, err
	}
	rows, err := d.db.QueryContext(ctx, `SELECT c.file_id, c.offset, c.line, c.received FROM json_each(?) j
		JOIN checkpoints c ON c.file_id = j.value ORDER BY c.file_id, c.offset`, string(b))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, r int64
		var c Checkpoint
		if err := rows.Scan(&id, &c.Offset, &c.Line, &r); err != nil {
			return nil, err
		}
		c.Received = tm(r)
		out[id] = append(out[id], c)
	}
	return out, rows.Err()
}
