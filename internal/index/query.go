package index

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

const deviceCols = `d.id, d.ip, d.name, d.grp, d.hidden, d.first_seen, d.last_heard, d.total_msgs, d.total_bytes,
	COALESCE((SELECT sum(f.size) FROM files f WHERE f.device_id = d.id), 0)`

func scanDevice(r interface{ Scan(...any) error }) (Device, error) {
	var dv Device
	var hidden int
	var first, last int64
	err := r.Scan(&dv.ID, &dv.IP, &dv.Name, &dv.Group, &hidden, &first, &last, &dv.TotalMsgs, &dv.TotalBytes, &dv.BytesOnDisk)
	dv.Hidden = hidden != 0
	dv.FirstSeen, dv.LastHeard = tm(first), tm(last)
	return dv, err
}

// ListDevices returns every device (hidden ones included), ordered by ID.
func (d *DB) ListDevices(ctx context.Context) ([]Device, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+deviceCols+` FROM devices d ORDER BY d.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		dv, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, dv)
	}
	return out, rows.Err()
}

// Device returns one device, or ErrNotFound.
func (d *DB) Device(ctx context.Context, id string) (Device, error) {
	dv, err := scanDevice(d.db.QueryRowContext(ctx, `SELECT `+deviceCols+` FROM devices d WHERE d.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	return dv, err
}

// statsUnion selects (device_id, start, msgs, bytes, truncated, dropped) from both
// stats tables over a range. Each table's rows are taken whole: a minute bucket counts
// when it starts in [from truncated to the minute, to), an hourly bucket when it starts
// in [from truncated to the hour, to). A message lives in exactly one bucket (the
// rollup moves rows in one transaction), so nothing is counted twice. Within the last
// MinuteRetention the result is exact to the minute; further back, to the hour.
func statsUnion(deviceIDs []string, from, to time.Time) (string, []any, bool) {
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
			return "", nil, false
		}
		in, a := inList(deviceIDs)
		devWhere, devArgs = ` AND device_id IN `+in, a
	}
	// Every data type counts (SPEC §11.1): syslog's tables and type_stats.
	q := `SELECT device_id, minute AS start, msgs, bytes, truncated, dropped FROM stats WHERE minute >= ? AND minute < ?` + devWhere +
		` UNION ALL SELECT device_id, hour AS start, msgs, bytes, truncated, dropped FROM stats_hourly WHERE hour >= ? AND hour < ?` + devWhere +
		` UNION ALL SELECT device_id, minute AS start, msgs, bytes, truncated, dropped FROM type_stats WHERE minute >= ? AND minute < ?` + devWhere +
		` UNION ALL SELECT device_id, hour AS start, msgs, bytes, truncated, dropped FROM type_stats_hourly WHERE hour >= ? AND hour < ?` + devWhere
	args := append([]any{fromMin, toMs}, devArgs...)
	args = append(append(args, fromHour, toMs), devArgs...)
	args = append(append(args, fromMin, toMs), devArgs...)
	args = append(append(args, fromHour, toMs), devArgs...)
	return q, args, true
}

// Counts returns the counts of deviceIDs (nil means all) over [from, to) (zero times
// are unbounded), spanning the minute and hourly buckets; see statsUnion for how the
// range edges are resolved. For dropped_24h use from = now-24h: that range is still
// in per-minute buckets, so it is exact to the minute.
func (d *DB) Counts(ctx context.Context, deviceIDs []string, from, to time.Time) (Counts, error) {
	var c Counts
	q, args, ok := statsUnion(deviceIDs, from, to)
	if !ok {
		return c, nil
	}
	err := d.db.QueryRowContext(ctx, `SELECT COALESCE(sum(msgs),0), COALESCE(sum(bytes),0), COALESCE(sum(truncated),0),
		COALESCE(sum(dropped),0) FROM (`+q+`)`, args...).Scan(&c.Msgs, &c.Bytes, &c.Truncated, &c.Dropped)
	return c, err
}

// TotalCounts is Counts for all devices.
func (d *DB) TotalCounts(ctx context.Context, from, to time.Time) (Counts, error) {
	return d.Counts(ctx, nil, from, to)
}

// DeviceCounts returns each device's counts over [from, to), like Counts. Devices
// with no activity in the range are absent.
func (d *DB) DeviceCounts(ctx context.Context, from, to time.Time) (map[string]Counts, error) {
	q, args, _ := statsUnion(nil, from, to)
	rows, err := d.db.QueryContext(ctx, `SELECT device_id, sum(msgs), sum(bytes), sum(truncated), sum(dropped)
		FROM (`+q+`) GROUP BY device_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]Counts{}
	for rows.Next() {
		var id string
		var c Counts
		if err := rows.Scan(&id, &c.Msgs, &c.Bytes, &c.Truncated, &c.Dropped); err != nil {
			return nil, err
		}
		out[id] = c
	}
	return out, rows.Err()
}

// HourSeries returns one entry per hour in [from, to), oldest first, with missing
// hours as zeros, summed over deviceIDs (nil means all). It spans both tables: recent
// hours come from the per-minute buckets not yet rolled up. from is truncated to the
// hour. For a 7-day chart use from = now-7d, to = now.
func (d *DB) HourSeries(ctx context.Context, deviceIDs []string, from, to time.Time) ([]HourCounts, error) {
	from = from.UTC().Truncate(time.Hour)
	if !to.After(from) {
		return nil, nil
	}
	n := int((to.Sub(from) + time.Hour - 1) / time.Hour)
	out := make([]HourCounts, n)
	for i := range out {
		out[i].Hour = from.Add(time.Duration(i) * time.Hour)
	}
	q, args, ok := statsUnion(deviceIDs, from, to)
	if !ok {
		return out, nil
	}
	rows, err := d.db.QueryContext(ctx, `SELECT (start / 3600000) * 3600000, sum(msgs), sum(bytes), sum(truncated), sum(dropped)
		FROM (`+q+`) GROUP BY start / 3600000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h int64
		var c Counts
		if err := rows.Scan(&h, &c.Msgs, &c.Bytes, &c.Truncated, &c.Dropped); err != nil {
			return nil, err
		}
		if i := int(tm(h).Sub(from) / time.Hour); i >= 0 && i < n {
			out[i].Counts = c
		}
	}
	return out, rows.Err()
}

// MinuteSeries returns one entry per minute in [from, to), oldest first, with missing
// minutes as zeros, summed over deviceIDs (nil means all devices). It reads only the
// per-minute buckets, so it covers the last MinuteRetention (24 h); older minutes read
// as zero once rolled up (use HourSeries). from is truncated to the minute. For the dashboard sparkline, use from = now-60m, to = now truncated
// to the minute, and divide Msgs by 60 for msgs/s.
func (d *DB) MinuteSeries(ctx context.Context, deviceIDs []string, from, to time.Time) ([]MinuteCounts, error) {
	from = from.Truncate(time.Minute).UTC()
	if !to.After(from) {
		return nil, nil
	}
	sel := func(table string) (string, []any) {
		q := `SELECT minute, msgs, bytes, truncated, dropped FROM ` + table + ` WHERE minute >= ? AND minute < ?`
		args := []any{ms(from), ms(to)}
		if deviceIDs != nil {
			ids := deviceIDs
			if len(ids) == 0 {
				ids = []string{""}
			}
			in, inArgs := inList(ids)
			q += ` AND device_id IN ` + in
			args = append(args, inArgs...)
		}
		return q, args
	}
	// Every data type counts (SPEC §11.1).
	q1, a1 := sel("stats")
	q2, a2 := sel("type_stats")
	q := `SELECT minute, sum(msgs), sum(bytes), sum(truncated), sum(dropped) FROM (` + q1 + ` UNION ALL ` + q2 + `) GROUP BY minute`
	args := append(a1, a2...)
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	n := int((to.Sub(from) + time.Minute - 1) / time.Minute)
	out := make([]MinuteCounts, n)
	for i := range out {
		out[i].Minute = from.Add(time.Duration(i) * time.Minute)
	}
	for rows.Next() {
		var m int64
		var c Counts
		if err := rows.Scan(&m, &c.Msgs, &c.Bytes, &c.Truncated, &c.Dropped); err != nil {
			return nil, err
		}
		if i := int(tm(m).Sub(from) / time.Minute); i >= 0 && i < n {
			out[i].Counts = c
		}
	}
	return out, rows.Err()
}

const fileCols = `id, device_id, path, day, part, first_received, last_received, size, raw_size, lines, compressed, type`

func scanFile(r interface{ Scan(...any) error }) (File, error) {
	var f File
	var first, last int64
	var comp int
	err := r.Scan(&f.ID, &f.DeviceID, &f.Path, &f.Day, &f.Part, &first, &last, &f.Size, &f.RawSize, &f.Lines, &comp, &f.Type)
	f.FirstReceived, f.LastReceived, f.Compressed = tm(first), tm(last), comp != 0
	return f, err
}

func (d *DB) queryFiles(ctx context.Context, q string, args ...any) ([]File, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// File returns a file by ID, or ErrNotFound.
func (d *DB) File(ctx context.Context, id int64) (File, error) {
	f, err := scanFile(d.db.QueryRowContext(ctx, `SELECT `+fileCols+` FROM files WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	return f, err
}

// FileByPath returns a file by its data-dir-relative path, or ErrNotFound.
func (d *DB) FileByPath(ctx context.Context, path string) (File, error) {
	f, err := scanFile(d.db.QueryRowContext(ctx, `SELECT `+fileCols+` FROM files WHERE path = ?`, path))
	if errors.Is(err, sql.ErrNoRows) {
		return File{}, ErrNotFound
	}
	return f, err
}

// Files returns a device's files ("" for all devices), ordered by device and
// FirstReceived.
func (d *DB) Files(ctx context.Context, deviceID string) ([]File, error) {
	if deviceID == "" {
		return d.queryFiles(ctx, `SELECT `+fileCols+` FROM files ORDER BY device_id, first_received, id`)
	}
	return d.queryFiles(ctx, `SELECT `+fileCols+` FROM files WHERE device_id = ? ORDER BY first_received, id`, deviceID)
}

// FilesInRange is FilesInRangeOf for syslog, the 1.1 meaning.
func (d *DB) FilesInRange(ctx context.Context, deviceIDs []string, from, to time.Time) ([]FileSpan, error) {
	return d.FilesInRangeOf(ctx, TypeSyslog, deviceIDs, from, to)
}

// FilesInRangeOf returns the files of one data type ("" means syslog) of
// deviceIDs (nil means all) holding any line received in [from, to] (a zero
// from or to is unbounded), ordered by device and FirstReceived, each with the
// checkpoint to start reading at for from. Lines before Start are all older
// than from; lines after it still need filtering.
func (d *DB) FilesInRangeOf(ctx context.Context, typ string, deviceIDs []string, from, to time.Time) ([]FileSpan, error) {
	q := `SELECT ` + fileCols + ` FROM files WHERE type = ?`
	args := []any{fileType(typ)}
	if !to.IsZero() {
		q += ` AND first_received <= ?`
		args = append(args, ms(to))
	}
	if !from.IsZero() {
		q += ` AND last_received >= ?`
		args = append(args, ms(from))
	}
	if deviceIDs != nil {
		if len(deviceIDs) == 0 {
			return nil, nil
		}
		in, inArgs := inList(deviceIDs)
		q += ` AND device_id IN ` + in
		args = append(args, inArgs...)
	}
	q += ` ORDER BY device_id, first_received, id`
	files, err := d.queryFiles(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	out := make([]FileSpan, len(files))
	for i, f := range files {
		out[i].File = f
		if !from.IsZero() && f.FirstReceived.Before(from) {
			cp, err := d.SeekCheckpoint(ctx, f.ID, from)
			if err != nil {
				return nil, err
			}
			out[i].Start = cp
		}
	}
	return out, nil
}

// Checkpoints returns a file's checkpoints in offset order.
func (d *DB) Checkpoints(ctx context.Context, fileID int64) ([]Checkpoint, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT offset, line, received FROM checkpoints WHERE file_id = ? ORDER BY offset`, fileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var c Checkpoint
		var r int64
		if err := rows.Scan(&c.Offset, &c.Line, &r); err != nil {
			return nil, err
		}
		c.Received = tm(r)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SeekCheckpoint returns the last checkpoint of a file whose Received is before t, so
// that every line before it is older than t. With none, it returns offset 0.
func (d *DB) SeekCheckpoint(ctx context.Context, fileID int64, t time.Time) (Checkpoint, error) {
	var c Checkpoint
	var r int64
	err := d.db.QueryRowContext(ctx, `SELECT offset, line, received FROM checkpoints
		WHERE file_id = ? AND received < ? ORDER BY offset DESC LIMIT 1`, fileID, ms(t)).Scan(&c.Offset, &c.Line, &r)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, nil
	}
	c.Received = tm(r)
	return c, err
}

// LastCheckpoint returns a file's newest checkpoint, and false if it has none.
func (d *DB) LastCheckpoint(ctx context.Context, fileID int64) (Checkpoint, bool, error) {
	var c Checkpoint
	var r int64
	err := d.db.QueryRowContext(ctx, `SELECT offset, line, received FROM checkpoints
		WHERE file_id = ? ORDER BY offset DESC LIMIT 1`, fileID).Scan(&c.Offset, &c.Line, &r)
	if errors.Is(err, sql.ErrNoRows) {
		return Checkpoint{}, false, nil
	}
	c.Received = tm(r)
	return c, err == nil, err
}

// Events returns events with from <= Time < to (zero times are unbounded), oldest
// first, at most limit (0 means no limit).
func (d *DB) Events(ctx context.Context, from, to time.Time, limit int) ([]Event, error) {
	q, args := rangeWhere(`SELECT id, time, level, kind, device_id, text, source FROM events`, "time", from, to)
	q += ` ORDER BY time, id`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var t int64
		var level, kind, source string
		if err := rows.Scan(&e.ID, &t, &level, &kind, &e.DeviceID, &e.Text, &source); err != nil {
			return nil, err
		}
		e.Time, e.Level, e.Kind, e.Source = tm(t), Level(level), Kind(kind), Source(source)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Deletions returns the storage history with from <= Time < to (zero times are
// unbounded), newest first, at most limit (0 means no limit).
func (d *DB) Deletions(ctx context.Context, from, to time.Time, limit int) ([]Deletion, error) {
	q, args := rangeWhere(`SELECT id, time, file, device_id, bytes, reason, type FROM deletions`, "time", from, to)
	q += ` ORDER BY time DESC, id DESC`
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Deletion
	for rows.Next() {
		var x Deletion
		var t int64
		var reason string
		if err := rows.Scan(&x.ID, &t, &x.File, &x.DeviceID, &x.Bytes, &reason, &x.Type); err != nil {
			return nil, err
		}
		x.Time, x.Reason = tm(t), readReason(reason, x.Type)
		out = append(out, x)
	}
	return out, rows.Err()
}

func rangeWhere(q, col string, from, to time.Time) (string, []any) {
	var args []any
	q += ` WHERE 1=1`
	if !from.IsZero() {
		q += ` AND ` + col + ` >= ?`
		args = append(args, ms(from))
	}
	if !to.IsZero() {
		q += ` AND ` + col + ` < ?`
		args = append(args, ms(to))
	}
	return q, args
}

// LatestEvent returns the newest event of kind for deviceID ("" for events
// that name no device); ok is false when there's none.
func (d *DB) LatestEvent(ctx context.Context, kind Kind, deviceID string) (e Event, ok bool, err error) {
	var t int64
	var level, k, source string
	err = d.db.QueryRowContext(ctx, `SELECT id, time, level, kind, device_id, text, source FROM events
		WHERE kind = ? AND device_id = ? ORDER BY time DESC, id DESC LIMIT 1`, string(kind), deviceID).
		Scan(&e.ID, &t, &level, &k, &e.DeviceID, &e.Text, &source)
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, false, nil
	}
	if err != nil {
		return Event{}, false, err
	}
	e.Time, e.Level, e.Kind, e.Source = tm(t), Level(level), Kind(k), Source(source)
	return e, true, nil
}
