package index

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// The flow type's index tables (SPEC §13.2): flow_segments has one row per
// .wsf segment (its flow-time range, totals, sampling rates and domains), so
// totals and file selection need no file reads; flow_minute has each
// segment's per-minute totals by flow time, so the unfiltered flow histogram
// and the timeline strip need none either. Both are derived: they live as long
// as their segment's files row, and Reindex rebuilds them from the footers.

// TypeFlow is the flow data type's name in files.type.
const TypeFlow = "flow"

// FlowSegment is a segment's flow_segments row.
type FlowSegment struct {
	Path     string // the files row's path
	DeviceID string
	// Start and End are the lowest flow start and highest flow end (unix
	// ms) of the segment's records.
	Start, End     int64
	Records        int64
	Bytes, Packets int64 // the no-double-count sums (SPEC §13.2.1)
	// Scaled sums; ScaledComplete is false when some record's sampling was
	// unknown (the scaled values are then a lower bound).
	BytesScaled, PacketsScaled int64
	ScaledComplete             bool
	Samplings                  []uint32
	Domains                    []uint32
	Raw                        int64 // raw sets (no_template + malformed)
	NoTemplate, Malformed      int64
	Late                       int64
	Closed                     bool
}

// FlowMinute is one segment's totals for one flow-time minute. A record counts
// once, in the minute of its end; its bytes and packets are spread over the
// minutes it covers.
type FlowMinute struct {
	Path     string
	DeviceID string
	Minute   int64 // unix ms at the minute's start
	Records  int64
	Bytes    int64
	Packets  int64
	// The scaled sums, and whether any record behind them had unknown sampling.
	BytesScaled, PacketsScaled int64
	Unknown                    bool
}

const flowMigration = `
CREATE TABLE flow_segments (
	path            TEXT PRIMARY KEY,
	device_id       TEXT NOT NULL,
	start           INTEGER NOT NULL,
	end             INTEGER NOT NULL,
	records         INTEGER NOT NULL,
	bytes           INTEGER NOT NULL,
	packets         INTEGER NOT NULL,
	bytes_scaled    INTEGER NOT NULL,
	packets_scaled  INTEGER NOT NULL,
	scaled_complete INTEGER NOT NULL,
	samplings       TEXT NOT NULL DEFAULT '',
	domains         TEXT NOT NULL DEFAULT '',
	raw             INTEGER NOT NULL DEFAULT 0,
	no_template     INTEGER NOT NULL DEFAULT 0,
	malformed       INTEGER NOT NULL DEFAULT 0,
	late            INTEGER NOT NULL DEFAULT 0,
	closed          INTEGER NOT NULL DEFAULT 0
) WITHOUT ROWID;
CREATE INDEX flow_segments_device_time ON flow_segments (device_id, end, start);
CREATE INDEX flow_segments_end ON flow_segments (end, path);
CREATE INDEX flow_segments_start ON flow_segments (start, path);
CREATE TABLE flow_minute (
	device_id      TEXT NOT NULL,
	minute         INTEGER NOT NULL,
	path           TEXT NOT NULL,
	records        INTEGER NOT NULL,
	bytes          INTEGER NOT NULL,
	packets        INTEGER NOT NULL,
	bytes_scaled   INTEGER NOT NULL,
	packets_scaled INTEGER NOT NULL,
	unknown        INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (device_id, minute, path)
) WITHOUT ROWID;
CREATE INDEX flow_minute_minute ON flow_minute (minute);
CREATE INDEX flow_minute_path ON flow_minute (path);
`

const upsertFlowSegmentSQL = `
INSERT INTO flow_segments (path, device_id, start, end, records, bytes, packets, bytes_scaled, packets_scaled,
	scaled_complete, samplings, domains, raw, no_template, malformed, late, closed)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (path) DO UPDATE SET
	device_id = excluded.device_id, start = excluded.start, end = excluded.end, records = excluded.records,
	bytes = excluded.bytes, packets = excluded.packets, bytes_scaled = excluded.bytes_scaled,
	packets_scaled = excluded.packets_scaled, scaled_complete = excluded.scaled_complete,
	samplings = excluded.samplings, domains = excluded.domains, raw = excluded.raw,
	no_template = excluded.no_template, malformed = excluded.malformed, late = excluded.late, closed = excluded.closed`

const addFlowMinuteSQL = `
INSERT INTO flow_minute (device_id, minute, path, records, bytes, packets, bytes_scaled, packets_scaled, unknown)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (device_id, minute, path) DO UPDATE SET
	records = records + excluded.records, bytes = bytes + excluded.bytes, packets = packets + excluded.packets,
	bytes_scaled = bytes_scaled + excluded.bytes_scaled, packets_scaled = packets_scaled + excluded.packets_scaled,
	unknown = max(unknown, excluded.unknown)`

func joinU32(v []uint32) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.FormatUint(uint64(x), 10)
	}
	return strings.Join(parts, ",")
}

func splitU32(s string) []uint32 {
	if s == "" {
		return nil
	}
	var out []uint32
	for _, p := range strings.Split(s, ",") {
		if n, err := strconv.ParseUint(p, 10, 32); err == nil {
			out = append(out, uint32(n))
		}
	}
	return out
}

func (s *stmts) flowSegment(f *FlowSegment) error {
	_, err := s.exec(upsertFlowSegmentSQL, f.Path, f.DeviceID, f.Start, f.End, f.Records, f.Bytes, f.Packets,
		f.BytesScaled, f.PacketsScaled, b2i(f.ScaledComplete), joinU32(f.Samplings), joinU32(f.Domains), f.Raw,
		f.NoTemplate, f.Malformed, f.Late, b2i(f.Closed))
	return err
}

func (s *stmts) flowMinute(m FlowMinute) error {
	_, err := s.exec(addFlowMinuteSQL, m.DeviceID, m.Minute, m.Path, m.Records, m.Bytes, m.Packets, m.BytesScaled,
		m.PacketsScaled, b2i(m.Unknown))
	return err
}

// deleteFlowRows removes a segment's derived rows (with its files row).
func (s *stmts) deleteFlowRows(path string) error {
	if _, err := s.exec(`DELETE FROM flow_segments WHERE path = ?`, path); err != nil {
		return err
	}
	_, err := s.exec(`DELETE FROM flow_minute WHERE path = ?`, path)
	return err
}

const flowSegCols = `path, device_id, start, end, records, bytes, packets, bytes_scaled, packets_scaled, scaled_complete,
	samplings, domains, raw, no_template, malformed, late, closed`

func scanFlowSegment(r interface{ Scan(...any) error }) (FlowSegment, error) {
	var f FlowSegment
	var sc, closed int
	var samp, doms string
	err := r.Scan(&f.Path, &f.DeviceID, &f.Start, &f.End, &f.Records, &f.Bytes, &f.Packets, &f.BytesScaled,
		&f.PacketsScaled, &sc, &samp, &doms, &f.Raw, &f.NoTemplate, &f.Malformed, &f.Late, &closed)
	f.ScaledComplete, f.Closed = sc != 0, closed != 0
	f.Samplings, f.Domains = splitU32(samp), splitU32(doms)
	return f, err
}

// FlowSegments returns the segments of deviceIDs (nil means all) whose flow
// time [start, end] overlaps [from, to] (zero bounds are open), newest end
// first. Segments with no records yet are left out.
func (d *DB) FlowSegments(ctx context.Context, deviceIDs []string, from, to time.Time) ([]FlowSegment, error) {
	where, args, ok := flowSegWhere(deviceIDs, from, to)
	if !ok {
		return nil, nil
	}
	return d.queryFlowSegments(ctx, `SELECT `+flowSegCols+` FROM flow_segments WHERE `+where+` ORDER BY end DESC, path DESC`, args...)
}

// FlowSegmentsNoTemplate returns FlowSegments' rows that hold raw sets kept
// for lack of a template (no_template > 0), by path.
func (d *DB) FlowSegmentsNoTemplate(ctx context.Context, deviceIDs []string, from, to time.Time) ([]FlowSegment, error) {
	where, args, ok := flowSegWhere(deviceIDs, from, to)
	if !ok {
		return nil, nil
	}
	return d.queryFlowSegments(ctx, `SELECT `+flowSegCols+` FROM flow_segments WHERE `+where+` AND no_template > 0 ORDER BY path`, args...)
}

// flowSegWhere is FlowSegments' condition; ok is false for an empty device
// list (no rows).
func flowSegWhere(deviceIDs []string, from, to time.Time) (string, []any, bool) {
	q := `records > 0`
	var args []any
	if !to.IsZero() {
		q += ` AND start <= ?`
		args = append(args, ms(to))
	}
	if !from.IsZero() {
		q += ` AND end >= ?`
		args = append(args, ms(from))
	}
	if deviceIDs != nil {
		if len(deviceIDs) == 0 {
			return "", nil, false
		}
		in, inArgs := inList(deviceIDs)
		q += ` AND device_id IN ` + in
		args = append(args, inArgs...)
	}
	return q, args, true
}

// FlowSegCursor is a FlowSegmentsPage position: the last row's order key
// (its end, or its start for an ascending page) and path.
type FlowSegCursor struct {
	Key  int64
	Path string
}

// FlowSegmentsPage returns at most limit of FlowSegments' rows after c (nil:
// from the first): newest end first, or with asc lowest start first. A flow
// query plans a window in pages, so its memory doesn't grow with the window.
func (d *DB) FlowSegmentsPage(ctx context.Context, deviceIDs []string, from, to time.Time, asc bool, c *FlowSegCursor,
	limit int) ([]FlowSegment, error) {
	q, args, ok := flowSegPageSQL(deviceIDs, from, to, asc, c, limit)
	if !ok {
		return nil, nil
	}
	return d.queryFlowSegments(ctx, q, args...)
}

// flowSegPageSQL is FlowSegmentsPage's query. Without a device list it walks
// flow_segments_end or flow_segments_start in order, so a page costs its own
// rows, not a sort of the table.
func flowSegPageSQL(deviceIDs []string, from, to time.Time, asc bool, c *FlowSegCursor, limit int) (string, []any, bool) {
	where, args, ok := flowSegWhere(deviceIDs, from, to)
	if !ok {
		return "", nil, false
	}
	order := ` ORDER BY end DESC, path DESC`
	if asc {
		order = ` ORDER BY start ASC, path ASC`
	}
	if c != nil {
		// Row values, so the order index serves the cursor as a range.
		if asc {
			where += ` AND (start, path) > (?, ?)`
		} else {
			where += ` AND (end, path) < (?, ?)`
		}
		args = append(args, c.Key, c.Path)
	}
	args = append(args, limit)
	return `SELECT ` + flowSegCols + ` FROM flow_segments WHERE ` + where + order + ` LIMIT ?`, args, true
}

// FlowSegmentsCount is how many rows FlowSegments would return and their
// records.
func (d *DB) FlowSegmentsCount(ctx context.Context, deviceIDs []string, from, to time.Time) (n, records int64, err error) {
	where, args, ok := flowSegWhere(deviceIDs, from, to)
	if !ok {
		return 0, 0, nil
	}
	err = d.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(records), 0) FROM flow_segments WHERE `+where, args...).
		Scan(&n, &records)
	return n, records, err
}

// FlowDevices is the device IDs with segments in FlowSegments' range, sorted.
func (d *DB) FlowDevices(ctx context.Context, deviceIDs []string, from, to time.Time) ([]string, error) {
	where, args, ok := flowSegWhere(deviceIDs, from, to)
	if !ok {
		return nil, nil
	}
	rows, err := d.db.QueryContext(ctx, `SELECT DISTINCT device_id FROM flow_segments WHERE `+where+` ORDER BY device_id`, args...)
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

// FlowSegmentsByPath returns the rows of the segments at paths that exist,
// by path (a flow plan's open segments: their rows change while it pages).
func (d *DB) FlowSegmentsByPath(ctx context.Context, paths []string) ([]FlowSegment, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	in, args := inList(paths)
	return d.queryFlowSegments(ctx, `SELECT `+flowSegCols+` FROM flow_segments WHERE path IN `+in+` ORDER BY path`, args...)
}

// AllFlowSegments returns every flow_segments row, by path.
func (d *DB) AllFlowSegments(ctx context.Context) ([]FlowSegment, error) {
	return d.queryFlowSegments(ctx, `SELECT `+flowSegCols+` FROM flow_segments ORDER BY path`)
}

// FlowSegmentsWithRaw returns at most limit segments of deviceIDs (nil: all)
// holding raw sets whose received times (their files row's, which cover the
// raw sets') overlap [from, to) (zero bounds are open), by path after after
// (a page's last path; "" from the first). The raw sets' times are read from
// the files.
func (d *DB) FlowSegmentsWithRaw(ctx context.Context, deviceIDs []string, from, to time.Time, after string,
	limit int) ([]FlowSegment, error) {
	q := `SELECT ` + flowSegCols + ` FROM flow_segments WHERE raw > 0 AND path > ?`
	args := []any{after}
	if !from.IsZero() || !to.IsZero() {
		q += ` AND path IN (SELECT path FROM files WHERE 1`
		if !to.IsZero() {
			q += ` AND first_received < ?`
			args = append(args, ms(to))
		}
		if !from.IsZero() {
			q += ` AND last_received >= ?`
			args = append(args, ms(from))
		}
		q += `)`
	}
	if deviceIDs != nil {
		in, inArgs := inList(deviceIDs)
		q += ` AND device_id IN ` + in
		args = append(args, inArgs...)
	}
	args = append(args, limit)
	return d.queryFlowSegments(ctx, q+` ORDER BY path LIMIT ?`, args...)
}

func (d *DB) queryFlowSegments(ctx context.Context, q string, args ...any) ([]FlowSegment, error) {
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FlowSegment
	for rows.Next() {
		f, err := scanFlowSegment(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// FlowBucket is a histogram bucket's flow totals.
type FlowBucket struct {
	Records, Bytes, Packets    int64
	BytesScaled, PacketsScaled int64
	Unknown                    bool // some record behind the scaled sums had unknown sampling
}

// Add adds o to b.
func (b *FlowBucket) Add(o FlowBucket) {
	b.Records += o.Records
	b.Bytes += o.Bytes
	b.Packets += o.Packets
	b.BytesScaled += o.BytesScaled
	b.PacketsScaled += o.PacketsScaled
	b.Unknown = b.Unknown || o.Unknown
}

// FlowMinuteBuckets sums flow_minute rows of deviceIDs (nil: all) for minutes
// in [fromMs, toMs) into buckets of size ms from origin, per device when
// perDevice is set (the key "" otherwise).
func (d *DB) FlowMinuteBuckets(ctx context.Context, deviceIDs []string, fromMs, toMs, origin, size int64, perDevice bool) (map[string]map[int64]FlowBucket, error) {
	out := map[string]map[int64]FlowBucket{}
	if fromMs >= toMs || size <= 0 {
		return out, nil
	}
	q := `SELECT device_id, minute, sum(records), sum(bytes), sum(packets), sum(bytes_scaled), sum(packets_scaled), max(unknown)
		FROM flow_minute WHERE minute >= ? AND minute < ?`
	args := []any{fromMs - fromMs%60000, toMs}
	if deviceIDs != nil {
		if len(deviceIDs) == 0 {
			return out, nil
		}
		in, inArgs := inList(deviceIDs)
		q += ` AND device_id IN ` + in
		args = append(args, inArgs...)
	}
	q += ` GROUP BY device_id, minute`
	rows, err := d.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var minute int64
		var b FlowBucket
		var unk int
		if err := rows.Scan(&id, &minute, &b.Records, &b.Bytes, &b.Packets, &b.BytesScaled, &b.PacketsScaled, &unk); err != nil {
			return nil, err
		}
		if minute < fromMs-fromMs%60000 || minute >= toMs {
			continue
		}
		b.Unknown = unk != 0
		key := ""
		if perDevice {
			key = id
		}
		m := out[key]
		if m == nil {
			m = map[int64]FlowBucket{}
			out[key] = m
		}
		bk := origin + floorDiv(minute-origin, size)*size
		x := m[bk]
		x.Add(b)
		m[bk] = x
	}
	return out, rows.Err()
}

// FlowDeviceTotals are the window totals of flow_minute rows per device.
func (d *DB) FlowDeviceTotals(ctx context.Context, deviceIDs []string, fromMs, toMs int64) (map[string]FlowBucket, error) {
	m, err := d.FlowMinuteBuckets(ctx, deviceIDs, fromMs, toMs, 0, 1<<62, true)
	if err != nil {
		return nil, err
	}
	out := map[string]FlowBucket{}
	for id, b := range m {
		var t FlowBucket
		for _, v := range b {
			t.Add(v)
		}
		out[id] = t
	}
	return out, nil
}

// FlowBytesOnDisk returns the bytes of flow segments per device, from files.
func (d *DB) FlowBytesOnDisk(ctx context.Context) (map[string]int64, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT device_id, sum(size) FROM files WHERE type = ? GROUP BY device_id`, TypeFlow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var id string
		var n int64
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// replaceFlowRows is Reindex's rebuild of a segment's derived rows.
func (s *stmts) replaceFlowRows(f *FlowSegment, mins []FlowMinute) error {
	if err := s.deleteFlowRows(f.Path); err != nil {
		return err
	}
	if err := s.flowSegment(f); err != nil {
		return err
	}
	for _, m := range mins {
		if err := s.flowMinute(m); err != nil {
			return err
		}
	}
	return nil
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// TypeDeviceBytes sums a type's stored bytes per device over [from, to) from
// type_stats and type_stats_hourly (a minute lives in one of the two).
func (d *DB) TypeDeviceBytes(ctx context.Context, typ string, from, to time.Time) (map[string]int64, error) {
	out := map[string]int64{}
	for _, q := range []string{
		`SELECT device_id, sum(bytes) FROM type_stats WHERE type = ? AND minute >= ? AND minute < ? GROUP BY device_id`,
		`SELECT device_id, sum(bytes) FROM type_stats_hourly WHERE type = ? AND hour >= ? AND hour < ? GROUP BY device_id`,
	} {
		rows, err := d.db.QueryContext(ctx, q, typ, ms(from), ms(to))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var n int64
			if err := rows.Scan(&id, &n); err != nil {
				rows.Close()
				return nil, err
			}
			out[id] += n
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
