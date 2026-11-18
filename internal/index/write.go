package index

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

const upsertFileSQL = `
INSERT INTO files (device_id, path, day, part, first_received, last_received, size, raw_size, lines, compressed, type)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (path) DO UPDATE SET
	device_id = excluded.device_id, type = excluded.type, day = excluded.day, part = excluded.part,
	first_received = excluded.first_received, last_received = excluded.last_received,
	size = excluded.size, raw_size = excluded.raw_size, lines = excluded.lines,
	compressed = excluded.compressed
RETURNING id`

const insertCheckpointSQL = `INSERT OR IGNORE INTO checkpoints (file_id, offset, line, received) VALUES (?, ?, ?, ?)`

const upsertStatsSQL = `
INSERT INTO stats (device_id, minute, msgs, bytes, truncated, dropped) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (device_id, minute) DO UPDATE SET
	msgs = msgs + excluded.msgs, bytes = bytes + excluded.bytes,
	truncated = truncated + excluded.truncated, dropped = dropped + excluded.dropped`

const upsertDeviceActivitySQL = `
INSERT INTO devices (id, ip, first_seen, last_heard, total_msgs, total_bytes) VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT (id) DO UPDATE SET
	first_seen = min(first_seen, excluded.first_seen),
	last_heard = max(last_heard, excluded.last_heard),
	total_msgs = total_msgs + excluded.total_msgs,
	total_bytes = total_bytes + excluded.total_bytes`

const upsertTypeStatsSQL = `
INSERT INTO type_stats (device_id, type, minute, msgs, bytes, truncated, dropped, late, no_template, malformed, seq_gaps,
	seq_lost, duplicates, off_ahead, off_behind, off_max_ahead_ms, off_max_behind_ms, flow_counted)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
ON CONFLICT (device_id, type, minute) DO UPDATE SET
	msgs = msgs + excluded.msgs, bytes = bytes + excluded.bytes,
	truncated = truncated + excluded.truncated, dropped = dropped + excluded.dropped,` + flowCountsUpsert

// flowCountsUpsert adds a stats row's flow counts (a row from before
// they existed stays flow_counted = 0: that minute is only partly counted).
const flowCountsUpsert = `
	late = late + excluded.late, no_template = no_template + excluded.no_template, malformed = malformed + excluded.malformed,
	seq_gaps = seq_gaps + excluded.seq_gaps, seq_lost = seq_lost + excluded.seq_lost, duplicates = duplicates + excluded.duplicates,
	off_ahead = off_ahead + excluded.off_ahead, off_behind = off_behind + excluded.off_behind,
	off_max_ahead_ms = max(off_max_ahead_ms, excluded.off_max_ahead_ms),
	off_max_behind_ms = max(off_max_behind_ms, excluded.off_max_behind_ms),
	flow_counted = min(flow_counted, excluded.flow_counted)`

const insertEventSQL = `INSERT INTO events (time, level, kind, device_id, text, source) VALUES (?, ?, ?, ?, ?, ?)`

const insertDeletionSQL = `INSERT INTO deletions (time, file, device_id, bytes, reason, type) VALUES (?, ?, ?, ?, ?, ?)`

// Apply applies a batch in one transaction.
func (d *DB) Apply(ctx context.Context, b Batch) error {
	if b.Empty() {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st := &stmts{tx: tx, ctx: ctx}
	defer st.close()
	for i := range b.Files {
		if err := st.fileOp(&b.Files[i]); err != nil {
			return err
		}
	}
	for _, m := range b.FlowMinutes {
		if err := st.flowMinute(m); err != nil {
			return err
		}
	}
	for _, a := range b.Activity {
		if err := st.activity(a); err != nil {
			return err
		}
	}
	for _, e := range b.Events {
		if err := st.event(e); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// stmts lazily prepares statements within one transaction.
type stmts struct {
	tx  *sql.Tx
	ctx context.Context
	m   map[string]*sql.Stmt
}

func (s *stmts) get(q string) (*sql.Stmt, error) {
	if st, ok := s.m[q]; ok {
		return st, nil
	}
	st, err := s.tx.PrepareContext(s.ctx, q)
	if err != nil {
		return nil, err
	}
	if s.m == nil {
		s.m = map[string]*sql.Stmt{}
	}
	s.m[q] = st
	return st, nil
}

func (s *stmts) exec(q string, args ...any) (sql.Result, error) {
	st, err := s.get(q)
	if err != nil {
		return nil, err
	}
	return st.ExecContext(s.ctx, args...)
}

func (s *stmts) close() {
	for _, st := range s.m {
		st.Close()
	}
}

func (s *stmts) upsertFile(f File) (int64, error) {
	st, err := s.get(upsertFileSQL)
	if err != nil {
		return 0, err
	}
	var id int64
	err = st.QueryRowContext(s.ctx, f.DeviceID, f.Path, f.Day, f.Part, ms(f.FirstReceived), ms(f.LastReceived),
		f.Size, f.RawSize, f.Lines, b2i(f.Compressed), fileType(f.Type)).Scan(&id)
	return id, err
}

func (s *stmts) checkpoints(fileID int64, cps []Checkpoint) error {
	for _, c := range cps {
		if _, err := s.exec(insertCheckpointSQL, fileID, c.Offset, c.Line, ms(c.Received)); err != nil {
			return err
		}
	}
	return nil
}

func (s *stmts) fileOp(op *FileOp) error {
	f := op.File
	switch op.Kind {
	case OpUpsert:
		id, err := s.upsertFile(f)
		if err != nil {
			return fmt.Errorf("index: upsert %s: %w", f.Path, err)
		}
		if op.ResetCheckpoints {
			if _, err := s.exec(`DELETE FROM checkpoints WHERE file_id = ?`, id); err != nil {
				return err
			}
		}
		if op.Flow != nil {
			if err := s.flowSegment(op.Flow); err != nil {
				return fmt.Errorf("index: flow segment %s: %w", f.Path, err)
			}
		}
		for _, m := range op.FlowMinutes {
			if err := s.flowMinute(m); err != nil {
				return fmt.Errorf("index: flow minutes %s: %w", f.Path, err)
			}
		}
		return s.checkpoints(id, op.Checkpoints)
	case OpRename:
		if op.OldPath != f.Path {
			if _, err := s.exec(`DELETE FROM files WHERE path = ?`, f.Path); err != nil {
				return err
			}
		}
		res, err := s.exec(`UPDATE files SET path = ?, device_id = ?, day = ?, part = ?, first_received = ?,
			last_received = ?, size = ?, raw_size = ?, lines = ?, compressed = ?, type = ? WHERE path = ?`,
			f.Path, f.DeviceID, f.Day, f.Part, ms(f.FirstReceived), ms(f.LastReceived), f.Size, f.RawSize,
			f.Lines, b2i(f.Compressed), fileType(f.Type), op.OldPath)
		if err != nil {
			return fmt.Errorf("index: rename %s: %w", op.OldPath, err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			// The old row never made it in (for example after a failed apply); create it.
			id, err := s.upsertFile(f)
			if err != nil {
				return err
			}
			return s.checkpoints(id, op.Checkpoints)
		}
		if len(op.Checkpoints) > 0 {
			var id int64
			st, err := s.get(`SELECT id FROM files WHERE path = ?`)
			if err != nil {
				return err
			}
			if err := st.QueryRowContext(s.ctx, f.Path).Scan(&id); err != nil {
				return err
			}
			return s.checkpoints(id, op.Checkpoints)
		}
		return nil
	case OpDelete:
		if _, err := s.exec(`DELETE FROM files WHERE path = ?`, f.Path); err != nil {
			return err
		}
		if fileType(f.Type) == TypeFlow {
			if err := s.deleteFlowRows(f.Path); err != nil {
				return err
			}
		}
		if del := op.Deletion; del != nil {
			if _, err := s.exec(insertDeletionSQL, ms(del.Time), del.File, del.DeviceID, del.Bytes, storedReason(del.Reason), fileType(del.Type)); err != nil {
				return fmt.Errorf("index: record deletion: %w", err)
			}
			text := fmt.Sprintf("deleted %s (%s, %d bytes)", del.File, reasonText(del.Reason), del.Bytes)
			return s.event(Event{Time: del.Time, Level: LevelInfo, Kind: KindDelete, DeviceID: del.DeviceID, Text: text})
		}
		return nil
	default:
		return fmt.Errorf("index: unknown file op %d", op.Kind)
	}
}

func reasonText(r Reason) string {
	switch r {
	case ReasonAge:
		return "older than the retention period"
	case ReasonCap:
		return "over the storage cap"
	case ReasonFlowBudget:
		return "flows over their budget"
	case ReasonLowDisk:
		return "low disk space"
	}
	return string(r)
}

// storedReason is a reason as the deletions table holds it (see ReasonFlowBudget).
func storedReason(r Reason) string {
	if r == ReasonFlowBudget {
		return string(ReasonCap)
	}
	return string(r)
}

// readReason is the Reason of a stored deletion row (see ReasonFlowBudget).
func readReason(reason, typ string) Reason {
	if Reason(reason) == ReasonCap && typ == TypeFlow {
		return ReasonFlowBudget
	}
	return Reason(reason)
}

// fileType is the stored form of a type: "" is syslog.
func fileType(t string) string {
	if t == "" {
		return TypeSyslog
	}
	return t
}

func (s *stmts) activity(a Activity) error {
	minute := a.Minute.Truncate(time.Minute)
	if t := fileType(a.Type); t == TypeSyslog {
		if _, err := s.exec(upsertStatsSQL, a.DeviceID, ms(minute), a.Msgs, a.Bytes, a.Truncated, a.Dropped); err != nil {
			return err
		}
	} else if _, err := s.exec(upsertTypeStatsSQL, a.DeviceID, t, ms(minute), a.Msgs, a.Bytes, a.Truncated, a.Dropped,
		a.Flow.Late, a.Flow.NoTemplate, a.Flow.Malformed, a.Flow.SeqGaps, a.Flow.SeqLost, a.Flow.Duplicates,
		a.Flow.Ahead, a.Flow.Behind, a.Flow.MaxAheadMs, a.Flow.MaxBehindMs); err != nil {
		return err
	}
	if a.DeviceID == RefusedDeviceID {
		// The synthetic stats id: no devices row. (Not any id starting with
		// "_": a sender on ::1 or ::a.b.c.d has the device id "__1".)
		return nil
	}
	first, last := a.FirstHeard, a.LastHeard
	if first.IsZero() {
		first = minute
	}
	if last.IsZero() {
		last = first
	}
	_, err := s.exec(upsertDeviceActivitySQL, a.DeviceID, a.IP, ms(first), ms(last), a.Msgs, a.Bytes)
	return err
}

func (s *stmts) event(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if e.Level == "" {
		e.Level = LevelInfo
	}
	_, err := s.exec(insertEventSQL, ms(e.Time), string(e.Level), string(e.Kind), e.DeviceID, e.Text, string(e.Source))
	return err
}

// AddEvent records one event (a zero Time means now).
func (d *DB) AddEvent(ctx context.Context, e Event) error {
	return d.Apply(ctx, Batch{Events: []Event{e}})
}

// UpdateDevice changes a device's user-set fields and returns the updated device.
func (d *DB) UpdateDevice(ctx context.Context, id string, u DeviceUpdate) (Device, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return Device{}, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM devices WHERE id = ?`, id).Scan(&n); err != nil {
		return Device{}, err
	}
	if n == 0 {
		return Device{}, ErrNotFound
	}
	if u.Name != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET name = ? WHERE id = ?`, *u.Name, id); err != nil {
			return Device{}, err
		}
	}
	if u.Group != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET grp = ? WHERE id = ?`, *u.Group, id); err != nil {
			return Device{}, err
		}
	}
	if u.Hidden != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE devices SET hidden = ? WHERE id = ?`, b2i(*u.Hidden), id); err != nil {
			return Device{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Device{}, err
	}
	return d.Device(ctx, id)
}

// RollupStats moves every per-minute bucket that starts before `before` (truncated to
// the hour) into its hourly bucket, in one transaction, so no message is counted twice
// or lost. It returns the number of minute buckets moved. The store runs it with
// before = now - MinuteRetention.
func (d *DB) RollupStats(ctx context.Context, before time.Time) (int64, error) {
	b := ms(before.UTC().Truncate(time.Hour))
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO stats_hourly (device_id, hour, msgs, bytes, truncated, dropped)
SELECT device_id, (minute / 3600000) * 3600000, sum(msgs), sum(bytes), sum(truncated), sum(dropped)
FROM stats WHERE minute < ? GROUP BY device_id, minute / 3600000
ON CONFLICT (device_id, hour) DO UPDATE SET
	msgs = msgs + excluded.msgs, bytes = bytes + excluded.bytes,
	truncated = truncated + excluded.truncated, dropped = dropped + excluded.dropped`, b); err != nil {
		return 0, fmt.Errorf("index: stats rollup: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM stats WHERE minute < ?`, b)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO type_stats_hourly (device_id, type, hour, msgs, bytes, truncated, dropped, late, no_template, malformed, seq_gaps,
	seq_lost, duplicates, off_ahead, off_behind, off_max_ahead_ms, off_max_behind_ms, flow_counted)
SELECT device_id, type, (minute / 3600000) * 3600000, sum(msgs), sum(bytes), sum(truncated), sum(dropped), sum(late),
	sum(no_template), sum(malformed), sum(seq_gaps), sum(seq_lost), sum(duplicates), sum(off_ahead), sum(off_behind),
	max(off_max_ahead_ms), max(off_max_behind_ms), min(flow_counted)
FROM type_stats WHERE minute < ? GROUP BY device_id, type, minute / 3600000
ON CONFLICT (device_id, type, hour) DO UPDATE SET
	msgs = msgs + excluded.msgs, bytes = bytes + excluded.bytes,
	truncated = truncated + excluded.truncated, dropped = dropped + excluded.dropped,`+flowCountsUpsert, b); err != nil {
		return 0, fmt.Errorf("index: type stats rollup: %w", err)
	}
	res, err = tx.ExecContext(ctx, `DELETE FROM type_stats WHERE minute < ?`, b)
	if err != nil {
		return 0, err
	}
	m, _ := res.RowsAffected()
	return n + m, tx.Commit()
}

// Prune deletes stats buckets (minute and hourly) starting before statsBefore, and
// events and deletions older than historyBefore (a zero time skips that part).
func (d *DB) Prune(ctx context.Context, statsBefore, historyBefore time.Time) error {
	if !statsBefore.IsZero() {
		if _, err := d.db.ExecContext(ctx, `DELETE FROM stats WHERE minute < ?`, ms(statsBefore)); err != nil {
			return err
		}
		if _, err := d.db.ExecContext(ctx, `DELETE FROM stats_hourly WHERE hour < ?`, ms(statsBefore.UTC().Truncate(time.Hour))); err != nil {
			return err
		}
		if _, err := d.db.ExecContext(ctx, `DELETE FROM type_stats WHERE minute < ?`, ms(statsBefore)); err != nil {
			return err
		}
		if _, err := d.db.ExecContext(ctx, `DELETE FROM type_stats_hourly WHERE hour < ?`, ms(statsBefore.UTC().Truncate(time.Hour))); err != nil {
			return err
		}
	}
	if !historyBefore.IsZero() {
		if _, err := d.db.ExecContext(ctx, `DELETE FROM events WHERE time < ?`, ms(historyBefore)); err != nil {
			return err
		}
		if _, err := d.db.ExecContext(ctx, `DELETE FROM deletions WHERE time < ?`, ms(historyBefore)); err != nil {
			return err
		}
	}
	return nil
}
