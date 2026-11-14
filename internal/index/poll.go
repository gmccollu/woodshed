package index

import (
	"bufio"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The SNMP poller's tables (SPEC §12.3):
//   - poll_targets: the configured targets and each one's cached v3 engine
//     (never a secret). User data like device names and saved searches, so
//     Reindex keeps it.
//   - poll_hourly: the headline series' hourly min, max, sum and count per
//     device. Derived data: the poller writes it as cycles arrive, and Reindex
//     rebuilds it from the poll files.

// Poll target errors.
var (
	ErrPollTargetExists  = errors.New("index: a poll target for that address and port already exists")
	ErrPollTargetChanged = errors.New("index: the poll target changed")
	ErrPollTargetLimit   = errors.New("index: too many poll targets")
)

// PollTarget is one stored target. Settings is the target's settings as JSON
// (opaque here; the poller validates it).
type PollTarget struct {
	ID       string // "pt_" and 8 hex digits
	Address  string
	Port     int
	DeviceID string
	Settings string
	// The agent's v3 engine as last learned: its ID, boots, and time at
	// EngineAt (wall clock).
	EngineID    []byte
	EngineBoots int64
	EngineTime  int64
	EngineAt    time.Time
	Created     time.Time
	Updated     time.Time
	Version     int64
}

const pollTargetCols = `id, address, port, device_id, settings, engine_id, engine_boots, engine_time, engine_at, created, updated, version`

func scanPollTarget(r interface{ Scan(...any) error }) (PollTarget, error) {
	var t PollTarget
	var eat, c, u int64
	var eid sql.NullString
	err := r.Scan(&t.ID, &t.Address, &t.Port, &t.DeviceID, &t.Settings, &eid, &t.EngineBoots, &t.EngineTime, &eat, &c, &u, &t.Version)
	if eid.Valid && eid.String != "" {
		t.EngineID, _ = hex.DecodeString(eid.String)
	}
	if eat != 0 {
		t.EngineAt = tm(eat)
	}
	t.Created, t.Updated = tm(c), tm(u)
	return t, err
}

// PollTargets returns every target, by device then address and port.
func (d *DB) PollTargets(ctx context.Context) ([]PollTarget, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT `+pollTargetCols+` FROM poll_targets ORDER BY device_id, address, port, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PollTarget{}
	for rows.Next() {
		t, err := scanPollTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PollTarget returns one target, or ErrNotFound.
func (d *DB) PollTarget(ctx context.Context, id string) (PollTarget, error) {
	t, err := scanPollTarget(d.db.QueryRowContext(ctx, `SELECT `+pollTargetCols+` FROM poll_targets WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return PollTarget{}, ErrNotFound
	}
	return t, err
}

func addrTaken(ctx context.Context, tx *sql.Tx, addr string, port int, exceptID string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM poll_targets WHERE address = ? AND port = ? AND id != ?`, addr, port, exceptID).Scan(&n)
	return n > 0, err
}

// CreatePollTarget adds a target (ID, times and Version are set here). It
// returns ErrPollTargetLimit at max targets and ErrPollTargetExists for an
// address and port already polled.
func (d *DB) CreatePollTarget(ctx context.Context, t PollTarget, max int, now time.Time) (PollTarget, error) {
	var b [4]byte
	_, _ = rand.Read(b[:])
	t.ID = "pt_" + hex.EncodeToString(b[:])
	t.Created, t.Updated, t.Version = now.UTC().Truncate(time.Millisecond), now.UTC().Truncate(time.Millisecond), 1
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return PollTarget{}, err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM poll_targets`).Scan(&n); err != nil {
		return PollTarget{}, err
	}
	if n >= max {
		return PollTarget{}, ErrPollTargetLimit
	}
	if taken, err := addrTaken(ctx, tx, t.Address, t.Port, ""); err != nil {
		return PollTarget{}, err
	} else if taken {
		return PollTarget{}, ErrPollTargetExists
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO poll_targets (id, address, port, device_id, settings, engine_id, engine_boots,
		engine_time, engine_at, created, updated, version) VALUES (?, ?, ?, ?, ?, '', 0, 0, 0, ?, ?, 1)`,
		t.ID, t.Address, t.Port, t.DeviceID, t.Settings, ms(t.Created), ms(t.Updated)); err != nil {
		return PollTarget{}, err
	}
	return t, tx.Commit()
}

// UpdatePollTarget replaces a target's address, port, device and settings.
// With ifVersion > 0 it saves only at that version (ErrPollTargetChanged).
// A changed address or port forgets the cached engine.
func (d *DB) UpdatePollTarget(ctx context.Context, t PollTarget, ifVersion int64, now time.Time) (PollTarget, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return PollTarget{}, err
	}
	defer tx.Rollback()
	cur, err := scanPollTarget(tx.QueryRowContext(ctx, `SELECT `+pollTargetCols+` FROM poll_targets WHERE id = ?`, t.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return PollTarget{}, ErrNotFound
	}
	if err != nil {
		return PollTarget{}, err
	}
	if ifVersion > 0 && cur.Version != ifVersion {
		return PollTarget{}, ErrPollTargetChanged
	}
	if taken, err := addrTaken(ctx, tx, t.Address, t.Port, t.ID); err != nil {
		return PollTarget{}, err
	} else if taken {
		return PollTarget{}, ErrPollTargetExists
	}
	out := cur
	out.Address, out.Port, out.DeviceID, out.Settings = t.Address, t.Port, t.DeviceID, t.Settings
	out.Updated, out.Version = now.UTC().Truncate(time.Millisecond), cur.Version+1
	engine := ""
	if cur.Address == t.Address && cur.Port == t.Port {
		engine = hex.EncodeToString(cur.EngineID)
	} else {
		out.EngineID, out.EngineBoots, out.EngineTime, out.EngineAt = nil, 0, 0, time.Time{}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE poll_targets SET address = ?, port = ?, device_id = ?, settings = ?, engine_id = ?,
		engine_boots = ?, engine_time = ?, engine_at = ?, updated = ?, version = ? WHERE id = ?`,
		out.Address, out.Port, out.DeviceID, out.Settings, engine, out.EngineBoots, out.EngineTime, msOrZero(out.EngineAt),
		ms(out.Updated), out.Version, out.ID); err != nil {
		return PollTarget{}, err
	}
	return out, tx.Commit()
}

func msOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return ms(t)
}

// SetPollEngine records a target's v3 engine (discovery, or boots and time
// learned since). It doesn't change the target's version: it's the poller's
// cache, not a setting.
func (d *DB) SetPollEngine(ctx context.Context, id string, engineID []byte, boots, etime int64, at time.Time) error {
	_, err := d.db.ExecContext(ctx, `UPDATE poll_targets SET engine_id = ?, engine_boots = ?, engine_time = ?, engine_at = ? WHERE id = ?`,
		hex.EncodeToString(engineID), boots, etime, msOrZero(at), id)
	return err
}

// DeletePollTarget removes a target (ErrNotFound for an unknown id). Its
// device's poll files stay until retention deletes them.
func (d *DB) DeletePollTarget(ctx context.Context, id string) error {
	r, err := d.db.ExecContext(ctx, `DELETE FROM poll_targets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddPollHourly merges rows into poll_hourly (min of mins, max of maxes,
// sums and counts added), so a flush of a partial hour adds to what an
// earlier flush wrote.
func (d *DB) AddPollHourly(ctx context.Context, rows []pollrec.Hourly) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.PrepareContext(ctx, `INSERT INTO poll_hourly (device_id, series, hour, min, max, sum, count) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (device_id, series, hour) DO UPDATE SET min = min(min, excluded.min), max = max(max, excluded.max),
		sum = sum + excluded.sum, count = count + excluded.count`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, h := range rows {
		if _, err := st.ExecContext(ctx, h.Device, h.Series, h.Hour.Unix(), h.Min, h.Max, h.Sum, h.Count); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PollHourly returns a device's rows for the series (nil: all) with an hour
// in [from, to), by series then hour.
func (d *DB) PollHourly(ctx context.Context, deviceID string, series []string, from, to time.Time) ([]pollrec.Hourly, error) {
	q := `SELECT device_id, series, hour, min, max, sum, count FROM poll_hourly WHERE device_id = ? AND hour >= ? AND hour < ?`
	args := []any{deviceID, from.Truncate(time.Hour).Unix(), to.Unix()}
	if series != nil {
		if len(series) == 0 {
			return nil, nil
		}
		q += ` AND series IN (?` + strings.Repeat(",?", len(series)-1) + `)`
		for _, s := range series {
			args = append(args, s)
		}
	}
	rows, err := d.db.QueryContext(ctx, q+` ORDER BY series, hour`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pollrec.Hourly
	for rows.Next() {
		var h pollrec.Hourly
		var hour int64
		if err := rows.Scan(&h.Device, &h.Series, &hour, &h.Min, &h.Max, &h.Sum, &h.Count); err != nil {
			return nil, err
		}
		h.Hour = time.Unix(hour, 0).UTC()
		out = append(out, h)
	}
	return out, rows.Err()
}

// RebuildPollHourly replaces poll_hourly with the rollups of every poll file
// under dataDir (Reindex). Files are only read.
func (d *DB) RebuildPollHourly(ctx context.Context, dataDir string) (int, error) {
	entries, _, err := logfile.List(dataDir)
	if err != nil {
		return 0, err
	}
	ru := pollrec.NewRollup()
	onDisk := map[string]bool{}
	for _, e := range entries {
		onDisk[e.Rel] = true
	}
	for _, e := range entries {
		if e.Type != logfile.TypePoll {
			continue
		}
		if e.Name.Compressed {
			plain := e.Name
			plain.Compressed = false
			if onDisk[logfile.RelPathType(e.Type, e.DeviceID, plain)] {
				continue // the .log is authoritative until the .gz is verified
			}
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		if err := rollupFile(e.Path, ru); err != nil {
			return 0, fmt.Errorf("index: poll rollups: %s: %w", e.Rel, err)
		}
	}
	rows := ru.Take()
	if _, err := d.db.ExecContext(ctx, `DELETE FROM poll_hourly`); err != nil {
		return 0, err
	}
	return len(rows), d.AddPollHourly(ctx, rows)
}

// rollupFile adds one poll file's cycles to ru.
func rollupFile(path string, ru *pollrec.Rollup) error {
	r, err := logfile.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer r.Close()
	br := bufio.NewReaderSize(r, 256<<10)
	var cur *pollrec.Cycle
	var buf []byte
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			buf = append(buf[:0], line...)
			for errors.Is(err, bufio.ErrBufferFull) {
				line, err = br.ReadSlice('\n')
				buf = append(buf, line...)
			}
			line = buf
		}
		if len(line) > 0 && line[len(line)-1] == '\n' {
			if l, perr := logfile.ParseLine(line); perr == nil {
				rec, perr := pollrec.Parse(l.Raw())
				if perr == nil {
					dev := model.DeviceID(l.Sender)
					if cur == nil || cur.Cycle != rec.Cycle || cur.Device != dev {
						if cur != nil {
							ru.AddCycle(cur)
						}
						cur = pollrec.NewCycle(dev, rec.Cycle, l.Received)
					}
					cur.Add(&rec)
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	if cur != nil {
		ru.AddCycle(cur)
	}
	return nil
}
