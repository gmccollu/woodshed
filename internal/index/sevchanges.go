package index

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// The severity filter's changes (SPEC §13.10 decision 86), one row per
// change beside its severity_filter event, written in the same transaction:
// what a bundle reads for the settings over its window and what a start
// checks before recording a change made while stopped. Keyed by the
// override's address (no zone, canonical), so every zone of an address shares
// one history, as it shares one setting. Created at Open beside the schema
// (auxSchema), so an index from 2.1.0-rc1 gains it and the schema stays 10;
// its changes before the table are only in the events' texts. Not pruned: a
// row per change.
const severityChangesSchema = `
CREATE TABLE IF NOT EXISTS severity_changes (
	id         INTEGER PRIMARY KEY,
	time       INTEGER NOT NULL,
	address    TEXT NOT NULL,
	is_default INTEGER NOT NULL,
	level      INTEGER NOT NULL,
	was        INTEGER,
	source     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS severity_changes_address ON severity_changes (address, time);
`

// SeverityChange is one change of the severity filter: the default's
// (Default, Address "") or one address's own setting. Level is the setting
// after it and Was before (0-7; -1: the address follows the default); WasKnown
// is false when that isn't known (a 2.1.0-rc1 event's). Source is "live" (the
// UI or API) or "stopped" (found at a start).
type SeverityChange struct {
	Time     time.Time
	Address  string
	Default  bool
	Level    int
	Was      int
	WasKnown bool
	Source   string
}

// Severity change sources.
const (
	SeverityLive    = "live"
	SeverityStopped = "stopped"
)

// AddSeverityChange records a change and its event in one transaction (a
// zero time is now, the same for both).
func (d *DB) AddSeverityChange(ctx context.Context, c SeverityChange, e Event) error {
	if c.Time.IsZero() {
		c.Time = time.Now()
	}
	e.Time, e.Kind = c.Time, KindSeverityFilter
	if e.Level == "" {
		e.Level = LevelInfo
	}
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, insertEventSQL, ms(e.Time), string(e.Level), string(e.Kind), e.DeviceID, e.Text, string(e.Source)); err != nil {
		return err
	}
	var was sql.NullInt64
	if c.WasKnown {
		was = sql.NullInt64{Int64: int64(c.Was), Valid: true}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO severity_changes (time, address, is_default, level, was, source) VALUES (?, ?, ?, ?, ?, ?)`,
		ms(c.Time), c.Address, c.Default, c.Level, was, c.Source); err != nil {
		return err
	}
	return tx.Commit()
}

const severityChangeCols = `time, address, is_default, level, was, source`

func scanSeverityChange(sc interface{ Scan(...any) error }) (SeverityChange, error) {
	var c SeverityChange
	var t int64
	var was sql.NullInt64
	if err := sc.Scan(&t, &c.Address, &c.Default, &c.Level, &was, &c.Source); err != nil {
		return c, err
	}
	c.Time, c.Was, c.WasKnown = tm(t), int(was.Int64), was.Valid
	return c, nil
}

// hasSeverityChanges: the table exists (an index OpenReadOnly opened that no
// 2.1.0-rc2 or later ever opened for writing lacks it).
func (d *DB) hasSeverityChanges(ctx context.Context) (bool, error) {
	var n int
	err := d.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'severity_changes'`).Scan(&n)
	return n > 0, err
}

// SeverityChanges returns every recorded change, oldest first.
func (d *DB) SeverityChanges(ctx context.Context) ([]SeverityChange, error) {
	if ok, err := d.hasSeverityChanges(ctx); err != nil || !ok {
		return nil, err
	}
	rows, err := d.db.QueryContext(ctx, `SELECT `+severityChangeCols+` FROM severity_changes ORDER BY time, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SeverityChange
	for rows.Next() {
		c, err := scanSeverityChange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LatestSeverityChange returns the newest change of the default (address "")
// or of an address's own setting; ok is false when there's none.
func (d *DB) LatestSeverityChange(ctx context.Context, address string) (c SeverityChange, ok bool, err error) {
	if ok, err := d.hasSeverityChanges(ctx); err != nil || !ok {
		return SeverityChange{}, false, err
	}
	c, err = scanSeverityChange(d.db.QueryRowContext(ctx, `SELECT `+severityChangeCols+` FROM severity_changes
		WHERE address = ? ORDER BY time DESC, id DESC LIMIT 1`, address))
	if errors.Is(err, sql.ErrNoRows) {
		return SeverityChange{}, false, nil
	}
	return c, err == nil, err
}
