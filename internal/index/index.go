// Package index is Woodshed's SQLite index (<data>/index.db): log files and their
// time checkpoints, devices, per-minute stats, the service's own events and the
// storage (deletion) history.
//
// The log files are the source of truth. Files and checkpoints can be rebuilt from
// them at any time with Reindex; devices keep their user-set name, group and hidden
// flag across a rebuild, and saved searches are left alone.
//
// All times are stored as Unix milliseconds and returned in UTC. File paths are
// relative to the data dir and '/'-separated ("logs/192.0.2.1/2026-11-10.log").
package index

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (pure Go, no cgo)
)

// FileName is the index's file name inside the data dir.
const FileName = "index.db"

// Stats retention. Per-minute buckets are kept for MinuteRetention, then RollupStats
// folds them into hourly buckets, which are kept for StatsRetention.
const (
	MinuteRetention = 24 * time.Hour
	StatsRetention  = 7 * 24 * time.Hour
)

// ErrNotFound is returned when a device or file doesn't exist.
var ErrNotFound = errors.New("index: not found")

// Open refuses to run as root on a data dir owned by another user (ErrRunAsOwner),
// and refuses index files that are links or not regular files (ErrUnsafeFile).
var (
	ErrRunAsOwner = errors.New("index: refusing to open the index as root in a data folder owned by another user")
	ErrUnsafeFile = errors.New("index: unsafe index file")
)

// DB is an open index. It is safe for concurrent use.
type DB struct {
	db *sql.DB
	// immutable: opened by OpenReadOnly with no writer present (it reads the
	// database file alone and wouldn't see a writer that starts later).
	immutable bool
	// created and migrated: what Open did to the schema (Migrations).
	created  bool
	migrated []Migration
}

// Migration is one schema step Open applied to an existing index.
type Migration struct {
	From, To int
	Took     time.Duration
}

// Text is the step as its event reads: "index migrated from schema 8 to 9 in 12 ms".
func (m Migration) Text() string {
	took := fmt.Sprintf("%d ms", m.Took.Milliseconds())
	if m.Took < time.Millisecond {
		took = "under 1 ms"
	}
	return fmt.Sprintf("index migrated from schema %d to %d in %s", m.From, m.To, took)
}

// Migrations reports what Open did to the schema: created is true for a new
// index (created at CurrentSchema, no steps listed); otherwise steps are the
// migrations applied to an existing one, oldest first (none when it was
// current). Each step is also recorded as a KindMigrate event.
func (d *DB) Migrations() (created bool, steps []Migration) {
	return d.created, append([]Migration(nil), d.migrated...)
}

// Open opens (creating if needed) the index at path, in WAL mode, and migrates its
// schema to the current version. A database from a newer Woodshed is refused.
func Open(path string) (*DB, error) {
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("index: unsupported character in path %q", path)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	q.Set("_txlock", "immediate")
	if err := prepareFiles(path); err != nil {
		return nil, fmt.Errorf("index: %w", err)
	}
	sdb, err := sql.Open("sqlite", path+"?"+q.Encode())
	if err != nil {
		return nil, fmt.Errorf("index: open %s: %w", path, err)
	}
	sdb.SetMaxOpenConns(8)
	sdb.SetMaxIdleConns(4)
	sdb.SetConnMaxIdleTime(5 * time.Minute)
	d := &DB{db: sdb}
	if err := d.migrate(context.Background()); err != nil {
		sdb.Close()
		return nil, err
	}
	if err := d.ensureAux(context.Background()); err != nil {
		sdb.Close()
		return nil, err
	}
	// The migration wrote, so the -wal and -shm files exist now; give them the
	// database's mode and owner too.
	if err := prepareFiles(path); err != nil {
		sdb.Close()
		return nil, fmt.Errorf("index: %w", err)
	}
	return d, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.db.Close() }

// SchemaVersion returns the schema version the database is at.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := d.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&v)
	return v, err
}

// migrations[i] moves the schema from version i to i+1. Append only; never edit a
// released migration.
var migrations = []string{
	// 0 -> 1: initial schema.
	`
CREATE TABLE devices (
	id          TEXT PRIMARY KEY,
	ip          TEXT NOT NULL,
	name        TEXT NOT NULL DEFAULT '',
	grp         TEXT NOT NULL DEFAULT '',
	hidden      INTEGER NOT NULL DEFAULT 0,
	first_seen  INTEGER NOT NULL,
	last_heard  INTEGER NOT NULL,
	total_msgs  INTEGER NOT NULL DEFAULT 0,
	total_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE files (
	id             INTEGER PRIMARY KEY,
	device_id      TEXT NOT NULL,
	path           TEXT NOT NULL UNIQUE,
	day            TEXT NOT NULL,
	part           INTEGER NOT NULL,
	first_received INTEGER NOT NULL,
	last_received  INTEGER NOT NULL,
	size           INTEGER NOT NULL,
	raw_size       INTEGER NOT NULL,
	lines          INTEGER NOT NULL,
	compressed     INTEGER NOT NULL
);
CREATE INDEX files_device_time ON files (device_id, first_received);
CREATE INDEX files_time ON files (last_received);
CREATE TABLE checkpoints (
	file_id  INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
	offset   INTEGER NOT NULL,
	line     INTEGER NOT NULL,
	received INTEGER NOT NULL,
	PRIMARY KEY (file_id, offset)
) WITHOUT ROWID;
CREATE TABLE stats (
	device_id TEXT NOT NULL,
	minute    INTEGER NOT NULL,
	msgs      INTEGER NOT NULL DEFAULT 0,
	bytes     INTEGER NOT NULL DEFAULT 0,
	truncated INTEGER NOT NULL DEFAULT 0,
	dropped   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (device_id, minute)
) WITHOUT ROWID;
CREATE INDEX stats_minute ON stats (minute);
CREATE TABLE events (
	id        INTEGER PRIMARY KEY,
	time      INTEGER NOT NULL,
	level     TEXT NOT NULL,
	kind      TEXT NOT NULL,
	device_id TEXT NOT NULL DEFAULT '',
	text      TEXT NOT NULL
);
CREATE INDEX events_time ON events (time);
CREATE TABLE deletions (
	id        INTEGER PRIMARY KEY,
	time      INTEGER NOT NULL,
	file      TEXT NOT NULL,
	device_id TEXT NOT NULL,
	bytes     INTEGER NOT NULL,
	reason    TEXT NOT NULL CHECK (reason IN ('age', 'cap', 'low_disk'))
);
CREATE INDEX deletions_time ON deletions (time);
`,
	// 1 -> 2: hourly stats buckets (per-minute buckets are rolled up after 24 h).
	`
CREATE TABLE stats_hourly (
	device_id TEXT NOT NULL,
	hour      INTEGER NOT NULL,
	msgs      INTEGER NOT NULL DEFAULT 0,
	bytes     INTEGER NOT NULL DEFAULT 0,
	truncated INTEGER NOT NULL DEFAULT 0,
	dropped   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (device_id, hour)
) WITHOUT ROWID;
CREATE INDEX stats_hourly_hour ON stats_hourly (hour);
`,
	// 2 -> 3: what an event is about (Event.Source), so readers such as export gap
	// detection don't depend on the event's wording.
	`
ALTER TABLE events ADD COLUMN source TEXT NOT NULL DEFAULT '';
`,
	// 3 -> 4: indexes for the device list and the dashboard at 10,000 devices
	// (QueryDevices' orders and rate window; drop and truncation counts read
	// only the buckets that have any).
	`
CREATE INDEX stats_minute_msgs ON stats (minute, device_id, msgs);
CREATE INDEX stats_drops ON stats (minute) WHERE dropped > 0 OR truncated > 0;
CREATE INDEX stats_hourly_drops ON stats_hourly (hour) WHERE dropped > 0 OR truncated > 0;
CREATE INDEX devices_last_heard ON devices (last_heard DESC, id);
CREATE INDEX devices_first_seen ON devices (first_seen DESC, id);
CREATE INDEX devices_name_sort ON devices ((CASE WHEN name = '' THEN ip ELSE name END) COLLATE NOCASE, id);
`,
	// 4 -> 5: saved searches (Events, SPEC §10.1.4). User data like device names:
	// Reindex rebuilds only files and checkpoints, so it keeps them. name_key is
	// the name folded for case, so names are unique ignoring case.
	`
CREATE TABLE saved_searches (
	id       TEXT PRIMARY KEY,
	name     TEXT NOT NULL,
	name_key TEXT NOT NULL UNIQUE,
	type     TEXT NOT NULL,
	query    TEXT NOT NULL,
	created  INTEGER NOT NULL,
	updated  INTEGER NOT NULL,
	version  INTEGER NOT NULL DEFAULT 1
);
`,
	// 5 -> 6: data types (SPEC §11.1, §11.7). Every 1.1 file row reads as syslog;
	// other types' stats go into their own tables, so syslog's are untouched; each
	// deletion records its file's type.
	`
ALTER TABLE files ADD COLUMN type TEXT NOT NULL DEFAULT 'syslog';
CREATE INDEX files_type_device_time ON files (type, device_id, first_received);
ALTER TABLE deletions ADD COLUMN type TEXT NOT NULL DEFAULT 'syslog';
CREATE TABLE type_stats (
	device_id TEXT NOT NULL,
	type      TEXT NOT NULL,
	minute    INTEGER NOT NULL,
	msgs      INTEGER NOT NULL DEFAULT 0,
	bytes     INTEGER NOT NULL DEFAULT 0,
	truncated INTEGER NOT NULL DEFAULT 0,
	dropped   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (device_id, type, minute)
) WITHOUT ROWID;
CREATE INDEX type_stats_minute ON type_stats (minute);
CREATE INDEX type_stats_type_minute ON type_stats (type, minute, device_id);
CREATE TABLE type_stats_hourly (
	device_id TEXT NOT NULL,
	type      TEXT NOT NULL,
	hour      INTEGER NOT NULL,
	msgs      INTEGER NOT NULL DEFAULT 0,
	bytes     INTEGER NOT NULL DEFAULT 0,
	truncated INTEGER NOT NULL DEFAULT 0,
	dropped   INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (device_id, type, hour)
) WITHOUT ROWID;
CREATE INDEX type_stats_hourly_hour ON type_stats_hourly (hour);
`,
	// 6 -> 7: the SNMP poller (SPEC §12.3, §12.9). poll_targets is user data
	// (Reindex keeps it); poll_hourly is derived (Reindex rebuilds it from the
	// poll files). Neither ever holds a secret.
	`
CREATE TABLE poll_targets (
	id           TEXT PRIMARY KEY,
	address      TEXT NOT NULL,
	port         INTEGER NOT NULL,
	device_id    TEXT NOT NULL,
	settings     TEXT NOT NULL,
	engine_id    TEXT NOT NULL DEFAULT '',
	engine_boots INTEGER NOT NULL DEFAULT 0,
	engine_time  INTEGER NOT NULL DEFAULT 0,
	engine_at    INTEGER NOT NULL DEFAULT 0,
	created      INTEGER NOT NULL,
	updated      INTEGER NOT NULL,
	version      INTEGER NOT NULL DEFAULT 1,
	UNIQUE (address, port)
);
CREATE TABLE poll_hourly (
	device_id TEXT NOT NULL,
	series    TEXT NOT NULL,
	hour      INTEGER NOT NULL,
	min       REAL NOT NULL,
	max       REAL NOT NULL,
	sum       REAL NOT NULL,
	count     INTEGER NOT NULL,
	PRIMARY KEY (device_id, series, hour)
) WITHOUT ROWID;
CREATE INDEX poll_hourly_hour ON poll_hourly (hour);
`,
	// 7 -> 8: flows (SPEC §13.2, §13.9): flow_segments and flow_minute, both
	// derived from the segments' footers (flow.go).
	flowMigration,
	// 8 -> 9: the flow collector's counts per exporter and minute (SPEC
	// §13.10 decisions 82 and 83), in type_stats beside msgs and bytes.
	flowCountsMigration,
}

// CurrentSchema is the schema version this build writes.
var CurrentSchema = len(migrations)

func (d *DB) migrate(ctx context.Context) error {
	v, err := d.SchemaVersion(ctx)
	if err != nil {
		return fmt.Errorf("index: read schema version: %w", err)
	}
	if v > len(migrations) {
		return fmt.Errorf("index: schema version %d is newer than this build supports (%d)", v, len(migrations))
	}
	d.created = v == 0
	for ; v < len(migrations); v++ {
		t0 := time.Now()
		tx, err := d.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[v]); err != nil {
			tx.Rollback()
			return fmt.Errorf("index: migrate %d -> %d: %w", v, v+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			tx.Rollback()
			return err
		}
		m := Migration{From: v, To: v + 1, Took: time.Since(t0)}
		if !d.created {
			// The step's event, in the step's transaction: an upgrade shows in Events
			// and the bundle's woodshed-events.log, not only in the service log.
			// (These columns exist from schema 1; source came with 3.)
			if _, err := tx.ExecContext(ctx, `INSERT INTO events (time, level, kind, device_id, text) VALUES (?, ?, ?, '', ?)`,
				time.Now().UnixMilli(), string(LevelInfo), string(KindMigrate), m.Text()); err != nil {
				tx.Rollback()
				return fmt.Errorf("index: migrate %d -> %d: record the event: %w", v, v+1, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("index: migrate %d -> %d: %w", v, v+1, err)
		}
		if !d.created {
			d.migrated = append(d.migrated, m)
		}
	}
	return nil
}

// auxSchema is what this build adds beside the versioned schema, idempotently
// at each Open, so the schema version stays 9 and a 2.0 release candidate
// can still open the index (it ignores both):
//   - flow_minute_path_sums covers Reconcile's per-segment sums of
//     flow_minute (flowMinuteSums) and replaces flow_minute_path, its prefix,
//     for the deletes by path;
//   - index_meta holds values like FlowRowsVersion.
const auxSchema = `
CREATE INDEX IF NOT EXISTS flow_minute_path_sums ON flow_minute (path, records, bytes);
DROP INDEX IF EXISTS flow_minute_path;
CREATE TABLE IF NOT EXISTS index_meta (
	key   TEXT PRIMARY KEY,
	value INTEGER NOT NULL
) WITHOUT ROWID;
`

func (d *DB) ensureAux(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, auxSchema); err != nil {
		return fmt.Errorf("index: %w", err)
	}
	return nil
}

// metaInt reads an index_meta value (0 when it's not set).
func (d *DB) metaInt(ctx context.Context, key string) (int64, error) {
	var v int64
	err := d.db.QueryRowContext(ctx, `SELECT value FROM index_meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return v, err
}

func (s *stmts) setMeta(key string, v int64) error {
	_, err := s.exec(`INSERT INTO index_meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value`, key, v)
	return err
}

func ms(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func tm(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// inList returns an IN-clause operand and its one argument for a set of ids. The ids
// travel as a single JSON array read with json_each, so any number of them fits
// (one placeholder per id hits SQLite's ~32k variable limit).
func inList(ids []string) (string, []any) {
	if ids == nil {
		ids = []string{}
	}
	b, _ := json.Marshal(ids)
	return `(SELECT value FROM json_each(?))`, []any{string(b)}
}
