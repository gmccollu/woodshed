package index

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/store/logfile"
)

var ctx = context.Background()

func openIn(t *testing.T, dir string) *DB {
	t.Helper()
	os.MkdirAll(dir, 0o700)
	d, err := Open(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

var t0 = time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)

func TestOpenMigrateAndWAL(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Application Support")
	d := openIn(t, dir)
	v, err := d.SchemaVersion(ctx)
	if err != nil || v != CurrentSchema || v < 1 {
		t.Fatalf("version %d %v", v, err)
	}
	var mode string
	d.db.QueryRow("PRAGMA journal_mode").Scan(&mode)
	if mode != "wal" {
		t.Fatalf("journal_mode %q", mode)
	}
	var fk int
	d.db.QueryRow("PRAGMA foreign_keys").Scan(&fk)
	if fk != 1 {
		t.Fatal("foreign keys off")
	}
	d.Close()
	// Reopening is a no-op migration.
	d2 := openIn(t, dir)
	if v2, _ := d2.SchemaVersion(ctx); v2 != v {
		t.Fatalf("reopen version %d", v2)
	}
	// A database from a newer build is refused.
	d2.db.Exec("PRAGMA user_version = 999")
	d2.Close()
	if _, err := Open(filepath.Join(dir, FileName)); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("newer schema: %v", err)
	}
	if _, err := Open(filepath.Join(dir, "a?b.db")); err == nil {
		t.Fatal("accepted '?' in path")
	}
}

func fileRow(dev, name string, first, last time.Time, lines int64) File {
	n, _ := logfile.ParseName(name)
	return File{DeviceID: dev, Path: logfile.RelPath(dev, n), Day: n.Day, Part: n.Part, FirstReceived: first,
		LastReceived: last, Size: lines * 100, RawSize: lines * 100, Lines: lines, Compressed: n.Compressed}
}

func TestFileOpsAndRanges(t *testing.T) {
	d := openIn(t, t.TempDir())
	a := fileRow("192.0.2.1", "2026-11-10.log", t0, t0.Add(time.Hour), 10)
	cps := []Checkpoint{{Received: t0, Offset: 0}, {Received: t0.Add(20 * time.Minute), Offset: 100 << 10, Line: 300},
		{Received: t0.Add(40 * time.Minute), Offset: 200 << 10, Line: 600}}
	b := fileRow("192.0.2.2", "2026-11-10.log", t0.Add(2*time.Hour), t0.Add(3*time.Hour), 5)
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpUpsert, File: a, Checkpoints: cps[:2]}, {Kind: OpUpsert, File: b}}}); err != nil {
		t.Fatal(err)
	}
	// Upserting again updates in place and adds checkpoints without duplicating.
	a.Lines, a.Size = 20, 2000
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpUpsert, File: a, Checkpoints: cps[1:]}}}); err != nil {
		t.Fatal(err)
	}
	fa, err := d.FileByPath(ctx, a.Path)
	if err != nil || fa.Lines != 20 {
		t.Fatalf("%+v %v", fa, err)
	}
	got, _ := d.Checkpoints(ctx, fa.ID)
	if len(got) != 3 {
		t.Fatalf("checkpoints %v", got)
	}
	// Seek: the last checkpoint before the time.
	if cp, _ := d.SeekCheckpoint(ctx, fa.ID, t0.Add(30*time.Minute)); cp.Offset != 100<<10 || cp.Line != 300 {
		t.Fatalf("seek %+v", cp)
	}
	if cp, _ := d.SeekCheckpoint(ctx, fa.ID, t0); cp.Offset != 0 {
		t.Fatalf("seek at start %+v", cp)
	}

	spans, err := d.FilesInRange(ctx, nil, t0.Add(45*time.Minute), t0.Add(150*time.Minute))
	if err != nil || len(spans) != 2 || spans[0].Start.Offset != 200<<10 || spans[1].Start.Offset != 0 {
		t.Fatalf("spans %+v %v", spans, err)
	}
	if spans, _ := d.FilesInRange(ctx, []string{"192.0.2.2"}, time.Time{}, time.Time{}); len(spans) != 1 || spans[0].DeviceID != "192.0.2.2" {
		t.Fatalf("device filter %+v", spans)
	}
	if spans, _ := d.FilesInRange(ctx, nil, t0.Add(4*time.Hour), time.Time{}); len(spans) != 0 {
		t.Fatalf("after all files: %+v", spans)
	}
	if spans, _ := d.FilesInRange(ctx, []string{}, time.Time{}, time.Time{}); len(spans) != 0 {
		t.Fatal("empty device list matched files")
	}

	// Rename (part close, then compression) keeps the ID and checkpoints.
	p1 := fileRow("192.0.2.1", "2026-11-10.001.log", a.FirstReceived, a.LastReceived, 20)
	p1gz := fileRow("192.0.2.1", "2026-11-10.001.log.gz", a.FirstReceived, a.LastReceived, 20)
	p1gz.Size = 300
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpRename, OldPath: a.Path, File: p1}, {Kind: OpRename, OldPath: p1.Path, File: p1gz}}}); err != nil {
		t.Fatal(err)
	}
	fz, err := d.File(ctx, fa.ID)
	if err != nil || fz.Path != p1gz.Path || !fz.Compressed || fz.Size != 300 || fz.RawSize != 2000 || fz.Part != 1 {
		t.Fatalf("after rename %+v %v", fz, err)
	}
	if got, _ := d.Checkpoints(ctx, fa.ID); len(got) != 3 {
		t.Fatal("rename lost checkpoints")
	}
	// Delete with a deletion record: the row, its checkpoints go; history and an event appear.
	del := &Deletion{Time: t0.Add(5 * time.Hour), File: p1gz.Path, DeviceID: "192.0.2.1", Bytes: 300, Reason: ReasonCap}
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpDelete, File: File{Path: p1gz.Path}, Deletion: del}}}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.File(ctx, fa.ID); err != ErrNotFound {
		t.Fatalf("deleted file still there: %v", err)
	}
	var n int
	d.db.QueryRow(`SELECT count(*) FROM checkpoints WHERE file_id = ?`, fa.ID).Scan(&n)
	if n != 0 {
		t.Fatal("checkpoints not cascaded")
	}
	hist, _ := d.Deletions(ctx, time.Time{}, time.Time{}, 0)
	if len(hist) != 1 || hist[0].Reason != ReasonCap || hist[0].Bytes != 300 || hist[0].File != p1gz.Path {
		t.Fatalf("history %+v", hist)
	}
	evs, _ := d.Events(ctx, time.Time{}, time.Time{}, 0)
	if len(evs) != 1 || evs[0].Kind != KindDelete || !strings.Contains(evs[0].Text, "storage cap") {
		t.Fatalf("events %+v", evs)
	}
	// An invalid reason is rejected by the schema.
	bad := &Deletion{Time: t0, File: "x", DeviceID: "y", Reason: "whim"}
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpDelete, File: File{Path: "x"}, Deletion: bad}}}); err == nil {
		t.Fatal("accepted bad reason")
	}
}

func TestDevicesAndStats(t *testing.T) {
	d := openIn(t, t.TempDir())
	act := []Activity{
		{DeviceID: "192.0.2.1", IP: "192.0.2.1", Minute: t0, FirstHeard: t0.Add(time.Second), LastHeard: t0.Add(50 * time.Second),
			Counts: Counts{Msgs: 100, Bytes: 10000, Truncated: 1}},
		{DeviceID: "192.0.2.1", IP: "192.0.2.1", Minute: t0.Add(2*time.Minute + 30*time.Second), LastHeard: t0.Add(150 * time.Second),
			Counts: Counts{Msgs: 50, Bytes: 5000}},
		{DeviceID: "2001_db8__1", IP: "2001:db8::1", Minute: t0.Add(time.Minute), FirstHeard: t0.Add(61 * time.Second),
			LastHeard: t0.Add(62 * time.Second), Counts: Counts{Dropped: 7}},
	}
	if err := d.Apply(ctx, Batch{Activity: act, Files: []FileOp{{Kind: OpUpsert, File: fileRow("192.0.2.1", "2026-11-10.log", t0, t0, 3)}}}); err != nil {
		t.Fatal(err)
	}
	// The same minute again adds up.
	if err := d.Apply(ctx, Batch{Activity: act[:1]}); err != nil {
		t.Fatal(err)
	}
	devs, err := d.ListDevices(ctx)
	if err != nil || len(devs) != 2 {
		t.Fatalf("%+v %v", devs, err)
	}
	d1 := devs[0]
	if d1.ID != "192.0.2.1" || d1.TotalMsgs != 250 || d1.TotalBytes != 25000 || !d1.FirstSeen.Equal(t0.Add(time.Second)) ||
		!d1.LastHeard.Equal(t0.Add(150*time.Second)) || d1.BytesOnDisk != 300 {
		t.Fatalf("device %+v", d1)
	}
	if d2 := devs[1]; d2.IP != "2001:db8::1" || d2.TotalMsgs != 0 || !d2.LastHeard.Equal(t0.Add(62*time.Second)) {
		t.Fatalf("dropped-only device %+v", d2)
	}
	name, group, hidden := "edge-01", "HQ", true
	up, err := d.UpdateDevice(ctx, "192.0.2.1", DeviceUpdate{Name: &name, Group: &group})
	if err != nil || up.Name != "edge-01" || up.Group != "HQ" || up.Hidden {
		t.Fatalf("%+v %v", up, err)
	}
	up, _ = d.UpdateDevice(ctx, "192.0.2.1", DeviceUpdate{Hidden: &hidden})
	if up.Name != "edge-01" || !up.Hidden {
		t.Fatalf("partial update %+v", up)
	}
	if _, err := d.UpdateDevice(ctx, "198.51.100.9", DeviceUpdate{Name: &name}); err != ErrNotFound {
		t.Fatalf("missing device: %v", err)
	}
	if _, err := d.Device(ctx, "198.51.100.9"); err != ErrNotFound {
		t.Fatal(err)
	}

	series, err := d.MinuteSeries(ctx, nil, t0, t0.Add(4*time.Minute))
	if err != nil || len(series) != 4 {
		t.Fatalf("%+v %v", series, err)
	}
	if series[0].Msgs != 200 || series[1].Dropped != 7 || series[2].Msgs != 50 || series[3].Msgs != 0 || !series[3].Minute.Equal(t0.Add(3*time.Minute)) {
		t.Fatalf("series %+v", series)
	}
	only, _ := d.MinuteSeries(ctx, []string{"2001_db8__1"}, t0, t0.Add(4*time.Minute))
	if only[0].Msgs != 0 || only[1].Dropped != 7 {
		t.Fatalf("filtered series %+v", only)
	}
	tot, _ := d.TotalCounts(ctx, t0.Add(-24*time.Hour), t0.Add(time.Hour))
	if tot.Msgs != 250 || tot.Dropped != 7 || tot.Truncated != 2 {
		t.Fatalf("totals %+v", tot)
	}
	per, _ := d.DeviceCounts(ctx, t0.Add(2*time.Minute), t0.Add(3*time.Minute))
	if len(per) != 1 || per["192.0.2.1"].Msgs != 50 {
		t.Fatalf("per device %+v", per)
	}
	// Prune drops old stats but keeps device totals.
	if err := d.Prune(ctx, t0.Add(2*time.Minute), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if tot, _ := d.TotalCounts(ctx, time.Time{}, t0.Add(time.Hour)); tot.Msgs != 50 {
		t.Fatalf("after prune %+v", tot)
	}
	if dv, _ := d.Device(ctx, "192.0.2.1"); dv.TotalMsgs != 250 {
		t.Fatal("prune touched device totals")
	}
}

func TestEvents(t *testing.T) {
	d := openIn(t, t.TempDir())
	for i := 0; i < 5; i++ {
		if err := d.AddEvent(ctx, Event{Time: t0.Add(time.Duration(i) * time.Minute), Level: LevelWarn, Kind: KindBind, Text: "bind tcp 514"}); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := d.Events(ctx, t0.Add(time.Minute), t0.Add(4*time.Minute), 0)
	if err != nil || len(evs) != 3 || !evs[0].Time.Equal(t0.Add(time.Minute)) || evs[0].Level != LevelWarn {
		t.Fatalf("%+v %v", evs, err)
	}
	if evs, _ := d.Events(ctx, time.Time{}, time.Time{}, 2); len(evs) != 2 {
		t.Fatal("limit")
	}
	d.Prune(ctx, time.Time{}, t0.Add(2*time.Minute))
	if evs, _ := d.Events(ctx, time.Time{}, time.Time{}, 0); len(evs) != 3 {
		t.Fatalf("after prune %d", len(evs))
	}
}

// writeLog writes a log file the way the store does.
func writeLog(t *testing.T, dataDir, dev, name string, start time.Time, n int, step time.Duration) {
	t.Helper()
	ip := netip.MustParseAddr(strings.ReplaceAll(dev, "_", ":"))
	var buf []byte
	for i := 0; i < n; i++ {
		buf = logfile.AppendLine(buf, start.Add(time.Duration(i)*step), ip, []byte(strings.Repeat("m", 200)+"\n"))
	}
	dir := filepath.Join(dataDir, logfile.LogsDir, dev)
	os.MkdirAll(dir, 0o700)
	if err := os.WriteFile(filepath.Join(dir, name), buf, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReindexAndReconcile(t *testing.T) {
	dataDir := t.TempDir()
	writeLog(t, dataDir, "192.0.2.1", "2026-11-10.log", t0, 5000, 100*time.Millisecond)
	writeLog(t, dataDir, "192.0.2.1", "2026-11-09.log", t0.Add(-24*time.Hour), 10, time.Second)
	writeLog(t, dataDir, "2001_db8__1", "2026-11-10.log", t0, 3, time.Second)
	d := openIn(t, t.TempDir())
	name := "kept"
	d.Apply(ctx, Batch{Activity: []Activity{{DeviceID: "192.0.2.1", IP: "192.0.2.1", Minute: t0.Add(-48 * time.Hour),
		FirstHeard: t0.Add(-48 * time.Hour), LastHeard: t0.Add(-48 * time.Hour), Counts: Counts{Msgs: 1}}}})
	d.UpdateDevice(ctx, "192.0.2.1", DeviceUpdate{Name: &name})

	res, err := d.Reindex(ctx, dataDir)
	if err != nil || len(res.Files) != 3 || res.Scanned != 3 || res.Devices != 2 {
		t.Fatalf("%+v %v", res, err)
	}
	dv, _ := d.Device(ctx, "192.0.2.1")
	if dv.Name != "kept" || !dv.FirstSeen.Equal(t0.Add(-48*time.Hour)) || dv.TotalMsgs != 5010 || dv.TotalBytes != 5010*201 {
		t.Fatalf("device after reindex %+v", dv)
	}
	if v6, _ := d.Device(ctx, "2001_db8__1"); v6.IP != "2001:db8::1" {
		t.Fatalf("v6 device %+v", v6)
	}
	big, _ := d.FileByPath(ctx, "logs/192.0.2.1/2026-11-10.log")
	cps, _ := d.Checkpoints(ctx, big.ID)
	if big.Lines != 5000 || len(cps) < 2 || !big.LastReceived.Equal(t0.Add(4999*100*time.Millisecond)) {
		t.Fatalf("file %+v, %d checkpoints", big, len(cps))
	}

	// Reconcile with nothing changed scans nothing.
	if res, err := d.Reconcile(ctx, dataDir); err != nil || res.Scanned != 0 || res.Removed != 0 {
		t.Fatalf("idle reconcile %+v %v", res, err)
	}
	// Grow the big file and delete another: Reconcile scans only the new tail and
	// ends up identical to a full rebuild.
	f, _ := os.OpenFile(filepath.Join(dataDir, "logs/192.0.2.1/2026-11-10.log"), os.O_APPEND|os.O_WRONLY, 0)
	var more []byte
	for i := 0; i < 3000; i++ {
		more = logfile.AppendLine(more, t0.Add(time.Hour+time.Duration(i)*100*time.Millisecond), netip.MustParseAddr("192.0.2.1"), []byte("more"))
	}
	f.Write(more)
	f.Close()
	os.Remove(filepath.Join(dataDir, "logs/2001_db8__1/2026-11-10.log"))
	res, err = d.Reconcile(ctx, dataDir)
	if err != nil || res.Scanned != 1 || res.Removed != 1 || len(res.Files) != 2 {
		t.Fatalf("reconcile %+v %v", res, err)
	}
	inc, _ := d.FileByPath(ctx, "logs/192.0.2.1/2026-11-10.log")
	incCPs, _ := d.Checkpoints(ctx, inc.ID)
	if inc.ID != big.ID {
		t.Fatal("reconcile changed the file ID")
	}
	fresh := openIn(t, t.TempDir())
	if _, err := fresh.Reindex(ctx, dataDir); err != nil {
		t.Fatal(err)
	}
	full, _ := fresh.FileByPath(ctx, inc.Path)
	fullCPs, _ := fresh.Checkpoints(ctx, full.ID)
	inc.ID, full.ID = 0, 0
	if inc != full {
		t.Fatalf("incremental %+v\nfull        %+v", inc, full)
	}
	if len(incCPs) != len(fullCPs) {
		t.Fatalf("checkpoints: incremental %d, full %d", len(incCPs), len(fullCPs))
	}
	for i := range incCPs {
		if incCPs[i] != fullCPs[i] {
			t.Fatalf("checkpoint %d: %+v vs %+v", i, incCPs[i], fullCPs[i])
		}
	}
}

func TestReindexSkipsUnfinishedCompression(t *testing.T) {
	dataDir := t.TempDir()
	writeLog(t, dataDir, "192.0.2.1", "2026-11-09.log", t0, 10, time.Second)
	os.WriteFile(filepath.Join(dataDir, "logs/192.0.2.1/2026-11-09.log.gz"), []byte("not really gzip"), 0o600)
	d := openIn(t, t.TempDir())
	res, err := d.Reindex(ctx, dataDir)
	if err != nil || len(res.Files) != 1 || len(res.Skipped) != 1 || res.Files[0].Compressed {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRollupAndCounts(t *testing.T) {
	d := openIn(t, t.TempDir())
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	// One message per device per minute for 30 hours, two devices, one drop an hour.
	var acts []Activity
	for m := 0; m < 30*60; m++ {
		min := base.Add(time.Duration(m) * time.Minute)
		for _, dev := range []string{"192.0.2.1", "192.0.2.2"} {
			a := Activity{DeviceID: dev, IP: dev, Minute: min, FirstHeard: min, LastHeard: min, Counts: Counts{Msgs: 1, Bytes: 10}}
			if m%60 == 0 && dev == "192.0.2.2" {
				a.Dropped, a.Truncated = 1, 1
			}
			acts = append(acts, a)
		}
	}
	if err := d.Apply(ctx, Batch{Activity: acts}); err != nil {
		t.Fatal(err)
	}
	now := base.Add(30*time.Hour - 20*time.Minute) // 05:40 on day 2
	before, _ := d.Counts(ctx, nil, time.Time{}, time.Time{})
	moved, err := d.RollupStats(ctx, now.Add(-MinuteRetention))
	// The boundary is 05:00 on day 1: hours 00..04 move (5 h x 60 min x 2 devices).
	if err != nil || moved != 600 {
		t.Fatalf("moved %d, %v", moved, err)
	}
	if again, _ := d.RollupStats(ctx, now.Add(-MinuteRetention)); again != 0 {
		t.Fatalf("second rollup moved %d", again)
	}
	after, _ := d.Counts(ctx, nil, time.Time{}, time.Time{})
	if after != before || after.Msgs != 3600 || after.Dropped != 30 {
		t.Fatalf("totals changed by the rollup: %+v -> %+v", before, after)
	}
	var minuteRows, hourRows int
	d.db.QueryRow(`SELECT count(*) FROM stats`).Scan(&minuteRows)
	d.db.QueryRow(`SELECT count(*) FROM stats_hourly`).Scan(&hourRows)
	if minuteRows != 3000 || hourRows != 10 {
		t.Fatalf("%d minute rows, %d hourly rows", minuteRows, hourRows)
	}
	// Last 24 h is still per-minute, so it's exact to the minute.
	c24, _ := d.Counts(ctx, nil, now.Add(-24*time.Hour), now)
	if c24.Msgs != 2*24*60 || c24.Dropped != 24 {
		t.Fatalf("24h %+v", c24)
	}
	// A range spanning both tables: day 1 00:30 .. 06:00 = hourly 00..04 whole, then minutes 05:00..05:59.
	span, _ := d.Counts(ctx, []string{"192.0.2.2"}, base.Add(30*time.Minute), base.Add(6*time.Hour))
	if span.Msgs != 6*60 || span.Dropped != 6 || span.Truncated != 6 {
		t.Fatalf("span %+v", span)
	}
	per, _ := d.DeviceCounts(ctx, time.Time{}, time.Time{})
	if per["192.0.2.1"].Msgs != 1800 || per["192.0.2.2"].Dropped != 30 {
		t.Fatalf("per device %+v", per)
	}
	// Hourly series covers both tables with no gap at the boundary.
	hs, err := d.HourSeries(ctx, nil, base, base.Add(30*time.Hour))
	if err != nil || len(hs) != 30 {
		t.Fatalf("%d hours %v", len(hs), err)
	}
	for i, h := range hs {
		if h.Msgs != 120 || !h.Hour.Equal(base.Add(time.Duration(i)*time.Hour)) {
			t.Fatalf("hour %d: %+v", i, h)
		}
	}
	// MinuteSeries reads minutes only: rolled-up minutes are zero.
	ms, _ := d.MinuteSeries(ctx, nil, base.Add(4*time.Hour+59*time.Minute), base.Add(5*time.Hour+time.Minute))
	if ms[0].Msgs != 0 || ms[1].Msgs != 2 {
		t.Fatalf("minute series at boundary %+v", ms)
	}
	// A late delta for a rolled-up minute is kept and counted once.
	late := base.Add(2*time.Hour + 5*time.Minute)
	d.Apply(ctx, Batch{Activity: []Activity{{DeviceID: "192.0.2.1", IP: "192.0.2.1", Minute: late, LastHeard: late, Counts: Counts{Msgs: 5}}}})
	if c, _ := d.Counts(ctx, nil, time.Time{}, time.Time{}); c.Msgs != 3605 {
		t.Fatalf("late delta %+v", c)
	}
	d.RollupStats(ctx, now.Add(-MinuteRetention))
	if c, _ := d.Counts(ctx, nil, time.Time{}, time.Time{}); c.Msgs != 3605 {
		t.Fatalf("late delta after rollup %+v", c)
	}
	// Prune drops hourly buckets older than the stats retention too.
	d.Prune(ctx, base.Add(3*time.Hour), time.Time{})
	if c, _ := d.Counts(ctx, nil, time.Time{}, time.Time{}); c.Msgs != 3605-5-3*120 {
		t.Fatalf("after prune %+v", c)
	}
}

// dropV6 undoes migration 5 -> 6 (data types).
const dropV6 = `DROP INDEX files_type_device_time; ALTER TABLE files DROP COLUMN type; ALTER TABLE deletions DROP COLUMN type;
	DROP TABLE type_stats; DROP TABLE type_stats_hourly; `

// dropV4Indexes undoes migrations 5 -> 6, 4 -> 5 and 3 -> 4, for tests that rebuild an older schema.
const dropV4Indexes = dropV6 + `DROP TABLE saved_searches; DROP INDEX stats_minute_msgs; DROP INDEX stats_drops; DROP INDEX stats_hourly_drops;
	DROP INDEX devices_last_heard; DROP INDEX devices_first_seen; DROP INDEX devices_name_sort; `

func TestMigrateV3ToV4Indexes(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV4Indexes + `PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != CurrentSchema || CurrentSchema != 6 {
		t.Fatalf("version %d", v)
	}
	var n int
	d2.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name IN ('stats_minute_msgs', 'stats_drops',
		'stats_hourly_drops', 'devices_last_heard', 'devices_first_seen', 'devices_name_sort')`).Scan(&n)
	if n != 6 {
		t.Errorf("%d of 6 indexes", n)
	}
}

func TestMigrateV2ToV3EventSource(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	// Turn it back into a v2 database with an event in it.
	if _, err := d.db.Exec(dropV4Indexes + `ALTER TABLE events DROP COLUMN source; PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec(`INSERT INTO events (time, level, kind, device_id, text) VALUES (?, 'info', 'start', '', 'old')`, t0.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != CurrentSchema {
		t.Fatalf("version %d", v)
	}
	d2.AddEvent(ctx, Event{Time: t0.Add(time.Second), Level: LevelInfo, Kind: KindStart, Text: "new", Source: SourceListenerUDP})
	evs, err := d2.Events(ctx, time.Time{}, time.Time{}, 0)
	if err != nil || len(evs) != 2 || evs[0].Source != "" || evs[1].Source != SourceListenerUDP || evs[1].Text != "new" {
		t.Fatalf("%+v %v", evs, err)
	}
	if ListenerSource("tcp") != SourceListenerTCP || ListenerSource("x") != "" {
		t.Error("ListenerSource")
	}
}

func TestMigrateV1ToV2(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	d.Apply(ctx, Batch{Activity: []Activity{{DeviceID: "192.0.2.1", IP: "192.0.2.1", Minute: t0, Counts: Counts{Msgs: 3}}}})
	// Turn it back into a v1 database.
	if _, err := d.db.Exec(dropV4Indexes + `DROP TABLE stats_hourly; ALTER TABLE events DROP COLUMN source; PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != CurrentSchema {
		t.Fatalf("version %d", v)
	}
	if n, err := d2.RollupStats(ctx, t0.Add(48*time.Hour)); err != nil || n != 1 {
		t.Fatalf("rollup after migration: %d %v", n, err)
	}
	if c, _ := d2.TotalCounts(ctx, time.Time{}, time.Time{}); c.Msgs != 3 {
		t.Fatalf("%+v", c)
	}
}

func TestManyDeviceIDs(t *testing.T) {
	d := openIn(t, t.TempDir())
	ids := make([]string, 40000)
	var acts []Activity
	var ops []FileOp
	for i := range ids {
		ids[i] = fmt.Sprintf("198.51.%d.%d", i/250, i%250)
		if i%1000 == 0 {
			acts = append(acts, Activity{DeviceID: ids[i], IP: ids[i], Minute: t0, LastHeard: t0, Counts: Counts{Msgs: 1}})
			ops = append(ops, FileOp{Kind: OpUpsert, File: fileRow(ids[i], "2026-11-10.log", t0, t0, 1)})
		}
	}
	if err := d.Apply(ctx, Batch{Activity: acts, Files: ops}); err != nil {
		t.Fatal(err)
	}
	if c, err := d.Counts(ctx, ids, time.Time{}, time.Time{}); err != nil || c.Msgs != 40 {
		t.Fatalf("Counts over 40k ids: %+v %v", c, err)
	}
	if ms, err := d.MinuteSeries(ctx, ids, t0, t0.Add(time.Minute)); err != nil || ms[0].Msgs != 40 {
		t.Fatalf("MinuteSeries over 40k ids: %+v %v", ms, err)
	}
	if hs, err := d.HourSeries(ctx, ids, t0, t0.Add(time.Hour)); err != nil || hs[0].Msgs != 40 {
		t.Fatalf("HourSeries over 40k ids: %+v %v", hs, err)
	}
	if spans, err := d.FilesInRange(ctx, ids, time.Time{}, time.Time{}); err != nil || len(spans) != 40 {
		t.Fatalf("FilesInRange over 40k ids: %d %v", len(spans), err)
	}
	// Quotes and other JSON-special characters in an id are matched literally.
	if c, _ := d.Counts(ctx, []string{`a"b\c`}, time.Time{}, time.Time{}); c.Msgs != 0 {
		t.Fatalf("%+v", c)
	}
}

func TestRefusedStatsHaveNoDevice(t *testing.T) {
	d := openIn(t, t.TempDir())
	if err := d.Apply(ctx, Batch{Activity: []Activity{{DeviceID: RefusedDeviceID, Minute: t0, Counts: Counts{Dropped: 9}}}}); err != nil {
		t.Fatal(err)
	}
	if devs, _ := d.ListDevices(ctx); len(devs) != 0 {
		t.Fatalf("devices %+v", devs)
	}
	if c, _ := d.TotalCounts(ctx, time.Time{}, time.Time{}); c.Dropped != 9 {
		t.Fatalf("%+v", c)
	}
}
