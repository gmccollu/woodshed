package index

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A 1.1 index (schema 5) migrates once: every file row reads as syslog, and
// the trap rows and stats go beside them (SPEC §11.7).
func TestMigrate11ToTypes(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV6 + `PRAGMA user_version = 5`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec(`INSERT INTO files (device_id, path, day, part, first_received, last_received, size, raw_size, lines, compressed)
		VALUES ('192.0.2.1', 'logs/192.0.2.1/2026-11-10.log', '2026-11-10', 0, ?, ?, 10, 10, 1, 0)`, t0.UnixMilli(), t0.UnixMilli()); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != CurrentSchema {
		t.Fatalf("version %d", v)
	}
	fs, err := d2.Files(ctx, "")
	if err != nil || len(fs) != 1 || fs[0].Type != TypeSyslog {
		t.Fatalf("%+v %v", fs, err)
	}
}

func TestTypeStatsAndFiles(t *testing.T) {
	d := openIn(t, t.TempDir())
	min := t0.Truncate(time.Minute)
	err := d.Apply(ctx, Batch{
		Activity: []Activity{
			{DeviceID: "192.0.2.1", IP: "192.0.2.1", Minute: min, FirstHeard: min, LastHeard: min, Counts: Counts{Msgs: 5, Bytes: 50}},
			{DeviceID: "192.0.2.1", IP: "192.0.2.1", Type: "trap", Minute: min, FirstHeard: min, LastHeard: min, Counts: Counts{Msgs: 2, Bytes: 200}},
			{DeviceID: "192.0.2.2", IP: "192.0.2.2", Type: "trap", Minute: min, FirstHeard: min, LastHeard: min.Add(time.Second), Counts: Counts{Msgs: 3, Bytes: 300}},
		},
		Files: []FileOp{
			{Kind: OpUpsert, File: File{DeviceID: "192.0.2.1", Path: "logs/192.0.2.1/2026-11-10.log", Day: "2026-11-10", FirstReceived: min, LastReceived: min, Size: 50, RawSize: 50, Lines: 5}},
			{Kind: OpUpsert, File: File{DeviceID: "192.0.2.1", Type: "trap", Path: "logs/192.0.2.1/traps/2026-11-10.log", Day: "2026-11-10", FirstReceived: min, LastReceived: min, Size: 200, RawSize: 200, Lines: 2}},
			{Kind: OpUpsert, File: File{DeviceID: "192.0.2.2", Type: "trap", Path: "logs/192.0.2.2/traps/2026-11-10.log", Day: "2026-11-10", FirstReceived: min, LastReceived: min, Size: 300, RawSize: 300, Lines: 3}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Syslog's own stats table is untouched by traps.
	var n int64
	d.db.QueryRow(`SELECT COALESCE(sum(msgs),0) FROM stats`).Scan(&n)
	if n != 5 {
		t.Fatalf("stats msgs %d", n)
	}
	// Totals and device counts count every type; a trap-only device exists and is heard.
	if c, _ := d.TotalCounts(ctx, time.Time{}, time.Time{}); c.Msgs != 10 || c.Bytes != 550 {
		t.Fatalf("totals %+v", c)
	}
	per, _ := d.DeviceCounts(ctx, time.Time{}, time.Time{})
	if per["192.0.2.1"].Msgs != 7 || per["192.0.2.2"].Msgs != 3 {
		t.Fatalf("per device %+v", per)
	}
	dev, err := d.Device(ctx, "192.0.2.2")
	if err != nil || dev.TotalMsgs != 3 || !dev.LastHeard.Equal(min.Add(time.Second)) {
		t.Fatalf("trap-only device %+v %v", dev, err)
	}
	ms, _ := d.MinuteSeries(ctx, nil, min, min.Add(time.Minute))
	if len(ms) != 1 || ms[0].Msgs != 10 {
		t.Fatalf("minute series %+v", ms)
	}
	// Files by type.
	sp, _ := d.FilesInRange(ctx, nil, time.Time{}, time.Time{})
	if len(sp) != 1 || sp[0].Type != TypeSyslog {
		t.Fatalf("syslog spans %+v", sp)
	}
	sp, _ = d.FilesInRangeOf(ctx, "trap", nil, time.Time{}, time.Time{})
	if len(sp) != 2 || sp[0].Type != "trap" {
		t.Fatalf("trap spans %+v", sp)
	}
	types, _ := d.DeviceTypes(ctx, nil)
	if types["192.0.2.1"]["syslog"] != 5 || types["192.0.2.1"]["trap"] != 2 || len(types["192.0.2.2"]) != 1 {
		t.Fatalf("device types %+v", types)
	}
	if ok, _ := d.HasType(ctx, "trap"); !ok {
		t.Fatal("HasType")
	}
	// The histogram reads the type's own stats.
	cut := map[string]int64{"192.0.2.1": 0, "192.0.2.2": 0}
	b, _ := d.StatsBucketsOf(ctx, "trap", cut, false, 0, min.Add(time.Hour).UnixMilli(), 0, 3600000)
	var sum int64
	for _, v := range b {
		sum += v
	}
	if sum != 5 {
		t.Fatalf("trap buckets %v", b)
	}
	b, _ = d.StatsBuckets(ctx, cut, false, 0, min.Add(time.Hour).UnixMilli(), 0, 3600000)
	sum = 0
	for _, v := range b {
		sum += v
	}
	if sum != 5 {
		t.Fatalf("syslog buckets %v", b)
	}
	// Rollup moves type_stats too; nothing is counted twice.
	if _, err := d.RollupStats(ctx, min.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c, _ := d.TotalCounts(ctx, time.Time{}, time.Time{}); c.Msgs != 10 {
		t.Fatalf("after rollup %+v", c)
	}
	b, _ = d.StatsBucketsOf(ctx, "trap", cut, false, 0, min.Add(time.Hour).UnixMilli(), 0, 3600000)
	sum = 0
	for _, v := range b {
		sum += v
	}
	if sum != 5 {
		t.Fatalf("trap buckets after rollup %v", b)
	}
	// A deletion records its type.
	if err := d.Apply(ctx, Batch{Files: []FileOp{{Kind: OpDelete, File: File{DeviceID: "192.0.2.2", Path: "logs/192.0.2.2/traps/2026-11-10.log"},
		Deletion: &Deletion{Time: t0, File: "logs/192.0.2.2/traps/2026-11-10.log", DeviceID: "192.0.2.2", Type: "trap", Bytes: 300, Reason: ReasonAge}}}}); err != nil {
		t.Fatal(err)
	}
	dels, _ := d.Deletions(ctx, time.Time{}, time.Time{}, 0)
	if len(dels) != 1 || dels[0].Type != "trap" {
		t.Fatalf("deletions %+v", dels)
	}
}

func TestReindexTypes(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o750)
		if err := os.WriteFile(p, []byte(body), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("logs/192.0.2.1/2026-11-10.log", "2026-11-10T12:00:00.000Z 192.0.2.1 <13>hello\n")
	write("logs/192.0.2.1/traps/2026-11-10.log", "2026-11-10T12:00:01.000Z 192.0.2.1 v=2c pdu=trap id=1 cred=#00000000 status=ok raw=AA==\n"+
		"2026-11-10T12:00:02.000Z 192.0.2.1 v=2c pdu=trap id=2 cred=#00000000 status=ok raw=AA==\n")
	write("logs/192.0.2.1/unknown/2026-11-10.log", "2026-11-10T12:00:01.000Z 192.0.2.1 x\n")
	d := openIn(t, dir)
	res, err := d.Reindex(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 2 {
		t.Fatalf("files %+v", res.Files)
	}
	byPath := map[string]File{}
	for _, f := range res.Files {
		byPath[f.Path] = f
	}
	if f := byPath["logs/192.0.2.1/traps/2026-11-10.log"]; f.Type != "trap" || f.Lines != 2 {
		t.Fatalf("trap row %+v", f)
	}
	if f := byPath["logs/192.0.2.1/2026-11-10.log"]; f.Type != TypeSyslog || f.Lines != 1 {
		t.Fatalf("syslog row %+v", f)
	}
	dev, _ := d.Device(ctx, "192.0.2.1")
	if dev.TotalMsgs != 3 {
		t.Fatalf("device %+v", dev)
	}
}
