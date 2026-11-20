package index

import (
	"strings"
	"testing"
	"time"
)

func sev(n map[int]int64) SevCounts {
	var c SevCounts
	for k, v := range n {
		c[k] = v
	}
	return c
}

// Filtered counts add up per minute, roll up into the hourly buckets exactly
// (no message counted twice or lost), are read per device and in total with
// Counts' edges, and are pruned with the other stats.
func TestFilteredCounts(t *testing.T) {
	d := openIn(t, t.TempDir())
	now := time.Date(2026, 11, 20, 12, 0, 30, 0, time.UTC)
	act := func(dev string, at time.Time, msgs int64, f SevCounts) Activity {
		return Activity{DeviceID: dev, IP: dev, Minute: at, FirstHeard: at, LastHeard: at, Counts: Counts{Msgs: msgs, Filtered: f}}
	}
	if err := d.Apply(ctx, Batch{Activity: []Activity{
		act("10.1.0.1", now.Add(-30*time.Hour), 1, sev(map[int]int64{7: 100})),
		act("10.1.0.1", now.Add(-2*time.Hour), 2, sev(map[int]int64{7: 10, 6: 1})),
		act("10.1.0.1", now.Add(-2*time.Hour), 0, sev(map[int]int64{7: 5})), // the same minute: added
		act("10.1.0.2", now.Add(-time.Minute), 3, SevCounts{}),
		act(RefusedDeviceID, now.Add(-time.Minute), 0, sev(map[int]int64{7: 4})),
	}}); err != nil {
		t.Fatal(err)
	}
	day := now.Add(-24 * time.Hour)
	got, err := d.FilteredCounts(ctx, nil, day, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["10.1.0.1"] != sev(map[int]int64{7: 15, 6: 1}) || got[RefusedDeviceID] != sev(map[int]int64{7: 4}) {
		t.Fatalf("24 h: %v", got)
	}
	if tot, err := d.FilteredTotal(ctx, day); err != nil || tot.Total() != 20 {
		t.Fatalf("total %v %v", tot, err)
	}
	if got, _ := d.FilteredCounts(ctx, []string{"10.1.0.2"}, time.Time{}, time.Time{}); len(got) != 0 {
		t.Fatalf("a device with none: %v", got)
	}
	if got, _ := d.FilteredCounts(ctx, []string{}, time.Time{}, time.Time{}); len(got) != 0 {
		t.Fatalf("no devices: %v", got)
	}
	// Stored messages and the device row are untouched by the filtered counts.
	if c, _ := d.Counts(ctx, []string{"10.1.0.1"}, time.Time{}, time.Time{}); c.Msgs != 3 || c.Dropped != 0 {
		t.Fatalf("counts %+v", c)
	}
	dv, err := d.Device(ctx, "10.1.0.1")
	if err != nil || dv.TotalMsgs != 3 || !dv.LastHeard.Equal(now.Add(-2*time.Hour).Truncate(time.Millisecond)) {
		t.Fatalf("device %+v %v", dv, err)
	}

	if _, err := d.RollupStats(ctx, now.Add(-MinuteRetention)); err != nil {
		t.Fatal(err)
	}
	all, _ := d.FilteredCounts(ctx, nil, time.Time{}, time.Time{})
	if all["10.1.0.1"] != sev(map[int]int64{7: 115, 6: 1}) {
		t.Fatalf("after the rollup: %v", all)
	}
	var hourly int
	d.db.QueryRowContext(ctx, `SELECT count(*) FROM stats_hourly WHERE filtered_debug = 100`).Scan(&hourly)
	if hourly != 1 {
		t.Fatalf("hourly rows %d", hourly)
	}
	d.Prune(ctx, now.Add(-24*time.Hour), time.Time{})
	if all, _ := d.FilteredCounts(ctx, nil, time.Time{}, time.Time{}); all["10.1.0.1"] != sev(map[int]int64{7: 15, 6: 1}) {
		t.Fatalf("after the prune: %v", all)
	}
}

// FilteredIn reports a window's counts with the span it really covers: whole
// minutes, from the hour where hourly buckets are in it, from the retention
// cutoff when it starts before it, nothing known when it's all older.
func TestFilteredInWindow(t *testing.T) {
	d := openIn(t, t.TempDir())
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	act := func(at time.Time, n int64) Activity {
		return Activity{DeviceID: "10.1.0.1", IP: "10.1.0.1", Minute: at, FirstHeard: at, LastHeard: at, Counts: Counts{Filtered: sev(map[int]int64{7: n})}}
	}
	if err := d.Apply(ctx, Batch{Activity: []Activity{act(now.Add(-9*24*time.Hour), 900), act(now.Add(-30*time.Hour), 30),
		act(now.Add(-10*time.Minute), 1), act(now.Add(-10*time.Minute+30*time.Second), 2), act(now.Add(-5*time.Minute), 4)}}); err != nil {
		t.Fatal(err)
	}
	d.RollupStats(ctx, now.Add(-MinuteRetention))
	kept := now.Add(-StatsRetention)
	d.Prune(ctx, kept, time.Time{})

	// A window inside the minute buckets, its edges inside minutes.
	w, err := d.FilteredIn(ctx, "10.1.0.1", now.Add(-10*time.Minute+10*time.Second), now.Add(-5*time.Minute+10*time.Second), kept)
	if err != nil {
		t.Fatal(err)
	}
	if w.Total() != 7 || w.ByHour || w.Partial || w.NotKept || !w.From.Equal(now.Add(-10*time.Minute)) || !w.To.Equal(now.Add(-4*time.Minute)) {
		t.Fatalf("minutes: %+v", w)
	}
	if w, _ := d.FilteredIn(ctx, "10.1.0.1", now.Add(-9*time.Minute), now.Add(-6*time.Minute), kept); w.Total() != 0 {
		t.Fatalf("an empty window: %+v", w)
	}
	// Mixed: hourly buckets 30 h back to the minute buckets.
	w, _ = d.FilteredIn(ctx, "10.1.0.1", now.Add(-30*time.Hour-17*time.Minute), now, kept)
	if w.Total() != 37 || !w.ByHour || w.Partial || !w.From.Equal(now.Add(-31*time.Hour)) {
		t.Fatalf("mixed: %+v", w)
	}
	// Across the retention cutoff: counted from there, and said so.
	w, _ = d.FilteredIn(ctx, "10.1.0.1", now.Add(-10*24*time.Hour), now, kept)
	if w.Total() != 37 || !w.Partial || !w.From.Equal(kept.Truncate(time.Hour)) {
		t.Fatalf("partial: %+v", w)
	}
	if w, _ := d.FilteredIn(ctx, "10.1.0.1", now.Add(-10*24*time.Hour), now.Add(-8*24*time.Hour), kept); !w.NotKept || w.Total() != 0 {
		t.Fatalf("not kept: %+v", w)
	}
}

// A schema-9 index (2.0.0) migrates to 10: its stats rows stay, with no
// filtered counts, and the step is an event.
func TestMigrateFilteredCounts(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV10 + `PRAGMA user_version = 9`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec(`INSERT INTO stats (device_id, minute, msgs, bytes) VALUES ('10.1.0.1', 60000, 5, 50)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != 10 {
		t.Fatalf("schema %d", v)
	}
	if _, steps := d2.Migrations(); len(steps) != 1 || steps[0].From != 9 || steps[0].To != 10 {
		t.Fatalf("steps %+v", steps)
	}
	evs, _ := d2.Events(ctx, time.Time{}, time.Time{}, 0)
	if len(evs) != 1 || evs[0].Kind != KindMigrate || !strings.HasPrefix(evs[0].Text, "index migrated from schema 9 to 10 in ") {
		t.Fatalf("events %+v", evs)
	}
	if c, _ := d2.Counts(ctx, nil, time.Time{}, time.Time{}); c.Msgs != 5 || c.Filtered.Total() != 0 {
		t.Fatalf("counts %+v", c)
	}
	if got, _ := d2.FilteredCounts(ctx, nil, time.Time{}, time.Time{}); len(got) != 0 {
		t.Fatalf("filtered %v", got)
	}
}

// The reads go through the partial indexes, so devices without filtered
// messages cost nothing (a page of the device list reads them): the
// queries' INDEXED BY must stay usable (SQLite fails the query otherwise).
func TestFilteredQueriesUseThePartialIndexes(t *testing.T) {
	d := openIn(t, t.TempDir())
	cols := strings.Join(filteredCols(""), ", ")
	for _, q := range []string{
		`EXPLAIN QUERY PLAN SELECT device_id, ` + cols + ` FROM stats INDEXED BY stats_filtered WHERE ` + filteredAny + ` AND device_id IN ('a', 'b') AND minute >= 0 AND minute < 9`,
		`EXPLAIN QUERY PLAN SELECT device_id, ` + cols + ` FROM stats_hourly INDEXED BY stats_hourly_filtered WHERE ` + filteredAny + ` AND device_id = 'a' AND hour >= 0 AND hour < 9`,
		`EXPLAIN QUERY PLAN SELECT ` + cols + ` FROM stats INDEXED BY stats_filtered WHERE ` + filteredAny + ` AND minute >= 0`,
	} {
		rows, err := d.db.QueryContext(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		var plan []string
		for rows.Next() {
			var id, parent, unused int
			var detail string
			rows.Scan(&id, &parent, &unused, &detail)
			plan = append(plan, detail)
		}
		rows.Close()
		if p := strings.Join(plan, "; "); !strings.Contains(p, "_filtered") {
			t.Errorf("plan %q for %s", p, q)
		}
	}
}
