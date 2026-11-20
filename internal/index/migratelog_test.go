package index

import (
	"regexp"
	"testing"
	"time"
)

// Open reports each schema step it applies to an existing index, and records
// it as an event; a new index reports created and records none.
func TestMigrationsReported(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if created, steps := d.Migrations(); !created || len(steps) != 0 {
		t.Fatalf("fresh: created %v steps %v", created, steps)
	}
	if evs, err := d.Events(ctx, time.Time{}, time.Time{}, 0); err != nil || len(evs) != 0 {
		t.Fatalf("fresh index events %v %v", evs, err)
	}
	// Back to a 1.3 index (schema 7), as an upgrade to 2.0 finds it.
	if _, err := d.db.Exec(dropV8 + `PRAGMA user_version = 7`); err != nil {
		t.Fatal(err)
	}
	d.Close()

	d2 := openIn(t, dir)
	created, steps := d2.Migrations()
	if created || len(steps) != 3 || steps[0].From != 7 || steps[0].To != 8 || steps[1].From != 8 || steps[1].To != 9 ||
		steps[2].From != 9 || steps[2].To != 10 {
		t.Fatalf("upgrade: created %v steps %+v", created, steps)
	}
	evs, err := d2.Events(ctx, time.Time{}, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^index migrated from schema (7 to 8|8 to 9|9 to 10) in (\d+ ms|under 1 ms)$`)
	var got []string
	for _, e := range evs {
		if e.Kind != KindMigrate || e.Level != LevelInfo || e.DeviceID != "" || !re.MatchString(e.Text) {
			t.Fatalf("event %+v", e)
		}
		got = append(got, e.Text)
	}
	if len(got) != 3 {
		t.Fatalf("migrate events %q", got)
	}
	d2.Close()

	// A current index: nothing to report, no new events.
	d3 := openIn(t, dir)
	if created, steps := d3.Migrations(); created || len(steps) != 0 {
		t.Fatalf("current: created %v steps %v", created, steps)
	}
	if evs, _ := d3.Events(ctx, time.Time{}, time.Time{}, 0); len(evs) != 3 {
		t.Fatalf("events after a no-op open: %d", len(evs))
	}
}

// A 1.0 index (schema 1, before events had a source) migrates all the way,
// one event per step.
func TestMigrationsFromSchema1(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV4Indexes + `DROP TABLE stats_hourly; ALTER TABLE events DROP COLUMN source; PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if _, steps := d2.Migrations(); len(steps) != CurrentSchema-1 {
		t.Fatalf("steps %+v", steps)
	}
	if evs, _ := d2.Events(ctx, time.Time{}, time.Time{}, 0); len(evs) != CurrentSchema-1 {
		t.Fatalf("events %d", len(evs))
	}
}

func TestMigrationText(t *testing.T) {
	for _, c := range []struct {
		took time.Duration
		want string
	}{
		{12*time.Millisecond + 400*time.Microsecond, "index migrated from schema 8 to 9 in 12 ms"},
		{300 * time.Microsecond, "index migrated from schema 8 to 9 in under 1 ms"},
		{2 * time.Second, "index migrated from schema 8 to 9 in 2000 ms"},
	} {
		if got := (Migration{From: 8, To: 9, Took: c.took}).Text(); got != c.want {
			t.Errorf("%v: %q", c.took, got)
		}
	}
}
