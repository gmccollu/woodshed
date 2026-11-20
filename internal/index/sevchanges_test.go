package index

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// A change and its event go in together; the newest per address (or the
// default) and the whole list read back as written, an unknown "was" too.
func TestSeverityChanges(t *testing.T) {
	d := openIn(t, t.TempDir())
	ctx := context.Background()
	at := time.Date(2026, 11, 20, 9, 30, 0, 0, time.UTC)
	for i, c := range []SeverityChange{
		{Time: at, Default: true, Level: 6, Was: 7, WasKnown: true, Source: SeverityLive},
		{Time: at.Add(time.Minute), Address: "fe80::1", Level: 6, Was: -1, WasKnown: true, Source: SeverityStopped},
		{Time: at.Add(2 * time.Minute), Address: "fe80::1", Level: -1, Source: SeverityLive},
	} {
		if err := d.AddSeverityChange(ctx, c, Event{DeviceID: "fe80__1_en0", Text: "change"}); err != nil {
			t.Fatal(i, err)
		}
	}
	cs, err := d.SeverityChanges(ctx)
	if err != nil || len(cs) != 3 {
		t.Fatalf("%v %v", cs, err)
	}
	if c := cs[1]; !c.Time.Equal(at.Add(time.Minute)) || c.Address != "fe80::1" || c.Default || c.Level != 6 || c.Was != -1 || !c.WasKnown || c.Source != SeverityStopped {
		t.Errorf("row %+v", c)
	}
	if c, ok, err := d.LatestSeverityChange(ctx, "fe80::1"); err != nil || !ok || c.Level != -1 || c.WasKnown {
		t.Errorf("latest %+v %v %v", c, ok, err)
	}
	if c, ok, err := d.LatestSeverityChange(ctx, ""); err != nil || !ok || !c.Default || c.Level != 6 {
		t.Errorf("latest default %+v %v %v", c, ok, err)
	}
	if _, ok, err := d.LatestSeverityChange(ctx, "192.0.2.1"); err != nil || ok {
		t.Errorf("none: %v %v", ok, err)
	}
	evs, err := d.EventsOfKind(ctx, KindSeverityFilter)
	if err != nil || len(evs) != 3 || !evs[0].Time.Equal(at) || evs[2].DeviceID != "fe80__1_en0" {
		t.Errorf("events %+v %v", evs, err)
	}
}

// An index from 2.1.0-rc1 (schema 10, no severity_changes) gains the table
// at Open, keeping the schema; opened read-only before that, it reads as no
// changes.
func TestSeverityChangesOnAnRC1Index(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(`DROP TABLE severity_changes`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	path := filepath.Join(dir, FileName)
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if cs, err := ro.SeverityChanges(context.Background()); err != nil || cs != nil {
		t.Errorf("read-only: %v %v", cs, err)
	}
	if _, ok, err := ro.LatestSeverityChange(context.Background(), ""); err != nil || ok {
		t.Errorf("read-only latest: %v %v", ok, err)
	}
	ro.Close()
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if v, _ := d.SchemaVersion(context.Background()); v != 10 {
		t.Errorf("schema %d", v)
	}
	if err := d.AddSeverityChange(context.Background(), SeverityChange{Default: true, Level: 4, Was: 7, WasKnown: true, Source: SeverityLive},
		Event{Text: "change"}); err != nil {
		t.Fatal(err)
	}
	if _, steps := d.Migrations(); len(steps) != 0 {
		t.Errorf("migrated %v", steps)
	}
}
