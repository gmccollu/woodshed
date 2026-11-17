package index

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/store/logfile"
	"net/netip"
)

// A 1.2 index (schema 6) migrates once to 7, keeping everything.
func TestMigrate12ToPoll(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV7 + `PRAGMA user_version = 6`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != CurrentSchema {
		t.Fatalf("schema %d", v)
	}
	if ts, err := d2.PollTargets(ctx); err != nil || len(ts) != 0 {
		t.Errorf("targets %v %v", ts, err)
	}
}

func TestPollTargetsCRUD(t *testing.T) {
	d := openIn(t, t.TempDir())
	now := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	a, err := d.CreatePollTarget(ctx, PollTarget{Address: "10.1.0.1", Port: 161, DeviceID: "10.1.0.1", Settings: `{"v":1}`}, 2, now)
	if err != nil || a.ID == "" || a.Version != 1 {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := d.CreatePollTarget(ctx, PollTarget{Address: "10.1.0.1", Port: 161, DeviceID: "x", Settings: "{}"}, 2, now); !errors.Is(err, ErrPollTargetExists) {
		t.Errorf("duplicate: %v", err)
	}
	b, err := d.CreatePollTarget(ctx, PollTarget{Address: "10.1.0.1", Port: 1161, DeviceID: "10.1.0.1", Settings: "{}"}, 2, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreatePollTarget(ctx, PollTarget{Address: "10.1.0.2", Port: 161, Settings: "{}"}, 2, now); !errors.Is(err, ErrPollTargetLimit) {
		t.Errorf("limit: %v", err)
	}
	if err := d.SetPollEngine(ctx, a.ID, []byte{0x80, 1, 2, 3, 4}, 7, 1234, now); err != nil {
		t.Fatal(err)
	}
	got, _ := d.PollTarget(ctx, a.ID)
	if string(got.EngineID) != "\x80\x01\x02\x03\x04" || got.EngineBoots != 7 || got.EngineTime != 1234 || !got.EngineAt.Equal(now) || got.Version != 1 {
		t.Errorf("engine %+v", got)
	}
	// Same address: the engine stays; a stale version is refused.
	a.Settings = `{"v":2}`
	up, err := d.UpdatePollTarget(ctx, a, 1, now)
	if err != nil || up.Version != 2 || up.EngineBoots != 7 {
		t.Fatalf("update %+v %v", up, err)
	}
	if _, err := d.UpdatePollTarget(ctx, a, 1, now); !errors.Is(err, ErrPollTargetChanged) {
		t.Errorf("stale: %v", err)
	}
	b.Port = 161
	if _, err := d.UpdatePollTarget(ctx, b, 0, now); !errors.Is(err, ErrPollTargetExists) {
		t.Errorf("collide: %v", err)
	}
	// A new address forgets the engine.
	a.Address = "10.1.0.9"
	up, _ = d.UpdatePollTarget(ctx, a, 0, now)
	if up.EngineID != nil || up.EngineBoots != 0 {
		t.Errorf("engine kept across addresses: %+v", up)
	}
	if err := d.DeletePollTarget(ctx, b.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeletePollTarget(ctx, b.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete twice: %v", err)
	}
	ts, _ := d.PollTargets(ctx)
	if len(ts) != 1 {
		t.Errorf("targets %+v", ts)
	}
}

// writePollFile writes a poll file for a device with two cycles.
func writePollFile(t *testing.T, dataDir string, dev netip.Addr, at time.Time) {
	t.Helper()
	dir := filepath.Join(dataDir, "logs", dev.String(), "poll")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	var b []byte
	for c := uint64(1); c <= 2; c++ {
		ts := at.Add(time.Duration(c) * time.Minute)
		b = logfile.AppendLine(b, ts, dev, pollrec.Format(pollrec.New(pollrec.KindSys, c).Uint("cpu", 10*c).Uint("mem_used", 50).Uint("mem_total", 100).Record()))
		b = logfile.AppendLine(b, ts, dev, pollrec.Format(pollrec.New(pollrec.KindIf, c).Uint("if", 1).Uint("in_bps", 100*c).Uint("out_bps", 1).Uint("in_err_d", 2).Record()))
		b = logfile.AppendLine(b, ts, dev, pollrec.Format(pollrec.New(pollrec.KindIf, c).Uint("if", 2).Uint("in_bps", 300).Uint("out_bps", 2).Uint("out_disc_d", 1).Record()))
	}
	if err := os.WriteFile(filepath.Join(dir, logfile.DayOf(at)+".log"), b, 0o640); err != nil {
		t.Fatal(err)
	}
}

func TestPollHourlyMergeAndRebuild(t *testing.T) {
	dataDir := t.TempDir()
	d := openIn(t, t.TempDir())
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	dev := netip.MustParseAddr("10.1.0.1")
	writePollFile(t, dataDir, dev, at)
	tgt, _ := d.CreatePollTarget(ctx, PollTarget{Address: "10.1.0.1", Port: 161, DeviceID: "10.1.0.1", Settings: "{}"}, 10, at)
	// A stale row the rebuild must replace.
	if err := d.AddPollHourly(ctx, []pollrec.Hourly{{Device: "10.1.0.1", Series: "cpu", Hour: at, Min: 99, Max: 99, Sum: 99, Count: 1}}); err != nil {
		t.Fatal(err)
	}
	res, err := d.Reindex(ctx, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if res.PollRollups != 8 {
		t.Errorf("%d rollup rows, want 8", res.PollRollups)
	}
	if ts, _ := d.PollTargets(ctx); len(ts) != 1 || ts[0].ID != tgt.ID {
		t.Errorf("reindex lost the targets: %+v", ts)
	}
	rows, err := d.PollHourly(ctx, "10.1.0.1", []string{"cpu", "in_bps", "max_if_in_bps", "errors_d", "discards_d", "mem_used_pct"}, at, at.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]pollrec.Hourly{
		"cpu":           {Min: 10, Max: 20, Sum: 30, Count: 2},
		"in_bps":        {Min: 400, Max: 500, Sum: 900, Count: 2},
		"max_if_in_bps": {Min: 300, Max: 300, Sum: 600, Count: 2},
		"errors_d":      {Min: 2, Max: 2, Sum: 4, Count: 2},
		"discards_d":    {Min: 1, Max: 1, Sum: 2, Count: 2},
		"mem_used_pct":  {Min: 50, Max: 50, Sum: 100, Count: 2},
	}
	for _, r := range rows {
		w := want[r.Series]
		if r.Min != w.Min || r.Max != w.Max || r.Sum != w.Sum || r.Count != w.Count {
			t.Errorf("%s: %+v, want %+v", r.Series, r, w)
		}
		delete(want, r.Series)
	}
	if len(want) != 0 {
		t.Errorf("missing %v", want)
	}
	// Merging a later flush of the same hour adds to it.
	if err := d.AddPollHourly(ctx, []pollrec.Hourly{{Device: "10.1.0.1", Series: "cpu", Hour: at, Min: 5, Max: 50, Sum: 55, Count: 2}}); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.PollHourly(ctx, "10.1.0.1", []string{"cpu"}, at, at.Add(time.Hour))
	if len(rows) != 1 || rows[0].Min != 5 || rows[0].Max != 50 || rows[0].Sum != 85 || rows[0].Count != 4 {
		t.Errorf("merge %+v", rows)
	}
}
