package index

import (
	"testing"
	"time"
)

// The flow collector's counts (SPEC §13.10 decisions 82 and 83): summed per
// minute, rolled up by the hour, read back over a window (widened to the
// hour where only hourly buckets remain) and in buckets for the collector's
// restore; rows from before the counts existed make a window "not known".
func TestFlowCountsWindowAndBuckets(t *testing.T) {
	d := openIn(t, t.TempDir())
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	act := func(dev string, at time.Time, msgs int64, fc FlowCounts) Activity {
		return Activity{DeviceID: dev, Type: TypeFlow, IP: dev, Minute: at, FirstHeard: at, LastHeard: at, Counts: Counts{Msgs: msgs, Flow: fc}}
	}
	early := now.Add(-30 * time.Hour) // rolled up below
	b := Batch{Activity: []Activity{
		act("10.1.0.1", early.Add(10*time.Minute), 5, FlowCounts{SeqGaps: 2, SeqLost: 60}),
		act("10.1.0.1", now.Add(-3*time.Hour), 100, FlowCounts{SeqGaps: 849, SeqLost: 37498, Late: 4}),
		act("10.1.0.1", now.Add(-20*time.Minute), 50, FlowCounts{SeqGaps: 1, SeqLost: 30, Duplicates: 2, Ahead: 3, MaxAheadMs: 5000}),
		act("10.1.0.1", now.Add(-20*time.Minute), 50, FlowCounts{SeqGaps: 2, SeqLost: 60, Ahead: 1, MaxAheadMs: 9000, NoTemplate: 1}),
		act("10.1.0.1", now.Add(-5*time.Minute), 10, FlowCounts{Malformed: 1}),
		act("10.1.0.2", now.Add(-10*time.Minute), 7, FlowCounts{}),
		{DeviceID: "10.1.0.1", Type: "syslog", Minute: now.Add(-20 * time.Minute), Counts: Counts{Msgs: 9}},
	}}
	if err := d.Apply(ctx, b); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RollupStats(ctx, now.Add(-MinuteRetention)); err != nil {
		t.Fatal(err)
	}
	// The last 30 minutes: the burst 3 h earlier isn't in it.
	w, err := d.FlowCountsIn(ctx, "10.1.0.1", now.Add(-30*time.Minute).Add(15*time.Second), now)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Known || w.SeqGaps != 3 || w.SeqLost != 90 || w.Duplicates != 2 || w.Ahead != 4 || w.MaxAheadMs != 9000 || w.NoTemplate != 1 ||
		w.Malformed != 1 || w.Records != 110 || w.ByHour || !w.From.Equal(now.Add(-30*time.Minute)) || !w.To.Equal(now) {
		t.Fatalf("window %+v", w)
	}
	// None in it.
	if w, _ := d.FlowCountsIn(ctx, "10.1.0.1", now.Add(-2*time.Hour), now.Add(-time.Hour)); w.Known || w.SeqGaps != 0 {
		t.Fatalf("empty window %+v", w)
	}
	if w, _ := d.FlowCountsIn(ctx, "10.1.0.2", now.Add(-time.Hour), now); !w.Known || w.SeqGaps != 0 || w.Records != 7 {
		t.Fatalf("no gaps %+v", w)
	}
	// Older than the minute buckets: counted by the hour, and the span says so.
	w, _ = d.FlowCountsIn(ctx, "10.1.0.1", early.Add(5*time.Minute), early.Add(15*time.Minute))
	if !w.Known || !w.ByHour || w.SeqGaps != 2 || !w.From.Equal(early.Truncate(time.Hour)) || !w.To.Equal(early.Truncate(time.Hour).Add(time.Hour)) {
		t.Fatalf("hourly %+v", w)
	}
	// A row from before the counts (2.0.0-rc1): not known.
	if _, err := d.db.Exec(`UPDATE type_stats SET flow_counted = 0 WHERE device_id = '10.1.0.2'`); err != nil {
		t.Fatal(err)
	}
	if w, _ := d.FlowCountsIn(ctx, "10.1.0.2", now.Add(-time.Hour), now); w.Known {
		t.Fatalf("uncounted %+v", w)
	}
	// An upsert into that row keeps it partly counted.
	if err := d.Apply(ctx, Batch{Activity: []Activity{act("10.1.0.2", now.Add(-10*time.Minute), 1, FlowCounts{SeqGaps: 1})}}); err != nil {
		t.Fatal(err)
	}
	if w, _ := d.FlowCountsIn(ctx, "10.1.0.2", now.Add(-time.Hour), now); w.Known || w.SeqGaps != 1 {
		t.Fatalf("partly counted %+v", w)
	}
	// Hourly buckets for the last 24 h, and 5-minute ones for the last hour.
	hb, err := d.FlowCountBuckets(ctx, now.Add(-24*time.Hour), now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, x := range hb {
		got[x.DeviceID+" "+x.Start.Format("15:04")] += x.SeqGaps
	}
	if len(hb) != 3 || got["10.1.0.1 09:00"] != 849 || got["10.1.0.1 11:00"] != 3 || got["10.1.0.2 11:00"] != 1 {
		t.Fatalf("hours %+v", hb)
	}
	fb, _ := d.FlowCountBuckets(ctx, now.Add(-time.Hour), now, 5*time.Minute)
	var n int
	for _, x := range fb {
		if x.DeviceID == "10.1.0.1" {
			n++
			if x.Start.Equal(now.Add(-20*time.Minute)) && (x.Ahead != 4 || x.MaxAheadMs != 9000) {
				t.Fatalf("five %+v", x)
			}
		}
	}
	if n != 2 {
		t.Fatalf("fives %+v", fb)
	}
	// Older than a day: from the hourly buckets.
	if old, _ := d.FlowCountBuckets(ctx, now.Add(-48*time.Hour), now.Add(-24*time.Hour), time.Hour); len(old) != 1 || old[0].SeqGaps != 2 {
		t.Fatalf("old %+v", old)
	}
}

func TestNewestFlowSegment(t *testing.T) {
	d := openIn(t, t.TempDir())
	h := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	var ops []FileOp
	for i, p := range []string{"logs/10.1.0.1/flows/2026-11-17T09.wsf", "logs/10.1.0.1/flows/2026-11-17T10.wsf", "logs/10.1.0.1/2026-11-17.log"} {
		typ := TypeFlow
		if i == 2 {
			typ = TypeSyslog
		}
		at := h.Add(time.Duration(i) * time.Hour)
		ops = append(ops, FileOp{Kind: OpUpsert, File: File{DeviceID: "10.1.0.1", Type: typ, Path: p, Day: "2026-11-17", FirstReceived: at, LastReceived: at}})
	}
	if err := d.Apply(ctx, Batch{Files: ops}); err != nil {
		t.Fatal(err)
	}
	if p, last, err := d.NewestFlowSegment(ctx, "10.1.0.1"); err != nil || p != "logs/10.1.0.1/flows/2026-11-17T10.wsf" || !last.Equal(h.Add(time.Hour)) {
		t.Fatalf("%q %v %v", p, last, err)
	}
	if p, _, err := d.NewestFlowSegment(ctx, "10.1.0.9"); err != nil || p != "" {
		t.Fatalf("none: %q %v", p, err)
	}
}

// A schema-8 index (2.0.0-rc1) migrates to 9: its type_stats rows stay,
// marked as not having flow counts.
func TestMigrateFlowCounts(t *testing.T) {
	dir := t.TempDir()
	d := openIn(t, dir)
	if _, err := d.db.Exec(dropV9 + `PRAGMA user_version = 8`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec(`INSERT INTO type_stats (device_id, type, minute, msgs, bytes) VALUES ('10.1.0.1', 'flow', 60000, 5, 50)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d2 := openIn(t, dir)
	if v, _ := d2.SchemaVersion(ctx); v != 9 {
		t.Fatalf("schema %d", v)
	}
	w, err := d2.FlowCountsIn(ctx, "10.1.0.1", time.UnixMilli(0), time.UnixMilli(120000))
	if err != nil || w.Known || w.Records != 5 {
		t.Fatalf("%+v %v", w, err)
	}
}
