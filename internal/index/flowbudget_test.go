package index

import (
	"strings"
	"testing"
	"time"
)

// A flow segment deleted for the flow budget is stored as "cap" (the table's
// CHECK) but reads back, and is worded, as the flow budget; a syslog file
// deleted for the cap keeps the storage-cap wording.
func TestFlowBudgetDeletionReason(t *testing.T) {
	d := openIn(t, t.TempDir())
	flow := "logs/192.0.2.1/flows/2026-11-10T09.wsf"
	sys := "logs/192.0.2.1/2026-11-09.log.gz"
	if err := d.Apply(ctx, Batch{Files: []FileOp{
		{Kind: OpDelete, File: File{DeviceID: "192.0.2.1", Type: TypeFlow, Path: flow},
			Deletion: &Deletion{Time: t0, File: flow, DeviceID: "192.0.2.1", Type: TypeFlow, Bytes: 4096, Reason: ReasonFlowBudget}},
		{Kind: OpDelete, File: File{DeviceID: "192.0.2.1", Path: sys},
			Deletion: &Deletion{Time: t0.Add(time.Second), File: sys, DeviceID: "192.0.2.1", Bytes: 300, Reason: ReasonCap}},
	}}); err != nil {
		t.Fatal(err)
	}
	var stored string
	d.db.QueryRow(`SELECT reason FROM deletions WHERE file = ?`, flow).Scan(&stored)
	if stored != "cap" {
		t.Fatalf("stored reason %q", stored)
	}
	hist, err := d.Deletions(ctx, time.Time{}, time.Time{}, 0)
	if err != nil || len(hist) != 2 || hist[0].File != sys || hist[0].Reason != ReasonCap ||
		hist[1].File != flow || hist[1].Reason != ReasonFlowBudget {
		t.Fatalf("history %+v %v", hist, err)
	}
	evs, _ := d.Events(ctx, time.Time{}, time.Time{}, 0)
	if len(evs) != 2 ||
		evs[0].Text != "deleted "+flow+" (flows over their budget, 4096 bytes)" ||
		evs[1].Text != "deleted "+sys+" (over the storage cap, 300 bytes)" {
		t.Fatalf("events %+v", evs)
	}
	for _, e := range evs[:1] {
		if strings.Contains(e.Text, "storage cap") {
			t.Fatalf("flow event says storage cap: %q", e.Text)
		}
	}
}
