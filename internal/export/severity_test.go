package export

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
)

// A bundle never hides what the severity filter left out: each syslog
// device's summary has the filter and the window's counts (only the buckets
// that start in the window), and the README says it in one line; a device
// that stores everything and lost nothing gets no line.
func TestBundleSeverityFilter(t *testing.T) {
	be := newBundleEnv(t)
	a := model.DeviceID(devA)
	min := func(at string) time.Time {
		t.Helper()
		v, err := time.Parse(time.RFC3339, at)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	var deb, inf index.SevCounts
	deb[7], inf[6] = 12345, 2
	var outside index.SevCounts
	outside[7] = 999
	if err := be.idx.Apply(bg, index.Batch{Activity: []index.Activity{
		{DeviceID: a, IP: devA.String(), Minute: min("2026-11-13T23:50:00Z"), Counts: index.Counts{Filtered: deb}},
		{DeviceID: a, IP: devA.String(), Minute: min("2026-11-14T00:14:00Z"), Counts: index.Counts{Filtered: inf}},
		{DeviceID: a, IP: devA.String(), Minute: min("2026-11-13T23:34:00Z"), Counts: index.Counts{Filtered: outside}}, // before the window
		{DeviceID: a, IP: devA.String(), Minute: min("2026-11-14T00:15:00Z"), Counts: index.Counts{Filtered: outside}}, // at its end
	}}); err != nil {
		t.Fatal(err)
	}
	m := be.manager(func(o *Options) {
		o.Location = est
		o.SeverityFilter = func(id string) (int, bool) {
			if id == a {
				return 6, true // the access point: info and above, its own setting
			}
			return 7, false
		}
	})
	in, err := m.Create(bg, be.bundleRequest())
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	readme := string(files["README.txt"])
	want := "  Filter       storing info and above (this device's setting); 12,345 debug and 2 info messages not stored in this window\n"
	if !strings.Contains(readme, want) {
		t.Errorf("README lacks %q:\n%s", want, readme)
	}
	if strings.Count(readme, "Filter ") != 1 {
		t.Errorf("a Filter line for a device that stores everything:\n%s", readme)
	}
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	sa, sb := man.Summary[0].SeverityFilter, man.Summary[1].SeverityFilter
	if sa == nil || sa.MinSeverity != "info" || !sa.Own || sa.NotStored != 12347 || sa.NotStoredBySeverity["debug"] != 12345 ||
		sa.NotStoredBySeverity["info"] != 2 || !sa.Known || sa.Partial || sa.ByHour {
		t.Errorf("A %+v", sa)
	}
	if sb == nil || sb.MinSeverity != "debug" || sb.Own || sb.NotStored != 0 || len(sb.NotStoredBySeverity) != 0 {
		t.Errorf("B %+v", sb)
	}
	// The filtered messages are in no drop count.
	if man.Summary[0].Dropped != 4 {
		t.Errorf("A dropped %d", man.Summary[0].Dropped)
	}
}

func TestSeverityReadmeWords(t *testing.T) {
	tf := timeFmt{}
	at := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		s    SeverityFilterSummary
		want string
	}{
		{SeverityFilterSummary{MinSeverity: "debug", Known: true}, ""},
		{SeverityFilterSummary{MinSeverity: "info", Known: true}, "storing info and above (the default); nothing was left out in this window"},
		{SeverityFilterSummary{MinSeverity: "emerg", Own: true, Known: true, NotStored: 1, NotStoredBySeverity: map[string]int64{"alert": 1}},
			"storing emerg only (this device's setting); 1 alert message not stored in this window"},
		{SeverityFilterSummary{MinSeverity: "debug", Known: true, NotStored: 5, NotStoredBySeverity: map[string]int64{"debug": 5}},
			"storing everything now (the default); 5 debug messages not stored in this window"},
		{SeverityFilterSummary{Known: true, NotStored: 5, NotStoredBySeverity: map[string]int64{"debug": 3, "info": 1, "notice": 1}},
			"3 debug, 1 info and 1 notice messages not stored in this window"},
		{SeverityFilterSummary{MinSeverity: "info", Known: true, Partial: true, From: at, NotStored: 7, NotStoredBySeverity: map[string]int64{"debug": 7}},
			"storing info and above (the default); 7 debug messages not stored since 09:00:00 (counts are kept 7 days)"},
		{SeverityFilterSummary{MinSeverity: "info", Known: true, ByHour: true, From: at, To: at.Add(2 * time.Hour), NotStored: 7, NotStoredBySeverity: map[string]int64{"debug": 7}},
			"storing info and above (the default); 7 debug messages not stored from 09:00:00 to 11:00:00 (counted by the hour)"},
		{SeverityFilterSummary{MinSeverity: "info"}, "storing info and above (the default); counts of messages it left out aren't kept this far back (7 days)"},
	} {
		if got := c.s.readme(tf); got != c.want {
			t.Errorf("%+v:\n got %q\nwant %q", c.s, got, c.want)
		}
	}
	var none *SeverityFilterSummary
	if none.readme(tf) != "" {
		t.Error("nil summary")
	}
}
