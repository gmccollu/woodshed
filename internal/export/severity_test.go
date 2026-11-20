package export

import (
	"encoding/json"
	"net/netip"
	"path/filepath"
	"slices"
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
	// The default went to warning before the window, the access point to its
	// own info and above in it; B follows the default throughout.
	sevRow(t, be.idx, "", index.SeverityChange{Time: min("2026-11-13T23:00:00Z"), Default: true, Level: 4, Was: 7, WasKnown: true})
	sevRow(t, be.idx, a, index.SeverityChange{Time: min("2026-11-13T23:55:00Z"), Address: devA.String(), Level: 6, Was: -1, WasKnown: true})
	if err := be.idx.RecordSeverityFilter(bg, index.SeverityFilterState{Default: 4, ByDevice: map[string]int{devA.String(): 6}}); err != nil {
		t.Fatal(err)
	}
	m := be.manager(func(o *Options) { o.Location = est })
	in, err := m.Create(bg, be.bundleRequest())
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	readme := string(files["README.txt"])
	for _, want := range []string{
		"  Filter       storing warning and above (the default) until 2026-11-13 23:55:00, then info and above (this device's setting); " +
			"12,345 debug and 2 info messages not stored in this window\n",
		"  Filter       storing warning and above (the default); nothing was left out in this window\n",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("README lacks %q:\n%s", want, readme)
		}
	}
	if strings.Count(readme, "Filter ") != 2 {
		t.Errorf("a Filter line for a device that stores everything:\n%s", readme)
	}
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	sa, sb := man.Summary[0].SeverityFilter, man.Summary[1].SeverityFilter
	from, to := min("2026-11-13T23:35:00Z"), min("2026-11-14T00:15:00Z") // the window
	if sa == nil || sa.NotStored != 12347 || sa.NotStoredBySeverity["debug"] != 12345 ||
		sa.NotStoredBySeverity["info"] != 2 || !sa.Known || sa.Partial || sa.ByHour {
		t.Errorf("A %+v", sa)
	}
	wantA := []SeveritySetting{{From: from, To: min("2026-11-13T23:55:00Z"), MinSeverity: "warning"},
		{From: min("2026-11-13T23:55:00Z"), To: to, MinSeverity: "info", Own: true}}
	if sa == nil || !sameSettings(sa.Settings, wantA) {
		t.Errorf("A settings %+v, want %+v", sa.Settings, wantA)
	}
	if sb == nil || sb.NotStored != 0 || len(sb.NotStoredBySeverity) != 0 ||
		!sameSettings(sb.Settings, []SeveritySetting{{From: from, To: to, MinSeverity: "warning"}}) {
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
	one := func(sev string, own bool) []SeveritySetting {
		return []SeveritySetting{{From: at, To: at.Add(time.Hour), MinSeverity: sev, Own: own}}
	}
	for _, c := range []struct {
		s    SeverityFilterSummary
		want string
	}{
		{SeverityFilterSummary{Settings: one("debug", false), Known: true}, ""},
		{SeverityFilterSummary{Settings: one("", false), Known: true}, ""},
		{SeverityFilterSummary{Settings: one("debug", false)}, ""},
		{SeverityFilterSummary{Settings: one("", false)}, "setting not recorded; counts of messages it left out aren't kept this far back (7 days)"},
		{SeverityFilterSummary{Settings: one("info", false), Known: true}, "storing info and above (the default); nothing was left out in this window"},
		{SeverityFilterSummary{Settings: one("emerg", true), Known: true, NotStored: 1, NotStoredBySeverity: map[string]int64{"alert": 1}},
			"storing emerg only (this device's setting); 1 alert message not stored in this window"},
		{SeverityFilterSummary{Settings: one("debug", false), Known: true, NotStored: 5, NotStoredBySeverity: map[string]int64{"debug": 5}},
			"storing everything (the default); 5 debug messages not stored in this window"},
		{SeverityFilterSummary{Known: true, NotStored: 5, NotStoredBySeverity: map[string]int64{"debug": 3, "info": 1, "notice": 1}},
			"3 debug, 1 info and 1 notice messages not stored in this window"},
		{SeverityFilterSummary{Settings: one("info", false), Known: true, Partial: true, From: at, NotStored: 7, NotStoredBySeverity: map[string]int64{"debug": 7}},
			"storing info and above (the default); 7 debug messages not stored since 09:00:00 (counts are kept 7 days)"},
		{SeverityFilterSummary{Settings: one("info", false), Known: true, ByHour: true, From: at, To: at.Add(2 * time.Hour), NotStored: 7, NotStoredBySeverity: map[string]int64{"debug": 7}},
			"storing info and above (the default); 7 debug messages not stored from 09:00:00 to 11:00:00 (counted by the hour)"},
		{SeverityFilterSummary{Settings: one("info", false)}, "storing info and above (the default); counts of messages it left out aren't kept this far back (7 days)"},
		{SeverityFilterSummary{Known: true, NotStored: 2, NotStoredBySeverity: map[string]int64{"debug": 2}, Settings: []SeveritySetting{
			{From: at, To: at.Add(10 * time.Minute)},
			{From: at.Add(10 * time.Minute), To: at.Add(20 * time.Minute), MinSeverity: "debug"},
			{From: at.Add(20 * time.Minute), To: at.Add(time.Hour), MinSeverity: "notice", Own: true}}},
			"setting before 09:10:00 not recorded, then storing everything (the default) until 09:20:00, then notice and above (this device's setting); " +
				"2 debug messages not stored in this window"},
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

// The settings over a window come from the severity_changes table (and,
// before its first row, 2.1.0-rc1's event texts): the last change before each
// moment, what the first change changed from before it, the recorded setting
// when nothing changed. "Not recorded" before the oldest event kept, where an
// rc1 event doesn't say what it changed from, and over a span whose next
// change (or the recorded setting) says it was something else. Every zone of
// an address shares its history.
func TestSeveritySettings(t *testing.T) {
	t0 := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	from, to := t0.Add(time.Hour), t0.Add(3*time.Hour)
	tt := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	set := func(f, t int, sev string, own bool) SeveritySetting {
		return SeveritySetting{From: tt(f), To: tt(t), MinSeverity: sev, Own: own}
	}
	const addr = "192.0.2.9"
	type ev struct { // an event written as it is: rc1's, or "Woodshed started"
		at   int
		id   string
		text string
	}
	type row struct {
		at       int
		addr     string // "": the default
		level    int
		was      int
		wasKnown bool
	}
	def := func(at, level, was int) row { return row{at, "", level, was, true} }
	dev := func(at, level, was int) row { return row{at, addr, level, was, true} }
	started := ev{0, "", "Woodshed started"}
	for _, c := range []struct {
		name   string
		evs    []ev
		rows   []row
		rec    *index.SeverityFilterState
		device [2]string // ID and row IP; default 192.0.2.9
		want   []SeveritySetting
	}{
		{name: "nothing recorded: stored everything", evs: []ev{started}, want: []SeveritySetting{set(60, 180, "debug", false)}},
		{name: "recorded, never changed", evs: []ev{started}, rec: &index.SeverityFilterState{Default: 6, ByDevice: map[string]int{addr: 5}},
			want: []SeveritySetting{set(60, 180, "notice", true)}},
		{name: "a change before the window and one in it", rows: []row{def(10, 4, 7), dev(109, 5, -1), def(150, 6, 4)},
			rec:  &index.SeverityFilterState{Default: 6, ByDevice: map[string]int{addr: 5}},
			want: []SeveritySetting{set(60, 109, "warning", false), set(109, 180, "notice", true)}},
		{name: "the default's first change, in the window, says what it was", evs: []ev{started}, rows: []row{def(90, 6, 7)},
			rec: &index.SeverityFilterState{Default: 6}, want: []SeveritySetting{set(60, 90, "debug", false), set(90, 180, "info", false)}},
		{name: "back to the default in the window", evs: []ev{started}, rows: []row{dev(120, -1, 3)},
			rec: &index.SeverityFilterState{Default: 6}, want: []SeveritySetting{set(60, 120, "err", true), set(120, 180, "info", false)}},
		{name: "an rc1 event doesn't say what it was", evs: []ev{started, {100, addr, "severity filter for 192.0.2.9 set to notice and above"}},
			rec:  &index.SeverityFilterState{Default: 7, ByDevice: map[string]int{addr: 5}},
			want: []SeveritySetting{set(60, 100, "", false), set(100, 180, "notice", true)}},
		{name: "events kept only from inside the window", evs: []ev{{80, "", "Woodshed started"}}, rec: &index.SeverityFilterState{Default: 6},
			want: []SeveritySetting{set(60, 80, "", false), set(80, 180, "info", false)}},
		{name: "another address's change doesn't split it", evs: []ev{started}, rows: []row{{100, "192.0.2.10", 0, -1, true}},
			rec:  &index.SeverityFilterState{Default: 6, ByDevice: map[string]int{"192.0.2.10": 0}},
			want: []SeveritySetting{set(60, 180, "info", false)}},
		{name: "zone en0 shares the address's history", evs: []ev{started}, rows: []row{{90, "fe80::1", 6, -1, true}},
			rec: &index.SeverityFilterState{Default: 7, ByDevice: map[string]int{"fe80::1": 6}}, device: [2]string{"fe80__1_en0", "fe80::1%en0"},
			want: []SeveritySetting{set(60, 90, "debug", false), set(90, 180, "info", true)}},
		{name: "and so does zone en1", evs: []ev{started}, rows: []row{{90, "fe80::1", 6, -1, true}},
			rec: &index.SeverityFilterState{Default: 7, ByDevice: map[string]int{"fe80::1": 6}}, device: [2]string{"fe80__1_en1", "fe80::1%en1"},
			want: []SeveritySetting{set(60, 90, "debug", false), set(90, 180, "info", true)}},
		{name: "a lost change: the next one was from something else", evs: []ev{started}, rows: []row{def(70, 4, 7), def(120, 6, 5)},
			rec:  &index.SeverityFilterState{Default: 6},
			want: []SeveritySetting{set(60, 70, "debug", false), set(70, 120, "", false), set(120, 180, "info", false)}},
		{name: "a lost change after the last one", evs: []ev{started}, rows: []row{def(70, 4, 7)}, rec: &index.SeverityFilterState{Default: 6},
			want: []SeveritySetting{set(60, 70, "debug", false), set(70, 180, "", false)}},
		{name: "an rc1 index upgraded: its events, then the table", evs: []ev{started,
			{10, "", "default severity filter set to warning and above (was everything)"},
			{80, addr, "severity filter for 192.0.2.9 set to notice and above"}},
			rows: []row{dev(130, -1, 5)}, rec: &index.SeverityFilterState{Default: 4},
			want: []SeveritySetting{set(60, 80, "", false), set(80, 130, "notice", true), set(130, 180, "warning", false)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			idx := openIndex(t)
			for _, e := range c.evs {
				sevEvent(t, idx, tt(e.at), e.id, e.text)
			}
			for _, r := range c.rows {
				id := ""
				if r.addr != "" {
					id = model.DeviceID(netip.MustParseAddr(r.addr))
				}
				sevRow(t, idx, id, index.SeverityChange{Time: tt(r.at), Address: r.addr, Default: r.addr == "", Level: r.level, Was: r.was, WasKnown: r.wasKnown})
			}
			if c.rec != nil {
				if err := idx.RecordSeverityFilter(bg, *c.rec); err != nil {
					t.Fatal(err)
				}
			}
			h, err := loadSevHistory(bg, idx)
			if err != nil {
				t.Fatal(err)
			}
			id, ip := c.device[0], c.device[1]
			if id == "" {
				id, ip = addr, addr
			}
			if got := h.settings(sevAddr(id, ip), from, to); !sameSettings(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

// sevRow records a change as the server does, with its event.
func sevRow(t *testing.T, idx *index.DB, deviceID string, c index.SeverityChange) {
	t.Helper()
	c.Source = index.SeverityLive
	if err := idx.AddSeverityChange(bg, c, index.Event{DeviceID: deviceID, Text: "a change"}); err != nil {
		t.Fatal(err)
	}
}

func sevEvent(t *testing.T, idx *index.DB, at time.Time, deviceID, text string) {
	t.Helper()
	kind := index.KindSeverityFilter
	if text == "Woodshed started" {
		kind = index.KindStart
	}
	if err := idx.AddEvent(bg, index.Event{Time: at, Level: index.LevelInfo, Kind: kind, DeviceID: deviceID, Text: text}); err != nil {
		t.Fatal(err)
	}
}

func openIndex(t *testing.T) *index.DB {
	t.Helper()
	idx, err := index.Open(filepath.Join(t.TempDir(), index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	return idx
}

func sameSettings(a, b []SeveritySetting) bool {
	return slices.EqualFunc(a, b, func(x, y SeveritySetting) bool {
		return x.From.Equal(y.From) && x.To.Equal(y.To) && x.MinSeverity == y.MinSeverity && x.Own == y.Own
	})
}

// A device whose syslog in the window was all left out by the severity filter
// is an active device: it gets its entry and says "heard, nothing stored"; and
// a window where only left-out messages arrived builds instead of failing
// "No device stored anything".
func TestBundleFilteredOnlyDevice(t *testing.T) {
	be := newBundleEnv(t)
	ap := netip.MustParseAddr("192.0.2.77")
	for _, at := range []time.Time{time.Date(2026, 11, 14, 0, 1, 0, 0, time.UTC), time.Date(2026, 11, 14, 3, 1, 0, 0, time.UTC)} {
		be.clock.Set(at)
		for i := 0; i < 5; i++ {
			be.st.Filtered(ap, at, 7)
		}
		be.st.Filtered(ap, at, 6)
		be.st.Maintain()
	}
	be.clock.Set(time.Date(2026, 11, 14, 4, 0, 0, 0, time.UTC))
	if err := be.idx.RecordSeverityFilter(bg, index.SeverityFilterState{Default: 7, ByDevice: map[string]int{"192.0.2.77": 5}}); err != nil {
		t.Fatal(err)
	}
	m := be.manager()
	check := func(r Request, devices int) {
		t.Helper()
		in, err := m.Create(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		in = wait(t, m, in.ID, Ready)
		files, _ := readZip(t, m, in.ID)
		readme := string(files["README.txt"])
		if want := "  Syslog       heard, nothing stored (severity filter): 5 debug and 1 info\n"; !strings.Contains(readme, want) {
			t.Errorf("README lacks %q:\n%s", want, readme)
		}
		var man Manifest
		if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
			t.Fatal(err)
		}
		if len(man.Summary) != devices {
			t.Fatalf("%d devices in the summary", len(man.Summary))
		}
		var s *SeverityFilterSummary
		for _, d := range man.Summary {
			if d.DeviceID == "192.0.2.77" {
				s = d.SeverityFilter
			}
		}
		if s == nil || s.NotStored != 6 || len(s.Settings) != 1 || s.Settings[0].MinSeverity != "notice" || !s.Settings[0].Own {
			t.Errorf("the access point's entry %+v", s)
		}
	}
	check(be.bundleRequest(), 3)
	at := time.Date(2026, 11, 14, 3, 5, 0, 0, time.UTC)
	check(Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute, ActiveDevices: true}}, 1)
}
