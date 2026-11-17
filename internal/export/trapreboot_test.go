package export

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// A coldStart or warmStart trap is read against the polls around it (SPEC
// §12.6, §12.10 build #19). The 1.3 lab: an agent restarted twice 15 s apart
// inside one 60 s poll interval; the poll saw one restart (reboot=0,
// engineBoots +2), two coldStart traps came in, and the README read "Restarts 3
// (1 reboot)", the first trap left alone as a reboot.

var t0 = time.Date(2026, 11, 16, 4, 0, 5, 0, time.UTC)

// sample is an answered poll at t0+min minutes with hrSystemUptime hr ticks.
func sample(min int, hr uint64) datatype.PollSample {
	return datatype.PollSample{Time: t0.Add(time.Duration(min) * time.Minute), Hr: hr, HaveHr: true}
}

// running is the polls 0…n minutes with hrSystemUptime rising in step.
func running(n int) []datatype.PollSample {
	var out []datatype.PollSample
	for m := 0; m <= n; m++ {
		out = append(out, sample(m, uint64(500000+m*6000)))
	}
	return out
}

// withRestart marks the poll at min as having written a restart line, and
// returns that restart.
func withRestart(s []datatype.PollSample, min int, reboot, detail string) datatype.Reboot {
	s[min].RestartAt, s[min].HasRestart = s[min].Time, true
	return datatype.Reboot{Time: s[min].Time, Source: "poll", Detail: detail, Reboot: reboot}
}

func trapAt(t time.Time) datatype.Reboot { return datatype.Reboot{Time: t, Source: "coldStart trap"} }

func sorted(rs ...datatype.Reboot) []datatype.Reboot {
	out := append([]datatype.Reboot(nil), rs...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Time.Before(out[j-1].Time); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// readmeOf is a device's Reboots/Restarts README line and its one-line summary.
func readmeOf(t *testing.T, rs []datatype.Reboot, types ...string) (string, string) {
	t.Helper()
	at := t0.Add(15 * time.Minute)
	info := Info{From: t0, To: t0.Add(20 * time.Minute),
		Filters: Filters{Kind: KindBundle, At: &at, Before: 15 * time.Minute, After: 5 * time.Minute, Types: types}}
	d := DeviceSummary{DeviceID: "10.1.0.1", IP: "10.1.0.1", Types: map[string]TypeSummary{}, Reboots: rs}
	b := newBuilder(Options{Location: time.UTC})
	r := b.bundleReadme(info, []DeviceSummary{d})
	for _, l := range strings.Split(r, "\n") {
		if strings.HasPrefix(l, "  Reboots ") || strings.HasPrefix(l, "  Restarts ") {
			return l, d.Line(types)
		}
	}
	t.Fatalf("no Reboots line:\n%s", r)
	return "", ""
}

const agentDetail = "sysUpTime reset, engineBoots went up; the agent restarted, not the device"

func TestTrapReadAgainstPolls(t *testing.T) {
	both := []string{datatype.Trap, datatype.Poll}

	t.Run("lab: two coldStarts in one interval, one poll restart reboot=0", func(t *testing.T) {
		s := running(20)
		poll := withRestart(s, 12, "0", agentDetail) // 04:12:05
		first := trapAt(time.Date(2026, 11, 16, 4, 11, 26, 211e6, time.UTC))
		second := trapAt(time.Date(2026, 11, 16, 4, 11, 41, 207e6, time.UTC))
		rs := mergeReboots(sorted(poll, first, second), s)
		// Two restarts: the poll's restart is the first trap's (one entry, as
		// a poll restart and its trap always were); the second trap is a
		// restart of its own, the agent's alone. Not three: the poll restart
		// isn't a third event.
		if len(rs) != 2 || rs[0].Source != "poll, coldStart trap" || rs[0].Reboot != "0" || !rs[0].Time.Equal(first.Time) ||
			rs[1].Source != "coldStart trap" || rs[1].Reboot != "0" || rs[1].Detail != keptRunning {
			t.Fatalf("merged %+v", rs)
		}
		l, line := readmeOf(t, rs, both...)
		want := "  Restarts     2 (0 reboots): 04:11:26.211 (poll: " + agentDetail + "; coldStart trap), " +
			"04:11:41.207 (coldStart trap; the polls show the device kept running)"
		if l != want {
			t.Errorf("README\n got %q\nwant %q", l, want)
		}
		if !strings.Contains(line, "restarts 2, reboots 0") {
			t.Errorf("line %q", line)
		}
		// The input order of equal-time entries doesn't matter.
		if again := mergeReboots(sorted(first, second, poll), s); len(again) != 2 || again[0].Source != rs[0].Source {
			t.Errorf("not deterministic: %+v", again)
		}
	})

	t.Run("lone coldStart, polls show hrSystemUptime rising, no poll restart", func(t *testing.T) {
		s := running(20)
		rs := mergeReboots([]datatype.Reboot{trapAt(t0.Add(7*time.Minute + 30*time.Second))}, s)
		if len(rs) != 1 || rs[0].Reboot != "0" || rs[0].Detail != keptRunning || datatype.CountReboots(rs) != 0 {
			t.Fatalf("merged %+v", rs)
		}
		l, line := readmeOf(t, rs, both...)
		if l != "  Restarts     1 (0 reboots): 04:07:35.000 (coldStart trap; the polls show the device kept running)" ||
			!strings.Contains(line, "restarts 1, reboots 0") {
			t.Errorf("README %q, line %q", l, line)
		}
	})

	t.Run("real reboot: hrSystemUptime reset, with its coldStart", func(t *testing.T) {
		s := running(20)
		for m := 9; m <= 20; m++ {
			s[m].Hr = uint64((m - 8) * 6000)
		}
		poll := withRestart(s, 9, "1", "sysUpTime and hrSystemUptime reset")
		rs := mergeReboots(sorted(poll, trapAt(t0.Add(8*time.Minute+40*time.Second))), s)
		l, line := readmeOf(t, rs, both...)
		if l != "  Reboots      1: 04:08:45.000 (poll: sysUpTime and hrSystemUptime reset; coldStart trap)" ||
			!strings.Contains(line, "reboots 1") || strings.Contains(line, "restarts") {
			t.Errorf("README %q, line %q", l, line)
		}
		// Received just after the poll that saw it: still the same reboot.
		rs = mergeReboots(sorted(poll, trapAt(t0.Add(9*time.Minute+300*time.Millisecond))), s)
		if l, _ := readmeOf(t, rs, both...); l != "  Reboots      1: 04:09:05.000 (poll: sysUpTime and hrSystemUptime reset; coldStart trap)" {
			t.Errorf("trap after its poll: %q", l)
		}
	})

	t.Run("unpolled device: as before", func(t *testing.T) {
		rs := mergeReboots([]datatype.Reboot{trapAt(t0.Add(5 * time.Minute))}, nil)
		if l, line := readmeOf(t, rs, datatype.Trap); l != "  Reboots      1: 04:05:05.000 (coldStart trap)" || !strings.Contains(line, "reboots 1") {
			t.Errorf("README %q, line %q", l, line)
		}
	})

	t.Run("no HOST-RESOURCES: as before", func(t *testing.T) {
		s := running(20)
		for i := range s {
			s[i].Hr, s[i].HaveHr = 0, false
		}
		poll := withRestart(s, 12, "?", "sysUpTime reset; the device may have rebooted")
		first := trapAt(time.Date(2026, 11, 16, 4, 11, 26, 211e6, time.UTC))
		second := trapAt(time.Date(2026, 11, 16, 4, 11, 41, 207e6, time.UTC))
		rs := mergeReboots(sorted(poll, first, second), s)
		// Before the fix, too: the poll restart joins the nearer trap, and the
		// other is a reboot of its own.
		if len(rs) != 2 || rs[0].Source != "coldStart trap" || rs[0].Reboot != "" || rs[0].Detail != "" ||
			rs[1].Source != "poll, coldStart trap" || !rs[1].Time.Equal(second.Time) {
			t.Fatalf("merged %+v", rs)
		}
		if l, _ := readmeOf(t, rs, both...); !strings.HasPrefix(l, "  Reboots      2: 04:11:26.211 (coldStart trap), 04:11:41.207 (poll: ") {
			t.Errorf("README %q", l)
		}
	})

	t.Run("hrSystemUptime stuck: no evidence, as before", func(t *testing.T) {
		s := running(20)
		for i := range s {
			s[i].Hr = 0 // some agents keep it at 0
		}
		rs := mergeReboots([]datatype.Reboot{trapAt(t0.Add(7*time.Minute + 30*time.Second))}, s)
		if len(rs) != 1 || rs[0].Reboot != "" || rs[0].Detail != "" {
			t.Errorf("merged %+v", rs)
		}
	})

	t.Run("trap after the window's last poll: as before, and says so", func(t *testing.T) {
		s := running(14) // the last answered poll at 04:14:05
		rs := mergeReboots([]datatype.Reboot{trapAt(t0.Add(14*time.Minute + 20*time.Second))}, s)
		if len(rs) != 1 || rs[0].Reboot != "" || rs[0].Detail != noPollAfter || datatype.CountReboots(rs) != 1 {
			t.Fatalf("merged %+v", rs)
		}
		if l, _ := readmeOf(t, rs, both...); l != "  Reboots      1: 04:14:25.000 (coldStart trap; no poll after it in the window to tell)" {
			t.Errorf("README %q", l)
		}
		// A poll restart just before it still joins it, as before.
		poll := withRestart(s, 14, "1", "sysUpTime and hrSystemUptime reset")
		rs = mergeReboots(sorted(poll, trapAt(t0.Add(14*time.Minute+20*time.Second))), s)
		if len(rs) != 1 || rs[0].Source != "poll, coldStart trap" || rs[0].Detail != poll.Detail {
			t.Errorf("merged %+v", rs)
		}
	})

	t.Run("trap before the window's first poll, no restart: as before", func(t *testing.T) {
		s := running(20)
		rs := mergeReboots([]datatype.Reboot{trapAt(t0.Add(-10 * time.Second))}, s)
		if len(rs) != 1 || rs[0].Reboot != "" || rs[0].Detail != "" {
			t.Errorf("merged %+v", rs)
		}
	})

	t.Run("a poll restart doesn't take a trap the polls place elsewhere", func(t *testing.T) {
		// The trap's interval (04:06:05–04:07:05) shows the device running;
		// the poll restart at 04:08:05, within 2 min, is another event.
		s := running(20)
		poll := withRestart(s, 8, "0", agentDetail)
		rs := mergeReboots(sorted(poll, trapAt(t0.Add(6*time.Minute+30*time.Second))), s)
		if len(rs) != 2 || rs[0].Source != "coldStart trap" || rs[0].Reboot != "0" || rs[1].Source != "poll" {
			t.Errorf("merged %+v", rs)
		}
	})
}

// The lab case end to end: the stored poll lines and traps through the
// bundle's summary into README.txt and manifest.json.
func TestBundleLabAgentRestartsInOneInterval(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	c := &clock{t: t0}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 64 << 10, Manual: true, Clock: c.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	idx.AddEvent(bg, index.Event{Time: t0.Add(-time.Hour), Level: index.LevelInfo, Kind: index.KindStart,
		Source: index.SourceService, Text: "Woodshed 1.3 (abc) started on test/test; data folder x."})
	w := func(at time.Time, typ string, raw []byte) {
		t.Helper()
		c.Set(at)
		if err := st.WriteType(typ, model.Message{Received: at, Sender: devA, Raw: raw}); err != nil {
			t.Fatal(err)
		}
	}
	first := time.Date(2026, 11, 16, 4, 11, 26, 211e6, time.UTC)
	second := time.Date(2026, 11, 16, 4, 11, 41, 207e6, time.UTC)
	for m := 0; m <= 20; m++ {
		at := t0.Add(time.Duration(m) * time.Minute)
		cyc := uint64(2000 + m)
		if m == 12 {
			w(first, logfile.TypeTrap, trapRec(t, 1, oidColdStart))
			w(second, logfile.TypeTrap, trapRec(t, 2, oidColdStart))
		}
		up := uint64(3000000 + m*6000)
		if m >= 12 {
			up = uint64(2380 + (m-12)*6000) // up since 04:11:41
		}
		hr := uint64(90000000 + m*6000) // the host never stopped
		w(at, logfile.TypePoll, pollrec.Format(pollrec.New(pollrec.KindSys, cyc).Uint("uptime", up).Uint("hr_uptime", hr).
			Uint("rtt_ms", 3).Uint("interval_s", 60).Record()))
		if m == 12 {
			w(at, logfile.TypePoll, pollrec.Format(pollrec.New(pollrec.KindRestart, cyc).Str("reboot", "0").
				Uint("uptime", up).Uint("prev_uptime", 3000000+11*6000).Uint("hr_uptime", hr).Uint("prev_hr_uptime", hr-6000).
				Int("boots", 7).Int("prev_boots", 5).Str("source", "sysUpTime,engineBoots").Record()))
		}
	}
	st.Flush()
	st.Maintain()
	c.Set(t0.Add(25 * time.Minute))
	e := &env{t: t, dir: dir, idx: idx, st: st, clock: c, day0: t0}
	e.eng = search.New(search.Options{DataDir: dir, Index: idx, Now: c.Now, Logger: quiet})
	m := e.manager()
	at := t0.Add(15 * time.Minute)
	in, err := m.Create(bg, Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 15 * time.Minute, After: 5 * time.Minute,
		ActiveDevices: true}})
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	readme := string(files["README.txt"])
	want := "  Restarts     2 (0 reboots): 04:11:26.211 (poll: sysUpTime reset, engineBoots went up; the agent restarted, not the device; " +
		"coldStart trap), 04:11:41.207 (coldStart trap; the polls show the device kept running)\n"
	if !strings.Contains(readme, want) {
		t.Errorf("README lacks\n%q:\n%s", want, readme)
	}
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if len(man.Summary) != 1 {
		t.Fatalf("summary %+v", man.Summary)
	}
	d := man.Summary[0]
	if len(d.Reboots) != 2 || d.Reboots[0].Source != "poll, coldStart trap" || d.Reboots[0].Reboot != "0" ||
		d.Reboots[1].Source != "coldStart trap" || d.Reboots[1].Reboot != "0" || d.Reboots[1].Detail != keptRunning {
		t.Errorf("reboots %+v", d.Reboots)
	}
	if line := d.Line(in.Filters.Types); !strings.Contains(line, "restarts 2, reboots 0") {
		t.Errorf("line %q", line)
	}
	// system.csv holds the poll's own restart row only; traps aren't merged there.
	if sys := string(files["poll/"+model.DeviceID(devA)+"/system.csv"]); strings.Count(sys, ",restart,") != 1 || strings.Contains(sys, "coldStart") {
		t.Errorf("system.csv:\n%s", sys)
	}
}
