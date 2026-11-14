package store

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
)

func randText(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + r.Intn(26))
	}
	return string(b)
}

// TestFairShareManySmallSenders is the review's N7 case: a flood spread over 200 new
// senders, each small, pushes the store over its cap. Largest-first wiped only the
// busiest real device. With fair shares every device over its share pays, the new
// senders included, and the target keeps today's file.
func TestFairShareManySmallSenders(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.PartBytes = 32 << 10 })
	r := rand.New(rand.NewSource(3))
	target := ip(1)
	end := e.clock.Now()
	e.clock.Set(end.Add(-6 * 24 * time.Hour))
	for day := 0; day < 7; day++ { // the target: a week of busy history
		for i := 0; i < 20; i++ {
			e.write(target, fmt.Sprintf("target %d %s", day, randText(r, 1000)))
		}
		e.maintain()
		if day < 6 {
			e.clock.Add(24 * time.Hour)
		}
	}
	// Today, 200 new senders each send a little over one part (one closed part each).
	for i := 0; i < 200; i++ {
		a := spread(i)
		for j := 0; j < 40; j++ {
			e.s.Write(model.Message{Received: e.clock.Now(), Sender: a, Raw: []byte(randText(r, 1000))})
		}
	}
	e.maintain()
	e.s.SetLimits(Limits{RetentionBytes: duLogs(e.dir) / 2})
	e.maintain()
	if after := e.files(target); !contains(after, "2026-11-10.log") {
		t.Fatalf("the target lost today's file: %v", after)
	}
	hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	var targetDel, spoofDel int
	for _, h := range hist {
		if h.DeviceID == "192.0.2.1" {
			targetDel++
		} else {
			spoofDel++
		}
	}
	t.Logf("deleted: target %d files, new senders %d", targetDel, spoofDel)
	if spoofDel == 0 {
		t.Fatalf("no new sender's file was deleted; target lost %d", targetDel)
	}
}

// TestCapAndGuaranteedDays: many established quiet devices and one heavy one. When
// the cap can be met without anyone's newest two days, it holds to within one part's
// size; when it can't, everything older goes and those two days stay for everyone.
func TestCapAndGuaranteedDays(t *testing.T) {
	const part = 16 << 10
	setup := func(t *testing.T) (*env, []netip.Addr, netip.Addr) {
		e := newEnv(t, func(o *Options) { o.PartBytes = part })
		r := rand.New(rand.NewSource(11))
		var quiet []netip.Addr
		for i := 0; i < 30; i++ {
			quiet = append(quiet, netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}))
		}
		heavy := ip(1)
		end := e.clock.Now()
		for d := 5; d >= 0; d-- { // five closed days and today for every device
			e.clock.Set(end.Add(-time.Duration(d) * 24 * time.Hour))
			for _, q := range quiet {
				e.write(q, fmt.Sprintf("quiet day -%d %s", d, randText(r, 300)))
			}
			for i := 0; i < 100; i++ {
				e.write(heavy, fmt.Sprintf("heavy day -%d %s", d, randText(r, 1000)))
			}
			e.maintain()
		}
		e.clock.Set(end)
		e.maintain()
		return e, quiet, heavy
	}
	keepsTwoDays := func(t *testing.T, e *env, devs ...netip.Addr) {
		t.Helper()
		for _, a := range devs {
			got := e.files(a)
			has09 := false
			for _, f := range got {
				has09 = has09 || strings.HasPrefix(f, "2026-11-09")
			}
			if !has09 || !contains(got, "2026-11-10.log") {
				t.Fatalf("%v lost one of its newest two days: %v", a, got)
			}
		}
	}
	t.Run("reachable", func(t *testing.T) {
		e, quiet, heavy := setup(t)
		limit := duLogs(e.dir) * 3 / 4
		e.s.SetLimits(Limits{RetentionBytes: limit})
		e.maintain()
		if got := duLogs(e.dir); got > limit+part {
			t.Fatalf("%d bytes on disk, cap %d (+ one part %d)", got, limit, part)
		}
		keepsTwoDays(t, e, append(quiet, heavy)...)
	})
	t.Run("below the guaranteed days", func(t *testing.T) {
		e, quiet, heavy := setup(t)
		e.s.SetLimits(Limits{RetentionBytes: duLogs(e.dir) / 10})
		e.maintain()
		keepsTwoDays(t, e, append(quiet, heavy)...)
		files, _ := e.idx.Files(bg, "")
		for _, f := range files {
			if f.Day < "2026-11-09" {
				t.Fatalf("%s kept although the store is over its cap", f.Path)
			}
		}
	})
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// TestLowDiskClosesOpenFiles is N9: many senders, each under the part size, fill the
// disk with active and parked files only. The guard closes the largest as parts and
// deletes them instead of pausing until midnight.
func TestLowDiskClosesOpenFiles(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MinFreeBytes = 1 << 20; o.MinFreePercent = 1 })
	e.disk.total = 1 << 30 // reserve: 10 MiB (1%)
	r := rand.New(rand.NewSource(5))
	var addrs []netip.Addr
	for i := 0; i < 60; i++ {
		a := netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})
		addrs = append(addrs, a)
		for j := 0; j < 10+i; j++ {
			e.write(a, randText(r, 2000))
		}
	}
	e.maintain()
	// Half go quiet: their files are parked.
	e.clock.Add(DefaultIdleClose + time.Second)
	for _, a := range addrs[:30] {
		e.write(a, "still here")
	}
	e.maintain()
	used := uint64(duLogs(e.dir))
	e.disk.setOther(1<<30 - used - (10<<20 - 1<<20)) // 1 MiB short of the reserve
	e.maintain()
	if e.s.Paused() {
		t.Fatal("paused although open files could be closed and deleted")
	}
	if free, _, _ := e.disk.usage(""); free < 10<<20 {
		t.Fatalf("free %d after the guard", free)
	}
	hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	if len(hist) == 0 || hist[0].Reason != index.ReasonLowDisk || !strings.Contains(hist[0].File, ".001.log") {
		t.Fatalf("deletions %+v", hist)
	}
	if n := len(eventsOf(t, e.idx, index.KindRotate)); n == 0 {
		t.Fatal("no early-close event")
	}
	// Every sender keeps writing, into a fresh file for today.
	for _, a := range addrs {
		e.write(a, "after the guard")
	}
	e.maintain()
	if e.s.Paused() {
		t.Fatal("paused")
	}
	for _, a := range addrs {
		ls := readLines(t, e.dir, model.DeviceID(a))
		if string(ls[len(ls)-1].Raw()) != "after the guard" {
			t.Fatalf("%v: last line %q", a, ls[len(ls)-1].Raw())
		}
	}
}

// TestPruneEmptyDevices is N15: a device whose logs retention has deleted, with no
// name or group and quiet for a day, is forgotten (index row, folder, known entry); a
// named one is kept.
func TestPruneEmptyDevices(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RetentionDays = 2 })
	gone, named := ip(1), ip(2)
	e.write(gone, "x")
	e.write(named, "y")
	name := "kept"
	e.maintain()
	if _, err := e.idx.UpdateDevice(bg, "192.0.2.2", index.DeviceUpdate{Name: &name}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ { // days pass; retention deletes both devices' files
		e.clock.Add(24 * time.Hour)
		e.maintain()
	}
	if files, _ := e.idx.Files(bg, ""); len(files) != 0 {
		t.Fatalf("files left %+v", files)
	}
	if devs, _ := e.idx.ListDevices(bg); len(devs) != 1 || devs[0].ID != "192.0.2.2" {
		t.Fatalf("devices %+v", devs)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "logs", "192.0.2.1")); !os.IsNotExist(err) {
		t.Fatalf("folder kept: %v", err)
	}
	e.s.devMu.Lock()
	_, knownGone := e.s.known["192.0.2.1"]
	_, knownNamed := e.s.known["192.0.2.2"]
	e.s.devMu.Unlock()
	if knownGone || !knownNamed {
		t.Fatalf("known: gone %v, named %v", knownGone, knownNamed)
	}
	// It comes back as a new device if it sends again.
	e.write(gone, "back")
	e.maintain()
	if d, err := e.idx.Device(bg, "192.0.2.1"); err != nil || d.TotalMsgs != 1 {
		t.Fatalf("%+v %v", d, err)
	}
}

// TestLowDiskFairOrderForOpenFiles: 200 small new senders and one busy established
// device, all with only open files for today, and low disk. The new senders' open
// files are closed and deleted first; the real device keeps today's file as long as
// anything else can be deleted, and every device that lost today's data is named in
// a warn event.
func TestLowDiskFairOrderForOpenFiles(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MinFreeBytes = 1 << 20; o.MinFreePercent = 1 })
	e.disk.total = 1 << 30 // reserve 10 MiB
	r := rand.New(rand.NewSource(9))
	real := ip(1)
	// The real device has a few days of history (closed and compressed) and is busy today.
	for d := 3; d >= 1; d-- {
		e.clock.Set(day0.Add(-time.Duration(d) * 24 * time.Hour))
		e.write(real, fmt.Sprintf("day -%d %s", d, randText(r, 1000)))
		e.maintain()
	}
	e.clock.Set(day0)
	e.maintain()
	for i := 0; i < 400; i++ {
		e.write(real, "today "+randText(r, 1000))
	}
	for i := 0; i < 200; i++ {
		for j := 0; j < 3; j++ {
			e.s.Write(model.Message{Received: e.clock.Now(), Sender: spread(i), Raw: []byte(randText(r, 1000))})
		}
	}
	e.maintain()
	used := uint64(duLogs(e.dir))
	// Short by 200 KiB: well under what the new senders' ~600 KiB of open files can free.
	e.disk.setOther(1<<30 - used - (10<<20 - 200<<10))
	e.maintain()
	if e.s.Paused() {
		t.Fatal("paused")
	}
	// Its older closed days may go (closed files older than a device's newest day come
	// before anyone's open files); its newest closed day and today's file stay.
	if got := strings.Join(e.files(real), ","); got != "2026-11-09.log.gz,2026-11-10.log" {
		t.Fatalf("real device files %s", got)
	}
	hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	if len(hist) == 0 {
		t.Fatal("nothing deleted")
	}
	named := map[string]bool{}
	for _, ev := range eventsOf(t, e.idx, index.KindDelete) {
		if ev.Level == index.LevelWarn && strings.Contains(ev.Text, "today's logs") {
			named[ev.DeviceID] = true
		}
	}
	for _, h := range hist {
		if h.DeviceID == "192.0.2.1" && !strings.Contains(h.File, "2026-11-07") && !strings.Contains(h.File, "2026-11-08") {
			t.Fatalf("the real device lost %s while new senders had open files", h.File)
		}
		if strings.Contains(h.File, "2026-11-10") && !named[h.DeviceID] {
			t.Fatalf("no warn event for %s losing today's %s", h.DeviceID, h.File)
		}
	}
	// Only when nothing else is left does the real device's today file go.
	e.disk.setOther(1<<30 - uint64(duLogs(e.dir)) - (10<<20 - uint64(duLogs(e.dir))/2))
	e.maintain()
	if !named["192.0.2.1"] {
		for _, ev := range eventsOf(t, e.idx, index.KindDelete) {
			if ev.Level == index.LevelWarn && ev.DeviceID == "192.0.2.1" {
				named["192.0.2.1"] = true
			}
		}
	}
	hist, _ = e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	for _, h := range hist {
		if h.DeviceID == "192.0.2.1" && strings.Contains(h.File, "2026-11-10") && !named["192.0.2.1"] {
			t.Fatal("the real device's today file went without a warn event")
		}
	}
}

// TestSpreadFloodReviewerScenarios is the second re-test's N7 case: a busy,
// long-established target with a few days of files and a week of stats, and 200
// small attackers, either new today or seeded two days earlier. With the cap at 90%
// or 75% of the data, the attackers lose files first and the target keeps its newest
// two days (yesterday's file and today's).
func TestSpreadFloodReviewerScenarios(t *testing.T) {
	for _, seeded := range []bool{false, true} {
		for _, pct := range []int64{90, 75} {
			t.Run(fmt.Sprintf("seeded=%v cap=%d%%", seeded, pct), func(t *testing.T) {
				e := newEnv(t, func(o *Options) { o.PartBytes = 8 << 10; o.RetentionDays = 3 })
				r := rand.New(rand.NewSource(13))
				target := ip(1)
				for d := 6; d >= 0; d-- { // a week of steady traffic; age retention keeps three days of files
					e.clock.Set(day0.Add(-time.Duration(d) * 24 * time.Hour))
					for i := 0; i < 300; i++ {
						e.write(target, fmt.Sprintf("target day -%d %s", d, randText(r, 1000)))
					}
					if seeded && d == 2 {
						for i := 0; i < 200; i++ {
							e.s.Write(model.Message{Received: e.clock.Now(), Sender: spread(i), Raw: []byte("seed " + randText(r, 1000))})
						}
					}
					e.maintain()
				}
				for i := 0; i < 200; i++ { // today: a little over one part each
					for j := 0; j < 12; j++ {
						e.s.Write(model.Message{Received: e.clock.Now(), Sender: spread(i), Raw: []byte(randText(r, 1000))})
					}
				}
				e.maintain()
				before := daysOf(e.files(target))
				if before != "2026-11-07,2026-11-08,2026-11-09,2026-11-10" {
					t.Fatalf("setup: target has days %s", before)
				}
				e.s.SetLimits(Limits{RetentionBytes: duLogs(e.dir) * pct / 100})
				e.maintain()
				after := daysOf(e.files(target))
				if !strings.HasSuffix(after, "2026-11-09,2026-11-10") || !contains(e.files(target), "2026-11-10.log") {
					t.Fatalf("the target lost one of its newest two days: %s -> %s", before, after)
				}
				hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
				var cap []index.Deletion
				for i := len(hist) - 1; i >= 0; i-- { // oldest first
					if hist[i].Reason == index.ReasonCap {
						cap = append(cap, hist[i])
					}
				}
				attackers := 0
				for _, h := range cap {
					if h.DeviceID != "192.0.2.1" {
						attackers++
					}
				}
				t.Logf("target %v -> %v; %d cap deletions, %d of them attackers'", before, after, len(cap), attackers)
				if len(cap) == 0 || cap[0].DeviceID == "192.0.2.1" || attackers == 0 {
					t.Fatalf("attackers didn't lose files first: %+v", cap[:min(3, len(cap))])
				}
			})
		}
	}
}

// daysOf returns the distinct days of a device's file names, comma-separated.
func daysOf(files []string) string {
	var out []string
	for _, f := range files {
		if d := f[:10]; len(out) == 0 || out[len(out)-1] != d {
			out = append(out, d)
		}
	}
	return strings.Join(out, ",")
}

// TestPruneKeepsReturningSender is L-c: a device whose logs retention deleted comes
// back just as the hourly prune runs. Registered (resident) before its first flush,
// it keeps its folder and its known-sender exemption, and its write lands on disk.
func TestPruneKeepsReturningSender(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RetentionDays = 2 })
	a := ip(1)
	e.write(a, "first")
	e.maintain()
	for i := 0; i < 5; i++ { // its files age out
		e.clock.Add(24 * time.Hour)
		e.maintain()
	}
	if files, _ := e.idx.Files(bg, "192.0.2.1"); len(files) != 0 {
		t.Fatalf("files left %+v", files)
	}
	dir := filepath.Join(e.dir, "logs", "192.0.2.1")
	if err := os.MkdirAll(dir, 0o750); err != nil { // an empty folder, as retention leaves it
		t.Fatal(err)
	}
	// The sender is back: resident, not flushed yet. Then the prune runs.
	if _, err := e.s.device(streamKey{addr: a}, true); err != nil {
		t.Fatal(err)
	}
	e.s.pruneDevices(e.clock.Now())
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the returning sender's folder was removed: %v", err)
	}
	e.s.devMu.Lock()
	_, known := e.s.known["192.0.2.1"]
	e.s.devMu.Unlock()
	if !known {
		t.Fatal("the returning sender lost its exemption")
	}
	e.write(a, "back")
	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := rawStrings(readLines(t, e.dir, "192.0.2.1")); strings.Join(got, "|") != "back" {
		t.Fatalf("lines %q", got)
	}
}
