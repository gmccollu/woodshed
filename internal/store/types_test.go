package store

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Data types in the store (SPEC §11.1): traps go to their own files in the
// device folder's traps/, with the same envelope, rotation and retention.

func (e *env) writeTrap(i int, rec string) {
	e.t.Helper()
	if err := e.s.WriteType(logfile.TypeTrap, model.Message{Received: e.clock.Now(), Sender: ip(i), Raw: []byte(rec)}); err != nil {
		e.t.Fatal(err)
	}
}

// trapFiles lists base names under a device's traps/ folder, sorted.
func (e *env) trapFiles(i int) []string {
	ents, _ := os.ReadDir(filepath.Join(e.dir, logfile.LogsDir, model.DeviceID(ip(i)), "traps"))
	var out []string
	for _, x := range ents {
		out = append(out, x.Name())
	}
	sort.Strings(out)
	return out
}

func TestTrapsInTheirOwnFiles(t *testing.T) {
	e := newEnv(t, nil)
	e.write(ip(1), "<13>syslog line")
	e.writeTrap(1, "v=2c pdu=trap id=1 cred=#3f9a1c07 status=ok trap=1.3.6.1.6.3.1.1.5.3 raw=AA==")
	e.writeTrap(2, "v=1 pdu=v1trap status=ok raw=AA==")
	e.maintain()
	if got := e.files(ip(1)); len(got) != 2 || got[0] != "2026-11-10.log" || got[1] != "traps" {
		t.Fatalf("device folder: %v", got)
	}
	// Syslog's file holds only syslog lines, byte for byte as 1.1 wrote them.
	b, err := os.ReadFile(filepath.Join(e.dir, "logs", "192.0.2.1", "2026-11-10.log"))
	if err != nil || string(b) != "2026-11-10T12:00:00.000Z 192.0.2.1 <13>syslog line\n" {
		t.Fatalf("syslog file %q %v", b, err)
	}
	b, err = os.ReadFile(filepath.Join(e.dir, "logs", "192.0.2.1", "traps", "2026-11-10.log"))
	if err != nil || !strings.HasPrefix(string(b), "2026-11-10T12:00:00.000Z 192.0.2.1 v=2c pdu=trap") {
		t.Fatalf("trap file %q %v", b, err)
	}
	files, _ := e.idx.Files(bg, "")
	types := map[string]string{}
	for _, f := range files {
		types[f.Path] = f.Type
	}
	if types["logs/192.0.2.1/2026-11-10.log"] != "syslog" || types["logs/192.0.2.1/traps/2026-11-10.log"] != "trap" ||
		types["logs/192.0.2.2/traps/2026-11-10.log"] != "trap" {
		t.Fatalf("index types %v", types)
	}
	// Device totals count every type; a trap-only sender is a device.
	if d, _ := e.idx.Device(bg, "192.0.2.1"); d.TotalMsgs != 2 {
		t.Fatalf("device 1 %+v", d)
	}
	if d, err := e.idx.Device(bg, "192.0.2.2"); err != nil || d.TotalMsgs != 1 {
		t.Fatalf("device 2 %+v %v", d, err)
	}
	if u := e.s.Usage(); u.Devices != 2 || u.Files != 3 {
		t.Fatalf("usage: %d devices (streams count once per device), %d files", u.Devices, u.Files)
	}
	if err := e.s.WriteType("sflow", model.Message{Sender: ip(1), Raw: []byte("x")}); err != ErrUnknownType {
		t.Fatalf("unknown type: %v", err)
	}
}

// A device is a device whatever it sends: one sender's syslog and traps take
// one slot under max_devices (§11.9 #4).
func TestTypesShareTheDeviceCap(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxDevices = 1; o.NewDeviceBurst = 5 })
	e.write(ip(1), "<13>one")
	e.writeTrap(1, "v=2c pdu=trap status=ok raw=AA==")
	if err := e.s.WriteType(logfile.TypeTrap, model.Message{Received: e.clock.Now(), Sender: ip(2), Raw: []byte("v=2c")}); err != ErrDeviceLimit {
		t.Fatalf("a second device's trap: %v", err)
	}
	if err := e.s.Write(model.Message{Received: e.clock.Now(), Sender: ip(2), Raw: []byte("<13>x")}); err != ErrDeviceLimit {
		t.Fatalf("a second device's syslog: %v", err)
	}
	if u := e.s.Usage(); u.Devices != 1 {
		t.Fatalf("devices %d", u.Devices)
	}
}

// At the cap a returning known sender evicts the least recently heard device,
// all of its types' streams.
func TestEvictionTakesEveryStream(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxDevices = 1 })
	e.write(ip(2), "<13>two")
	e.maintain()
	e.reopen() // ip(2) has logs on disk now: a known sender
	e.write(ip(1), "<13>one")
	e.writeTrap(1, "v=2c pdu=trap id=1 status=ok raw=AA==")
	e.clock.Add(2 * time.Second)
	e.write(ip(2), "<13>two again") // known: takes ip(1)'s slot, both its streams
	e.maintain()
	if u := e.s.Usage(); u.Devices != 1 {
		t.Fatalf("devices %d", u.Devices)
	}
	e.s.devMu.Lock()
	_, syslogRes := e.s.devSet[streamKey{ip(1), 0}]
	_, trapRes := e.s.devSet[streamKey{ip(1), 1}]
	e.s.devMu.Unlock()
	if syslogRes || trapRes {
		t.Fatalf("ip(1) still resident: syslog %v trap %v", syslogRes, trapRes)
	}
	e.clock.Add(2 * time.Second)
	e.writeTrap(1, "v=2c pdu=trap id=2 status=ok raw=AA==") // back again: appends to its parked file
	e.maintain()
	b, _ := os.ReadFile(filepath.Join(e.dir, "logs", "192.0.2.1", "traps", "2026-11-10.log"))
	if strings.Count(string(b), "\n") != 2 {
		t.Fatalf("trap file %q", b)
	}
	if got := rawStrings(readLines(t, e.dir, "192.0.2.2")); len(got) != 2 {
		t.Fatalf("ip(2) %q", got)
	}
}

// Recovery parks each type's file for today, and a restart appends to both.
func TestTypesRecoverAndRotate(t *testing.T) {
	e := newEnv(t, nil)
	e.write(ip(1), "<13>before")
	e.writeTrap(1, "v=2c pdu=trap id=1 status=ok raw=AA==")
	e.reopen()
	e.write(ip(1), "<13>after")
	e.writeTrap(1, "v=2c pdu=trap id=2 status=ok raw=AA==")
	e.maintain()
	if tf := e.trapFiles(1); len(tf) != 1 || tf[0] != "2026-11-10.log" {
		t.Fatalf("trap files after restart: %v", tf)
	}
	b, _ := os.ReadFile(filepath.Join(e.dir, "logs", "192.0.2.1", "traps", "2026-11-10.log"))
	if strings.Count(string(b), "\n") != 2 {
		t.Fatalf("trap file %q", b)
	}
	// Midnight closes and compresses each type's file.
	e.clock.Set(time.Date(2026, 11, 11, 0, 0, 1, 0, time.UTC))
	e.writeTrap(1, "v=2c pdu=trap id=3 status=ok raw=AA==")
	e.maintain()
	e.maintain()
	if tf := e.trapFiles(1); len(tf) != 2 || tf[0] != "2026-11-10.log.gz" || tf[1] != "2026-11-11.log" {
		t.Fatalf("trap files after midnight: %v", tf)
	}
	files, _ := e.idx.Files(bg, "192.0.2.1")
	for _, f := range files {
		if strings.Contains(f.Path, "/traps/") != (f.Type == "trap") {
			t.Fatalf("row %+v", f)
		}
	}
}

// Retention treats all of a device's types as one (SPEC §11.1): the age limit
// deletes old trap files too, and within a device the oldest file goes first
// whatever its type; deletions record the type.
func TestRetentionAcrossTypes(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RetentionDays = 3 })
	r := rand.New(rand.NewSource(3))
	end := e.clock.Now()
	for d := 6; d >= 0; d-- {
		e.clock.Set(end.Add(-time.Duration(d) * 24 * time.Hour))
		for i := 0; i < 20; i++ {
			e.write(ip(1), fmt.Sprintf("<13>day -%d %s", d, randText(r, 200)))
			if d%2 == 0 {
				e.writeTrap(1, fmt.Sprintf("v=2c pdu=trap id=%d status=ok vb=1.3.6.1.4.1.32473.1.1.1.0:str:\"%s\" raw=AA==", i, randText(r, 200)))
			}
		}
		e.maintain()
		e.maintain()
	}
	e.clock.Set(end)
	e.maintain()
	for _, f := range e.trapFiles(1) {
		if f < "2026-11-07" {
			t.Fatalf("old trap file kept: %v", e.trapFiles(1))
		}
	}
	dels, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	var trapDels int
	for _, d := range dels {
		if d.Type == "trap" {
			trapDels++
			if !strings.Contains(d.File, "/traps/") {
				t.Fatalf("deletion %+v", d)
			}
		}
	}
	if trapDels == 0 {
		t.Fatalf("no trap deletions: %+v", dels)
	}

	// The size cap: one device, both types. The oldest file goes first across
	// types, so trap and syslog files of the same old day go before newer days.
	limit := duLogs(e.dir) / 2
	e.s.SetLimits(Limits{RetentionBytes: limit})
	e.maintain()
	files, _ := e.idx.Files(bg, "192.0.2.1")
	oldest := map[string]string{}
	for _, f := range files {
		if o, ok := oldest[f.Type]; !ok || f.Day < o {
			oldest[f.Type] = f.Day
		}
	}
	// The trap files exist only on even days (-6, -4, -2, 0); after the cap, no
	// type keeps a day older than the other type's oldest by more than the gap
	// between trap days.
	if oldest["syslog"] == "" || oldest["trap"] == "" {
		t.Fatalf("a type lost everything: %v (%+v)", oldest, files)
	}
	sd, _ := logfile.DayStart(oldest["syslog"])
	td, _ := logfile.DayStart(oldest["trap"])
	if gap := sd.Sub(td); gap > 48*time.Hour || gap < -48*time.Hour {
		t.Fatalf("oldest days differ by %v: %v", gap, oldest)
	}
}

// The low-disk guard counts and deletes every type's files.
func TestLowDiskAcrossTypes(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MinFreeBytes = 1 << 20; o.MinFreePercent = 1 })
	r := rand.New(rand.NewSource(5))
	end := e.clock.Now()
	for d := 3; d >= 1; d-- {
		e.clock.Set(end.Add(-time.Duration(d) * 24 * time.Hour))
		for i := 0; i < 200; i++ {
			e.writeTrap(1, fmt.Sprintf("v=2c pdu=trap id=%d status=ok vb=1.3.6.1.4.1.32473.1.1.1.0:str:\"%s\" raw=AA==", i, randText(r, 2000)))
		}
		e.maintain()
		e.maintain()
	}
	e.clock.Set(end)
	e.write(ip(1), "<13>today")
	e.maintain()
	used := uint64(duLogs(e.dir))
	e.disk.total = 100 << 20
	e.disk.setOther(e.disk.total - (1 << 20) - used/2) // short by about half of what's on disk
	e.maintain()
	dels, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	if len(dels) == 0 || dels[len(dels)-1].Type != "trap" || dels[len(dels)-1].Reason != index.ReasonLowDisk {
		t.Fatalf("low-disk deletions %+v", dels)
	}
	if got := readLines(t, e.dir, "192.0.2.1"); len(got) != 1 {
		t.Fatalf("today's syslog %q", rawStrings(got))
	}
}

// pruneDevices removes an empty traps/ folder with its device folder.
func TestPruneRemovesTypeFolders(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RetentionDays = 1 })
	e.writeTrap(1, "v=2c pdu=trap status=ok raw=AA==")
	e.maintain()
	e.clock.Add(24 * time.Hour)
	e.maintain()
	e.maintain()
	e.clock.Add(4 * 24 * time.Hour)
	e.maintain()
	e.maintain()
	e.clock.Add(2 * time.Hour)
	e.maintain()
	if _, err := os.Stat(filepath.Join(e.dir, "logs", "192.0.2.1")); !os.IsNotExist(err) {
		ents, _ := os.ReadDir(filepath.Join(e.dir, "logs", "192.0.2.1", "traps"))
		t.Fatalf("device folder kept (%v): %v", err, ents)
	}
}
