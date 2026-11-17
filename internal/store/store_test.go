package store

import (
	"bytes"
	"errors"
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
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

func TestWriteFormatAndIndex(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(1)
	raws := []string{"<134>Nov 10 12:00:00 host app: hello", "multi\nline\r\nwith \\ backslash", ""}
	for _, r := range raws {
		e.write(a, r)
		e.clock.Add(1500 * time.Microsecond)
	}
	v6 := netip.MustParseAddr("2001:db8::7")
	e.write(v6, "v6 sender")
	if err := e.s.Write(model.Message{Sender: netip.MustParseAddr("::ffff:192.0.2.1"), Raw: []byte("mapped, zero time"), Truncated: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Write(model.Message{Raw: []byte("no sender")}); !errors.Is(err, ErrInvalidSender) {
		t.Fatalf("no sender: %v", err)
	}
	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "logs/192.0.2.1/2026-11-10.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-11-10T12:00:00.000Z 192.0.2.1 <134>Nov 10 12:00:00 host app: hello\n" +
		"2026-11-10T12:00:00.001Z 192.0.2.1 multi\\nline\\r\\nwith \\\\ backslash\n" +
		"2026-11-10T12:00:00.003Z 192.0.2.1 \n" +
		"2026-11-10T12:00:00.004Z 192.0.2.1 mapped, zero time \\#truncated\n"
	if string(data) != want {
		t.Fatalf("file:\n%s\nwant:\n%s", data, want)
	}
	got := rawStrings(readLines(t, e.dir, "192.0.2.1"))
	if got[1] != raws[1] {
		t.Fatalf("unescaped %q", got[1])
	}
	if _, err := os.Stat(filepath.Join(e.dir, "logs/2001_db8__7/2026-11-10.log")); err != nil {
		t.Fatal(err)
	}
	f, err := e.idx.FileByPath(bg, "logs/192.0.2.1/2026-11-10.log")
	if err != nil || f.Lines != 4 || f.Size != int64(len(data)) || !f.FirstReceived.Equal(day0) || f.Compressed {
		t.Fatalf("%+v %v", f, err)
	}
	dv, _ := e.idx.Device(bg, "192.0.2.1")
	if dv.TotalMsgs != 4 || dv.IP != "192.0.2.1" || dv.BytesOnDisk != int64(len(data)) {
		t.Fatalf("device %+v", dv)
	}
	tot, _ := e.idx.TotalCounts(bg, day0.Add(-time.Hour), day0.Add(time.Hour))
	if tot.Msgs != 5 || tot.Truncated != 1 {
		t.Fatalf("stats %+v", tot)
	}
	u := e.s.Usage()
	if u.Written != 5 || u.Files != 2 || u.DaysKept != 1 || u.BytesOnDisk != duLogs(e.dir) {
		t.Fatalf("usage %+v (du %d)", u, duLogs(e.dir))
	}
}

// An incomplete frame's line carries the marker (2.0), its raw comes back
// without it, and it isn't counted as truncated.
func TestWriteIncomplete(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(1)
	for _, m := range []model.Message{
		{Sender: a, Raw: []byte("<13>short"), Incomplete: true, FrameArrived: 9, FrameLength: 50},
		{Sender: a, Raw: []byte("<13>short")},
		{Sender: a, Raw: []byte("<13>cut line"), Incomplete: true},
		{Sender: a, Raw: []byte("<13>abcd"), Truncated: true, Incomplete: true, FrameArrived: 70000, FrameLength: 100000},
	} {
		if err := e.s.Write(m); err != nil {
			t.Fatal(err)
		}
		e.clock.Add(time.Millisecond)
	}
	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(e.dir, "logs/192.0.2.1/2026-11-10.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := "2026-11-10T12:00:00.000Z 192.0.2.1 <13>short \\#incomplete=9/50\n" +
		"2026-11-10T12:00:00.001Z 192.0.2.1 <13>short\n" +
		"2026-11-10T12:00:00.002Z 192.0.2.1 <13>cut line \\#incomplete\n" +
		"2026-11-10T12:00:00.003Z 192.0.2.1 <13>abcd \\#truncated,incomplete=70000/100000\n"
	if string(data) != want {
		t.Fatalf("file:\n%s\nwant:\n%s", data, want)
	}
	if got := rawStrings(readLines(t, e.dir, "192.0.2.1")); strings.Join(got, "|") != "<13>short|<13>short|<13>cut line|<13>abcd" {
		t.Fatalf("raws %q", got)
	}
	tot, _ := e.idx.TotalCounts(bg, day0.Add(-time.Hour), day0.Add(time.Hour))
	if tot.Msgs != 4 || tot.Truncated != 1 {
		t.Fatalf("stats %+v", tot)
	}
}

func TestEscapeHelpers(t *testing.T) {
	raw := []byte("a\nb\\c\r")
	if got := Unescape(nil, Escape(nil, raw)); !bytes.Equal(got, raw) {
		t.Fatalf("round trip %q", got)
	}
	line := FormatLine(nil, day0, ip(9), raw)
	l, err := ParseLine(line)
	if err != nil || !bytes.Equal(l.Raw(), raw) || l.Sender != ip(9) {
		t.Fatalf("%+v %v", l, err)
	}
}

func TestMidnightRotation(t *testing.T) {
	e := newEnv(t, nil)
	busy, idle := ip(1), ip(2)
	e.clock.Set(time.Date(2026, 11, 10, 23, 59, 59, 500e6, time.UTC))
	e.write(busy, "before midnight")
	e.write(idle, "idle device, before midnight")
	e.maintain()
	e.clock.Set(time.Date(2026, 11, 11, 0, 0, 0, 200e6, time.UTC))
	e.write(busy, "after midnight")
	// A message received before midnight but processed after the rotation goes into the
	// new day's file and keeps its own timestamp.
	late := time.Date(2026, 11, 10, 23, 59, 59, 900e6, time.UTC)
	if err := e.s.Write(model.Message{Received: late, Sender: busy, Raw: []byte("late")}); err != nil {
		t.Fatal(err)
	}
	e.maintain() // closes the idle device's file too, and compresses both
	if got := strings.Join(e.files(busy), ","); got != "2026-11-10.log.gz,2026-11-11.log" {
		t.Fatalf("busy files %s", got)
	}
	if got := strings.Join(e.files(idle), ","); got != "2026-11-10.log.gz" {
		t.Fatalf("idle files %s", got)
	}
	got := rawStrings(readLines(t, e.dir, "192.0.2.1"))
	if strings.Join(got, "|") != "before midnight|after midnight|late" {
		t.Fatalf("lines %q", got)
	}
	f, _ := e.idx.FileByPath(bg, "logs/192.0.2.1/2026-11-11.log")
	if !f.FirstReceived.Equal(late) {
		t.Fatalf("first received of new day file %v", f.FirstReceived)
	}
	if gz, err := e.idx.FileByPath(bg, "logs/192.0.2.2/2026-11-10.log.gz"); err != nil || !gz.Compressed || gz.Lines != 1 {
		t.Fatalf("%+v %v", gz, err)
	}
	if n := len(eventsOf(t, e.idx, index.KindRotate)); n != 2 {
		t.Fatalf("%d rotate events", n)
	}
	// After a restart the late-message rule still holds: day 10 is closed for good.
	e.reopen()
	if err := e.s.Write(model.Message{Received: late, Sender: idle, Raw: []byte("very late")}); err != nil {
		t.Fatal(err)
	}
	e.s.Flush()
	if got := strings.Join(e.files(idle), ","); got != "2026-11-10.log.gz,2026-11-11.log" {
		t.Fatalf("idle files after restart %s", got)
	}
}

func TestSizeParts(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.PartBytes = 8 << 10 })
	a := ip(1)
	var want []string
	for i := 0; i < 300; i++ {
		r := fmt.Sprintf("message %03d %s", i, strings.Repeat("x", 60))
		want = append(want, r)
		e.write(a, r)
		e.clock.Add(time.Second)
		if i%37 == 0 {
			e.s.Flush()
		}
	}
	e.s.Flush()
	before, _ := e.idx.Files(bg, "192.0.2.1")
	e.maintain()
	names := e.files(a)
	if len(names) < 3 || names[len(names)-1] != "2026-11-10.log" || names[0] != "2026-11-10.001.log.gz" {
		t.Fatalf("names %v", names)
	}
	for _, n := range names[:len(names)-1] {
		if !strings.HasSuffix(n, ".log.gz") {
			t.Fatalf("closed part not compressed: %v", names)
		}
		st, _ := os.Stat(filepath.Join(e.dir, "logs/192.0.2.1", n))
		if st.Size() > 8<<10 {
			t.Fatalf("%s is %d bytes", n, st.Size())
		}
	}
	got := rawStrings(readLines(t, e.dir, "192.0.2.1"))
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %d lines back, want %d, or out of order", len(got), len(want))
	}
	after, _ := e.idx.Files(bg, "192.0.2.1")
	if len(after) != len(names) || len(before) != len(after) {
		t.Fatalf("index has %d then %d files, disk %d", len(before), len(after), len(names))
	}
	for i := range before {
		if before[i].ID != after[i].ID || !after[i].Compressed && i < len(after)-1 {
			t.Fatalf("file %d: ID %d -> %d, %+v", i, before[i].ID, after[i].ID, after[i])
		}
	}
	var lines int64
	for _, f := range after {
		lines += f.Lines
	}
	if lines != 300 {
		t.Fatalf("index counts %d lines", lines)
	}
}

func TestGzipVerifyFailureKeepsOriginal(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(1)
	corrupt := 1
	e.s.testHookGzip = func(path string) {
		if corrupt > 0 {
			corrupt--
			data, _ := os.ReadFile(path)
			data[len(data)/2] ^= 0xff
			data[len(data)/2+1] ^= 0xff
			os.WriteFile(path, data, 0o600)
		}
	}
	for i := 0; i < 2000; i++ {
		e.write(a, fmt.Sprintf("line %d", i))
	}
	e.clock.Add(24 * time.Hour)
	e.maintain()
	if got := strings.Join(e.files(a), ","); got != "2026-11-10.log" {
		t.Fatalf("after a failed verify: %s", got)
	}
	evs := eventsOf(t, e.idx, index.KindCompress)
	if len(evs) != 1 || !strings.Contains(evs[0].Text, "original kept") {
		t.Fatalf("events %+v", evs)
	}
	if u := e.s.Usage(); u.PendingCompression != 1 {
		t.Fatalf("usage %+v", u)
	}
	e.maintain() // backoff: not retried yet
	if got := strings.Join(e.files(a), ","); got != "2026-11-10.log" {
		t.Fatalf("retried too early: %s", got)
	}
	e.clock.Add(3 * time.Minute)
	e.maintain()
	if got := strings.Join(e.files(a), ","); got != "2026-11-10.log.gz" {
		t.Fatalf("after retry: %s", got)
	}
	if n := len(readLines(t, e.dir, "192.0.2.1")); n != 2000 {
		t.Fatalf("%d lines", n)
	}
}

func TestVerifyDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "a.log")
	os.WriteFile(src, bytes.Repeat([]byte("2026-11-10T12:00:00.000Z 192.0.2.1 hello world\n"), 5000), 0o600)
	sum, n, err := gzipTo(bg, src, src+".gz")
	if err != nil {
		t.Fatal(err)
	}
	vs, vn, err := hashGzip(src + ".gz")
	if err != nil || vn != n || !bytes.Equal(vs, sum) {
		t.Fatalf("clean gzip didn't verify: %v", err)
	}
	data, _ := os.ReadFile(src + ".gz")
	os.WriteFile(src+".gz", data[:len(data)-10], 0o600) // truncated
	if _, _, err := hashGzip(src + ".gz"); err == nil {
		t.Fatal("truncated gzip verified")
	}
}

// writeDays writes one message a day per device for n days ending today, and lets
// maintenance close and compress each day.
func writeDays(e *env, addrs []netip.Addr, n int, payload int) {
	start := e.clock.Now().Add(-time.Duration(n-1) * 24 * time.Hour)
	end := e.clock.Now()
	e.clock.Set(start)
	r := rand.New(rand.NewSource(int64(n)))
	text := func() string {
		b := make([]byte, payload)
		for i := range b {
			b[i] = byte('a' + r.Intn(26))
		}
		return string(b)
	}
	for i := 0; i < n; i++ {
		for _, a := range addrs {
			e.write(a, fmt.Sprintf("day %d %s", i, text()))
		}
		e.maintain()
		if i < n-1 {
			e.clock.Add(24 * time.Hour)
		}
	}
	e.clock.Set(end)
	e.maintain()
}

func TestRetentionByAge(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.RetentionDays = 30 })
	a := ip(1)
	// Keep retention off while back-filling, then turn it on.
	e.s.SetLimits(Limits{RetentionDays: 1000})
	writeDays(e, []netip.Addr{a}, 40, 10)
	if n := len(e.files(a)); n != 40 {
		t.Fatalf("%d files before retention", n)
	}
	e.s.SetLimits(Limits{RetentionDays: 30})
	e.maintain()
	names := e.files(a)
	// Today's active file plus compressed files whose newest line is under 30 days old.
	if len(names) != 31 || names[0] != "2026-10-11.log.gz" || names[30] != "2026-11-10.log" {
		t.Fatalf("%d files: %v", len(names), names)
	}
	hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	if len(hist) != 9 || hist[0].Reason != index.ReasonAge || hist[len(hist)-1].File != "logs/192.0.2.1/2026-10-02.log.gz" {
		t.Fatalf("history %+v", hist)
	}
	if n := len(eventsOf(t, e.idx, index.KindDelete)); n != 9 {
		t.Fatalf("%d delete events", n)
	}
	if u := e.s.Usage(); u.DaysKept != 31 {
		t.Fatalf("days kept %d", u.DaysKept)
	}
	files, _ := e.idx.Files(bg, "")
	if len(files) != 31 {
		t.Fatalf("index has %d files", len(files))
	}
}

func TestRetentionByCap(t *testing.T) {
	e := newEnv(t, nil)
	addrs := []netip.Addr{ip(1), ip(2)}
	writeDays(e, addrs, 10, 20000) // ~ one small gzip per device per day
	total := duLogs(e.dir)
	cap := total * 6 / 10
	e.s.SetLimits(Limits{RetentionBytes: cap})
	e.maintain()
	if got := duLogs(e.dir); got > cap {
		t.Fatalf("%d bytes on disk, cap %d", got, cap)
	}
	if u := e.s.Usage(); u.BytesOnDisk != duLogs(e.dir) {
		t.Fatalf("usage says %d, disk %d", u.BytesOnDisk, duLogs(e.dir))
	}
	hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	if len(hist) == 0 {
		t.Fatal("nothing deleted")
	}
	// Oldest first: every deleted file is older than every kept compressed file.
	var newestDeleted string
	for _, h := range hist {
		if h.Reason != index.ReasonCap {
			t.Fatalf("reason %s", h.Reason)
		}
		day := filepath.Base(h.File)[:10]
		if day > newestDeleted {
			newestDeleted = day
		}
	}
	files, _ := e.idx.Files(bg, "")
	for _, f := range files {
		if f.Day < newestDeleted {
			t.Fatalf("kept %s but deleted a file from %s", f.Path, newestDeleted)
		}
	}
	// Far over the cap, each established device still keeps its newest two days
	// (today's active file and yesterday's): the size cap never takes those.
	e.s.SetLimits(Limits{RetentionBytes: 1})
	e.maintain()
	for _, a := range addrs {
		if got := strings.Join(e.files(a), ","); got != "2026-11-09.log.gz,2026-11-10.log" {
			t.Fatalf("files %s", got)
		}
	}
}

func TestLowDiskGuardAndPause(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MinFreeBytes = 1 << 20; o.MinFreePercent = 5 })
	e.disk.total = 100 << 20 // threshold: 5 MiB
	a, b := ip(1), ip(2)
	writeDays(e, []netip.Addr{a}, 5, 600000) // four ~360 KB gzips and today's active file
	logs := uint64(duLogs(e.dir))
	// Leave 300 KB less than the 5 MiB threshold: the guard deletes the oldest gzip.
	e.disk.setOther(100<<20 - logs - (5<<20 - 300<<10))
	e.maintain()
	if e.s.Paused() {
		t.Fatal("paused although there was something to delete")
	}
	hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	if len(hist) != 1 || hist[0].Reason != index.ReasonLowDisk || hist[0].File != "logs/192.0.2.1/2026-11-06.log.gz" {
		t.Fatalf("history %+v", hist)
	}
	free, _, _ := e.disk.usage("")
	if free < 5<<20 {
		t.Fatalf("free %d after the guard", free)
	}
	// Now nothing closed is left that would help: writes pause, drops are counted.
	e.disk.setOther(100<<20 - uint64(duLogs(e.dir)) - 1<<20)
	e.maintain()
	if !e.s.Paused() || !e.s.Usage().WritesPaused {
		t.Fatal("not paused")
	}
	if got := strings.Join(e.files(a), ","); got != "2026-11-10.log" {
		t.Fatalf("active file touched: %s", got)
	}
	for i := 0; i < 7; i++ {
		if err := e.s.Write(model.Message{Received: e.clock.Now(), Sender: b, Raw: []byte("dropped")}); !errors.Is(err, ErrPaused) {
			t.Fatalf("write while paused: %v", err)
		}
	}
	e.clock.Add(2 * time.Minute)
	e.maintain()
	if u := e.s.Usage(); u.Dropped != 7 {
		t.Fatalf("usage %+v", u)
	}
	tot, _ := e.idx.TotalCounts(bg, day0.Add(-time.Hour), day0.Add(time.Hour))
	if tot.Dropped != 7 {
		t.Fatalf("stats %+v", tot)
	}
	per, _ := e.idx.DeviceCounts(bg, day0.Add(-time.Hour), day0.Add(time.Hour))
	if per["192.0.2.2"].Dropped != 7 {
		t.Fatalf("per device %+v", per)
	}
	if u := e.s.Usage(); u.ReserveBytes != 5<<20 {
		t.Fatalf("reserve %d", u.ReserveBytes)
	}
	if evs := eventsOf(t, e.idx, index.KindPause); len(evs) != 1 || evs[0].Level != index.LevelError ||
		!strings.Contains(evs[0].Text, "low-disk reserve of 0.0 GiB (5242880 bytes)") {
		t.Fatalf("pause events %+v", evs)
	}
	if evs := eventsOf(t, e.idx, index.KindDrop); len(evs) != 1 || evs[0].DeviceID != "192.0.2.2" || !strings.Contains(evs[0].Text, "dropped 7") {
		t.Fatalf("drop events %+v", evs)
	}
	// Space comes back: writing resumes.
	e.disk.setOther(0)
	e.maintain()
	if e.s.Paused() {
		t.Fatal("still paused")
	}
	e.write(b, "back")
	if n := len(eventsOf(t, e.idx, index.KindResume)); n != 1 {
		t.Fatalf("%d resume events", n)
	}
}

func TestLowDiskGuardReclaimsFirst(t *testing.T) {
	var asked []uint64
	var e *env
	reclaimable := uint64(2 << 20) // say, exports
	e = newEnv(t, func(o *Options) {
		o.MinFreeBytes, o.MinFreePercent = 1<<20, 5
		o.Reclaim = func(need uint64) uint64 {
			asked = append(asked, need)
			freed := min(reclaimable, need+need/2)
			reclaimable -= freed
			e.disk.mu.Lock()
			e.disk.other -= freed
			e.disk.mu.Unlock()
			return freed
		}
	})
	e.disk.total = 100 << 20 // threshold: 5 MiB
	writeDays(e, []netip.Addr{ip(1)}, 5, 600000)
	logs := uint64(duLogs(e.dir))
	// 300 KB short: the exports cover it, so no log is deleted.
	e.disk.setOther(100<<20 - logs - (5<<20 - 300<<10))
	e.maintain()
	if len(asked) != 1 || asked[0] < 300<<10 || asked[0] > 310<<10 {
		t.Fatalf("Reclaim asked for %v", asked)
	}
	if hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0); len(hist) != 0 {
		t.Fatalf("deleted logs although exports covered it: %+v", hist)
	}
	// 3 MiB short: the rest of the exports (~1.5 MiB) aren't enough, so the
	// oldest logs go too.
	e.disk.setOther(100<<20 - uint64(duLogs(e.dir)) - (5<<20 - 3<<20))
	e.maintain()
	if reclaimable != 0 || len(asked) != 2 {
		t.Fatalf("reclaimable left %d, asked %v", reclaimable, asked)
	}
	hist, _ := e.idx.Deletions(bg, time.Time{}, time.Time{}, 0)
	if len(hist) == 0 || hist[0].Reason != index.ReasonLowDisk {
		t.Fatalf("history %+v", hist)
	}
	if free, _, _ := e.disk.usage(""); free < 5<<20 {
		t.Fatalf("free %d after the guard", free)
	}
}

func TestDiskUsageErrorDisablesGuard(t *testing.T) {
	e := newEnv(t, func(o *Options) {
		o.DiskUsage = func(string) (uint64, uint64, error) { return 0, 0, errors.New("statfs: boom") }
	})
	e.write(ip(1), "x")
	e.maintain()
	e.maintain()
	if e.s.Paused() {
		t.Fatal("paused on a disk usage error")
	}
	if evs := eventsOf(t, e.idx, index.KindError); len(evs) != 1 || !strings.Contains(evs[0].Text, "guard is off") {
		t.Fatalf("events %+v", evs)
	}
}

func TestRealDiskUsage(t *testing.T) {
	free, total, err := DiskUsage(t.TempDir())
	if err != nil || total == 0 || free > total {
		t.Fatalf("free %d total %d err %v", free, total, err)
	}
}

func TestHandleLRU(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxOpenFiles = 8 })
	const devices, rounds = 200, 5
	for r := 0; r < rounds; r++ {
		for i := 0; i < devices; i++ {
			e.write(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), fmt.Sprintf("round %d", r))
		}
		if err := e.s.Flush(); err != nil {
			t.Fatal(err)
		}
	}
	e.s.lruMu.Lock()
	maxOpen, open := e.s.maxOpen, e.s.openFiles
	e.s.lruMu.Unlock()
	if maxOpen > 8 || open > 8 {
		t.Fatalf("max open %d, open %d", maxOpen, open)
	}
	for i := 0; i < devices; i++ {
		ls := readLines(t, e.dir, model.DeviceID(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)})))
		if len(ls) != rounds {
			t.Fatalf("device %d has %d lines", i, len(ls))
		}
	}
	// Evicted-while-dirty files were fsynced through a fresh handle.
	for _, d := range e.s.allDevices() {
		d.fileMu.Lock()
		dirty := d.dirty
		d.fileMu.Unlock()
		if dirty {
			t.Fatalf("%s still dirty after Flush", d.id)
		}
	}
}

// crash simulates the process dying: buffers are lost, nothing more reaches the
// index, and the handles are just closed.
func (e *env) crash() {
	s := e.s
	s.closed.Store(true)
	close(s.stop)
	s.cancel()
	s.wg.Wait()
	for _, d := range s.allDevices() {
		d.fileMu.Lock()
		if d.f != nil {
			d.f.Close()
			d.f = nil
		}
		d.fileMu.Unlock()
	}
	e.s = nil
}

func TestCrashRecovery(t *testing.T) {
	e := newEnv(t, nil)
	a, b := ip(1), ip(2)
	for i := 0; i < 500; i++ {
		e.write(a, fmt.Sprintf("indexed %d", i))
	}
	e.s.Flush()
	for i := 0; i < 200; i++ {
		e.write(a, fmt.Sprintf("written, not indexed %d", i))
	}
	e.s.flushAll(false) // in the file, but the index update never happened
	for i := 0; i < 50; i++ {
		e.write(a, "only buffered: lost in the crash")
	}
	e.crash()

	dir := filepath.Join(e.dir, "logs/192.0.2.1")
	active := filepath.Join(dir, "2026-11-10.log")
	// A torn last line, with its header intact.
	f, _ := os.OpenFile(active, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("2026-11-10T12:00:01.000Z 192.0.2.1 torn mess")
	f.Close()
	// Yesterday's file, closed but never compressed, ending in garbage.
	var y []byte
	for i := 0; i < 10; i++ {
		y = logfile.AppendLine(y, day0.Add(-24*time.Hour), a, []byte("yesterday"))
	}
	os.WriteFile(filepath.Join(dir, "2026-11-09.log"), append(y, "\x00\x00\x00\x00"...), 0o640)
	// An interrupted compression (the .gz is complete, the original wasn't deleted).
	var w []byte
	for i := 0; i < 10; i++ {
		w = logfile.AppendLine(w, day0.Add(-48*time.Hour), a, []byte("two days ago"))
	}
	os.WriteFile(filepath.Join(dir, "2026-11-08.log"), w, 0o640)
	gzipBytes(t, filepath.Join(dir, "2026-11-08.log.gz"), w)
	// A leftover temp gzip, and device b's file from a run the index never heard of.
	os.WriteFile(filepath.Join(dir, "2026-11-07.log.gz.tmp"), []byte("partial"), 0o640)
	os.MkdirAll(filepath.Join(e.dir, "logs/192.0.2.2"), 0o750)
	os.WriteFile(filepath.Join(e.dir, "logs/192.0.2.2/2026-11-10.log"), logfile.AppendLine(nil, day0, b, []byte("b before")), 0o640)

	e.open()
	e.write(a, "after restart")
	e.write(b, "b after")
	e.maintain()

	if got := strings.Join(e.files(a), ","); got != "2026-11-08.log.gz,2026-11-09.log.gz,2026-11-10.log" {
		t.Fatalf("files %s", got)
	}
	lines := rawStrings(readLines(t, e.dir, "192.0.2.1"))
	if len(lines) != 10+10+500+200+1+1 {
		t.Fatalf("%d lines", len(lines))
	}
	if lines[len(lines)-2] != "torn mess" || lines[len(lines)-1] != "after restart" {
		t.Fatalf("tail %q", lines[len(lines)-3:])
	}
	if got := rawStrings(readLines(t, e.dir, "192.0.2.2")); strings.Join(got, "|") != "b before|b after" {
		t.Fatalf("device b %q", got)
	}
	recov := eventsOf(t, e.idx, index.KindRecover)
	var texts []string
	for _, ev := range recov {
		texts = append(texts, ev.Text)
	}
	all := strings.Join(texts, "\n")
	for _, want := range []string{"kept it as its own line", "unreadable partial line", "1 unfinished gzip", "1 interrupted compression"} {
		if !strings.Contains(all, want) {
			t.Errorf("no recovery event %q in:\n%s", want, all)
		}
	}
	// The index matches a rebuild from the files alone.
	e.s.Close()
	got := indexSnapshot(t, e.idx)
	fresh, _ := index.Open(filepath.Join(t.TempDir(), "fresh.db"))
	defer fresh.Close()
	if _, err := fresh.Reindex(bg, e.dir); err != nil {
		t.Fatal(err)
	}
	if want := indexSnapshot(t, fresh); filesPart(got) != filesPart(want) {
		t.Fatalf("index after recovery:\n%s\nrebuild:\n%s", filesPart(got), filesPart(want))
	}
	e.s = nil
}

// filesPart drops device lines: totals legitimately differ (lost buffered messages
// were counted as received only by the crashed process, and never reached the index).
func filesPart(snap string) string {
	var out []string
	for _, l := range strings.Split(snap, "\n") {
		if !strings.HasPrefix(l, "dev ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func gzipBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	tmp := path + ".src"
	os.WriteFile(tmp, data, 0o600)
	if _, _, err := gzipTo(bg, tmp, path); err != nil {
		t.Fatal(err)
	}
	os.Remove(tmp)
}

func TestReindexReproducesIndex(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.PartBytes = 64 << 10 })
	addrs := []netip.Addr{ip(1), ip(2), netip.MustParseAddr("2001:db8::3")}
	e.clock.Set(time.Date(2026, 11, 9, 22, 0, 0, 0, time.UTC))
	for i := 0; i < 12000; i++ {
		a := addrs[i%len(addrs)]
		e.write(a, fmt.Sprintf("msg %d with\nnewline and \\ %s", i, strings.Repeat("z", i%90)))
		e.clock.Add(1300 * time.Millisecond) // crosses midnight; spans > 1 min per file
		if i%1000 == 0 {
			e.maintain()
		}
	}
	e.maintain()
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	e.s = nil
	got := indexSnapshot(t, e.idx)
	if !strings.Contains(got, ".001.log.gz") || !strings.Contains(got, "2026-11-10.log ") {
		t.Fatalf("workload didn't produce parts and rotation:\n%s", got)
	}
	fresh, err := index.Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.Reindex(bg, e.dir); err != nil {
		t.Fatal(err)
	}
	if want := indexSnapshot(t, fresh); got != want {
		t.Fatalf("store's index:\n%s\nrebuilt:\n%s", got, want)
	}
	// Reindex over the existing index is idempotent too.
	if _, err := e.idx.Reindex(bg, e.dir); err != nil {
		t.Fatal(err)
	}
	if again := indexSnapshot(t, e.idx); again != got {
		t.Fatalf("reindex in place changed the index:\n%s", again)
	}
}

func TestSetLimitsAndDefaults(t *testing.T) {
	e := newEnv(t, nil)
	l := e.s.Limits()
	if l.PartBytes != DefaultPartBytes || l.RetentionDays != 30 || l.RetentionBytes != 20<<30 {
		t.Fatalf("defaults %+v", l)
	}
	e.s.SetLimits(Limits{PartBytes: 1 << 20})
	if l := e.s.Limits(); l.PartBytes != 1<<20 || l.RetentionDays != 30 {
		t.Fatalf("after set %+v", l)
	}
	if _, err := Open(Options{DataDir: e.dir}); err == nil {
		t.Fatal("opened without an index")
	}
}

func TestClosed(t *testing.T) {
	e := newEnv(t, nil)
	e.write(ip(1), "x")
	if err := e.s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.s.Write(model.Message{Sender: ip(1), Raw: []byte("y")}); !errors.Is(err, ErrClosed) {
		t.Fatalf("write after close: %v", err)
	}
	if err := e.s.Maintain(); !errors.Is(err, ErrClosed) {
		t.Fatalf("maintain after close: %v", err)
	}
	if n := len(readLines(t, e.dir, "192.0.2.1")); n != 1 {
		t.Fatalf("close lost the buffer: %d lines", n)
	}
	e.s.Close() // idempotent
}

func TestClockStepBackIsRecorded(t *testing.T) {
	e := newEnv(t, nil)
	a := ip(1)
	e.write(a, "first")
	e.clock.Add(time.Minute)
	e.write(a, "a minute on")
	// Small steps back (interleaving, NTP slews) are within logfile.MaxSkew.
	e.clock.Add(-4 * time.Minute)
	e.write(a, "4 minutes back: tolerated")
	e.maintain()
	if evs := eventsOf(t, e.idx, index.KindClock); len(evs) != 0 {
		t.Fatalf("events for a small step: %+v", evs)
	}
	// A step of 7m12s past the high-water mark is a warning, once.
	e.clock.Add(4*time.Minute - 7*time.Minute - 12*time.Second)
	e.write(a, "stepped back")
	e.clock.Add(time.Second)
	e.write(a, "and on from there")
	e.maintain()
	evs := eventsOf(t, e.idx, index.KindClock)
	if len(evs) != 1 || evs[0].Level != index.LevelWarn || !strings.Contains(evs[0].Text, "stepped back 7m12s") ||
		!strings.Contains(evs[0].Text, "searches near this time may miss lines") {
		t.Fatalf("clock events %+v", evs)
	}
	// After a restart the high-water mark comes from the index, so a step back
	// while stopped is noticed too.
	e.clock.Add(time.Hour)
	e.write(a, "an hour on")
	e.maintain()
	e.reopen()
	e.clock.Add(-30 * time.Minute)
	e.write(a, "after a restart, 30 minutes back")
	e.maintain()
	if evs := eventsOf(t, e.idx, index.KindClock); len(evs) != 2 || !strings.Contains(evs[1].Text, "stepped back 30m") {
		t.Fatalf("after restart %+v", evs)
	}
}

func TestReserveRule(t *testing.T) {
	const GiB = 1 << 30
	cases := []struct {
		name  string
		total uint64
		want  uint64
	}{
		{"10 GB volume: the 1 GiB floor", 10e9, 1 * GiB},
		{"20 GiB volume: 5% equals the floor", 20 * GiB, 1 * GiB},
		{"100 GiB volume: 5%", 100 * GiB, 5 * GiB},
		{"200 GiB volume: 5% equals the cap", 200 * GiB, 10 * GiB},
		{"460 GB volume: capped", 460e9, 10 * GiB},
		{"4 TB volume: capped", 4e12, 10 * GiB},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, nil) // production defaults: 1 GiB floor, 5%, 10 GiB cap
			e.disk.total = c.total
			e.write(ip(1), "x")
			e.maintain()
			u := e.s.Usage()
			if u.ReserveBytes != c.want {
				t.Fatalf("reserve %d (%.2f GiB), want %d", u.ReserveBytes, float64(u.ReserveBytes)/GiB, c.want)
			}
			if e.s.Paused() {
				t.Fatal("paused with an empty disk")
			}
		})
	}
	// The owner's case: a 460 GB volume with 24 GB free. The old max(1 GiB, 5%) rule
	// reserved ~21.4 GiB and paused; the capped reserve keeps writing.
	e := newEnv(t, nil)
	e.disk.total = 460e9
	e.disk.setOther(460e9 - 24e9)
	e.write(ip(1), "x")
	e.maintain()
	if e.s.Paused() {
		t.Fatal("paused at 24 GB free on a 460 GB volume")
	}
	e.write(ip(1), "still writing")
	// Below the cap it pauses, and the event names the reserve it used.
	e.disk.setOther(460e9 - 9*GiB)
	e.maintain()
	if !e.s.Paused() {
		t.Fatal("not paused at 9 GiB free")
	}
	evs := eventsOf(t, e.idx, index.KindPause)
	if len(evs) != 1 || !strings.Contains(evs[0].Text, "reserve of 10.0 GiB (10737418240 bytes)") {
		t.Fatalf("pause events %+v", evs)
	}
	// A cap below the floor leaves the floor in charge.
	if got := reserveFor(4e12, 2*GiB, 5, 1*GiB); got != 2*GiB {
		t.Fatalf("floor over cap: %d", got)
	}
}
