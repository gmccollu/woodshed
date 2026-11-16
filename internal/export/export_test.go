package export

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

var bg = context.Background()

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

type msg struct {
	at  time.Time
	dev netip.Addr
	raw string
}

type env struct {
	t     *testing.T
	dir   string
	idx   *index.DB
	st    *store.Store
	clock *clock
	eng   *search.Engine
	msgs  []msg
	day0  time.Time
}

var (
	devA = netip.MustParseAddr("192.0.2.1")
	devB = netip.MustParseAddr("192.0.2.2")
	devC = netip.MustParseAddr("2001:db8::7")
)

func raw(i int) string {
	switch i % 9 {
	case 0:
		return fmt.Sprintf("<11>host app: multi\nline\r\nmessage %d", i)
	case 3:
		return fmt.Sprintf(`<14>host app: C:\new\temp \n literal %d`, i)
	case 2:
		return fmt.Sprintf("no pri at all %d", i)
	case 1:
		return fmt.Sprintf("<13>Ünïcode \xff\xfe bytes %d", i)
	case 6: // device A
		return fmt.Sprintf("<166>Nov 10 00:00:00 edge-fw-01 %%FW-6-302013: Built conn %d", i)
	case 7: // device B
		return fmt.Sprintf("<38>Nov 10 00:00:00 web-01 sshd[7]: Accepted publickey %d", i)
	}
	return fmt.Sprintf("<%d>Nov 10 00:00:00 host app[1]: conn opened tcp 203.0.113.%d seq=%06d", 128+i%8, i%250, i)
}

// newEnv writes perDay messages per device for two days, with small parts so
// the export reads compressed parts, day files and today's plain file.
func newEnv(t *testing.T, perDay int) *env {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	day0 := time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC)
	c := &clock{t: day0}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 32 << 10, Manual: true, Clock: c.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{t: t, dir: dir, idx: idx, st: st, clock: c, day0: day0}
	idx.AddEvent(bg, index.Event{Time: day0.Add(time.Millisecond), Level: index.LevelInfo, Kind: index.KindStart,
		Source: index.SourceService, Text: "Woodshed 1.0 (abc) started on test/test; data folder x."})
	i := 0
	for d := 0; d < 2; d++ {
		start := day0.Add(time.Duration(d) * 24 * time.Hour)
		c.Set(start.Add(time.Second))
		st.Maintain()
		step := 24 * time.Hour / time.Duration(perDay*3+2)
		at := start.Add(time.Second)
		for n := 0; n < perDay; n++ {
			for _, a := range []netip.Addr{devA, devB, devC} {
				at = at.Add(step)
				r := raw(i)
				i++
				if err := st.Write(model.Message{Received: at, Sender: a, Raw: []byte(r)}); err != nil {
					t.Fatal(err)
				}
				e.msgs = append(e.msgs, msg{at: at.Truncate(time.Millisecond), dev: a, raw: r})
			}
		}
		c.Set(at)
		st.Maintain()
	}
	st.Flush()
	st.Maintain()
	g := "HQ"
	idx.UpdateDevice(bg, model.DeviceID(devA), index.DeviceUpdate{Group: &g})
	idx.UpdateDevice(bg, model.DeviceID(devB), index.DeviceUpdate{Group: &g})
	e.eng = search.New(search.Options{DataDir: dir, Index: idx, Now: c.Now, Logger: quiet})
	return e
}

func (e *env) manager(opts ...func(*Options)) *Manager {
	o := Options{DataDir: e.dir, Index: e.idx, Search: e.eng, Version: "1.2.3", Now: e.clock.Now, Logger: quiet, janitor: time.Hour}
	for _, f := range opts {
		f(&o)
	}
	m, err := Open(o)
	if err != nil {
		e.t.Fatal(err)
	}
	m.Start()
	e.t.Cleanup(m.Close)
	return m
}

func wait(t *testing.T, m *Manager, id string, want State) Info {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		in, err := m.Get(id)
		if err == nil && in.State == want {
			return in
		}
		if err == nil && in.State == Failed && want != Failed {
			t.Fatalf("export failed: %s", in.Error)
		}
		if time.Now().After(deadline) {
			t.Fatalf("export %s: %+v %v, want %s", id, in, err, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// readZip opens a ready export and returns its files.
func readZip(t *testing.T, m *Manager, id string) (map[string][]byte, []string) {
	t.Helper()
	f, info, err := m.Download(id)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	if st.Size() != info.SizeBytes {
		t.Errorf("size_bytes %d, file %d", info.SizeBytes, st.Size())
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	var names []string
	for _, zf := range zr.File {
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", zf.Name, err) // includes the CRC check
		}
		out[zf.Name] = b
		names = append(names, zf.Name)
	}
	return out, names
}

// expected builds the export's log files from what was written.
func (e *env) expected(devs []netip.Addr, from, to time.Time, keep func(raw string) bool) map[string][]byte {
	out := map[string][]byte{}
	for _, d := range devs {
		for _, mm := range e.msgs {
			if mm.dev != d || mm.at.Before(from) || !mm.at.Before(to) || (keep != nil && !keep(mm.raw)) {
				continue
			}
			name := "logs/" + model.DeviceID(d) + "/" + logfile.DayOf(mm.at) + ".log"
			out[name] = logfile.AppendLine(out[name], mm.at, d, []byte(mm.raw)) // as stored, escaped
		}
	}
	return out
}

func checkExport(t *testing.T, files map[string][]byte, want map[string][]byte) Manifest {
	t.Helper()
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if _, ok := files["README.txt"]; !ok {
		t.Error("no README.txt")
	}
	if _, ok := files["woodshed-events.log"]; !ok {
		t.Error("no woodshed-events.log")
	}
	got := 0
	for name, b := range files {
		if !strings.HasPrefix(name, "logs/") {
			continue
		}
		got++
		if !bytes.Equal(b, want[name]) {
			t.Errorf("%s: %d bytes, want %d\n got %.300q\nwant %.300q", name, len(b), len(want[name]), b, want[name])
		}
	}
	if got != len(want) {
		t.Errorf("%d log files, want %d", got, len(want))
	}
	if len(man.Files) != len(want) {
		t.Errorf("manifest lists %d files, want %d", len(man.Files), len(want))
	}
	var lines int64
	for _, mf := range man.Files {
		sum := sha256.Sum256(files[mf.Path])
		if hex.EncodeToString(sum[:]) != mf.SHA256 {
			t.Errorf("%s: checksum mismatch", mf.Path)
		}
		if mf.Bytes != int64(len(files[mf.Path])) {
			t.Errorf("%s: bytes %d", mf.Path, mf.Bytes)
		}
		lines += mf.Lines
	}
	if lines != man.Lines {
		t.Errorf("manifest lines %d, files sum to %d", man.Lines, lines)
	}
	return man
}

func TestExportZipContents(t *testing.T) {
	e := newEnv(t, 400)
	m := e.manager()
	from, to := e.day0.Add(3*time.Hour), e.day0.Add(40*time.Hour)
	e.idx.AddEvent(bg, index.Event{Time: e.day0.Add(10 * time.Hour), Level: index.LevelWarn, Kind: index.KindClock,
		Text: "system clock stepped back 7m12s (received times went from a to b); searches near this time may miss lines"})
	in, err := m.Create(bg, Request{Devices: []string{"192.0.2.1", "2001_db8__7"}, From: from, To: to})
	if err != nil {
		t.Fatal(err)
	}
	if in.State != Queued || !ValidID(in.ID) {
		t.Fatalf("%+v", in)
	}
	in = wait(t, m, in.ID, Ready)
	if in.ReadyAt == nil || in.ExpiresAt == nil || in.ExpiresAt.Sub(*in.ReadyAt) != DefaultTTL || in.Progress != 1 {
		t.Errorf("ready entry %+v", in)
	}
	files, names := readZip(t, m, in.ID)
	want := e.expected([]netip.Addr{devA, devC}, from, to, nil)
	man := checkExport(t, files, want)
	if names[len(names)-1] != "manifest.json" {
		t.Errorf("entries %v", names)
	}
	if man.WoodshedVersion != "1.2.3" || !man.Request.From.Equal(from) || len(man.Request.Devices) != 2 ||
		man.Request.Devices[0].Group != "HQ" || man.Request.Devices[1].IP != "2001:db8::7" {
		t.Errorf("manifest %+v", man)
	}
	if in.Lines != man.Lines || man.Lines == 0 {
		t.Errorf("lines %d vs %d", in.Lines, man.Lines)
	}
	// One message per line, every line with its prefix; unescaping the message
	// gives back the raw bytes exactly, CR, LF and backslashes included.
	var raws []string
	for name, b := range files {
		if !strings.HasPrefix(name, "logs/") {
			continue
		}
		for _, ln := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
			l, err := logfile.ParseLine([]byte(ln))
			if err != nil {
				t.Fatalf("%s: line without the prefix: %q", name, ln)
			}
			raws = append(raws, string(logfile.Unescape(nil, l.Escaped)))
		}
	}
	wantRaw := map[string]bool{}
	for _, mm := range e.msgs {
		if (mm.dev == devA || mm.dev == devC) && !mm.at.Before(from) && mm.at.Before(to) {
			wantRaw[mm.raw] = true
		}
	}
	got := map[string]bool{}
	for _, r := range raws {
		got[r] = true
	}
	if len(raws) != len(wantRaw) || len(got) != len(wantRaw) {
		t.Fatalf("%d lines (%d distinct), want %d", len(raws), len(got), len(wantRaw))
	}
	for r := range wantRaw {
		if !got[r] {
			t.Fatalf("raw %q missing after unescaping", r)
		}
	}
	everything := ""
	for name, b := range files {
		if strings.HasPrefix(name, "logs/") {
			everything += string(b)
		}
	}
	if !strings.Contains(everything, `multi\nline\r\nmessage`) || !strings.Contains(everything, `C:\\new\\temp \\n literal`) {
		t.Error("CR, LF and backslash aren't escaped as stored")
	}
	if !strings.Contains(string(files["README.txt"]), `perl -pe`) {
		t.Error("README doesn't explain the escaping")
	}
	ev := string(files["woodshed-events.log"])
	if !strings.Contains(ev, "Z warn clock system clock stepped back 7m12s") {
		t.Errorf("clock warning missing from the events log")
	}
	if !strings.Contains(ev, " info rotate 192.0.2.1 closed ") {
		t.Errorf("events log:\n%.500s", ev)
	}
	if strings.Contains(ev, "started on test/test") {
		t.Error("an event before the range is in the events log")
	}
	if zipTool(t, m, in.ID) {
		t.Log("unzip -t: ok")
	}
	// The "ready" event is recorded after the state turns Ready (export.go: save,
	// unlock, then m.event), so wait for it.
	var kinds []string
	deadline := time.Now().Add(10 * time.Second)
	for {
		evs, _ := e.idx.Events(bg, time.Time{}, time.Time{}, 0)
		kinds = kinds[:0]
		for _, x := range evs {
			if x.Kind == index.KindExport {
				kinds = append(kinds, x.Text)
			}
		}
		if len(kinds) >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(kinds) != 2 || !strings.Contains(kinds[0], "queued") || !strings.Contains(kinds[1], "ready") {
		t.Errorf("export events %q", kinds)
	}
}

// zipTool checks the zip with Info-ZIP's unzip when it's installed.
func zipTool(t *testing.T, m *Manager, id string) bool {
	t.Helper()
	path, err := exec.LookPath("unzip")
	if err != nil {
		return false
	}
	out, err := exec.Command(path, "-t", m.zipPath(id)).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "No errors detected") {
		t.Errorf("unzip -t: %v\n%s", err, out)
	}
	return true
}

func TestExportFiltersMatchSearch(t *testing.T) {
	e := newEnv(t, 300)
	m := e.manager()
	from, to := e.day0, e.day0.Add(48*time.Hour)
	for _, r := range []Request{
		{Filters: Filters{Group: "HQ", Q: "CONN opened"}},
		{Filters: Filters{Ungrouped: true, Severities: hub.SeveritySet(0).With(3).With(model.Unknown)}},
		{Devices: []string{"192.0.2.2"}, Filters: Filters{Q: `^<1[34]>`, Regex: true, Case: true}},
		{Devices: []string{"192.0.2.1"}, Filters: Filters{Q: "multi\nline"}},
		{Devices: []string{"192.0.2.1"}, Filters: Filters{Severities: hub.SeverityNone}},
		{Filters: Filters{Group: "HQ", Apps: []string{"%fw-*", "SSHD"}}},
		{Devices: []string{"192.0.2.2"}, Filters: Filters{Hosts: []string{"WEB-01"}, Exclude: "7$", Regex: true}},
		{Filters: Filters{Ungrouped: true, Q: "TCP", Exclude: "203.0.113.1"}},
	} {
		r.From, r.To = from, to
		in, err := m.Create(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		in = wait(t, m, in.ID, Ready)
		files, _ := readZip(t, m, in.ID)
		// The same query as a search, oldest first.
		q := search.Query{Filter: search.Filter{Q: r.Q, Regex: r.Regex, Case: r.Case, Severities: r.Severities, From: from, To: to,
			Apps: r.Apps, Hosts: r.Hosts, Exclude: r.Exclude},
			Devices: r.Devices, Group: r.Group, Ungrouped: r.Ungrouped, Asc: true, Limit: search.MaxLimit}
		want := map[string][]byte{}
		var n int
		for {
			p, err := e.eng.Search(bg, q)
			if err != nil {
				t.Fatal(err)
			}
			// Asc results interleave devices by time; files are per device-day.
			for _, l := range p.Results {
				ip := netip.MustParseAddr(strings.ReplaceAll(l.DeviceID, "_", ":"))
				name := "logs/" + l.DeviceID + "/" + logfile.DayOf(l.Received) + ".log"
				want[name] = logfile.AppendLine(want[name], l.Received, ip, l.Raw)
				n++
			}
			if p.NextCursor == "" {
				break
			}
			q.Cursor = p.NextCursor
		}
		if n == 0 && r.Severities != hub.SeverityNone {
			t.Fatalf("%+v matches nothing", r)
		}
		man := checkExport(t, files, want)
		if man.Lines != int64(n) {
			t.Errorf("%+v: export has %d lines, search %d", r.Filters, man.Lines, n)
		}
		if got, _ := json.Marshal(man.Request.Filters.Severities); r.Severities == hub.SeverityNone && string(got) != `["none"]` {
			t.Errorf("severities echo %s", got)
		}
		if !reflect.DeepEqual(in.Filters, r.Filters) {
			t.Errorf("filters echo %+v, want %+v", in.Filters, r.Filters)
		}
	}
}

func TestExportZip64(t *testing.T) {
	e := newEnv(t, 300)
	m := e.manager(func(o *Options) { o.zip64Limit = 1000 })
	in, err := m.Create(bg, Request{Devices: []string{"192.0.2.1", "192.0.2.2"}, From: e.day0, To: e.day0.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	checkExport(t, files, e.expected([]netip.Addr{devA, devB}, e.day0, e.day0.Add(48*time.Hour), nil))
	b, _ := os.ReadFile(m.zipPath(in.ID))
	if !bytes.Contains(b, []byte{0x50, 0x4b, 0x06, 0x06}) || !bytes.Contains(b, []byte{0x50, 0x4b, 0x06, 0x07}) {
		t.Error("no zip64 end records")
	}
	zipTool(t, m, in.ID)
}

func TestExportCancelAndQueue(t *testing.T) {
	e := newEnv(t, 200)
	gate := make(chan struct{})
	var once sync.Once
	started := make(chan struct{})
	m := e.manager(func(o *Options) {
		o.testHookLine = func() {
			once.Do(func() { close(started) })
			<-gate
		}
	})
	r := Request{Devices: []string{"192.0.2.1"}, From: e.day0, To: e.day0.Add(48 * time.Hour)}
	a, _ := m.Create(bg, r)
	<-started
	b, _ := m.Create(bg, r)
	c, _ := m.Create(bg, r)
	if in, _ := m.Get(a.ID); in.State != Building {
		t.Fatalf("first: %s", in.State)
	}
	for _, id := range []string{b.ID, c.ID} {
		if in, _ := m.Get(id); in.State != Queued {
			t.Fatalf("second and third should queue: %s", in.State)
		}
	}
	if _, _, err := m.Download(a.ID); !errors.Is(err, ErrNotReady) {
		t.Errorf("download while building: %v", err)
	}
	list := m.List()
	if len(list) != 3 || list[0].ID != c.ID {
		t.Errorf("list order %v", list)
	}
	// Cancel the queued third, and the building first.
	if err := m.Delete(c.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(a.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("cancelled export still there: %v", err)
	}
	close(gate)
	wait(t, m, b.ID, Ready)
	des, _ := os.ReadDir(filepath.Join(e.dir, Dir))
	var left []string
	for _, d := range des {
		left = append(left, d.Name())
	}
	if len(left) != 2 || !strings.HasPrefix(left[0], b.ID) || !strings.HasPrefix(left[1], b.ID) {
		t.Errorf("files left %v", left)
	}
	if err := m.Delete(b.ID); err != nil {
		t.Fatal(err)
	}
	if des, _ := os.ReadDir(filepath.Join(e.dir, Dir)); len(des) != 0 {
		t.Errorf("files left after delete: %d", len(des))
	}
	if err := m.Delete(b.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete: %v", err)
	}
}

func TestExportExpiryAndRestart(t *testing.T) {
	e := newEnv(t, 100)
	m := e.manager()
	e.clock.Set(e.day0.Add(48 * time.Hour))
	in, _ := m.Create(bg, Request{Devices: []string{"192.0.2.1"}, From: e.day0, To: e.day0.Add(48 * time.Hour)})
	in = wait(t, m, in.ID, Ready)

	// A restart keeps the ready export; an interrupted one becomes failed.
	m.Close()
	broken := Info{ID: "exp_00000000000000aa", Created: e.clock.Now(), State: Building, Devices: []string{"192.0.2.1"}}
	bb, _ := json.Marshal(broken)
	os.WriteFile(filepath.Join(e.dir, Dir, broken.ID+".json"), bb, 0o640)
	os.WriteFile(filepath.Join(e.dir, Dir, broken.ID+".zip.tmp"), []byte("half"), 0o640)
	m = e.manager()
	if got, err := m.Get(in.ID); err != nil || got.State != Ready {
		t.Fatalf("after restart: %+v %v", got, err)
	}
	if got, _ := m.Get(broken.ID); got.State != Failed || !strings.Contains(got.Error, "stopped") {
		t.Errorf("interrupted export: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(e.dir, Dir, broken.ID+".zip.tmp")); err == nil {
		t.Error("temp file left")
	}

	e.clock.Set(in.ExpiresAt.Add(-time.Second))
	m.expire()
	if got, _ := m.Get(in.ID); got.State != Ready {
		t.Fatalf("expired early: %s", got.State)
	}
	e.clock.Set(*in.ExpiresAt)
	m.expire()
	if got, _ := m.Get(in.ID); got.State != Expired {
		t.Fatalf("not expired: %s", got.State)
	}
	if _, _, err := m.Download(in.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("download after expiry: %v", err)
	}
	if _, err := os.Stat(m.zipPath(in.ID)); err == nil {
		t.Error("zip still there")
	}
	e.clock.Set(in.ExpiresAt.Add(DefaultKeep + time.Minute))
	m.expire()
	if _, err := m.Get(in.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired entry kept forever: %v", err)
	}
}

func TestExportReclaim(t *testing.T) {
	e := newEnv(t, 100)
	m := e.manager()
	var ids []string
	for i := 0; i < 3; i++ {
		e.clock.Set(e.day0.Add(48*time.Hour + time.Duration(i)*time.Minute))
		in, _ := m.Create(bg, Request{Devices: []string{"192.0.2.1"}, From: e.day0, To: e.day0.Add(48 * time.Hour)})
		wait(t, m, in.ID, Ready)
		ids = append(ids, in.ID)
	}
	st, _ := os.Stat(m.zipPath(ids[0]))
	freed := m.Reclaim(uint64(st.Size()))
	if freed != uint64(st.Size()) {
		t.Errorf("freed %d, want %d", freed, st.Size())
	}
	if in, _ := m.Get(ids[0]); in.State != Expired {
		t.Errorf("oldest export: %s", in.State)
	}
	for _, id := range ids[1:] {
		if in, _ := m.Get(id); in.State != Ready {
			t.Errorf("newer export: %s", in.State)
		}
	}
	if freed := m.Reclaim(1 << 40); freed == 0 {
		t.Error("nothing freed")
	}
	for _, id := range ids {
		if _, err := os.Stat(m.zipPath(id)); err == nil {
			t.Errorf("%s still on disk", id)
		}
	}
}

func TestExportValidation(t *testing.T) {
	e := newEnv(t, 10)
	m := e.manager()
	var re *RequestError
	for name, r := range map[string]Request{
		"no devices":    {From: e.day0, To: e.day0.Add(time.Hour)},
		"no range":      {Devices: []string{"192.0.2.1"}},
		"backwards":     {Devices: []string{"192.0.2.1"}, From: e.day0.Add(time.Hour), To: e.day0},
		"bad regex":     {Devices: []string{"192.0.2.1"}, From: e.day0, To: e.day0.Add(time.Hour), Filters: Filters{Q: "(", Regex: true}},
		"no match":      {From: e.day0, To: e.day0.Add(time.Hour), Filters: Filters{Group: "nope"}},
		"group and ug":  {From: e.day0, To: e.day0.Add(time.Hour), Filters: Filters{Group: "HQ", Ungrouped: true}},
		"all and named": {AllDevices: true, Devices: []string{"192.0.2.1"}, From: e.day0, To: e.day0.Add(time.Hour)},
	} {
		if _, err := m.Create(bg, r); !errors.As(err, &re) {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := m.Estimate(bg, r); !errors.As(err, &re) {
			t.Errorf("%s (estimate): %v", name, err)
		}
	}
}

func TestEstimateIsAnUpperBound(t *testing.T) {
	e := newEnv(t, 400)
	m := e.manager()
	for _, r := range []Request{
		{Devices: []string{"192.0.2.1"}, From: e.day0, To: e.day0.Add(48 * time.Hour)},
		{Filters: Filters{Group: "HQ"}, From: e.day0.Add(5 * time.Hour), To: e.day0.Add(30 * time.Hour)},
	} {
		est, err := m.Estimate(bg, r)
		if err != nil {
			t.Fatal(err)
		}
		in, _ := m.Create(bg, r)
		in = wait(t, m, in.ID, Ready)
		files, _ := readZip(t, m, in.ID)
		var bytes int64
		n := 0
		for name, b := range files {
			if strings.HasPrefix(name, "logs/") {
				bytes += int64(len(b))
				n++
			}
		}
		if est.Lines < in.Lines || est.Bytes < bytes || est.Files < 1 || est.Lines == 0 {
			t.Errorf("estimate %+v below the export (%d lines, %d bytes, %d files)", est, in.Lines, bytes, n)
		}
		t.Logf("estimate %d lines / %d bytes; export %d lines / %d bytes", est.Lines, est.Bytes, in.Lines, bytes)
	}
}

func TestExportAllDevices(t *testing.T) {
	e := newEnv(t, 50)
	yes := true
	e.idx.UpdateDevice(bg, model.DeviceID(devC), index.DeviceUpdate{Hidden: &yes})
	m := e.manager()
	in, err := m.Create(bg, Request{AllDevices: true, From: e.day0, To: e.day0.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(in.Devices, ",") != "192.0.2.1,192.0.2.2" {
		t.Errorf("devices %v (hidden ones only when named)", in.Devices)
	}
	est, err := m.Estimate(bg, Request{AllDevices: true, From: e.day0, To: e.day0.Add(48 * time.Hour)})
	if err != nil || est.Lines == 0 {
		t.Errorf("estimate %+v %v", est, err)
	}
	wait(t, m, in.ID, Ready)
}

// TestExportAppHostExclude checks the program/tag, host and exclude filters
// against the messages as written (not through search), over plain and
// compressed files, and that the manifest and README record them.
func TestExportAppHostExclude(t *testing.T) {
	e := newEnv(t, 300)
	m := e.manager()
	from, to := e.day0, e.day0.Add(48*time.Hour)
	r := Request{Devices: []string{"192.0.2.1", "192.0.2.2"}, From: from, To: to,
		Filters: Filters{Apps: []string{"fw-6-*", "sshd"}, Hosts: []string{"EDGE-FW-01", "web-01"}, Exclude: `[05]$`, Regex: true}}
	in, err := m.Create(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	ex := regexp.MustCompile(`(?i)[05]$`)
	want := e.expected([]netip.Addr{devA, devB}, from, to, func(raw string) bool {
		return (strings.Contains(raw, " edge-fw-01 %FW-6-") || strings.Contains(raw, " web-01 sshd[")) && !ex.MatchString(raw)
	})
	man := checkExport(t, files, want)
	if man.Lines == 0 {
		t.Fatal("the filters matched nothing; the test tests nothing")
	}
	// Both days: day 0's files are compressed by now, day 1 has the plain active file.
	for _, day := range []string{logfile.DayOf(from), logfile.DayOf(from.Add(24 * time.Hour))} {
		if _, ok := files["logs/192.0.2.2/"+day+".log"]; !ok {
			t.Errorf("no file for %s", day)
		}
	}
	f := man.Request.Filters
	if !reflect.DeepEqual(f.App, []string{"fw-6-*", "sshd"}) || !reflect.DeepEqual(f.Host, []string{"EDGE-FW-01", "web-01"}) || f.Exclude != `[05]$` || !f.Regex {
		t.Errorf("manifest filters %+v", f)
	}
	readme := string(files["README.txt"])
	for _, s := range []string{"Program/tag: fw-6-*, sshd", "Host: EDGE-FW-01, web-01", `Exclude: "[05]$" (regular expression, any case)`} {
		if !strings.Contains(readme, s) {
			t.Errorf("README doesn't say %q:\n%.600s", s, readme)
		}
	}
	// An export without filters says so, and its manifest lists empty filters.
	in, err = m.Create(bg, Request{Devices: []string{"192.0.2.1"}, From: from, To: from.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ = readZip(t, m, in.ID)
	if !strings.Contains(string(files["README.txt"]), "Filters: none") {
		t.Error("README of an unfiltered export")
	}
	if !strings.Contains(string(files["manifest.json"]), `"app": [],`) {
		t.Errorf("manifest of an unfiltered export: %s", files["manifest.json"])
	}
	// An invalid exclude regex is refused, like q.
	_, err = m.Create(bg, Request{Devices: []string{"192.0.2.1"}, From: from, To: to, Filters: Filters{Exclude: "a(", Regex: true}})
	var re *RequestError
	if !errors.As(err, &re) || !strings.HasPrefix(re.Msg, "exclude: ") {
		t.Errorf("invalid exclude: %v", err)
	}
}
