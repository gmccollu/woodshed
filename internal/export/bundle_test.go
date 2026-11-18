package export

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The incident bundle (SPEC §11.3, §11.6): a fixture with syslog and traps
// across midnight UTC (yesterday's day compressed, today's plain), a gap in
// the events log, a coldStart trap, drops and a truncated message.

var update = flag.Bool("update", false, "rewrite the golden files in testdata/")

func trapRec(t testing.TB, id int64, trap string) []byte {
	t.Helper()
	o, err := snmp.ParseOID(trap)
	if err != nil {
		t.Fatal(err)
	}
	seq, _ := snmp.ParseOID("1.3.6.1.4.1.32473.1.1.1.0")
	vbs := []snmp.Varbind{
		{OID: snmp.OIDSysUpTime, Value: snmp.Value{Kind: snmp.KindTimeTicks, Uint: 100}},
		{OID: snmp.OIDSnmpTrapOID, Value: snmp.Value{Kind: snmp.KindOID, OID: o}},
		{OID: seq, Value: snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(fmt.Sprintf("seq=fixture:%d", id))}},
	}
	raw := snmp.EncodeCommunity(snmp.V2c, []byte("s3cret-community"), snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUTrap, RequestID: id, Varbinds: vbs}))
	return snmp.FormatRecord(nil, snmp.Decode(raw, nil, time.Now()), snmp.RecordOptions{Names: snmp.BuiltinMIBs()})
}

const (
	oidLinkDown  = "1.3.6.1.6.3.1.1.5.3"
	oidLinkUp    = "1.3.6.1.6.3.1.1.5.4"
	oidColdStart = "1.3.6.1.6.3.1.1.5.1"
)

// rec is one stored record of the fixture.
type rec struct {
	at  time.Time
	dev netip.Addr
	typ string
	raw []byte
	fl  logfile.Flags // the line's marker
}

type bundleEnv struct {
	*env
	recs []rec
	at   time.Time // the moment: 2026-11-14 00:05:00 UTC
	now  time.Time
}

var (
	devH = netip.MustParseAddr("192.0.2.9")   // hidden, active in the window
	devQ = netip.MustParseAddr("192.0.2.200") // quiet: only before the window
)

// newBundleEnv writes the fixture through a real store. The window around
// at (30 min before, 10 after) is [2026-11-13 23:35, 2026-11-14 00:15).
//   - A (edge-fw-01, group HQ): syslog every 20 s from 23:00 to 00:30 with
//     severities cycling crit, err, warning, notice, info; traps linkDown,
//     linkUp at 23:50:00 and :10, coldStart at 23:50:58.250, linkDown at 00:40.
//   - B (ungrouped): syslog every 30 s, one truncated message at 23:55.
//   - Q: syslog only before 23:20; H: hidden, syslog in the window.
//   - Woodshed stopped at 23:40:00 and started again at 23:42:30: nothing is
//     written in between.
//   - Drops: A 4 at 23:45, B 2 at 00:20 (outside), A 9 at 23:34 (outside).
func newBundleEnv(t *testing.T) *bundleEnv {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	day0 := time.Date(2026, 11, 13, 22, 0, 0, 0, time.UTC)
	c := &clock{t: day0}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 16 << 10, Manual: true, Clock: c.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	be := &bundleEnv{env: &env{t: t, dir: dir, idx: idx, st: st, clock: c, day0: day0},
		at: time.Date(2026, 11, 14, 0, 5, 0, 0, time.UTC)}
	ev := func(at time.Time, kind index.Kind, src index.Source, text string) {
		if err := idx.AddEvent(bg, index.Event{Time: at, Level: index.LevelInfo, Kind: kind, Source: src, Text: text}); err != nil {
			t.Fatal(err)
		}
	}
	ev(day0, index.KindStart, index.SourceService, "Woodshed 1.2 (abc) started on test/test; data folder x.")
	stopAt, startAt := time.Date(2026, 11, 13, 23, 40, 0, 0, time.UTC), time.Date(2026, 11, 13, 23, 42, 30, 0, time.UTC)
	ev(stopAt, index.KindStop, index.SourceService, "Woodshed stopping.")
	ev(startAt, index.KindStart, index.SourceService, "Woodshed 1.2 (abc) started on test/test; data folder x.")

	sevs := []int{2, 3, 4, 5, 6}
	write := func(at time.Time, dev netip.Addr, typ string, raw []byte, truncated bool) {
		t.Helper()
		if !at.Before(stopAt) && at.Before(startAt) {
			return // Woodshed wasn't running
		}
		c.Set(at)
		m := model.Message{Received: at, Sender: dev, Raw: raw, Truncated: truncated}
		var err error
		if typ == datatype.Syslog {
			err = st.Write(m)
		} else {
			err = st.WriteType(typ, m)
		}
		if err != nil {
			t.Fatal(err)
		}
		be.recs = append(be.recs, rec{at: at.Truncate(time.Millisecond), dev: dev, typ: typ, raw: raw, fl: logfile.Flags{Truncated: truncated}})
	}
	type item struct {
		at        time.Time
		dev       netip.Addr
		typ       string
		raw       []byte
		truncated bool
	}
	var items []item
	start := time.Date(2026, 11, 13, 23, 0, 0, 14e6, time.UTC)
	for i := 0; ; i++ {
		at := start.Add(time.Duration(i) * 20 * time.Second)
		if !at.Before(time.Date(2026, 11, 14, 0, 30, 0, 0, time.UTC)) {
			break
		}
		items = append(items, item{at: at, dev: devA, typ: datatype.Syslog,
			raw: []byte(fmt.Sprintf("<%d>Nov 13 23:00:00 edge-fw-01 app[1]: event %d", 8+sevs[i%len(sevs)], i))})
	}
	for i := 0; ; i++ {
		at := start.Add(5*time.Second + time.Duration(i)*30*time.Second)
		if !at.Before(time.Date(2026, 11, 14, 0, 30, 0, 0, time.UTC)) {
			break
		}
		r := fmt.Sprintf("<13>web-01 sshd: session %d", i)
		if i%7 == 3 {
			r = fmt.Sprintf("no PRI here %d", i)
		}
		items = append(items, item{at: at, dev: devB, typ: datatype.Syslog, raw: []byte(r)})
	}
	items = append(items,
		item{at: time.Date(2026, 11, 13, 23, 55, 0, 500e6, time.UTC), dev: devB, typ: datatype.Syslog, raw: []byte("<11>web-01 app: cut off"), truncated: true},
		item{at: time.Date(2026, 11, 13, 23, 50, 0, 0, time.UTC), dev: devA, typ: datatype.Trap, raw: trapRec(t, 1, oidLinkDown)},
		item{at: time.Date(2026, 11, 13, 23, 50, 10, 0, time.UTC), dev: devA, typ: datatype.Trap, raw: trapRec(t, 2, oidLinkUp)},
		item{at: time.Date(2026, 11, 13, 23, 50, 58, 250e6, time.UTC), dev: devA, typ: datatype.Trap, raw: trapRec(t, 3, oidColdStart)},
		item{at: time.Date(2026, 11, 14, 0, 40, 0, 0, time.UTC), dev: devA, typ: datatype.Trap, raw: trapRec(t, 4, oidLinkDown)},
		item{at: time.Date(2026, 11, 13, 23, 10, 0, 0, time.UTC), dev: devQ, typ: datatype.Syslog, raw: []byte("<14>quiet: before")},
		item{at: time.Date(2026, 11, 13, 23, 15, 0, 0, time.UTC), dev: devQ, typ: datatype.Syslog, raw: []byte("<14>quiet: before 2")},
		item{at: time.Date(2026, 11, 14, 0, 1, 0, 0, time.UTC), dev: devH, typ: datatype.Syslog, raw: []byte("<14>hidden: in the window")},
	)
	sort.SliceStable(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })
	midnight := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	maintained := false
	for n, it := range items {
		if !maintained && !it.at.Before(midnight) {
			st.Flush()
			c.Set(midnight.Add(time.Second))
			st.Maintain() // closes and compresses yesterday's files
			maintained = true
		}
		write(it.at, it.dev, it.typ, it.raw, it.truncated)
		if n%40 == 0 {
			st.Maintain()
		}
	}
	st.Flush()
	be.now = time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC)
	c.Set(be.now)
	st.Maintain()
	st.Flush()

	if err := idx.Apply(bg, index.Batch{Activity: []index.Activity{
		{DeviceID: model.DeviceID(devA), IP: devA.String(), Minute: time.Date(2026, 11, 13, 23, 45, 0, 0, time.UTC), Counts: index.Counts{Dropped: 4}},
		{DeviceID: model.DeviceID(devB), IP: devB.String(), Minute: time.Date(2026, 11, 14, 0, 20, 0, 0, time.UTC), Counts: index.Counts{Dropped: 2}},
		{DeviceID: model.DeviceID(devA), IP: devA.String(), Minute: time.Date(2026, 11, 13, 23, 34, 0, 0, time.UTC), Counts: index.Counts{Dropped: 9}},
	}}); err != nil {
		t.Fatal(err)
	}
	name, g, hidden := "edge-fw-01", "HQ", true
	idx.UpdateDevice(bg, model.DeviceID(devA), index.DeviceUpdate{Name: &name, Group: &g})
	idx.UpdateDevice(bg, model.DeviceID(devH), index.DeviceUpdate{Hidden: &hidden})
	be.eng = search.New(search.Options{DataDir: dir, Index: idx, Now: c.Now, Logger: quiet})

	// The fixture must have both a compressed and a plain day of each type.
	files, _ := idx.Files(bg, model.DeviceID(devA))
	var gz, plain int
	for _, f := range files {
		if f.Compressed {
			gz++
		} else {
			plain++
		}
	}
	if gz == 0 || plain == 0 {
		t.Fatalf("fixture: %d compressed and %d plain files", gz, plain)
	}
	return be
}

var est = time.FixedZone("EST", -5*3600)

func (be *bundleEnv) bundleManager() *Manager {
	return be.manager(func(o *Options) { o.Location = est })
}

func (be *bundleEnv) bundleRequest() Request {
	at := be.at
	return Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute, ActiveDevices: true}}
}

// expectedFiles is the bundle's record files from what was written.
func (be *bundleEnv) expectedFiles(devs []netip.Addr, from, to time.Time) map[string][]byte {
	out := map[string][]byte{}
	for _, r := range be.recs {
		keep := false
		for _, d := range devs {
			keep = keep || d == r.dev
		}
		if !keep || r.at.Before(from) || !r.at.Before(to) {
			continue
		}
		name := FolderOf(r.typ) + "/" + model.DeviceID(r.dev) + "/" + logfile.DayOf(r.at) + ".log"
		out[name] = logfile.AppendLineFlags(out[name], r.at, r.dev, r.raw, r.fl)
	}
	return out
}

func unzipFile(t *testing.T, path string) (map[string][]byte, []string) {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
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
			t.Fatalf("%s: %v", zf.Name, err)
		}
		out[zf.Name] = b
		names = append(names, zf.Name)
	}
	return out, names
}

// checkGolden compares got with testdata/name (or writes it with -update).
// The losses note depends on the OS, so it's replaced first.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	got = bytes.ReplaceAll(got, []byte(lossNote()), []byte("<loss note>"))
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from the golden file (run with -update after checking):\n--- got\n%s\n--- want\n%s", name, got, want)
	}
}

// normalizedManifest is manifest.json without what differs between builds
// (the ID and the build time).
func normalizedManifest(t *testing.T, b []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	m["id"], m["exported_at"] = "<id>", "<exported_at>"
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func TestBundleGolden(t *testing.T) {
	be := newBundleEnv(t)
	m := be.bundleManager()
	in, err := m.Create(bg, be.bundleRequest())
	if err != nil {
		t.Fatal(err)
	}
	from, to := time.Date(2026, 11, 13, 23, 35, 0, 0, time.UTC), time.Date(2026, 11, 14, 0, 15, 0, 0, time.UTC)
	if !in.From.Equal(from) || !in.To.Equal(to) || strings.Join(in.Devices, ",") != "192.0.2.1,192.0.2.2" ||
		strings.Join(in.Filters.Types, ",") != "syslog,trap" {
		t.Fatalf("resolved %v to %v, devices %v, types %v", in.From, in.To, in.Devices, in.Filters.Types)
	}
	in = wait(t, m, in.ID, Ready)
	files, names := readZip(t, m, in.ID)

	// Every record in the window, from the active, non-hidden devices, once.
	want := be.expectedFiles([]netip.Addr{devA, devB}, from, to)
	var got []string
	for _, n := range names {
		if strings.HasPrefix(n, "logs/") || strings.HasPrefix(n, "traps/") {
			got = append(got, n)
			if !bytes.Equal(files[n], want[n]) {
				t.Errorf("%s: %d bytes, want %d", n, len(files[n]), len(want[n]))
			}
		}
	}
	if len(got) != len(want) {
		t.Errorf("record files %v, want %d", got, len(want))
	}
	// Both days of A's syslog, one of them read from a .gz.
	for _, n := range []string{"logs/192.0.2.1/2026-11-13.log", "logs/192.0.2.1/2026-11-14.log", "traps/192.0.2.1/2026-11-13.log"} {
		if _, ok := files[n]; !ok {
			t.Errorf("no %s", n)
		}
	}
	// Each file's SHA-256 and lines match the manifest, and every file is listed.
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if len(man.Files) != len(want) {
		t.Errorf("manifest lists %d files, want %d", len(man.Files), len(want))
	}
	for _, mf := range man.Files {
		sum := sha256.Sum256(files[mf.Path])
		if hex.EncodeToString(sum[:]) != mf.SHA256 || mf.Lines != int64(bytes.Count(files[mf.Path], []byte("\n"))) {
			t.Errorf("%s: checksum or lines differ from the manifest", mf.Path)
		}
	}
	if man.Kind != KindBundle || man.Before != "30m" || man.After != "10m" || man.At == nil || !man.At.Equal(be.at) ||
		man.Folders["traps"] != "trap" || man.Folders["logs"] != "syslog" || !man.Request.Filters.ActiveDevices {
		t.Errorf("manifest header %+v", man)
	}
	if len(man.Gaps) != 1 || man.Gaps[0].Kind != GapNotRunning || !man.Gaps[0].From.Equal(time.Date(2026, 11, 13, 23, 40, 0, 0, time.UTC)) {
		t.Errorf("gaps %+v", man.Gaps)
	}
	// A community appears nowhere in the zip.
	for n, b := range files {
		if bytes.Contains(b, []byte("s3cret-community")) {
			t.Errorf("%s holds the community", n)
		}
	}
	// The summary's counts are the zip's.
	sa := man.Summary[0]
	if sa.DeviceID != "192.0.2.1" || sa.Name != "edge-fw-01" || sa.Dropped != 4 || len(sa.Reboots) != 1 ||
		sa.Reboots[0].Source != "coldStart trap" || sa.Types["trap"].Lines != 3 || sa.Types["trap"].Key != "by_trap" {
		t.Errorf("summary A %+v", sa)
	}
	var nA int64
	for _, mf := range man.Files {
		if mf.DeviceID == "192.0.2.1" && strings.HasPrefix(mf.Path, "logs/") {
			nA += mf.Lines
		}
	}
	if sa.Types["syslog"].Lines != nA {
		t.Errorf("A syslog %d, files %d", sa.Types["syslog"].Lines, nA)
	}
	if sb := man.Summary[1]; sb.Truncated != 1 || sb.Dropped != 0 || len(sb.Reboots) != 0 || sb.Types["trap"].Lines != 0 {
		t.Errorf("summary B %+v", sb)
	}

	checkGolden(t, "bundle_readme.golden", files["README.txt"])
	checkGolden(t, "bundle_manifest.golden", normalizedManifest(t, files["manifest.json"]))

	// The entry echoes the bundle.
	if in.Filters.Kind != KindBundle || in.Filters.Before != 30*time.Minute || !in.Filters.ActiveDevices {
		t.Errorf("entry %+v", in.Filters)
	}
}

// TestBundleOfflineMatchesQueue: Prepare and Plan.Write (woodshed bundle)
// write the zip the queue writes, apart from the ID and the build time.
func TestBundleOfflineMatchesQueue(t *testing.T) {
	be := newBundleEnv(t)
	m := be.bundleManager()
	in, err := m.Create(bg, be.bundleRequest())
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	qfiles, qnames := readZip(t, m, in.ID)

	ro, err := index.OpenReadOnly(filepath.Join(be.dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	eng := search.New(search.Options{DataDir: be.dir, Index: ro, Now: be.clock.Now, Logger: quiet})
	p, err := Prepare(bg, Options{Index: ro, Search: eng, Version: "1.2.3", Now: be.clock.Now, Location: est}, be.bundleRequest())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "b.zip")
	f, err := os.OpenFile(out, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	res, err := p.Write(bg, f, nil)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	ofiles, onames := unzipFile(t, out)
	if strings.Join(qnames, "\n") != strings.Join(onames, "\n") {
		t.Fatalf("entries differ:\n%v\n%v", qnames, onames)
	}
	for _, n := range qnames {
		a, b := qfiles[n], ofiles[n]
		if n == "manifest.json" {
			a, b = normalizedManifest(t, a), normalizedManifest(t, b)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs", n)
		}
	}
	if st, _ := os.Stat(out); res.Size != st.Size() || res.Lines != in.Lines || len(res.Summary) != 2 {
		t.Errorf("result %+v", res)
	}
}

func TestBundleRequests(t *testing.T) {
	be := newBundleEnv(t)
	m := be.bundleManager()
	at := be.at
	base := func(f func(*Request)) Request {
		r := be.bundleRequest()
		f(&r)
		return r
	}
	future := be.now.Add(time.Second)
	for _, c := range []struct {
		name string
		r    Request
		msg  string
	}{
		{"no at", base(func(r *Request) { r.At = nil }), "at is required"},
		{"future", base(func(r *Request) { r.At = &future }), "is in the future"},
		{"both zero", base(func(r *Request) { r.Before, r.After = 0, 0 }), "can't both be 0s"},
		{"too long", base(func(r *Request) { r.Before = MaxSpan + time.Millisecond }), "before must be from 0s to 7d"},
		{"negative", base(func(r *Request) { r.After = -time.Second }), "after must be from 0s to 7d"},
		{"no devices", base(func(r *Request) { r.ActiveDevices = false }), "Pick the devices"},
		{"two picks", base(func(r *Request) { r.Group = "HQ" }), "alternatives"},
		{"all devices", base(func(r *Request) { r.AllDevices = true }), "all_devices"},
		{"exclude", base(func(r *Request) { r.ExcludeDevices = []string{"192.0.2.1"} }), "exclude_devices"},
		{"filter", base(func(r *Request) { r.Q = "x" }), "takes no filters"},
		{"type", base(func(r *Request) { r.Types = []string{"sflow"} }), "unknown data type"},
		{"empty window", base(func(r *Request) {
			now := be.now
			r.At, r.Before, r.After = &now, 0, time.Minute
		}), "is empty"},
		{"nothing active", base(func(r *Request) {
			early := time.Date(2026, 11, 13, 21, 0, 0, 0, time.UTC)
			r.At = &early
		}), "No device stored anything between"},
		{"nothing active of a type", base(func(r *Request) {
			r.Before, r.After, r.Types = time.Minute, time.Minute, []string{"trap"}
		}), "No device stored SNMP traps between"},
	} {
		_, err := m.Create(bg, c.r)
		var re *RequestError
		if !errors.As(err, &re) || !strings.Contains(re.Msg, c.msg) {
			t.Errorf("%s: %v, want %q", c.name, err, c.msg)
		}
		if c.name == "nothing active" && !re.Empty {
			t.Errorf("nothing active isn't Empty")
		}
	}

	// Named devices: hidden ones too, silent ones too; types from the data.
	in, err := m.Create(bg, Request{Devices: []string{"192.0.2.9", "192.0.2.200"},
		Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(in.Devices, ",") != "192.0.2.200,192.0.2.9" || strings.Join(in.Filters.Types, ",") != "syslog" {
		t.Errorf("named %v %v", in.Devices, in.Filters.Types)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	readme := string(files["README.txt"])
	for _, s := range []string{"Devices: 2, chosen by name. Types: syslog.\n", "192.0.2.200\n  Syslog       none\n",
		"192.0.2.9, hidden\n  Syslog       1 message, first 2026-11-14 00:01:00.000", "Reboots      not known (no SNMP traps or polls in this bundle)"} {
		if !strings.Contains(readme, s) {
			t.Errorf("README lacks %q:\n%s", s, readme)
		}
	}
	if strings.Contains(readme, "traps/<device>") || strings.Contains(readme, "Communities") {
		t.Errorf("a syslog-only bundle explains traps:\n%s", readme)
	}

	// A group, and traps only: an empty device gets "none" lines.
	in, err = m.Create(bg, Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute,
		Group: "HQ", Types: []string{"trap"}}})
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ = readZip(t, m, in.ID)
	readme = string(files["README.txt"])
	if !strings.Contains(readme, "Devices: 1, the group HQ. Types: SNMP traps.\n") ||
		!strings.Contains(readme, "  SNMP traps   3: linkDown 1, linkUp 1, coldStart 1; first 2026-11-13 23:50:00.000, last 2026-11-13 23:50:58.250\n") ||
		strings.Contains(readme, "logs/<device>") {
		t.Errorf("group README:\n%s", readme)
	}
	for n := range files {
		if strings.HasPrefix(n, "logs/") {
			t.Errorf("a trap bundle has %s", n)
		}
	}

	// A bundle around now is cut at now, and says so; the estimate is an
	// upper bound on what it writes.
	late := be.now.Add(-5 * time.Minute)
	r := Request{Filters: Filters{Kind: KindBundle, At: &late, Before: 2 * time.Hour, After: time.Hour, ActiveDevices: true}}
	e, err := m.Estimate(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	in, err = m.Create(bg, r)
	if err != nil {
		t.Fatal(err)
	}
	if !in.To.Equal(be.now) {
		t.Errorf("to %v, want now %v", in.To, be.now)
	}
	in = wait(t, m, in.ID, Ready)
	files, _ = readZip(t, m, in.ID)
	if !strings.Contains(string(files["README.txt"]), "Window: 2026-11-13 22:55:00 to 2026-11-14 01:00:00 UTC, cut at the time it was built (local time UTC-05:00)\n") {
		t.Errorf("cut README:\n%s", files["README.txt"])
	}
	if e.Lines < in.Lines || e.Lines == 0 {
		t.Errorf("estimate %d lines, built %d", e.Lines, in.Lines)
	}
}

func TestSpans(t *testing.T) {
	for in, want := range map[string]time.Duration{"0": 0, "0s": 0, "30m": 30 * time.Minute, "1h30m": 90 * time.Minute, "7d": MaxSpan,
		"1.5h": 90 * time.Minute, "250ms": 250 * time.Millisecond, " 15M ": 15 * time.Minute, "1d2h": 26 * time.Hour} {
		got, err := ParseSpan(in)
		if err != nil || got != want {
			t.Errorf("ParseSpan(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "m", "30", "5x", "-5m", "1h-5m", "1e3s"} {
		if _, err := ParseSpan(in); err == nil {
			t.Errorf("ParseSpan(%q) took it", in)
		}
	}
	for d, want := range map[time.Duration]string{0: "0s", 30 * time.Minute: "30m", 90 * time.Minute: "1h30m", MaxSpan: "7d",
		26*time.Hour + time.Second + 500*time.Millisecond: "1d2h1s500ms"} {
		if got := FormatSpan(d); got != want {
			t.Errorf("FormatSpan(%v) = %q, want %q", d, got, want)
		}
		if back, _ := ParseSpan(FormatSpan(d)); back != d {
			t.Errorf("round trip %v → %v", d, back)
		}
	}
	for d, want := range map[time.Duration]string{0: "nothing", 30 * time.Minute: "30 min", time.Hour: "1 h", 90 * time.Minute: "1 h 30 min",
		MaxSpan: "7 days", 24 * time.Hour: "1 day", 45 * time.Second: "45 s"} {
		if got := humanSpan(d); got != want {
			t.Errorf("humanSpan(%v) = %q, want %q", d, got, want)
		}
	}
	if got := BundleFileName("edge host/1", time.Date(2026, 11, 14, 9, 42, 0, 0, time.UTC)); got != "woodshed-bundle-edge_host_1-20261114T094200Z.zip" {
		t.Errorf("file name %q", got)
	}
}
