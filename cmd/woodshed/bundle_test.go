package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
	_ "time/tzdata" // America/New_York on every OS, for the DST case

	"github.com/gmccollu/woodshed/internal/export"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// `woodshed bundle` (SPEC §11.3, §11.6): the zip the queue builds, exit codes,
// read-only, and the window's edges in local input across midnight and DST.

var bxNow = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

type bxRec struct {
	at  time.Time
	dev netip.Addr
	typ string
	raw []byte
}

type bundleFixture struct {
	dir  string
	recs []bxRec
}

func bxTrap(t *testing.T, id int64, oid string) []byte {
	t.Helper()
	o, _ := snmp.ParseOID(oid)
	seq, _ := snmp.ParseOID("1.3.6.1.4.1.32473.1.1.1.0")
	raw := snmp.EncodeCommunity(snmp.V2c, []byte("bx-community"), snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUTrap, RequestID: id, Varbinds: []snmp.Varbind{
		{OID: snmp.OIDSysUpTime, Value: snmp.Value{Kind: snmp.KindTimeTicks, Uint: 5}},
		{OID: snmp.OIDSnmpTrapOID, Value: snmp.Value{Kind: snmp.KindOID, OID: o}},
		{OID: seq, Value: snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(fmt.Sprintf("seq=bx:%d", id))}},
	}}))
	return snmp.FormatRecord(nil, snmp.Decode(raw, nil, bxNow), snmp.RecordOptions{Names: snmp.BuiltinMIBs()})
}

var (
	bxA = netip.MustParseAddr("192.0.2.1")
	bxB = netip.MustParseAddr("192.0.2.2")
	bxC = netip.MustParseAddr("198.51.100.7")
)

// newBundleFixture writes, through a real store, then closes (no -wal):
//   - A (edge-fw-01, HQ): syslog every 30 s 09:00–10:00 on 11-14, and every
//     minute 23:30 11-13 to 00:30 11-14 (across midnight: a .gz day and a plain
//     one); traps coldStart 09:30:58.250 and linkDown 09:31:00.
//   - B: syslog every minute on the minute 09:00–10:00 (records exactly at
//     09:12:00 and 09:52:00, the edges of the window around 09:42).
//   - C: syslog every 10 minutes 2026-11-01 03:00–08:00 UTC (the New York DST
//     change at 06:00 UTC).
func newBundleFixture(t *testing.T) *bundleFixture {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 8 << 10, Manual: true, Clock: clock,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f := &bundleFixture{dir: dir}
	var recs []bxRec
	add := func(at time.Time, dev netip.Addr, typ string, raw []byte) {
		recs = append(recs, bxRec{at: at, dev: dev, typ: typ, raw: raw})
	}
	for at := time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC); !at.After(time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC)); at = at.Add(10 * time.Minute) {
		add(at, bxC, logfile.TypeSyslog, []byte("<14>dst-01 app: tick "+at.Format(time.RFC3339)))
	}
	for at := time.Date(2026, 11, 13, 23, 30, 0, 0, time.UTC); !at.After(time.Date(2026, 11, 14, 0, 30, 0, 0, time.UTC)); at = at.Add(time.Minute) {
		add(at, bxA, logfile.TypeSyslog, []byte("<13>edge-fw-01 app: midnight "+at.Format(time.RFC3339)))
	}
	sevs := []int{2, 3, 4, 6}
	for i, at := 0, time.Date(2026, 11, 14, 9, 0, 0, 14e6, time.UTC); at.Before(time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)); i, at = i+1, at.Add(30*time.Second) {
		add(at, bxA, logfile.TypeSyslog, []byte(fmt.Sprintf("<%d>edge-fw-01 app: event %d", 8+sevs[i%len(sevs)], i)))
	}
	for at := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC); !at.After(time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)); at = at.Add(time.Minute) {
		add(at, bxB, logfile.TypeSyslog, []byte("<14>web-01 sshd: minute "+at.Format("15:04")))
	}
	add(time.Date(2026, 11, 14, 9, 30, 58, 250e6, time.UTC), bxA, logfile.TypeTrap, bxTrap(t, 1, "1.3.6.1.6.3.1.1.5.1"))
	add(time.Date(2026, 11, 14, 9, 31, 0, 0, time.UTC), bxA, logfile.TypeTrap, bxTrap(t, 2, "1.3.6.1.6.3.1.1.5.3"))
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].at.Before(recs[j].at) })
	day := ""
	for n, r := range recs {
		if d := r.at.Format(time.DateOnly); d != day {
			st.Flush()
			now = r.at
			st.Maintain() // a new day: yesterday's files are compressed
			day = d
		}
		now = r.at
		var err error
		m := model.Message{Received: r.at, Sender: r.dev, Raw: r.raw}
		if r.typ == logfile.TypeSyslog {
			err = st.Write(m)
		} else {
			err = st.WriteType(r.typ, m)
		}
		if err != nil {
			t.Fatal(err)
		}
		if n%50 == 0 {
			st.Maintain()
		}
	}
	now = bxNow
	st.Flush()
	st.Maintain()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := idx.AddEvent(context.Background(), index.Event{Time: time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC), Level: index.LevelInfo,
		Kind: index.KindStart, Source: index.SourceService, Text: "Woodshed started."}); err != nil {
		t.Fatal(err)
	}
	name, grp := "edge-fw-01", "HQ"
	idx.UpdateDevice(context.Background(), model.DeviceID(bxA), index.DeviceUpdate{Name: &name, Group: &grp})
	if err := idx.Close(); err != nil {
		t.Fatal(err)
	}
	f.recs = recs
	return f
}

// expected is the bundle's record files over [from, to) for devs.
func (f *bundleFixture) expected(from, to time.Time, devs ...netip.Addr) map[string][]byte {
	out := map[string][]byte{}
	for _, r := range f.recs {
		keep := false
		for _, d := range devs {
			keep = keep || r.dev == d
		}
		if !keep || r.at.Before(from) || !r.at.Before(to) {
			continue
		}
		name := export.FolderOf(r.typ) + "/" + model.DeviceID(r.dev) + "/" + logfile.DayOf(r.at) + ".log"
		out[name] = logfile.AppendLine(out[name], r.at, r.dev, r.raw)
	}
	return out
}

var bxZone = time.FixedZone("UTC-5", -5*3600)

// runBundle runs `woodshed bundle` in-process at bxNow, local time loc.
func runBundle(t *testing.T, loc *time.Location, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	searchNow = func() time.Time { return bxNow }
	searchLocation = func() *time.Location { return loc }
	bundleHostname = func() (string, error) { return "bx-host", nil }
	t.Cleanup(func() {
		searchNow, searchLocation, bundleHostname = time.Now, func() *time.Location { return time.Local }, os.Hostname
	})
	return runCLI(append([]string{"bundle"}, args...)...)
}

func readZipFile(t *testing.T, path string) (map[string][]byte, []string) {
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
			t.Fatal(err)
		}
		out[zf.Name] = b
		names = append(names, zf.Name)
	}
	return out, names
}

func recordFiles(files map[string][]byte) map[string][]byte {
	out := map[string][]byte{}
	for n, b := range files {
		if strings.HasPrefix(n, "logs/") || strings.HasPrefix(n, "traps/") {
			out[n] = b
		}
	}
	return out
}

func normManifest(t *testing.T, b []byte) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "id")
	delete(m, "exported_at")
	out, _ := json.MarshalIndent(m, "", " ")
	return string(out)
}

// TestBundleCLIMatchesQueue: the CLI's zip holds the same files, byte for
// byte, as the export queue's for the same request; only the manifest's ID
// and build time differ.
func TestBundleCLIMatchesQueue(t *testing.T) {
	f := newBundleFixture(t)
	out := filepath.Join(t.TempDir(), "cli.zip")
	code, stdout, stderr := runBundle(t, bxZone, "--data", f.dir, "--at", "2026-11-14 04:42", "--out", out)
	if code != 0 {
		t.Fatalf("exit %d\n%s%s", code, stdout, stderr)
	}
	cli, cliNames := readZipFile(t, out)

	idx, err := index.Open(filepath.Join(f.dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	eng := search.New(search.Options{DataDir: f.dir, Index: idx, Now: func() time.Time { return bxNow }})
	m, err := export.Open(export.Options{DataDir: f.dir, Index: idx, Search: eng, Version: version, Now: func() time.Time { return bxNow },
		Location: bxZone, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	m.Start()
	defer m.Close()
	at := time.Date(2026, 11, 14, 9, 42, 0, 0, time.UTC)
	in, err := m.Create(context.Background(), export.Request{Filters: export.Filters{Kind: export.KindBundle, At: &at,
		Before: 30 * time.Minute, After: 10 * time.Minute, ActiveDevices: true}})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for in.State != export.Ready {
		if in, err = m.Get(in.ID); err != nil || in.State == export.Failed || time.Now().After(deadline) {
			t.Fatalf("queue: %+v %v", in, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	zf, _, err := m.Download(in.ID)
	if err != nil {
		t.Fatal(err)
	}
	zf.Close()
	api, apiNames := readZipFile(t, filepath.Join(f.dir, export.Dir, in.ID+".zip"))

	if strings.Join(cliNames, ",") != strings.Join(apiNames, ",") {
		t.Fatalf("entries:\n cli %v\n api %v", cliNames, apiNames)
	}
	for _, n := range apiNames {
		if n == "manifest.json" {
			if normManifest(t, cli[n]) != normManifest(t, api[n]) {
				t.Errorf("manifest differs beyond id and exported_at")
			}
		} else if !bytes.Equal(cli[n], api[n]) {
			t.Errorf("%s differs", n)
		}
	}
	// What it holds: [09:12, 09:52) from A and B, B's 09:12 included and 09:52 not.
	from, to := time.Date(2026, 11, 14, 9, 12, 0, 0, time.UTC), time.Date(2026, 11, 14, 9, 52, 0, 0, time.UTC)
	if want := f.expected(from, to, bxA, bxB); !maps.EqualFunc(recordFiles(cli), want, bytes.Equal) {
		t.Errorf("record files %v, want %v", keys(recordFiles(cli)), keys(want))
	}
	b := string(cli["logs/192.0.2.2/2026-11-14.log"])
	if !strings.Contains(b, "minute 09:12") || strings.Contains(b, "minute 09:52") || strings.Contains(b, "minute 09:11") {
		t.Errorf("edges:\n%s", b)
	}
	// The output: path, size and SHA-256, the window, a line per device.
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 6 || lines[0] != out || !strings.Contains(lines[1], "SHA-256 ") ||
		lines[2] != "  2026-11-14 09:12:00 to 2026-11-14 09:52:00 UTC: 122 records from 2 devices (syslog, SNMP traps)" ||
		lines[3] != "  edge-fw-01 (192.0.2.1), group HQ: syslog 80, SNMP traps 2, reboots 1, dropped 0, truncated 0" ||
		lines[4] != "  192.0.2.2: syslog 40, SNMP traps 0, reboots 0, dropped 0, truncated 0" ||
		lines[5] != "  gaps: none of 1 s or more (Woodshed and its listeners were up the whole window)" {
		t.Errorf("stdout:\n%s", stdout)
	}
	if !strings.Contains(string(cli["README.txt"]), "  Reboots      1: 09:30:58.250 (coldStart trap)\n") ||
		!strings.Contains(string(cli["README.txt"]), "(local time UTC-05:00)") {
		t.Errorf("README:\n%s", cli["README.txt"])
	}
	for n, b := range cli {
		if bytes.Contains(b, []byte("bx-community")) {
			t.Errorf("%s holds the community", n)
		}
	}
}

func keys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestBundleCLIWindows: --at in local time across midnight and across the
// DST change, and the default --out name.
func TestBundleCLIWindows(t *testing.T) {
	f := newBundleFixture(t)
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	manifest := func(path string) (from, to time.Time, files map[string][]byte) {
		files, _ = readZipFile(t, path)
		var m struct {
			Request struct{ From, To time.Time }
		}
		if err := json.Unmarshal(files["manifest.json"], &m); err != nil {
			t.Fatal(err)
		}
		return m.Request.From, m.Request.To, recordFiles(files)
	}
	for _, c := range []struct {
		name     string
		loc      *time.Location
		args     []string
		from, to time.Time
		devs     []netip.Addr
	}{
		// Midnight UTC, typed in UTC: 23:50 to 00:20 reads the .gz day and the plain one.
		{"midnight", bxZone, []string{"--at", "2026-11-14 00:10", "--utc", "--before", "20m", "--after", "10m", "--devices", "192.0.2.1"},
			time.Date(2026, 11, 13, 23, 50, 0, 0, time.UTC), time.Date(2026, 11, 14, 0, 20, 0, 0, time.UTC), []netip.Addr{bxA}},
		// The same moment typed as local time (UTC-5).
		{"midnight local", bxZone, []string{"--at", "2026-11-13 19:10", "--before", "20m", "--after", "10m", "--devices", "192.0.2.1"},
			time.Date(2026, 11, 13, 23, 50, 0, 0, time.UTC), time.Date(2026, 11, 14, 0, 20, 0, 0, time.UTC), []netip.Addr{bxA}},
		// New York falls back at 02:00 EDT (06:00 UTC) on 2026-11-01: 01:30 is the
		// first one (EDT, 05:30 UTC); the window is real time, 2 h across the change.
		{"dst", ny, []string{"--at", "2026-11-01 01:30", "--before", "1h", "--after", "1h"},
			time.Date(2026, 11, 1, 4, 30, 0, 0, time.UTC), time.Date(2026, 11, 1, 6, 30, 0, 0, time.UTC), []netip.Addr{bxC}},
		// After the change, 01:30 EST is 06:30 UTC.
		{"dst after", ny, []string{"--at", "2026-11-01T01:30:00-05:00", "--before", "30m", "--after", "0s"},
			time.Date(2026, 11, 1, 6, 0, 0, 0, time.UTC), time.Date(2026, 11, 1, 6, 30, 0, 0, time.UTC), []netip.Addr{bxC}},
	} {
		out := filepath.Join(t.TempDir(), "b.zip")
		code, stdout, stderr := runBundle(t, c.loc, append([]string{"--data", f.dir, "--out", out}, c.args...)...)
		if code != 0 {
			t.Errorf("%s: exit %d %s%s", c.name, code, stdout, stderr)
			continue
		}
		from, to, got := manifest(out)
		if !from.Equal(c.from) || !to.Equal(c.to) {
			t.Errorf("%s: window %v to %v, want %v to %v", c.name, from, to, c.from, c.to)
		}
		if want := f.expected(c.from, c.to, c.devs...); !maps.EqualFunc(got, want, bytes.Equal) {
			t.Errorf("%s: files %v, want %v", c.name, keys(got), keys(want))
		}
	}
	// The DST window holds 12 ticks (04:30 to 06:20 UTC, two real hours), not 6 or 18.
	out := filepath.Join(t.TempDir(), "dst.zip")
	runBundle(t, ny, "--data", f.dir, "--out", out, "--at", "2026-11-01 01:30", "--before", "1h", "--after", "1h")
	_, _, got := manifest(out)
	if n := bytes.Count(got["logs/198.51.100.7/2026-11-01.log"], []byte("\n")); n != 12 {
		t.Errorf("DST window: %d records", n)
	}

	// The default name, in the current folder.
	cwd, _ := os.Getwd()
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(cwd)
	if code, stdout, stderr := runBundle(t, bxZone, "--data", f.dir, "--at", "2026-11-14T09:42:00Z"); code != 0 ||
		!strings.HasSuffix(strings.SplitN(stdout, "\n", 2)[0], string(filepath.Separator)+"woodshed-bundle-bx-host-20261114T094200Z.zip") {
		t.Errorf("default out: %d %s%s", code, stdout, stderr)
	}
	if _, err := os.Stat(filepath.Join(tmp, "woodshed-bundle-bx-host-20261114T094200Z.zip")); err != nil {
		t.Error(err)
	}
	// Again: never overwritten.
	if code, _, stderr := runBundle(t, bxZone, "--data", f.dir, "--at", "2026-11-14T09:42:00Z"); code != exitUsage ||
		!strings.Contains(stderr, "already exists; woodshed bundle never overwrites a file") {
		t.Errorf("existing out: %d %s", code, stderr)
	}
}

func TestBundleCLIExitCodes(t *testing.T) {
	f := newBundleFixture(t)
	tmp := t.TempDir()
	out := filepath.Join(tmp, "x.zip")
	for _, c := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"--data", f.dir}, exitUsage, "--at is required"},
		{[]string{"--data", f.dir, "--at", "tomorrow"}, exitUsage, `--at: "tomorrow" isn't a time`},
		{[]string{"--data", f.dir, "--at", "now", "--before", "5x"}, exitUsage, `--before: "5x" isn't a duration`},
		{[]string{"--data", f.dir, "--at", "now", "--before", "8d"}, exitUsage, "before must be from 0s to 7d"},
		{[]string{"--data", f.dir, "--at", "now", "--before", "0s", "--after", "0"}, exitUsage, "can't both be 0s"},
		{[]string{"--data", f.dir, "--at", "2026-11-15T00:00:00Z"}, exitUsage, "is in the future"},
		{[]string{"--data", f.dir, "--at", "now", "--group", "HQ", "--active"}, exitUsage, "alternatives"},
		{[]string{"--data", f.dir, "--at", "now", "--types", "sflow"}, exitUsage, `--types: unknown data type "sflow"`},
		{[]string{"--data", f.dir, "--at", "now", "extra"}, exitUsage, `unexpected argument "extra"`},
		{[]string{"--data", f.dir, "--at", "now", "--out", filepath.Join(f.dir, "logs", "b.zip")}, exitUsage, "is inside the data folder"},
		{[]string{"--data", f.dir, "--at", "now", "--group", "nobody"}, exitUsage, "No device matches the selection."},
		// Nothing in the window: active devices, and named ones.
		{[]string{"--data", f.dir, "--at", "2026-11-10T00:00:00Z", "--out", out}, exitNoMatch, "No device stored anything between"},
		{[]string{"--data", f.dir, "--at", "2026-11-10T00:00:00Z", "--devices", "192.0.2.1", "--out", out}, exitNoMatch,
			"nothing was stored from 192.0.2.1 between 2026-11-09T23:30:00.000Z and 2026-11-10T00:10:00.000Z. No zip written."},
		{[]string{"--data", filepath.Join(tmp, "nope"), "--at", "now"}, exitNoData, "there's no data folder"},
		{[]string{"--data", tmp, "--at", "now"}, exitNoData, "there's no index"},
	} {
		code, stdout, stderr := runBundle(t, bxZone, c.args...)
		if code != c.code || !strings.Contains(stderr, c.msg) || stdout != "" {
			t.Errorf("%v: exit %d, stderr %q, stdout %q; want %d, %q", c.args, code, stderr, stdout, c.code, c.msg)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%v wrote %s", c.args, out)
		}
	}
	if code, stdout, _ := runBundle(t, bxZone, "--help"); code != 0 || !strings.Contains(stdout, "usage: woodshed bundle") {
		t.Errorf("help %d", code)
	}
	if code, stdout, _ := runCLI("help"); code != 0 || !strings.Contains(stdout, "  bundle  ") {
		t.Errorf("woodshed help doesn't list bundle")
	}
}

// TestBundleIsReadOnly: the data folder is exactly as it was (no file, mode,
// size or time changed), whatever the bundle.
func TestBundleIsReadOnly(t *testing.T) {
	f := newBundleFixture(t)
	time.Sleep(10 * time.Millisecond)
	before := treeState(t, f.dir)
	tmp := t.TempDir()
	for i, args := range [][]string{
		{"--at", "2026-11-14 04:42"},
		{"--at", "2026-11-14T00:10:00Z", "--before", "1h", "--after", "1h", "--types", "syslog"},
		{"--at", "2026-11-14T09:31:00Z", "--types", "trap", "--group", "HQ"},
		{"--at", "2026-11-10T00:00:00Z"},
		{"--at", "now", "--before", "7d", "--after", "0s"},
		{"--at", "now", "--types", "sflow"},
	} {
		runBundle(t, bxZone, append([]string{"--data", f.dir, "--out", filepath.Join(tmp, fmt.Sprintf("%d.zip", i))}, args...)...)
	}
	if after := treeState(t, f.dir); !maps.Equal(before, after) {
		for k, v := range after {
			if before[k] != v {
				t.Errorf("changed or new: %s", k)
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				t.Errorf("gone: %s", k)
			}
		}
	}
}

// `woodshed bundle --types flow --flow-formats ipfix`: the flows from the
// closed segments as an IPFIX file per exporter, no CSV.
func TestBundleCLIFlows(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC)
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Manual: true, Clock: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	exp := netip.MustParseAddr("192.0.2.60")
	n := 0
	for at := time.Date(2026, 11, 14, 9, 30, 0, 0, time.UTC); at.Before(time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)); at = at.Add(10 * time.Second) {
		now = at
		ms := at.UnixMilli()
		r := &flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasProto | flow.HasDstPort | flow.HasBytes | flow.HasPackets,
			Received: ms, Start: ms - 5000, End: ms, Src: netip.MustParseAddr("10.20.0.5"), Dst: netip.MustParseAddr("198.51.100.7"),
			Proto: 6, DstPort: 443, Bytes: 1000, Packets: 2, Sampling: 1, Domain: 1, Version: flow.IPFIX}
		if err := st.WriteFlows(exp, store.FlowBatch{Received: at, Records: []*flow.Record{r}}); err != nil {
			t.Fatal(err)
		}
		if at.Before(time.Date(2026, 11, 14, 9, 52, 0, 0, time.UTC)) && !at.Before(time.Date(2026, 11, 14, 9, 12, 0, 0, time.UTC)) {
			n++
		}
	}
	now = bxNow
	st.Maintain()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := idx.AddEvent(context.Background(), index.Event{Time: time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), Level: index.LevelInfo,
		Kind: index.KindStart, Source: index.SourceService, Text: "Woodshed started."}); err != nil {
		t.Fatal(err)
	}
	idx.Close()
	out := filepath.Join(t.TempDir(), "flows.zip")
	code, stdout, stderr := runBundle(t, time.UTC, "--data", dir, "--at", "2026-11-14T09:42:00Z", "--types", "flow", "--flow-formats", "ipfix",
		"--out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	files, names := readZipFile(t, out)
	if _, ok := files["flows/192.0.2.60/flows.csv"]; ok {
		t.Fatalf("csv with --flow-formats ipfix: %v", names)
	}
	got := 0
	if err := flow.ReadFile(bytes.NewReader(files["flows/192.0.2.60/flows.ipfix"]), flow.FileReadOptions{}, func(*flow.Record) { got++ }); err != nil {
		t.Fatal(err)
	}
	// Flow time overlaps the window: one record whose start is before the
	// window's end but whose end (and receipt) is after it counts too.
	if got != n+1 {
		t.Fatalf("%d records, want %d", got, n+1)
	}
	if !strings.Contains(stdout, "flows ") || !strings.Contains(string(files["README.txt"]), "Flows        ") {
		t.Errorf("stdout %s\nREADME %s", stdout, files["README.txt"])
	}
	if code, _, stderr := runBundle(t, time.UTC, "--data", dir, "--at", "2026-11-14T09:42:00Z", "--flow-formats", "pcap",
		"--out", filepath.Join(t.TempDir(), "x.zip")); code != exitUsage || !strings.Contains(stderr, `--flow-formats: "pcap" isn't csv or ipfix`) {
		t.Errorf("bad format: %d %s", code, stderr)
	}
}
