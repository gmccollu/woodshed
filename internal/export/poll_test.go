package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"slices"
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

// Polls in exports and bundles (SPEC §12.6): three CSVs per device with the
// documented columns, rows matching the stored lines, empty cells for "not
// measured", the README's Polls lines, and a poll restart merged with a
// coldStart trap into one reboot.

// newPollEnv writes, for device A, a poll cycle every 60 s from 09:00 to
// 09:40 UTC (two interfaces, a custom OID, an hourly info line), a timeout
// at 09:20, eth3 down at 09:30:58 and up at 09:31:40, a restart at 09:31:00
// with a coldStart trap at 09:30:58.112, and syslog beside it.
func newPollEnv(t *testing.T) (*env, time.Time) {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	day0 := time.Date(2026, 11, 15, 9, 0, 0, 0, time.UTC)
	c := &clock{t: day0}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 64 << 10, Manual: true, Clock: c.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	idx.AddEvent(bg, index.Event{Time: day0.Add(-time.Hour), Level: index.LevelInfo, Kind: index.KindStart,
		Source: index.SourceService, Text: "Woodshed 1.3 (abc) started on test/test; data folder x."})
	w := func(at time.Time, typ string, raw []byte) {
		t.Helper()
		c.Set(at)
		var err error
		if typ == logfile.TypeSyslog {
			err = st.Write(model.Message{Received: at, Sender: devA, Raw: raw})
		} else {
			err = st.WriteType(typ, model.Message{Received: at, Sender: devA, Raw: raw})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	poll := func(at time.Time, r pollrec.Record) { w(at, logfile.TypePoll, pollrec.Format(r)) }
	ifl := func(c uint64, idx uint64, name, oper string) *pollrec.Builder {
		return pollrec.New(pollrec.KindIf, c).Uint("if", idx).Str("name", name).Str("oper", oper).Uint("speed_mbps", 1000)
	}
	var in1, in3 uint64
	for i := 0; i <= 40; i++ {
		at := day0.Add(time.Duration(i)*time.Minute + 120*time.Millisecond)
		cyc := uint64(1000 + i)
		w(at.Add(-time.Second), logfile.TypeSyslog, []byte("<13>edge-fw-01 app: tick"))
		if i == 0 {
			poll(at, pollrec.New(pollrec.KindInfo, cyc).Str("sys_name", "edge-fw-01").Str("sys_descr", "a \"router\", v1").Record())
			poll(at, pollrec.New(pollrec.KindInfo, cyc).Uint("if", 1).Str("name", "eth1").Str("alias", "uplink, primary").Record())
			poll(at, pollrec.New(pollrec.KindInfo, cyc).Uint("if", 3).Str("name", "eth3").Str("alias", "lab").Record())
		}
		if i == 20 {
			poll(at, pollrec.New(pollrec.KindStatus, cyc).Str("status", "timeout").Str("detail", "no answer after 1 retry").
				Str("cred", "#3f9a1c07").Uint("interval_s", 60).Record())
			continue
		}
		up := uint64(104512345 + i*6000)
		if i >= 31 {
			up = uint64((i - 30) * 6000)
		}
		poll(at, pollrec.New(pollrec.KindSys, cyc).Uint("uptime", up).Uint("hr_uptime", up+10).Uint("cpu", uint64(10+i%5)).
			Uint("mem_used", 40).Uint("mem_total", 100).Uint("rtt_ms", 4).Uint("interval_s", 60).Record())
		b1 := ifl(cyc, 1, "eth1", "up").Uint("in_octets", in1).Uint("out_octets", in1/10)
		if i > 0 && i != 21 {
			bps := uint64(800e6)
			if i == 31 {
				bps = 812e6
			}
			b1.Uint("in_bps", bps).Uint("out_bps", bps/10).Uint("in_err", 0).Uint("in_err_d", 0).Uint("out_err_d", 0).
				Uint("in_disc_d", 0).Uint("out_disc_d", 0)
		}
		if i == 21 {
			b1.Str("disc", "1")
		}
		in1 += 6e9
		poll(at, b1.Record())
		oper := "up"
		if i == 31 {
			oper = "down"
		}
		b3 := ifl(cyc, 3, "eth3", oper).Uint("in_octets", in3)
		if i == 31 {
			b3.Str("oper_was", "up")
		}
		if i == 32 {
			b3.Str("oper_was", "down")
		}
		if i > 0 && i != 21 {
			b3.Uint("in_bps", 1000).Uint("out_bps", 0).Uint("in_err_d", 0).Uint("out_err_d", 0).Uint("in_disc_d", 0).Uint("out_disc_d", 0)
			if i == 30 {
				b3.Uint("in_err_d", 12).Uint("in_disc_d", 340)
			}
		}
		poll(at, b3.Record())
		poll(at, pollrec.New(pollrec.KindOID, cyc).Str("oid", "1.3.6.1.4.1.32473.1.2.0").Str("label", "queue depth").Str("type", "g32").
			Uint("value", uint64(i)).Record())
		if i == 31 {
			poll(at.Add(time.Millisecond), pollrec.New(pollrec.KindRestart, cyc).Str("reboot", "1").Uint("uptime", up).
				Uint("prev_uptime", 104512345+30*6000).Str("source", "sysUpTime,hrSystemUptime").Record())
		}
	}
	w(time.Date(2026, 11, 15, 9, 30, 58, 112e6, time.UTC), logfile.TypeTrap, trapRec(t, 77, oidColdStart))
	st.Flush()
	st.Maintain()
	end := day0.Add(45 * time.Minute)
	c.Set(end)
	e := &env{t: t, dir: dir, idx: idx, st: st, clock: c, day0: day0}
	e.eng = search.New(search.Options{DataDir: dir, Index: idx, Now: c.Now, Logger: quiet})
	return e, end
}

func readCSV(t *testing.T, b []byte) [][]string {
	t.Helper()
	if !bytes.HasSuffix(b, []byte("\r\n")) {
		t.Errorf("CSV doesn't end in CRLF")
	}
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func TestPollExportCSV(t *testing.T) {
	e, end := newPollEnv(t)
	m := e.manager()
	in, err := m.Create(bg, Request{Devices: []string{model.DeviceID(devA)}, From: e.day0, To: end, Filters: Filters{Types: []string{datatype.Poll}}})
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, names := readZip(t, m, in.ID)
	dev := model.DeviceID(devA)
	for _, f := range []string{"system.csv", "interfaces.csv", "oids.csv"} {
		if !slices.Contains(names, "poll/"+dev+"/"+f) {
			t.Fatalf("no %s in %v", f, names)
		}
	}
	for _, n := range names {
		if strings.HasPrefix(n, "logs/") || strings.HasPrefix(n, "traps/") {
			t.Errorf("a %s in a poll export", n)
		}
	}
	sys := readCSV(t, files["poll/"+dev+"/system.csv"])
	if !slices.Equal(sys[0], SystemCSVColumns) || len(sys) != 1+42 { // 40 sys, 1 timeout, 1 restart
		t.Fatalf("system.csv: %d rows, header %v", len(sys), sys[0])
	}
	if r := sys[1]; r[0] != "2026-11-15T09:00:00.120Z" || r[1] != "1000" || r[2] != "1045123.45" || r[4] != "10" || r[8] != "ok" || r[9] != "" {
		t.Errorf("first row %v", r)
	}
	var timeout, restart []string
	for _, r := range sys[1:] {
		switch r[8] {
		case "timeout":
			timeout = r
		case "restart":
			restart = r
		}
	}
	if timeout == nil || timeout[2] != "" || timeout[4] != "" || timeout[9] != "no answer after 1 retry" {
		t.Errorf("timeout row %v", timeout)
	}
	if restart == nil || restart[9] != "sysUpTime and hrSystemUptime reset" {
		t.Errorf("restart row %v", restart)
	}
	ifs := readCSV(t, files["poll/"+dev+"/interfaces.csv"])
	if !slices.Equal(ifs[0], InterfacesCSVColumns) || len(ifs) != 1+80 {
		t.Fatalf("interfaces.csv: %d rows", len(ifs))
	}
	first := ifs[1]
	if first[2] != "1" || first[3] != "eth1" || first[4] != "uplink, primary" || first[9] != "" || first[13] != "" {
		t.Errorf("first interface row (no previous sample: empty rates) %v", first)
	}
	var discRow []string
	for _, r := range ifs[1:] {
		if r[19] == "1" {
			discRow = r
		}
		if r[3] == "eth3" && r[4] != "lab" {
			t.Errorf("eth3 alias %q", r[4])
		}
	}
	if discRow == nil || discRow[9] != "" {
		t.Errorf("discontinuity row %v", discRow)
	}
	oids := readCSV(t, files["poll/"+dev+"/oids.csv"])
	if !slices.Equal(oids[0], OIDsCSVColumns) || len(oids) != 41 || oids[1][3] != "queue depth" || oids[1][5] != "g32" || oids[1][4] != "" {
		t.Errorf("oids.csv %d %v", len(oids), oids[1])
	}
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if man.Folders["poll"] != "poll" || !slices.Equal(man.Types, []string{"poll"}) || man.Request.Filters.Type != "poll" {
		t.Errorf("manifest %v %v %s", man.Folders, man.Types, man.Request.Filters.Type)
	}
	if len(man.Files) != 3 {
		t.Fatalf("manifest files %+v", man.Files)
	}
	var rows int64
	for _, f := range man.Files {
		sum := sha256.Sum256(files[f.Path])
		if f.SHA256 != hex.EncodeToString(sum[:]) || f.Bytes != int64(len(files[f.Path])) {
			t.Errorf("%s: sha %s bytes %d", f.Path, f.SHA256, f.Bytes)
		}
		rows += f.Lines
	}
	if rows != 42+80+40 || man.Lines != rows {
		t.Errorf("rows %d, manifest lines %d", rows, man.Lines)
	}
	if !strings.Contains(string(files["README.txt"]), "poll/<device>/system.csv, interfaces.csv, oids.csv") ||
		!strings.Contains(string(files["README.txt"]), "in_errors, out_errors") {
		t.Errorf("README:\n%s", files["README.txt"])
	}

	// A filtered export: only the interface file, only the down rows.
	pf, _ := datatype.ParsePollFilter(func(k string) string { return map[string]string{"kinds": "if", "oper": "down"}[k] })
	in, err = m.Create(bg, Request{Devices: []string{dev}, From: e.day0, To: end, Filters: Filters{Types: []string{datatype.Poll}, Poll: pf}})
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	files, names = readZip(t, m, in.ID)
	if slices.Contains(names, "poll/"+dev+"/system.csv") || slices.Contains(names, "poll/"+dev+"/oids.csv") {
		t.Errorf("files %v", names)
	}
	if ifs := readCSV(t, files["poll/"+dev+"/interfaces.csv"]); len(ifs) != 2 || ifs[1][3] != "eth3" || ifs[1][4] != "lab" {
		t.Errorf("filtered %v", ifs)
	}
	// A poll export never holds a community: only the hash.
	for n, b := range files {
		if bytes.Contains(b, []byte("s3cret-community")) {
			t.Errorf("%s holds the community", n)
		}
	}
}

func TestPollBundle(t *testing.T) {
	e, _ := newPollEnv(t)
	m := e.manager()
	at := time.Date(2026, 11, 15, 9, 40, 0, 0, time.UTC)
	in, err := m.Create(bg, Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 40 * time.Minute, After: 5 * time.Minute,
		ActiveDevices: true}})
	if err != nil {
		t.Fatal(err)
	}
	in = wait(t, m, in.ID, Ready)
	if !slices.Equal(in.Filters.Types, []string{"syslog", "trap", "poll"}) {
		t.Errorf("types %v", in.Filters.Types)
	}
	files, _ := readZip(t, m, in.ID)
	readme := string(files["README.txt"])
	for _, s := range []string{
		"  Polls        40 of 41 cycles answered (60 s); uptime 10 min at the end of the window\n",
		"               peak in 812 Mb/s (eth1, 09:31), peak out 81 Mb/s (eth1, 09:31); CPU peak 14 % (09:04), memory peak 40 %\n",
		"               errors +12 in (eth3), +0 out; discards +340 in (eth3), +0 out; eth3 down 09:31:00 to 09:32:00\n",
		"  Reboots      1: 09:30:58.112 (poll: sysUpTime and hrSystemUptime reset; coldStart trap)\n",
	} {
		if !strings.Contains(readme, s) {
			t.Errorf("README lacks %q:\n%s", s, readme)
		}
	}
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if len(man.Summary) != 1 {
		t.Fatalf("summary %+v", man.Summary)
	}
	d := man.Summary[0]
	if d.Poll == nil || d.Poll.Cycles != 41 || d.Poll.Answered != 40 || *d.Poll.IntervalS != 60 || d.Poll.PeakInIf != "eth1" ||
		*d.Poll.ErrorsInD != 12 || len(d.Poll.OperChanges) != 1 || d.Poll.OperChanges[0].If != "eth3" {
		t.Errorf("poll summary %+v", d.Poll)
	}
	if len(d.Reboots) != 1 || d.Reboots[0].Source != "poll, coldStart trap" || d.Reboots[0].Detail != "sysUpTime and hrSystemUptime reset" ||
		!d.Reboots[0].Time.Equal(time.Date(2026, 11, 15, 9, 30, 58, 112e6, time.UTC)) {
		t.Errorf("reboots %+v", d.Reboots)
	}
	if ts := d.Types["poll"]; ts.Key != "by_kind" || ts.Lines != 42+80+40 {
		t.Errorf("types.poll %+v", ts)
	}
	if !strings.Contains(string(files["manifest.json"]), `"poll": {`) {
		t.Error("no poll object in manifest.json")
	}
	for n, b := range files {
		if bytes.Contains(b, []byte("s3cret-community")) {
			t.Errorf("%s holds the community", n)
		}
	}
	if _, ok := files["poll/"+model.DeviceID(devA)+"/interfaces.csv"]; !ok {
		t.Error("no interfaces.csv in the bundle")
	}
	// The merge window: a trap more than 2 min away stays its own reboot.
	rs := mergeReboots([]datatype.Reboot{{Time: at, Source: "coldStart trap"}, {Time: at.Add(3 * time.Minute), Source: "poll", Detail: "x"}}, nil)
	if len(rs) != 2 {
		t.Errorf("merged %+v", rs)
	}
}
