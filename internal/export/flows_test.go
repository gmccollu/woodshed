package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/store"
)

// The flow fixture: two exporters through a real store.
//   - fwDev, an event-style firewall (domain 1, unsampled): per connection a
//     created and a deleted event with initiator/responder totals, NAT and a
//     rule ID; every third connection an update; and denied events with only
//     an event time. Interface names from options data.
//   - rtDev, a router (delta counters): domain 1 sampled 1 in 100, domain 2
//     unsampled, biflow reverse counters on some, an enterprise extra.
// Records arrive every 15 s from 23:30 to 00:20 UTC, and fwDev has two raw
// sets (one no_template, one malformed) at 23:55.
var (
	fwDev = netip.MustParseAddr("192.0.2.50")
	rtDev = netip.MustParseAddr("192.0.2.51")
)

type flowEnv struct {
	*env
	fe   *flowquery.Engine
	recs map[string][]flow.Record
	at   time.Time
	now  time.Time
}

func flowRec(i int, at time.Time, dev netip.Addr) []flow.Record {
	ms := at.UnixMilli()
	src := netip.AddrFrom4([4]byte{10, 20, 0, byte(5 + i%4)})
	dst := netip.AddrFrom4([4]byte{198, 51, 100, byte(7 + i%3)})
	if dev == rtDev {
		r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto |
			flow.HasTCPFlags | flow.HasPackets | flow.HasBytes | flow.HasInIf | flow.HasOutIf | flow.HasToS | flow.HasSrcAS | flow.HasDstAS |
			flow.HasNextHop,
			Received: ms, Start: ms - 20000, End: ms - 1000, Src: src, Dst: dst, SrcPort: uint16(40000 + i), DstPort: []uint16{443, 53, 22}[i%3],
			Proto: []uint8{6, 17, 6}[i%3], TCPFlags: 0x1b, Packets: uint64(10 + i), Bytes: uint64(1500 * (10 + i)), InIf: 3, OutIf: 1, ToS: 0,
			SrcAS: 64500, DstAS: 64501, NextHop: netip.MustParseAddr("192.0.2.254"), Sampling: 100, Domain: 1, Version: flow.IPFIX}
		if i%2 == 1 {
			r.Domain, r.Sampling = 2, 1
		}
		if i%4 == 0 {
			r.Has |= flow.HasRevBytes | flow.HasRevPackets
			r.RevBytes, r.RevPackets = uint64(800*(i+1)), uint64(i+1)
		}
		if i%5 == 0 {
			r.Extras = []flow.Extra{{PEN: 32473, ID: 1, Value: []byte{0x0a, byte(i)}}}
		}
		return []flow.Record{r}
	}
	post := netip.MustParseAddr("192.0.2.10")
	base := flow.Record{Has: flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto | flow.HasFwEvent |
		flow.HasInIf | flow.HasOutIf | flow.HasInIfName | flow.HasOutIfName | flow.HasRuleID | flow.HasEventTime,
		Received: ms, Src: src, Dst: dst, SrcPort: uint16(50000 + i), DstPort: 443, Proto: 6, InIf: 3, InIfName: "inside", OutIf: 1,
		OutIfName: "outside", RuleID: "acl-7", Sampling: 1, Domain: 1, Version: flow.IPFIX, EventTime: ms}
	nat := func(r flow.Record, ev uint8) flow.Record {
		r.Has |= flow.HasNatEvent | flow.HasPostNATSrc | flow.HasPostNATSrcPort | flow.HasPostNATDst | flow.HasPostNATDstPort
		r.NatEvent, r.PostNATSrc, r.PostNATSrcPort, r.PostNATDst, r.PostNATDstPort = ev, post, uint16(30000+i), r.Dst, 443
		return r
	}
	created := nat(base, 4)
	created.FwEvent = flow.FwCreated
	created.Has |= flow.HasStart | flow.HasEnd
	created.Start, created.End = ms-30000, ms-30000
	deleted := nat(base, 5)
	deleted.FwEvent = flow.FwDeleted
	deleted.Has |= flow.HasStart | flow.HasEnd | flow.HasInitiatorBytes | flow.HasResponderBytes | flow.HasInitiatorPackets |
		flow.HasResponderPackets
	deleted.Start, deleted.End = ms-30000, ms
	deleted.InitiatorBytes, deleted.ResponderBytes, deleted.InitiatorPackets, deleted.ResponderPackets = uint64(2000+i), uint64(9000+i), 12, 20
	out := []flow.Record{created, deleted}
	if i%3 == 0 {
		up := nat(base, 4)
		up.FwEvent = flow.FwUpdate
		up.Has |= flow.HasInitiatorBytes | flow.HasStart | flow.HasEnd
		up.InitiatorBytes = 999
		up.Start, up.End = ms, ms
		out = append(out, up)
	}
	denied := base
	denied.Has &^= flow.HasInIfName | flow.HasOutIfName
	denied.FwEvent = flow.FwDenied
	denied.Src = netip.AddrFrom4([4]byte{203, 0, 113, byte(50 + i%2)})
	denied.DstPort = []uint16{23, 445}[i%2]
	denied.RuleID = "deny-all"
	// As the decoder stores an event with only an event time.
	denied.Has |= flow.HasStart | flow.HasEnd
	denied.Start, denied.End = ms, ms
	out = append(out, denied)
	return out
}

func newFlowEnv(t *testing.T) *flowEnv {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	c := &clock{t: time.Date(2026, 11, 13, 23, 30, 0, 0, time.UTC)}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Manual: true, Clock: c.Now, Logger: quiet, Version: "1.2.3",
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := idx.AddEvent(bg, index.Event{Time: time.Date(2026, 11, 13, 23, 0, 0, 0, time.UTC), Level: index.LevelInfo, Kind: index.KindStart,
		Source: index.SourceService, Text: "Woodshed 2.0 (abc) started on test/test; data folder x."}); err != nil {
		t.Fatal(err)
	}
	fe := &flowEnv{env: &env{t: t, dir: dir, idx: idx, st: st, clock: c}, recs: map[string][]flow.Record{},
		at: time.Date(2026, 11, 14, 0, 5, 0, 0, time.UTC), now: time.Date(2026, 11, 14, 1, 0, 0, 0, time.UTC)}
	start := time.Date(2026, 11, 13, 23, 30, 0, 7e6, time.UTC)
	for i := 0; ; i++ {
		at := start.Add(time.Duration(i) * 15 * time.Second)
		if !at.Before(time.Date(2026, 11, 14, 0, 20, 0, 0, time.UTC)) {
			break
		}
		c.Set(at)
		for _, dev := range []netip.Addr{fwDev, rtDev} {
			rs := flowRec(i, at, dev)
			batch := store.FlowBatch{Received: at, Size: 1200}
			for j := range rs {
				batch.Records = append(batch.Records, &rs[j])
			}
			if dev == fwDev && i == 100 {
				batch.Raw = []*flow.RawSet{
					{Received: at.UnixMilli(), Domain: 1, Version: flow.IPFIX, TemplateID: 300, Status: flow.StatusNoTemplate, Data: []byte{1, 2, 3, 4}},
					{Received: at.UnixMilli(), Version: flow.V9, Status: flow.StatusMalformed, Data: []byte{0, 9, 0, 1}},
				}
			}
			if err := st.WriteFlows(dev, batch); err != nil {
				t.Fatal(err)
			}
			fe.recs[model.DeviceID(dev)] = append(fe.recs[model.DeviceID(dev)], rs...)
		}
		if i%40 == 0 {
			st.Maintain()
		}
	}
	c.Set(fe.now)
	st.Maintain()
	st.Flush()
	name := "edge-fw-01"
	idx.UpdateDevice(bg, model.DeviceID(fwDev), index.DeviceUpdate{Name: &name})
	fe.eng = search.New(search.Options{DataDir: dir, Index: idx, Now: c.Now, Logger: quiet})
	fe.fe = flowquery.New(flowquery.Options{DataDir: dir, Index: idx, Logger: quiet, Open: func(ids []string) []flowquery.OpenSegment {
		var out []flowquery.OpenSegment
		for _, s := range st.OpenFlowSegments(ids) {
			out = append(out, flowquery.OpenSegment{DeviceID: s.DeviceID, Rel: s.Rel, Path: s.Path, Footer: s.Footer})
		}
		return out
	}})
	return fe
}

func (fe *flowEnv) flowManager(opts ...func(*Options)) *Manager {
	return fe.manager(append([]func(*Options){func(o *Options) {
		o.Flows, o.Location = fe.fe, est
		o.FlowStats = func(id string) *FlowStats {
			if id == model.DeviceID(fwDev) {
				return &FlowStats{SequenceGaps: 3, LostEstimate: 90}
			}
			return &FlowStats{}
		}
	}}, opts...)...)
}

// inWindow is the fixture's records of dev whose flow time overlaps [from, to).
func (fe *flowEnv) inWindow(dev string, from, to time.Time) []flow.Record {
	var out []flow.Record
	for _, r := range fe.recs[dev] {
		s, e := flowquery.FlowStart(&r), flowquery.FlowEnd(&r)
		if e >= from.UnixMilli() && s < to.UnixMilli() {
			out = append(out, r)
		}
	}
	return out
}

func csvRows(t *testing.T, b []byte) [][]string {
	t.Helper()
	if !bytes.HasSuffix(b, []byte("\r\n")) {
		t.Fatalf("not CRLF: %q", b[max(0, len(b)-10):])
	}
	rows, err := csv.NewReader(bytes.NewReader(b)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func sortedRows(rows [][]string) []string {
	var out []string
	for _, r := range rows {
		out = append(out, strings.Join(r, ","))
	}
	slices.Sort(out)
	return out
}

// A flow export: the CSV holds exactly the window's records (every column,
// empty cells for what a record lacks), the IPFIX file reads back to the same
// rows, raw.txt holds the raw sets, and the manifest lists the files.
func TestFlowExportFiles(t *testing.T) {
	fe := newFlowEnv(t)
	m := fe.flowManager()
	from, to := time.Date(2026, 11, 13, 23, 50, 0, 0, time.UTC), time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	in, err := m.Create(bg, Request{Devices: []string{model.DeviceID(fwDev), model.DeviceID(rtDev)}, From: from, To: to,
		Filters: Filters{Types: []string{"flow"}}})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, m, in.ID, Ready)
	files, names := readZip(t, m, in.ID)
	for _, dev := range []netip.Addr{fwDev, rtDev} {
		id := model.DeviceID(dev)
		want := fe.inWindow(id, from, to)
		var wantRows [][]string
		for i := range want {
			wantRows = append(wantRows, FlowCSVRow(&want[i]))
		}
		rows := csvRows(t, files["flows/"+id+"/flows.csv"])
		if !slices.Equal(rows[0], FlowCSVColumns) || len(rows)-1 != len(want) || len(want) == 0 {
			t.Fatalf("%s: %d rows, want %d (header %v)", id, len(rows)-1, len(want), rows[0])
		}
		if !slices.Equal(sortedRows(rows[1:]), sortedRows(wantRows)) {
			t.Fatalf("%s: CSV rows differ from the records written", id)
		}
		// The IPFIX file reads back to the same rows; it doesn't carry the
		// decode status (every fixture record is ok).
		var back [][]string
		if err := flow.ReadFile(bytes.NewReader(files["flows/"+id+"/flows.ipfix"]), flow.FileReadOptions{}, func(r *flow.Record) {
			c := *r
			if c.RuleID == "" {
				c.Has &^= flow.HasRuleID
			}
			back = append(back, FlowCSVRow(&c))
		}); err != nil {
			t.Fatal(err)
		}
		if len(back) != len(want) {
			t.Fatalf("%s: ipfix %d records, want %d", id, len(back), len(want))
		}
		// rule_id comes back only through rule_id_ies (it travels as an extra).
		ruleCol := slices.Index(FlowCSVColumns, "rule_id")
		strip := func(rs [][]string) []string {
			var c [][]string
			for _, r := range rs {
				r = slices.Clone(r)
				r[ruleCol] = ""
				c = append(c, r)
			}
			return sortedRows(c)
		}
		if g, w := strip(back), strip(rows[1:]); !slices.Equal(g, w) {
			for i := range g {
				if g[i] != w[i] {
					t.Fatalf("%s: ipfix row differs:\n got %s\nwant %s", id, g[i], w[i])
				}
			}
		}
	}
	// One fw row checked cell by cell: a deleted event with NAT, totals, names.
	rows := csvRows(t, files["flows/192.0.2.50/flows.csv"])
	col := func(r []string, name string) string { return r[slices.Index(FlowCSVColumns, name)] }
	var del, den []string
	for _, r := range rows[1:] {
		switch col(r, "fw_event") {
		case "deleted":
			del = r
		case "denied":
			den = r
		}
	}
	if col(del, "nat_event") != "nat44_session_delete" || col(del, "post_nat_src") != "192.0.2.10" || col(del, "in_if_name") != "inside" ||
		col(del, "initiator_bytes") == "" || col(del, "bytes") != "" || col(del, "proto") != "6" || col(del, "rule_id") != "acl-7" ||
		col(del, "sampling") != "1" || col(del, "bytes_scaled") != "" || col(del, "time_source") != "exporter" || col(del, "status") != "ok" ||
		!strings.HasSuffix(col(del, "received"), "Z") || len(col(del, "received")) != len("2026-11-13T23:50:00.007Z") {
		t.Errorf("deleted row %v", del)
	}
	if col(den, "start") != col(den, "event_time") || col(den, "event_time") == "" || col(den, "in_if_name") != "" || col(den, "rule_id") != "deny-all" {
		t.Errorf("denied row %v", den)
	}
	rt := csvRows(t, files["flows/192.0.2.51/flows.csv"])
	var sampled []string
	for _, r := range rt[1:] {
		if col(r, "sampling") == "100" {
			sampled = r
		}
	}
	if col(sampled, "bytes_scaled") == "" || col(sampled, "tcp_flags") != "SAFP" || col(sampled, "next_hop") != "192.0.2.254" {
		t.Errorf("sampled row %v", sampled)
	}
	// raw.txt: the two raw sets, received 23:55:00.007.
	raw := string(files["flows/192.0.2.50/raw.txt"])
	if lines := strings.Split(strings.TrimSpace(raw), "\n"); len(lines) != 2 ||
		lines[0] != "2026-11-13T23:55:00.007Z no_template v10 domain=1 template=300 AQIDBA==" ||
		!strings.HasPrefix(lines[1], "2026-11-13T23:55:00.007Z malformed v9 ") {
		t.Errorf("raw.txt %q", raw)
	}
	if _, ok := files["flows/192.0.2.51/raw.txt"]; ok {
		t.Error("raw.txt for an exporter without raw sets")
	}
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if man.Folders["flows"] != "flow" || !slices.Equal(man.Types, []string{"flow"}) || len(man.Files) != 5 ||
		!slices.Equal(man.Request.Filters.FlowFormats, []string{"csv", "ipfix"}) {
		t.Errorf("manifest %+v (files %v)", man, names)
	}
	var total int64
	for _, f := range man.Files {
		if strings.HasSuffix(f.Path, ".csv") {
			total += f.Lines
		}
	}
	if man.Lines != total || total == 0 {
		t.Errorf("manifest lines %d, csv rows %d", man.Lines, total)
	}
	if !strings.Contains(string(files["README.txt"]), "flows/<device>/flows.ipfix") {
		t.Errorf("README lacks the flows files:\n%s", files["README.txt"])
	}
}

// flow_formats and a flow filter.
func TestFlowExportFormatsAndFilter(t *testing.T) {
	fe := newFlowEnv(t)
	m := fe.flowManager()
	from, to := time.Date(2026, 11, 13, 23, 30, 0, 0, time.UTC), time.Date(2026, 11, 14, 0, 30, 0, 0, time.UTC)
	in, err := m.Create(bg, Request{Devices: []string{model.DeviceID(fwDev)}, From: from, To: to,
		Filters: Filters{Types: []string{"flow"}, Flow: map[string]string{"fw_event": "denied", "dst_port": "23"}, FlowFormats: []string{"ipfix"}}})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, m, in.ID, Ready)
	files, names := readZip(t, m, in.ID)
	if _, ok := files["flows/192.0.2.50/flows.csv"]; ok {
		t.Fatalf("csv with flow_formats ipfix: %v", names)
	}
	n := 0
	if err := flow.ReadFile(bytes.NewReader(files["flows/192.0.2.50/flows.ipfix"]), flow.FileReadOptions{}, func(r *flow.Record) {
		if r.FwEvent != flow.FwDenied || r.DstPort != 23 {
			t.Errorf("filtered out record %+v", r)
		}
		n++
	}); err != nil {
		t.Fatal(err)
	}
	want := 0
	for _, r := range fe.inWindow("192.0.2.50", from, to) {
		if r.FwEvent == flow.FwDenied && r.DstPort == 23 {
			want++
		}
	}
	if n != want || n == 0 {
		t.Fatalf("%d records, want %d", n, want)
	}
	if readme := string(files["README.txt"]); !strings.Contains(readme, "Flows, fw_event: denied") || strings.Contains(readme, "flows.csv\n") {
		t.Errorf("README:\n%s", readme)
	}
	// A bad flow filter is a request error.
	_, err = m.Create(bg, Request{Devices: []string{model.DeviceID(fwDev)}, From: from, To: to,
		Filters: Filters{Types: []string{"flow"}, Flow: map[string]string{"dst_port": "x"}}})
	var re *RequestError
	if !errors.As(err, &re) || !strings.Contains(re.Msg, "dst_port") {
		t.Fatalf("bad filter: %v", err)
	}
}

// The per-device cap: a 400 naming the device and the count, at estimate
// and at create; and the estimate by type.
func TestFlowCapAndEstimate(t *testing.T) {
	fe := newFlowEnv(t)
	m := fe.flowManager()
	from, to := time.Date(2026, 11, 13, 23, 30, 0, 0, time.UTC), time.Date(2026, 11, 14, 0, 30, 0, 0, time.UTC)
	req := Request{Devices: []string{model.DeviceID(fwDev), model.DeviceID(rtDev)}, From: from, To: to,
		Filters: Filters{Types: []string{"flow", "syslog"}}}
	by, err := m.EstimateByType(bg, req)
	if err != nil {
		t.Fatal(err)
	}
	want := int64(len(fe.inWindow("192.0.2.50", from, to)) + len(fe.inWindow("192.0.2.51", from, to)))
	if by["flow"].Records != want || by["flow"].Bytes != want*(csvBytesPerRecord+ipfixBytesPerRecord) || by["syslog"].Lines != 0 {
		t.Fatalf("by type %+v, want %d records", by, want)
	}
	old := maxFlowRecords
	maxFlowRecords = 5
	t.Cleanup(func() { maxFlowRecords = old })
	for _, f := range []func() error{
		func() error { _, err := m.EstimateByType(bg, req); return err },
		func() error { _, err := m.Estimate(bg, req); return err },
		func() error { _, err := m.Create(bg, req); return err },
	} {
		var re *RequestError
		if err := f(); !errors.As(err, &re) || !strings.HasPrefix(re.Msg, "Too many flow records for one zip (") ||
			!strings.HasSuffix(re.Msg, " for 192.0.2.50); narrow the window or add a flow filter.") {
			t.Errorf("cap: %v", err)
		}
	}
	if err := capError("10.1.0.1", 24113002); err.Error() != "Too many flow records for one zip (24,113,002 for 10.1.0.1); narrow the window or add a flow filter." {
		t.Errorf("message %q", err)
	}
}

// A bundle with flows: every type with data in the window, flows included;
// the README's Flows block (golden) and the manifest summary's flow entry.
func TestFlowBundle(t *testing.T) {
	fe := newFlowEnv(t)
	m := fe.flowManager()
	at := fe.at
	in, err := m.Create(bg, Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute,
		ActiveDevices: true}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(in.Filters.Types, []string{"flow"}) || len(in.Devices) != 2 {
		t.Fatalf("types %v devices %v", in.Filters.Types, in.Devices)
	}
	wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	checkGolden(t, "flow_bundle_readme.golden", files["README.txt"])
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	var fw *FlowSummary
	for _, d := range man.Summary {
		if d.DeviceID == "192.0.2.50" {
			fw = d.Flow
			if d.Types["flow"].Lines != fw.Records {
				t.Errorf("lines %d records %d", d.Types["flow"].Lines, fw.Records)
			}
		}
	}
	from, to := at.Add(-30*time.Minute), at.Add(10*time.Minute)
	want := fe.inWindow("192.0.2.50", from, to)
	var created, deleted, denied, natc int64
	for _, r := range want {
		switch r.FwEvent {
		case flow.FwCreated:
			created++
		case flow.FwDeleted:
			deleted++
		case flow.FwDenied:
			denied++
		}
		if r.Is(flow.HasNatEvent) && flow.NATCreate(r.NatEvent) {
			natc++
		}
	}
	if fw == nil || fw.Records != int64(len(want)) || fw.FwEvents != (FwEventCounts{created, deleted, denied}) || fw.NATConnections != natc ||
		fw.NoTemplate != 1 || fw.Malformed != 1 || fw.SequenceGaps == nil || *fw.SequenceGaps != 3 || len(fw.TopDeniedSources) != 2 ||
		fw.TopDeniedPorts[0].Key != "tcp/23" && fw.TopDeniedPorts[0].Key != "tcp/445" || fw.TopPostNATSources[0].Key != "192.0.2.10" {
		t.Fatalf("fw summary %+v", fw)
	}
	b, _ := json.Marshal(fw)
	for _, k := range []string{`"records"`, `"domains"`, `"sampling"`, `"bytes"`, `"bytes_scaled"`, `"packets"`, `"packets_scaled"`,
		`"top_talkers"`, `"top_dst_ports"`, `"top_conversations"`, `"fw_events"`, `"top_denied_sources"`, `"top_denied_ports"`,
		`"nat_connections"`, `"top_post_nat_sources"`, `"sequence_gaps"`, `"lost_estimate"`, `"no_template"`, `"malformed"`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Errorf("summary JSON lacks %s: %s", k, b)
		}
	}
}

// Without the collector's counts (woodshed bundle), the README says the
// sequence gaps aren't known; the bundle is otherwise the same.
func TestFlowBundleOffline(t *testing.T) {
	fe := newFlowEnv(t)
	at := fe.at
	plan, err := Prepare(bg, Options{Index: fe.idx, Search: fe.eng, Flows: fe.fe, Version: "1.2.3", Now: fe.clock.Now, Location: est},
		Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute, ActiveDevices: true,
			FlowFormats: []string{"csv"}}})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "b.zip")
	f, err := createFile(p)
	if err != nil {
		t.Fatal(err)
	}
	res, err := plan.Write(bg, f, nil)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	files, _ := unzipFile(t, p)
	readme := string(files["README.txt"])
	if !strings.Contains(readme, "sequence gaps not known (only the running service counts them)") {
		t.Errorf("README:\n%s", readme)
	}
	if _, ok := files["flows/192.0.2.50/flows.ipfix"]; ok {
		t.Error("ipfix with flow_formats csv")
	}
	if len(res.Summary) != 2 || res.Summary[0].Flow == nil || res.Summary[0].Flow.SequenceGaps != nil {
		t.Errorf("summary %+v", res.Summary)
	}
	if !strings.Contains(res.Summary[1].Line([]string{"flow"}), "flows ") {
		t.Errorf("line %q", res.Summary[1].Line([]string{"flow"}))
	}
}

func TestFlowHumanUnits(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 999: "999 B", 1000: "1.0 kB", 18_200_000_000: "18.2 GB", 1_900_000_000_000: "1.9 TB",
		312_000_000: "312 MB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("%d: %q want %q", n, got, want)
		}
	}
	for n, want := range map[int64]string{980: "980", 21_400_000: "21.4 M", 2_100_000_000: "2.1 G", 999_999: "999,999"} {
		if got := humanCount(n); got != want {
			t.Errorf("%d: %q want %q", n, got, want)
		}
	}
	if got := samplingWords([]DomainSampling{{1, []uint32{1000}}, {2, []uint32{1}}}); got != "sampled 1 in 1,000 on domain 1, unsampled on domain 2" {
		t.Errorf("%q", got)
	}
	if got := string(AppendFlowCSVRow(nil, &flow.Record{Has: flow.HasSrc, Src: netip.MustParseAddr("10.0.0.1"), Sampling: 0})); !strings.HasPrefix(got, ",,,10.0.0.1,") ||
		!strings.HasSuffix(got, "\r\n") || len(FlowCSVHeader()) != 39 {
		t.Errorf("row %q", got)
	}
}

func createFile(p string) (*os.File, error) { return os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600) }
