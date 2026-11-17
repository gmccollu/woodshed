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
	"github.com/gmccollu/woodshed/internal/flowseg"
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
//
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
	return newFlowEnvWith(t, nil)
}

// newFlowEnvWith is newFlowEnv with the store's options changed by mod.
func newFlowEnvWith(t *testing.T, mod func(*store.Options)) *flowEnv {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	c := &clock{t: time.Date(2026, 11, 13, 23, 30, 0, 0, time.UTC)}
	so := store.Options{DataDir: dir, Index: idx, Manual: true, Clock: c.Now, Logger: quiet, Version: "1.2.3",
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }}
	if mod != nil {
		mod(&so)
	}
	st, err := store.Open(so)
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
			// Sequence gaps (SPEC §13.10 decision 82): a burst before the
			// bundle window (23:35–00:15 in TestFlowBundle) and a few in it.
			if dev == fwDev && i == 4 {
				batch.SeqGaps, batch.SeqLost = 849, 37498
			}
			if dev == fwDev && i == 100 {
				batch.SeqGaps, batch.SeqLost = 3, 90
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
				return &FlowStats{SequenceGaps: 852, LostEstimate: 37588}
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
		fw.NoTemplate != 1 || fw.Malformed != 1 || fw.SequenceGaps == nil || *fw.SequenceGaps != 3 || *fw.LostEstimate != 90 ||
		fw.SequenceGapsSpan == nil || !fw.SequenceGapsSpan.From.Equal(from) || !fw.SequenceGapsSpan.To.Equal(to) || fw.SequenceGapsSpan.ByHour ||
		fw.SequenceGaps24h == nil || *fw.SequenceGaps24h != 852 || len(fw.TopDeniedSources) != 2 ||
		fw.TopDeniedPorts[0].Key != "tcp/23" && fw.TopDeniedPorts[0].Key != "tcp/445" || fw.TopPostNATSources[0].Key != "192.0.2.10" {
		t.Fatalf("fw summary %+v", fw)
	}
	b, _ := json.Marshal(fw)
	for _, k := range []string{`"records"`, `"domains"`, `"sampling"`, `"bytes"`, `"bytes_scaled"`, `"packets"`, `"packets_scaled"`,
		`"top_talkers"`, `"top_dst_ports"`, `"top_conversations"`, `"fw_events"`, `"top_denied_sources"`, `"top_denied_ports"`,
		`"nat_connections"`, `"top_post_nat_sources"`, `"zero_omitted"`, `"sequence_gaps"`, `"lost_estimate"`, `"sequence_gaps_span"`,
		`"sequence_gaps_24h"`, `"lost_estimate_24h"`, `"no_template"`, `"malformed"`} {
		if !bytes.Contains(b, []byte(k)) {
			t.Errorf("summary JSON lacks %s: %s", k, b)
		}
	}
}

// With a segment's part limit at 10 blocks, or the writers' directory
// budget at a few blocks (the store closes the segment keeping the most),
// every exporter's hours are many parts (closed, and the open one): a
// bundle's records and a flow count over the window still find every
// record once.
func TestFlowBundleOverParts(t *testing.T) {
	for _, c := range []struct {
		name  string
		mod   func(o *store.Options)
		parts int // at least (the budget closes segments at maintenance passes, every 40 batches here)
	}{
		{"block limit", func(o *store.Options) { o.FlowPartBlocks = 10 }, 20},
		{"directory budget", func(o *store.Options) { o.FlowDirBudget = flowseg.DirEntryBytes }, 4},
	} {
		t.Run(c.name, func(t *testing.T) { bundleOverParts(t, c.mod, c.parts) })
	}
}

func bundleOverParts(t *testing.T, mod func(o *store.Options), minParts int) {
	fe := newFlowEnvWith(t, mod)
	parts, _ := filepath.Glob(filepath.Join(fe.dir, "logs", "*", "flows", "*.0[0-9][0-9].wsf"))
	if len(parts) < minParts {
		t.Fatalf("%d numbered parts", len(parts))
	}
	m := fe.flowManager()
	at := fe.at
	in, err := m.Create(bg, Request{Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute,
		ActiveDevices: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Devices) != 2 {
		t.Fatalf("devices %v", in.Devices)
	}
	wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	from, to := at.Add(-30*time.Minute), at.Add(10*time.Minute)
	got := map[string]int64{}
	for _, d := range man.Summary {
		if d.Flow != nil {
			got[d.DeviceID] = d.Flow.Records
		}
	}
	counts, err := fe.fe.Count(bg, flowquery.Query{From: from, To: to})
	if err != nil {
		t.Fatal(err)
	}
	for _, dev := range []string{model.DeviceID(fwDev), model.DeviceID(rtDev)} {
		want := int64(len(fe.inWindow(dev, from, to)))
		if want == 0 || got[dev] != want || counts[dev] != want {
			t.Fatalf("%s: bundle %d records, count %d, want %d", dev, got[dev], counts[dev], want)
		}
	}
}

// Without the collector (woodshed bundle), the window's sequence gaps still
// come from the index; only the collector's 24-hour counts are missing.
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
	if !strings.Contains(readme, "sequence gaps 3 (≈ 90 records lost before Woodshed) in this window; waiting for a template 1") ||
		strings.Contains(readme, "24 h before") {
		t.Errorf("README:\n%s", readme)
	}
	if _, ok := files["flows/192.0.2.50/flows.ipfix"]; ok {
		t.Error("ipfix with flow_formats csv")
	}
	if len(res.Summary) != 2 || res.Summary[0].Flow == nil || res.Summary[0].Flow.SequenceGaps == nil || res.Summary[0].Flow.SequenceGaps24h != nil {
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

// Shares in the README: whole percents from 10 %, one decimal under that,
// "<0.1 %" for a non-zero share under 0.1 %, never "0 %" for a share that
// isn't 0 (lab, 2.0.0-rc1: a 0.31 % conversation read "0 %"). The UI's
// shareText (web/src/lib/flows.ts) gives the same strings.
func TestFlowShareText(t *testing.T) {
	for share, want := range map[float64]string{0.31: "31 %", 0.1: "10 %", 0.0999: "10 %", 0.042: "4.2 %", 0.04: "4 %",
		0.0031: "0.3 %", 0.001: "0.1 %", 0.0009: "<0.1 %", 0.00001: "<0.1 %", 1: "100 %", 0.9996: "100 %", 0: "0 %"} {
		if got := pct(share); got != want {
			t.Errorf("%v: %q want %q", share, got, want)
		}
	}
}

// The README's sequence gaps are the window's (SPEC §13.10 decision 82):
// none, some, by the hour for a window older than a day; when the window's
// aren't known it says why, and only then adds the collector's 24 hours,
// labelled as not the window's.
func TestFlowReadmeSequenceGaps(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	base := FlowSummary{Records: 10, Domains: 1, Sampling: []DomainSampling{{1, []uint32{1}}}, Bytes: 5000}
	last := func(s FlowSummary) []string {
		l := flowReadme(&s)
		return l[len(l)-2:]
	}
	from := time.Date(2026, 11, 15, 14, 20, 0, 0, time.UTC)
	for _, c := range []struct {
		name string
		mod  func(s *FlowSummary)
		want []string
	}{
		{"none", func(s *FlowSummary) {
			s.SequenceGaps, s.LostEstimate, s.SequenceGaps24h, s.LostEstimate24h = n(0), n(0), n(849), n(37498)
		},
			[]string{"sequence gaps 0 in this window; waiting for a template 0; malformed 0"}},
		{"some", func(s *FlowSummary) { s.SequenceGaps, s.LostEstimate = n(3), n(90) },
			[]string{"sequence gaps 3 (≈ 90 records lost before Woodshed) in this window; waiting for a template 0; malformed 0"}},
		{"by hour", func(s *FlowSummary) {
			s.SequenceGaps, s.LostEstimate = n(1234), n(5000)
			s.SequenceGapsSpan = &GapSpan{From: from.Truncate(time.Hour), To: from.Truncate(time.Hour).Add(2 * time.Hour), ByHour: true}
		}, []string{"sequence gaps 1,234 (≈ 5,000 records lost before Woodshed) in 2026-11-15 14:00–16:00 UTC " +
			"(from the hour: counts older than a day are kept by the hour); waiting for a template 0; malformed 0"}},
		{"by hour, then minutes", func(s *FlowSummary) {
			s.SequenceGaps, s.LostEstimate = n(3), n(90)
			s.SequenceGapsSpan = &GapSpan{From: from.Truncate(time.Hour), To: from.Add(26*time.Hour + 13*time.Minute), ByHour: true}
		}, []string{"sequence gaps 3 (≈ 90 records lost before Woodshed) in 2026-11-15 14:00–2026-11-16 16:33 UTC " +
			"(from the hour: counts older than a day are kept by the hour); waiting for a template 0; malformed 0"}},
		{"across the retention", func(s *FlowSummary) {
			s.SequenceGaps, s.LostEstimate = n(1), n(30)
			s.SequenceGapsSpan = &GapSpan{From: from.Truncate(time.Hour), To: from.Add(7 * 24 * time.Hour), Partial: true}
		}, []string{"sequence gaps 1 (≈ 30 records lost before Woodshed) in 2026-11-15 14:00–2026-11-22 14:20 UTC only " +
			"(Woodshed keeps the counts 7 days, and this window starts earlier); waiting for a template 0; malformed 0"}},
		{"nothing received", func(s *FlowSummary) { s.SequenceGapsUnknown = "nothing_received" },
			[]string{"sequence gaps in this window not known (no flow datagram arrived in it: gaps are counted by arrival, and its " +
				"records are here by their own times); waiting for a template 0; malformed 0"}},
		{"not kept, with the collector's", func(s *FlowSummary) {
			s.SequenceGapsUnknown, s.SequenceGaps24h, s.LostEstimate24h = "not_kept", n(849), n(37498)
		}, []string{"sequence gaps in this window not known (Woodshed keeps them 7 days); waiting for a template 0; malformed 0",
			"collector sequence gaps in the 24 h before this bundle was made (not limited to this window): 849 (≈ 37,498 records lost)"}},
		{"not counted", func(s *FlowSummary) { s.SequenceGapsUnknown = "not_counted" },
			[]string{"sequence gaps in this window not known (part of it was stored by a Woodshed that didn't count them); waiting for a template 0; malformed 0"}},
	} {
		s := base
		c.mod(&s)
		got := last(s)
		if len(c.want) == 1 {
			got = got[1:]
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s:\n%q\nwant\n%q", c.name, got, c.want)
		}
	}
}

// A top list leaves out keys with 0 bytes and says how many; with only
// those it says "none"; with none left out it says nothing more.
func TestFlowReadmeZeroOmitted(t *testing.T) {
	s := &FlowSummary{Records: 10, Domains: 1, Sampling: []DomainSampling{{1, []uint32{1}}}, Bytes: 5000,
		TopTalkers: []KeyShare{{"10.0.0.1", 0.9}, {"10.0.0.2", 0.1}}, TopDstPorts: []KeyShare{{"tcp/443", 1}},
		ZeroOmitted: TopZeroOmitted{TopTalkers: 3, TopConversations: 2}}
	text := strings.Join(flowReadme(s), "\n")
	for _, want := range []string{"top talkers by bytes: 10.0.0.1 90 %, 10.0.0.2 10 % (3 with 0 bytes not shown)\n",
		"top destination ports: tcp/443 100 %\n", "top conversations: none (2 with 0 bytes not shown)\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	s.ZeroOmitted.Approx = true
	if text := strings.Join(flowReadme(s), "\n"); !strings.Contains(text, "(at least 3 with 0 bytes not shown)") {
		t.Errorf("approx:\n%s", text)
	}
	s.ZeroOmitted.Approx = false
	b, _ := json.Marshal(s)
	if !bytes.Contains(b, []byte(`"zero_omitted":{"top_talkers":3,"top_dst_ports":0,"top_conversations":2,"top_denied_sources":0,`+
		`"top_denied_ports":0,"top_post_nat_sources":0,"approx":false}`)) {
		t.Errorf("JSON %s", b)
	}
}

// A share through shares() never reads "0 %": rounded to 0.01 % it would be
// 0 for 1 byte in a million (review, 2026-11-17).
func TestFlowTinyShare(t *testing.T) {
	top, _ := flowquery.NewTop("src", "bytes")
	add := func(src string, b uint64) {
		top.Add(&flow.Record{Has: flow.HasSrc | flow.HasBytes, Src: netip.MustParseAddr(src), Bytes: b, Sampling: 1})
	}
	add("10.0.0.1", 999_998)
	add("10.0.0.2", 1)
	add("10.0.0.3", 1)
	ks, _ := shares(top, "bytes")
	if len(ks) != 3 || pct(ks[0].Share) != "100 %" || pct(ks[1].Share) != "<0.1 %" || pct(ks[2].Share) != "<0.1 %" {
		t.Fatalf("%+v", ks)
	}
}

func createFile(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
}

// Records whose flow time is far from their arrival (SPEC §13.10 decision
// 70): every one written is stored and kept as sent; the bundle's README gets
// a line with the window's own count (a record that arrived an hour and more
// before its times, so it's in the window) and the collector's 24-hour count
// (which includes one 49.7 days ahead, whose own time is outside the window);
// the manifest summary has both. Without either, no line (TestFlowBundle's
// golden).
func TestFlowBundleTimeOffsets(t *testing.T) {
	fe := newFlowEnv(t)
	dev := netip.MustParseAddr("192.0.2.52")
	id := model.DeviceID(dev)
	rec := func(received, end time.Time) *flow.Record {
		return &flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasPackets,
			Received: received.UnixMilli(), Start: end.Add(-time.Second).UnixMilli(), End: end.UnixMilli(),
			Src: netip.MustParseAddr("10.30.0.1"), Dst: netip.MustParseAddr("198.51.100.30"), Bytes: 100, Packets: 1, Sampling: 1, Version: flow.IPFIX}
	}
	early := time.Date(2026, 11, 13, 22, 30, 0, 0, time.UTC)
	in := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	wrap := time.Duration(1<<32) * time.Millisecond
	batches := []store.FlowBatch{
		{Received: early, Size: 200, Records: []*flow.Record{rec(early, early.Add(70*time.Minute))}},             // ahead, in the window
		{Received: in, Size: 200, Records: []*flow.Record{rec(in, in.Add(-time.Second)), rec(in, in.Add(wrap))}}, // normal; 49.7 days ahead
	}
	for _, b := range batches {
		fe.clock.Set(b.Received)
		if err := fe.st.WriteFlows(dev, b); err != nil {
			t.Fatal(err)
		}
	}
	fe.clock.Set(fe.now)
	fe.st.Maintain()
	fe.st.Flush()
	stats := flow.TimeOffsets{Ahead: 2, MaxAheadMs: in.Add(wrap).Sub(in).Milliseconds()}
	m := fe.manager(func(o *Options) {
		o.Flows, o.Location = fe.fe, est
		o.FlowStats = func(d string) *FlowStats {
			if d == id {
				return &FlowStats{TimeOffsets: stats}
			}
			return &FlowStats{}
		}
	})
	at := fe.at
	inf, err := m.Create(bg, Request{Devices: []string{id}, Filters: Filters{Kind: KindBundle, At: &at, Before: 30 * time.Minute, After: 10 * time.Minute}})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, m, inf.ID, Ready)
	files, _ := readZip(t, m, inf.ID)
	rows := csvRows(t, files["flows/"+id+"/flows.csv"])
	if len(rows) != 3 { // the header, the early record and the normal one
		t.Fatalf("CSV rows %d:\n%s", len(rows), files["flows/"+id+"/flows.csv"])
	}
	readme := string(files["README.txt"])
	want := "times off arrival: 1 ahead (up to 1.2 h) in this window; 2 ahead (up to 49.7 days) in the last 24 h; kept at their own times, " +
		"so a window around their arrival misses them (the exporter's clock or uptime is probably wrong)"
	if !strings.Contains(readme, want) {
		t.Errorf("README lacks %q:\n%s", want, readme)
	}
	var man Manifest
	if err := json.Unmarshal(files["manifest.json"], &man); err != nil {
		t.Fatal(err)
	}
	if len(man.Summary) != 1 || man.Summary[0].Flow == nil {
		t.Fatalf("summary %+v", man.Summary)
	}
	s := man.Summary[0].Flow
	if s.Records != 2 || s.TimeOffsets != (flow.TimeOffsets{Ahead: 1, MaxAheadMs: 70 * 60_000}) || s.TimeOffsets24h == nil || *s.TimeOffsets24h != stats {
		t.Errorf("summary %d records, offsets %+v, 24h %v", s.Records, s.TimeOffsets, s.TimeOffsets24h)
	}
	// The 49.7-day record is stored: a flow-time window at its own time finds it.
	far, err := fe.fe.Count(bg, flowquery.Query{DeviceIDs: []string{id}, From: in.Add(wrap - time.Minute), To: in.Add(wrap + time.Minute)})
	if err != nil || far[id] != 1 {
		t.Errorf("at its own time: %v %v", far, err)
	}
	// No offsets anywhere: no line.
	if l := timeOffLine(&FlowSummary{TimeOffsets24h: &flow.TimeOffsets{}}); l != "" {
		t.Errorf("line without offsets: %q", l)
	}
	if l := timeOffLine(&FlowSummary{TimeOffsets: flow.TimeOffsets{Behind: 3, MaxBehindMs: 30 * 3600_000}}); l !=
		"times off arrival: 3 behind (up to 30 h) in this window; kept at their own times, so a window around their arrival misses them "+
			"(the exporter's clock or uptime is probably wrong)" {
		t.Errorf("behind line %q", l)
	}
}
