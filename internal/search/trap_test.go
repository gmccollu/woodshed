package search

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The engine over two data types (SPEC §11.1): a syslog search never reads
// trap bytes, a trap search never reads syslog bytes, and each type's filters
// and fields are its own.

func trapRec(t testing.TB, community string, id int64, trap string, text string) []byte {
	t.Helper()
	o, _ := snmp.ParseOID(trap)
	seq, _ := snmp.ParseOID("1.3.6.1.4.1.32473.1.1.1.0")
	vbs := []snmp.Varbind{
		{OID: snmp.OIDSysUpTime, Value: snmp.Value{Kind: snmp.KindTimeTicks, Uint: 100}},
		{OID: snmp.OIDSnmpTrapOID, Value: snmp.Value{Kind: snmp.KindOID, OID: o}},
		{OID: seq, Value: snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(text)}},
	}
	raw := snmp.EncodeCommunity(snmp.V2c, []byte(community), snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUTrap, RequestID: id, Varbinds: vbs}))
	return snmp.FormatRecord(nil, snmp.Decode(raw, nil, time.Now()), snmp.RecordOptions{Names: snmp.BuiltinMIBs()})
}

type trapFixture struct {
	eng   *Engine
	idx   *index.DB
	st    *store.Store
	start time.Time
}

// newTrapFixture writes n syslog lines and n traps per device over an hour,
// half the traps linkDown and half linkUp, through a real store, then closes
// the day (so there are compressed files of both types too).
func newTrapFixture(t *testing.T, n int) *trapFixture {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(dir + "/" + index.FileName)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	start := time.Date(2026, 11, 13, 23, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: start}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 8 << 10, Manual: true, Clock: clock.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i) * (2 * time.Hour) / time.Duration(n))
		clock.Set(at)
		for _, a := range []string{"192.0.2.1", "192.0.2.2"} {
			addr := netip.MustParseAddr(a)
			if err := st.Write(model.Message{Received: at, Sender: addr, Raw: []byte(fmt.Sprintf("<13>host app: linkDown syslog %d", i))}); err != nil {
				t.Fatal(err)
			}
			trap := "1.3.6.1.6.3.1.1.5.3"
			if i%2 == 1 {
				trap = "1.3.6.1.6.3.1.1.5.4"
			}
			rec := trapRec(t, "public", int64(i), trap, fmt.Sprintf("seq=run:%d", i))
			if err := st.WriteType(logfile.TypeTrap, model.Message{Received: at.Add(time.Millisecond), Sender: addr, Raw: rec}); err != nil {
				t.Fatal(err)
			}
		}
		if i%50 == 0 {
			st.Maintain()
		}
	}
	st.Flush()
	st.Maintain()
	st.Maintain()
	end := start.Add(2 * time.Hour)
	eng := New(Options{DataDir: dir, Index: idx, Now: func() time.Time { return end }, Logger: quiet, block: 4 << 10})
	return &trapFixture{eng: eng, idx: idx, st: st, start: start}
}

func (f *trapFixture) all(t *testing.T, q Query) []Line {
	t.Helper()
	q.From, q.To = f.start, f.start.Add(2*time.Hour)
	var out []Line
	for {
		p, err := f.eng.Search(bg, q)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p.Results...)
		if p.NextCursor == "" {
			return out
		}
		q.Cursor = p.NextCursor
	}
}

func trapFilter(t *testing.T, params map[string]string) *datatype.TrapFilter {
	t.Helper()
	tf, err := datatype.ParseTrapFilter(func(k string) string { return params[k] })
	if err != nil {
		t.Fatal(err)
	}
	return tf
}

func TestSearchByType(t *testing.T) {
	f := newTrapFixture(t, 400)
	syslogLines := f.all(t, Query{})
	if len(syslogLines) != 800 {
		t.Fatalf("syslog: %d lines", len(syslogLines))
	}
	for _, l := range syslogLines {
		if l.Type != TypeSyslog || !strings.HasPrefix(string(l.Raw), "<13>") {
			t.Fatalf("syslog result %+v", l)
		}
	}
	traps := f.all(t, Query{Filter: Filter{Type: TypeTrap}, Limit: 77})
	if len(traps) != 800 {
		t.Fatalf("traps: %d", len(traps))
	}
	for i, l := range traps {
		if l.Type != TypeTrap || !strings.HasPrefix(string(l.Raw), "v=2c pdu=trap") {
			t.Fatalf("trap result %+v", l)
		}
		if i > 0 && l.Received.After(traps[i-1].Received) {
			t.Fatal("not newest first")
		}
	}
	// q reads the record without raw= (never base64), and the type's filters apply.
	if got := f.all(t, Query{Filter: Filter{Type: TypeTrap, Q: "linkDown"}}); len(got) != 400 {
		t.Fatalf("q linkDown: %d", len(got))
	}
	if got := f.all(t, Query{Filter: Filter{Type: TypeTrap, Q: "MIGT"}}); len(got) != 0 {
		t.Fatalf("q matched base64: %d", len(got))
	}
	if got := f.all(t, Query{Filter: Filter{Type: TypeTrap, Trap: trapFilter(t, map[string]string{"trap_oid": "linkUp"})}, Devices: []string{"192.0.2.2"}}); len(got) != 200 {
		t.Fatalf("linkUp on one device: %d", len(got))
	}
	if got := f.all(t, Query{Filter: Filter{Type: TypeTrap, Q: "seq=run:7\"", Trap: trapFilter(t, map[string]string{"status": "ok"})}, Asc: true}); len(got) != 2 {
		t.Fatalf("seq 7: %d", len(got))
	}
	if got := f.all(t, Query{Filter: Filter{Type: TypeTrap, Trap: trapFilter(t, map[string]string{"pdus": "none"})}}); len(got) != 0 {
		t.Fatalf("none: %d", len(got))
	}
	// Syslog filters with type=trap are refused, and the reverse.
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Type: TypeTrap, Severities: 3}}); err == nil {
		t.Fatal("severities with type=trap")
	}
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Trap: trapFilter(t, map[string]string{"pdus": "trap"})}}); err == nil {
		t.Fatal("trap filters with syslog")
	}
	// Context stays within the ref's type.
	cp, err := f.eng.Context(bg, traps[300].Ref, 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(cp.Lines) != 11 {
		t.Fatalf("context %d lines", len(cp.Lines))
	}
	for _, l := range cp.Lines {
		if l.Type != TypeTrap {
			t.Fatalf("context crossed types: %+v", l)
		}
	}
	// A cursor of one type isn't another's.
	p, _ := f.eng.Search(bg, Query{Filter: Filter{Type: TypeTrap, From: f.start, To: f.start.Add(2 * time.Hour)}, Limit: 10})
	if _, err := f.eng.Search(bg, Query{Filter: Filter{From: f.start, To: f.start.Add(2 * time.Hour)}, Limit: 10, Cursor: p.NextCursor}); err == nil {
		t.Fatal("trap cursor accepted for syslog")
	}
}

func TestSummaryByType(t *testing.T) {
	f := newTrapFixture(t, 200)
	run := func(q SummaryQuery) Summary {
		t.Helper()
		q.From, q.To = f.start, f.start.Add(2*time.Hour)
		q.Budget = MaxSummaryBudget
		for {
			s, err := f.eng.Summary(bg, q)
			if err != nil {
				t.Fatal(err)
			}
			if s.NextCursor == "" {
				return s
			}
			q.Cursor = s.NextCursor
		}
	}
	s := run(SummaryQuery{Filter: Filter{Type: TypeTrap}, Bucket: time.Hour})
	if s.Matched != 400 || s.Histogram == nil || s.Histogram.Source != "index" {
		t.Fatalf("matched %d, histogram %+v", s.Matched, s.Histogram)
	}
	var hist int64
	for _, b := range s.Histogram.Buckets {
		hist += *b.Count
	}
	if hist != 400 {
		t.Fatalf("index histogram %d", hist)
	}
	byKey := map[string]FieldCounts{}
	for _, fc := range s.Fields {
		byKey[fc.Key] = fc
	}
	if fc := byKey["trap_oid"]; len(fc.Values) != 2 || fc.Values[0].Count != 200 || (fc.Values[0].Label != "linkDown" && fc.Values[0].Label != "linkUp") {
		t.Fatalf("trap_oid %+v", fc)
	}
	if fc := byKey["version"]; len(fc.Values) != 1 || fc.Values[0].Value != "2c" || fc.Values[0].Label != "v2c" {
		t.Fatalf("version %+v", fc)
	}
	if fc := byKey["generic"]; fc.None != 400 {
		t.Fatalf("generic %+v", fc)
	}
	if fc := byKey["device"]; len(fc.Values) != 2 {
		t.Fatalf("device %+v", fc)
	}
	// A filtered trap summary scans, and counts what search finds.
	s = run(SummaryQuery{Filter: Filter{Type: TypeTrap, Trap: trapFilter(t, map[string]string{"trap_oid": "linkDown"})}, Bucket: time.Hour})
	if s.Matched != 200 || s.Histogram.Source != "scan" {
		t.Fatalf("filtered %d %s", s.Matched, s.Histogram.Source)
	}
	// Syslog's summary is untouched by traps.
	s = run(SummaryQuery{Bucket: time.Hour})
	if s.Matched != 400 {
		t.Fatalf("syslog matched %d", s.Matched)
	}
	if _, err := f.eng.Summary(bg, SummaryQuery{Filter: Filter{Type: TypeTrap}, Fields: []string{"severity"}}); err == nil {
		t.Fatal("a syslog field for traps")
	}
}

// Export's scanner and Each read one type too.
func TestScannerAndEachByType(t *testing.T) {
	f := newTrapFixture(t, 100)
	flt := Filter{Type: TypeTrap, From: f.start, To: f.start.Add(2 * time.Hour)}
	sc, err := f.eng.NewScanner(bg, "192.0.2.1", flt)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for {
		h, ok := sc.Next()
		if !ok {
			break
		}
		if !strings.Contains(string(h.Escaped), "pdu=trap") {
			t.Fatalf("scanner %q", h.Line)
		}
		n++
	}
	sc.Close()
	if n != 100 {
		t.Fatalf("scanner %d", n)
	}
	st, err := f.eng.Each(bg, Query{Filter: flt}, func(r *Result) error { return nil })
	if err != nil || st.Matches != 200 {
		t.Fatalf("each %+v %v", st, err)
	}
	est, err := f.eng.Estimate(bg, []string{"192.0.2.1", "192.0.2.2"}, flt)
	if err != nil || est.Lines != 200 {
		t.Fatalf("estimate %+v %v", est, err)
	}
}
