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
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The poll type through the engine (SPEC §12.3): poll lines are searchable,
// with the poll filters and fields, and never mixed with the other types.

// newPollFixture writes n cycles per device over two hours: a sys line, two
// if lines (eth1 up, eth2 going down every 10th cycle), and every 25th cycle
// a timeout, plus syslog lines, through a real store.
func newPollFixture(t *testing.T, n int) *trapFixture {
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
	write := func(addr netip.Addr, at time.Time, r pollrec.Record) {
		if err := st.WriteType(logfile.TypePoll, model.Message{Received: at, Sender: addr, Raw: pollrec.Format(r)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < n; i++ {
		at := start.Add(time.Duration(i) * (2 * time.Hour) / time.Duration(n))
		clock.Set(at)
		c := uint64(i + 1)
		for _, a := range []string{"192.0.2.1", "192.0.2.2"} {
			addr := netip.MustParseAddr(a)
			if err := st.Write(model.Message{Received: at, Sender: addr, Raw: []byte(fmt.Sprintf("<13>host app: oper=down %d", i))}); err != nil {
				t.Fatal(err)
			}
			if i%25 == 24 {
				write(addr, at, pollrec.New(pollrec.KindStatus, c).Str("status", "timeout").Str("detail", "no answer after 1 retry").Record())
				continue
			}
			write(addr, at, pollrec.New(pollrec.KindSys, c).Uint("uptime", uint64(i)*6000).Uint("cpu", uint64(i%100)).Record())
			write(addr, at, pollrec.New(pollrec.KindIf, c).Uint("if", 1).Str("name", "eth1").Str("oper", "up").Uint("in_bps", 1000).Record())
			oper := "up"
			if i%10 == 0 {
				oper = "down"
			}
			write(addr, at, pollrec.New(pollrec.KindIf, c).Uint("if", 2).Str("name", "eth2").Str("oper", oper).Record())
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

func pollFilter(t *testing.T, params map[string]string) *datatype.PollFilter {
	t.Helper()
	pf, err := datatype.ParsePollFilter(func(k string) string { return params[k] })
	if err != nil {
		t.Fatal(err)
	}
	return pf
}

func TestSearchPoll(t *testing.T) {
	f := newPollFixture(t, 200)
	// 200 cycles, 8 timeouts, 192 answered with 3 lines: 584 per device.
	lines := f.all(t, Query{Filter: Filter{Type: TypePoll}, Limit: 97})
	if len(lines) != 2*(192*3+8) {
		t.Fatalf("poll: %d lines", len(lines))
	}
	for _, l := range lines {
		if l.Type != TypePoll || !strings.HasPrefix(string(l.Raw), "kind=") {
			t.Fatalf("poll result %+v", l)
		}
	}
	if got := f.all(t, Query{}); len(got) != 400 {
		t.Fatalf("syslog: %d", len(got))
	}
	cases := []struct {
		params map[string]string
		q      string
		want   int
	}{
		{map[string]string{"kinds": "status"}, "", 16},
		{map[string]string{"poll_status": "timeout"}, "", 16},
		{map[string]string{"kinds": "if", "oper": "down"}, "", 2 * 20},
		{nil, "oper=down", 2 * 20},
		{map[string]string{"ifs": "eth1"}, "", 2 * 192},
		{map[string]string{"kinds": "if", "exclude_ifs": "eth1"}, "", 2 * 192},
		{map[string]string{"reboot": "1"}, "", 0},
		{map[string]string{"kinds": "none"}, "", 0},
	}
	for _, c := range cases {
		var pf *datatype.PollFilter
		if c.params != nil {
			pf = pollFilter(t, c.params)
		}
		if got := f.all(t, Query{Filter: Filter{Type: TypePoll, Q: c.q, Poll: pf}}); len(got) != c.want {
			t.Errorf("%v %q: %d, want %d", c.params, c.q, len(got), c.want)
		}
	}
	// Other types' filters with type=poll are refused, and the reverse.
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Type: TypePoll, Severities: 3}}); err == nil {
		t.Error("severities with type=poll")
	}
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Type: TypePoll, Trap: trapFilter(t, map[string]string{"pdus": "trap"})}}); err == nil {
		t.Error("trap filters with type=poll")
	}
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Poll: pollFilter(t, map[string]string{"kinds": "if"})}}); err == nil {
		t.Error("poll filters with syslog")
	}
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Type: TypeTrap, Poll: pollFilter(t, map[string]string{"kinds": "if"})}}); err == nil {
		t.Error("poll filters with traps")
	}
	// A cursor binds the poll filter.
	from, to := f.start, f.start.Add(2*time.Hour)
	p, _ := f.eng.Search(bg, Query{Filter: Filter{Type: TypePoll, From: from, To: to, Poll: pollFilter(t, map[string]string{"kinds": "if"})}, Limit: 10})
	if _, err := f.eng.Search(bg, Query{Filter: Filter{Type: TypePoll, From: from, To: to, Poll: pollFilter(t, map[string]string{"kinds": "sys"})},
		Limit: 10, Cursor: p.NextCursor}); err == nil {
		t.Error("a cursor for another poll filter accepted")
	}
}

func TestSummaryPoll(t *testing.T) {
	f := newPollFixture(t, 100)
	q := SummaryQuery{Filter: Filter{Type: TypePoll, From: f.start, To: f.start.Add(2 * time.Hour)}, Bucket: time.Hour, Budget: MaxSummaryBudget}
	var s Summary
	for {
		var err error
		if s, err = f.eng.Summary(bg, q); err != nil {
			t.Fatal(err)
		}
		if s.NextCursor == "" {
			break
		}
		q.Cursor = s.NextCursor
	}
	// 100 cycles: 4 timeouts, 96 answered with 3 lines.
	if s.Matched != 2*(96*3+4) {
		t.Fatalf("matched %d", s.Matched)
	}
	byKey := map[string]FieldCounts{}
	for _, fc := range s.Fields {
		byKey[fc.Key] = fc
	}
	if fc := byKey["kind"]; len(fc.Values) != 3 || fc.Values[0].Value != "if" || fc.Values[0].Label != "interface" {
		t.Errorf("kind %+v", fc)
	}
	if fc := byKey["status"]; len(fc.Values) != 2 || fc.Values[1].Value != "timeout" || fc.Values[1].Count != 8 {
		t.Errorf("status %+v", fc)
	}
	if fc := byKey["if"]; len(fc.Values) != 2 {
		t.Errorf("if %+v", fc)
	}
	if _, err := f.eng.Summary(bg, SummaryQuery{Filter: Filter{Type: TypePoll}, Fields: []string{"trap_oid"}}); err == nil {
		t.Error("a trap field for polls")
	}
}
