package search

import (
	"fmt"
	"math/rand"
	"net/netip"
	"slices"
	"sort"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Active (the bundle's active_devices, SPEC §11.3) is exact: compared with
// the records written, over random windows and the edges, a device is active
// exactly when it stored a record of the type in [from, to).
func TestActiveIsExact(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(dir + "/" + index.FileName)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	start := time.Date(2026, 11, 13, 22, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: start}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, PartBytes: 4 << 10, Manual: true, Clock: clock.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	type rec struct {
		at       time.Time
		dev, typ string
	}
	var recs []rec
	type item struct {
		at  time.Time
		dev netip.Addr
		typ string
	}
	var items []item
	add := func(dev string, typ string, ats ...time.Time) {
		for _, at := range ats {
			items = append(items, item{at: at, dev: netip.MustParseAddr(dev), typ: typ})
		}
	}
	h := func(hh, mm, ss int, ms ...int) time.Time {
		t := time.Date(2026, 11, 13, hh, mm, ss, 0, time.UTC)
		if len(ms) > 0 {
			t = t.Add(time.Duration(ms[0]) * time.Millisecond)
		}
		return t
	}
	// Sparse: a gap inside one file, so only a read can tell.
	add("192.0.2.1", logfile.TypeSyslog, h(22, 0, 0), h(23, 59, 0))
	// Exactly at the edges of 23:00–23:30.
	add("192.0.2.2", logfile.TypeSyslog, h(23, 0, 0), h(23, 50, 0))
	add("192.0.2.3", logfile.TypeSyslog, h(22, 10, 0), h(23, 30, 0))
	add("192.0.2.4", logfile.TypeSyslog, h(22, 59, 59, 999))
	// Traps only.
	add("192.0.2.5", logfile.TypeTrap, h(23, 10, 0), h(23, 40, 0, 500))
	// Dense: every 7 s for two hours (many parts and checkpoints).
	for at := h(22, 0, 3); at.Before(h(23, 59, 59)); at = at.Add(7 * time.Second) {
		add("192.0.2.6", logfile.TypeSyslog, at)
	}
	// Dense with a hole from 23:00 to 23:20.
	for at := h(22, 0, 1); at.Before(h(23, 59, 59)); at = at.Add(3 * time.Second) {
		if at.Before(h(23, 0, 0)) || !at.Before(h(23, 20, 0)) {
			add("192.0.2.7", logfile.TypeSyslog, at)
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].at.Before(items[j].at) })
	for n, it := range items {
		clock.Set(it.at)
		m := model.Message{Received: it.at, Sender: it.dev, Raw: []byte(fmt.Sprintf("<14>host app: line %d with some padding to fill parts", n))}
		if it.typ == logfile.TypeSyslog {
			err = st.Write(m)
		} else {
			err = st.WriteType(it.typ, m)
		}
		if err != nil {
			t.Fatal(err)
		}
		recs = append(recs, rec{at: it.at, dev: model.DeviceID(it.dev), typ: it.typ})
		if n%97 == 0 {
			st.Maintain()
		}
	}
	end := h(23, 59, 59)
	clock.Set(end)
	st.Flush()
	st.Maintain()
	eng := New(Options{DataDir: dir, Index: idx, Now: clock.Now, Logger: quiet})

	types := []string{logfile.TypeSyslog, logfile.TypeTrap}
	want := func(from, to time.Time) map[string][]string {
		out := map[string][]string{}
		for _, typ := range types {
			for _, r := range recs {
				if r.typ == typ && !r.at.Before(from) && r.at.Before(to) && !slices.Contains(out[r.dev], typ) {
					out[r.dev] = append(out[r.dev], typ)
				}
			}
		}
		return out
	}
	check := func(from, to time.Time) {
		t.Helper()
		got, err := eng.Active(bg, types, from, to)
		if err != nil {
			t.Fatal(err)
		}
		w := want(from, to)
		if fmt.Sprint(sorted(got)) != fmt.Sprint(sorted(w)) {
			t.Errorf("[%s, %s): got %v, want %v", from.Format("15:04:05.000"), to.Format("15:04:05.000"), sorted(got), sorted(w))
		}
	}
	// The edges: from is included, to isn't.
	check(h(23, 0, 0), h(23, 30, 0))
	check(h(23, 0, 0, 1), h(23, 30, 0, 1))
	check(h(22, 59, 59, 999), h(23, 0, 0))
	check(h(23, 5, 0), h(23, 15, 0))
	check(h(23, 40, 0, 500), h(23, 40, 0, 501))
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 300; i++ {
		from := start.Add(time.Duration(r.Int63n(int64(2 * time.Hour))))
		to := from.Add(time.Duration(1 + r.Int63n(int64(20*time.Minute))))
		check(from.Truncate(time.Millisecond), to.Truncate(time.Millisecond))
	}
	if got, _ := eng.Active(bg, types, h(23, 0, 0), h(23, 0, 0)); len(got) != 0 {
		t.Errorf("an empty range: %v", got)
	}
	if _, err := eng.Active(bg, []string{"flow"}, h(23, 0, 0), h(23, 1, 0)); err == nil {
		t.Error("an unknown type")
	}
}

func sorted(m map[string][]string) []string {
	var out []string
	for d, ts := range m {
		out = append(out, d+":"+fmt.Sprint(ts))
	}
	sort.Strings(out)
	return out
}
