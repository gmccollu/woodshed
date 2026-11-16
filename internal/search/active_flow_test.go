package search

import (
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store"
)

// Active is exact for flows too: a device is active exactly when one of its
// flow records (or raw sets) was received in [from, to), a gap inside a
// segment included, over random windows.
func TestActiveFlowsIsExact(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(dir + "/" + index.FileName)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	start := time.Date(2026, 11, 13, 22, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: start}
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Manual: true, Clock: clock.Now, Logger: quiet,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := func(hh, mm, ss int) time.Time { return time.Date(2026, 11, 13, hh, mm, ss, 0, time.UTC) }
	type item struct {
		at  time.Time
		dev string
		raw bool
	}
	items := []item{
		{h(22, 0, 0), "192.0.2.1", false}, {h(22, 0, 0), "192.0.2.1", false}, {h(22, 40, 0), "192.0.2.1", false}, // a gap in one segment
		{h(22, 20, 0), "192.0.2.2", false}, {h(23, 10, 0), "192.0.2.2", false},
		{h(22, 30, 0), "192.0.2.3", true}, // only a raw set
	}
	for i, it := range items {
		clock.t = it.at
		ms := it.at.UnixMilli()
		b := store.FlowBatch{Received: it.at}
		if it.raw {
			b.Raw = []*flow.RawSet{{Received: ms, Status: flow.StatusNoTemplate, Version: flow.IPFIX, TemplateID: 300, Data: []byte{1, 2, 3, 4}}}
		} else {
			b.Records = []*flow.Record{{Has: flow.HasStart | flow.HasEnd | flow.HasSrc, Received: ms, Start: ms - 1000, End: ms,
				Src: netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), Sampling: 1}}
		}
		if err := st.WriteFlows(netip.MustParseAddr(it.dev), b); err != nil {
			t.Fatal(err)
		}
		if err := st.Maintain(); err != nil { // a block per item
			t.Fatal(err)
		}
	}
	// The second hour's segment stays open (no footer): Active reads it live.
	eng := New(Options{DataDir: dir, Index: idx, Now: clock.Now, Logger: quiet})
	types := []string{"flow"}
	check := func(from, to time.Time) {
		t.Helper()
		got, err := eng.Active(bg, types, from, to)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]bool{}
		for _, it := range items {
			if !it.at.Before(from) && it.at.Before(to) {
				want[it.dev] = true
			}
		}
		if len(got) != len(want) {
			t.Fatalf("[%v, %v): got %v, want %v", from.Format("15:04:05"), to.Format("15:04:05"), got, want)
		}
		for d := range want {
			if len(got[d]) != 1 || got[d][0] != "flow" {
				t.Fatalf("[%v, %v): %s missing: %v", from.Format("15:04:05"), to.Format("15:04:05"), d, got)
			}
		}
	}
	check(h(22, 10, 0), h(22, 15, 0)) // inside 192.0.2.1's gap: nobody
	check(h(22, 0, 0), h(22, 0, 1))
	check(h(22, 39, 59), h(22, 40, 0))
	check(h(22, 25, 0), h(22, 35, 0)) // the raw set only
	check(h(23, 0, 0), h(23, 30, 0))  // the open segment
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		from := start.Add(time.Duration(r.Int63n(int64(80 * time.Minute)))).Truncate(time.Millisecond)
		check(from, from.Add(time.Duration(1+r.Int63n(int64(20*time.Minute)))).Truncate(time.Millisecond))
	}
}
