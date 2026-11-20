package store

import (
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
)

// Filtered messages count in the device's stats per minute and severity,
// exactly, beside the stored ones; they make the device heard but add no
// line, no file and no stored message; and the counts survive a restart.
func TestFilteredCountsInStats(t *testing.T) {
	e := newEnv(t, nil)
	ap := ip(10)
	e.write(ap, "<14>stored info")
	for i := 0; i < 5; i++ {
		e.s.Filtered(ap, e.clock.Now(), 7)
	}
	e.s.Filtered(ap, e.clock.Now(), 6)
	e.clock.Add(time.Minute)
	e.s.Filtered(ap, e.clock.Now(), 7)
	e.s.Filtered(netip.MustParseAddr("::ffff:192.0.2.10"), e.clock.Now(), 7) // the same device
	e.maintain()

	id := "192.0.2.10"
	got, err := e.idx.FilteredCounts(bg, []string{id}, time.Time{}, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if c := got[id]; c[7] != 7 || c[6] != 1 || c.Total() != 8 {
		t.Fatalf("filtered %v", got)
	}
	if c, _ := e.idx.Counts(bg, []string{id}, time.Time{}, time.Time{}); c.Msgs != 1 || c.Dropped != 0 {
		t.Fatalf("stored counts %+v", c)
	}
	d, err := e.idx.Device(bg, id)
	if err != nil || d.TotalMsgs != 1 || !d.LastHeard.Equal(e.clock.Now()) {
		t.Fatalf("device %+v %v (want last heard %v)", d, err, e.clock.Now())
	}
	if lines := readLines(t, e.dir, id); len(lines) != 1 {
		t.Fatalf("lines %d", len(lines))
	}
	if u := e.s.Usage(); u.Filtered != 8 || u.Dropped != 0 {
		t.Fatalf("usage filtered %d dropped %d", u.Filtered, u.Dropped)
	}

	// Counted before a stop, read after the restart.
	e.s.Filtered(ap, e.clock.Now(), 5)
	e.reopen()
	got, _ = e.idx.FilteredCounts(bg, []string{id}, time.Time{}, time.Time{})
	if c := got[id]; c.Total() != 9 || c[5] != 1 {
		t.Fatalf("after the restart %v", got)
	}
}

// A sender that sends only filtered messages becomes a device (admitted like
// any sender, so the device limits hold); one refused by the limits counts
// under the refused bucket, so the total is still exact.
func TestFilteredNewSenders(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.NewDeviceBurst, o.NewDevicesPerMinute, o.PrefixBurst = 1, 1, 1 })
	e.s.Filtered(ip(20), e.clock.Now(), 7)
	e.s.Filtered(ip(21), e.clock.Now(), 7) // over the burst
	e.s.Filtered(ip(21), e.clock.Now(), 7)
	e.maintain()
	got, _ := e.idx.FilteredCounts(bg, nil, time.Time{}, time.Time{})
	if got["192.0.2.20"][7] != 1 || got[index.RefusedDeviceID][7] != 2 || len(got) != 2 {
		t.Fatalf("filtered %v", got)
	}
	if _, err := e.idx.Device(bg, "192.0.2.20"); err != nil {
		t.Fatalf("no device row: %v", err)
	}
	if _, err := e.idx.Device(bg, "192.0.2.21"); err == nil {
		t.Fatal("a refused sender has a device row")
	}
	if c, _ := e.idx.Counts(bg, nil, time.Time{}, time.Time{}); c.Dropped != 0 {
		t.Fatalf("filtered messages counted as drops: %+v", c)
	}
}

// Many writers at once (the UDP reader and TCP connections) lose no count,
// and the pending table's cap sends the overflow to the refused bucket
// without losing any either.
func TestFilteredConcurrentAndCapped(t *testing.T) {
	e := newEnv(t, nil)
	const writers, each = 8, 2000
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				e.s.Filtered(ip(1+w), e.clock.Now(), 7)
			}
		}(w)
	}
	wg.Wait()
	// Over the cap in one shard: addresses that all land on shard 0.
	for i := 0; i < maxFiltPending+10; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0})
		if a.As16()[15]%filtShards != 0 {
			t.Fatal("shard")
		}
		e.s.Filtered(a, e.clock.Now(), 6)
	}
	e.maintain()
	tot, err := e.idx.FilteredTotal(bg, time.Time{})
	if err != nil || tot[7] != writers*each || tot[6] != maxFiltPending+10 {
		t.Fatalf("total %v %v", tot, err)
	}
}

func BenchmarkFiltered(b *testing.B) {
	dir := b.TempDir()
	idx, err := index.Open(dir + "/" + index.FileName)
	if err != nil {
		b.Fatal(err)
	}
	defer idx.Close()
	s, err := Open(Options{DataDir: dir, Index: idx, Manual: true, Logger: quiet})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	from, at := ip(10), time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		s.Filtered(from, at, 7)
	}
}
