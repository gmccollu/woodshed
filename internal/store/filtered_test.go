package store

import (
	"fmt"
	"net/netip"
	"runtime"
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

// A device the store knows is counted under its own ID even when its shard of
// the pending table is full of new senders, and is heard.
func TestFilteredKnownDeviceExactInAFullShard(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxDevices = 10 })
	known := ip(16) // shard 0
	if known.As16()[15]%filtShards != 0 {
		t.Fatal("shard")
	}
	e.write(known, "<13>stored notice")
	e.maintain()
	e.clock.Add(time.Minute)
	for i := 0; i < maxFiltPending; i++ {
		e.s.Filtered(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), e.clock.Now(), 6)
	}
	for i := 0; i < 3; i++ {
		e.s.Filtered(known, e.clock.Now(), 7)
	}
	e.maintain()
	id := "192.0.2.16"
	got, _ := e.idx.FilteredCounts(bg, nil, time.Time{}, time.Time{})
	if got[id][7] != 3 || got[id].Total() != 3 {
		t.Fatalf("the known device %v", got[id])
	}
	var info int64
	for _, c := range got {
		info += c[6]
	}
	if info != maxFiltPending {
		t.Fatalf("the new senders' total %d", info)
	}
	if d, err := e.idx.Device(bg, id); err != nil || !d.LastHeard.Equal(e.clock.Now()) {
		t.Fatalf("not heard: %+v %v", d, err)
	}
	// The device limits refused most new senders: none of that names a reason
	// for a device_limit event (nothing was refused as a message).
	e.s.refMu.Lock()
	reason, pending := e.s.refReason, e.s.refPending
	e.s.refMu.Unlock()
	if reason != "" || pending != 0 {
		t.Fatalf("refusal noted for filtered-only senders: %q %d", reason, pending)
	}
}

// The running 24-hour totals agree with the index, survive a restart (seeded
// from the index), and age out after 24 hours.
func TestFiltered24hTotals(t *testing.T) {
	e := newEnv(t, nil)
	a, b := ip(30), ip(31)
	for i := 0; i < 4; i++ {
		e.s.Filtered(a, e.clock.Now(), 7)
	}
	e.s.Filtered(b, e.clock.Now(), 6)
	if got := e.s.Filtered24h(nil); len(got) != 0 {
		t.Fatalf("before the maintenance pass %v", got)
	}
	e.maintain()
	e.clock.Add(90 * time.Minute)
	e.s.Filtered(a, e.clock.Now(), 6)
	e.maintain()
	want, _ := e.idx.FilteredCounts(bg, nil, e.clock.Now().Add(-24*time.Hour), time.Time{})
	check := func(when string) {
		t.Helper()
		got := e.s.Filtered24h(nil)
		if len(got) != 2 || got["192.0.2.30"] != want["192.0.2.30"] || got["192.0.2.31"] != want["192.0.2.31"] ||
			got["192.0.2.30"][7] != 4 || got["192.0.2.30"][6] != 1 {
			t.Fatalf("%s: %v, index %v", when, got, want)
		}
		if one := e.s.Filtered24h([]string{"192.0.2.31", "192.0.2.99"}); len(one) != 1 || one["192.0.2.31"][6] != 1 {
			t.Fatalf("%s: by id %v", when, one)
		}
	}
	check("running")
	e.reopen()
	check("after a restart")
	e.clock.Add(24 * time.Hour)
	if got := e.s.Filtered24h(nil); len(got) != 1 || got["192.0.2.30"].Total() != 1 {
		t.Fatalf("a day later %v", got)
	}
}

// The run-state path's read at 500 filtering devices with every hour of the
// last 24 filled.
func BenchmarkFiltered24h500Devices(b *testing.B) {
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
	hr := time.Now().Unix() / 3600
	for i := 0; i < 500; i++ {
		for h := int64(0); h < filtHourSpan; h++ {
			s.ftot.add(netip.AddrFrom4([4]byte{10, 0, byte(i / 250), byte(i % 250)}).String(), hr-h, index.SevCounts{7: 2400, 6: 120})
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := s.Filtered24h(nil); len(got) != 500 {
			b.Fatal(len(got))
		}
	}
}

// The running totals keep only the hours with any, and at most
// maxFiltTracked device IDs: a new ID past the cap counts under the refused
// bucket, so the total stays exact.
func TestFilteredTotalsSparseAndCapped(t *testing.T) {
	var ft filtTotals
	hr := int64(500_000)
	ft.add("a", hr-30, index.SevCounts{7: 1}) // out of the window once newer hours come
	ft.add("a", hr-3, index.SevCounts{7: 2})
	ft.add("a", hr, index.SevCounts{7: 3})
	ft.add("a", hr-1, index.SevCounts{6: 1}) // an older hour, in order
	if h := ft.dev["a"]; len(h) != 3 || int64(h[0].hour) != hr-3 || int64(h[1].hour) != hr-1 || int64(h[2].hour) != hr {
		t.Fatalf("hours %+v", h)
	}
	if c := sumHours(ft.dev["a"], hr); c[7] != 5 || c[6] != 1 {
		t.Fatalf("sum %v", c)
	}
	for i := 0; i < maxFiltTracked+5; i++ {
		ft.add(fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255), hr, index.SevCounts{7: 1})
	}
	if len(ft.dev) != maxFiltTracked+1 {
		t.Fatalf("%d ids tracked", len(ft.dev))
	}
	var tot int64
	for _, h := range ft.dev {
		tot += sumHours(h, hr).Total()
	}
	if tot != 6+maxFiltTracked+5 || sumHours(ft.dev[index.RefusedDeviceID], hr)[7] < 5 {
		t.Fatalf("total %d, refused %v", tot, sumHours(ft.dev[index.RefusedDeviceID], hr))
	}
}

// Bytes per device ID in the running totals, for the review's numbers (run
// with -v): one hour with any (a sender heard once), and every hour of the
// window (a device that filters all day).
func TestFilteredTotalsBytesPerDevice(t *testing.T) {
	measure := func(hours int) float64 {
		const n = 10_000
		runtime.GC()
		var a, b runtime.MemStats
		runtime.ReadMemStats(&a)
		ft := &filtTotals{}
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("10.%d.%d.%d", i>>16, (i>>8)&255, i&255)
			for h := 0; h < hours; h++ {
				ft.add(id, int64(500_000+h), index.SevCounts{7: 40, 6: 2})
			}
		}
		runtime.GC()
		runtime.ReadMemStats(&b)
		runtime.KeepAlive(ft)
		return float64(b.HeapAlloc-a.HeapAlloc) / n
	}
	one, all := measure(1), measure(filtHourSpan)
	t.Logf("bytes per device ID: %.0f with one hour, %.0f with all %d", one, all, filtHourSpan)
	if one <= 0 || all <= one {
		t.Logf("(heap noise: %v %v)", one, all)
	}
}

// The reader's path takes no store-wide lock, even when a shard is full and
// it has to tell a known device from a new sender: with devMu held (as
// admissions and the prefix prune hold it during a flood), Filtered still
// returns, and counts the known device under its own ID.
func TestFilteredTakesNoStoreLock(t *testing.T) {
	e := newEnv(t, nil)
	known := ip(16) // shard 0
	e.write(known, "<13>stored")
	e.maintain()
	for i := 0; i < maxFiltPending; i++ {
		e.s.Filtered(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), e.clock.Now(), 6)
	}
	e.s.devMu.Lock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		e.s.Filtered(known, e.clock.Now(), 7)                               // known: its own entry
		e.s.Filtered(netip.MustParseAddr("10.255.255.0"), e.clock.Now(), 7) // new: the overflow
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Filtered waited for devMu")
	}
	e.s.devMu.Unlock()
	sh := &e.s.filt.shards[0]
	sh.mu.Lock()
	_, own := sh.m[filtKey{known, e.clock.Now().UnixMilli() / 60000}]
	sh.mu.Unlock()
	if !own {
		t.Fatal("the known device went to the overflow")
	}
}
