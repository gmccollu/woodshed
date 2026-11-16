package flowseg

import (
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// heapInuse is the heap's in-use spans (objects and the free room in their
// spans), as runtime.MemStats.HeapInuse, read without stopping the world.
func heapInuse() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}, {Name: "/memory/classes/heap/unused:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64() + s[1].Value.Uint64()
}

// peakDuring samples heapInuse every millisecond while fn runs and returns
// the peak above the heap before it (after a GC).
func peakDuring(fn func()) (peak, base uint64) {
	runtime.GC()
	runtime.GC() // sync.Pool's victims go on the second
	base = heapInuse()
	var top atomic.Uint64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Millisecond)
		defer t.Stop()
		for {
			if h := heapInuse(); h > top.Load() {
				top.Store(h)
			}
			select {
			case <-stop:
				return
			case <-t.C:
			}
		}
	}()
	fn()
	close(stop)
	wg.Wait()
	if h := heapInuse(); h > top.Load() {
		top.Store(h)
	}
	if top.Load() < base {
		return 0, base
	}
	return top.Load() - base, base
}

// bigHeaderWriter starts a segment with one real block of rows records over
// hosts distinct sources, destinations and ports (9,000 at 50,000 rows gives
// loadgen's header size, about 34 KB, the Bloom filter most of it), flushed.
func bigHeaderWriter(t *testing.T, path string, rows, hosts int) *Writer {
	t.Helper()
	w, err := Create(path, "10.1.0.1", testHour, "test")
	if err != nil {
		t.Fatal(err)
	}
	r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort |
		flow.HasProto | flow.HasBytes | flow.HasInIf, Sampling: 1, Proto: 6}
	for i := 0; i < rows; i++ {
		ms := testHour.UnixMilli() + int64(i)*999/int64(rows)
		r.Received, r.End, r.Start = ms, ms, ms-100
		s, d := i%hosts, (i*7)%hosts
		r.Src = netip.AddrFrom4([4]byte{10, 0, byte(s >> 8), byte(s)})
		r.Dst = netip.AddrFrom4([4]byte{172, 16, byte(d >> 8), byte(d)})
		r.SrcPort, r.DstPort, r.InIf, r.Bytes = uint16(1024+i%hosts), 443, uint32(i%7), uint64(i)
		if err := w.Append(&r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return w
}

// repeatBlock makes the writer's segment hold n blocks with the first one's
// large header, without encoding n blocks: blocks 2..n are directory entries
// over a sparse stretch of the file (a hole as long as the header) whose
// header span is the first block's. Their content is never read (a
// footer's copy is what readFooterStream and Reader.Block use), so the
// footer the writer builds is exactly a real n-block segment's in size.
func repeatBlock(t *testing.T, w *Writer, n int) (hdrLen int64) {
	t.Helper()
	snap := w.Snapshot()
	if len(snap.Blocks) != 1 {
		t.Fatalf("%d blocks", len(snap.Blocks))
	}
	b0 := snap.Blocks[0]
	hdr := make([]byte, b0.hdrLen)
	if _, err := w.f.ReadAt(hdr, b0.hdrOff); err != nil {
		t.Fatal(err)
	}
	var bi BlockInfo
	readHeader(&dec{b: hdr}, &bi)
	if !bi.loaded {
		t.Fatal("the header doesn't parse")
	}
	length := max(b0.hdrLen, prefixLen)
	for i := 1; i < n; i++ {
		w.st.addBlock(&bi, w.st.off, length, b0.hdrOff, b0.hdrLen)
	}
	if err := w.f.Truncate(w.st.off); err != nil { // the hole
		t.Fatal(err)
	}
	w.TakeMinutes()
	return b0.hdrLen
}

// Closing a segment of many blocks with large headers stays under a small
// fixed heap ceiling, the same for 1,000 and 4,000 blocks (35 and 140 MB
// footers): the tail is written through a bounded buffer and Close returns
// the directory only.
func TestCloseHeapBounded(t *testing.T) {
	noSync(t)
	const ceiling = 8 << 20
	for _, n := range []int{1000, 4000} {
		path := filepath.Join(t.TempDir(), "a.wsf")
		w := bigHeaderWriter(t, path, 50_000, 9000)
		hl := repeatBlock(t, w, n)
		var foot *Footer
		var err error
		var alloc uint64
		peak, base := peakDuring(func() {
			a0 := heapAllocs()
			foot, err = w.Close()
			alloc = heapAllocs() - a0
		})
		if err != nil {
			t.Fatal(err)
		}
		// What Close allocated in all, which a sampled peak could miss.
		if alloc > ceiling {
			t.Fatalf("%d blocks: Close allocated %.1f MiB, over the %d MiB ceiling", n, float64(alloc)/(1<<20), ceiling>>20)
		}

		t.Logf("%d blocks, %d-byte headers (footer about %.1f MB): Close's peak heap %.2f MiB above %.1f MiB",
			n, hl, float64(int64(n)*hl)/1e6, float64(peak)/(1<<20), float64(base)/(1<<20))
		if peak > ceiling {
			t.Fatalf("%d blocks: Close's peak heap %.1f MiB, over the %d MiB ceiling", n, float64(peak)/(1<<20), ceiling>>20)
		}
		if len(foot.Blocks) != n {
			t.Fatalf("%d blocks in the footer", len(foot.Blocks))
		}
		// The segment reads back: every block's index from the footer's copy.
		rd, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, i := range []int{0, 1, n / 2, n - 1} {
			bi, err := rd.Block(i)
			if err != nil || !bi.loaded || bi.Rows != 50_000 || !bi.MayHaveAddr(netip.MustParseAddr("10.0.35.39")) {
				t.Fatalf("block %d: %v %+v", i, err, bi)
			}
		}
		rd.Close()

		os.Remove(path)
	}
}
