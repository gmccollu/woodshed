package flowseg

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"testing"
)

// The writer's memory over an hour of ingest (SPEC §13.10 decision 57). A
// simulated store drives one Writer per exporter as internal/store does:
// blocks at the exporter's rate, the index rows read after each one (the
// store's flush), a new part at FlowPartBytes or FlowPartBlocks, and every
// exporter's segment closed at the hour mark, one after another (the
// store's single ingest goroutine and its maintenance pass). Blocks after
// a part's first aren't encoded: each part starts with one real block of
// the case's size (its header the size loadgen's traffic gives, the Bloom
// filter most of it), and the rest are directory entries over a sparse
// stretch of the file whose header span is the first block's. Each is as
// long as a real block of the case's records at hourRecordBytes (the
// test's own records compress far better than real traffic), so parts
// rotate as a real hour's do. The writer's directory, the footers it
// streams and the part sizes are a real hour's.

// The store's part limits (store.FlowPartBytes, store.FlowPartBlocks; the
// store imports this package).
const (
	hourPartBytes  = 256 << 20
	hourPartBlocks = 8192
)

// hourRecordBytes is a stored record's bytes at these rates (SPEC §13.6's
// first bench: 20.2 at 50,000 a second, 21.9 at 5,000).
const hourRecordBytes = 20

// hourRows is what the store reads for a flush's index rows; hourClose is
// how it closes a segment.
func hourRows(w *Writer) *Footer           { return w.Summary() }
func hourClose(w *Writer) (*Footer, error) { return w.CloseSummary() }

type hourCase struct {
	name      string
	exporters int
	rows      int // records a block
	hosts     int // distinct hosts a block (bigHeaderWriter)
	perSec    int // blocks a second per exporter
	seconds   int // the "hour"
}

type hourStats struct {
	fixed     uint64 // an exporter's heap at the hour's start (its writer, one block written)
	peak      uint64 // heap above the start, over the hour (part closes included)
	closePeak uint64 // above the heap before the hour mark, while every exporter closes
	grown     uint64 // live heap the hour added (after a GC, before the hour mark)
	alloc     uint64 // bytes allocated over the hour
	parts     int    // segments written
	blocks    int    // blocks an exporter wrote
	footer    int64  // the largest footer body
	hdrLen    int64  // a block header's bytes
	secLen    int64  // a block's bytes
}

// hourExporter is one exporter's open segment.
type hourExporter struct {
	dir    string
	part   int
	w      *Writer
	sec    []byte // a real block section, as written at each part's start
	length int64  // every later block's bytes
	bi     BlockInfo
	hdrAt  int64 // the header's offset within sec
	hdrOff int64 // the current part's first header in the file
}

func (e *hourExporter) path() string {
	return filepath.Join(e.dir, Name{Day: "2026-11-16", Hour: 9, Part: e.part}.String())
}

// newPart starts the exporter's next part with its real block.
func (e *hourExporter) newPart(t *testing.T) {
	e.part++
	w, err := Create(e.path(), "10.1.0.1", testHour, "test")
	if err != nil {
		t.Fatal(err)
	}
	off := w.st.off
	if _, err := w.f.WriteAt(e.sec, off); err != nil {
		t.Fatal(err)
	}
	e.hdrOff = off + e.hdrAt
	w.st.addBlock(&e.bi, off, int64(len(e.sec)), e.hdrOff, e.bi.hdrLen)
	hourRows(w)
	e.w = w
}

// addBlock records one more block, as a flush would, rotating first.
func (e *hourExporter) addBlock(t *testing.T, s *hourStats) {
	if e.w.Size() >= hourPartBytes || len(e.w.st.blocks) >= hourPartBlocks {
		e.close(t, s)
		e.newPart(t)
		s.parts++
		return
	}
	e.w.st.addBlock(&e.bi, e.w.st.off, e.length, e.hdrOff, e.bi.hdrLen)
	hourRows(e.w)
}

func (e *hourExporter) close(t *testing.T, s *hourStats) {
	path := e.path()
	if _, err := hourClose(e.w); err != nil {
		t.Fatal(err)
	}
	e.w = nil
	if fi, err := os.Stat(path); err == nil {
		f, _ := os.Open(path)
		var tr [trailerLen]byte
		f.ReadAt(tr[:], fi.Size()-trailerLen)
		f.Close()
		s.footer = max(s.footer, int64(uint32(tr[0])|uint32(tr[1])<<8|uint32(tr[2])<<16|uint32(tr[3])<<24))
	}
	os.Remove(path)
}

func heapAllocs() uint64 {
	s := []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}}
	metrics.Read(s)
	return s[0].Value.Uint64()
}

// runHour runs case c at GOGC gc (a low one makes the peak what's live
// plus any transient spike, not the collector's headroom over the rest of
// the heap).
func runHour(t *testing.T, c hourCase, gc int) hourStats {
	t.Helper()
	noSync(t)
	defer debug.SetGCPercent(debug.SetGCPercent(gc))
	root := t.TempDir()
	var s hourStats
	exps := make([]*hourExporter, c.exporters)
	runtime.GC()
	h0 := heapInuse()
	for i := range exps {
		dir := filepath.Join(root, fmt.Sprint(i))
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
		e := &hourExporter{dir: dir}
		// The hour's first part: a real block, then its section kept.
		e.w = bigHeaderWriter(t, e.path(), c.rows, c.hosts)
		bi := e.w.Snapshot().Blocks[0]
		e.sec = make([]byte, bi.Length)
		if _, err := e.w.f.ReadAt(e.sec, bi.Offset); err != nil {
			t.Fatal(err)
		}
		e.hdrAt, e.hdrOff = bi.hdrOff-bi.Offset, bi.hdrOff
		readHeader(&dec{b: e.sec[e.hdrAt : e.hdrAt+bi.hdrLen]}, &e.bi)
		if !e.bi.loaded {
			t.Fatal("the block's header doesn't parse")
		}
		e.bi.hdrLen = bi.hdrLen
		e.length = max(bi.Length, int64(c.rows)*hourRecordBytes)
		s.hdrLen, s.secLen = bi.hdrLen, e.length
		exps[i] = e
	}
	runtime.GC()
	if h := heapInuse(); h > h0 {
		var secs int64
		for _, e := range exps {
			secs += int64(cap(e.sec))
		}
		s.fixed = (h - h0 - uint64(secs)) / uint64(c.exporters)
	}
	s.parts = c.exporters
	a0 := heapAllocs()
	var grownBase uint64
	s.peak, grownBase = peakDuring(func() {
		for sec := 0; sec < c.seconds; sec++ {
			for _, e := range exps {
				for k := 0; k < c.perSec; k++ {
					if sec == 0 && k == 0 {
						continue // the part's real block
					}
					e.addBlock(t, &s)
				}
			}
		}
	})
	s.alloc = heapAllocs() - a0
	s.blocks = c.seconds * c.perSec
	runtime.GC()
	runtime.GC()
	if h := heapInuse(); h > grownBase {
		s.grown = h - grownBase
	}
	s.closePeak, _ = peakDuring(func() {
		for _, e := range exps {
			e.close(t, &s)
		}
	})
	runtime.KeepAlive(exps)
	return s
}

func (s hourStats) log(t *testing.T, c hourCase) {
	mib := func(v uint64) float64 { return float64(v) / (1 << 20) }
	t.Logf("%s: %d exporters x %d blocks (%d-byte blocks, %d-byte headers), %d segments, largest footer %.1f MB: "+
		"%.2f MiB an exporter at the start; peak %.1f MiB over the hour, %.1f MiB at the hour mark; the hour kept %.1f MiB "+
		"(%.0f B a block); %.0f MiB allocated",
		c.name, c.exporters, s.blocks, s.secLen, s.hdrLen, s.parts, float64(s.footer)/1e6, mib(s.fixed), mib(s.peak),
		mib(s.closePeak), mib(s.grown), float64(s.grown)/float64(c.exporters*s.blocks), mib(s.alloc))
}

// hourCases are the three ingest shapes (SPEC §13.6): 50,000 records a second
// from one exporter (one block a second), 150,000 from one (two full blocks
// and a remainder a second; every block full here), and 150,000 over 50
// exporters (3,000 each, one block a second). The header sizes are
// loadgen's at those block sizes. short scales the hour down.
func hourCases(short bool) []hourCase {
	cs := []hourCase{
		{"50k/s, 1 exporter", 1, 50_000, 9000, 1, 3600},
		{"150k/s, 1 exporter", 1, 65_536, 9900, 3, 3600},
		{"150k/s, 50 exporters", 50, 3000, 1560, 1, 3600},
	}
	if short {
		cs[0].seconds, cs[1].seconds = 600, 300
		cs[2].exporters, cs[2].seconds = 10, 900
	}
	return cs
}

// An hour of ingest keeps the writer's heap flat but for the directory's
// 216 bytes a block (at most FlowPartBlocks of them a segment), and the
// hour mark, when every exporter closes, adds about nothing: the footers
// are streamed, the index rows come from Summary, and CloseSummary builds
// no directory. Measured at GOGC 10, so the peak is what's live plus any
// spike (the old writer held about 4 times each footer while closing it).
func TestWriterHourHeapBounded(t *testing.T) {
	if raceEnabled {
		t.Skip("race: the heap ceilings are for the real build")
	}
	for _, c := range hourCases(testing.Short()) {
		s := runHour(t, c, 10)
		s.log(t, c)
		dir := uint64(c.exporters) * uint64(min(s.blocks, hourPartBlocks)) * 216
		if lim := dir*5/4 + 24<<20; s.peak > lim {
			t.Errorf("%s: peak %.1f MiB over the hour, ceiling %.1f MiB", c.name, float64(s.peak)/(1<<20), float64(lim)/(1<<20))
		}
		if per := s.grown / uint64(c.exporters*min(s.blocks, hourPartBlocks)); per > 300 {
			t.Errorf("%s: the hour kept %d bytes a block", c.name, per)
		}
		if s.closePeak > 8<<20 {
			t.Errorf("%s: %.1f MiB of heap at the hour mark", c.name, float64(s.closePeak)/(1<<20))
		}
		if c.exporters > 1 && s.parts != c.exporters {
			t.Errorf("%s: %d segments, want one an exporter", c.name, s.parts)
		}
	}
}
