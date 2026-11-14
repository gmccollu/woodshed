package search

import (
	"fmt"
	"github.com/gmccollu/woodshed/internal/index"
	"testing"
	"time"
)

// TestSummaryGzipRoundsReadEachByteOnce: a summary over closed (gzipped) days
// that takes many requests decompresses each byte about once, because a pass
// paused by the budget keeps its reader for the next request.
func TestSummaryGzipRoundsReadEachByteOnce(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("big part")
	}
	// One large part per device per day: the first two days are compressed.
	// About 300 one-block requests serially (850 with WOODSHED_LONG_TESTS=1).
	perDay, minGz := 2500, int64(1<<20)
	if longTests {
		perDay, minGz = 6000, 2<<20
	}
	f := newFixtureParts(t, 3, perDay, 64<<20)
	q := SummaryQuery{Filter: Filter{From: f.day0, To: f.day0.Add(48 * time.Hour)}, Top: MaxTop, forceScan: true}
	files, _ := f.idx.Files(bg, "")
	var gz, gzFiles int64
	for _, fl := range files {
		if fl.Compressed && fl.FirstReceived.Before(q.To) && fl.DeviceID != "2001_db8__5" { // the hidden device isn't searched
			gz += fl.RawSize
			gzFiles++
		}
	}
	if gzFiles < 6 || gz < minGz {
		t.Fatalf("fixture: %d gz files, %d bytes", gzFiles, gz)
	}
	want := f.expect(Query{Filter: q.Filter})
	f.eng.testMaxSteps = 1 // every request reads one block of a pass, then the budget is gone
	for _, c := range []struct {
		name    string
		workers int
		noKeep  bool
	}{{"serial", 1, false}, {"parallel", 4, false}, {"without kept readers (1.1 build before the fix)", 1, true}} {
		f.eng.sumWorkers, f.eng.sumNoKeep = c.workers, c.noKeep
		before, start := f.eng.inflated.Load(), time.Now()
		s, pages := f.runSummary(t, c.name, q, want)
		took := time.Since(start)
		inflated := f.eng.inflated.Load() - before
		ratio := float64(inflated) / float64(gz)
		t.Logf("%s: %d requests in %s (with the brute-force check of each), decompressed %d bytes for %d bytes of .gz content (%.2fx)",
			c.name, pages, took.Round(time.Millisecond), inflated, gz, ratio)
		if s.Matched != int64(len(want)) {
			t.Errorf("%s: matched %d, want %d", c.name, s.Matched, len(want))
		}
		if pages < 50 {
			t.Errorf("%s: only %d requests; the rounds aren't exercised", c.name, pages)
		}
		if !c.noKeep && ratio > 1.1 {
			t.Errorf("%s: decompressed %.2fx the content", c.name, ratio)
		}
		if c.noKeep && ratio < 10 {
			t.Errorf("without kept readers: only %.2fx; the comparison shows nothing", ratio)
		}
	}
}

func TestSummaryKeptReadersClose(t *testing.T) {
	t.Parallel()
	f := newFixtureParts(t, 2, 2000, 64<<20)
	f.eng.testMaxSteps, f.eng.sumWorkers = 1, 1
	q := SummaryQuery{Filter: Filter{From: f.day0, To: f.day0.Add(24 * time.Hour)}, forceScan: true}
	s, err := f.eng.Summary(bg, q)
	if err != nil || s.NextCursor == "" {
		t.Fatal(err)
	}
	st := func() *sumState {
		f.eng.sums.mu.Lock()
		defer f.eng.sums.mu.Unlock()
		for _, x := range f.eng.sums.byID {
			return x
		}
		return nil
	}()
	if st == nil || st.kept.len() != 1 {
		t.Fatalf("a paused pass should be kept: %+v", st)
	}
	// Evicting the state (MaxSummaries newer ones) closes its readers.
	for i := 0; i < MaxSummaries; i++ {
		q2 := q
		q2.Top = i + 1 // not bound; any request makes a new state
		if _, err := f.eng.Summary(bg, q2); err != nil {
			t.Fatal(err)
		}
	}
	if n := st.kept.len(); n != 0 {
		t.Errorf("evicted state still keeps %d readers", n)
	}
	// MaxKeptReaders bounds one state.
	k := newKeptReaders()
	for i := 0; i < MaxKeptReaders+3; i++ {
		o, err := f.eng.open(bg, &fileInfo{File: mustFile(t, f, i%2)})
		if err != nil {
			t.Fatal(err)
		}
		k.put(int64(1000+i), &keptPass{o: o, fr: newFwd(nil, 0, 16)})
	}
	if k.len() != MaxKeptReaders {
		t.Errorf("%d kept", k.len())
	}
	k.closeAll()
	if k.len() != 0 {
		t.Error("closeAll")
	}
}

func mustFile(t *testing.T, f *fixture, i int) index.File {
	t.Helper()
	files, _ := f.idx.Files(bg, "")
	if len(files) <= i {
		t.Fatal(fmt.Sprint("no file ", i))
	}
	return files[i]
}
