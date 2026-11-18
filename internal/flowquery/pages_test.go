package flowquery

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flowseg"
)

// pageReads pages through q n times (limit hits each, or until the end) and
// returns each page's hits and cursor, and the segment bytes read for it.
func pageReads(t testing.TB, e *Engine, q Query, asc bool, limit, n int) ([][]Hit, []int64, []string) {
	t.Helper()
	var hits [][]Hit
	var reads []int64
	var cursors []string
	cursor := ""
	for range n {
		r0 := flowseg.ReadBytes()
		res, err := e.Search(bg, q, limit, asc, cursor, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		reads = append(reads, flowseg.ReadBytes()-r0)
		hits = append(hits, res.Hits)
		cursors = append(cursors, res.Cursor)
		if res.Cursor == "" {
			break
		}
		cursor = res.Cursor
	}
	return hits, reads, cursors
}

// pageResult is what a page gives a client.
type pageResult struct {
	Hits    []Hit
	Cursor  string
	Partial bool
}

// pagesOf is every page of q, limit a page, to the end.
func pagesOf(t *testing.T, e *Engine, q Query, asc bool, limit int, budget time.Duration) []pageResult {
	t.Helper()
	var out []pageResult
	cursor := ""
	for pages := 0; ; pages++ {
		if pages > 100000 {
			t.Fatal("no end")
		}
		res, err := e.Search(bg, q, limit, asc, cursor, budget)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, pageResult{res.Hits, res.Cursor, res.Partial})
		if res.Cursor == "" {
			return out
		}
		cursor = res.Cursor
	}
}

func samePages(t *testing.T, what string, got, want []pageResult) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d pages, want %d", what, len(got), len(want))
	}
	for i := range got {
		if got[i].Cursor != want[i].Cursor || got[i].Partial != want[i].Partial {
			t.Fatalf("%s: page %d cursor %q partial %v, want %q %v", what, i, got[i].Cursor, got[i].Partial, want[i].Cursor, want[i].Partial)
		}
		sameHits(t, fmt.Sprintf("%s page %d", what, i), got[i].Hits, want[i].Hits)
	}
}

// statelessTwin is an engine over fx's store whose pages are all stateless
// (today's pages, read from the cursor alone).
func statelessTwin(e *Engine) *Engine {
	s := New(Options{DataDir: e.o.DataDir, Index: e.o.Index, Open: e.o.Open, Workers: e.o.Workers})
	s.page, s.batch, s.statelessPages = e.page, e.batch, true
	return s
}

// A page's saved stream gives exactly the pages stateless pages give: the
// same hits, cursors (byte for byte) and partial flags, over open and closed
// segments, plan pages and batches, filters, device selections, both orders
// and page sizes down to one hit; every page after the first continues the
// saved stream (but an empty last page); and a finished listing leaves
// nothing saved or charged.
func TestSearchPagesMatchStateless(t *testing.T) {
	fx := newFixture(t, 2000)
	twin := statelessTwin(fx.eng)
	for _, asc := range []bool{false, true} {
		for _, fq := range []string{"", "proto=udp&dst_port=53", "src=10.20.0.7"} {
			for _, devs := range [][]string{nil, {"10.1.0.3"}, {"10.1.0.1", "10.1.0.2"}} {
				for _, limit := range []int{1, 137, 1000, 100000} {
					if limit == 1 && fq != "src=10.20.0.7" {
						continue // one-hit pages over the sparse filter only (the stateless twin plans every page)
					}
					q := Query{DeviceIDs: devs, From: fx.h.Add(10 * time.Minute), To: fx.h.Add(110 * time.Minute), Filter: mustFilter(t, fq)}
					what := fmt.Sprintf("asc %v %q %v limit %d", asc, fq, devs, limit)
					want := pagesOf(t, twin, q, asc, limit, time.Minute)
					s0, r0 := fx.eng.pageStarts.Load(), fx.eng.pageResumes.Load()
					got := pagesOf(t, fx.eng, q, asc, limit, time.Minute)
					samePages(t, what, got, want)
					// One stream, and a second for the empty last page when the one
					// before it filled exactly at the window's end (its cursor is
					// a stateless page's, but there's nothing left to save).
					if s, r := fx.eng.pageStarts.Load()-s0, fx.eng.pageResumes.Load()-r0; s < 1 || s > 2 || s+r != int64(len(got)) {
						t.Fatalf("%s: %d streams started, %d pages continued, of %d", what, s, r, len(got))
					}
					if n, u := fx.eng.savedPages(), fx.eng.pool.Used(); n != 0 || u != 0 {
						t.Fatalf("%s: %d saved, %d pool bytes after the listing", what, n, u)
					}
				}
			}
		}
	}
	if fx.eng.pageFallbacks.Load() != 0 {
		t.Fatalf("%d fell back", fx.eng.pageFallbacks.Load())
	}
	// Raw sets decoded on read, in the same places.
	eng, h := rawFixture(t)
	for _, asc := range []bool{false, true} {
		q := Query{From: h, To: h.Add(time.Hour)}
		samePages(t, fmt.Sprintf("raw asc %v", asc), pagesOf(t, eng, q, asc, 2, time.Minute), pagesOf(t, statelessTwin(eng), q, asc, 2, time.Minute))
	}
}

// Out of budget, a page from the saved stream is partial as a stateless one
// is (what's certain, a cursor that moves on) and the listing still gives
// every record once, in order; a page's stream also carries on past one.
func TestSearchPagesPartial(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	for _, asc := range []bool{false, true} {
		want := searchAll(t, statelessTwin(fx.eng), q, asc, 137)
		got := pagesOf(t, fx.eng, q, asc, 137, 0)
		var all []Hit
		partial := 0
		for _, p := range got {
			all = append(all, p.Hits...)
			if p.Partial {
				partial++
			}
		}
		sameHits(t, fmt.Sprintf("asc %v budget 0", asc), all, want)
		t.Logf("asc %v: %d pages, %d partial", asc, len(got), partial)
	}
	if n, u := fx.eng.savedPages(), fx.eng.pool.Used(); n != 0 || u != 0 {
		t.Fatalf("%d saved, %d pool bytes after", n, u)
	}
}

// Without its saved stream (dropped for room, expired, taken by another
// request with the same cursor, a server restarted), a page is read from the
// cursor's values: the same page, byte for byte, and its own stream saved
// for the page after it.
func TestSearchPageStateGone(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour), Filter: mustFilter(t, "proto=tcp")}
	for _, asc := range []bool{false, true} {
		want := pagesOf(t, statelessTwin(fx.eng), q, asc, 300, time.Minute)
		if len(want) < 6 {
			t.Fatalf("%d pages", len(want))
		}
		ways := map[string]func(e *Engine, page int){
			"dropped for room": func(e *Engine, page int) {
				if page%2 == 1 && !e.evictOne() {
					t.Fatal("nothing to drop")
				}
			},
			"expired": func(e *Engine, page int) {
				if page%2 == 1 {
					now := time.Now().Add(StateTTL + time.Minute)
					e.o.Clock = func() time.Time { return now }
				} else {
					e.o.Clock = time.Now
				}
			},
			"restarted": nil, // a new engine for every page
		}
		for name, gone := range ways {
			what := fmt.Sprintf("asc %v %s", asc, name)
			e := New(Options{DataDir: fx.dir, Index: fx.idx, Open: fx.eng.o.Open, Workers: 3})
			e.page, e.batch = fx.eng.page, fx.eng.batch
			var got []pageResult
			cursor := ""
			for page := 0; ; page++ {
				if gone == nil {
					e = New(Options{DataDir: fx.dir, Index: fx.idx, Open: fx.eng.o.Open, Workers: 3})
					e.page, e.batch = fx.eng.page, fx.eng.batch
				} else {
					gone(e, page)
				}
				res, err := e.Search(bg, q, 300, asc, cursor, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, pageResult{res.Hits, res.Cursor, res.Partial})
				if res.Cursor == "" {
					break
				}
				cursor = res.Cursor
			}
			samePages(t, what, got, want)
			if gone != nil {
				if s, r := e.pageStarts.Load(), e.pageResumes.Load(); s < int64(len(got)/2) || r < int64(len(got)/2-1) {
					t.Fatalf("%s: %d started, %d continued over %d pages", what, s, r, len(got))
				}
			}
		}
		// Two requests continuing from one cursor: the first takes the
		// stream, the second reads from the cursor; both the same page.
		e := New(Options{DataDir: fx.dir, Index: fx.idx, Open: fx.eng.o.Open, Workers: 3})
		e.page, e.batch = fx.eng.page, fx.eng.batch
		first, err := e.Search(bg, q, 300, asc, "", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		for i := range 2 {
			res, err := e.Search(bg, q, 300, asc, first.Cursor, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			samePages(t, fmt.Sprintf("asc %v twice %d", asc, i), []pageResult{{res.Hits, res.Cursor, res.Partial}}, want[1:2])
		}
		if s, r := e.pageStarts.Load(), e.pageResumes.Load(); s != 2 || r != 1 {
			t.Fatalf("twice: %d started, %d continued", s, r)
		}
		for e.evictPage() {
		}
		if u := e.pool.Used(); u != 0 {
			t.Fatalf("pool %d after dropping the saved pages", u)
		}
	}
}

// A segment deleted (retention) between two pages is gone for the next
// page whether it continues the saved stream or reads from the cursor.
func TestSearchPageAfterDeletion(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{DeviceIDs: []string{"10.1.0.1", "10.1.0.2"}, From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	first, err := fx.eng.Search(bg, q, 300, false, "", time.Minute)
	if err != nil || first.Cursor == "" {
		t.Fatal(err)
	}
	gone := filepath.Join(fx.dir, "logs", "10.1.0.2", "flows", flowseg.NameFor(fx.h).String()) // the older hour: not read yet
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	got := []pageResult{{first.Hits, first.Cursor, first.Partial}}
	for cursor := first.Cursor; cursor != ""; {
		res, err := fx.eng.Search(bg, q, 300, false, cursor, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, pageResult{res.Hits, res.Cursor, res.Partial})
		cursor = res.Cursor
	}
	// The stateless pages after the deletion, from the same first page.
	twin := statelessTwin(fx.eng)
	want := got[:1]
	for cursor := first.Cursor; cursor != ""; {
		res, err := twin.Search(bg, q, 300, false, cursor, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want, pageResult{res.Hits, res.Cursor, res.Partial})
		cursor = res.Cursor
	}
	samePages(t, "after deletion", got, want)
	if r := fx.eng.pageResumes.Load(); r < int64(len(got)-2) { // an empty last page starts again
		t.Fatalf("%d of %d pages continued", r, len(got)-1)
	}
}

// The saved streams are bounded: at most MaxPageStates (the least recently
// used dropped), charged to the pool, and the pool drops them before a
// top-N's state, which can't be read again from its cursor.
func TestSearchPageStatesBounded(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	e := fx.eng
	var cursors []string
	for i := range MaxPageStates + 3 {
		qi := q
		qi.Filter = mustFilter(t, fmt.Sprintf("src=10.20.0.%d", i))
		res, err := e.Search(bg, qi, 10, false, "", time.Minute)
		if err != nil || res.Cursor == "" {
			t.Fatal(err)
		}
		cursors = append(cursors, res.Cursor)
	}
	if n := e.savedPages(); n != MaxPageStates {
		t.Fatalf("%d saved, cap %d", n, MaxPageStates)
	}
	e.mu.Lock()
	for _, c := range cursors[:3] {
		if e.pages[c] != nil {
			t.Fatal("an oldest stream kept")
		}
	}
	e.mu.Unlock()
	if e.pool.Used() == 0 {
		t.Fatal("the saved streams aren't charged")
	}
	top, err := e.Top(bg, q, "src", "flows", 3, 0, "")
	if err != nil || top.Cursor == "" {
		t.Fatalf("top: %v (needs a partial answer)", err)
	}
	for range MaxPageStates {
		if !e.evictOne() {
			t.Fatal("nothing dropped")
		}
	}
	if n := e.savedPages(); n != 0 {
		t.Fatalf("%d page streams left, the top-N's state dropped first", n)
	}
	if _, err := e.Top(bg, q, "src", "flows", 3, time.Minute, top.Cursor); err != nil {
		t.Fatalf("the top-N's state: %v", err)
	}
	if u := e.pool.Used(); u != 0 {
		t.Fatalf("pool %d after", u)
	}
}

// A page's stream over its budget even trimmed carries on with stateless
// pages from the last record it gave: the same pages.
func TestSearchPageOverBudget(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	for _, asc := range []bool{false, true} {
		want := pagesOf(t, statelessTwin(fx.eng), q, asc, 500, time.Minute)
		for _, pool := range []int64{1, 20_000} {
			e := New(Options{DataDir: fx.dir, Index: fx.idx, Open: fx.eng.o.Open, Workers: 3, PoolBytes: pool})
			e.page, e.batch = fx.eng.page, fx.eng.batch
			samePages(t, fmt.Sprintf("asc %v pool %d", asc, pool), pagesOf(t, e, q, asc, 500, time.Minute), want)
			if e.pageFallbacks.Load() == 0 {
				t.Fatalf("pool %d: never over budget", pool)
			}
			for e.evictPage() {
			}
			if u := e.pool.Used(); u != 0 {
				t.Fatalf("pool %d: %d left charged", pool, u)
			}
		}
	}
}

// Pages after the first read about only their own records (SPEC §13.6):
// over a store whose every block holds a few rows ending far before the
// rest (each stateless page read again every such block overlapping it:
// 63 to 626 times the records it returned), 20 consecutive pages of 500
// and 5,000, both orders, read at most 2.2 times their records' share of
// the segments plus a wave of blocks, each continuing the saved stream;
// the same with a pool small enough that the streams trim.
func TestSearchPagesReadOnlyNewData(t *testing.T) {
	const hours, blocks, rows, span = 2, 300, 1000, 120
	e, q, n, size := outlierStore(t, hours, blocks, rows, span, 0)
	small := New(Options{DataDir: e.o.DataDir, Index: e.o.Index, Workers: 4, PoolBytes: 16 << 20}) // 1 MiB a stream
	perRec, perBlock := float64(size)/float64(n), size/int64(hours*blocks)
	twin := statelessTwin(e)
	for _, eng := range []*Engine{e, small} {
		for _, asc := range []bool{false, true} {
			for _, limit := range []int{500, 5000} {
				what := fmt.Sprintf("pool %d asc %v limit %d", eng.pool.cap, asc, limit)
				r0, f0, t0 := eng.pageResumes.Load(), eng.pageFallbacks.Load(), eng.streamTrims.Load()
				hits, reads, cursors := pageReads(t, eng, q, asc, limit, 20)
				if len(reads) != 20 {
					t.Fatalf("%s: %d pages", what, len(reads))
				}
				var later int64
				recs := 0
				for i := 1; i < len(reads); i++ {
					later += reads[i]
					recs += len(hits[i])
				}
				ceiling := int64(2.2*float64(recs)*perRec) + int64(eng.o.Workers)*perBlock
				t.Logf("%s: first page %d KB, pages 2-20 %d KB for %d records (%.2f× their %d KB; ceiling %d KB); %d trims", what,
					reads[0]>>10, later>>10, recs, float64(later)/(float64(recs)*perRec), int64(float64(recs)*perRec)>>10, ceiling>>10,
					eng.streamTrims.Load()-t0)
				if later > ceiling {
					t.Errorf("%s: pages 2-20 read %d bytes, ceiling %d", what, later, ceiling)
				}
				if r, f := eng.pageResumes.Load()-r0, eng.pageFallbacks.Load()-f0; r != 19 || f != 0 {
					t.Fatalf("%s: %d of 19 pages continued, %d fell back", what, r, f)
				}
				// The same pages as stateless ones (only the first two of
				// the stateless, which are slow: each reads ~120 blocks).
				wh, _, wc := pageReads(t, twin, q, asc, limit, 2)
				for i := range wh {
					if wc[i] != cursors[i] {
						t.Fatalf("%s: page %d cursor %q, stateless %q", what, i, cursors[i], wc[i])
					}
					sameHits(t, fmt.Sprintf("%s page %d", what, i), hits[i], wh[i])
				}
				for eng.evictPage() {
				}
			}
		}
		if eng == small && eng.streamTrims.Load() == 0 {
			t.Fatal("the small pool's streams never trimmed")
		}
	}
}

// The measurement for SPEC §13.6 (WOODSHED_PAGES_BIG=1: an hourly segment
// of 18 M records at 5,000 a second, 1 % ending up to 20 min early): the
// bytes 20 consecutive pages of 500 and 5,000 read, both orders, with saved
// streams and stateless (as before).
func TestSearchPagesMeasure(t *testing.T) {
	hours, blocks, rows, span := 2, 300, 1000, 120
	if os.Getenv("WOODSHED_PAGES_BIG") == "1" {
		hours, blocks, rows, span = 1, 3600, 5000, 1200
	} else if testing.Short() {
		t.Skip("short")
	}
	e, q, n, size := outlierStore(t, hours, blocks, rows, span, 0)
	t.Logf("%d records, %.1f MB of segments", n, float64(size)/1e6)
	perRec := float64(size) / float64(n)
	for _, eng := range []*Engine{e, statelessTwin(e)} {
		for _, asc := range []bool{false, true} {
			for _, limit := range []int{500, 5000} {
				start := time.Now()
				d0, a0 := eng.streamDecodes.Load(), eng.streamRereads.Load()
				hits, reads, _ := pageReads(t, eng, q, asc, limit, 20)
				el := time.Since(start)
				dec, again := eng.streamDecodes.Load()-d0, eng.streamRereads.Load()-a0
				var total, later int64
				got := 0
				for i, r := range reads {
					total += r
					if i > 0 {
						later += r
					}
					got += len(hits[i])
				}
				t.Logf("stateless %v asc %v pages of %d: %d pages, %d hits, %.2f s; first page %.2f MB, pages 2-%d %.2f MB "+
					"(%.2f× their records' %.2f MB); all %.2f MB (%.1f blocks' worth); streams decoded %d blocks, %d of them again",
					eng.statelessPages, asc, limit, len(reads), got, el.Seconds(),
					float64(reads[0])/1e6, len(reads), float64(later)/1e6, float64(later)/(float64(got-len(hits[0]))*perRec),
					float64(got-len(hits[0]))*perRec/1e6, float64(total)/1e6, float64(total)/(float64(size)/float64(hours*blocks)), dec, again)
				for eng.evictPage() {
				}
			}
		}
	}
}
