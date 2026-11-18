package flowquery

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
)

// ---- page streams over a store that changes between pages (the review of
// 2026-11-18) ----

// liveSeg is a segment a test writes while a listing runs.
type liveSeg struct {
	dev, rel, path string
	name           flowseg.Name
	w              *flowseg.Writer
}

func newLiveSeg(t *testing.T, fx *fixture, dev string, hour time.Time) *liveSeg {
	t.Helper()
	dir := filepath.Join(fx.dir, "logs", dev, "flows")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	name := flowseg.NameFor(hour)
	path := filepath.Join(dir, name.String())
	w, err := flowseg.Create(path, dev, hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	return &liveSeg{dev: dev, rel: "logs/" + dev + "/flows/" + name.String(), path: path, name: name, w: w}
}

// add appends n records whose ends are spread over [from, to), received at
// recv, SrcAS from as, and flushes them as one block.
func (ls *liveSeg) add(t *testing.T, rng *rand.Rand, n int, recv, from, to time.Time, as uint32) {
	t.Helper()
	for i := range n {
		end := from.UnixMilli() + rng.Int64N(to.UnixMilli()-from.UnixMilli())
		r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasSrcAS,
			Received: recv.UnixMilli() + int64(i), End: end, Start: end - rng.Int64N(60000),
			Src: netip.AddrFrom4([4]byte{10, 30, 0, byte(i)}), Dst: netip.MustParseAddr("198.51.100.9"), Bytes: uint64(i), SrcAS: as + uint32(i)}
		if err := ls.w.Append(&r); err != nil {
			t.Fatal(err)
		}
	}
	if err := ls.w.Flush(); err != nil {
		t.Fatal(err)
	}
}

// index writes the segment's index row (open: from its snapshot, as the
// store does on every flush).
func (ls *liveSeg) index(t *testing.T, fx *fixture, foot *flowseg.Footer, closed bool) {
	t.Helper()
	ff := index.FlowFile{DeviceID: ls.dev, Name: ls.name, Rel: ls.rel, Path: ls.path}
	rows := index.FlowRowsOf(ff, foot, ls.w.Size(), closed)
	if err := fx.idx.Apply(bg, index.Batch{Files: []index.FileOp{{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment}},
		FlowMinutes: rows.Minutes}); err != nil {
		t.Fatal(err)
	}
}

func (ls *liveSeg) close(t *testing.T, fx *fixture) {
	t.Helper()
	foot, err := ls.w.Close()
	if err != nil {
		t.Fatal(err)
	}
	ls.index(t, fx, foot, true)
}

// liveOpens makes fx's engine list extra open segments beside the
// fixture's, each through its writer's snapshot (as the store's).
type liveOpens struct {
	mu   sync.Mutex
	segs []*liveSeg
}

func (lo *liveOpens) install(fx *fixture) {
	base := fx.eng.o.Open
	fx.eng.o.Open = func(ids []string) []OpenSegment {
		out := base(ids)
		lo.mu.Lock()
		defer lo.mu.Unlock()
		for _, ls := range lo.segs {
			out = append(out, OpenSegment{DeviceID: ls.dev, Rel: ls.rel, Path: ls.path, Snap: ls.w.Snapshot})
		}
		return out
	}
}

func (lo *liveOpens) add(ls *liveSeg) {
	lo.mu.Lock()
	lo.segs = append(lo.segs, ls)
	lo.mu.Unlock()
}

// While the store changes between pages (a closed segment indexed with raw
// sets ending behind the listing, a closed segment indexed whose records
// end on both sides of it, an open segment written to, an open segment
// started, a segment deleted and written again under its name), a listing
// whose pages continue their saved streams gives exactly the pages a
// stateless listing gives at the same moments: no record twice, none out of
// order, the same cursors; and the same when the saved stream is dropped
// as the store changes, or a page after. Writes to open segments are read
// as a stream resumes (no rebuild); the others rebuild it from the cursor.
func TestSearchPagesWhileTheStoreChanges(t *testing.T) {
	for _, asc := range []bool{false, true} {
		for _, mode := range []string{"continued", "evicted at the write", "evicted a page after"} {
			what := fmt.Sprintf("asc %v %s", asc, mode)
			fx := newFixture(t, 2000)
			h := fx.h
			rng := rand.New(rand.NewPCG(7, 7))
			var lo liveOpens
			lo.install(fx)
			grow := newLiveSeg(t, fx, "10.1.0.8", h.Add(time.Hour)) // open from the start
			grow.add(t, rng, 300, h.Add(61*time.Minute), h.Add(60*time.Minute), h.Add(118*time.Minute), 800_000)
			grow.index(t, fx, grow.w.Snapshot(), false)
			lo.add(grow)
			t.Cleanup(func() { grow.w.Close() })
			twin := statelessTwin(fx.eng)
			q := Query{From: h.Add(-time.Hour), To: h.Add(3 * time.Hour)}
			writes := map[int]func(){
				3: func() { // a closed segment with raw sets ending behind (asc) or ahead (desc) of the listing
					ls := newLiveSeg(t, fx, "10.1.0.9", h.Add(time.Hour))
					ls.add(t, rng, 5, h.Add(110*time.Minute), h.Add(110*time.Minute), h.Add(111*time.Minute), 810_000)
					raws, tmpl := rawSetsEnding(t, h, 10, h.Add(5*time.Minute))
					ls.w.AddTemplate(tmpl)
					for _, rs := range raws {
						if err := ls.w.AppendRaw(rs); err != nil {
							t.Fatal(err)
						}
					}
					ls.close(t, fx)
				},
				6: func() { // a closed segment whose records end all over the window
					ls := newLiveSeg(t, fx, "10.1.0.7", h)
					ls.add(t, rng, 400, h.Add(59*time.Minute), h.Add(-30*time.Minute), h.Add(119*time.Minute), 820_000)
					ls.close(t, fx)
				},
				9: func() { // the open segment written to: late records all over, new ones
					grow.add(t, rng, 300, h.Add(119*time.Minute), h.Add(-20*time.Minute), h.Add(119*time.Minute), 830_000)
					grow.add(t, rng, 300, h.Add(119*time.Minute), h.Add(118*time.Minute), h.Add(119*time.Minute), 840_000)
					grow.index(t, fx, grow.w.Snapshot(), false)
				},
				12: func() { // an open segment started
					ls := newLiveSeg(t, fx, "10.1.0.6", h.Add(time.Hour))
					ls.add(t, rng, 200, h.Add(100*time.Minute), h.Add(40*time.Minute), h.Add(100*time.Minute), 850_000)
					ls.index(t, fx, ls.w.Snapshot(), false)
					lo.add(ls)
					t.Cleanup(func() { ls.w.Close() })
				},
				15: func() { // a segment deleted and written again under its name (another file, the same index row count)
					path := filepath.Join(fx.dir, "logs", "10.1.0.1", "flows", flowseg.NameFor(h.Add(time.Hour)).String())
					old, err := flowseg.ReadIdentity(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					waitPast(old.Created) // another creation time
					ls := newLiveSeg(t, fx, "10.1.0.1", h.Add(time.Hour))
					ls.add(t, rng, 700, h.Add(90*time.Minute), h.Add(30*time.Minute), h.Add(118*time.Minute), 860_000)
					ls.close(t, fx)
				},
				18: func() { // the open segment again, after the rebuilds
					grow.add(t, rng, 200, h.Add(119*time.Minute), h.Add(-50*time.Minute), h.Add(119*time.Minute), 870_000)
					grow.index(t, fx, grow.w.Snapshot(), false)
				},
			}
			type rec struct {
				k  hitKey
				as uint32
			}
			seen := map[rec]bool{}
			var prev *hitKey
			c1, c2 := "", ""
			for page := 0; ; page++ {
				if page > 5000 {
					t.Fatal("no end")
				}
				if w := writes[page]; w != nil {
					w()
					if mode == "evicted at the write" {
						for fx.eng.evictPage() {
						}
					}
				}
				if writes[page-1] != nil && mode == "evicted a page after" {
					for fx.eng.evictPage() {
					}
				}
				got, err := fx.eng.Search(bg, q, 137, asc, c1, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				want, err := twin.Search(bg, q, 137, asc, c2, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				samePages(t, fmt.Sprintf("%s page %d", what, page), []pageResult{{got.Hits, got.Cursor, got.Partial}},
					[]pageResult{{want.Hits, want.Cursor, want.Partial}})
				for i := range got.Hits {
					k := keyOfHit(&got.Hits[i])
					r := rec{k, got.Hits[i].Record.SrcAS}
					if seen[r] {
						t.Fatalf("%s page %d: a record twice", what, page)
					}
					seen[r] = true
					if prev != nil && !prev.before(k, asc) {
						t.Fatalf("%s page %d: out of order", what, page)
					}
					prev = &k
				}
				if got.Cursor == "" {
					break
				}
				c1, c2 = got.Cursor, want.Cursor
			}
			t.Logf("%s: %d records; %d resumed, %d rebuilt, %d started, %d blocks caught up, %d late rows left out", what, len(seen),
				fx.eng.pageResumes.Load(), fx.eng.pageRebuilds.Load(), fx.eng.pageStarts.Load(), fx.eng.pageCatchUps.Load(),
				fx.eng.streamLate.Load())
			if mode == "continued" {
				if fx.eng.pageCatchUps.Load() == 0 {
					t.Fatalf("%s: the open segment's new blocks were never read on resume", what)
				}
				if fx.eng.pageRebuilds.Load() < 4 {
					t.Fatalf("%s: %d rebuilds for 4 changes that need one", what, fx.eng.pageRebuilds.Load())
				}
			}
			for fx.eng.evictPage() {
			}
			if u := fx.eng.pool.Used(); u != 0 {
				t.Fatalf("%s: pool %d after", what, u)
			}
		}
	}
}

// The reviewer's case, kept as it was found: oldest first, a segment with
// raw sets ending at 09:05 indexed after page 3 (the listing at 09:29);
// pages from then on are 1 record, and the saved stream is dropped when a
// page ends on one of those records. Before the fix they came out after a
// 10:49 record, the cursor jumped back, and the stateless pages after the
// drop gave 3,155 records again.
func TestSearchPagesRawSegmentBehindThenEvicted(t *testing.T) {
	fx := newFixture(t, 600)
	fx.eng.page, fx.eng.batch = 1, 1
	h := fx.h
	q := Query{From: h.Add(-time.Hour), To: h.Add(3 * time.Hour)}
	seen := map[hitKey]int{}
	var prev *hitKey
	cursor, limit := "", 300
	rng := rand.New(rand.NewPCG(3, 3))
	for pages := 1; ; pages++ {
		if pages > 20000 {
			t.Fatal("no end")
		}
		res, err := fx.eng.Search(bg, q, limit, true, cursor, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		for i := range res.Hits {
			k := keyOfHit(&res.Hits[i])
			if seen[k]++; seen[k] > 1 {
				t.Fatalf("page %d: a record twice", pages)
			}
			if prev != nil && !prev.before(k, true) {
				t.Fatalf("page %d: out of order", pages)
			}
			prev = &k
			if res.Hits[i].Record.Status == flow.StatusLate {
				t.Fatalf("page %d: a raw set's record from behind the listing", pages)
			}
		}
		if res.Cursor == "" {
			break
		}
		cursor = res.Cursor
		if pages == 3 {
			ls := newLiveSeg(t, fx, "10.1.0.9", h.Add(time.Hour))
			ls.add(t, rng, 5, h.Add(110*time.Minute), h.Add(110*time.Minute), h.Add(111*time.Minute), 900_000)
			raws, tmpl := rawSetsEnding(t, h, 10, h.Add(5*time.Minute))
			ls.w.AddTemplate(tmpl)
			for _, rs := range raws {
				if err := ls.w.AppendRaw(rs); err != nil {
					t.Fatal(err)
				}
			}
			ls.close(t, fx)
		}
		if pages > 3 && res.Hits[len(res.Hits)-1].Record.End > h.Add(109*time.Minute).UnixMilli() {
			limit = 1
			for fx.eng.evictPage() {
			}
		}
	}
	if len(seen) != 3605 { // the fixture's 3,600 and the new segment's 5 (its raw sets end behind the listing)
		t.Fatalf("%d records", len(seen))
	}
}

// A segment deleted and written again under its name between pages (its
// part number reused) isn't read through the footer the saved stream kept:
// the stream is rebuilt from the cursor, and the page is the stateless one.
func TestSearchPageSegmentReplaced(t *testing.T) {
	for _, asc := range []bool{false, true} {
		fx := newFixture(t, 2000)
		twin := statelessTwin(fx.eng)
		q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
		first, err := fx.eng.Search(bg, q, 300, asc, "", time.Minute)
		if err != nil || first.Cursor == "" {
			t.Fatal(err)
		}
		// The segment the stream is reading: the newest hour's (desc), the oldest's (asc).
		hour := fx.h.Add(time.Hour)
		if asc {
			hour = fx.h
		}
		path := filepath.Join(fx.dir, "logs", "10.1.0.1", "flows", flowseg.NameFor(hour).String())
		old, err := flowseg.ReadIdentity(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		waitPast(old.Created) // another creation time
		ls := newLiveSeg(t, fx, "10.1.0.1", hour)
		ls.add(t, rand.New(rand.NewPCG(5, 5)), 2000, hour.Add(30*time.Minute), hour, hour.Add(time.Hour), 880_000)
		ls.close(t, fx)
		r0 := fx.eng.pageRebuilds.Load()
		var got, want []pageResult
		for c := first.Cursor; c != ""; {
			res, err := fx.eng.Search(bg, q, 300, asc, c, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, pageResult{res.Hits, res.Cursor, res.Partial})
			c = res.Cursor
		}
		for c := first.Cursor; c != ""; {
			res, err := twin.Search(bg, q, 300, asc, c, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			want = append(want, pageResult{res.Hits, res.Cursor, res.Partial})
			c = res.Cursor
		}
		samePages(t, fmt.Sprintf("asc %v after the part was replaced", asc), got, want)
		if fx.eng.pageRebuilds.Load() == r0 {
			t.Fatalf("asc %v: the replaced segment didn't rebuild the stream", asc)
		}
	}
}

// Requests resuming one cursor at once (8 at a time): one takes the saved
// stream, the others read from the cursor; every page is the stateless
// one, and nothing is left charged.
func TestSearchPagesConcurrentResume(t *testing.T) {
	fx := newFixture(t, 2000)
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour), Filter: mustFilter(t, "proto=tcp")}
	rounds := 5
	if raceEnabled {
		rounds = 2
	}
	for _, asc := range []bool{false, true} {
		want := pagesOf(t, statelessTwin(fx.eng), q, asc, 300, time.Minute)
		for round := 0; round < rounds; round++ {
			first, err := fx.eng.Search(bg, q, 300, asc, "", time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			errs := make(chan string, 8)
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					cursor := first.Cursor
					for i := 1; cursor != ""; i++ {
						res, err := fx.eng.Search(bg, q, 300, asc, cursor, time.Minute)
						if err != nil {
							errs <- err.Error()
							return
						}
						w := want[i]
						if res.Cursor != w.Cursor || res.Partial != w.Partial || len(res.Hits) != len(w.Hits) {
							errs <- fmt.Sprintf("page %d differs", i)
							return
						}
						for j := range res.Hits {
							if keyOfHit(&res.Hits[j]) != keyOfHit(&w.Hits[j]) || res.Hits[j].Record.SrcAS != w.Hits[j].Record.SrcAS {
								errs <- fmt.Sprintf("page %d hit %d differs", i, j)
								return
							}
						}
						cursor = res.Cursor
					}
				}()
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				t.Fatalf("asc %v round %d: %s", asc, round, e)
			}
		}
	}
	for fx.eng.evictPage() {
	}
	if u := fx.eng.pool.Used(); u != 0 || fx.eng.savedPageBytes.Load() != 0 {
		t.Fatalf("pool %d, saved %d", u, fx.eng.savedPageBytes.Load())
	}
}

// A default-range listing ("now" moves on between pages) and one whose page
// size changes from page to page continue as stateless pages do.
func TestSearchPagesDefaultRangeAndLimits(t *testing.T) {
	fx := newFixture(t, 2000)
	twin := statelessTwin(fx.eng)
	limits := []int{137, 1, 500, 3, 2000, 50, 999}
	for _, asc := range []bool{false, true} {
		for _, defRange := range []bool{false, true} {
			what := fmt.Sprintf("asc %v default range %v", asc, defRange)
			q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour), DefaultRange: defRange}
			var got, want []pageResult
			for i, c1, c2 := 0, "", ""; ; i++ {
				qi := q
				if defRange && i > 0 { // later requests' "now"
					qi.From, qi.To = q.From.Add(time.Duration(i)*time.Minute), q.To.Add(time.Duration(i)*time.Minute)
				}
				limit := limits[i%len(limits)]
				r1, err := fx.eng.Search(bg, qi, limit, asc, c1, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				r2, err := twin.Search(bg, qi, limit, asc, c2, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
				got, want = append(got, pageResult{r1.Hits, r1.Cursor, r1.Partial}), append(want, pageResult{r2.Hits, r2.Cursor, r2.Partial})
				if r1.Cursor == "" || r2.Cursor == "" {
					break
				}
				c1, c2 = r1.Cursor, r2.Cursor
			}
			samePages(t, what, got, want)
			if n := len(fx.brute(q)); func() int {
				c := 0
				for _, p := range got {
					c += len(p.Hits)
				}
				return c
			}() != n {
				t.Fatalf("%s: not every record", what)
			}
		}
	}
	if fx.eng.pageResumes.Load() == 0 {
		t.Fatal("never continued")
	}
}

// Abandoned listings release their page streams once StateTTL has passed:
// on any query (it plans), and from the sweep's timer with no query at all;
// the saved streams' bytes are what the pool holds while they're idle, so
// the collector nudge (which counts what running queries hold) ignores
// them; and together they stay under half the pool.
func TestSearchPageStreamsReleased(t *testing.T) {
	fx := newFixture(t, 2000)
	e := fx.eng
	q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
	save := func() {
		for i := range MaxPageStates {
			qi := q
			qi.Filter = mustFilter(t, fmt.Sprintf("src=10.20.0.%d", i))
			if _, err := e.Search(bg, qi, 10, false, "", time.Minute); err != nil {
				t.Fatal(err)
			}
		}
		if e.savedPages() != MaxPageStates || e.pool.Used() == 0 {
			t.Fatalf("%d saved, pool %d", e.savedPages(), e.pool.Used())
		}
		if u, s := e.pool.Used(), e.savedPageBytes.Load(); u != s {
			t.Fatalf("idle: pool %d, the saved streams' %d (the nudge would count them)", u, s)
		}
	}
	later := func() { now := time.Now().Add(StateTTL + time.Minute); e.o.Clock = func() time.Time { return now } }
	save()
	later()
	if _, err := e.Count(bg, q); err != nil { // not a search page: it plans
		t.Fatal(err)
	}
	if n, u := e.savedPages(), e.pool.Used(); n != 0 || u != 0 || e.savedPageBytes.Load() != 0 {
		t.Fatalf("after TTL and a count: %d saved, pool %d", n, u)
	}
	e.o.Clock = time.Now
	save()
	e.mu.Lock()
	armed := e.pageTimer != nil
	e.mu.Unlock()
	if !armed {
		t.Fatal("no sweep timer")
	}
	later()
	e.pageTimerFired() // what the timer runs
	if n, u := e.savedPages(), e.pool.Used(); n != 0 || u != 0 {
		t.Fatalf("after TTL and the timer: %d saved, pool %d", n, u)
	}
	e.mu.Lock()
	armed = e.pageTimer != nil
	e.mu.Unlock()
	if armed {
		t.Fatal("the timer runs on with nothing saved")
	}
	// Half the pool between them, rows and plan batches (a week's batch
	// can be as big as a stream's rows): streams of an eighth of the pool
	// each, so four fit.
	e.o.Clock = time.Now
	for i := range MaxPageStates {
		st := &stream{e: e, p: &plan{e: e}, h: &heldHeap{}}
		st.used.Store(e.pool.cap / 16) // its rows (counted, not in held blocks: never in the pool)
		e.pool.used.Add(e.pool.cap / 16)
		st.p.charged = e.pool.cap / 16 // its plan's batch
		e.savePage(fmt.Sprintf("c%d", i), "q", st)
		if s := e.savedPageBytes.Load(); s > e.pool.cap/2 {
			t.Fatalf("saved streams hold %d, over half the pool's %d", s, e.pool.cap)
		}
	}
	if n := e.savedPages(); n != 4 {
		t.Fatalf("%d saved, want the 4 that fit in half the pool", n)
	}
	e.mu.Lock()
	for i := range 4 {
		if e.pages[fmt.Sprintf("c%d", i)] != nil {
			t.Fatal("an older stream kept over a newer one")
		}
	}
	e.mu.Unlock()
	for e.evictPage() {
	}
	if e.savedPageBytes.Load() != 0 || e.pool.Used() != 0 {
		t.Fatalf("saved bytes %d, pool %d after", e.savedPageBytes.Load(), e.pool.Used())
	}
}

// An oldest-first listing that resumes after a busy open segment gained
// many blocks ahead of it holds at most its budget and a wave while it
// reads them (it trims between waves): the review found 400 new blocks
// held at once, 22.6 MiB against a 1 MiB budget in a 16 MiB pool. The page
// is still the stateless one.
func TestSearchPageCatchUpBounded(t *testing.T) {
	for _, blocks := range []int{20, 200} {
		fx := newFixture(t, 1500)
		e := New(Options{DataDir: fx.dir, Index: fx.idx, Open: fx.eng.o.Open, Workers: 3, PoolBytes: 16 << 20})
		fx.eng = e
		h := fx.h
		rng := rand.New(rand.NewPCG(3, 3))
		var lo liveOpens
		lo.install(fx)
		grow := newLiveSeg(t, fx, "10.1.0.8", h.Add(time.Hour))
		grow.add(t, rng, 2000, h.Add(61*time.Minute), h.Add(60*time.Minute), h.Add(61*time.Minute), 1)
		grow.index(t, fx, grow.w.Snapshot(), false)
		lo.add(grow)
		t.Cleanup(func() { grow.w.Close() })
		twin := statelessTwin(e)
		q := Query{From: h.Add(-time.Hour), To: h.Add(3 * time.Hour)}
		cursor := ""
		for range 3 { // until the open segment is loaded (oldest first: at its start less an hour)
			res, err := e.Search(bg, q, 500, true, cursor, time.Minute)
			if err != nil || res.Cursor == "" {
				t.Fatal(err)
			}
			cursor = res.Cursor
		}
		for b := range blocks { // ahead of the listing: ending near the window's end
			grow.add(t, rng, 2000, h.Add(119*time.Minute), h.Add(118*time.Minute), h.Add(119*time.Minute), uint32(10_000+b*2000))
		}
		foot := grow.w.Snapshot()
		grow.index(t, fx, foot, false)
		maxRows := 0
		for i := range foot.Blocks {
			maxRows = max(maxRows, foot.Blocks[i].Rows)
		}
		// The pool besides the stream's rows: its saved plan batch.
		e.mu.Lock()
		var batch int64
		for _, ps := range e.pages {
			batch = ps.s.p.charged
		}
		e.mu.Unlock()
		var peak atomic.Int64
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
				}
				if u := e.pool.Used(); u > peak.Load() {
					peak.Store(u)
				}
				runtime.Gosched()
			}
		}()
		c0, r0 := e.pageCatchUps.Load(), e.pageResumes.Load()
		got, err := e.Search(bg, q, 500, true, cursor, time.Minute)
		close(stop)
		<-done
		if err != nil {
			t.Fatal(err)
		}
		want, err := twin.Search(bg, q, 500, true, cursor, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		samePages(t, fmt.Sprintf("%d new blocks", blocks), []pageResult{{got.Hits, got.Cursor, got.Partial}},
			[]pageResult{{want.Hits, want.Cursor, want.Partial}})
		budget := e.pool.cap / pageBudgetShare
		wave := int64(e.streamWave()) * int64(maxRows) * 200 // a decoded wave's rows packed (generous: ~100 bytes a row)
		ceiling := budget + wave + batch + int64(len(foot.Blocks))*entryCost
		t.Logf("%d new blocks: caught up %d; pool peak %d KiB, ceiling %d KiB (budget %d, a wave %d, batch %d)", blocks,
			e.pageCatchUps.Load()-c0, peak.Load()>>10, ceiling>>10, budget>>10, wave>>10, batch>>10)
		if e.pageResumes.Load() == r0 || e.pageCatchUps.Load() == c0 {
			t.Fatal("the page didn't resume and catch up")
		}
		if peak.Load() > ceiling {
			t.Fatalf("%d new blocks: the pool peaked at %d, over the stream's budget and a wave (%d)", blocks, peak.Load(), ceiling)
		}
		// The rest of the listing (pages of 5,000), the caught-up rows trimmed
		// and read again as the merge reaches them: still the stateless pages.
		c1, c2 := got.Cursor, want.Cursor
		if raceEnabled && blocks > 20 {
			c1 = "" // the slow twin: the 20-block case pages on under -race
		}
		for page := 1; c1 != ""; page++ {
			r1, err := e.Search(bg, q, 5000, true, c1, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			r2, err := twin.Search(bg, q, 5000, true, c2, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			samePages(t, fmt.Sprintf("%d new blocks, page %d after", blocks, page), []pageResult{{r1.Hits, r1.Cursor, r1.Partial}},
				[]pageResult{{r2.Hits, r2.Cursor, r2.Partial}})
			c1, c2 = r1.Cursor, r2.Cursor
		}
		if e.streamTrims.Load() == 0 {
			t.Fatalf("%d new blocks: never trimmed (the budget should be too small)", blocks)
		}
		for e.evictPage() {
		}
		if u := e.pool.Used(); u != 0 {
			t.Fatalf("pool %d after", u)
		}
	}
}

// waitPast waits until the clock's unix ms is past ms (a file created then
// has another creation time; the clock may tick in steps of 15 ms or so).
func waitPast(ms int64) {
	for time.Now().UnixMilli() <= ms {
		time.Sleep(time.Millisecond)
	}
}
