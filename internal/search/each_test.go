package search

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// each collects Each's results.
func (f *fixture) each(q Query) ([]Result, EachStats) {
	f.t.Helper()
	var out []Result
	st, err := f.eng.Each(bg, q, func(r *Result) error {
		c := *r
		c.Stored = bytes.Clone(r.Stored)
		out = append(out, c)
		return nil
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out, st
}

func TestEachEqualsSearchPages(t *testing.T) {
	f := newFixture(t, 3, 400)
	all := Filter{From: f.day0, To: f.day0.Add(72 * time.Hour)}
	cases := map[string]Query{
		"everything":   {Filter: all},
		"q":            {Filter: Filter{Q: "link down", From: all.From, To: all.To}},
		"regex":        {Filter: Filter{Q: `seq=0+1\d\b`, Regex: true, From: all.From, To: all.To}},
		"severities":   {Filter: Filter{Severities: sevs(0, 3, model.Unknown), From: all.From, To: all.To}},
		"app and host": {Filter: Filter{Apps: []string{"FW-*"}, ExcludeHosts: []string{"edge-fw-01"}, From: all.From, To: all.To}},
		"group":        {Filter: all, Group: "HQ"},
		"hidden named": {Filter: all, Devices: []string{model.DeviceID(devH)}},
		"part of a day": {Filter: Filter{Q: "seq", From: f.day0.Add(30 * time.Hour), To: f.day0.Add(50 * time.Hour)},
			ExcludeDevices: []string{model.DeviceID(devC)}},
	}
	for name, q := range cases {
		for _, asc := range []bool{true, false} {
			q.Asc = asc
			q.Limit = 333
			pages, _ := f.all(q)
			got, st := f.each(q)
			if len(got) != len(pages) || st.Matches != int64(len(got)) {
				t.Fatalf("%s asc=%v: Each %d (stats %d), pages %d", name, asc, len(got), st.Matches, len(pages))
			}
			same(t, name, lines(got), f.expect(q))
			for i := range got {
				if got[i].Ref != pages[i].Ref {
					t.Fatalf("%s asc=%v: result %d ref differs", name, asc, i)
				}
				id, off, _, _ := decodeRef(got[i].Ref)
				if id != got[i].FileID || off != got[i].Offset {
					t.Fatalf("%s: FileID/Offset %d/%d, ref says %d/%d", name, got[i].FileID, got[i].Offset, id, off)
				}
				ln, err := logfile.ParseLine(got[i].Stored)
				if err != nil || !bytes.Equal(ln.Raw(), got[i].Raw) || ln.Received.UnixMilli() != got[i].Received.UnixMilli() {
					t.Fatalf("%s: stored %q doesn't hold the result (%v)", name, got[i].Stored, err)
				}
			}
			if len(got) > 0 && (st.ScannedBytes == 0 || st.ScannedFiles == 0) {
				t.Fatalf("%s: stats %+v", name, st)
			}
		}
	}
}

func lines(rs []Result) []Line {
	out := make([]Line, len(rs))
	for i, r := range rs {
		out[i] = r.Line
	}
	return out
}

func TestEachStopsAndCounts(t *testing.T) {
	f := newFixture(t, 2, 300)
	q := Query{Filter: Filter{From: f.day0, To: f.day0.Add(48 * time.Hour)}, Asc: true}
	stop := errors.New("stop")
	n := 0
	st, err := f.eng.Each(bg, q, func(*Result) error {
		if n++; n == 10 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || st.Matches != 10 {
		t.Fatalf("fn error: %v, %d matches", err, st.Matches)
	}
	ctx, cancel := context.WithCancel(bg)
	n = 0
	st, err = f.eng.Each(ctx, q, func(*Result) error {
		if n++; n == 5 {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) || st.Matches < 5 || st.Matches > 4000 {
		t.Fatalf("cancel: %v, %d matches", err, st.Matches)
	}
	if _, err := f.eng.Each(bg, Query{Filter: Filter{Q: "(", Regex: true}}, func(*Result) error { return nil }); err == nil {
		t.Fatal("bad regex accepted")
	} else if _, ok := err.(*QueryError); !ok {
		t.Fatalf("bad regex: %T %v", err, err)
	}

	// A file that vanishes is skipped and counted.
	files, _ := f.idx.Files(bg, model.DeviceID(devB))
	victim := files[len(files)/2]
	f.eng.testHookOpen = func(rel string) {
		if rel == victim.Path {
			os.Remove(filepath.Join(f.dir, filepath.FromSlash(victim.Path)))
		}
	}
	got, st := f.each(q)
	if st.GoneFiles != 1 {
		t.Fatalf("gone files %d", st.GoneFiles)
	}
	for _, r := range got {
		if r.FileID == victim.ID {
			t.Fatal("a line of the vanished file")
		}
	}
}

// fileLines reads every line of a stored file with its offset.
func fileLines(t *testing.T, dir, rel string) (offs []int64, ls [][]byte) {
	t.Helper()
	rc, err := logfile.Open(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	br := bufio.NewReader(rc)
	var off int64
	for {
		b, err := br.ReadBytes('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		offs, ls = append(offs, off), append(ls, bytes.TrimSuffix(b, []byte("\n")))
		off += int64(len(b))
	}
	return offs, ls
}

func TestAroundMatchesTheFile(t *testing.T) {
	for name, f := range map[string]*fixture{"small files": newFixture(t, 3, 400), "checkpointed files": newBigFixture(t)} {
		all := Filter{Q: "seq=", From: f.day0, To: f.day0.Add(72 * time.Hour)}
		for mode := 0; mode < 3; mode++ { // asc, desc, desc without the whole-file cache
			asc := mode == 0
			for _, n := range []int{0, 1, 3, 40} {
				hits, _ := f.each(Query{Filter: Filter{Q: "link", From: all.From, To: all.To}, Asc: asc})
				a := f.eng.NewAround(bg, !asc)
				if mode == 2 {
					a.window, a.wholeCap = 32<<10, 0
				}
				cache := map[int64][2]any{}
				for i, h := range hits {
					if i%7 != 0 && n == 40 {
						continue // keep the big case quick
					}
					pre, post, err := a.Lines(h.FileID, h.Offset, n, n)
					if err != nil {
						t.Fatal(err)
					}
					c, ok := cache[h.FileID]
					if !ok {
						row, err := f.idx.File(bg, h.FileID)
						if err != nil {
							t.Fatal(err)
						}
						offs, ls := fileLines(t, f.dir, row.Path)
						c = [2]any{offs, ls}
						cache[h.FileID] = c
					}
					offs, ls := c[0].([]int64), c[1].([][]byte)
					k := -1
					for j, o := range offs {
						if o == h.Offset {
							k = j
						}
					}
					if k < 0 || !bytes.Equal(ls[k], h.Stored) {
						t.Fatalf("%s: hit not at its offset", name)
					}
					wantPre, wantPost := ls[max(0, k-n):k], ls[k+1:min(len(ls), k+1+n)]
					if len(pre) != len(wantPre) || len(post) != len(wantPost) {
						t.Fatalf("%s asc=%v n=%d hit %d: %d before, %d after; want %d, %d", name, asc, n, i, len(pre), len(post), len(wantPre), len(wantPost))
					}
					for j := range pre {
						if !bytes.Equal(pre[j].Stored, wantPre[j]) || pre[j].FileID != h.FileID || pre[j].DeviceID != h.DeviceID {
							t.Fatalf("%s asc=%v n=%d: before line %d = %q, want %q", name, asc, n, j, pre[j].Stored, wantPre[j])
						}
					}
					for j := range post {
						if !bytes.Equal(post[j].Stored, wantPost[j]) {
							t.Fatalf("%s asc=%v n=%d: after line %d = %q, want %q", name, asc, n, j, post[j].Stored, wantPost[j])
						}
					}
				}
				a.Close()
			}
		}
	}
}

// Backwards over compressed files, Around decompresses each file once (and
// without the whole-file cache it would decompress far more: the test can
// tell the two apart).
func TestAroundDescReadsCompressedFilesOnce(t *testing.T) {
	f := newBigFixture(t)
	q := Query{Filter: Filter{Q: "link", From: f.day0, To: f.day0.Add(72 * time.Hour)}}
	hits, _ := f.each(q)
	inflated := func(wholeCap int64) (got, gzBytes int64) {
		f.eng.inflated.Store(0)
		a := f.eng.NewAround(bg, true)
		defer a.Close()
		a.window, a.wholeCap = 32<<10, wholeCap // windows much smaller than the files
		seen := map[int64]bool{}
		for _, h := range hits {
			row, err := f.idx.File(bg, h.FileID)
			if err != nil {
				t.Fatal(err)
			}
			if row.Compressed && !seen[row.ID] {
				seen[row.ID] = true
				gzBytes += row.RawSize
			}
			if _, _, err := a.Lines(h.FileID, h.Offset, 3, 3); err != nil {
				t.Fatal(err)
			}
		}
		return f.eng.inflated.Load(), gzBytes
	}
	got, gzBytes := inflated(aroundWholeCap)
	if gzBytes == 0 {
		t.Fatal("no compressed files in the fixture")
	}
	if got > gzBytes {
		t.Fatalf("decompressed %d bytes for %d bytes of compressed files (%d hits)", got, gzBytes, len(hits))
	}
	if without, _ := inflated(0); without < 3*gzBytes {
		t.Fatalf("without the cache only %d bytes for %d: the test doesn't exercise restarts", without, gzBytes)
	}
}
