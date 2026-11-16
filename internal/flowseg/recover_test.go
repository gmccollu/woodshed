package flowseg

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// crashSegment writes a few blocks, raw chunks and template chunks and
// returns the open (footerless) file's bytes, its snapshot, and the records
// of each block.
func crashSegment(t *testing.T, dir string) ([]byte, []byte, *Footer, [][]flow.Record) {
	t.Helper()
	r := rand.New(rand.NewPCG(42, 42))
	path := filepath.Join(dir, "c.wsf")
	w, err := Create(path, "10.9.9.9", testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	var blocks [][]flow.Record
	recv := testHour.UnixMilli()
	for b := 0; b < 4; b++ {
		var recs []flow.Record
		for i := 0; i < 6; i++ {
			recs = append(recs, randRecord(r, recv, b%2 == 0))
			w.Append(&recs[len(recs)-1])
		}
		if b == 1 {
			raw := randRaw(r, recv)
			w.AppendRaw(&raw)
			w.SetMeta([]byte{byte(b)})
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		blocks = append(blocks, recs)
		recv += 1500
	}
	snap := w.Snapshot()
	open, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	closed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return open, closed, snap, blocks
}

// Crash cuts at every byte offset: recovery keeps exactly the blocks wholly
// before the cut, and their records.
func TestRecoverCutAtEveryOffset(t *testing.T) {
	noSync(t)
	dir := t.TempDir()
	open, closed, snap, blocks := crashSegment(t, dir)
	if !bytes.HasPrefix(closed, open) {
		t.Fatal("close rewrote the blocks")
	}
	hl := len(encodeHeader(header{deviceID: "10.9.9.9", version: "v"}))
	// closed[:k] == open[:k] up to len(open), so the closed file only adds the
	// cuts inside its template table, footer and trailer.
	check := func(path string, k int) error {
		b := closed[:k]
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return err
		}
		res, err := Recover(path)
		if k < hl {
			if !errors.Is(err, ErrBadHeader) {
				return fmt.Errorf("cut %d: %v", k, err)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("cut %d: %v", k, err)
		}
		want := 0
		for _, b := range snap.Blocks {
			if b.Offset+b.Length <= int64(k) {
				want++
			}
		}
		if res.KeptBlocks != want {
			return fmt.Errorf("cut %d: kept %d blocks, want %d", k, res.KeptBlocks, want)
		}
		if res.Clean != (k == len(closed)) {
			return fmt.Errorf("cut %d: clean %v", k, res.Clean)
		}
		rd, err := Open(path)
		if err != nil {
			return fmt.Errorf("cut %d: open after recover: %v", k, err)
		}
		defer rd.Close()
		var got []flow.Record
		for i := 0; i < rd.Blocks(); i++ {
			recs, err := rd.ReadBlock(i, ColAll, nil)
			if err != nil {
				return fmt.Errorf("cut %d: block %d: %v", k, i, err)
			}
			got = append(got, recs...)
		}
		var exp []flow.Record
		for _, b := range blocks[:want] {
			exp = append(exp, b...)
		}
		if len(got) != len(exp) || rd.Footer().Totals.Records != int64(len(exp)) {
			return fmt.Errorf("cut %d: %d records, want %d", k, len(got), len(exp))
		}
		for i := range exp {
			if e := normalize(exp[i]); !reflect.DeepEqual(e.Has, got[i].Has) || e.Received != got[i].Received || e.Src != got[i].Src {
				return fmt.Errorf("cut %d: record %d differs", k, i)
			}
		}
		wantRaw := int64(0)
		for _, c := range snap.RawChunks {
			if c.Offset+c.Length <= int64(k) {
				wantRaw += int64(c.Count)
			}
		}
		if m := string(rd.Meta()); rd.Footer().Raw != wantRaw || want >= 2 && m != "\x01" || m != "" && m != "\x01" {
			return fmt.Errorf("cut %d: raw %d (want %d) meta %q", k, rd.Footer().Raw, wantRaw, m)
		}
		// Idempotent.
		again, err := Recover(path)
		if err != nil || !again.Clean || again.KeptBlocks != want {
			return fmt.Errorf("cut %d: second recover %+v %v", k, again, err)
		}
		return nil
	}
	var offsets []int
	for k := 0; k <= len(closed); k++ {
		offsets = append(offsets, k)
	}
	const workers = 8
	errs := make(chan error, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			path := filepath.Join(dir, fmt.Sprintf("cut%d.wsf", w))
			for i := w; i < len(offsets); i += workers {
				if err := check(path, offsets[i]); err != nil {
					errs <- err
					return
				}
			}
			errs <- nil
		}(w)
	}
	for w := 0; w < workers; w++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	// The full records survive exactly on a cut at a block's end.
	path := filepath.Join(dir, "full.wsf")
	k := int(snap.Blocks[2].Offset + snap.Blocks[2].Length)
	os.WriteFile(path, open[:k], 0o600)
	if _, err := Recover(path); err != nil {
		t.Fatal(err)
	}
	rd, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	got := readAll(t, rd)
	exp := append(append(append([]flow.Record{}, blocks[0]...), blocks[1]...), blocks[2]...)
	for i := range exp {
		sameRecord(t, exp[i], got[i], "cut at a block end")
	}
}

// noSync skips fsync for a test that recovers thousands of files (on macOS
// each one is a full flush to the device).
func noSync(t *testing.T) {
	old := syncFile
	syncFile = func(*os.File) error { return nil }
	t.Cleanup(func() { syncFile = old })
}

// A block failing its CRC is cut with everything after it, even under an
// intact footer.
func TestRecoverBadCRC(t *testing.T) {
	dir := t.TempDir()
	_, closed, snap, blocks := crashSegment(t, dir)
	path := filepath.Join(dir, "bad.wsf")
	for bi, b := range snap.Blocks {
		for _, at := range []int64{b.Offset + 5, b.Offset + prefixLen + 3, b.Offset + b.Length - 1} {
			mut := bytes.Clone(closed)
			mut[at] ^= 0x40
			os.WriteFile(path, mut, 0o600)
			if rd, err := Open(path); err == nil {
				// The footer may be intact, but the block mustn't read.
				if _, err := rd.ReadBlock(bi, ColAll, nil); err == nil {
					t.Fatalf("block %d with a flipped byte at %d read", bi, at)
				}
				rd.Close()
			}
			res, err := Recover(path)
			if err != nil {
				t.Fatal(err)
			}
			if res.KeptBlocks != bi || res.Clean {
				t.Fatalf("flip in block %d at %d: kept %d", bi, at, res.KeptBlocks)
			}
			rd, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := readAll(t, rd); len(got) != bi*len(blocks[0]) {
				t.Fatalf("flip in block %d: %d records", bi, len(got))
			}
			rd.Close()
		}
	}
}
