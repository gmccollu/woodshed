package flowseg

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// OpenLive reads a segment mid-write (flushed, not closed) and one with a
// torn tail, and never changes the file.
func TestOpenLive(t *testing.T) {
	dir := t.TempDir()
	recs := genRecords(31, 900, true)
	path := filepath.Join(dir, "live.wsf")
	w, err := Create(path, "10.1.0.1", testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 600; i++ {
		w.Append(&recs[i])
		if i%200 == 199 {
			w.Flush()
		}
	}
	raw := flow.RawSet{Received: 3, Status: flow.StatusNoTemplate, TemplateID: 999, Data: []byte{1, 2}}
	w.AppendRaw(&raw)
	w.Flush()
	w.Append(&recs[600]) // in the open block: not on disk
	before, _ := os.ReadFile(path)

	check := func(p string, wantRecs int, wantRaw int64) {
		t.Helper()
		r, err := OpenLive(p)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		got := readAll(t, r)
		if len(got) != wantRecs || r.Footer().Totals.Records != int64(wantRecs) || r.Footer().Raw != wantRaw {
			t.Fatalf("%s: %d records (footer %d), raw %d; want %d, %d", filepath.Base(p), len(got),
				r.Footer().Totals.Records, r.Footer().Raw, wantRecs, wantRaw)
		}
		for i := range got {
			sameRecord(t, recs[i], got[i], "live")
		}
		if string(r.Meta()) != "" || len(r.Templates()) == 0 {
			t.Fatalf("templates %d", len(r.Templates()))
		}
		if _, err := r.Block(0); err != nil {
			t.Fatal(err)
		}
		n := 0
		r.Raw(func(*flow.RawSet) bool { n++; return true })
		if int64(n) != wantRaw {
			t.Fatalf("raw sets read %d", n)
		}
	}
	check(path, 600, 1)
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("OpenLive changed the file")
	}

	// A torn tail: half of the next block written.
	w.Flush()
	full, _ := os.ReadFile(path)
	snap := w.Snapshot()
	last := snap.Blocks[len(snap.Blocks)-1]
	torn := filepath.Join(dir, "torn.wsf")
	os.WriteFile(torn, full[:last.Offset+last.Length/2], 0o600)
	check(torn, 600, 1)
	if b, _ := os.ReadFile(torn); int64(len(b)) != last.Offset+last.Length/2 {
		t.Fatal("OpenLive cut the torn file")
	}
	check(path, 601, 1)

	// A closed segment reads through its footer.
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
	check(path, 601, 1)
	r, _ := OpenLive(path)
	// Its blocks' header copies are the footer's (past the template table).
	if foot := r.Footer(); foot.Blocks[0].hdrOff < foot.tableOff {
		t.Fatal("closed segment didn't use its footer")
	}
	r.Close()
}
