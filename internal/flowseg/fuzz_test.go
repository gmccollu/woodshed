package flowseg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

func fuzzSeeds(f *testing.F) {
	dir := f.TempDir()
	recs := genRecords(77, 40, true)
	raws := []flow.RawSet{{Received: 1, Status: flow.StatusMalformed, Data: []byte{1, 2, 3}}}
	path, _ := writeSegment(f, dir, recs, raws, 13)
	b, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add(b[:len(b)-20])
	f.Add(b[:len(b)/2])
	f.Add(b[:headerFixed+10])
	f.Add([]byte(Magic))
	f.Add([]byte{})
}

// FuzzSegment: any bytes as a segment file. Open and Recover never panic, and
// a recovered segment never keeps a block whose CRC fails: every block it
// lists reads.
func FuzzSegment(f *testing.F) {
	fuzzSeeds(f)
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(dir, "f.wsf")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if r, err := Open(path); err == nil {
			for i := 0; i < r.Blocks(); i++ {
				r.Block(i)
				r.ReadBlock(i, ColAll, nil)
			}
			r.Raw(func(*flow.RawSet) bool { return true })
			r.Close()
		}
		res, err := Recover(path)
		if err != nil {
			return
		}
		r, err := Open(path)
		if err != nil {
			t.Fatalf("recovered segment doesn't open: %v", err)
		}
		defer r.Close()
		if r.Blocks() != res.KeptBlocks {
			t.Fatalf("recover kept %d blocks, footer lists %d", res.KeptBlocks, r.Blocks())
		}
		var n int64
		for i := 0; i < r.Blocks(); i++ {
			recs, err := r.ReadBlock(i, ColAll, nil)
			if err != nil {
				t.Fatalf("recovered block %d doesn't read: %v", i, err)
			}
			n += int64(len(recs))
		}
		if n != r.Footer().Totals.Records {
			t.Fatalf("%d records read, footer says %d", n, r.Footer().Totals.Records)
		}
		if err := r.Raw(func(*flow.RawSet) bool { return true }); err != nil {
			t.Fatalf("recovered raw sets don't read: %v", err)
		}
	})
}

// FuzzBlockBody feeds bytes straight to the block decoder, past the CRC a
// random file can't pass, so the column parsers see hostile input too.
func FuzzBlockBody(f *testing.F) {
	var e encoder
	for _, full := range []bool{true, false} {
		recs := genRecords(3, 20, full)
		body, _ := e.encodeBlock(recs, make([]rowMeta, len(recs)))
		f.Add(append([]byte(nil), body...))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var b Block
		if decodeBody(body, ColAll, testTemplates, &b) != nil {
			return
		}
		var r flow.Record
		for i := 0; i < b.Rows; i++ {
			b.Record(i, &r)
		}
		bi := b.Info
		bi.MayHaveAddr(r.Src)
		bi.MayHavePort(r.SrcPort)
		bi.MayHaveInIf(r.InIf)
	})
}
