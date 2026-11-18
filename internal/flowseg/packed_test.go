package flowseg

import (
	"math/rand/v2"
	"reflect"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Packed rows come back exactly as Block.Record gives them, for every column
// set, in any order and subset of rows, with the Packed and the Block reused.
func TestPackedMatchesRecord(t *testing.T) {
	for _, tc := range []struct {
		name  string
		full  bool
		n     int
		flush int
	}{{"full", true, 3000, 397}, {"sparse", false, 3000, 0}, {"big", true, MaxBlockRows + 10, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			recs := genRecords(11, tc.n, tc.full)
			path, _ := writeSegment(t, t.TempDir(), recs, nil, tc.flush)
			r, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			rng := rand.New(rand.NewPCG(5, 9))
			var b Block
			var p Packed
			for _, cols := range []Cols{ColAll, ColOptional, Cols(flow.HasSrc|flow.HasEnd) | ColReceived | ColTemplate,
				Cols(flow.HasStart|flow.HasEventTime) | ColReceived, Cols(flow.HasStart),
				ColMeta | ColExtras | ColStatus | ColTimeSource, ColAll &^ ColExtras} {
				for bi := 0; bi < r.Blocks(); bi++ {
					if err := r.Decode(bi, cols, &b); err != nil {
						t.Fatal(err)
					}
					rows := rng.Perm(b.Rows)[:rng.IntN(b.Rows+1)]
					p.Reset(&b)
					for _, row := range rows {
						p.Add(&b, row)
					}
					if p.Len() != len(rows) {
						t.Fatalf("len %d, added %d", p.Len(), len(rows))
					}
					var want, got flow.Record
					for row := 0; row < b.Rows; row++ { // Block.EffectiveTimes is the record's
						b.Record(row, &want)
						ws, we := EffectiveTimes(&want)
						if gs, ge := b.EffectiveTimes(row); gs != ws || ge != we {
							t.Fatalf("cols %x block %d row %d: times %d %d, want %d %d", cols, bi, row, gs, ge, ws, we)
						}
					}
					// The first third read, the next third moved to q (Take), the
					// rest read from p after it: every row as Record gives it.
					var q Packed
					k := len(rows) / 3
					check := func(pk *Packed, rs []int, what string) {
						for _, row := range rs {
							b.Record(row, &want)
							pk.Next(&got)
							if !reflect.DeepEqual(want, got) {
								t.Fatalf("%s: cols %x block %d row %d:\n got %+v\nwant %+v", what, cols, bi, row, got, want)
							}
						}
					}
					check(&p, rows[:k], "read")
					p.Take(k, &q)
					if q.Len() != k {
						t.Fatalf("took %d of %d", q.Len(), k)
					}
					check(&q, rows[k:2*k], "taken")
					check(&p, rows[2*k:], "after the take")
					if p.Bytes() <= 0 && len(rows) > 0 {
						t.Fatal("no bytes")
					}
				}
			}
		})
	}
}

func BenchmarkPacked(b *testing.B) {
	recs := genRecords(11, MaxBlockRows, false)
	path, _ := writeSegment(b, b.TempDir(), recs, nil, 0)
	r, err := Open(path)
	if err != nil {
		b.Fatal(err)
	}
	defer r.Close()
	var blk Block
	if err := r.Decode(0, ColAll, &blk); err != nil {
		b.Fatal(err)
	}
	var p Packed
	var rec flow.Record
	b.Run("add+next", func(b *testing.B) {
		for b.Loop() {
			p.Reset(&blk)
			for row := 0; row < blk.Rows; row++ {
				p.Add(&blk, row)
			}
			for row := 0; row < blk.Rows; row++ {
				p.Next(&rec)
			}
		}
		b.ReportMetric(float64(len(p.data))/float64(blk.Rows), "B/row")
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(blk.Rows), "ns/row")
	})
	b.Run("record", func(b *testing.B) {
		for b.Loop() {
			for row := 0; row < blk.Rows; row++ {
				blk.Record(row, &rec)
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N)/float64(blk.Rows), "ns/row")
	})
}
