package flowquery

import (
	"testing"
	"time"
)

// An index read that fails while a listing goes on (here the index closed
// after page k) is the listing's error, never a short listing that ends as
// if the window were exhausted (it ended at 2,400 of 3,600 with no error).
func TestSearchPagesIndexError(t *testing.T) {
	for _, asc := range []bool{false, true} {
		for _, limit := range []int{50, 137} {
			for _, k := range []int{1, 2, 3, 5, 8, 13, 21, 34} {
				fx := newFixture(t, 600)
				q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
				got, cursor := 0, ""
				var lastErr error
				for pages := 1; ; pages++ {
					res, err := fx.eng.Search(bg, q, limit, asc, cursor, time.Minute)
					if err != nil {
						lastErr = err
						break
					}
					got += len(res.Hits)
					if cursor = res.Cursor; cursor == "" {
						break
					}
					if pages == k {
						fx.idx.Close()
					}
				}
				if lastErr == nil && got < 3600 {
					t.Fatalf("asc %v limit %d: the index closed after page %d: %d of 3,600 records and no error", asc, limit, k, got)
				}
			}
		}
	}
}

// Stream (the CLI's listing) too: an index read failing mid-stream is its
// error.
func TestStreamIndexError(t *testing.T) {
	for _, asc := range []bool{false, true} {
		fx := newFixture(t, 600)
		q := Query{From: fx.h.Add(-time.Hour), To: fx.h.Add(3 * time.Hour)}
		n := 0
		err := fx.eng.Stream(bg, q, asc, func(*Hit) error {
			if n++; n == 50 {
				fx.idx.Close()
			}
			return nil
		})
		if err == nil && n < 3600 {
			t.Fatalf("asc %v: %d of 3,600 records and no error", asc, n)
		}
		t.Logf("asc %v: %d records, %v", asc, n, err)
	}
}
