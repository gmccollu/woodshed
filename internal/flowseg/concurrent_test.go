package flowseg

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Readers of a live segment, through snapshots taken while the writer
// appends and flushes, always read an exact prefix of what was appended, and
// blocks decode in parallel from one Reader.
func TestSnapshotsBesideTheWriter(t *testing.T) {
	recs := genRecords(21, 6000, false)
	path := filepath.Join(t.TempDir(), "c.wsf")
	w, err := Create(path, "d", testHour, "v")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	errs := make(chan error, 4)
	seen := make(chan struct{}, 4) // each reader read a snapshot with blocks at least once
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reported := false
			for {
				select {
				case <-done:
					errs <- nil
					return
				default:
				}
				snap := w.Snapshot()
				r, err := OpenSnapshot(path, snap)
				if err != nil {
					errs <- err
					return
				}
				// Decode the blocks in parallel.
				out := make([][]flow.Record, r.Blocks())
				var bw sync.WaitGroup
				var mu sync.Mutex
				var firstErr error
				for i := 0; i < r.Blocks(); i++ {
					bw.Add(1)
					go func(i int) {
						defer bw.Done()
						if _, err := r.Block(i); err != nil {
							mu.Lock()
							firstErr = err
							mu.Unlock()
							return
						}
						recs, err := r.ReadBlock(i, ColAll, nil)
						mu.Lock()
						defer mu.Unlock()
						if err != nil {
							firstErr = err
						}
						out[i] = recs
					}(i)
				}
				bw.Wait()
				r.Close()
				if firstErr != nil {
					errs <- firstErr
					return
				}
				n := 0
				for _, b := range out {
					for j := range b {
						if b[j].Received != recs[n].Received || b[j].Has != normalize(recs[n]).Has {
							errs <- fmt.Errorf("snapshot record %d isn't the one appended", n)
							return
						}
						n++
					}
				}
				if int64(n) != snap.Totals.Records {
					errs <- fmt.Errorf("read %d records, snapshot says %d", n, snap.Totals.Records)
					return
				}
				if n > 0 && !reported {
					reported = true
					seen <- struct{}{}
				}
			}
		}()
	}
	for i := range recs {
		if err := w.Append(&recs[i]); err != nil {
			t.Fatal(err)
		}
		if i%250 == 0 {
			if err := w.Flush(); err != nil {
				t.Fatal(err)
			}
			w.TakeMinutes()
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	for g := 0; g < 4; g++ {
		select {
		case <-seen:
		case err := <-errs:
			t.Fatal(err) // a reader failed before it read anything
		}
	}
	close(done)
	wg.Wait()
	for g := 0; g < 4; g++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.Close(); err != nil {
		t.Fatal(err)
	}
}
