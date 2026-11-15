package trap

import (
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
)

// TryHandle (the SNMP reader's fast path) never blocks: it stores through
// TryWrite when that can, and otherwise returns the write as a finish func.
// Either way the datagram is decoded and counted exactly once.
func TestTryHandle(t *testing.T) {
	var writes, tries []string
	tryOK := true
	r, err := Open(Options{DataDir: t.TempDir(),
		Write: func(m model.Message) error { writes = append(writes, string(m.Raw)); return nil },
		TryWrite: func(m model.Message) (bool, error) {
			tries = append(tries, string(m.Raw))
			return tryOK, nil
		}}, Settings{AnswerInforms: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	junk := []byte("junk")

	if f := r.TryHandle(packet(junk, now)); f != nil {
		t.Fatal("TryWrite stored it, but TryHandle returned a finish func")
	}
	if len(tries) != 1 || len(writes) != 0 {
		t.Fatalf("tries %d, writes %d", len(tries), len(writes))
	}

	tryOK = false // the store write would block
	f := r.TryHandle(packet(junk, now))
	if f == nil {
		t.Fatal("no finish func for a write that would block")
	}
	if c := r.Counts(); c.Received != 2 || c.ByStatus["malformed"] != 2 {
		t.Fatalf("counted before the write: %+v", c)
	}
	if len(writes) != 0 {
		t.Fatal("written before finish")
	}
	f()
	if len(writes) != 1 || writes[0] != tries[1] || !strings.Contains(writes[0], "status=malformed") {
		t.Fatalf("finish wrote %q (the try had %q)", writes, tries[1])
	}
	if c := r.Counts(); c.Received != 2 || c.ByStatus["malformed"] != 2 {
		t.Fatalf("finish counted again: %+v", c)
	}
	if fs := r.Failures(); len(fs) != 1 || fs[0].Count24h != 2 {
		t.Fatalf("failures %+v", fs)
	}

	// Without TryWrite the write is always left to finish.
	r2 := openRcv(t, t.TempDir(), nil)
	if r2.TryHandle(packet(junk, now)) == nil {
		t.Error("no TryWrite, but no finish func")
	}
}
