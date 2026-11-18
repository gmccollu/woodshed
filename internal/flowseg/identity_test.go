package flowseg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// A segment's identity is its header's: the same through a reader, a
// snapshot's reader and ReadIdentity, and another one for a file deleted
// and written again under the same name (a part number reused).
func TestIdentity(t *testing.T) {
	dir := t.TempDir()
	hour := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	path := filepath.Join(dir, NameFor(hour).String())
	write := func() *Footer {
		w, err := Create(path, "192.0.2.1", hour, "t")
		if err != nil {
			t.Fatal(err)
		}
		r := flow.Record{Has: flow.HasEnd, End: hour.UnixMilli(), Received: hour.UnixMilli()}
		if err := w.Append(&r); err != nil {
			t.Fatal(err)
		}
		foot, err := w.Close()
		if err != nil {
			t.Fatal(err)
		}
		return foot
	}
	foot := write()
	r, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := r.Identity()
	r.Close()
	if id.DeviceID != "192.0.2.1" || id.Hour != hour.UnixMilli() || id.Created == 0 {
		t.Fatalf("identity %+v", id)
	}
	if got, err := ReadIdentity(path); err != nil || got != id {
		t.Fatalf("ReadIdentity %+v %v, want %+v", got, err, id)
	}
	sr, err := OpenSnapshot(path, foot)
	if err != nil {
		t.Fatal(err)
	}
	if sr.Identity() != id {
		t.Fatalf("snapshot reader %+v, want %+v", sr.Identity(), id)
	}
	sr.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for time.Now().UnixMilli() <= id.Created { // another creation time (the clock may tick in steps)
		time.Sleep(time.Millisecond)
	}
	write()
	if got, err := ReadIdentity(path); err != nil || got == id {
		t.Fatalf("written again: %+v %v, the old %+v", got, err, id)
	}
	// The old snapshot against the new, shorter file: refused.
	big := *foot
	big.Blocks = append([]BlockInfo(nil), foot.Blocks...)
	big.Blocks[len(big.Blocks)-1].Offset += 1 << 20
	if r, err := OpenSnapshot(path, &big); err == nil {
		r.Close()
		t.Fatal("a snapshot past the file's end opened")
	}
	if _, err := ReadIdentity(filepath.Join(dir, "gone")); err == nil {
		t.Fatal("no error for a missing file")
	}
}
