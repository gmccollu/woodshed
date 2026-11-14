package index

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// dirState is every file of dir with its size, mode, mtime and contents.
func dirState(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		v := fi.Mode().String() + " " + fi.ModTime().String()
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			v += " " + string(b)
		}
		out[p] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOpenReadOnlyChangesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.db.Exec(`INSERT INTO devices (id, ip, name, first_seen, last_heard) VALUES ('192.0.2.1', '192.0.2.1', 'edge-fw-01', 1, 2)`); err != nil {
		t.Fatal(err)
	}
	w.Close() // the last close removes -wal and -shm
	if exists(path+"-wal") || exists(path+"-shm") {
		t.Fatal("-wal or -shm left after close")
	}
	time.Sleep(20 * time.Millisecond)
	before := dirState(t, dir)

	r, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	devs, err := r.ListDevices(ctx)
	if err != nil || len(devs) != 1 || devs[0].Name != "edge-fw-01" {
		t.Fatalf("devices %+v %v", devs, err)
	}
	if _, err := r.db.Exec(`DELETE FROM devices`); err == nil {
		t.Fatal("a read-only index accepted a write")
	}
	r.Close()
	if after := dirState(t, dir); !maps.Equal(before, after) {
		t.Fatalf("the folder changed:\nbefore %v\nafter  %v", keys(before), keys(after))
	}
}

func TestOpenReadOnlyBesideWriter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, FileName)
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	ins := func(id string) {
		if _, err := w.db.Exec(`INSERT INTO devices (id, ip, first_seen, last_heard) VALUES (?, ?, 1, 2)`, id, id); err != nil {
			t.Fatal(err)
		}
	}
	ins("192.0.2.1")
	r, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	ins("192.0.2.2") // after the reader opened: WAL, not immutable, so it's seen
	devs, err := r.ListDevices(ctx)
	if err != nil || len(devs) != 2 {
		t.Fatalf("devices %+v %v", devs, err)
	}
}

func TestOpenReadOnlyRefusals(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenReadOnly(filepath.Join(dir, FileName)); !errors.Is(err, ErrNoIndex) {
		t.Fatalf("missing: %v", err)
	}
	if es, _ := os.ReadDir(dir); len(es) != 0 {
		t.Fatalf("a missing index was created: %v", es)
	}
	path := filepath.Join(dir, FileName)
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	w.db.Exec("PRAGMA user_version = 999")
	w.Close()
	if _, err := OpenReadOnly(path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("newer schema: %v", err)
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), FileName)
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenReadOnly(link); !errors.Is(err, ErrUnsafeFile) {
			t.Fatalf("symlink: %v", err)
		}
	}
	if _, err := OpenReadOnly(filepath.Join(dir, "a#b.db")); err == nil {
		t.Fatal("# in path accepted")
	}
}

func TestFileURI(t *testing.T) {
	for in, want := range map[string]string{
		"/Library/Application Support/Woodshed/index.db": "file:///Library/Application%20Support/Woodshed/index.db",
		"/var/lib/woodshed/index.db":                     "file:///var/lib/woodshed/index.db",
	} {
		if got := fileURI(in); got != want {
			t.Errorf("fileURI(%q) = %q, want %q", in, got, want)
		}
	}
	if runtime.GOOS == "windows" {
		if got := fileURI(`C:\ProgramData\Woodshed\index.db`); got != "file:///C:/ProgramData/Woodshed/index.db" {
			t.Errorf("windows: %q", got)
		}
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
