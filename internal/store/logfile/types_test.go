package logfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListTypes(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string) {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("2026-11-14T00:00:00.000Z 192.0.2.1 x\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	write("logs/192.0.2.1/2026-11-14.log")
	write("logs/192.0.2.1/traps/2026-11-13.log.gz")
	write("logs/192.0.2.1/traps/2026-11-14.log")
	write("logs/192.0.2.1/other/2026-11-14.log") // no type claims it
	write("logs/192.0.2.2/traps/2026-11-14.001.log")
	files, _, unknown, err := ListAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range files {
		got = append(got, f.Type+" "+f.Rel)
	}
	want := []string{
		"syslog logs/192.0.2.1/2026-11-14.log",
		"trap logs/192.0.2.1/traps/2026-11-13.log.gz",
		"trap logs/192.0.2.1/traps/2026-11-14.log",
		"trap logs/192.0.2.2/traps/2026-11-14.001.log",
	}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
	if len(unknown) != 1 || unknown[0] != "logs/192.0.2.1/other" {
		t.Fatalf("unknown %q", unknown)
	}
	if RelPathType(TypeTrap, "192.0.2.1", Name{Day: "2026-11-14"}) != "logs/192.0.2.1/traps/2026-11-14.log" ||
		RelPathType(TypeSyslog, "192.0.2.1", Name{Day: "2026-11-14"}) != "logs/192.0.2.1/2026-11-14.log" {
		t.Fatal("RelPathType")
	}
}
