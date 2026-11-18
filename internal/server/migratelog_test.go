package server

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gmccollu/woodshed/internal/index"
)

// A new index logs one "index created" line; reopening a current one logs
// nothing. (The per-step lines of an upgrade: index.TestMigrationsReported
// and Migration.Text.)
func TestLogMigrations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, index.FileName)
	open := func() string {
		t.Helper()
		idx, err := index.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer idx.Close()
		var b bytes.Buffer
		logMigrations(slog.New(slog.NewTextHandler(&b, nil)), idx)
		return b.String()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := open(); strings.Count(got, "\n") != 1 || !strings.Contains(got, fmt.Sprintf(`msg="index created" schema=%d`, index.CurrentSchema)) {
		t.Fatalf("fresh: %q", got)
	}
	if got := open(); got != "" {
		t.Fatalf("current: %q", got)
	}
}
