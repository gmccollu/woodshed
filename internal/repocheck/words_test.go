// Package repocheck holds checks over the repository's tracked files (they run
// in CI with go test ./...).
package repocheck

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// bannedWords are words no tracked file may contain, in any case: trademarks
// the project must not use (owner decision 2026-11-16, SPEC §13.10). Each is
// written in pieces so this file doesn't match itself. Third-party tool names
// we invoke (softflowd, nfprobe, tshark's cflow fields) don't contain them.
var bannedWords = []string{"net" + "flow"}

// repoRoot is the module root (go test runs in the package's folder).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test")
		}
		dir = parent
	}
}

func TestNoBannedWordsInTrackedFiles(t *testing.T) {
	root := repoRoot(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git isn't installed")
	}
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("not a git checkout (%v)", err)
	}
	files := strings.Split(strings.TrimRight(string(out), "\x00"), "\x00")
	if len(files) < 100 {
		t.Fatalf("only %d tracked files", len(files))
	}
	for _, f := range files {
		lowerName := strings.ToLower(f)
		for _, w := range bannedWords {
			if strings.Contains(lowerName, w) {
				t.Errorf("%s: the file name has a banned word (%d letters, starting %q)", f, len(w), w[:3])
			}
		}
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			if os.IsNotExist(err) {
				continue // deleted in the working tree, not yet committed
			}
			t.Fatal(err)
		}
		lower := bytes.ToLower(b)
		for _, w := range bannedWords {
			if n := bytes.Count(lower, []byte(w)); n > 0 {
				line := 1 + bytes.Count(lower[:bytes.Index(lower, []byte(w))], []byte("\n"))
				t.Errorf("%s:%d: a banned word (%d letters, starting %q), %d times in the file", f, line, len(w), w[:3], n)
			}
		}
	}
}
