// Package repocheck holds checks over the repository's tracked files (they run
// in CI with go test ./...).
package repocheck

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// hardwareNames are hardware product names the prose (the spec, docs, the
// changelog and FAQ, the site's pages, issue templates) describes instead
// ("a 14-core laptop", "x64 and ARM64"): no vendor product names (owner
// decision 2026-11-16). Written in pieces, like bannedWords. Code may still
// name what it must (a plist DOCTYPE, a font stack, a signing tool's
// variables), so only prose files are checked.
var hardwareNames = regexp.MustCompile(`(?i)\b(` + strings.Join([]string{
	"app" + "le", "int" + "el", "mac" + "book", "mac " + "mini", "i" + "mac", "x" + "eon", "ry" + "zen", "ep" + "yc",
	`co` + `re i[3579]`, "rasp" + "berry pi", "gra" + "viton", "snap" + "dragon", `m[1-9] (p` + `ro|m` + `ax|ul` + `tra)`,
	"build " + "mac",
}, "|") + `)\b`)

// proseFile reports whether a tracked file is prose for hardwareNames.
func proseFile(f string) bool {
	return strings.HasSuffix(f, ".md") || strings.HasPrefix(f, "docs/") && !strings.HasSuffix(f, ".gif") ||
		strings.HasPrefix(f, ".github/ISSUE_TEMPLATE/") || strings.HasPrefix(f, "site/") && strings.HasSuffix(f, ".html")
}

func TestNoHardwareNamesInProse(t *testing.T) {
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
	checked := 0
	for _, f := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if !proseFile(f) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatal(err)
		}
		checked++
		for _, loc := range hardwareNames.FindAllIndex(b, -1) {
			line := 1 + bytes.Count(b[:loc[0]], []byte("\n"))
			t.Errorf("%s:%d: a hardware product name (%d letters); describe the machine instead", f, line, loc[1]-loc[0])
		}
	}
	if checked < 10 {
		t.Fatalf("only %d prose files", checked)
	}
	// The pattern still catches what it's for.
	for _, s := range []string{"on a 14-core " + "App" + "le M4 " + "Pro", "x86 (" + "Int" + "el)", "a Mac" + "Book"} {
		if !hardwareNames.MatchString(s) {
			t.Errorf("the pattern misses a hardware name (%d letters)", len(s))
		}
	}
}
