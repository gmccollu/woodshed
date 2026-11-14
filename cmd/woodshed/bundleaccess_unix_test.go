//go:build !windows

package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// woodshed bundle has the access rules of woodshed search (SPEC §11.3): a
// folder this user can't read is exit 3 with the way in, and no zip.
func TestBundleAccessDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder")
	}
	f := newBundleFixture(t)
	if err := os.Chmod(f.dir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.dir, 0o700)
	me, _ := user.Current()
	out := filepath.Join(t.TempDir(), "b.zip")
	code, stdout, stderr := runBundle(t, bxZone, "--data", f.dir, "--at", "now", "--out", out)
	want := fmt.Sprintf("Can't read %s (owner %s, mode 0000). Run it as root (sudo woodshed bundle --data %s --at now --out %s)",
		f.dir, me.Username, shellQuote(f.dir), shellQuote(out))
	if code != exitAccess || stdout != "" || !strings.Contains(stderr, want) {
		t.Fatalf("exit %d, stdout %q, stderr %q\nwant %q", code, stdout, stderr, want)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("a zip was written")
	}
}

// As root on a folder another account owns, a bundle changes nothing.
func TestBundleAsRootChangesNothing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	f := newBundleFixture(t)
	filepath.WalkDir(f.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			os.Lchown(p, 65534, 65534)
		}
		return nil
	})
	before := treeState(t, f.dir)
	if code, _, stderr := runBundle(t, bxZone, "--data", f.dir, "--at", "2026-11-14 04:42", "--out", filepath.Join(t.TempDir(), "b.zip")); code != 0 {
		t.Fatalf("exit %d %s", code, stderr)
	}
	after := treeState(t, f.dir)
	if len(after) != len(before) {
		t.Fatalf("%d entries, was %d", len(after), len(before))
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("changed: %s", k)
		}
	}
}
