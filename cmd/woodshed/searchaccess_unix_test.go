//go:build !windows

package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func ownerOf(fi fs.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf(" %d:%d", st.Uid, st.Gid)
	}
	return ""
}

// A data folder this user can't read: exit 3 and the message with its owner,
// mode and both ways in (SPEC §11.4).
func TestSearchAccessDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder")
	}
	f := newSearchFixture(t)
	if err := os.Chmod(f.dir, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.dir, 0o700)
	me, _ := user.Current()
	code, out, errOut := runSearch(t, f.dir, "link")
	want := fmt.Sprintf("Can't read %s (owner %s, mode 0000). Run it as root (sudo woodshed search --data %s link) "+
		"or as the service account (sudo -u %s woodshed search --data %s link).", f.dir, me.Username, shellQuote(f.dir), me.Username, shellQuote(f.dir))
	if code != 3 || out != "" || !strings.Contains(errOut, want) {
		t.Fatalf("exit %d, stdout %q, stderr %q\nwant %q", code, out, errOut, want)
	}
	os.Chmod(f.dir, 0o700)

	// Only the logs folder unreadable.
	logs := filepath.Join(f.dir, "logs")
	os.Chmod(logs, 0)
	defer os.Chmod(logs, 0o700)
	if code, _, errOut := runSearch(t, f.dir, "link"); code != 3 || !strings.Contains(errOut, "Can't read "+logs) {
		t.Fatalf("logs: exit %d %q", code, errOut)
	}
	os.Chmod(logs, 0o700)

	// Only the index unreadable.
	db := filepath.Join(f.dir, "index.db")
	os.Chmod(db, 0)
	defer os.Chmod(db, 0o600)
	if code, _, errOut := runSearch(t, f.dir, "link"); code != 3 || !strings.Contains(errOut, "Can't read "+db) {
		t.Fatalf("index: exit %d %q", code, errOut)
	}
}

// Another user's private folder (root's home): exit 3, naming root as the
// owner and the default service account as the second way in.
func TestSearchAnotherUsersFolder(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every folder")
	}
	for _, dir := range []string{"/var/root", "/root"} {
		fi, err := os.Stat(dir)
		if err != nil {
			continue
		}
		if _, err := os.ReadDir(dir); err == nil {
			continue
		}
		code, _, errOut := runSearch(t, dir)
		account := "woodshed"
		if strings.Contains(errOut, "_woodshed") {
			account = "_woodshed"
		}
		want := fmt.Sprintf("Can't read %s (owner root, mode %04o). Run it as root (sudo woodshed search --data %s) or as the service account (sudo -u %s woodshed search --data %s).",
			dir, fi.Mode().Perm(), dir, account, dir)
		if code != 3 || !strings.Contains(errOut, want) {
			t.Fatalf("exit %d %q\nwant %q", code, errOut, want)
		}
		return
	}
	t.Skip("no unreadable folder of another user here")
}

// As root on a folder the service account owns, a search changes nothing:
// no new file, and no changed owner or mode (SPEC §11.6).
func TestSearchAsRootChangesNothing(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	f := newSearchFixture(t)
	filepath.WalkDir(f.dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil {
			os.Lchown(p, 65534, 65534)
		}
		return nil
	})
	before := treeState(t, f.dir)
	for _, args := range [][]string{nil, {"--json", "--context", "2", "link"}, {"--order", "desc"}} {
		if code, _, errOut := runSearch(t, f.dir, append(fxRange, args...)...); code != 0 {
			t.Fatalf("exit %d %s", code, errOut)
		}
	}
	after := treeState(t, f.dir)
	if len(after) != len(before) {
		t.Fatalf("%d entries, was %d", len(after), len(before))
	}
	for k, v := range before {
		if after[k] != v {
			t.Errorf("changed: %s\n  %s\n  %s", k, v, after[k])
		}
	}
}
