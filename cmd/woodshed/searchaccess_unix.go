//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"syscall"
)

// accessDenied is `woodshed search`'s exit-3 message for a folder or file it
// can't read (SPEC §11.4): the path, its owner and mode, and both ways in.
func accessDenied(path, cmdline string) string {
	account := "woodshed"
	if runtime.GOOS == "darwin" {
		account = "_woodshed"
	}
	about := "permission denied"
	if fi, err := os.Stat(path); err == nil {
		owner := "unknown"
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			owner = fmt.Sprint(st.Uid)
			if u, err := user.LookupId(owner); err == nil {
				owner = u.Username
			}
			if st.Uid != 0 {
				account = owner // the service account owns its data folder
			}
		}
		about = fmt.Sprintf("owner %s, mode %04o", owner, fi.Mode().Perm())
	}
	return fmt.Sprintf("Can't read %s (%s). Run it as root (sudo %s) or as the service account (sudo -u %s %s).",
		path, about, cmdline, account, cmdline)
}
