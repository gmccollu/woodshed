//go:build windows

package main

import (
	"fmt"

	"github.com/gmccollu/woodshed/internal/winacl"
)

// accessDenied is `woodshed search`'s exit-3 message for a folder or file it
// can't read (SPEC §11.4): the path, its owner, and the way in.
func accessDenied(path, _ string) string {
	who := ""
	if _, owner, err := winacl.OwnedByAdmins(path); err == nil && owner != "" {
		who = " (owner " + owner + ")"
	}
	return fmt.Sprintf("Can't read %s%s. Run it in an administrator prompt.", path, who)
}
