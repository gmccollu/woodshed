//go:build windows

package index

import (
	"fmt"
	"os"
)

// checkReadable opens the index file to check it can be read, and refuses a
// link: on Windows the data folder's ACL governs access (prepareFiles).
func checkReadable(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return fmt.Errorf("%w: %s is a link", ErrUnsafeFile, p)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file", ErrUnsafeFile, p)
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	return f.Close()
}
