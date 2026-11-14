//go:build !windows

package index

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// checkReadable opens the index file without following a link (and without
// blocking on a FIFO) and refuses anything but a regular file with one link,
// like prepareFiles but changing nothing: as root on the service account's
// folder, a planted link must not make root read another file.
func checkReadable(p string) error {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) {
		return fmt.Errorf("%w: %s is a symbolic link", ErrUnsafeFile, p)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%w: %s is not a regular file (%v)", ErrUnsafeFile, p, st.Mode().Type())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && sys.Nlink > 1 {
		return fmt.Errorf("%w: %s has %d hard links", ErrUnsafeFile, p, sys.Nlink)
	}
	return nil
}
