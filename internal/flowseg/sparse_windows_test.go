//go:build windows

package flowseg

import (
	"syscall"
	"testing"
)

// fsctlSetSparse is FSCTL_SET_SPARSE (winioctl.h).
const fsctlSetSparse = 0x000900c4

// sparse marks f sparse, so a write far past its end doesn't make the file
// system write zeros over the gap first. The hour tests skip most of each
// part's bytes (one real block a part, the rest directory entries over a gap
// up to 256 MiB); without this every close on Windows zero-filled its whole
// part, about 30 GB over the full hour, and the test took 200-250 s there
// against 2 s elsewhere.
func sparse(t *testing.T, f segFile) {
	t.Helper()
	fd, ok := f.(interface{ Fd() uintptr })
	if !ok {
		return
	}
	var n uint32
	if err := syscall.DeviceIoControl(syscall.Handle(fd.Fd()), fsctlSetSparse, nil, 0, nil, 0, &n, nil); err != nil {
		t.Logf("FSCTL_SET_SPARSE: %v (the file system writes zeros over each gap)", err)
	}
}
