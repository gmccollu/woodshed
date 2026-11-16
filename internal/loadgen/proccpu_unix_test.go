//go:build unix

package loadgen

import (
	"syscall"
	"time"
)

// processCPU is this process's user and kernel CPU time so far (getrusage;
// children aren't included).
func processCPU() (user, sys time.Duration) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, 0
	}
	return time.Duration(ru.Utime.Nano()), time.Duration(ru.Stime.Nano())
}
