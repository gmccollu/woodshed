//go:build windows

package loadgen

import (
	"syscall"
	"time"
)

// processCPU is this process's user and kernel CPU time so far
// (GetProcessTimes; child processes aren't included).
func processCPU() (user, sys time.Duration) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, 0
	}
	var created, exited, kernel, usr syscall.Filetime
	if err := syscall.GetProcessTimes(h, &created, &exited, &kernel, &usr); err != nil {
		return 0, 0
	}
	return filetimeDuration(usr), filetimeDuration(kernel)
}

// filetimeDuration reads a FILETIME holding a duration (100 ns units).
func filetimeDuration(f syscall.Filetime) time.Duration {
	return time.Duration(int64(f.HighDateTime)<<32|int64(f.LowDateTime)) * 100
}
