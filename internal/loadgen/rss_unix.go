//go:build unix

package loadgen

import "syscall"

// maxRSS is the process's peak resident set in bytes (getrusage: KiB on
// Linux, bytes on macOS).
func maxRSS() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return int64(ru.Maxrss) * rssUnit
}

// cpuTimes is the process's user plus kernel CPU time so far.
func cpuTimes() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return ru.Utime.Nano() + ru.Stime.Nano()
}
