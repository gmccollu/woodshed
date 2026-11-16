package loadgen

import (
	"syscall"
	"unsafe"
)

// maxRSS is the process's peak working set in bytes.
func maxRSS() int64 {
	type counters struct {
		cb                         uint32
		pageFaultCount             uint32
		peakWorkingSetSize         uintptr
		workingSetSize             uintptr
		quotaPeakPagedPoolUsage    uintptr
		quotaPagedPoolUsage        uintptr
		quotaPeakNonPagedPoolUsage uintptr
		quotaNonPagedPoolUsage     uintptr
		pagefileUsage              uintptr
		peakPagefileUsage          uintptr
	}
	var c counters
	c.cb = uint32(unsafe.Sizeof(c))
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	proc := syscall.NewLazyDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	if r, _, _ := proc.Call(uintptr(h), uintptr(unsafe.Pointer(&c)), uintptr(c.cb)); r == 0 {
		return 0
	}
	return int64(c.peakWorkingSetSize)
}

// cpuTimes is the process's user plus kernel CPU time so far (ns).
func cpuTimes() int64 {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0
	}
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0
	}
	ft := func(f syscall.Filetime) int64 { return (int64(f.HighDateTime)<<32 | int64(f.LowDateTime)) * 100 }
	return ft(kernel) + ft(user)
}
