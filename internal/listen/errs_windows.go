package listen

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// isAddrInUse: WSAEACCES too, which is what a port held with SO_EXCLUSIVEADDRUSE
// (or reserved by another service) gives.
func isAddrInUse(err error) bool {
	return errors.Is(err, windows.WSAEADDRINUSE) || errors.Is(err, windows.WSAEACCES)
}

// isConnReset reports whether a read failed because the peer reset the
// connection: WSAECONNRESET (10054) from Winsock, or the portable ECONNRESET.
func isConnReset(err error) bool {
	return errors.Is(err, windows.WSAECONNRESET) || errors.Is(err, syscall.ECONNRESET)
}

// commonErrText returns the OS-independent text for the common bind failures, or
// "" for anything else. WSAEACCES (10013) also means another process holds the
// port with exclusive use, or the port is in an excluded range (Hyper-V, WinNAT).
func commonErrText(err error) string {
	switch {
	case errors.Is(err, windows.WSAEADDRINUSE):
		return "address already in use"
	case errors.Is(err, windows.WSAEACCES):
		return "permission denied or port reserved by the system"
	case errors.Is(err, windows.WSAEADDRNOTAVAIL):
		return "address not available"
	}
	return ""
}
