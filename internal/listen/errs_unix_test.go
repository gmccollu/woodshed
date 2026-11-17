//go:build !windows

package listen

import "syscall"

var errAddrInUse, errAccess, errAddrNotAvail error = syscall.EADDRINUSE, syscall.EACCES, syscall.EADDRNOTAVAIL

// errConnReset is what a read gets when the peer resets the connection.
var errConnReset error = syscall.ECONNRESET
