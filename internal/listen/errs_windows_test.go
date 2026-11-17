package listen

import "golang.org/x/sys/windows"

var errAddrInUse, errAccess, errAddrNotAvail error = windows.WSAEADDRINUSE, windows.WSAEACCES, windows.WSAEADDRNOTAVAIL

// errConnReset is what a read gets when the peer resets the connection (10054).
var errConnReset error = windows.WSAECONNRESET
