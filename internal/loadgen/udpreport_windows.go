package loadgen

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// reportRefusals turns ICMP port-unreachable reporting back on for one of
// `woodshed send`'s own connected UDP sockets (SPEC §13.10 decision 84). Go
// turns it off on every Windows UDP socket it makes (net/fd_windows.go sets
// SIO_UDP_CONNRESET to FALSE, go.dev/issue/5834), which is right for a
// server's listening socket, where one sender's ICMP error would otherwise
// fail the next read for everyone; the server's sockets never come here. With
// it on, Windows reports the ICMP message on a later send or receive as
// WSAECONNRESET, which isConnRefused counts. (WSASend's documentation: "For a
// UDP datagram socket, this error would indicate that a previous send
// operation resulted in an ICMP 'Port Unreachable' message",
// https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasend;
// SIO_UDP_CONNRESET: "Set to TRUE to enable reporting",
// https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls.)
//
// It's set after the dial: a Dialer's Control runs before the socket's init,
// which sets it back to FALSE (net/sock_posix.go: dial runs Control, then
// fd.connect, which starts with fd.init). If it fails the sender goes on as before, never seeing a refusal.
func reportRefusals(c net.Conn) {
	uc, ok := c.(*net.UDPConn)
	if !ok {
		return
	}
	rc, err := uc.SyscallConn()
	if err != nil {
		return
	}
	_ = rc.Control(func(fd uintptr) {
		on, n := uint32(1), uint32(0)
		_ = windows.WSAIoctl(windows.Handle(fd), windows.SIO_UDP_CONNRESET, (*byte)(unsafe.Pointer(&on)),
			uint32(unsafe.Sizeof(on)), nil, 0, &n, nil, 0)
	})
}
