package listen

import (
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"testing"
)

// listenErr builds the error net.Listen returns for a failed bind.
func listenErr(errno error) error {
	return &net.OpError{Op: "listen", Net: "udp", Err: os.NewSyscallError("bind", errno)}
}

func TestOsErrorCommon(t *testing.T) {
	eacces := "bind: permission denied"
	if runtime.GOOS == "windows" {
		eacces = "bind: permission denied or port reserved by the system"
	}
	for _, tc := range []struct {
		errno error
		want  string
	}{
		{errAddrInUse, "bind: address already in use"},
		{errAccess, eacces},
		{errAddrNotAvail, "bind: address not available"},
	} {
		if got := osError(listenErr(tc.errno)); got != tc.want {
			t.Errorf("%v: %q, want %q", tc.errno, got, tc.want)
		}
	}
	if !isAddrInUse(listenErr(errAddrInUse)) {
		t.Error("isAddrInUse missed the in-use errno")
	}
	// Anything unrecognised keeps the OS text, without Go's "listen udp ..." prefix.
	other := errors.New("some other failure")
	if got := osError(listenErr(other)); got != "bind: some other failure" {
		t.Errorf("unrecognised: %q", got)
	}
}

// A read failing on the peer's reset, as net.Conn.Read wraps it, is a reset; a
// clean EOF, a deadline and other errors aren't.
func TestIsConnReset(t *testing.T) {
	readErr := func(errno error) error {
		return &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errno)}
	}
	if !isConnReset(readErr(errConnReset)) {
		t.Errorf("isConnReset missed %v", errConnReset)
	}
	for _, err := range []error{io.EOF, os.ErrDeadlineExceeded, readErr(errAccess), errors.New("x")} {
		if isConnReset(err) {
			t.Errorf("isConnReset(%v) = true", err)
		}
	}
}
