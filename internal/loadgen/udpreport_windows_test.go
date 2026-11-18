package loadgen

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Windows reports an ICMP port unreachable on a connected UDP socket as
// WSAECONNRESET (WSASend's documentation); it's a refusal.
func TestConnResetIsRefusal(t *testing.T) {
	if !isConnRefused(writeErr(windows.WSAECONNRESET)) {
		t.Error("isConnRefused missed WSAECONNRESET")
	}
}

// writesUntilRefused writes to c for up to a second and returns the error
// that showed the refusal (nil if none came).
func writesUntilRefused(t *testing.T, c net.Conn) error {
	t.Helper()
	for end := time.Now().Add(time.Second); time.Now().Before(end); {
		if _, err := c.Write([]byte("<13>woodshed test")); err != nil {
			if isConnRefused(err) {
				return err
			}
			t.Fatalf("write: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

// A sender's socket (dialUDP) sees a closed loopback port refuse; a plain Go
// socket, with Go's own setting, never does, so the difference is
// reportRefusals.
func TestDialUDPReportsRefusals(t *testing.T) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	dead := l.LocalAddr().String()
	l.Close()

	var d net.Dialer
	plain, err := d.DialContext(context.Background(), "udp", dead)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if err := writesUntilRefused(t, plain); err != nil {
		t.Fatalf("a plain Go UDP socket reported %v: Go's SIO_UDP_CONNRESET default changed", err)
	}

	c, err := dialUDP(context.Background(), &d, dead)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = writesUntilRefused(t, c)
	if err == nil {
		t.Fatal("no refusal from a closed port in 1 s")
	}
	t.Logf("refused: %v", err)
}
