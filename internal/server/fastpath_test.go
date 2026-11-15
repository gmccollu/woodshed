package server

import (
	"fmt"
	"net"
	"testing"
	"time"
)

// Lone UDP datagrams are stored by the reader through the store's TryWrite
// (no drainer wake-up), and are stored, counted and published like any other.
func TestUDPFastPath(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, writeConfig(t, dir, port, 0, nil))
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ln := r.srv.be.ln.Load()
	// The first datagram opens the device's stream, which TryWrite never does, so
	// it goes through the queue: send it alone and let it settle first.
	fmt.Fprintf(conn, "<13>warm-up")
	waitFor(t, "the warm-up stored", func() bool { return r.srv.be.store.Usage().Written == 1 })
	const n = 20
	for i := 0; i < n; i++ {
		time.Sleep(3 * time.Millisecond)
		fmt.Fprintf(conn, "<13>lone %d", i)
	}
	// Received is counted before the sink publishes (queue path) and before
	// Inline (fast path), so wait for what's read below.
	waitFor(t, "all received and published", func() bool {
		return ln.Status().Received == n+1 && r.srv.hub.Stats().Published == n+1
	})
	st := ln.Status()
	// On a busy runner a datagram can still take the queue (read within the quiet
	// gap of the one before, or a flush holding the device), so most, not all.
	if st.Inline < 15 {
		t.Errorf("%d of %d stored by the reader", st.Inline, n)
	}
	r.stop(t)
	if u := r.srv.be.store.Usage(); u.Written != n+1 || u.Dropped != 0 {
		t.Errorf("store wrote %d, dropped %d", u.Written, u.Dropped)
	}
}
