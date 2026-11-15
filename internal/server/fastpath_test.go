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
	const n = 20
	for i := 0; i < n; i++ {
		fmt.Fprintf(conn, "<13>lone %d", i)
		time.Sleep(3 * time.Millisecond)
	}
	waitFor(t, "all received", func() bool { return ln.Status().Received == n })
	st := ln.Status()
	// The first one opens the device's stream, which TryWrite never does: it
	// goes through the queue.
	if st.Inline < n-2 {
		t.Errorf("%d of %d stored by the reader", st.Inline, n)
	}
	if p := r.srv.hub.Stats().Published; p != n {
		t.Errorf("published %d", p)
	}
	r.stop(t)
	if u := r.srv.be.store.Usage(); u.Written != n || u.Dropped != 0 {
		t.Errorf("store wrote %d, dropped %d", u.Written, u.Dropped)
	}
}
