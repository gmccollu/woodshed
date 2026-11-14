package store_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store"
)

// TestQueuedUDPDuringLowDiskPause: messages waiting in the UDP queue when the
// low-disk guard pauses writing are dropped as "paused" when the drainer reaches
// them, counted for their device, never lost uncounted. The real listener,
// queue and store.
func TestQueuedUDPDuringLowDiskPause(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	var free atomic.Uint64
	free.Store(1 << 40)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Manual: true, Logger: quiet, MinFreeBytes: 1 << 30,
		DiskUsage: func(string) (uint64, uint64, error) { return free.Load(), 2 << 40, nil }})
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var mu sync.Mutex
	gate := make(chan struct{})
	var inSink atomic.Int32
	sink := func(m model.Message) {
		mu.Lock()
		g := gate
		mu.Unlock()
		if g != nil {
			inSink.Add(1)
			<-g
		}
		st.Write(m)
	}
	ln, err := listen.Start(config.Listeners{UDP: config.Listener{Enabled: true, Addr: "127.0.0.1"}},
		listen.Options{Sink: sink, OnQueueDrop: st.DropQueued, Logger: quiet, Holder: func(string, int) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	ap, _ := ln.UDPAddr()
	conn, err := net.Dial("udp", ap.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// One message to stall the drainer on, then 499 that wait in the queue.
	conn.Write([]byte("<13>m0"))
	waitUntil(t, func() bool { return inSink.Load() == 1 })
	for i := 1; i < 500; i++ {
		fmt.Fprintf(conn, "<13>m%d", i)
	}
	waitUntil(t, func() bool { return ln.Status().UDPQueues[0].Depth == 499 })

	// The disk fills: the guard pauses writing while they're queued.
	free.Store(1 << 20)
	if err := st.Maintain(); err != nil {
		t.Fatal(err)
	}
	if !st.Paused() {
		t.Fatal("not paused")
	}
	mu.Lock()
	close(gate)
	gate = nil
	mu.Unlock()
	ln.Close() // drains the queue into the (paused) store

	if r := st.DropsByReason24h(); r != (store.DropReasons{Paused: 500}) {
		t.Fatalf("by reason %+v", r)
	}
	if u := st.Usage(); u.Dropped != 500 || u.Written != 0 {
		t.Fatalf("usage dropped %d written %d", u.Dropped, u.Written)
	}
	if err := st.Flush(); err != nil {
		t.Fatal(err)
	}
	per, err := idx.DeviceCounts(context.Background(), time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if per["127.0.0.1"].Dropped != 500 {
		t.Fatalf("device stats %+v", per)
	}
	if q := ln.Status().UDPQueues[0]; q.Dropped != 0 {
		t.Fatalf("counted as queue drops too: %+v", q)
	}
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
