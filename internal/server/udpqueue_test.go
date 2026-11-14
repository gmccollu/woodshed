package server

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/listen"
)

func TestUDPQueueBanner(t *testing.T) {
	if b := udpQueueBanner(nil); b != nil {
		t.Errorf("no queues: %+v", b)
	}
	at := time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)
	q := listen.QueueStatus{Listener: "udp", CapacityMessages: 100000, CapacityBytes: 64 << 20, Dropped24h: 500}
	if b := udpQueueBanner([]listen.QueueStatus{q}); b != nil {
		t.Errorf("drops only earlier than the last hour: %+v", b)
	}
	q.DroppedLastHour, q.LastFullBy, q.LastDrop = 123, listen.FullByMessages, &at
	b := udpQueueBanner([]listen.QueueStatus{q})
	want := "123 UDP messages were dropped in the last hour because writing to disk fell behind (the queue holds 100,000). " +
		"Check the disk, or raise listeners.udp_queue_messages."
	if b == nil || b.Kind != "udp_queue_full" || b.Level != api.LevelWarn || b.Action != "" || b.Text != want {
		t.Errorf("banner %+v", b)
	}
	// The byte limit refused the latest: the advice names it.
	q.DroppedLastHour, q.LastFullBy = 1, listen.FullByBytes
	if b := udpQueueBanner([]listen.QueueStatus{q}); b == nil || !strings.HasPrefix(b.Text, "1 UDP message was dropped") ||
		!strings.Contains(b.Text, "(the queue holds 64 MiB)") || !strings.HasSuffix(b.Text, "raise listeners.udp_queue_bytes.") {
		t.Errorf("bytes banner %+v", b)
	}
	// Two listeners: one banner, the counts summed, the advice from the latest.
	later := at.Add(time.Minute)
	q2 := listen.QueueStatus{Listener: "snmp", CapacityMessages: 2000, DroppedLastHour: 1000, LastFullBy: listen.FullByMessages, LastDrop: &later}
	if b := udpQueueBanner([]listen.QueueStatus{q, q2}); b == nil || !strings.HasPrefix(b.Text, "1,001 UDP messages") ||
		!strings.Contains(b.Text, "holds 2,000") {
		t.Errorf("two listeners %+v", b)
	}
}

func TestGroupDigits(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 100000: "100,000", 2000000: "2,000,000", -1234: "-1,234"} {
		if got := groupDigits(n); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}

// /api/stats has the queue and the drops by reason; a stop drains what the
// UDP reader read into the store, so nothing read is lost.
func TestUDPQueueStatsAndShutdown(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, writeConfig(t, dir, port, 0, nil))
	var st api.Stats
	r.do(t, "GET", "/api/stats", nil, &st)
	if len(st.UDPQueue) != 1 || st.UDPQueue[0].Listener != "udp" || st.UDPQueue[0].Port != port ||
		st.UDPQueue[0].CapacityMessages != 100000 || st.UDPQueue[0].CapacityBytes != 64<<20 || len(st.UDPQueue[0].HighWaterByHour) != 1 ||
		st.DroppedByReason != (api.DroppedByReason{}) {
		t.Fatalf("stats %+v", st)
	}
	// The JSON has every key, empty or not.
	var raw map[string]any
	r.do(t, "GET", "/api/stats", nil, &raw)
	if s := fmt.Sprint(raw["dropped_by_reason"]); s != "map[paused:0 queue_full:0 refused:0 write_error:0]" {
		t.Errorf("dropped_by_reason %s", s)
	}

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(conn, "<13>m%d", i)
	}
	ln := r.srv.be.ln.Load()
	waitFor(t, "some received", func() bool { return ln.Status().Received > 0 })
	t0 := time.Now()
	r.stop(t)
	if d := time.Since(t0); d > 5*time.Second {
		t.Errorf("stop took %v", d)
	}
	ls := ln.Status()
	u := r.srv.be.store.Usage()
	if ls.Received == 0 || u.Written+u.Dropped != ls.Received || ls.UDPQueues[0].Depth != 0 {
		t.Errorf("listener passed on %d, store wrote %d and dropped %d; queue depth %d", ls.Received, u.Written, u.Dropped, ls.UDPQueues[0].Depth)
	}
}
