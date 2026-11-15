package server

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/loadgen"
)

// liveLines streams /api/live?query and sends each message event's data line.
func liveLines(t *testing.T, base, query string) <-chan string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/api/live?"+query, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 1000)
	go func() {
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			if line := sc.Text(); strings.HasPrefix(line, "data: ") && strings.Contains(line, `"raw"`) {
				ch <- line
			}
		}
	}()
	return ch
}

// gotWithin reports whether a line containing want arrives on ch within d.
func gotWithin(ch <-chan string, want string, d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case l := <-ch:
			if strings.Contains(l, want) {
				return true
			}
		case <-deadline:
			return false
		}
	}
}

func TestLiveTailHidesHiddenDevices(t *testing.T) {
	dir := t.TempDir()
	port := freePort(t)
	r := start(t, writeConfig(t, dir, port, 0, nil))
	run := loadgen.NewRunID()
	send := func(seq int) string {
		t.Helper()
		if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{Addr: fmt.Sprintf("127.0.0.1:%d", port), Proto: "tcp",
			Count: 1, RunID: run, FirstSeq: seq, Message: "live"}); err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%s%d live", loadgen.SeqTag(run), seq)
	}
	send(0)
	waitFor(t, "the device in the index", func() bool {
		var page struct{ Devices []map[string]any }
		r.do(t, "GET", "/api/devices", nil, &page)
		return len(page.Devices) == 1
	})
	if code := r.do(t, "PATCH", "/api/devices/127.0.0.1", map[string]any{"hidden": true}, nil); code != 200 {
		t.Fatalf("hide: %d", code)
	}
	all := liveLines(t, r.base, "")
	named := liveLines(t, r.base, "devices=127.0.0.1")
	if gotWithin(all, loadgen.SeqTag(run)+"0 ", 300*time.Millisecond) {
		t.Error("a hidden device's message was replayed to a default subscriber")
	}
	if !gotWithin(named, loadgen.SeqTag(run)+"0 ", 5*time.Second) { // returns as soon as it arrives; 5 s like the others
		t.Error("a subscriber naming the hidden device didn't get its replay")
	}
	m1 := send(1)
	if !gotWithin(named, m1, 5*time.Second) {
		t.Error("a subscriber naming the hidden device didn't get its message")
	}
	if gotWithin(all, m1, 300*time.Millisecond) {
		t.Error("a hidden device's message reached a default subscriber")
	}
	// Un-hide: the open default stream gets the next message, no reconnect.
	if code := r.do(t, "PATCH", "/api/devices/127.0.0.1", map[string]any{"hidden": false}, nil); code != 200 {
		t.Fatalf("unhide: %d", code)
	}
	m2 := send(2)
	if !gotWithin(all, m2, 5*time.Second) {
		t.Error("after un-hiding, the default stream didn't get the device's message")
	}
}

func TestLiveDevicesEvictIdleSenders(t *testing.T) {
	l := newLiveDevices()
	t0 := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 50000; i++ {
		l.add(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), t0.Add(time.Duration(i)*time.Microsecond))
	}
	if n := l.len(); n != 50000 {
		t.Fatalf("%d tracked", n)
	}
	keep := netip.MustParseAddr("192.0.2.1")
	// Nine minutes on, one sender is still talking: nothing is old enough yet.
	l.add(keep, t0.Add(9*time.Minute))
	if n := l.len(); n != 50001 {
		t.Fatalf("evicted early: %d", n)
	}
	// Eleven minutes on, the 50,000 silent senders go; the talking one stays.
	l.add(keep, t0.Add(11*time.Minute))
	if n := l.len(); n != 1 {
		t.Fatalf("%d tracked after the sweep, want 1", n)
	}
	if st, ok := l.snapshot(t0.Add(11 * time.Minute))["192.0.2.1"]; !ok || st.MsgsPerMin == 0 {
		t.Errorf("survivor %+v %v", st, ok)
	}
}
