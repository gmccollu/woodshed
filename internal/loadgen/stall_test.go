package loadgen

import (
	"context"
	"testing"
	"time"
)

// TestStalledDisk is SPEC §11.6's UDP queue test, shortened: writes block for 2 s
// every 3 s while UDP arrives at a steady rate, through the real listener,
// queue, drainer and store. With the default queue nothing is lost and the
// queue absorbs each stall; with a 1,000-message queue the overflow is counted
// exactly (sent = stored + counted drops, so the kernel dropped nothing), per
// the listener and per the store alike.
func TestStalledDisk(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	rate := 5000.0
	if raceEnabled {
		rate = 2000
	}
	opts := BenchOptions{Proto: "udp", Rate: rate, Duration: 7 * time.Second, StallEvery: 3 * time.Second, StallFor: 2 * time.Second}

	t.Run("default queue", func(t *testing.T) {
		res, err := Bench(context.Background(), opts)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("race=%v\n%s", raceEnabled, res.String())
		if !res.OK() || res.QueueDropped != 0 || res.StoreQueueFull != 0 {
			t.Errorf("%d missing, %d duplicates, %d queue drops of %d sent", res.Missing, res.Duplicates, res.QueueDropped, res.Sent)
		}
		if res.Stalls != 2 {
			t.Errorf("%d stalls, want 2", res.Stalls)
		}
		// Each stall held about 2 s of messages in the queue.
		if min := int(rate); res.QueueHighWater < min {
			t.Errorf("queue high-water %d, want at least %d (the stalls weren't absorbed by the queue)", res.QueueHighWater, min)
		}
	})

	t.Run("small queue", func(t *testing.T) {
		o := opts
		o.QueueMessages = 1000
		res, err := Bench(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("race=%v\n%s", raceEnabled, res.String())
		if res.QueueDropped == 0 {
			t.Fatal("no queue drops with a 1,000-message queue")
		}
		if !res.Accounted() {
			t.Errorf("sent %d = on disk %d + missing %d; queue drops %d (listener), %d (store): not every loss was counted",
				res.Sent, res.Received, res.Missing, res.QueueDropped, res.StoreQueueFull)
		}
		if res.Received+res.QueueDropped != res.Sent {
			t.Errorf("sent %d != stored %d + counted drops %d", res.Sent, res.Received, res.QueueDropped)
		}
		if res.KernelDropsVisible && res.KernelDrops != 0 {
			t.Errorf("%d kernel drops", res.KernelDrops)
		}
		if res.QueueHighWater != 1000 {
			t.Errorf("queue high-water %d, want 1000", res.QueueHighWater)
		}
		if res.StoreDropped != 0 {
			t.Errorf("store dropped %d for other reasons", res.StoreDropped)
		}
	})
}
