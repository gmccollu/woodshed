package store

import (
	"os"
	"testing"
)

// Every store test keeps the compressor at normal priority: none of them is about the OS scheduling a
// background-band thread, and on a busy CI runner (macOS especially) such a thread may not run for many seconds,
// which made tests that wait for a compression flaky. The starved-thread case is simulated with
// testHookLowerPrio (TestCloseDoesntWaitForAStarvedCompressor).
func TestMain(m *testing.M) {
	keepPrioForTests.Store(true)
	os.Exit(m.Run())
}
