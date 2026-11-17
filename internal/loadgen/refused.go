package loadgen

import (
	"fmt"
	"sync"
	"time"
)

// RefusedGrace is how long a UDP sender must have been sending without a
// refusal before a refusal stops being fatal (SPEC §13.10 decision 84).
//
// A refusal is the OS reporting, on a later send, an ICMP port unreachable
// for an earlier datagram: nothing was listening on the port when it
// arrived. Before the sender has gone RefusedGrace without one, nothing has
// ever answered, so it stops at once, as before ("nothing is listening"). After
// that the receiver was listening and has gone away for a while (a restart):
// the refusal is counted, the datagram is sent again (the OS consumed the
// error instead of sending it), and sending goes on, as a real exporter's does.
const RefusedGrace = time.Second

// refusals tracks a sender's refusals. Safe for concurrent use (a trap
// sender's reply reader shares it).
type refusals struct {
	mu    sync.Mutex
	since time.Time // the first send, or the last refusal before the sender was established
	ok    bool      // a refusal-free RefusedGrace has passed: the receiver was listening
	n     int
}

// wrote notes a datagram the OS accepted.
func (r *refusals) wrote(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.since.IsZero() {
		r.since = now
	}
	if !r.ok && now.Sub(r.since) >= RefusedGrace {
		r.ok = true
	}
}

// refused handles a refusal: fatal (nothing has ever answered) before the
// sender is established, else counted.
func (r *refusals) refused() (fatal bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ok {
		return true
	}
	r.n++
	return false
}

func (r *refusals) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func notListening(addr string) error {
	return fmt.Errorf("loadgen: %s: nothing is listening (connection refused)", addr)
}

// RefusedText is the summary's words for n refusals ("" for none).
func RefusedText(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%d refused (ICMP port unreachable: the receiver stopped listening for a while, so at least that many "+
		"datagrams were lost); sending went on", n)
}
