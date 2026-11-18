package loadgen

import (
	"context"
	"fmt"
	"net"
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

// Refusals are a sender's counted refusals (RefusedGrace) and when the first
// and last came. The count is a lower bound on the datagrams lost: the OS
// keeps one pending error per socket and ICMP replies are rate-limited, so
// many datagrams can be lost for each refusal reported. On Windows the
// sender's sockets turn the reporting Go switches off back on (reportRefusals).
type Refusals struct {
	Count       int
	First, Last time.Time
}

// refusals tracks a sender's refusals. Safe for concurrent use (a trap
// sender's reply reader shares it).
type refusals struct {
	mu sync.Mutex
	// since is the first datagram the OS accepted; ok turns true once a
	// RefusedGrace has passed since then with no refusal (a refusal before
	// that is fatal, so since never moves).
	since time.Time
	ok    bool
	r     Refusals
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

// refused handles a refusal at now: fatal (nothing has ever answered)
// before the sender is established, else counted.
func (r *refusals) refused(now time.Time) (fatal bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ok {
		return true
	}
	if r.r.Count == 0 {
		r.r.First = now
	}
	r.r.Count++
	r.r.Last = now
	return false
}

func (r *refusals) result() Refusals {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.r
}

// dialUDP dials a connected UDP socket for a sender, with refusals reported
// (reportRefusals). Only senders use it, never a listener.
func dialUDP(ctx context.Context, d *net.Dialer, addr string) (net.Conn, error) {
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	reportRefusals(c)
	return c, nil
}

func notListening(addr string) error {
	return fmt.Errorf("loadgen: %s: nothing is listening (connection refused)", addr)
}

// RefusedText is the summary's words for a sender's refusals ("" for none).
func RefusedText(r Refusals) string {
	if r.Count <= 0 {
		return ""
	}
	span := r.First.Format("15:04:05.000")
	if r.Last.After(r.First) {
		span = "from " + span + " to " + r.Last.Format("15:04:05.000") + fmt.Sprintf(" (%.1f s)", r.Last.Sub(r.First).Seconds())
	} else {
		span = "at " + span
	}
	return fmt.Sprintf("The receiver refused datagrams %s: %d ICMP port unreachable reported, a lower bound on the datagrams "+
		"lost (one is reported per send at most, and ICMP is rate-limited); sending went on", span, r.Count)
}
