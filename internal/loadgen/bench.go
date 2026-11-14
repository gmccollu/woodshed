package loadgen

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

// Defaults for BenchOptions.
const (
	DefaultBenchRate     = 10000
	DefaultBenchDuration = 30 * time.Second
	DefaultSettle        = 5 * time.Second
)

// BenchOptions configures Bench.
type BenchOptions struct {
	Proto    string        // "udp" (default), "tcp" or "tls"
	Framing  string        // TCP: "lf" (default) or "octet"
	Rate     float64       // target messages per second (default 10,000)
	Duration time.Duration // how long to send (default 30 s)
	Size     int           // approximate message size (default 200 bytes)

	// DataDir is where the store writes. Empty means a new temp dir, deleted
	// afterwards unless Keep is set. A given DataDir is never deleted.
	DataDir string
	Keep    bool

	// Settle is how long to wait, after the last send, with no new message arriving
	// before giving up on the rest (default 5 s).
	Settle      time.Duration
	RcvbufBytes int          // UDP receive buffer to request (default 32 MiB)
	Logger      *slog.Logger // for the store and listener; default discards

	// QueueMessages is the UDP receive queue's capacity (default
	// listeners.udp_queue_messages' default).
	QueueMessages int
	// A fake slow disk (SPEC §11.6): every StallEvery from the start, writes
	// block for StallFor, as a store whose write hangs on an fsync would.
	// Both zero: no stalls.
	StallEvery, StallFor time.Duration
}

// BenchResult is what Bench measured. Missing and Duplicates come from reading
// the log files back, not from counters.
type BenchResult struct {
	Proto   string
	Framing string `json:",omitempty"`
	RunID   string

	Sent       int64 // messages the sender handed to the OS
	Received   int64 // distinct sequence numbers found on disk
	Missing    int64 // sent but not on disk
	Duplicates int64 // extra copies on disk
	Foreign    int64 // lines on disk that aren't from this run (a reused DataDir)

	Listened       int64 // messages the listener passed to the pipeline
	Stored         int64 // messages the store wrote
	StoreDropped   int64 // messages the store refused (low disk, write errors), not counting QueueDropped
	StoreQueueFull int64 // UDP queue drops as the store counted them (dropped_by_reason.queue_full)
	Stalls         int   // fake slow-disk stalls that happened (StallEvery, StallFor)

	TargetRate   float64
	AchievedRate float64       // Sent / SendTime
	SendTime     time.Duration // time spent sending
	Elapsed      time.Duration // the whole run, including settling and the read-back

	UDPRcvbufBytes          int
	UDPRcvbufRequestedBytes int
	KernelDropsVisible      bool
	KernelDrops             int64 // Linux only
	Backpressure            int   // UDP sends retried because the OS send queue was full
	QueueCapacity           int   // UDP: the receive queue's capacity in messages (SPEC §11.5)
	QueueHighWater          int   // UDP: the most messages waiting in it at once
	QueueDropped            int64 // UDP: dropped because it was full (counted, unlike kernel drops)

	DataDir  string // where the files are (removed unless Keep or a given DataDir)
	LogBytes int64  // bytes of log files written
}

// OK reports whether every message sent arrived exactly once.
func (r BenchResult) OK() bool { return r.Sent > 0 && r.Missing == 0 && r.Duplicates == 0 }

// Accounted reports whether every message sent was stored once or counted as a
// UDP queue drop (by the listener and by the store alike): nothing was lost
// uncounted, in the kernel or anywhere else.
func (r BenchResult) Accounted() bool {
	return r.Sent > 0 && r.Duplicates == 0 && r.Missing == r.QueueDropped && r.StoreQueueFull == r.QueueDropped
}

// String is a human-readable summary.
func (r BenchResult) String() string {
	var b strings.Builder
	proto := strings.ToUpper(r.Proto)
	if r.Proto == "tcp" || r.Proto == "tls" {
		proto += " (" + r.Framing + ")"
	}
	verdict := "PASS"
	if !r.OK() {
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "%s %s: sent %d in %v (%.0f msg/s, target %.0f)\n", verdict, proto, r.Sent,
		r.SendTime.Round(time.Millisecond), r.AchievedRate, r.TargetRate)
	fmt.Fprintf(&b, "  on disk: %d received, %d missing, %d duplicates", r.Received, r.Missing, r.Duplicates)
	if r.Foreign > 0 {
		fmt.Fprintf(&b, ", %d other lines", r.Foreign)
	}
	fmt.Fprintf(&b, "\n  pipeline: listener %d, store wrote %d, store dropped %d\n", r.Listened, r.Stored, r.StoreDropped)
	if r.Proto == "udp" {
		fmt.Fprintf(&b, "  UDP receive buffer: %d bytes granted of %d requested\n", r.UDPRcvbufBytes, r.UDPRcvbufRequestedBytes)
		if r.KernelDropsVisible {
			fmt.Fprintf(&b, "  kernel UDP drops: %d\n", r.KernelDrops)
		} else {
			b.WriteString("  kernel UDP drops: not visible on this OS\n")
		}
		fmt.Fprintf(&b, "  UDP queue: high-water %d of %d messages, %d dropped because it was full\n",
			r.QueueHighWater, r.QueueCapacity, r.QueueDropped)
		if r.Stalls > 0 {
			fmt.Fprintf(&b, "  fake slow disk: %d stalls\n", r.Stalls)
		}
		switch {
		case r.Missing == 0:
		case r.Accounted():
			b.WriteString("  every missing message was counted as a queue drop: none lost uncounted\n")
		default:
			fmt.Fprintf(&b, "  %d missing messages weren't counted by Woodshed (lost before it read them: the kernel or the network)\n",
				r.Missing-r.QueueDropped)
		}
		if r.Backpressure > 0 {
			fmt.Fprintf(&b, "  sender backpressure retries: %d\n", r.Backpressure)
		}
	}
	return b.String()
}

// Bench runs an in-process pipeline (listener on 127.0.0.1, store and live hub,
// as the server wires them), sends Rate × Duration messages to it, waits for them
// to settle, closes the store and then reads every log file back to check that
// each sequence number arrived exactly once.
func Bench(ctx context.Context, o BenchOptions) (BenchResult, error) {
	t0 := time.Now()
	if o.Proto == "" {
		o.Proto = "udp"
	}
	if (o.Proto == "tcp" || o.Proto == "tls") && o.Framing == "" {
		o.Framing = "lf"
	}
	if o.Rate <= 0 {
		o.Rate = DefaultBenchRate
	}
	if o.Duration <= 0 {
		o.Duration = DefaultBenchDuration
	}
	if o.Settle <= 0 {
		o.Settle = DefaultSettle
	}
	if o.RcvbufBytes <= 0 {
		o.RcvbufBytes = config.DefaultUDPRcvbufBytes
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	res := BenchResult{Proto: o.Proto, Framing: o.Framing, RunID: NewRunID(), TargetRate: o.Rate}

	dir := o.DataDir
	if dir == "" {
		d, err := os.MkdirTemp("", "woodshed-bench-*")
		if err != nil {
			return res, err
		}
		dir = d
		if !o.Keep {
			defer os.RemoveAll(dir)
		}
	}
	res.DataDir = dir

	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		return res, err
	}
	defer idx.Close()
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Logger: o.Logger})
	if err != nil {
		return res, err
	}
	storeOpen := true
	defer func() {
		if storeOpen {
			st.Close()
		}
	}()
	live := hub.New(hub.Options{})
	defer live.Close()

	var writeErrs atomic.Int64
	var stalls atomic.Int64
	cfg := config.Listeners{UDPRcvbufBytes: o.RcvbufBytes, MaxMessageBytes: config.DefaultMaxMessageBytes,
		UDPQueueMessages: o.QueueMessages}
	ln := config.Listener{Enabled: true, Addr: "127.0.0.1", Port: 0}
	var certs *tlscert.Manager
	var clientTLS *tls.Config
	switch o.Proto {
	case "udp":
		cfg.UDP = ln
	case "tls":
		// Woodshed's own CA and certificate, made in the bench's data folder.
		cfg.TLS = config.TLSListener{Enabled: true, Addr: ln.Addr, Port: 0}
		certs = tlscert.New(tlscert.Options{DataDir: dir, Identity: func() (tlscert.Identity, error) {
			return tlscert.Identity{Host: "localhost", Primary: "localhost", Names: []string{"localhost"},
				IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}, nil
		}})
		if _, err := certs.Load(true); err != nil {
			return res, err
		}
		der, err := certs.CADER()
		if err != nil {
			return res, err
		}
		ca, _ := x509.ParseCertificate(der)
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		clientTLS = &tls.Config{RootCAs: pool, ServerName: "localhost"}
	default:
		cfg.TCP = ln
	}
	stall := newStaller(o.StallEvery, o.StallFor)
	lopts := listen.Options{
		Logger: o.Logger,
		Sink: func(m model.Message) {
			if stall.wait() {
				stalls.Add(1)
			}
			if st.Write(m) != nil {
				writeErrs.Add(1)
			}
			live.Publish(m)
		},
		OnQueueDrop: st.DropQueued,
	}
	if certs != nil {
		lopts.TLSCertificate = certs.Certificate
	}
	srv, err := listen.Start(cfg, lopts)
	if err != nil {
		return res, err
	}
	listenerOpen := true
	defer func() {
		if listenerOpen {
			srv.Close()
		}
	}()
	addr, ok := srv.UDPAddr()
	switch o.Proto {
	case "tcp":
		addr, ok = srv.TCPAddr()
	case "tls":
		addr, ok = srv.TLSAddr()
	}
	if !ok {
		ls := srv.Status().Listeners
		if len(ls) > 0 {
			return res, fmt.Errorf("loadgen: listener failed: %s", ls[0].Error)
		}
		return res, errors.New("loadgen: listener failed to start")
	}
	stat := srv.Status()
	res.UDPRcvbufBytes, res.UDPRcvbufRequestedBytes = stat.UDPRcvbufBytes, stat.UDPRcvbufRequestedBytes

	sres, sendErr := Send(ctx, SendOptions{
		Addr: addr.String(), Proto: o.Proto, Framing: o.Framing, TLS: clientTLS,
		Rate: o.Rate, Duration: o.Duration, Size: o.Size, RunID: res.RunID,
	})
	res.Sent, res.SendTime, res.AchievedRate, res.Backpressure = int64(sres.Sent), sres.Elapsed, sres.Rate, sres.Backpressure
	if sendErr != nil && res.Sent == 0 {
		return res, sendErr
	}

	// Let the listener catch up: wait until it has passed on (or counted as
	// dropped from its queue) everything sent, or nothing new has arrived for
	// Settle.
	last, lastChange := int64(-1), time.Now()
	for {
		n := srv.Status().Received + queueDropped(srv.Status())
		if n >= res.Sent {
			break
		}
		if n != last {
			last, lastChange = n, time.Now()
		} else if time.Since(lastChange) > o.Settle {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	srv.Close() // drains the UDP queue
	listenerOpen = false
	stat = srv.Status()
	res.Listened = stat.Received
	for _, q := range stat.UDPQueues {
		res.QueueCapacity, res.QueueHighWater, res.QueueDropped = q.CapacityMessages, q.HighWater24h, q.Dropped
	}
	res.KernelDropsVisible, res.KernelDrops = stat.KernelDropsVisible, stat.KernelDrops

	if err := st.Flush(); err != nil {
		return res, fmt.Errorf("loadgen: flushing the store: %w", err)
	}
	u := st.Usage() // Written counts messages once they're in the files
	res.StoreQueueFull = st.DropsByReason24h().QueueFull
	if err := st.Close(); err != nil {
		return res, fmt.Errorf("loadgen: closing the store: %w", err)
	}
	storeOpen = false
	res.Stored, res.StoreDropped = u.Written, u.Dropped-res.StoreQueueFull+writeErrs.Load()
	res.Stalls = int(stalls.Load())

	v, err := Verify(dir, res.RunID, int(res.Sent))
	if err != nil {
		return res, err
	}
	res.Received, res.Missing, res.Duplicates, res.Foreign, res.LogBytes = v.Received, v.Missing, v.Duplicates, v.Foreign, v.LogBytes
	res.Elapsed = time.Since(t0)
	return res, sendErr
}

// staller is the fake slow disk: from start, every `every`, writes block for
// `for_`. Only the UDP drainer (one goroutine) or TCP connections call it.
type staller struct {
	start       time.Time
	every, for_ time.Duration
	mu          sync.Mutex
	last        int // the stall last waited for
}

func newStaller(every, for_ time.Duration) *staller {
	return &staller{start: time.Now(), every: every, for_: for_}
}

// wait blocks until the end of the stall in progress, if any, and reports
// whether it was the first wait in that stall.
func (s *staller) wait() bool {
	if s == nil || s.every <= 0 || s.for_ <= 0 {
		return false
	}
	el := time.Since(s.start)
	k := int(el / s.every)
	if k == 0 || el-time.Duration(k)*s.every >= s.for_ {
		return false
	}
	time.Sleep(time.Duration(k)*s.every + s.for_ - el)
	s.mu.Lock()
	first := s.last != k
	s.last = k
	s.mu.Unlock()
	return first
}

func queueDropped(st listen.Status) int64 {
	var n int64
	for _, q := range st.UDPQueues {
		n += q.Dropped
	}
	return n
}

// VerifyResult is what Verify found on disk.
type VerifyResult struct {
	Received   int64 // distinct sequence numbers in [0, n)
	Missing    int64
	Duplicates int64
	Foreign    int64 // lines without this run's tag, or with a sequence number out of range
	LogBytes   int64
}

// Verify reads every log file under dataDir (compressed or not) and checks that
// sequence numbers 0..n-1 of runID each appear exactly once.
func Verify(dataDir, runID string, n int) (VerifyResult, error) {
	var v VerifyResult
	files, _, err := logfile.List(dataDir)
	if err != nil {
		return v, err
	}
	seen := make([]uint8, n)
	tag := []byte(SeqTag(runID))
	for _, f := range files {
		v.LogBytes += f.Size
		r, err := logfile.Open(f.Path)
		if err != nil {
			return v, err
		}
		_, err = logfile.Scan(r, logfile.ScanOptions{OnLine: func(_ int64, l logfile.Line) error {
			i := bytes.Index(l.Escaped, tag)
			if i < 0 {
				v.Foreign++
				return nil
			}
			num := l.Escaped[i+len(tag):]
			if j := bytes.IndexByte(num, ' '); j >= 0 {
				num = num[:j]
			}
			seq, err := strconv.Atoi(string(num))
			if err != nil || seq < 0 || seq >= n {
				v.Foreign++
				return nil
			}
			if seen[seq] < 255 {
				seen[seq]++
			}
			return nil
		}})
		r.Close()
		if err != nil {
			return v, fmt.Errorf("loadgen: reading %s: %w", f.Rel, err)
		}
	}
	for _, c := range seen {
		switch {
		case c == 0:
			v.Missing++
		default:
			v.Received++
			v.Duplicates += int64(c) - 1
		}
	}
	return v, nil
}
