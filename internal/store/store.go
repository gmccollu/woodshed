// Package store writes received messages to Woodshed's plain log files (SPEC §3.3–3.4)
// and keeps them within the disk budget.
//
// Layout: <data>/logs/<model.DeviceID(sender)>/<YYYY-MM-DD>.log is a device's active
// file. It is closed at 00:00 UTC, or at PartBytes, when it is renamed to the next
// numbered part <YYYY-MM-DD>.NNN.log. A background worker gzips closed files to .log.gz
// (verifying the gzip before deleting the original), and retention deletes the oldest
// compressed files by age, by total size and when the disk runs low.
//
// Writes are buffered per device and flushed every FlushInterval or FlushBytes, and
// fsynced every SyncInterval, so a crash loses at most about SyncInterval of data.
// See package logfile for the line format.
package store

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Defaults for Options.
const (
	DefaultPartBytes      = 100 << 20
	DefaultRetentionDays  = 30
	DefaultRetentionBytes = 20 << 30
	DefaultMinFreeBytes   = 1 << 30
	DefaultMinFreePercent = 5.0
	DefaultMaxReserve     = 10 << 30
	DefaultFlushInterval  = time.Second
	DefaultFlushBytes     = 1 << 20
	DefaultSyncInterval   = 5 * time.Second
	DefaultMaxOpenFiles   = 512
	DefaultCloseWorkers   = 8

	DefaultMaxDevices          = 10000
	DefaultNewDeviceBurst      = 5000
	DefaultNewDevicesPerMinute = 200.0
	DefaultIdleClose           = 10 * time.Minute
	DefaultIdleEvict           = time.Minute
)

// Errors returned by Write.
var (
	ErrClosed        = errors.New("store: closed")
	ErrPaused        = errors.New("store: writes paused: the disk is nearly full")
	ErrInvalidSender = errors.New("store: message has no valid sender address")
	ErrDeviceLimit   = errors.New("store: new sender refused: device cap or new-device rate reached")
)

// Options configures a Store. Zero fields take the defaults above.
type Options struct {
	DataDir string    // required; logs go under DataDir/logs
	Index   *index.DB // required; the store doesn't close it

	PartBytes      int64 // close the active file at this size (uncompressed)
	RetentionDays  int   // delete compressed files older than this
	RetentionBytes int64 // delete the oldest compressed files while all logs exceed this
	// Low-disk guard reserve: keep max(MinFreeBytes, min(MinFreePercent of the
	// volume, MaxReserveBytes)) free. The floor protects small volumes; the cap keeps
	// a large volume from reserving tens of GB it never needs.
	MinFreeBytes    uint64
	MinFreePercent  float64
	MaxReserveBytes uint64
	// Reclaim, if set, is called by the low-disk guard before it deletes any log
	// file, with the number of bytes it needs freed. It should delete files that
	// matter less than logs (exports) and return how many bytes it freed; the
	// guard then reads the free space again. It runs on the maintenance loop, so
	// it must be quick and must not call the Store.
	Reclaim func(need uint64) (freed uint64)

	FlushInterval time.Duration // write buffers to the files at least this often
	FlushBytes    int           // and whenever a device's buffer reaches this
	SyncInterval  time.Duration // fsync written files this often
	MaxOpenFiles  int           // cap on open log file handles (LRU)
	// New-sender limits, so spoofed or rotating source addresses can't exhaust memory
	// and disk. At most MaxDevices senders are held in memory at once. A sender with
	// no logs on disk yet also needs a token from a bucket of NewDeviceBurst that
	// refills at NewDevicesPerMinute. A refused message counts as dropped (stats under
	// index.RefusedDeviceID, Usage.RefusedMsgs) and Write returns ErrDeviceLimit.
	MaxDevices          int
	NewDeviceBurst      int
	NewDevicesPerMinute float64
	// PrefixBurst and PrefixPerMinute size the per-network buckets in front of the
	// global one (a /24 for IPv4, a /48 for IPv6), so one network can't keep the global
	// bucket empty. Defaults 256 and 20.
	PrefixBurst     float64
	PrefixPerMinute float64
	// ReadmitPerSecond limits how many known senders that aren't resident are
	// readmitted a second while the cap is full (each one evicts the least recently
	// heard resident). Beyond it they're refused (reason "churn"). Default 500.
	ReadmitPerSecond float64
	// IdleClose closes a quiet sender's file early, before midnight, once nothing was
	// heard for this long; its next message appends to the same file. IdleEvict then
	// frees the sender's in-memory state once it has no open file and nothing was
	// heard for that long; it's recreated on its next message, and its index row is
	// kept. So MaxDevices bounds the senders heard in about the last IdleClose.
	IdleClose time.Duration
	IdleEvict time.Duration

	// CloseWorkers bounds how many closed files (yesterday's at midnight, or a full
	// part) are fsynced at once, off the write path.
	CloseWorkers int

	// Clock returns the current time (tests inject a fake). It decides midnight
	// rotation of idle files, retention age and the time of a message with a zero
	// Received. Default time.Now.
	Clock func() time.Time
	// DiskUsage reports the free and total bytes of the volume holding path (tests
	// inject a fake). Default: the real DiskUsage for this OS.
	DiskUsage func(path string) (free, total uint64, err error)

	// Manual turns off every background goroutine. Call Maintain to rotate, compress,
	// apply retention and update the index, and Flush to write and fsync. Compression
	// then runs inside Maintain. Meant for tests.
	Manual bool

	Logger *slog.Logger // default slog.Default()
}

// Limits are the settings that can change while the store runs.
type Limits struct {
	RetentionDays  int
	RetentionBytes int64
	PartBytes      int64

	MaxDevices          int
	NewDeviceBurst      int
	NewDevicesPerMinute float64
}

// Store writes messages to log files. It is safe for concurrent use.
type Store struct {
	opts    Options
	dataDir string
	logsDir string
	idx     *index.DB
	clock   func() time.Time
	disk    func(string) (uint64, uint64, error)
	log     *slog.Logger

	retentionDays  atomic.Int64
	retentionBytes atomic.Int64
	partBytes      atomic.Int64

	devices  sync.Map // netip.Addr -> *device, for the lock-free lookup in Write
	devMu    sync.Mutex
	devSet   map[netip.Addr]*device   // the same devices, authoritative (devMu)
	known    map[string]struct{}      // device IDs with logs on disk or seen since Open (devMu)
	leavingN int                      // residents marked for eviction (devMu)
	readmit  bucket                   // re-admissions at the cap (devMu)
	resMu    sync.Mutex               // guards resident and device.resElem (a leaf lock)
	resident list.List                // resident devices, most recently heard first
	global   bucket                   // new-sender bucket (devMu)
	prefixes map[netip.Prefix]*bucket // per-network new-sender buckets (devMu)
	// The live new-sender limits (devMu); Options holds only the initial values.
	maxDevices int
	burst      int
	perMinute  float64

	refMu       sync.Mutex
	refMinutes  map[int64]int64 // refused messages per unix minute, not yet in the index
	refPending  int64           // refused since the last device_limit event
	refReason   string          // "cap" or "rate", the latest
	lastRefEv   time.Time
	refusedMsgs atomic.Int64
	lastRefused atomic.Int64 // unix ms

	closed      atomic.Bool
	paused      atomic.Bool
	pausedSince atomic.Int64 // unix ms
	dropped     atomic.Int64 // messages dropped since Open
	written     atomic.Int64 // messages written to files since Open
	activeBytes atomic.Int64 // bytes on disk in active files

	lruMu     sync.Mutex
	lru       list.List // of *device with an open handle, most recent first
	openFiles int
	maxOpen   int // high-water mark of openFiles, for tests

	qMu     sync.Mutex
	qOps    []index.FileOp
	qAct    []index.Activity
	qEvents []index.Event
	applyMu sync.Mutex

	catMu    sync.Mutex
	cat      map[string]*catEntry // closed files by rel path
	catBytes int64
	orphans  map[string]bool // compressed originals still to delete (abs paths)

	diskMu       sync.Mutex
	lastFree     uint64
	lastTotal    uint64
	diskErrShown bool

	maintMu   sync.Mutex
	lastPrune time.Time

	reasons    reasonHours // drops by reason, last 24 h (DropsByReason24h)
	dropMu     sync.Mutex
	dropCounts map[dropKey]int64 // drops not yet reported in an event
	dropErrs   map[string]string // device -> last write error
	lastDropEv time.Time

	stop       chan struct{}
	wg         sync.WaitGroup
	compressCh chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc

	closeMu   sync.Mutex
	closeCond *sync.Cond
	closeQ    []closeJob
	closeStop bool
	closeWG   sync.WaitGroup
	syncPath  func(path string) error // fsync by path; tests slow it down

	lastRollup     time.Time
	lastFloodCheck time.Time
	lastUnparkDay  string

	// clockHW is the highest received time written (unix ms), to notice the
	// received clock stepping back (watchClock).
	clockHW atomic.Int64

	// testHookGzip, if set, is called with the temp gzip path before verification.
	testHookGzip func(path string)
}

// watchClock records a warning event when a message's received time is more
// than logfile.MaxSkew before the newest one written: the system clock stepped
// back, so lines within a file are out of order by more than readers allow
// for, and searches near that time may miss lines. It warns once per step
// (the high-water mark moves back with the clock).
func (s *Store) watchClock(rec time.Time) {
	ms := rec.UnixMilli()
	for {
		hw := s.clockHW.Load()
		if ms > hw {
			if s.clockHW.CompareAndSwap(hw, ms) {
				return
			}
			continue
		}
		back := time.Duration(hw-ms) * time.Millisecond
		if back <= logfile.MaxSkew {
			return
		}
		if s.clockHW.CompareAndSwap(hw, ms) {
			s.event(index.LevelWarn, index.KindClock, "", fmt.Sprintf(
				"system clock stepped back %s (received times went from %s to %s); searches near this time may miss lines",
				back.Round(time.Second), time.UnixMilli(hw).UTC().Format(time.RFC3339), rec.Format(time.RFC3339)))
			return
		}
	}
}

// Open recovers the data dir (see recover.go) and starts the store.
func Open(opts Options) (*Store, error) {
	if opts.DataDir == "" {
		return nil, errors.New("store: DataDir is required")
	}
	if opts.Index == nil {
		return nil, errors.New("store: Index is required")
	}
	setDefault(&opts.PartBytes, DefaultPartBytes)
	setDefault(&opts.RetentionDays, DefaultRetentionDays)
	setDefault(&opts.RetentionBytes, DefaultRetentionBytes)
	setDefault(&opts.MinFreeBytes, DefaultMinFreeBytes)
	setDefault(&opts.MinFreePercent, DefaultMinFreePercent)
	setDefault(&opts.MaxReserveBytes, DefaultMaxReserve)
	setDefault(&opts.FlushInterval, DefaultFlushInterval)
	setDefault(&opts.FlushBytes, DefaultFlushBytes)
	setDefault(&opts.SyncInterval, DefaultSyncInterval)
	setDefault(&opts.MaxOpenFiles, DefaultMaxOpenFiles)
	setDefault(&opts.CloseWorkers, DefaultCloseWorkers)
	setDefault(&opts.MaxDevices, DefaultMaxDevices)
	setDefault(&opts.NewDeviceBurst, DefaultNewDeviceBurst)
	setDefault(&opts.NewDevicesPerMinute, DefaultNewDevicesPerMinute)
	setDefault(&opts.IdleClose, DefaultIdleClose)
	setDefault(&opts.PrefixBurst, DefaultPrefixBurst)
	setDefault(&opts.PrefixPerMinute, DefaultPrefixPerMinute)
	setDefault(&opts.ReadmitPerSecond, DefaultReadmitPerSecond)
	setDefault(&opts.IdleEvict, DefaultIdleEvict)
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.DiskUsage == nil {
		opts.DiskUsage = DiskUsage
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	s := &Store{
		opts:       opts,
		dataDir:    opts.DataDir,
		logsDir:    filepath.Join(opts.DataDir, logfile.LogsDir),
		idx:        opts.Index,
		clock:      opts.Clock,
		disk:       opts.DiskUsage,
		log:        opts.Logger,
		cat:        map[string]*catEntry{},
		orphans:    map[string]bool{},
		dropCounts: map[dropKey]int64{},
		dropErrs:   map[string]string{},
		stop:       make(chan struct{}),
		compressCh: make(chan struct{}, 1),
		syncPath:   syncPath,
		devSet:     map[netip.Addr]*device{},
		prefixes:   map[netip.Prefix]*bucket{},
		known:      map[string]struct{}{},
		refMinutes: map[int64]int64{},
	}
	s.global.tokens = float64(opts.NewDeviceBurst)
	s.readmit.tokens = opts.ReadmitPerSecond
	s.maxDevices, s.burst, s.perMinute = opts.MaxDevices, opts.NewDeviceBurst, opts.NewDevicesPerMinute
	s.closeCond = sync.NewCond(&s.closeMu)
	s.retentionDays.Store(int64(opts.RetentionDays))
	s.retentionBytes.Store(opts.RetentionBytes)
	s.partBytes.Store(opts.PartBytes)
	s.ctx, s.cancel = context.WithCancel(context.Background())
	if err := os.MkdirAll(s.logsDir, 0o750); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := s.recover(s.ctx); err != nil {
		return nil, fmt.Errorf("store: recovery: %w", err)
	}
	if err := s.applyIndex(); err != nil {
		s.log.Warn("store: index update failed", "err", err)
	}
	// A clock that stepped back while Woodshed was stopped counts too.
	if files, err := s.idx.Files(s.ctx, ""); err == nil {
		for _, f := range files {
			if ms := f.LastReceived.UnixMilli(); ms > s.clockHW.Load() {
				s.clockHW.Store(ms)
			}
		}
	}
	if !opts.Manual {
		s.wg.Add(3)
		go s.flushLoop()
		go s.syncLoop()
		go s.compressLoop()
		s.startClosers()
		s.kickCompress()
	}
	return s, nil
}

func setDefault[T int | int64 | uint64 | float64 | time.Duration](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

// SetLimits changes retention, the part size and the new-sender limits while the
// store runs; zero fields are left unchanged. Retention and part size apply from the
// next maintenance pass, the sender limits to the next new sender. Raising the burst
// adds the difference to the bucket at once, so senders refused a moment ago get in.
func (s *Store) SetLimits(l Limits) {
	if l.RetentionDays > 0 {
		s.retentionDays.Store(int64(l.RetentionDays))
	}
	if l.RetentionBytes > 0 {
		s.retentionBytes.Store(l.RetentionBytes)
	}
	if l.PartBytes > 0 {
		s.partBytes.Store(l.PartBytes)
	}
	s.devMu.Lock()
	defer s.devMu.Unlock()
	if l.MaxDevices > 0 {
		s.maxDevices = l.MaxDevices
	}
	if l.NewDeviceBurst > 0 {
		s.global.refill(s.clock(), float64(s.burst), s.perMinute)
		if d := l.NewDeviceBurst - s.burst; d > 0 {
			s.global.tokens += float64(d)
		}
		s.burst = l.NewDeviceBurst
		s.global.tokens = min(s.global.tokens, float64(s.burst))
	}
	if l.NewDevicesPerMinute > 0 {
		s.perMinute = l.NewDevicesPerMinute
	}
}

// Limits returns the limits in effect.
func (s *Store) Limits() Limits {
	s.devMu.Lock()
	defer s.devMu.Unlock()
	return Limits{
		RetentionDays:       int(s.retentionDays.Load()),
		RetentionBytes:      s.retentionBytes.Load(),
		PartBytes:           s.partBytes.Load(),
		MaxDevices:          s.maxDevices,
		NewDeviceBurst:      s.burst,
		NewDevicesPerMinute: s.perMinute,
	}
}

// Write stores one message. It never blocks on the disk except to write a full
// buffer (FlushBytes) to the OS. It returns ErrPaused, and counts the message as
// dropped, while the low-disk guard has paused writing.
func (s *Store) Write(m model.Message) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if !m.Sender.IsValid() {
		return ErrInvalidSender
	}
	rec := m.Received
	if rec.IsZero() {
		rec = s.clock()
	}
	rec = time.UnixMilli(rec.UnixMilli()).UTC() // the file keeps milliseconds; so does the index
	s.watchClock(rec)
	addr := m.Sender.Unmap()
	for {
		d, err := s.device(addr, true)
		if err != nil {
			s.noteRefused(rec)
			return err
		}
		if err, retry := s.writeTo(d, rec, &m); !retry {
			return err
		}
		// The device was evicted between the lookup and the lock: look it up again.
	}
}

func (s *Store) writeTo(d *device, rec time.Time, m *model.Message) (err error, retry bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.evicted {
		return nil, true
	}
	if d.closed {
		return ErrClosed, false
	}
	d.lastHeard = rec
	ms := rec.UnixMilli()
	d.heardMs.Store(ms)
	d.writeSeq.Add(1)
	if ms-d.resTouch >= 1000 || ms < d.resTouch { // keep the resident list roughly LRU, cheaply
		d.resTouch = ms
		s.resMu.Lock()
		if d.resElem != nil {
			s.resident.MoveToFront(d.resElem)
		}
		s.resMu.Unlock()
	}
	if s.paused.Load() {
		d.dropLocked(rec, 1, dropPaused)
		return ErrPaused, false
	}
	return d.appendLocked(rec, m), false
}

// device returns the state for a sender, creating it on first use. With admit set
// (messages), a sender with no logs on disk must fit under MaxDevices and take a
// token from its network's bucket and from the global bucket; otherwise
// ErrDeviceLimit. A sender with logs on disk is always admitted: at the cap it takes
// the slot of the least recently heard sender, whose file is flushed and parked.
// Recovery creates devices unchecked.
func (s *Store) device(addr netip.Addr, admit bool) (*device, error) {
	if v, ok := s.devices.Load(addr); ok {
		return v.(*device), nil
	}
	s.devMu.Lock()
	defer s.devMu.Unlock()
	if d, ok := s.devSet[addr]; ok {
		return d, nil
	}
	id := model.DeviceID(addr)
	now := s.clock()
	if admit {
		full := len(s.devSet)-s.leavingN >= s.maxDevices
		if _, known := s.known[id]; known {
			if full {
				// Re-admissions at the cap are rate limited, so cycling through many
				// known senders can't turn every message into an eviction.
				s.readmit.refill(now, s.opts.ReadmitPerSecond, s.opts.ReadmitPerSecond*60)
				if s.readmit.tokens < 1 {
					s.setRefuseReason("churn")
					return nil, ErrDeviceLimit
				}
				s.readmit.tokens--
				s.makeRoomLocked()
			}
		} else {
			if full {
				s.setRefuseReason("cap")
				return nil, ErrDeviceLimit
			}
			if reason := s.takeTokenLocked(addr, now); reason != "" {
				s.setRefuseReason(reason)
				return nil, ErrDeviceLimit
			}
		}
	}
	d := newDevice(s, addr)
	d.heardMs.Store(now.UnixMilli())
	d.resTouch = now.UnixMilli()
	s.resMu.Lock()
	d.resElem = s.resident.PushFront(d)
	s.resMu.Unlock()
	s.devSet[addr] = d
	s.known[id] = struct{}{}
	s.devices.Store(addr, d)
	return d, nil
}

// Per-network new-sender buckets: one network can't drain the global bucket.
const (
	DefaultReadmitPerSecond = 500.0
	DefaultPrefixBurst      = 256
	DefaultPrefixPerMinute  = 20.0
	maxPrefixBuckets        = 1 << 16
)

type bucket struct {
	tokens float64
	at     time.Time
}

func (b *bucket) refill(now time.Time, burst, perMinute float64) {
	if !b.at.IsZero() && now.After(b.at) {
		b.tokens = min(burst, b.tokens+now.Sub(b.at).Minutes()*perMinute)
	}
	b.at = now
}

// newSenderPrefix is the network a new-sender bucket covers: /24 for IPv4, /48 for IPv6.
func newSenderPrefix(a netip.Addr) netip.Prefix {
	bits := 48
	if a.Is4() {
		bits = 24
	}
	p, _ := a.Prefix(bits)
	return p
}

// takeTokenLocked takes a token from the sender's network bucket and the global
// bucket, both or neither; it returns "" or the refusal reason ("prefix", "rate").
func (s *Store) takeTokenLocked(addr netip.Addr, now time.Time) string {
	pfx := newSenderPrefix(addr)
	pb := s.prefixes[pfx]
	if pb == nil {
		if len(s.prefixes) >= maxPrefixBuckets {
			s.prunePrefixesLocked(now)
		}
		pb = &bucket{tokens: s.opts.PrefixBurst, at: now}
		s.prefixes[pfx] = pb
	}
	pb.refill(now, s.opts.PrefixBurst, s.opts.PrefixPerMinute)
	s.global.refill(now, float64(s.burst), s.perMinute)
	if pb.tokens < 1 {
		return "prefix"
	}
	if s.global.tokens < 1 {
		return "rate"
	}
	pb.tokens--
	s.global.tokens--
	return ""
}

// prunePrefixesLocked forgets networks whose bucket has refilled (they're back to
// a fresh bucket anyway), then, if that wasn't enough, half of the rest.
func (s *Store) prunePrefixesLocked(now time.Time) {
	for p, b := range s.prefixes {
		b.refill(now, s.opts.PrefixBurst, s.opts.PrefixPerMinute)
		if b.tokens >= s.opts.PrefixBurst {
			delete(s.prefixes, p)
		}
	}
	for p := range s.prefixes {
		if len(s.prefixes) < maxPrefixBuckets/2 {
			break
		}
		delete(s.prefixes, p)
	}
}

// makeRoomLocked frees a slot for a known sender at the cap: the least recently
// heard resident (the back of the resident list, O(1)) is marked as leaving, which
// frees its slot at once, and the closer pool flushes and parks it later, off devMu.
// It reports false if no resident can be marked.
func (s *Store) makeRoomLocked() bool {
	s.resMu.Lock()
	defer s.resMu.Unlock()
	for e := s.resident.Back(); e != nil; e = e.Prev() {
		v := e.Value.(*device)
		if v.leaving.Load() {
			continue
		}
		v.leaving.Store(true)
		v.leaveSeq.Store(v.writeSeq.Load())
		s.leavingN++
		s.resident.MoveToFront(e) // so the next search starts at the next-oldest
		s.queueClose(closeJob{evict: v})
		return true
	}
	return false
}

// finishEvict carries out a makeRoomLocked eviction. If the device was written to
// after it was marked, it stays: a resident sender is never refused.
func (s *Store) finishEvict(v *device) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.evicted || v.closed || !v.leaving.Load() {
		return
	}
	if v.writeSeq.Load() != v.leaveSeq.Load() || v.flushLocked() != nil || (v.day != "" && !v.parkLocked()) {
		s.devMu.Lock()
		if v.leaving.Swap(false) {
			s.leavingN--
		}
		s.devMu.Unlock()
		return
	}
	v.collectLocked()
	s.evictLocked(v)
}

// evictLocked frees an idle device's in-memory state; the caller holds d.mu.
func (s *Store) evictLocked(d *device) {
	d.evicted = true
	s.devMu.Lock()
	if s.devSet[d.addr] == d {
		delete(s.devSet, d.addr)
	}
	if d.leaving.Swap(false) {
		s.leavingN--
	}
	s.resMu.Lock()
	if d.resElem != nil {
		s.resident.Remove(d.resElem)
		d.resElem = nil
	}
	s.resMu.Unlock()
	s.devMu.Unlock()
	s.devices.CompareAndDelete(d.addr, d)
}

func (s *Store) allDevices() []*device {
	s.devMu.Lock()
	defer s.devMu.Unlock()
	out := make([]*device, 0, len(s.devSet))
	for _, d := range s.devSet {
		out = append(out, d)
	}
	return out
}

func (s *Store) setRefuseReason(r string) {
	s.refMu.Lock()
	s.refReason = r
	s.refMu.Unlock()
}

// noteRefused counts a message from a refused new sender.
func (s *Store) noteRefused(rec time.Time) {
	s.refusedMsgs.Add(1)
	s.dropped.Add(1)
	s.reasons.add(rec, dropRefused, 1)
	s.lastRefused.Store(s.clock().UnixMilli())
	s.refMu.Lock()
	s.refMinutes[rec.UnixMilli()/60000]++
	s.refPending++
	s.refMu.Unlock()
}

// collectRefused queues refused counts for the index and, at most once a minute, a
// warn event.
func (s *Store) collectRefused(now time.Time, force bool) {
	lim := s.Limits() // before refMu: device() takes devMu then refMu
	s.refMu.Lock()
	mins := s.refMinutes
	if len(mins) > 0 {
		s.refMinutes = map[int64]int64{}
	}
	var text string
	if s.refPending > 0 && (force || now.Sub(s.lastRefEv) >= time.Minute) {
		var why string
		switch s.refReason {
		case "prefix":
			why = fmt.Sprintf("new senders from one network (a /24, or a /48 for IPv6) arrived faster than %g a minute (burst %g)",
				s.opts.PrefixPerMinute, s.opts.PrefixBurst)
		case "rate":
			why = fmt.Sprintf("new senders arrived faster than %g a minute (burst %d)", lim.NewDevicesPerMinute, lim.NewDeviceBurst)
		case "churn":
			why = fmt.Sprintf("the device cap (%d) is full and known senders came back faster than %g a second",
				lim.MaxDevices, s.opts.ReadmitPerSecond)
		default:
			why = fmt.Sprintf("the device cap (%d senders heard in the last few minutes) was reached", lim.MaxDevices)
		}
		text = fmt.Sprintf("refused %d messages from new senders: %s. If these senders are unexpected (spoofed or "+
			"misconfigured), set the sender allowlist in Settings; if they're real, raise the limit", s.refPending, why)
		s.refPending, s.lastRefEv = 0, now
	}
	s.refMu.Unlock()
	if len(mins) > 0 {
		acts := make([]index.Activity, 0, len(mins))
		for m, n := range mins {
			acts = append(acts, index.Activity{DeviceID: index.RefusedDeviceID, Minute: time.UnixMilli(m * 60000).UTC(),
				Counts: index.Counts{Dropped: n}})
		}
		s.qMu.Lock()
		s.qAct = append(s.qAct, acts...)
		s.qMu.Unlock()
	}
	if text != "" {
		s.event(index.LevelWarn, index.KindDeviceLimit, "", text)
	}
}

// Flush writes every buffer to its file, fsyncs the written files and updates the
// index.
func (s *Store) Flush() error {
	err := s.flushAll(false)
	s.drainClose()
	if serr := s.syncAll(); err == nil {
		err = serr
	}
	if ierr := s.applyIndex(); err == nil {
		err = ierr
	}
	return err
}

// Close flushes and fsyncs everything, updates the index and stops the background
// work. A compression in progress is abandoned and redone at the next Open.
func (s *Store) Close() error {
	if s.closed.Swap(true) {
		return nil
	}
	close(s.stop)
	s.cancel()
	s.wg.Wait()
	s.stopClosers()
	var first error
	keep := func(err error) {
		if first == nil && err != nil {
			first = err
		}
	}
	for _, d := range s.allDevices() {
		d.mu.Lock()
		d.closed = true
		keep(d.flushLocked())
		d.collectLocked()
		keep(d.closeFileLocked(true))
		d.mu.Unlock()
	}
	s.drainClose()
	s.collectRefused(s.clock(), true)
	s.reportDrops(s.clock(), true)
	keep(s.applyIndex())
	return first
}

// Usage is the storage summary for /api/stats and the storage settings.
type Usage struct {
	BytesOnDisk        int64     // all log files, compressed and not
	CapBytes           int64     // RetentionBytes
	RetentionDays      int       // the age limit
	FreeBytes          uint64    // free space on the data volume (last check)
	VolumeBytes        uint64    // size of the data volume (last check)
	ReserveBytes       uint64    // free space the low-disk guard keeps (for the current volume size)
	DaysKept           int       // calendar days from the oldest file's day to today
	Oldest             time.Time // earliest received time on disk (zero if none)
	Files              int       // log files on disk
	PendingCompression int       // closed files not yet gzipped
	WritesPaused       bool      // the low-disk guard stopped writing (red banner)
	PausedSince        time.Time // zero when not paused
	Dropped            int64     // messages dropped since Open (paused, write errors, refused senders, UDP queue full)
	Written            int64     // messages written since Open

	Devices           int       // senders held in memory now
	MaxDevices        int       // the cap on Devices
	RefusedMsgs       int64     // messages from refused new senders since Open (included in Dropped)
	LastRefused       time.Time // zero if none
	DeviceLimited     bool      // a new sender was refused in the last DeviceLimitWindow (device_limit banner)
	DeviceLimitReason string    // "cap", "rate", "prefix" or "churn": why the latest one was refused
}

// DeviceLimitWindow is how long Usage.DeviceLimited stays set after a refusal.
const DeviceLimitWindow = 5 * time.Minute

// Usage returns the current storage summary.
func (s *Store) Usage() Usage {
	u := Usage{
		CapBytes:      s.retentionBytes.Load(),
		RetentionDays: int(s.retentionDays.Load()),
		WritesPaused:  s.paused.Load(),
		Dropped:       s.dropped.Load(),
		Written:       s.written.Load(),
	}
	if u.WritesPaused {
		u.PausedSince = time.UnixMilli(s.pausedSince.Load()).UTC()
	}
	s.devMu.Lock()
	u.Devices = len(s.devSet) - s.leavingN // marked senders have given up their slot
	s.devMu.Unlock()
	u.MaxDevices = s.Limits().MaxDevices
	u.RefusedMsgs = s.refusedMsgs.Load()
	if ms := s.lastRefused.Load(); ms != 0 {
		u.LastRefused = time.UnixMilli(ms).UTC()
		u.DeviceLimited = s.clock().Sub(u.LastRefused) < DeviceLimitWindow
		s.refMu.Lock()
		u.DeviceLimitReason = s.refReason
		s.refMu.Unlock()
	}
	s.diskMu.Lock()
	u.FreeBytes, u.VolumeBytes = s.lastFree, s.lastTotal
	s.diskMu.Unlock()
	u.ReserveBytes = s.minFree(u.VolumeBytes)
	oldestDay := ""
	s.catMu.Lock()
	u.BytesOnDisk = s.catBytes
	u.Files = len(s.cat)
	for _, e := range s.cat {
		if !e.name.Compressed && !e.parked {
			u.PendingCompression++
		}
		if oldestDay == "" || e.name.Day < oldestDay {
			oldestDay = e.name.Day
		}
		if !e.first.IsZero() && (u.Oldest.IsZero() || e.first.Before(u.Oldest)) {
			u.Oldest = e.first
		}
	}
	s.catMu.Unlock()
	u.BytesOnDisk += s.activeBytes.Load()
	for _, d := range s.allDevices() {
		d.mu.Lock()
		if d.day != "" && d.w.size > 0 {
			u.Files++
			if oldestDay == "" || d.day < oldestDay {
				oldestDay = d.day
			}
			if !d.w.first.IsZero() && (u.Oldest.IsZero() || d.w.first.Before(u.Oldest)) {
				u.Oldest = d.w.first
			}
		}
		d.mu.Unlock()
	}
	if oldestDay != "" {
		if t, err := logfile.DayStart(oldestDay); err == nil {
			today, _ := logfile.DayStart(logfile.DayOf(s.clock()))
			u.DaysKept = int(today.Sub(t)/(24*time.Hour)) + 1
			if u.DaysKept < 1 {
				u.DaysKept = 1
			}
		}
	}
	return u
}

// Paused reports whether the low-disk guard has paused writing.
func (s *Store) Paused() bool { return s.paused.Load() }

// event queues a service event for the index.
func (s *Store) event(level index.Level, kind index.Kind, dev, text string) {
	s.qMu.Lock()
	s.qEvents = append(s.qEvents, index.Event{Time: s.clock(), Level: level, Kind: kind, DeviceID: dev, Text: text})
	s.qMu.Unlock()
	switch level {
	case index.LevelError:
		s.log.Error("store: "+text, "device", dev)
	case index.LevelWarn:
		s.log.Warn("store: "+text, "device", dev)
	default:
		s.log.Debug("store: "+text, "device", dev)
	}
}

func (s *Store) pushOps(ops ...index.FileOp) {
	s.qMu.Lock()
	s.qOps = append(s.qOps, ops...)
	s.qMu.Unlock()
}

// maxQueued bounds the index queue if the index keeps failing; the files stay
// correct, and Reconcile at the next start rebuilds what was lost.
const maxQueued = 1 << 20

// applyIndex writes the queued file ops, activity and events in one transaction.
func (s *Store) applyIndex() error {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.qMu.Lock()
	b := index.Batch{Files: s.qOps, Activity: s.qAct, Events: s.qEvents}
	s.qOps, s.qAct, s.qEvents = nil, nil, nil
	s.qMu.Unlock()
	if b.Empty() {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s.idx.Apply(ctx, b)
	if err == nil {
		return nil
	}
	s.log.Error("store: index update failed; will retry", "err", err)
	s.qMu.Lock()
	s.qOps = append(b.Files, s.qOps...)
	s.qAct = append(b.Activity, s.qAct...)
	s.qEvents = append(b.Events, s.qEvents...)
	if len(s.qOps) > maxQueued {
		s.qOps = s.qOps[len(s.qOps)-maxQueued:]
	}
	if len(s.qAct) > maxQueued {
		s.qAct = s.qAct[len(s.qAct)-maxQueued:]
	}
	if len(s.qEvents) > maxQueued {
		s.qEvents = s.qEvents[len(s.qEvents)-maxQueued:]
	}
	s.qMu.Unlock()
	return err
}

func (s *Store) rel(abs string) string {
	r, err := filepath.Rel(s.dataDir, abs)
	if err != nil {
		return filepath.ToSlash(abs)
	}
	return filepath.ToSlash(r)
}
