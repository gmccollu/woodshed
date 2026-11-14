package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// catEntry is a closed log file (awaiting compression, or compressed).
type catEntry struct {
	deviceID    string
	name        logfile.Name
	abs, rel    string
	first, last time.Time
	size        int64 // on disk
	rawSize     int64
	lines       int64

	busy    bool // being compressed
	syncing bool // just closed; the closer pool hasn't fsynced it yet
	// parked: a device's file for today, closed early because the device went quiet
	// (IdleClose) or found at startup. It's still that day's active file: never
	// compressed or deleted, and the device appends to it again on its next message.
	// At midnight it becomes an ordinary closed file.
	parked   bool
	cp       logfile.Checkpointer // checkpoint state to resume a parked file
	failures int
	nextTry  time.Time
}

func (e *catEntry) row() index.File {
	return index.File{DeviceID: e.deviceID, Path: e.rel, Day: e.name.Day, Part: e.name.Part, FirstReceived: e.first,
		LastReceived: e.last, Size: e.size, RawSize: e.rawSize, Lines: e.lines, Compressed: e.name.Compressed}
}

func (s *Store) addClosed(e *catEntry) {
	s.catMu.Lock()
	if old := s.cat[e.rel]; old != nil {
		s.catBytes -= old.size
	}
	s.cat[e.rel] = e
	s.catBytes += e.size
	s.catMu.Unlock()
}

func (s *Store) flushLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.opts.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.maintain()
		}
	}
}

func (s *Store) syncLoop() {
	defer s.wg.Done()
	t := time.NewTicker(s.opts.SyncInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.syncAll()
		}
	}
}

// Maintain runs one maintenance pass now: flush buffers, close files whose day has
// ended, compress (in Manual mode; otherwise the background worker is woken),
// apply retention and the low-disk guard, and update the index. The background loop
// runs it every FlushInterval.
func (s *Store) Maintain() error {
	if s.closed.Load() {
		return ErrClosed
	}
	return s.maintain()
}

func (s *Store) maintain() error {
	s.maintMu.Lock()
	defer s.maintMu.Unlock()
	err := s.flushAll(true)
	if s.opts.Manual {
		s.drainClose()
		s.compressPending(s.ctx)
	}
	now := s.clock()
	s.cleanOrphans()
	s.enforceRetention(now)
	s.guardDisk(now)
	s.reportDrops(now, false)
	if b := now.Add(-index.MinuteRetention).UTC().Truncate(time.Hour); !b.Equal(s.lastRollup) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if _, rerr := s.idx.RollupStats(ctx, b); rerr != nil {
			s.log.Warn("store: rolling up stats failed", "err", rerr)
		} else {
			s.lastRollup = b
		}
		cancel()
	}
	if now.Sub(s.lastPrune) >= time.Hour {
		s.lastPrune = now
		hist := time.Duration(max(2*s.retentionDays.Load(), 90)) * 24 * time.Hour
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		if perr := s.idx.Prune(ctx, now.Add(-index.StatsRetention), now.Add(-hist)); perr != nil {
			s.log.Warn("store: pruning the index failed", "err", perr)
		}
		cancel()
	}
	if ierr := s.applyIndex(); err == nil {
		err = ierr
	}
	if now.Sub(s.lastFloodCheck) >= time.Hour { // after the apply, so it sees this pass's stats
		s.lastFloodCheck = now
		s.checkFloods(now)
		s.pruneDevices(now) // after the apply too, so deleted files are gone from the index
	}
	if !s.opts.Manual && s.hasCompressWork(now) {
		s.kickCompress()
	}
	return err
}

// flushAll writes every device's buffer and, with midnight set, closes files whose
// day has ended.
// With midnight set (the maintenance pass) it also evicts idle devices.
func (s *Store) flushAll(midnight bool) error {
	now := s.clock()
	today := logfile.DayOf(now)
	var first error
	for _, d := range s.allDevices() {
		d.mu.Lock()
		if !d.closed && !d.evicted {
			if midnight && d.day != "" && d.day < today {
				d.rotateLocked(rotMidnight)
			} else if err := d.flushLocked(); err != nil && first == nil {
				first = err
			} else if midnight && d.day != "" && now.Sub(d.lastHeard) >= s.opts.IdleClose {
				d.parkLocked()
			}
		}
		d.collectLocked()
		if midnight && !d.evicted && d.idleLocked(now) {
			s.evictLocked(d)
		}
		d.mu.Unlock()
	}
	s.collectRefused(now, false)
	if midnight && today != s.lastUnparkDay {
		s.lastUnparkDay = today
		s.unparkBefore(today)
	}
	return first
}

// dayClosed reports whether a device's file for day was already closed (it's in
// the catalog, compressed or not).
func (s *Store) dayClosed(id, day string) bool {
	n := logfile.Name{Day: day}
	gz := logfile.Name{Day: day, Compressed: true}
	s.catMu.Lock()
	defer s.catMu.Unlock()
	if e := s.cat[logfile.RelPath(id, n)]; e != nil && !e.parked {
		return true
	}
	return s.cat[logfile.RelPath(id, gz)] != nil
}

// takeParked removes and returns a device's parked file for day, if any.
func (s *Store) takeParked(id, day string) *catEntry {
	rel := logfile.RelPath(id, logfile.Name{Day: day})
	s.catMu.Lock()
	defer s.catMu.Unlock()
	e := s.cat[rel]
	if e == nil || !e.parked {
		return nil
	}
	delete(s.cat, rel)
	s.catBytes -= e.size
	return e
}

// unparkBefore turns parked files of days before today into ordinary closed files
// (compressible), as the midnight close does for live devices.
func (s *Store) unparkBefore(today string) {
	var done []*catEntry
	s.catMu.Lock()
	for _, e := range s.cat {
		if e.parked && e.name.Day < today {
			e.parked = false
			done = append(done, e)
		}
	}
	s.catMu.Unlock()
	for _, e := range done {
		s.event(index.LevelInfo, index.KindRotate, e.deviceID, fmt.Sprintf("closed %s (end of day, %d lines, %d bytes)", e.rel, e.lines, e.size))
	}
	if len(done) > 0 {
		s.kickCompress()
	}
}

// syncAll fsyncs every file written since the last pass, a few at a time.
func (s *Store) syncAll() error {
	var dirty []*device
	for _, d := range s.allDevices() {
		d.fileMu.Lock()
		if d.dirty {
			dirty = append(dirty, d)
		}
		d.fileMu.Unlock()
	}
	var mu sync.Mutex
	var first error
	one := func(d *device) {
		d.fileMu.Lock()
		var err error
		if d.dirty {
			if d.f != nil {
				err = syncFile(d.f)
			} else if d.dirtyPath != "" {
				err = syncPath(d.dirtyPath)
				if errors.Is(err, fs.ErrNotExist) {
					err = nil // renamed or deleted since; rotation synced it
				}
			}
			d.dirty = false
		}
		d.fileMu.Unlock()
		if err != nil {
			mu.Lock()
			if first == nil {
				first = err
			}
			mu.Unlock()
		}
	}
	const workers = 4
	if len(dirty) <= workers {
		for _, d := range dirty {
			one(d)
		}
	} else {
		ch := make(chan *device)
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for d := range ch {
					one(d)
				}
			}()
		}
		for _, d := range dirty {
			ch <- d
		}
		close(ch)
		wg.Wait()
	}
	if first != nil {
		s.log.Warn("store: fsync failed", "err", first)
	}
	return first
}

// sortedClosed returns closed entries matching keep, oldest first (by the newest
// line in the file, then path).
func (s *Store) sortedClosed(keep func(*catEntry) bool) []*catEntry {
	s.catMu.Lock()
	var out []*catEntry
	for _, e := range s.cat {
		if !e.busy && !e.syncing && !e.parked && keep(e) {
			out = append(out, e)
		}
	}
	s.catMu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].last.Equal(out[j].last) {
			return out[i].last.Before(out[j].last)
		}
		return out[i].rel < out[j].rel
	})
	return out
}

// enforceRetention deletes compressed files older than RetentionDays, then the oldest
// compressed files while all logs together exceed RetentionBytes. It runs every pass,
// so the common case (nothing to delete) is one scan without sorting.
func (s *Store) enforceRetention(now time.Time) {
	cutoff := now.Add(-time.Duration(s.retentionDays.Load()) * 24 * time.Hour)
	for _, e := range s.sortedClosed(func(e *catEntry) bool { return e.name.Compressed && e.last.Before(cutoff) }) {
		s.deleteEntry(e, index.ReasonAge, now)
	}
	limit := s.retentionBytes.Load()
	over := func() bool {
		s.catMu.Lock()
		total := s.catBytes
		s.catMu.Unlock()
		return total+s.activeBytes.Load() > limit
	}
	if !over() {
		return
	}
	s.fairDelete(now, index.ReasonCap, false, false, s.fairInfoAt(now), func(uint64) bool { return !over() })
}

// deviceBytes returns each device's bytes on disk: closed files plus its active file.
func (s *Store) deviceBytes() map[string]int64 {
	out := map[string]int64{}
	s.catMu.Lock()
	for _, e := range s.cat {
		out[e.deviceID] += e.size
	}
	s.catMu.Unlock()
	for _, d := range s.allDevices() {
		d.mu.Lock()
		if d.day != "" {
			out[d.id] += d.w.size
		}
		d.mu.Unlock()
	}
	return out
}

// deleteEntry removes a closed file and records the deletion.
func (s *Store) deleteEntry(e *catEntry, reason index.Reason, now time.Time) bool {
	s.catMu.Lock()
	if e.busy || e.syncing || e.parked || s.cat[e.rel] != e {
		s.catMu.Unlock()
		return false
	}
	if err := os.Remove(e.abs); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.catMu.Unlock()
		s.log.Warn("store: couldn't delete a log file; will retry", "file", e.rel, "err", err)
		return false
	}
	delete(s.cat, e.rel)
	s.catBytes -= e.size
	s.catMu.Unlock()
	s.pushOps(index.FileOp{Kind: index.OpDelete, File: index.File{DeviceID: e.deviceID, Path: e.rel},
		Deletion: &index.Deletion{Time: now, File: e.rel, DeviceID: e.deviceID, Bytes: e.size, Reason: reason}})
	if e.name.Day >= logfile.DayOf(now) {
		s.event(index.LevelWarn, index.KindDelete, e.deviceID, fmt.Sprintf(
			"deleted today's logs of %s: %s (%d lines, %d bytes), %s", e.deviceID, e.rel, e.lines, e.size, reasonText(reason)))
	}
	return true
}

// minFree is the low-disk reserve for a volume of total bytes:
// max(MinFreeBytes, min(MinFreePercent of total, MaxReserveBytes)).
func (s *Store) minFree(total uint64) uint64 {
	return reserveFor(total, s.opts.MinFreeBytes, s.opts.MinFreePercent, s.opts.MaxReserveBytes)
}

func reserveFor(total, floor uint64, pct float64, ceiling uint64) uint64 {
	return max(floor, min(uint64(float64(total)*pct/100), ceiling))
}

// gib formats a byte count for event text, e.g. "9.8 GiB (10522669875 bytes)".
func gib(n uint64) string {
	return fmt.Sprintf("%.1f GiB (%d bytes)", float64(n)/(1<<30), n)
}

// checkDisk reads the data volume's free space.
func (s *Store) checkDisk() (free, total uint64, ok bool) {
	free, total, err := s.disk(s.dataDir)
	s.diskMu.Lock()
	defer s.diskMu.Unlock()
	if err != nil {
		if !s.diskErrShown {
			s.diskErrShown = true
			s.event(index.LevelWarn, index.KindError, "", fmt.Sprintf("can't read free disk space (%v); the low-disk guard is off", err))
		}
		return 0, 0, false
	}
	s.diskErrShown = false
	s.lastFree, s.lastTotal = free, total
	return free, total, true
}

// guardDisk keeps free space above the reserve (see minFree): it asks
// Reclaim (exports) first, then deletes closed files in fair-share order (see
// fairDelete), then closes the largest active or parked files as parts so they can be
// deleted too, and pauses writing only when nothing is left.
func (s *Store) guardDisk(now time.Time) {
	free, total, ok := s.checkDisk()
	if !ok {
		return
	}
	thr := s.minFree(total)
	if free < thr && s.opts.Reclaim != nil {
		if freed := s.opts.Reclaim(thr - free); freed > 0 {
			if free, total, ok = s.checkDisk(); !ok {
				return
			}
			thr = s.minFree(total)
		}
	}
	diskOK := true
	enough := func(freed uint64) bool {
		if freed == 0 {
			return false
		}
		if free, total, diskOK = s.checkDisk(); !diskOK {
			return true
		}
		thr = s.minFree(total)
		return free >= thr
	}
	// In order, while short: closed files (not a device's newest day); the open files
	// of devices over their share and of new devices, closed as parts; the newest days;
	// then anyone's open files, largest first. Open files are closed only if that can
	// reach the reserve: otherwise it would throw away today's logs and pause anyway.
	short := func() bool { return diskOK && free < thr }
	var seen *fairInfo
	if short() {
		seen = s.fairInfoAt(now)
		s.fairDelete(now, index.ReasonLowDisk, true, false, seen, enough)
	}
	canReach := short() && uint64(s.deletableBytes()) >= thr-free
	tried := map[string]bool{}
	for canReach && short() && s.closeOpen(now, tried, false, seen) {
		s.fairDelete(now, index.ReasonLowDisk, true, false, seen, enough)
	}
	if short() {
		s.fairDelete(now, index.ReasonLowDisk, true, true, seen, enough)
	}
	for canReach && short() && s.closeOpen(now, tried, true, seen) {
		s.fairDelete(now, index.ReasonLowDisk, true, true, seen, enough)
	}
	if !diskOK {
		return
	}
	if free < thr {
		if !s.paused.Swap(true) {
			s.pausedSince.Store(now.UnixMilli())
			s.event(index.LevelError, index.KindPause, "", fmt.Sprintf(
				"writes paused: %s free on the data volume, below the low-disk reserve of %s, and no closed logs left to delete",
				gib(free), gib(thr)))
		}
		return
	}
	// Resume only with some headroom, so the banner doesn't flap.
	if s.paused.Load() && free >= thr+thr/20 {
		s.paused.Store(false)
		s.event(index.LevelInfo, index.KindResume, "", fmt.Sprintf("writes resumed: %s free, reserve %s", gib(free), gib(thr)))
	}
}

type dropReason int

const (
	dropPaused dropReason = iota
	dropWriteError
	dropRefused   // only in reasonHours: refused senders have their own events (collectRefused)
	dropQueueFull // a UDP queue drop (DropQueued)
)

type dropKey struct {
	dev    string
	reason dropReason
}

func (s *Store) noteDrop(dev string, r dropReason, n int64) {
	if n <= 0 {
		return
	}
	s.dropMu.Lock()
	s.dropCounts[dropKey{dev, r}] += n
	s.dropMu.Unlock()
}

// queueFullEventText is the one event a minute for UDP queue drops, however
// many devices they were from.
func queueFullEventText(n int64, devices int) string {
	from := ""
	switch {
	case devices == 1:
		from = " from 1 device"
	case devices > 1:
		from = fmt.Sprintf(" from %d devices", devices)
	}
	return fmt.Sprintf("dropped %d UDP messages%s: the UDP receive queue was full because writing to disk fell behind "+
		"(check the disk, or raise listeners.udp_queue_messages)", n, from)
}

func (s *Store) noteWriteError(dev, rel string, err error) {
	s.dropMu.Lock()
	s.dropErrs[dev] = fmt.Sprintf("%s: %v", rel, err)
	s.dropMu.Unlock()
}

// reportDrops turns counted drops into events, at most once a minute per device and
// reason (or now, with force).
func (s *Store) reportDrops(now time.Time, force bool) {
	s.dropMu.Lock()
	if len(s.dropCounts) == 0 || (!force && now.Sub(s.lastDropEv) < time.Minute) {
		s.dropMu.Unlock()
		return
	}
	counts, errs := s.dropCounts, s.dropErrs
	s.dropCounts, s.dropErrs = map[dropKey]int64{}, map[string]string{}
	s.lastDropEv = now
	s.dropMu.Unlock()
	keys := make([]dropKey, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].dev < keys[j].dev || (keys[i].dev == keys[j].dev && keys[i].reason < keys[j].reason)
	})
	var qfN int64
	qfDevs := map[string]bool{}
	for _, k := range keys {
		var text string
		switch k.reason {
		case dropQueueFull:
			qfN += counts[k]
			if k.dev != "" {
				qfDevs[k.dev] = true
			}
			continue
		case dropPaused:
			text = fmt.Sprintf("dropped %d messages: writes paused (low disk space)", counts[k])
		default:
			text = fmt.Sprintf("dropped %d messages: write error (%s)", counts[k], errs[k.dev])
		}
		s.event(index.LevelError, index.KindDrop, k.dev, text)
	}
	if qfN > 0 {
		dev := ""
		if len(qfDevs) == 1 {
			for d := range qfDevs {
				dev = d
			}
		}
		s.event(index.LevelWarn, index.KindDrop, dev, queueFullEventText(qfN, len(qfDevs)))
	}
}

// Flood warning thresholds: a device sending more than floodShare of all bytes in
// the last 24 h, when at least two devices sent and the total is at least floodMin.
const (
	floodShare = 0.5
	floodMin   = 1 << 20
)

// checkFloods records a warn event for each device that sent more than half of the
// last 24 h's bytes. It runs at most once an hour, so each device gets at most one
// such event an hour.
func (s *Store) checkFloods(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	per, err := s.idx.DeviceCounts(ctx, now.Add(-24*time.Hour), now)
	if err != nil {
		s.log.Warn("store: flood check failed", "err", err)
		return
	}
	var total int64
	senders := 0
	for id, c := range per {
		if strings.HasPrefix(id, "_") || c.Bytes == 0 {
			continue
		}
		total += c.Bytes
		senders++
	}
	if senders < 2 || total < floodMin {
		return
	}
	ids := make([]string, 0, len(per))
	for id := range per {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b := per[id].Bytes
		if strings.HasPrefix(id, "_") || float64(b) <= floodShare*float64(total) {
			continue
		}
		s.event(index.LevelWarn, index.KindFlood, id, fmt.Sprintf(
			"%s sent %.0f%% of the last 24 h's bytes (%d of %d); when storage runs short its own oldest logs are deleted first",
			id, 100*float64(b)/float64(total), b, total))
	}
}

// DevicePruneAfter is how long a device with no files, name or group must have been
// quiet before pruneDevices forgets it.
const DevicePruneAfter = 24 * time.Hour

// pruneDevices forgets devices that have no files left (retention deleted them all),
// no name and no group, and weren't heard for DevicePruneAfter: their index row, their
// empty folder and their known-sender entry (so they count as new again). Named or
// grouped devices are kept.
func (s *Store) pruneDevices(now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ids, err := s.idx.PruneDevices(ctx, now.Add(-DevicePruneAfter))
	if err != nil {
		s.log.Warn("store: pruning devices failed", "err", err)
		return
	}
	if len(ids) == 0 {
		return
	}
	onDisk := s.deviceBytes()
	removed := 0
	// The residency check, the remove and the known-sender delete happen under devMu,
	// the lock under which a returning sender is registered before its first flush
	// recreates the folder. So the folder can't vanish under a sender that's opening
	// its file. (os.Remove also only deletes an empty folder.)
	s.devMu.Lock()
	resident := make(map[string]bool, len(s.devSet))
	for _, d := range s.devSet {
		resident[d.id] = true
	}
	for _, id := range ids {
		if resident[id] || onDisk[id] > 0 {
			continue // back already; keep its folder and exemption
		}
		if err := os.Remove(filepath.Join(s.logsDir, id)); err == nil || errors.Is(err, fs.ErrNotExist) {
			delete(s.known, id)
			removed++
		}
	}
	s.devMu.Unlock()
	s.log.Info("store: forgot devices with no logs left", "devices", len(ids), "folders_removed", removed)
}

func reasonText(r index.Reason) string {
	switch r {
	case index.ReasonLowDisk:
		return "low disk space"
	case index.ReasonCap:
		return "over the storage cap"
	}
	return "older than the retention period"
}
