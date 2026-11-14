package store

import (
	"bytes"
	"container/list"
	"fmt"
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

// fileState is what is known about the active file's contents.
type fileState struct {
	size, lines int64
	first, last time.Time // lowest and highest received time
}

// actAcc accumulates counters for one minute.
type actAcc struct {
	minute      int64 // unix minute
	first, last time.Time
	c           index.Counts
}

// device is one sender's write state.
//
// Locking: mu guards everything except where noted. Opening or closing f needs both
// mu and fileMu; fsync needs only fileMu, so the sync loop never waits for a device's
// writers. Lock order: device.mu -> Store.lruMu -> (TryLock only) other device.mu ->
// device.fileMu; device.mu -> Store.qMu / Store.catMu.
type device struct {
	s    *Store
	addr netip.Addr
	id   string
	ip   string
	dir  string

	mu     sync.Mutex
	closed bool
	day    string // day of the active file, "" when there is none
	minDay string // never open a file for an earlier day (that day was closed at midnight)
	abs    string // active file path
	rel    string
	f      *os.File
	elem   *list.Element // position in the handle LRU; guarded by Store.lruMu

	w, p     fileState // written (in the file) and pending (including the buffer)
	wcp, cp  logfile.Checkpointer
	newCPs   []logfile.Checkpoint // checkpoints in the pending part
	resetCPs bool                 // the index must replace this file's checkpoints
	buf      []byte
	bufAct   []actAcc // counters of the buffered messages
	act      []actAcc // counters of flushed (or dropped) messages, not yet collected

	renameRetry time.Time     // don't retry a failed part rename before this
	needResync  bool          // re-read the file before the next write
	evicted     bool          // removed from the store; writers must look the device up again
	lastHeard   time.Time     // received time of the latest message (for idle eviction)
	heardMs     atomic.Int64  // the same, readable without mu
	writeSeq    atomic.Uint64 // messages taken, for finishEvict to see a write after the mark
	leaving     atomic.Bool   // marked for eviction by makeRoomLocked
	leaveSeq    atomic.Uint64 // writeSeq when marked
	resTouch    int64         // last move to the front of the resident list, unix ms (mu)
	resElem     *list.Element // in Store.resident (Store.resMu)
	lastFlush   int           // bytes in the last flushed buffer (sizes the next one)

	fileMu    sync.Mutex
	dirty     bool   // written since the last fsync (fileMu)
	dirtyPath string // what to fsync when f was closed while dirty (fileMu)
}

func newDevice(s *Store, addr netip.Addr) *device {
	id := model.DeviceID(addr)
	return &device{s: s, addr: addr, id: id, ip: addr.String(), dir: filepath.Join(s.logsDir, id)}
}

// Buffers: a device starts with a small buffer that grows by append, so many quiet
// or one-message senders cost about 1 KiB each until the next flush. A device whose
// last flush was big takes a pooled large buffer instead.
const (
	smallBufSize = 1 << 10
	bigBufSize   = 64 << 10
)

var bufPool = sync.Pool{New: func() any { b := make([]byte, 0, bigBufSize); return &b }}

func (d *device) newBuf() []byte {
	if d.lastFlush >= bigBufSize/4 {
		return (*bufPool.Get().(*[]byte))[:0]
	}
	return make([]byte, 0, smallBufSize)
}

func putBuf(b []byte) {
	if cap(b) < bigBufSize || cap(b) > 4<<20 {
		return // small ones go to the GC; huge ones aren't worth keeping
	}
	b = b[:0]
	bufPool.Put(&b)
}

// appendLocked buffers one message, rotating first if the day changed or the part
// is full.
func (d *device) appendLocked(rec time.Time, m *model.Message) error {
	day := logfile.DayOf(rec)
	if day < d.minDay {
		day = d.minDay
	}
	if d.day != "" && day < d.day {
		day = d.day // late message after a rotation: it keeps its own timestamp
	}
	if d.day != "" && day > d.day {
		d.rotateLocked(rotMidnight)
	}
	if d.day == "" {
		// A device recreated after eviction doesn't remember which days it closed;
		// the catalog does. Never reopen a closed day.
		for d.s.dayClosed(d.id, day) {
			day = nextDay(day)
		}
		d.startDayLocked(day)
		if e := d.s.takeParked(d.id, day); e != nil {
			d.adoptLocked(e)
		}
	}
	if d.buf == nil {
		d.buf = d.newBuf()
	}
	start := len(d.buf)
	d.buf = logfile.AppendLine(d.buf, rec, d.addr, m.Raw)
	n := int64(len(d.buf) - start)
	if d.p.size > 0 && d.p.size+n > d.s.partBytes.Load() &&
		(d.renameRetry.IsZero() || !d.s.clock().Before(d.renameRetry)) {
		line := append([]byte(nil), d.buf[start:]...)
		d.buf = d.buf[:start]
		d.rotateLocked(rotSize)
		if d.buf == nil {
			d.buf = d.newBuf()
		}
		d.buf = append(d.buf, line...)
	}
	if cp, ok := d.cp.Observe(d.p.size, d.p.lines, rec); ok {
		d.newCPs = append(d.newCPs, cp)
	}
	d.p.size += n
	d.p.lines++
	if d.p.first.IsZero() || rec.Before(d.p.first) {
		d.p.first = rec
	}
	if rec.After(d.p.last) {
		d.p.last = rec
	}
	a := d.accFor(&d.bufAct, rec)
	a.c.Msgs++
	a.c.Bytes += int64(len(m.Raw))
	if m.Truncated {
		a.c.Truncated++
	}
	if len(d.buf) >= d.s.opts.FlushBytes {
		return d.flushLocked()
	}
	return nil
}

// accFor returns the accumulator for rec's minute, at the end of *list.
func (d *device) accFor(list *[]actAcc, rec time.Time) *actAcc {
	min := rec.UnixMilli() / 60000
	if k := len(*list); k > 0 && (*list)[k-1].minute == min {
		a := &(*list)[k-1]
		if rec.Before(a.first) {
			a.first = rec
		}
		if rec.After(a.last) {
			a.last = rec
		}
		return a
	}
	*list = append(*list, actAcc{minute: min, first: rec, last: rec})
	return &(*list)[len(*list)-1]
}

// dropLocked counts n messages received at rec that won't be stored, for
// reason dropPaused or dropQueueFull.
func (d *device) dropLocked(rec time.Time, n int64, reason dropReason) {
	d.accFor(&d.act, rec).c.Dropped += n
	d.s.dropped.Add(n)
	d.s.reasons.add(rec, reason, n)
	d.s.noteDrop(d.id, reason, n)
}

func (d *device) startDayLocked(day string) {
	d.day = day
	d.abs = filepath.Join(d.dir, logfile.Name{Day: day}.String())
	d.rel = d.s.rel(d.abs)
	d.w, d.p = fileState{}, fileState{}
	d.wcp, d.cp = logfile.Checkpointer{}, logfile.Checkpointer{}
	d.newCPs, d.resetCPs = nil, false
	d.renameRetry = time.Time{}
	if st, err := os.Stat(d.abs); err == nil && st.Size() > 0 {
		d.needResync = true // a file we didn't know about; read it before appending
	}
}

// fileRow is the index row for the active file as written.
func (d *device) fileRow() index.File {
	return index.File{DeviceID: d.id, Path: d.rel, Day: d.day, FirstReceived: d.w.first, LastReceived: d.w.last,
		Size: d.w.size, RawSize: d.w.size, Lines: d.w.lines}
}

// flushLocked writes the buffer to the active file and queues the index update.
func (d *device) flushLocked() error {
	if len(d.buf) == 0 {
		return nil
	}
	if err := d.ensureOpenLocked(); err != nil {
		d.failBufferLocked(err)
		return err
	}
	if d.needResync {
		if err := d.resyncLocked(); err != nil {
			d.failBufferLocked(err)
			return err
		}
	}
	d.fileMu.Lock()
	n, err := d.f.Write(d.buf)
	if n > 0 {
		d.dirty = true
	}
	if err != nil && n > 0 {
		if terr := d.f.Truncate(d.w.size); terr != nil {
			d.needResync = true
		}
	}
	d.fileMu.Unlock()
	if err != nil {
		d.failBufferLocked(err)
		return err
	}
	d.s.activeBytes.Add(int64(len(d.buf)))
	d.s.written.Add(d.p.lines - d.w.lines)
	d.w, d.wcp = d.p, d.cp
	d.s.pushOps(index.FileOp{Kind: index.OpUpsert, File: d.fileRow(), Checkpoints: d.newCPs, ResetCheckpoints: d.resetCPs})
	d.newCPs, d.resetCPs = nil, false
	for _, a := range d.bufAct {
		d.mergeAct(a)
	}
	d.bufAct = d.bufAct[:0]
	d.lastFlush = len(d.buf)
	putBuf(d.buf)
	d.buf = nil
	d.s.touch(d)
	return nil
}

func (d *device) mergeAct(a actAcc) {
	if k := len(d.act); k > 0 && d.act[k-1].minute == a.minute {
		x := &d.act[k-1]
		x.c.Add(a.c)
		if a.first.Before(x.first) {
			x.first = a.first
		}
		if a.last.After(x.last) {
			x.last = a.last
		}
		return
	}
	d.act = append(d.act, a)
}

// failBufferLocked discards the buffer after a write error, counting its messages
// as dropped, and rolls the pending state back to what is in the file.
func (d *device) failBufferLocked(err error) {
	lines := d.p.lines - d.w.lines
	if d.resetCPs {
		d.needResync = true
	}
	d.p, d.cp = d.w, d.wcp
	d.newCPs = nil
	for _, a := range d.bufAct {
		a.c = index.Counts{Dropped: a.c.Msgs}
		d.mergeAct(a)
	}
	d.bufAct = d.bufAct[:0]
	putBuf(d.buf)
	d.buf = nil
	d.s.dropped.Add(lines)
	d.s.reasons.add(d.s.clock(), dropWriteError, lines)
	d.s.noteDrop(d.id, dropWriteError, lines)
	d.s.noteWriteError(d.id, d.rel, err)
	d.closeFileLocked(false)
}

// collectLocked hands the device's counters to the index queue.
func (d *device) collectLocked() {
	if len(d.act) == 0 {
		return
	}
	acts := make([]index.Activity, len(d.act))
	for i, a := range d.act {
		acts[i] = index.Activity{DeviceID: d.id, IP: d.ip, Minute: time.UnixMilli(a.minute * 60000).UTC(),
			FirstHeard: a.first, LastHeard: a.last, Counts: a.c}
	}
	d.act = d.act[:0]
	d.s.qMu.Lock()
	d.s.qAct = append(d.s.qAct, acts...)
	d.s.qMu.Unlock()
}

// ensureOpenLocked opens the active file for appending, taking an LRU slot.
func (d *device) ensureOpenLocked() error {
	if d.f != nil {
		return nil
	}
	if err := os.MkdirAll(d.dir, 0o750); err != nil {
		return err
	}
	d.s.acquireSlot(d)
	f, err := os.OpenFile(d.abs, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		d.s.releaseSlot(d)
		return err
	}
	if st, err := f.Stat(); err != nil || st.Size() != d.w.size {
		d.needResync = true
	}
	d.fileMu.Lock()
	d.f = f
	d.fileMu.Unlock()
	return nil
}

// closeFileLocked closes the active file's handle, fsyncing it first if asked.
func (d *device) closeFileLocked(sync bool) error {
	var err error
	d.fileMu.Lock()
	if d.f != nil {
		if sync && d.dirty {
			err = syncFile(d.f)
			d.dirty = false
		}
		if cerr := d.f.Close(); err == nil {
			err = cerr
		}
		d.f = nil
		if d.dirty {
			d.dirtyPath = d.abs
		}
		d.fileMu.Unlock()
		d.s.releaseSlot(d)
		return err
	}
	if sync && d.dirty && d.dirtyPath != "" {
		err = syncPath(d.dirtyPath)
		d.dirty = false
	}
	d.fileMu.Unlock()
	return err
}

// resyncLocked re-reads the active file (after a failed truncate, or a file changed
// behind our back), then re-derives the buffer's offsets and checkpoints from it.
func (d *device) resyncLocked() error {
	if _, _, err := repairTail(d.abs); err != nil && !os.IsNotExist(err) {
		return err
	}
	sum, err := logfile.ScanFile(d.abs)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	d.s.activeBytes.Add(sum.RawSize - d.w.size)
	d.w = fileState{size: sum.RawSize, lines: sum.Lines, first: sum.First, last: sum.Last}
	d.wcp = sum.Checkpointer
	cps := sum.Checkpoints
	d.p, d.cp = d.w, d.wcp
	if len(d.buf) > 0 {
		cp := d.wcp
		bs, err := logfile.Scan(bytes.NewReader(d.buf), logfile.ScanOptions{Start: d.w.size, StartLine: d.w.lines, Checkpointer: &cp})
		if err != nil {
			return err
		}
		d.p.size, d.p.lines = bs.RawSize, bs.Lines
		if !bs.First.IsZero() && (d.p.first.IsZero() || bs.First.Before(d.p.first)) {
			d.p.first = bs.First
		}
		if bs.Last.After(d.p.last) {
			d.p.last = bs.Last
		}
		d.cp = bs.Checkpointer
		cps = append(cps, bs.Checkpoints...)
	}
	d.newCPs, d.resetCPs, d.needResync = cps, true, false
	return nil
}

type rotateReason int

const (
	rotMidnight rotateReason = iota
	rotSize
	rotLowDisk // closed as a part early, so the low-disk guard can delete it
)

// rotateLocked closes the active file: at a day change, or at the part size, in which
// case it is renamed to the next numbered part. A failed rename leaves the file
// active and is retried a minute later. It returns the closed file's catalog
// entry, or nil if nothing was closed.
func (d *device) rotateLocked(reason rotateReason) *catEntry {
	if d.day == "" {
		return nil
	}
	if d.needResync {
		if err := d.resyncLocked(); err != nil {
			d.s.event(index.LevelWarn, index.KindError, d.id, fmt.Sprintf("re-read %s: %v", d.rel, err))
		}
	}
	d.flushLocked()
	// Close the handle without fsync: the closer pool fsyncs the file by path, off the
	// write path, so writes for the new file never wait for the old one's fsync.
	d.detachFileLocked()
	day := d.day
	reset := func() {
		d.s.activeBytes.Add(-d.w.size)
		if reason != rotMidnight {
			d.startDayLocked(day)
		} else {
			d.day = ""
			d.minDay = nextDay(day)
			d.w, d.p = fileState{}, fileState{}
			d.wcp, d.cp = logfile.Checkpointer{}, logfile.Checkpointer{}
			d.newCPs, d.resetCPs = nil, false
		}
	}
	if d.w.size == 0 {
		if st, err := os.Stat(d.abs); err == nil && st.Size() == 0 {
			os.Remove(d.abs) // nothing was written; don't leave an empty file
		}
		reset()
		return nil
	}
	name := logfile.Name{Day: day}
	abs, rel := d.abs, d.rel
	if reason != rotMidnight {
		nn := logfile.Name{Day: day, Part: nextPart(d.dir, day)}
		nabs := filepath.Join(d.dir, nn.String())
		if err := os.Rename(abs, nabs); err != nil {
			d.fileMu.Lock()
			d.dirty, d.dirtyPath = true, abs // still active: the sync loop fsyncs it
			d.fileMu.Unlock()
			d.renameRetry = d.s.clock().Add(time.Minute)
			d.s.event(index.LevelWarn, index.KindRotate, d.id,
				fmt.Sprintf("couldn't close part %s (%v); still writing to it, retrying in a minute", rel, err))
			return nil
		}
		nrel := d.s.rel(nabs)
		row := d.fileRow()
		row.Path, row.Part = nrel, nn.Part
		d.s.pushOps(index.FileOp{Kind: index.OpRename, OldPath: rel, File: row})
		name, abs, rel = nn, nabs, nrel
	}
	ce := &catEntry{deviceID: d.id, name: name, abs: abs, rel: rel, first: d.w.first, last: d.w.last,
		size: d.w.size, rawSize: d.w.size, lines: d.w.lines, syncing: true}
	d.s.addClosed(ce)
	d.s.queueClose(closeJob{e: ce, path: abs, dir: d.dir, renamed: reason != rotMidnight})
	why := "end of day"
	switch reason {
	case rotSize:
		why = "part size reached"
	case rotLowDisk:
		why = "closed early: low disk space"
	}
	d.s.event(index.LevelInfo, index.KindRotate, d.id, fmt.Sprintf("closed %s (%s, %d lines, %d bytes)", rel, why, d.w.lines, d.w.size))
	reset()
	return ce
}

// detachFileLocked closes the active file's handle without fsyncing it and clears the
// dirty state; the caller hands the fsync to the closer pool.
func (d *device) detachFileLocked() {
	d.fileMu.Lock()
	had := d.f != nil
	if had {
		d.f.Close()
		d.f = nil
	}
	d.dirty, d.dirtyPath = false, ""
	d.fileMu.Unlock()
	if had {
		d.s.releaseSlot(d)
	}
}

// nextPart returns the next free part number for day in dir.
func nextPart(dir, day string) int {
	max := 0
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if n, ok := logfile.ParseName(e.Name()); ok && n.Day == day && n.Part > max {
			max = n.Part
		} else if base, ok := cutTemp(e.Name()); ok {
			if n, ok := logfile.ParseName(base); ok && n.Day == day && n.Part > max {
				max = n.Part
			}
		}
	}
	return max + 1
}

func cutTemp(name string) (string, bool) {
	if len(name) > len(logfile.TempSuffix) && name[len(name)-len(logfile.TempSuffix):] == logfile.TempSuffix {
		return name[:len(name)-len(logfile.TempSuffix)], true
	}
	return "", false
}

func nextDay(day string) string {
	t, err := logfile.DayStart(day)
	if err != nil {
		return day
	}
	return logfile.DayOf(t.Add(24 * time.Hour))
}

// acquireSlot reserves an open-file slot for d, closing the least recently used
// handles over the cap. A handle whose device is busy is skipped, so the cap can be
// exceeded briefly under contention rather than deadlock.
func (s *Store) acquireSlot(d *device) {
	s.lruMu.Lock()
	defer s.lruMu.Unlock()
	for s.openFiles >= s.opts.MaxOpenFiles && s.evictOneLocked(d) {
	}
	s.openFiles++
	if s.openFiles > s.maxOpen {
		s.maxOpen = s.openFiles
	}
	d.elem = s.lru.PushFront(d)
}

func (s *Store) evictOneLocked(except *device) bool {
	for e := s.lru.Back(); e != nil; e = e.Prev() {
		v := e.Value.(*device)
		if v == except || !v.mu.TryLock() {
			continue
		}
		v.fileMu.Lock()
		if v.f != nil {
			v.f.Close()
			v.f = nil
			if v.dirty {
				v.dirtyPath = v.abs // the sync loop fsyncs it through a fresh handle
			}
		}
		v.fileMu.Unlock()
		s.lru.Remove(e)
		v.elem = nil
		s.openFiles--
		v.mu.Unlock()
		return true
	}
	return false
}

func (s *Store) releaseSlot(d *device) {
	s.lruMu.Lock()
	if d.elem != nil {
		s.lru.Remove(d.elem)
		d.elem = nil
		s.openFiles--
	}
	s.lruMu.Unlock()
}

func (s *Store) touch(d *device) {
	s.lruMu.Lock()
	if d.elem != nil {
		s.lru.MoveToFront(d.elem)
	}
	s.lruMu.Unlock()
}

// idleLocked reports whether the device can be evicted: no active file, nothing
// buffered or uncounted, no handle or pending fsync, and quiet for IdleEvict.
func (d *device) idleLocked(now time.Time) bool {
	if d.closed || d.day != "" || len(d.buf) > 0 || len(d.act) > 0 || len(d.bufAct) > 0 || d.f != nil ||
		now.Sub(d.lastHeard) < d.s.opts.IdleEvict {
		return false
	}
	d.fileMu.Lock()
	dirty := d.dirty
	d.fileMu.Unlock()
	return !dirty
}

// parkLocked closes the active file early because the device went quiet
// (IdleClose): the buffer is written, the handle closed and the file handed to the
// closer pool to fsync, and the file stays in the catalog as parked with its state,
// so the device can append to it again. Then IdleEvict can free the device.
func (d *device) parkLocked() bool {
	if d.needResync {
		if err := d.resyncLocked(); err != nil {
			return false // try again next pass
		}
	}
	if len(d.buf) > 0 {
		return false // flushLocked failed; try again next pass
	}
	d.detachFileLocked()
	if d.w.size == 0 {
		if st, err := os.Stat(d.abs); err == nil && st.Size() == 0 {
			os.Remove(d.abs)
		}
	} else {
		ce := &catEntry{deviceID: d.id, name: logfile.Name{Day: d.day}, abs: d.abs, rel: d.rel, first: d.w.first,
			last: d.w.last, size: d.w.size, rawSize: d.w.size, lines: d.w.lines, parked: true, syncing: true, cp: d.wcp}
		d.s.addClosed(ce)
		d.s.activeBytes.Add(-d.w.size)
		d.s.queueClose(closeJob{e: ce, path: d.abs, dir: d.dir})
	}
	d.day = ""
	d.w, d.p = fileState{}, fileState{}
	d.wcp, d.cp = logfile.Checkpointer{}, logfile.Checkpointer{}
	d.newCPs, d.resetCPs, d.needResync = nil, false, false
	return true
}

// adoptLocked makes a parked file the active file again, resuming its line count and
// checkpoint sequence; appends go to its end. (If the file changed on disk meanwhile,
// ensureOpenLocked sees the size differ and re-reads it.)
func (d *device) adoptLocked(e *catEntry) {
	d.w = fileState{size: e.size, lines: e.lines, first: e.first, last: e.last}
	d.wcp = e.cp
	d.p, d.cp = d.w, d.wcp
	d.needResync = false
	d.s.activeBytes.Add(e.size)
}
