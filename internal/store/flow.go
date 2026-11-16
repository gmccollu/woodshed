package store

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Flows (SPEC §13.2): one columnar segment (package flowseg) per device per
// received hour, logs/<device>/flows/<YYYY-MM-DD>T<HH>.wsf, a new part past
// FlowPartBytes or FlowPartBlocks. The device side is the framework's: a flow
// exporter is admitted, heard and counted (type_stats, by received minute)
// through its own stream (flowTI), like any type. The segment writers live
// here, outside the line streams, so a quiet exporter's device state can be
// evicted while its hour's segment stays open until the hour ends.
//
// Durability: the open block is written every FlushInterval (1 s) and the
// segment fsynced every SyncInterval (5 s), as for lines. Closed segments are
// immutable, already compressed, and never gzipped. At startup a segment
// without a footer (a crash) is recovered (flowseg.Recover: cut after the last
// good block, footer written) and closed; the exporter's next record starts a
// new part, so a closed segment is never reopened.
//
// Retention: flows have their own budget (FlowBudgetBytes, 40 % of the cap by
// default). While they're over it the oldest flow segments go, fair-shared
// between exporters by their 7-day average, before any other type is
// touched; the other types share the rest of the cap (the cap minus what
// flows hold, at most the budget), so flows never count against it beyond
// their budget. The age limit applies to flows too. The low-disk guard
// deletes closed flow segments first, oldest first. A device's current and
// previous hour are never deleted by the budget.

// FlowPartBytes is the size at which a segment starts a numbered part.
const FlowPartBytes = 256 << 20

// FlowPartBlocks is the block count at which a segment starts a numbered
// part (SPEC §13.10 decision 56). It bounds what one writer keeps for its
// open segment (a 216-byte directory entry a block, at most 1.7 MiB), what a
// query's snapshot of it copies (472 bytes a block, 3.9 MiB) and the footer
// (every block's header again). An exporter writes about one block a second
// (the 1 s rule and the store's 1 s flush), 3,600 an hour, and up to about
// two a second when early flushes under FlowOpenBytesCap add some, so an
// hour stays one part; a busy exporter's full blocks reach FlowPartBytes
// first (about 200 blocks of 65,536 records).
const FlowPartBlocks = 8192

// flowPartBlocks is FlowPartBlocks (tests lower it).
var flowPartBlocks = FlowPartBlocks

// FlowOpenBytesCap bounds the open blocks of every writer together; a writer
// over its share flushes early (SPEC §13.6).
const FlowOpenBytesCap = 64 << 20

// DefaultFlowBudgetPercent of RetentionBytes is the flow budget when
// FlowBudgetBytes is 0.
const DefaultFlowBudgetPercent = 40

// flowTI is the flow stream's type index: after logfile.DataTypes, which are
// the line types.
var flowTI = uint8(len(logfile.DataTypes))

// flowSeg is a closed segment.
type flowSeg struct {
	deviceID    string
	rel, abs    string
	name        flowseg.Name
	first, last time.Time // received
	size        int64
	records     int64
}

// flowStream is one device's open segment.
type flowStream struct {
	mu          sync.Mutex
	id          string
	dir         string
	w           *flowseg.Writer
	name        flowseg.Name
	rel, abs    string
	hour        time.Time // the segment's received hour
	first, last time.Time
	dirty       bool // flushed since the last fsync
	pending     bool // appended to since the last flush
	failed      time.Time
	meta        []byte    // the exporter's latest metadata blob, given to every segment it opens
	lastWrite   time.Time // the latest batch's received time (the stream is forgotten an hour after it)
}

// flowStreamIdle is how long a stream without an open segment is kept (with
// its metadata) after its last batch.
const flowStreamIdle = time.Hour

// flows is the store's flow state.
type flows struct {
	mu       sync.Mutex
	streams  map[string]*flowStream // by device ID
	cat      map[string]*flowSeg    // closed segments by rel path
	catBytes int64
}

// FlowBudget returns the flow budget in effect.
func (s *Store) FlowBudget() int64 {
	if b := s.flowBudget.Load(); b > 0 {
		return b
	}
	return s.retentionBytes.Load() * DefaultFlowBudgetPercent / 100
}

// FlowBytes returns the bytes flow segments take on disk, closed and open.
func (s *Store) FlowBytes() int64 {
	s.fl.mu.Lock()
	n := s.fl.catBytes
	streams := make([]*flowStream, 0, len(s.fl.streams))
	for _, st := range s.fl.streams {
		streams = append(streams, st)
	}
	s.fl.mu.Unlock()
	for _, st := range streams {
		st.mu.Lock()
		if st.w != nil {
			n += st.w.Size()
		}
		st.mu.Unlock()
	}
	return n
}

// FlowBatch is one datagram's worth of decoded flow data for WriteFlows.
type FlowBatch struct {
	Received time.Time // when the datagram was read (the segment's hour)
	Size     int       // the datagram's bytes (the type_stats bytes)
	Records  []*flow.Record
	Raw      []*flow.RawSet
	Meta     []byte // the exporter's metadata blob, if it changed (nil: unchanged)
	// Templates the raw sets might need later (flowseg.Writer.AddTemplate).
	Templates []*flow.Template
}

// WriteFlows stores one exporter's batch. It never blocks on the disk beyond
// writing a full block. It returns ErrPaused (counting the records as
// dropped) while the low-disk guard has paused writing, and ErrDeviceLimit
// for a new sender the limits refuse.
func (s *Store) WriteFlows(addr netip.Addr, b FlowBatch) error {
	if s.closed.Load() {
		return ErrClosed
	}
	if !addr.IsValid() {
		return ErrInvalidSender
	}
	n := int64(len(b.Records))
	rec := b.Received
	if rec.IsZero() {
		rec = s.clock()
	}
	rec = time.UnixMilli(rec.UnixMilli()).UTC()
	addr = addr.Unmap()
	var d *device
	for {
		var err error
		if d, err = s.device(streamKey{addr, flowTI}, true); err != nil {
			s.noteRefused(rec)
			return err
		}
		d.mu.Lock()
		if !d.evicted {
			break
		}
		d.mu.Unlock()
	}
	if d.closed {
		d.mu.Unlock()
		return ErrClosed
	}
	d.heardLocked(rec)
	if s.paused.Load() {
		d.dropLocked(rec, max(n, 1), dropPaused)
		d.mu.Unlock()
		return ErrPaused
	}
	d.mu.Unlock()

	st := s.flowStream(d.id)
	st.mu.Lock()
	err := s.appendFlowsLocked(st, rec, &b)
	st.mu.Unlock()

	d.mu.Lock()
	if err != nil {
		d.dropLocked(rec, max(n, 1), dropWriteError)
	} else {
		a := d.accFor(&d.act, rec)
		a.c.Msgs += n
		a.c.Bytes += int64(b.Size)
		s.written.Add(n)
	}
	d.mu.Unlock()
	if err != nil {
		s.noteWriteError(d.id, st.rel, err)
	}
	return err
}

// flowStream returns a device's stream, creating it.
func (s *Store) flowStream(id string) *flowStream {
	s.fl.mu.Lock()
	defer s.fl.mu.Unlock()
	st := s.fl.streams[id]
	if st == nil {
		st = &flowStream{id: id, dir: filepath.Join(s.logsDir, id, logfile.FlowDir)}
		s.fl.streams[id] = st
	}
	return st
}

// appendFlowsLocked writes a batch to the stream's segment, opening or
// rotating it first (st.mu held).
func (s *Store) appendFlowsLocked(st *flowStream, rec time.Time, b *FlowBatch) error {
	hour := rec.Truncate(time.Hour)
	if st.w != nil && (hour.After(st.hour) || st.w.Size() >= FlowPartBytes || st.w.Blocks() >= flowPartBlocks) {
		s.closeFlowLocked(st, "")
	}
	if st.w == nil {
		if !st.failed.IsZero() && rec.Sub(st.failed) < time.Second {
			return errors.New("store: can't open a flow segment (retrying each second)")
		}
		if err := s.openFlowLocked(st, hour); err != nil {
			st.failed = rec
			return err
		}
		st.failed = time.Time{}
	}
	for _, t := range b.Templates {
		st.w.AddTemplate(t)
	}
	if b.Meta != nil {
		st.meta = append([]byte(nil), b.Meta...)
		st.w.SetMeta(st.meta)
	}
	for _, r := range b.Records {
		if err := st.w.Append(r); err != nil {
			return err
		}
	}
	for _, r := range b.Raw {
		if err := st.w.AppendRaw(r); err != nil {
			return err
		}
	}
	st.pending = true
	st.lastWrite = rec
	if st.first.IsZero() || rec.Before(st.first) {
		st.first = rec
	}
	if rec.After(st.last) {
		st.last = rec
	}
	// Keep every writer's open block together under the cap: one over its
	// equal share writes its block early.
	s.fl.mu.Lock()
	share := int64(FlowOpenBytesCap) / int64(max(len(s.fl.streams), 1))
	s.fl.mu.Unlock()
	if st.w.OpenBytes() > share {
		return s.flushFlowLocked(st)
	}
	return nil
}

// openFlowLocked starts the stream's segment for hour: the first free part.
func (s *Store) openFlowLocked(st *flowStream, hour time.Time) error {
	if err := os.MkdirAll(st.dir, 0o750); err != nil {
		return err
	}
	n := flowseg.NameFor(hour)
	for {
		abs := filepath.Join(st.dir, n.String())
		if _, err := os.Lstat(abs); errors.Is(err, fs.ErrNotExist) {
			w, err := flowseg.Create(abs, st.id, hour, s.opts.Version)
			if errors.Is(err, fs.ErrExist) {
				n.Part++
				continue
			}
			if err != nil {
				return err
			}
			st.w, st.name, st.abs, st.rel, st.hour = w, n, abs, s.rel(abs), hour
			st.first, st.last, st.dirty = time.Time{}, time.Time{}, false
			if st.meta != nil {
				w.SetMeta(st.meta) // a new hour or part carries the metadata in force
			}
			return nil
		}
		n.Part++
		if n.Part > 999 {
			return fmt.Errorf("store: %s: 1,000 flow segment parts in one hour", st.dir)
		}
	}
}

// flushFlowLocked writes the open block and queues the index rows (st.mu held).
func (s *Store) flushFlowLocked(st *flowStream) error {
	if st.w == nil || !st.pending {
		return nil
	}
	err := st.w.Flush()
	st.dirty, st.pending = true, false
	s.queueFlowRows(st, false, nil)
	return err
}

// queueFlowRows queues the stream's files and flow_segments rows (from the
// writer's summary, or foot when closing) and its new minutes. The rows use
// only the footer's segment-level fields, so a flush never copies the block
// directory.
func (s *Store) queueFlowRows(st *flowStream, closed bool, foot *flowseg.Footer) {
	mins := st.w.TakeMinutes()
	size := st.w.Size()
	if foot == nil {
		foot = st.w.Summary()
	} else if fi, err := os.Stat(st.abs); err == nil {
		size = fi.Size()
	}
	if foot.Empty() && len(mins) == 0 && !closed {
		return
	}
	ff := index.FlowFile{DeviceID: st.id, Name: st.name, Rel: st.rel, Path: st.abs}
	rows := index.FlowRowsOf(ff, foot, size, closed)
	s.qMu.Lock()
	s.qOps = append(s.qOps, index.FileOp{Kind: index.OpUpsert, File: rows.File, Flow: &rows.Segment})
	s.qFlowMin = append(s.qFlowMin, index.FlowMinutesOf(st.rel, st.id, mins)...)
	s.qMu.Unlock()
}

// closeFlowLocked closes the stream's segment and moves it to the catalog
// (st.mu held). why, when set, is logged as a rotate event.
func (s *Store) closeFlowLocked(st *flowStream, why string) {
	if st.w == nil {
		return
	}
	foot, err := st.w.Close()
	if err != nil {
		s.log.Warn("store: closing a flow segment failed; recovery finishes it at the next start", "file", st.rel, "err", err)
		if foot == nil {
			foot = st.w.Summary()
		}
	}
	s.queueFlowRows(st, err == nil, foot)
	size := int64(0)
	if fi, serr := os.Stat(st.abs); serr == nil {
		size = fi.Size()
	}
	seg := &flowSeg{deviceID: st.id, rel: st.rel, abs: st.abs, name: st.name, first: st.first, last: st.last, size: size,
		records: foot.Totals.Records}
	if seg.first.IsZero() {
		seg.first, seg.last = time.UnixMilli(foot.MinReceived).UTC(), time.UnixMilli(foot.MaxReceived).UTC()
	}
	s.fl.mu.Lock()
	s.fl.cat[seg.rel] = seg
	s.fl.catBytes += seg.size
	s.fl.mu.Unlock()
	if why != "" {
		s.event(index.LevelInfo, index.KindRotate, st.id, fmt.Sprintf("closed %s (%s, %d flow records, %d bytes)",
			st.rel, why, foot.Totals.Records, size))
	}
	st.w = nil
	st.dirty, st.pending = false, false
}

// flushFlows writes every open block; with rotate set (the maintenance pass)
// it also closes segments whose hour has ended and forgets quiet streams.
func (s *Store) flushFlows(now time.Time, rotate bool) error {
	s.fl.mu.Lock()
	streams := make([]*flowStream, 0, len(s.fl.streams))
	for _, st := range s.fl.streams {
		streams = append(streams, st)
	}
	s.fl.mu.Unlock()
	hour := now.UTC().Truncate(time.Hour)
	var first error
	for _, st := range streams {
		st.mu.Lock()
		if st.w != nil {
			if rotate && st.hour.Before(hour) {
				s.closeFlowLocked(st, "")
			} else if err := s.flushFlowLocked(st); err != nil && first == nil {
				first = err
			}
		}
		idle := st.w == nil && now.Sub(st.lastWrite) >= flowStreamIdle
		st.mu.Unlock()
		if rotate && idle {
			s.fl.mu.Lock()
			st.mu.Lock()
			if st.w == nil && now.Sub(st.lastWrite) >= flowStreamIdle && s.fl.streams[st.id] == st {
				delete(s.fl.streams, st.id)
			}
			st.mu.Unlock()
			s.fl.mu.Unlock()
		}
	}
	return first
}

// syncFlows fsyncs the segments written since the last pass.
func (s *Store) syncFlows() error {
	s.fl.mu.Lock()
	streams := make([]*flowStream, 0, len(s.fl.streams))
	for _, st := range s.fl.streams {
		streams = append(streams, st)
	}
	s.fl.mu.Unlock()
	var first error
	for _, st := range streams {
		st.mu.Lock()
		if st.w != nil && st.dirty {
			if err := st.w.Sync(); err != nil && first == nil {
				first = err
			}
			st.dirty = false
		}
		st.mu.Unlock()
	}
	return first
}

// closeFlows closes every open segment (the store's Close).
func (s *Store) closeFlows() {
	s.fl.mu.Lock()
	streams := make([]*flowStream, 0, len(s.fl.streams))
	for _, st := range s.fl.streams {
		streams = append(streams, st)
	}
	s.fl.mu.Unlock()
	for _, st := range streams {
		st.mu.Lock()
		s.closeFlowLocked(st, "")
		st.mu.Unlock()
	}
}

// FlowSnapshot is a device's open segment as a query sees it.
type FlowSnapshot struct {
	DeviceID string
	Rel      string
	Path     string
	Footer   *flowseg.Footer
}

// OpenFlowSegments returns the open segments' snapshots (deviceIDs nil: all),
// for queries of the current hour.
func (s *Store) OpenFlowSegments(deviceIDs []string) []FlowSnapshot {
	want := map[string]bool{}
	for _, id := range deviceIDs {
		want[id] = true
	}
	s.fl.mu.Lock()
	streams := make([]*flowStream, 0, len(s.fl.streams))
	for id, st := range s.fl.streams {
		if deviceIDs == nil || want[id] {
			streams = append(streams, st)
		}
	}
	s.fl.mu.Unlock()
	var out []FlowSnapshot
	for _, st := range streams {
		st.mu.Lock()
		if st.w != nil {
			out = append(out, FlowSnapshot{DeviceID: st.id, Rel: st.rel, Path: st.abs, Footer: st.w.Snapshot()})
		}
		st.mu.Unlock()
	}
	return out
}

// ---- recovery ----

// recoverFlows closes every segment a crash left open and catalogs the
// closed ones. It runs before the index is reconciled.
func (s *Store) recoverFlows() error {
	files, err := index.ListFlowFiles(s.dataDir)
	if err != nil {
		return err
	}
	for _, ff := range files {
		r, err := flowseg.Open(ff.Path)
		if errors.Is(err, flowseg.ErrNoFooter) {
			rr, rerr := flowseg.Recover(ff.Path)
			if rerr != nil {
				s.event(index.LevelWarn, index.KindRecover, ff.DeviceID, fmt.Sprintf(
					"%s couldn't be recovered (%v); it's left as it is and not searched", ff.Rel, rerr))
				continue
			}
			s.event(index.LevelWarn, index.KindRecover, ff.DeviceID, fmt.Sprintf(
				"%s was left open by an unclean stop; kept %d complete blocks and removed %d bytes after them",
				ff.Rel, rr.KeptBlocks, rr.CutBytes))
			r, err = flowseg.Open(ff.Path)
		}
		if err != nil {
			s.event(index.LevelWarn, index.KindRecover, ff.DeviceID, fmt.Sprintf("%s can't be read (%v); not searched", ff.Rel, err))
			continue
		}
		f := r.Footer()
		r.Close()
		size := ff.Size
		if fi, err := os.Stat(ff.Path); err == nil {
			size = fi.Size()
		}
		seg := &flowSeg{deviceID: ff.DeviceID, rel: ff.Rel, abs: ff.Path, name: ff.Name, size: size, records: f.Totals.Records,
			first: time.UnixMilli(f.MinReceived).UTC(), last: time.UnixMilli(f.MaxReceived).UTC()}
		s.fl.cat[seg.rel] = seg
		s.fl.catBytes += seg.size
		s.devMu.Lock()
		s.known[ff.DeviceID] = struct{}{}
		s.devMu.Unlock()
	}
	return nil
}

// ---- retention ----

// sortedFlowSegs returns closed segments matching keep, oldest first.
func (s *Store) sortedFlowSegs(keep func(*flowSeg) bool) []*flowSeg {
	s.fl.mu.Lock()
	var out []*flowSeg
	for _, e := range s.fl.cat {
		if keep(e) {
			out = append(out, e)
		}
	}
	s.fl.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].last.Equal(out[j].last) {
			return out[i].last.Before(out[j].last)
		}
		return out[i].rel < out[j].rel
	})
	return out
}

// deleteFlowSeg removes a closed segment and records the deletion.
func (s *Store) deleteFlowSeg(e *flowSeg, reason index.Reason, now time.Time) bool {
	s.fl.mu.Lock()
	if s.fl.cat[e.rel] != e {
		s.fl.mu.Unlock()
		return false
	}
	if err := os.Remove(e.abs); err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.fl.mu.Unlock()
		s.log.Warn("store: couldn't delete a flow segment; will retry", "file", e.rel, "err", err)
		return false
	}
	delete(s.fl.cat, e.rel)
	s.fl.catBytes -= e.size
	s.fl.mu.Unlock()
	s.pushOps(index.FileOp{Kind: index.OpDelete, File: index.File{DeviceID: e.deviceID, Type: index.TypeFlow, Path: e.rel},
		Deletion: &index.Deletion{Time: now, File: e.rel, DeviceID: e.deviceID, Type: index.TypeFlow, Bytes: e.size, Reason: reason}})
	return true
}

// flowProtected reports whether the budget must keep a segment: the
// current or previous received hour.
func flowProtected(e *flowSeg, now time.Time) bool {
	return !e.name.Time().Before(now.UTC().Truncate(time.Hour).Add(-time.Hour))
}

// enforceFlowRetention deletes flow segments past the age limit, then the
// oldest, fair-shared between exporters, while flows exceed their budget.
func (s *Store) enforceFlowRetention(now time.Time) {
	cutoff := now.Add(-time.Duration(s.retentionDays.Load()) * 24 * time.Hour)
	for _, e := range s.sortedFlowSegs(func(e *flowSeg) bool { return e.last.Before(cutoff) && !flowProtected(e, now) }) {
		s.deleteFlowSeg(e, index.ReasonAge, now)
	}
	budget := s.FlowBudget()
	if s.FlowBytes() <= budget {
		return
	}
	s.flowFairDelete(now, index.ReasonCap, func() bool { return s.FlowBytes() <= budget }, flowProtected)
}

// flowFairDelete deletes closed segments until done: the exporter most over
// its share first (shares split the budget by each exporter's 7-day average
// of flow bytes, as §3.4 shares devices), oldest segment first, then the
// oldest of anyone. protect keeps a segment.
func (s *Store) flowFairDelete(now time.Time, reason index.Reason, done func() bool, protect func(*flowSeg, time.Time) bool) {
	segs := s.sortedFlowSegs(func(e *flowSeg) bool { return !protect(e, now) })
	if len(segs) == 0 || done() {
		return
	}
	weights := s.flowWeights(now)
	bytes := map[string]int64{}
	s.fl.mu.Lock()
	for _, e := range s.fl.cat {
		bytes[e.deviceID] += e.size
	}
	s.fl.mu.Unlock()
	var total float64
	for id := range bytes {
		total += max(weights[id], minShareWeight)
	}
	budget := float64(s.FlowBudget())
	share := func(id string) int64 {
		if total == 0 {
			return 0
		}
		return int64(budget * max(weights[id], minShareWeight) / total)
	}
	byDev := map[string][]*flowSeg{}
	for _, e := range segs {
		byDev[e.deviceID] = append(byDev[e.deviceID], e)
	}
	for !done() {
		var pick string
		var over int64
		for id, l := range byDev {
			if len(l) == 0 {
				continue
			}
			if o := bytes[id] - share(id); o > 0 && (pick == "" || o > over || (o == over && id < pick)) {
				pick, over = id, o
			}
		}
		if pick == "" { // nobody over: the oldest of anyone
			var oldest *flowSeg
			for id, l := range byDev {
				if len(l) > 0 && (oldest == nil || l[0].last.Before(oldest.last) || (l[0].last.Equal(oldest.last) && l[0].rel < oldest.rel)) {
					oldest, pick = l[0], id
				}
			}
			if oldest == nil {
				return
			}
		}
		e := byDev[pick][0]
		byDev[pick] = byDev[pick][1:]
		if s.deleteFlowSeg(e, reason, now) {
			bytes[pick] -= e.size
		}
	}
}

// flowWeights are each exporter's average flow bytes a day over the last
// 7 days (type_stats), the fair-share weights.
func (s *Store) flowWeights(now time.Time) map[string]float64 {
	out := map[string]float64{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	by, err := s.idx.TypeDeviceBytes(ctx, index.TypeFlow, now.Add(-shareHistory), now)
	if err != nil {
		s.log.Warn("store: reading recent flow volumes failed", "err", err)
		return out
	}
	for id, n := range by {
		out[id] = float64(n) / (shareHistory.Hours() / 24)
	}
	return out
}

// flowLowDisk is the low-disk guard's first step: delete closed flow
// segments, oldest first (every exporter's open segment stays), until enough.
func (s *Store) flowLowDisk(now time.Time, enough func(freed uint64) bool) {
	var freed uint64
	for _, e := range s.sortedFlowSegs(func(*flowSeg) bool { return true }) {
		if enough(freed) {
			return
		}
		if s.deleteFlowSeg(e, index.ReasonLowDisk, now) {
			freed += uint64(e.size)
		}
	}
}

// flowHeld is what flows hold against the cap: their bytes, at most the
// budget. The other types share the rest.
func (s *Store) flowHeld() int64 { return min(s.FlowBytes(), s.FlowBudget()) }

// DropQueuedFlows is DropQueued for the flow listener's queue: the drops
// count for the exporter's flow stream.
func (s *Store) DropQueuedFlows(from netip.Addr, at time.Time, n int64) {
	s.dropQueued(flowTI, from, at, n)
}
