package search

import (
	"bytes"
	"context"
	"math"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/store/logfile"
	"github.com/gmccollu/woodshed/internal/syslog"
)

// The scan behind a summary (summary.go). It steps the device streams like a
// desc search, newest bound first, but every matching line goes straight to
// the holdback. A compressed file is read forward in one pass (gzip can't be
// read backwards); when the budget runs out in the middle of one, its open
// reader is kept in the summary's state, so the next request carries on from
// that byte instead of decompressing the file from the top again. Streams
// whose next read is a compressed pass are read in parallel.

// MaxKeptReaders is how many paused compressed-file readers one summary keeps
// (each holds an open file and a few blocks of read-ahead).
const MaxKeptReaders = 8

// keptPass is a compressed-file pass paused at fr.off.
type keptPass struct {
	o   *opened
	fr  *fwd
	seq uint64
}

// keptReaders are a summary's paused passes, by file ID.
type keptReaders struct {
	mu  sync.Mutex
	m   map[int64]*keptPass
	seq uint64
}

func newKeptReaders() *keptReaders { return &keptReaders{m: map[int64]*keptPass{}} }

// take returns the paused pass of file id if it continues at off, or nil.
func (k *keptReaders) take(id int64, path string, off int64) *keptPass {
	k.mu.Lock()
	kp := k.m[id]
	delete(k.m, id)
	k.mu.Unlock()
	if kp == nil {
		return nil
	}
	if kp.o.file.Path != path || kp.fr.off != off {
		kp.o.Close()
		return nil
	}
	return kp
}

func (k *keptReaders) put(id int64, kp *keptPass) {
	k.mu.Lock()
	k.seq++
	kp.seq = k.seq
	var drop []*keptPass
	if old := k.m[id]; old != nil {
		drop = append(drop, old)
	}
	k.m[id] = kp
	for len(k.m) > MaxKeptReaders {
		var oid int64
		var old *keptPass
		for i, p := range k.m {
			if old == nil || p.seq < old.seq {
				oid, old = i, p
			}
		}
		delete(k.m, oid)
		drop = append(drop, old)
	}
	k.mu.Unlock()
	for _, p := range drop {
		p.o.Close()
	}
}

// closeAll closes every paused pass.
func (k *keptReaders) closeAll() {
	if k == nil {
		return
	}
	k.mu.Lock()
	m := k.m
	k.m = map[int64]*keptPass{}
	k.mu.Unlock()
	for _, p := range m {
		p.o.Close()
	}
}

// len is the number of paused passes (tests).
func (k *keptReaders) len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.m)
}

// pendLine is a found line, with its host and app as local intern IDs (for
// another data type, ext is its row of field value IDs in sumCollect.extIDs).
type pendLine struct {
	ms        int64
	dev       int32
	pri       int16
	host, app int32 // -1: none
	ext       int32 // -1: none
}

// localIntern gives the strings one collector sees small IDs, so lines found
// on another goroutine are cheap to keep until they're added to the tallies.
type localIntern struct {
	ids   map[string]int32
	vals  []string
	tally []int32 // the tally slot of each value, once looked up (-3: not yet)
}

func (li *localIntern) id(v string) int32 {
	if v == "" {
		return -1
	}
	if i, ok := li.ids[v]; ok {
		return i
	}
	if li.ids == nil {
		li.ids = map[string]int32{}
	}
	i := int32(len(li.vals))
	li.ids[v] = i
	li.vals = append(li.vals, v)
	return i
}

// sumCollect gathers one run's found lines.
type sumCollect struct {
	kept       *keptReaders
	fields     bool  // parse host and app
	dev        int32 // the device the lines come from
	pend       []pendLine
	hosts      localIntern
	apps       localIntern
	onBlock    func() // called after each block of a pass (the main run drains there)
	passBlocks int    // blocks read by passes, for tests

	// Another data type than syslog: the field keys counted (genKeys, in
	// order), a local intern per key, and each line's IDs, len(genKeys) a line.
	dt      datatype.Type
	genKeys []string
	gens    []localIntern
	extIDs  []int32
}

// add records one matching line. It runs after r.lines has finished with the
// block, so it may reuse r's scratch buffers.
func (c *sumCollect) add(r *run, h hit) {
	raw := h.esc
	if bytes.IndexByte(raw, '\\') >= 0 {
		r.unesc = logfile.Unescape(r.unesc[:0], raw)
		raw = r.unesc
	}
	if c.dt != nil && c.dt.Name() != TypeSyslog {
		p := pendLine{ms: h.ms, dev: c.dev, pri: -1, host: -1, app: -1, ext: -1}
		if len(c.genKeys) > 0 {
			if len(c.gens) < len(c.genKeys) {
				c.gens = make([]localIntern, len(c.genKeys))
			}
			p.ext = int32(len(c.extIDs) / len(c.genKeys))
			row := len(c.extIDs)
			c.extIDs = append(c.extIDs, make([]int32, len(c.genKeys))...)
			for i := range c.genKeys {
				c.extIDs[row+i] = -1
			}
			c.dt.FieldValues(raw, &r.sc, func(k, v string) {
				for i, gk := range c.genKeys {
					if gk == k {
						c.extIDs[row+i] = c.gens[i].id(v)
					}
				}
			})
		}
		c.pend = append(c.pend, p)
		return
	}
	p := pendLine{ms: h.ms, dev: c.dev, pri: int16(PRI(raw)), host: -1, app: -1, ext: -1}
	if c.fields {
		syslog.Parse(raw, &r.sc.Msg)
		p.host, p.app = c.hosts.id(r.sc.Msg.Hostname), c.apps.id(r.sc.Msg.App)
	}
	c.pend = append(c.pend, p)
}

// sumPass reads [lo, hi) of a compressed file forward for a summary, from a
// paused pass if the summary kept one there. Out of budget, it pauses the pass
// and keeps the reader; [lo, where it stopped) has been counted either way.
func (s *stream) sumPass(r *run, fi *fileInfo, lo, hi int64) error {
	var fr *fwd
	if kp := r.sum.kept.take(fi.ID, s.cur.file.Path, lo); kp != nil {
		s.cur.Close()
		s.cur, fr = kp.o, kp.fr
	}
	if fr == nil {
		rd, err := s.cur.readAhead(lo, r.e.block, r.e.decodeSem)
		if err != nil {
			return err
		}
		fr = newFwd(rd, lo, r.e.block)
	}
	var tmp []hit
	for blocks := 0; ; blocks++ {
		if blocks > 0 && r.expired() {
			if !r.e.sumNoKeep {
				r.sum.kept.put(fi.ID, &keptPass{o: s.cur, fr: fr})
				s.cur = nil
			}
			s.pos, s.hint = hi, fr.off
			if hi < 0 {
				s.pos = -1
			}
			return nil
		}
		buf, off, err := fr.next()
		if err != nil {
			return err
		}
		if buf == nil || (hi >= 0 && off >= hi) {
			break
		}
		r.scanned += int64(len(buf))
		r.sum.passBlocks++
		tmp = r.lines(buf, off, hi, fi, tmp[:0])
		for _, h := range tmp {
			r.sum.add(r, h)
		}
		if r.sum.onBlock != nil {
			r.sum.onBlock()
		}
		if hi >= 0 && off+int64(len(buf)) >= hi {
			break
		}
	}
	s.pos, s.hint = s.rs, 0 // the whole region has been read
	return nil
}

// drain moves a collector's lines into the holdback.
func (st *sumState) drain(c *sumCollect) {
	if len(c.pend) == 0 {
		return
	}
	look := func(li *localIntern, t *tally, app bool, id int32) int32 {
		if id < 0 {
			return idNone
		}
		for len(li.tally) < len(li.vals) {
			li.tally = append(li.tally, -3)
		}
		if li.tally[id] == -3 {
			li.tally[id] = t.id(li.vals[id], app)
		}
		return li.tally[id]
	}
	for _, p := range c.pend {
		h := held{ms: p.ms, dev: p.dev, pri: p.pri, host: idNone, app: idNone, ext: -1}
		if c.fields {
			h.host = look(&c.hosts, st.host, false, p.host)
			h.app = look(&c.apps, st.app, true, p.app)
		}
		if p.ext >= 0 {
			n := len(c.genKeys)
			row := st.extRow()
			for i := 0; i < n; i++ {
				st.extRows[row][i] = look(&c.gens[i], st.gen[i], false, c.extIDs[int(p.ext)*n+i])
			}
			h.ext = row
		}
		st.hold = append(st.hold, h)
	}
	c.pend = c.pend[:0]
	c.extIDs = c.extIDs[:0]
}

// child is a run for one stream's step on another goroutine.
func (r *run) child(dev int32) *run {
	return &run{e: r.e, ctx: r.ctx, deadline: r.deadline, now: r.now, fromMs: r.fromMs, toMs: r.toMs, desc: true,
		m: r.m, ex: r.ex, dt: r.dt, tf: r.tf, need: r.need, ringBytes: r.ringBytes,
		files: map[int64]struct{}{}, steps: r.steps, maxSteps: r.maxSteps,
		sum: &sumCollect{kept: r.sum.kept, fields: r.sum.fields, dev: dev, dt: r.sum.dt, genKeys: r.sum.genKeys}}
}

// compressedNext reports whether the stream's next read is a compressed pass.
func (s *stream) compressedNext() bool {
	if s.done || s.head() != nil || s.pending || s.fi < 0 || s.fi >= len(s.files) {
		return false
	}
	if s.cur != nil {
		return s.cur.file.Compressed && !s.finished(true)
	}
	return s.files[s.fi].Compressed
}

// summaryScan advances st's scan until the deadline or the end.
func (e *Engine) summaryScan(ctx context.Context, st *sumState, c compiled, deadline time.Time) (int64, int, error) {
	r := &run{e: e, ctx: ctx, deadline: deadline, maxSteps: e.testMaxSteps, now: e.now(), desc: true, m: c.m, ex: c.ex,
		dt: c.dt, tf: c.tf, need: 1 << 30, files: map[int64]struct{}{}, ringBytes: math.MaxInt}
	r.fromMs, r.toMs = st.fromMs, st.toMs
	r.sum = &sumCollect{kept: st.kept, dt: st.dt, genKeys: st.genKeys}
	if st.syslog() {
		r.sum.fields = slices.Contains(st.wantFields, FieldHost) || slices.Contains(st.wantFields, FieldApp)
	}
	r.sum.onBlock = func() {
		if len(r.sum.pend) >= 4096 {
			st.drain(r.sum)
		}
	}
	devIdx := make(map[string]int32, len(st.devs))
	for i, d := range st.devs {
		devIdx[d] = int32(i)
	}
	var streams []*stream
	if st.started {
		cur, err := e.decodeCursor(st.scanCursor, st.bind)
		if err != nil {
			return 0, 0, err
		}
		devs := make([]string, len(cur.streams))
		for i, cs := range cur.streams {
			devs[i] = cs.dev
		}
		files, err := e.filesByDevice(ctx, st.dt.Name(), devs, r.fromMs, r.toMs)
		if err != nil {
			return 0, 0, err
		}
		for _, cs := range cur.streams {
			streams = append(streams, cs.resume(files[cs.dev], true))
		}
	} else {
		files, err := e.filesByDevice(ctx, st.dt.Name(), st.devs, r.fromMs, r.toMs)
		if err != nil {
			return 0, 0, err
		}
		for _, d := range st.devs {
			s := newStream(d, files[d])
			s.fi = len(s.files) - 1
			streams = append(streams, s)
		}
		st.started = true
	}
	r.streams = streams
	defer func() {
		for _, s := range streams {
			s.close()
		}
	}()
	if st.holdFlushN == 0 {
		st.holdFlushN = 4096
	}
	workers := e.sumWorkers
	if workers == 0 {
		workers = max(1, min(4, runtime.NumCPU()/2))
	}
	for {
		// Read the stream with the newest unread lines next, so the counted span
		// grows from to downwards.
		best, bestKey := -1, int64(0)
		for i, s := range streams {
			if s.done {
				continue
			}
			k, _ := s.key(r)
			if best < 0 || k > bestKey || (k == bestKey && s.dev < streams[best].dev) {
				best, bestKey = i, k
			}
		}
		if best < 0 {
			break
		}
		if r.steps > 0 && r.expired() {
			break
		}
		r.steps++
		group := []int{best}
		if workers > 1 && streams[best].compressedNext() {
			// Other streams due for a compressed pass decompress at the same time,
			// newest first.
			var more []int
			for i, s := range streams {
				if i != best && s.compressedNext() {
					more = append(more, i)
				}
			}
			slices.SortFunc(more, func(a, b int) int {
				ka, _ := streams[a].key(r)
				kb, _ := streams[b].key(r)
				switch {
				case ka > kb:
					return -1
				case ka < kb:
					return 1
				}
				return 0
			})
			group = append(group, more[:min(len(more), workers-1)]...)
		}
		if len(group) == 1 {
			s := streams[best]
			r.sum.dev = devIdx[s.dev]
			s.step(r)
			if r.err != nil {
				return 0, 0, r.err
			}
			for s.head() != nil {
				r.sum.add(r, s.pop())
			}
			st.drain(r.sum)
		} else {
			kids := make([]*run, len(group))
			var wg sync.WaitGroup
			for i, gi := range group {
				s := streams[gi]
				kid := r.child(devIdx[s.dev])
				kids[i] = kid
				wg.Add(1)
				go func() {
					defer wg.Done()
					s.step(kid)
					for s.head() != nil {
						kid.sum.add(kid, s.pop())
					}
				}()
			}
			wg.Wait()
			for _, kid := range kids {
				r.scanned += kid.scanned
				for id := range kid.files {
					r.files[id] = struct{}{}
				}
				r.sum.passBlocks += kid.sum.passBlocks
				if kid.err != nil && r.err == nil {
					r.err = kid.err
				}
				r.timedOut = r.timedOut || kid.timedOut
				st.drain(kid.sum)
			}
			if r.err != nil {
				return 0, 0, r.err
			}
		}
		if len(st.hold) >= st.holdFlushN {
			st.flush(r, streams)
			st.holdFlushN = max(4096, 2*len(st.hold))
		}
	}
	st.flush(r, streams)
	st.scanCursor = e.encodeCursor(st.bind, r, streams)
	st.passBlocks += r.sum.passBlocks
	if st.scanCursor == "" {
		st.done = true
		st.flush(r, nil) // nothing is unread: commit the rest
		st.countedMs = st.fromMs
	}
	return r.scanned, len(r.files), nil
}
