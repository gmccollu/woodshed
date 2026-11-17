package flow

import (
	"container/list"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Defaults for Options (SPEC §13.1, §13.1.2, §13.1.3).
const (
	DefaultTemplateTimeout    = 30 * time.Minute
	DefaultPendingBytes       = 32 << 20
	DefaultPendingPerExporter = 1 << 20
	DefaultMaxTemplatesPerKey = 256
	DefaultMaxTemplates       = 10000
	DefaultMaxExporters       = 20000
	// MaxTemplateFields bounds one template (a longer one is malformed).
	MaxTemplateFields = 1024
	// maxTemplateBytes bounds the cache's templates and plans together, and
	// maxMetaBytes the exporter metadata, so both stay within 16 MiB (§13.6).
	maxTemplateBytes = 12 << 20
	maxMetaBytes     = 4 << 20
	// maxIfName bounds one interface name or description.
	maxIfName = 256
	// ClockSkewLimit: an exporter whose clock is further off than this has
	// its records put on received time (SPEC §13.2).
	ClockSkewLimit = time.Hour
	// dupWindow: the same sequence number again within it is a duplicate.
	dupWindow = time.Minute
)

// Options configures a Collector. Zero fields take the defaults.
type Options struct {
	TemplateTimeout    time.Duration
	PendingBytes       int
	PendingPerExporter int
	// RuleIDIEs are listeners.flow.rule_id_ies, in priority order: the first
	// one a record has fills rule_id.
	RuleIDIEs          []IEKey
	MaxTemplatesPerKey int
	MaxTemplates       int
	MaxExporters       int
	Clock              func() time.Time // Expire's default now; default time.Now
}

func (o *Options) defaults() {
	if o.TemplateTimeout <= 0 {
		o.TemplateTimeout = DefaultTemplateTimeout
	}
	if o.PendingBytes <= 0 {
		o.PendingBytes = DefaultPendingBytes
	}
	if o.PendingPerExporter <= 0 {
		o.PendingPerExporter = DefaultPendingPerExporter
	}
	if o.MaxTemplatesPerKey <= 0 {
		o.MaxTemplatesPerKey = DefaultMaxTemplatesPerKey
	}
	if o.MaxTemplates <= 0 {
		o.MaxTemplates = DefaultMaxTemplates
	}
	if o.MaxExporters <= 0 {
		o.MaxExporters = DefaultMaxExporters
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	o.RuleIDIEs = slices.Clone(o.RuleIDIEs)
}

// Packet is one datagram for Decode. Data may be kept by the collector
// (pending data is copied).
type Packet struct {
	Data     []byte
	From     netip.AddrPort
	Received time.Time
}

// settings are the options that can change live.
type settings struct {
	timeout time.Duration
	rules   []IEKey
	gen     uint64
}

// tkey is a template scope inside one exporter address: the exporter's
// source port, the observation domain (v9 source ID) and the version.
type tkey struct {
	port    uint16
	domain  uint32
	version uint8
}

type tmplEntry struct {
	t         *Template
	p         *plan
	refreshed int64
	key       tkey
	exp       *exporter
	elem      *list.Element // in Collector.lru
	size      int
}

// domainState is one (port, domain, version) scope's templates and metadata.
type domainState struct {
	key          tkey
	templates    map[uint16]*tmplEntry
	lastTemplate int64
	sysInitMs    int64
	sampling     uint32            // the domain's own (options data without a sampler)
	samplers     map[uint32]uint32 // sampler or selector ID -> rate
	seq          seqState
	seqMode      string  // seq.mode() for Stats (written under Collector.mu)
	avgPerPkt    float64 // records per packet (v9 loss estimate)
	// opts are the options records kept raw (options.go), by template and
	// scope values, oldest version first.
	opts map[string][]*OptionsData
}

// exporter is one exporter address's state.
type exporter struct {
	addr    netip.Addr
	domains map[tkey]*domainState
	ifNames map[uint64]string // (domain<<32 | ifindex) -> name
	meta    int               // metadata bytes held
	rawOpt  int               // of those, raw options bytes (also counted in Collector.rawOptBytes)
	elem    *list.Element     // in Collector.expLRU
	metaVer atomic.Uint64     // rises with every metadata change (Metadata)

	pending    atomic.Int64         // bytes waiting for templates
	pendOldest atomic.Int64         // received time (unix ms) of the oldest of them; 0 when none
	pkeys      map[pendKey]struct{} // the pending buffer's keys of this exporter (Decode's goroutine)

	cmu       sync.Mutex // counts and the 24 h ring
	counts    Counts
	hours     [24]hourCounts
	off       *offState // records far from their arrival time; nil until the first (timeoff.go)
	skewMs    atomic.Int64
	skewed    atomic.Bool
	lastHeard atomic.Int64
}

// Counts are an exporter's decode counts (SPEC §13.1.3).
type Counts struct {
	Records      int64 `json:"records"`
	Late         int64 `json:"late"`
	NoTemplate   int64 `json:"no_template"`
	Malformed    int64 `json:"malformed"`
	SequenceGaps int64 `json:"sequence_gaps"`
	// LostEstimate is the records the gaps stand for (v9 counts packets, so
	// it's the gap times the average records per packet).
	LostEstimate int64 `json:"lost_estimate"`
	Duplicates   int64 `json:"duplicates"`
}

func (c *Counts) add(o Counts) {
	c.Records += o.Records
	c.Late += o.Late
	c.NoTemplate += o.NoTemplate
	c.Malformed += o.Malformed
	c.SequenceGaps += o.SequenceGaps
	c.LostEstimate += o.LostEstimate
	c.Duplicates += o.Duplicates
}

type hourCounts struct {
	hour int64 // unix hour
	c    Counts
}

func (e *exporter) count(at int64, c Counts) {
	h := at / 3600000
	e.cmu.Lock()
	e.counts.add(c)
	slot := &e.hours[h%24]
	if slot.hour != h {
		*slot = hourCounts{hour: h}
	}
	slot.c.add(c)
	e.cmu.Unlock()
}

// Collector decodes flow v5, v9 and IPFIX datagrams. Decode and Expire
// must be called from one goroutine; Stats, Templates and SetOptions are safe
// from any.
type Collector struct {
	opts Options
	set  atomic.Pointer[settings]

	mu        sync.RWMutex // held for writing when Decode changes the maps below; readers hold it to read
	exporters map[netip.Addr]*exporter
	expLRU    list.List // *exporter, most recently heard first
	lru       list.List // *tmplEntry, most recently refreshed first
	nTmpl     int
	tmplBytes int
	metaBytes int
	// rawOptBytes are the raw options records' bytes (within maxRawOptBytes).
	rawOptBytes int

	pend      pendingBuf
	scratch   Record
	fileMode  bool // the IPFIX file reader: no clock check, received from collectionTimeMilliseconds
	fileRecv  int64
	lastStamp int64
}

// NewCollector returns a collector.
func NewCollector(o Options) *Collector {
	o.defaults()
	c := &Collector{opts: o, exporters: map[netip.Addr]*exporter{}}
	c.set.Store(&settings{timeout: o.TemplateTimeout, rules: o.RuleIDIEs, gen: 1})
	c.pend.init()
	return c
}

// SetOptions changes the live settings: the template timeout and rule_id_ies
// (the other options are fixed at NewCollector). Templates are recompiled for
// new rule IEs on their next use.
func (c *Collector) SetOptions(timeout time.Duration, rules []IEKey) {
	if timeout <= 0 {
		timeout = DefaultTemplateTimeout
	}
	old := c.set.Load()
	c.set.Store(&settings{timeout: timeout, rules: slices.Clone(rules), gen: old.gen + 1})
}

// exporterFor returns (creating) the state of addr. Decode's goroutine only.
func (c *Collector) exporterFor(addr netip.Addr, at int64) *exporter {
	e := c.exporters[addr]
	if e == nil {
		c.mu.Lock()
		for len(c.exporters) >= c.opts.MaxExporters {
			old := c.expLRU.Back()
			if old == nil {
				break
			}
			c.dropExporterLocked(old.Value.(*exporter))
		}
		e = &exporter{addr: addr, domains: map[tkey]*domainState{}, ifNames: map[uint64]string{}}
		e.elem = c.expLRU.PushFront(e)
		c.exporters[addr] = e
		c.mu.Unlock()
	} else {
		c.expLRU.MoveToFront(e.elem)
	}
	e.lastHeard.Store(at)
	return e
}

func (c *Collector) dropExporterLocked(e *exporter) {
	for _, d := range e.domains {
		for _, te := range d.templates {
			c.lru.Remove(te.elem)
			c.nTmpl--
			c.tmplBytes -= te.size
		}
	}
	c.metaBytes -= e.meta
	c.rawOptBytes -= e.rawOpt
	c.pend.dropExporter(e)
	c.expLRU.Remove(e.elem)
	delete(c.exporters, e.addr)
}

func (e *exporter) domain(k tkey) *domainState {
	return e.domains[k]
}

// domainFor returns (creating, under c.mu) a scope's state.
func (c *Collector) domainFor(e *exporter, k tkey) *domainState {
	d := e.domains[k]
	if d == nil {
		c.mu.Lock()
		d = &domainState{key: k, templates: map[uint16]*tmplEntry{}}
		e.domains[k] = d
		c.mu.Unlock()
	}
	return d
}

// lookup returns a scope's template, or nil when it isn't cached or has
// timed out (it's then removed).
func (c *Collector) lookup(d *domainState, id uint16, now int64) *tmplEntry {
	if d == nil {
		return nil
	}
	te := d.templates[id]
	if te == nil {
		return nil
	}
	if now-te.refreshed > c.set.Load().timeout.Milliseconds() {
		c.mu.Lock()
		c.removeTemplateLocked(d, te)
		c.mu.Unlock()
		return nil
	}
	return te
}

func (c *Collector) removeTemplateLocked(d *domainState, te *tmplEntry) {
	if d.templates[te.t.ID] != te {
		return
	}
	delete(d.templates, te.t.ID)
	c.lru.Remove(te.elem)
	c.nTmpl--
	c.tmplBytes -= te.size
}

// planOf returns the entry's plan, recompiled if the settings changed.
func (c *Collector) planOf(te *tmplEntry) *plan {
	s := c.set.Load()
	if te.p == nil || te.p.gen != s.gen {
		te.p = compile(te.t, s.rules, s.gen)
	}
	return te.p
}

func sameFields(a, b *Template) bool {
	return a.Options == b.Options && a.ScopeCount == b.ScopeCount && slices.Equal(a.Fields, b.Fields)
}

// addTemplate caches t (a new definition replaces an older one with the same
// ID from now on; an identical one only refreshes it) and returns its entry.
func (c *Collector) addTemplate(e *exporter, d *domainState, t *Template, now int64) *tmplEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	d.lastTemplate = now
	if old := d.templates[t.ID]; old != nil && sameFields(old.t, t) {
		old.refreshed = now
		c.lru.MoveToFront(old.elem)
		return old
	}
	size := 96 + len(t.Fields)*(8+16)
	if old := d.templates[t.ID]; old != nil {
		c.removeTemplateLocked(d, old)
	}
	if len(d.templates) >= c.opts.MaxTemplatesPerKey {
		var oldest *tmplEntry
		for _, x := range d.templates {
			if oldest == nil || x.refreshed < oldest.refreshed {
				oldest = x
			}
		}
		c.removeTemplateLocked(d, oldest)
	}
	for (c.nTmpl >= c.opts.MaxTemplates || (c.tmplBytes+size > maxTemplateBytes && !c.fileMode)) && c.lru.Len() > 0 {
		x := c.lru.Back().Value.(*tmplEntry)
		c.removeTemplateLocked(x.exp.domains[x.key], x)
	}
	te := &tmplEntry{t: t, refreshed: now, key: d.key, exp: e, size: size}
	te.elem = c.lru.PushFront(te)
	d.templates[t.ID] = te
	c.nTmpl++
	c.tmplBytes += size
	return te
}

// withdraw removes one template (or, with all, every template of the kind)
// from a scope (IPFIX withdrawal, SPEC §13.1.2).
func (c *Collector) withdraw(d *domainState, id uint16, all, options bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !all {
		if te := d.templates[id]; te != nil {
			c.removeTemplateLocked(d, te)
		}
		return
	}
	for _, te := range d.templates {
		if te.t.Options == options {
			c.removeTemplateLocked(d, te)
		}
	}
}

// setIfName records an interface name from options data.
func (c *Collector) setIfName(e *exporter, domain, ifindex uint32, name string) {
	if len(name) > maxIfName {
		name = name[:maxIfName]
	}
	k := uint64(domain)<<32 | uint64(ifindex)
	old, ok := e.ifNames[k]
	if ok && old == name {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delta := len(name) - len(old)
	if !ok {
		delta += 32
	}
	if name == "" {
		delete(e.ifNames, k)
		e.meta -= len(old) + 32
		c.metaBytes -= len(old) + 32
		e.metaVer.Add(1)
		return
	}
	if c.metaBytes+delta > maxMetaBytes {
		return
	}
	e.ifNames[k] = name
	e.meta += delta
	c.metaBytes += delta
	e.metaVer.Add(1)
}

// ifName returns the name of an interface: the domain's own, else any
// domain's of the same exporter (names come from the device).
func (e *exporter) ifName(domain, ifindex uint32, exact bool) (string, bool) {
	if n, ok := e.ifNames[uint64(domain)<<32|uint64(ifindex)]; ok {
		return n, true
	}
	if exact || len(e.ifNames) == 0 {
		return "", false
	}
	for k, n := range e.ifNames {
		if uint32(k) == ifindex {
			return n, true
		}
	}
	return "", false
}

// --- sequence numbers ---

type seqSeen struct {
	seq uint32
	at  int64
}

// The sequence conventions (SPEC §13, decision 78). RFC 7011 §3.1 numbers a
// message by the data records sent before it: seq[n+1] = seq[n] + count[n].
// Some exporters number it after counting its own: seq[n+1] = seq[n] +
// count[n+1]. Either may or may not count options data records.
const (
	seqRFC   = 1 // timing: the records before the message (RFC 7011)
	seqAfter = 2 // timing: the records up to and including it

	seqOptsCounted = 1 // options data records count
	seqOptsNot     = 2 // only (non-options) data records count

	// seqDecide telling messages in a row decide (or change) a convention:
	// ones that only one side of it explains.
	seqDecide = 3
	// seqRestartRun messages behind the expected number, each following the
	// one before, are an exporter restart (a late message is one alone).
	seqRestartRun = 3
)

// seqMsg is one message's number and record counts.
type seqMsg struct {
	seq        uint32
	data, opts uint32 // data records, options data records
	known      bool   // both counts are known
}

func (m seqMsg) count(opts int) uint32 {
	if opts == seqOptsCounted {
		return m.data + m.opts
	}
	return m.data
}

type seqState struct {
	valid bool
	prev  seqMsg // the last message in order
	// learn: the convention is learned from the stream (IPFIX); otherwise
	// it's fixed: RFC, every counted unit (v5 records, v9 packets).
	learn bool
	// timing and opts are the conventions in use, 0 while undecided (then
	// either explains a jump); tRun and oRun count telling messages in a
	// row for each side (index: convention - 1).
	timing, opts int
	tRun, oRun   [2]int
	// back is the run of messages behind the expected number, each
	// following the one before (backN of them).
	back   seqMsg
	backN  int
	recent [16]seqSeen
	ri     int
}

// mode is the learned timing for /api/flows: "rfc", "after", or "" while
// it's undecided (and for v5 and v9, which don't learn).
func (s *seqState) mode() string {
	switch s.timing {
	case seqRFC:
		return "rfc"
	case seqAfter:
		return "after"
	}
	return ""
}

// expect is the number m should carry after p under a convention, false
// when the counts it needs are unknown.
func expect(p, m seqMsg, timing, opts int) (uint32, bool) {
	if timing == seqRFC {
		return p.seq + p.count(opts), p.known
	}
	return p.seq + m.count(opts), m.known
}

// check records a message's sequence number. count is what it advances
// (records for v5, 1 packet for v9); known is false when some of the
// message's records couldn't be counted. It returns the gap (units lost
// before this message) and whether it's a duplicate.
func (s *seqState) check(seq, count uint32, known bool, at int64) (gap int64, dup bool) {
	return s.checkMsg(seqMsg{seq: seq, data: count, known: known}, at)
}

// checkMsg is check with the data and options record counts apart (IPFIX).
// A gap is counted only when no convention still in play explains the
// jump; once one is decided, only it does, so a real loss always shows.
func (s *seqState) checkMsg(m seqMsg, at int64) (gap int64, dup bool) {
	// A message without records (templates only) shares its number with the
	// next one under either convention: it's not a duplicate.
	if !m.known || m.data+m.opts > 0 {
		for _, r := range s.recent {
			if r.at != 0 && r.seq == m.seq && at-r.at <= dupWindow.Milliseconds() && at >= r.at {
				return 0, true
			}
		}
		s.recent[s.ri] = seqSeen{seq: m.seq, at: at}
		s.ri = (s.ri + 1) % len(s.recent)
	}
	if !s.valid {
		s.prev, s.valid, s.backN = m, true, 0
		return 0, false
	}
	timings, optses := []int{seqRFC}, []int{seqOptsCounted}
	if s.learn {
		timings, optses = []int{seqRFC, seqAfter}, []int{seqOptsCounted, seqOptsNot}
	}
	var explains [3][3]bool // [timing][opts]
	computed, zero, behind, restart := false, false, false, true
	var ahead int64 = -1
	for _, t := range timings {
		for _, o := range optses {
			e, ok := expect(s.prev, m, t, o)
			if !ok {
				continue
			}
			d := int32(m.seq - e)
			explains[t][o] = d == 0
			if (s.timing != 0 && t != s.timing) || (s.opts != 0 && o != s.opts) {
				continue // not in play
			}
			computed = true
			switch {
			case d == 0:
				zero = true
			case d > 0:
				if ahead < 0 || int64(d) < ahead {
					ahead = int64(d)
				}
			default:
				behind = true
			}
			restart = restart && d < -100000
		}
	}
	if s.learn && m.known && s.prev.known {
		s.vote(explains)
	}
	switch {
	case !computed: // the counts it needs are unknown: resync from here
	case zero:
	case restart: // a jump back of over 100,000: an exporter restart
	case behind:
		// Behind the expected number: a late message (don't move back), or,
		// after a run of them in sequence, an exporter restart.
		if s.backN > 0 && s.follows(s.back, m) {
			s.backN++
		} else {
			s.backN = 1
		}
		s.back = m
		if s.backN < seqRestartRun {
			if !m.known && s.timing != seqAfter {
				s.valid = false
			}
			return 0, false
		}
	default:
		gap = ahead
	}
	s.prev, s.backN = m, 0
	return gap, false
}

// follows reports whether m comes right after p under a convention in play.
func (s *seqState) follows(p, m seqMsg) bool {
	for _, t := range []int{seqRFC, seqAfter} {
		for _, o := range []int{seqOptsCounted, seqOptsNot} {
			if (!s.learn && (t != seqRFC || o != seqOptsCounted)) || (s.timing != 0 && t != s.timing) || (s.opts != 0 && o != s.opts) {
				continue
			}
			if e, ok := expect(p, m, t, o); ok && e == m.seq {
				return true
			}
		}
	}
	return false
}

// vote learns from one message whose counts and predecessor's are known: a
// side of a convention gets a vote when only it explains the number (among
// the other convention's sides in play). seqDecide votes in a row decide it,
// or change a decided one (an exporter replaced by another).
func (s *seqState) vote(ex [3][3]bool) {
	inPlay := func(cur, v int) bool { return cur == 0 || cur == v }
	var t, o [3]bool
	for _, ti := range []int{seqRFC, seqAfter} {
		for _, oi := range []int{seqOptsCounted, seqOptsNot} {
			if ex[ti][oi] && inPlay(s.opts, oi) {
				t[ti] = true
			}
			if ex[ti][oi] && inPlay(s.timing, ti) {
				o[oi] = true
			}
		}
	}
	tally := func(side [3]bool, run *[2]int, decided *int) {
		if side[1] == side[2] {
			return // both or neither: nothing learned
		}
		v := 1
		if side[2] {
			v = 2
		}
		run[v-1]++
		run[2-v] = 0
		if run[v-1] >= seqDecide {
			*decided = v
		}
	}
	tally(t, &s.tRun, &s.timing)
	tally(o, &s.oRun, &s.opts)
}

// --- the pending buffer ---

type pendKey struct {
	e   *exporter
	k   tkey
	tid uint16
}

type pendSet struct {
	key      pendKey
	hdr      hdrCtx
	header   []byte
	data     []byte
	received int64
	gone     bool
}

type pendingBuf struct {
	fifo  []*pendSet
	head  int
	byKey map[pendKey][]*pendSet
	bytes int
}

func (p *pendingBuf) init() { p.byKey = map[pendKey][]*pendSet{} }

func (p *pendingBuf) size(s *pendSet) int { return len(s.data) + len(s.header) + 128 }

func (p *pendingBuf) add(s *pendSet) {
	p.fifo = append(p.fifo, s)
	p.byKey[s.key] = append(p.byKey[s.key], s)
	n := p.size(s)
	p.bytes += n
	e := s.key.e
	e.pending.Add(int64(n))
	if e.pkeys == nil {
		e.pkeys = map[pendKey]struct{}{}
	}
	e.pkeys[s.key] = struct{}{}
	if o := e.pendOldest.Load(); o == 0 || s.received < o {
		e.pendOldest.Store(max(s.received, 1))
	}
}

// oldestOf recomputes an exporter's oldest pending received time.
func (p *pendingBuf) oldestOf(e *exporter) {
	var o int64
	for k := range e.pkeys {
		for _, x := range p.byKey[k] {
			if o == 0 || x.received < o {
				o = x.received
			}
		}
	}
	if o != 0 {
		o = max(o, 1)
	}
	e.pendOldest.Store(o)
}

func (p *pendingBuf) remove(s *pendSet) {
	if s.gone {
		return
	}
	s.gone = true
	n := p.size(s)
	p.bytes -= n
	s.key.e.pending.Add(-int64(n))
	l := p.byKey[s.key]
	for i, x := range l {
		if x == s {
			l = append(l[:i], l[i+1:]...)
			break
		}
	}
	if len(l) == 0 {
		delete(p.byKey, s.key)
		delete(s.key.e.pkeys, s.key)
	} else {
		p.byKey[s.key] = l
	}
	if e := s.key.e; max(s.received, 1) <= e.pendOldest.Load() || len(e.pkeys) == 0 {
		p.oldestOf(e)
	}
}

// take removes and returns the sets waiting for a template, oldest first.
func (p *pendingBuf) take(k pendKey) []*pendSet {
	l := p.byKey[k]
	if len(l) == 0 {
		return nil
	}
	out := slices.Clone(l)
	for _, s := range out {
		p.remove(s)
	}
	return out
}

// expired pops the sets received before cutoff.
func (p *pendingBuf) expired(cutoff int64, fn func(*pendSet)) {
	for p.head < len(p.fifo) {
		s := p.fifo[p.head]
		if !s.gone && s.received > cutoff {
			break
		}
		p.fifo[p.head] = nil
		p.head++
		if !s.gone {
			p.remove(s)
			fn(s)
		}
	}
	if p.head > 1024 && p.head*2 > len(p.fifo) {
		p.fifo = append(p.fifo[:0], p.fifo[p.head:]...)
		p.head = 0
	}
}

func (p *pendingBuf) dropExporter(e *exporter) {
	for k, l := range p.byKey {
		if k.e == e {
			for _, s := range slices.Clone(l) {
				p.remove(s)
			}
		}
	}
}

// --- stats ---

// DomainStats is one observation domain (or v9 source ID) of an exporter.
type DomainStats struct {
	ID       uint32 `json:"id"`
	Sampling uint32 `json:"sampling"`
	// SeqMode is how the domain numbers its messages, learned from its
	// stream (IPFIX): "rfc" (RFC 7011: the records before the message) or
	// "after" (the records up to and including it); "" while undecided.
	SeqMode      string    `json:"seq_mode,omitempty"`
	Templates    int       `json:"templates"`
	LastTemplate time.Time `json:"last_template"`
}

// ExporterStats is one exporter's state for GET /api/flows (records_per_sec
// is the caller's).
type ExporterStats struct {
	Addr         netip.Addr    `json:"-"`
	Domains      []DomainStats `json:"domains"`
	PendingBytes int64         `json:"pending_bytes"`
	// PendingOldest is the received time of the oldest data still waiting
	// for its template (zero when none), for the flow_templates banner.
	PendingOldest time.Time `json:"pending_oldest"`
	// OptionsRaw counts the options records kept raw (Options).
	OptionsRaw  int    `json:"options_raw"`
	Counts      Counts `json:"counts"`     // since the collector started
	Counts24h   Counts `json:"counts_24h"` // the last 24 hours (by hour)
	ClockSkewMs int64  `json:"clock_skew_ms"`
	TimeSource  string `json:"time_source"` // "exporter" or "received"
	// TimeOffsets24h and TimeOffsets1h count the records whose flow time was
	// far from when they arrived (TimeOffset), and the largest offsets, over
	// the last 24 hours (by hour) and the last hour (by 5 minutes).
	TimeOffsets24h TimeOffsets `json:"time_offsets_24h"`
	TimeOffsets1h  TimeOffsets `json:"time_offsets_1h"`
	LastHeard      time.Time   `json:"-"`
}

// Stats returns every exporter's state, by address.
func (c *Collector) Stats(now time.Time) []ExporterStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	nowH := now.UnixMilli() / 3600000
	out := make([]ExporterStats, 0, len(c.exporters))
	for _, e := range c.exporters {
		st := ExporterStats{Addr: e.addr, PendingBytes: e.pending.Load(), ClockSkewMs: e.skewMs.Load(),
			TimeSource: TimeExporter.String(), LastHeard: time.UnixMilli(e.lastHeard.Load()).UTC()}
		if e.skewed.Load() {
			st.TimeSource = TimeReceived.String()
		}
		if o := e.pendOldest.Load(); o > 0 && st.PendingBytes > 0 {
			st.PendingOldest = time.UnixMilli(o).UTC()
		}
		byID := map[uint32]*DomainStats{}
		for _, d := range e.domains {
			ds := byID[d.key.domain]
			if ds == nil {
				ds = &DomainStats{ID: d.key.domain}
				byID[d.key.domain] = ds
			}
			ds.Templates += len(d.templates)
			for _, h := range d.opts {
				st.OptionsRaw += len(h)
			}
			if d.lastTemplate > 0 && time.UnixMilli(d.lastTemplate).After(ds.LastTemplate) {
				ds.LastTemplate = time.UnixMilli(d.lastTemplate).UTC()
			}
			// A scope's own rate, else its samplers' highest. The scopes
			// of one ID (ports, versions: v5 is always domain 0) merge to
			// the highest, so the result doesn't depend on map order.
			r := d.sampling
			if r == 0 {
				for _, x := range d.samplers {
					r = max(r, x)
				}
			}
			ds.Sampling = max(ds.Sampling, r)
			// The scopes of one ID with different numberings: "after" wins
			// (the one a reader needs to know about), whatever the map order.
			if d.seqMode != "" && ds.SeqMode != "after" {
				ds.SeqMode = d.seqMode
			}
		}
		for _, ds := range byID {
			st.Domains = append(st.Domains, *ds)
		}
		slices.SortFunc(st.Domains, func(a, b DomainStats) int { return int(int64(a.ID) - int64(b.ID)) })
		e.cmu.Lock()
		st.Counts = e.counts
		for _, h := range e.hours {
			if h.hour > nowH-24 && h.hour <= nowH {
				st.Counts24h.add(h.c)
			}
		}
		if e.off != nil {
			st.TimeOffsets24h, st.TimeOffsets1h = e.off.sums(now.UnixMilli())
		}
		e.cmu.Unlock()
		out = append(out, st)
	}
	slices.SortFunc(out, func(a, b ExporterStats) int { return a.Addr.Compare(b.Addr) })
	return out
}

// TemplateField info for the template field list.
type FieldInfo struct {
	PEN    uint32 `json:"pen"`
	ID     uint16 `json:"id"`
	Name   string `json:"name"`
	Length uint16 `json:"length"` // 65535: variable
	Scope  bool   `json:"scope,omitempty"`
}

// TemplateInfo is one cached template of an exporter.
type TemplateInfo struct {
	Domain    uint32      `json:"domain"`
	Port      uint16      `json:"port"`
	Version   uint8       `json:"version"`
	ID        uint16      `json:"id"`
	Options   bool        `json:"options"`
	Fields    []FieldInfo `json:"fields"`
	Received  time.Time   `json:"received"`  // when this definition arrived
	Refreshed time.Time   `json:"refreshed"` // the latest copy
}

// Templates returns an exporter's cached templates (by domain, then ID).
func (c *Collector) Templates(addr netip.Addr) []TemplateInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e := c.exporters[addr.Unmap()]
	if e == nil {
		return nil
	}
	var out []TemplateInfo
	for _, d := range e.domains {
		for _, te := range d.templates {
			t := te.t
			ti := TemplateInfo{Domain: d.key.domain, Port: d.key.port, Version: d.key.version, ID: t.ID, Options: t.Options,
				Received: time.UnixMilli(t.Received).UTC(), Refreshed: time.UnixMilli(te.refreshed).UTC()}
			for i, f := range t.Fields {
				scope := t.Options && i < t.ScopeCount
				name := IEName(f.PEN, f.ID)
				if scope && t.Version == V9 {
					if n, ok := v9ScopeNames[f.ID]; ok {
						name = n
					}
				}
				ti.Fields = append(ti.Fields, FieldInfo{PEN: f.PEN, ID: f.ID, Name: name, Length: f.Length, Scope: scope})
			}
			out = append(out, ti)
		}
	}
	slices.SortFunc(out, func(a, b TemplateInfo) int {
		if a.Domain != b.Domain {
			return int(int64(a.Domain) - int64(b.Domain))
		}
		if a.Port != b.Port {
			return int(a.Port) - int(b.Port)
		}
		return int(a.ID) - int(b.ID)
	})
	return out
}

// PendingBytes is the buffer's total (data waiting for templates).
func (c *Collector) PendingBytes() int { return c.pend.bytes }
