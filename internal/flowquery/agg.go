package flowquery

import (
	"encoding/binary"
	"hash/maphash"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/gmccollu/woodshed/internal/flow"
)

// The top-N aggregation (SPEC §13.3, §13.10 decision 51). Memory is bounded
// whatever the input:
//
//   - Keys are counted exactly in one table shared by the workers, split in
//     shards by key hash, up to the exact limit (keys in all shards) and the
//     pool's bytes, both shared. Each worker combines repeated keys in a small
//     cache and hands keys to the shards in batches, so the shard locks are
//     cheap.
//   - A shard that can't take a new key (the limit or the pool reached) keeps
//     its exact keys exact and counts every new key in a fixed-size
//     space-saving table with a fixed-size count-min sketch beside it, so
//     memory stops growing. A newcomer to a full table replaces the lightest
//     entry only if its estimate (the lighter of the lightest entry and its
//     sketch count) beats it; that estimate becomes the row's possible
//     overestimate (Row.Err), so every approximate row is an upper bound with
//     a known error, and a key that isn't listed has at most the lightest
//     entry's count (ErrorBound).

// Pool is a byte budget for exact top-N tables and summary values, shared by
// every query that draws on it. Safe for concurrent use.
type Pool struct {
	cap  int64
	used atomic.Int64
	// full frees something (a saved query's state) and reports whether it did.
	full func() bool
}

// NewPool returns a pool of bytes.
func NewPool(bytes int64) *Pool { return &Pool{cap: bytes} }

// Used is the bytes reserved.
func (p *Pool) Used() int64 { return p.used.Load() }

func (p *Pool) reserve(n int64) bool {
	freed := 0
	for {
		u := p.used.Load()
		if u+n <= p.cap {
			if p.used.CompareAndSwap(u, u+n) {
				return true
			}
			continue
		}
		if p.full == nil || freed > MaxStates+MaxPageStates || !p.full() {
			return false
		}
		freed++
	}
}

func (p *Pool) release(n int64) {
	if n != 0 {
		p.used.Add(-n)
	}
}

// aggSize is an aggregation's fixed approximate structures.
type aggSize struct {
	shardBits  uint // 1<<shardBits shards
	ssPerShard int  // space-saving entries per shard
	cmsWidth   int  // sketch columns per shard (a power of two), cmsDepth rows
}

const cmsDepth = 4

var (
	// A query's: 16,384 space-saving entries and a 4 × 65,536 sketch in all
	// (about 5 MiB once every shard is approximate).
	querySize = aggSize{shardBits: 6, ssPerShard: 256, cmsWidth: 1024}
	// A bundle README's top 3s: 1,024 entries and a 4 × 4,096 sketch.
	smallSize = aggSize{shardBits: 3, ssPerShard: 128, cmsWidth: 512}
)

const (
	cacheSize = 1024 // a worker's combining cache (entries)
	batchSize = 32   // keys a worker hands a shard at a time
	chunkKeys = 256  // keys a shard reserves pool bytes for at a time
	slabChunk = 256  // Sums per allocation of a shard's exact values
)

// Key kinds: fixed-size, pointer-free (but rule and interface names), so a
// table costs its slots and the garbage collector doesn't scan it.
type (
	addrK struct {
		a  [16]byte
		v4 bool
	}
	pairK struct {
		a, b [16]byte
		v4   uint8 // 1: a is IPv4, 2: b is
	}
	numK uint64
	strK struct {
		n uint64
		s string
	}
)

func addrKOf(a netip.Addr) addrK { return addrK{a: a.As16(), v4: a.Is4()} }

func (k addrK) addr() netip.Addr {
	if k.v4 {
		return netip.AddrFrom4([4]byte(k.a[12:]))
	}
	return netip.AddrFrom16(k.a)
}

func addrOf16(a [16]byte, v4 bool) netip.Addr { return addrK{a: a, v4: v4}.addr() }

func mix(x uint64) uint64 {
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return x
}

func le(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

var strSeed = maphash.MakeSeed()

// kind is a key kind's functions.
type kind[K comparable] struct {
	of    func(r *flow.Record) (K, bool)
	hash  func(K) uint64
	key   func(K) key // the display key (keyLabel, appendKey)
	extra func(K) int64
}

func addrKind(get func(r *flow.Record) (netip.Addr, bool)) kind[addrK] {
	return kind[addrK]{
		of: func(r *flow.Record) (addrK, bool) {
			a, ok := get(r)
			return addrKOf(a), ok
		},
		hash: func(k addrK) uint64 {
			v := uint64(0)
			if k.v4 {
				v = 1
			}
			return mix(le(k.a[:8]) ^ mix(le(k.a[8:])^v))
		},
		key: func(k addrK) key { return key{a: k.addr()} },
	}
}

var pairKind = kind[pairK]{
	of: func(r *flow.Record) (pairK, bool) {
		k := keyOf("conversation", r)
		v := uint8(0)
		if k.a.Is4() {
			v |= 1
		}
		if k.b.Is4() {
			v |= 2
		}
		return pairK{a: k.a.As16(), b: k.b.As16(), v4: v}, k.ok
	},
	hash: func(k pairK) uint64 {
		return mix(le(k.a[:8]) ^ mix(le(k.a[8:])^mix(le(k.b[:8])^mix(le(k.b[8:])^uint64(k.v4)))))
	},
	key: func(k pairK) key { return key{a: addrOf16(k.a, k.v4&1 != 0), b: addrOf16(k.b, k.v4&2 != 0)} },
}

func numKind(by string) kind[numK] {
	return kind[numK]{
		of: func(r *flow.Record) (numK, bool) {
			k := keyOf(by, r)
			return numK(k.n), k.ok
		},
		hash: func(k numK) uint64 { return mix(uint64(k) + 0x9e3779b97f4a7c15) },
		key:  func(k numK) key { return key{n: uint64(k)} },
	}
}

func strKind(by string) kind[strK] {
	return kind[strK]{
		of: func(r *flow.Record) (strK, bool) {
			k := keyOf(by, r)
			return strK{n: k.n, s: k.s}, k.ok
		},
		hash:  func(k strK) uint64 { return mix(k.n ^ maphash.String(strSeed, k.s)) },
		key:   func(k strK) key { return key{n: k.n, s: k.s} },
		extra: func(k strK) int64 { return int64(len(k.s)) },
	}
}

// aggregator is a top-N aggregation of one key kind.
type aggregator interface {
	newLocal() local
	// rows are the top n with some of the metric, and how many keys have
	// none (never listed).
	rows(n int) ([]Row, int64)
	approx() bool
	errorBound() int64
	keys() int
	free()
}

// local is one goroutine's side of an aggregation; flush before reading.
type local interface {
	add(r *flow.Record)
	flush()
}

type aggOptions struct {
	maxKeys int
	pool    *Pool
	size    aggSize
}

func newAggregator(by, metric string, o aggOptions) aggregator {
	switch by {
	case "src":
		return newAgg(by, metric, o, addrKind(func(r *flow.Record) (netip.Addr, bool) { return r.Src, r.Is(flow.HasSrc) }))
	case "dst":
		return newAgg(by, metric, o, addrKind(func(r *flow.Record) (netip.Addr, bool) { return r.Dst, r.Is(flow.HasDst) }))
	case "post_nat_src":
		return newAgg(by, metric, o, addrKind(func(r *flow.Record) (netip.Addr, bool) { return r.PostNATSrc, r.Is(flow.HasPostNATSrc) }))
	case "post_nat_dst":
		return newAgg(by, metric, o, addrKind(func(r *flow.Record) (netip.Addr, bool) { return r.PostNATDst, r.Is(flow.HasPostNATDst) }))
	case "conversation":
		return newAgg(by, metric, o, pairKind)
	case "in_if", "out_if", "rule_id":
		return newAgg(by, metric, o, strKind(by))
	}
	return newAgg(by, metric, o, numKind(by))
}

type agg[K comparable] struct {
	by, metric string
	conv       bool
	k          kind[K]
	size       aggSize
	maxKeys    int64
	pool       *Pool
	perKey     int64 // pool bytes a key costs, beyond its name
	nkeys      atomic.Int64
	approxOn   atomic.Bool
	shards     []shard[K]
	freed      atomic.Bool
}

type shard[K comparable] struct {
	mu       sync.Mutex
	ents     [][]slabEnt[K] // the exact keys, in chunks of slabChunk
	n        int
	tab      htab  // key → index into ents
	resv     int64 // pool bytes reserved
	resvKeys int   // keys the reservation covers
	ss       *ssTable[K]
	_        [64]byte // keep shards' locks on separate cache lines
}

type slabEnt[K comparable] struct {
	k K
	s Sums
}

// keyCost is the pool bytes one exact key of kind K costs: its entry (the
// key and its Sums) and its 8-byte slot in the hash table at the table's
// worst load (7/16, just after a split). Checked against the heap in
// TestAggKeyCostCoversHeap: 131 bytes for a conversation, 115 for an
// address, 99 for a port.
func keyCost[K comparable]() int64 {
	return int64(unsafe.Sizeof(slabEnt[K]{})) + 8*tabSlots/(tabMax/2) + 2
}

func newAgg[K comparable](by, metric string, o aggOptions, k kind[K]) *agg[K] {
	a := &agg[K]{by: by, metric: metric, conv: by == "conversation", k: k, size: o.size, maxKeys: int64(o.maxKeys),
		pool: o.pool, perKey: keyCost[K]()}
	a.shards = make([]shard[K], 1<<o.size.shardBits)
	return a
}

func (a *agg[K]) shardOf(h uint64) int { return int(h >> (64 - a.size.shardBits)) }

func (a *agg[K]) approx() bool { return a.approxOn.Load() }

func (a *agg[K]) keys() int { return int(a.nkeys.Load()) }

// free releases the pool bytes; the aggregation is unusable after.
func (a *agg[K]) free() {
	if a.freed.Swap(true) {
		return
	}
	for i := range a.shards {
		sh := &a.shards[i]
		sh.mu.Lock()
		a.pool.release(sh.resv)
		sh.resv, sh.resvKeys, sh.ents, sh.n, sh.tab, sh.ss = 0, 0, nil, 0, htab{}, nil
		sh.mu.Unlock()
	}
}

func (sh *shard[K]) ent(i uint32) *slabEnt[K] { return &sh.ents[i/slabChunk][i%slabChunk] }

// The exact table's hash index: an extendible hash (a directory of
// fixed-size linear-probing tables, one split at a time, in place), so it
// grows without leaving old tables behind as garbage. A slot is the key's
// hash tag (32 bits) and its index into ents plus one (0: empty).
const (
	tabSlots    = 1024
	tabMax      = tabSlots * 7 / 8
	maxTabDepth = 20 // splits that don't separate keys stop here (the shard turns approximate)
)

type tab struct {
	local uint8
	n     int
	slot  [tabSlots]uint64
}

type htab struct {
	dir   []*tab
	depth uint8
}

func (a *agg[K]) tabOf(sh *shard[K], h uint64) *tab {
	return sh.tab.dir[(h<<a.size.shardBits)>>(64-uint64(sh.tab.depth))]
}

func tagOf(h uint64) uint64 { return uint64(uint32(h>>10)|1) << 32 }

// lookup finds k's Sums, or nil.
func (a *agg[K]) lookup(sh *shard[K], k K, h uint64) *Sums {
	if sh.tab.dir == nil {
		return nil
	}
	t, tag := a.tabOf(sh, h), tagOf(h)
	for p := h & (tabSlots - 1); ; p = (p + 1) & (tabSlots - 1) {
		v := t.slot[p]
		if v == 0 {
			return nil
		}
		if v&^0xffffffff == tag {
			if e := sh.ent(uint32(v) - 1); e.k == k {
				return &e.s
			}
		}
	}
}

func place(t *tab, h, v uint64) {
	p := h & (tabSlots - 1)
	for t.slot[p] != 0 {
		p = (p + 1) & (tabSlots - 1)
	}
	t.slot[p] = tagOf(h) | v&0xffffffff
	t.n++
}

// insert adds k (not present) with s; false if its table can't split
// further.
func (a *agg[K]) insert(sh *shard[K], k K, h uint64, s *Sums) bool {
	if sh.tab.dir == nil {
		sh.tab.dir = []*tab{{}}
	}
	t := a.tabOf(sh, h)
	for t.n >= tabMax {
		if t.local >= maxTabDepth {
			return false
		}
		a.split(sh, t)
		t = a.tabOf(sh, h)
	}
	if sh.n%slabChunk == 0 {
		sh.ents = append(sh.ents, make([]slabEnt[K], slabChunk))
	}
	i := uint32(sh.n)
	sh.n++
	*sh.ent(i) = slabEnt[K]{k: k, s: *s}
	place(t, h, uint64(i)+1)
	return true
}

// split moves the half of t's keys whose next hash bit is 1 to a new table.
func (a *agg[K]) split(sh *shard[K], t *tab) {
	ht := &sh.tab
	if t.local == ht.depth {
		nd := make([]*tab, 2*len(ht.dir))
		for i := range nd {
			nd[i] = ht.dir[i>>1]
		}
		ht.dir, ht.depth = nd, ht.depth+1
	}
	t.local++
	nt := &tab{local: t.local}
	for i, x := range ht.dir {
		if x == t && (i>>(ht.depth-t.local))&1 == 1 {
			ht.dir[i] = nt
		}
	}
	old := t.slot
	t.slot, t.n = [tabSlots]uint64{}, 0
	for _, v := range old {
		if v != 0 {
			h := a.k.hash(sh.ent(uint32(v) - 1).k)
			place(a.tabOf(sh, h), h, v)
		}
	}
}

// add counts one combined entry into its shard (locked).
func (a *agg[K]) addLocked(sh *shard[K], k K, h uint64, s *Sums) {
	if x := a.lookup(sh, k, h); x != nil {
		x.merge(s)
		return
	}
	// A shard that once couldn't take a key never takes another: a key the
	// approximate side has seen must stay there, or its exact count would
	// miss what came before.
	if sh.ss == nil {
		if a.admit(sh, k) {
			if a.insert(sh, k, h, s) {
				return
			}
			a.nkeys.Add(-1)
		}
		sh.ss = newSSTable[K](a.metric, a.size.ssPerShard, a.size.cmsWidth)
	}
	if sh.ss.add(k, h, s) {
		a.approxOn.Store(true)
	}
}

// admit reserves room for one more exact key in sh.
func (a *agg[K]) admit(sh *shard[K], k K) bool {
	if a.nkeys.Add(1) > a.maxKeys {
		a.nkeys.Add(-1)
		return false
	}
	var extra int64
	if a.k.extra != nil {
		extra = a.k.extra(k)
	}
	if sh.n >= sh.resvKeys || extra > 0 {
		need := extra
		if sh.n >= sh.resvKeys {
			need += chunkKeys * a.perKey
		}
		if !a.pool.reserve(need) {
			a.nkeys.Add(-1)
			return false
		}
		sh.resv += need
		if sh.n >= sh.resvKeys {
			sh.resvKeys += chunkKeys
		}
	}
	return true
}

func (a *agg[K]) errorBound() int64 {
	var b int64
	for i := range a.shards {
		sh := &a.shards[i]
		sh.mu.Lock()
		if sh.ss != nil && len(sh.ss.items) >= sh.ss.max {
			b = max(b, sh.ss.items[0].s.Metric(a.metric))
		}
		sh.mu.Unlock()
	}
	return b
}

// rows are the top n by the metric, ties by key, leaving out (and counting)
// the keys with none of it; labels are built only for rows that make it.
func (a *agg[K]) rows(n int) ([]Row, int64) {
	sel := topSel{metric: a.metric, n: n}
	var scratch []byte
	var zero int64
	consider := func(k K, s *Sums, err int64, approx bool) {
		m := s.Metric(a.metric)
		if m <= 0 {
			// A key with none of the metric isn't ranked by it (SPEC §13.3):
			// it's counted instead, so lists can say how many were left out.
			zero++
			return
		}
		if n <= 0 {
			return
		}
		if len(sel.h) >= n {
			w := sel.h[0]
			if m < w.m {
				return
			}
			if m == w.m {
				scratch = appendKey(scratch[:0], a.by, a.k.key(k))
				if string(scratch) >= w.key {
					return
				}
			}
		}
		dk := a.k.key(k)
		kk, l := keyLabel(a.by, dk)
		sel.push(selItem{m: m, key: kk, row: Row{Key: kk, Label: l, Sums: *s, Err: err, Approx: approx}})
	}
	for i := range a.shards {
		sh := &a.shards[i]
		sh.mu.Lock()
		for x := 0; x < sh.n; x++ {
			e := sh.ent(uint32(x))
			consider(e.k, &e.s, 0, false)
		}
		if sh.ss != nil {
			for _, it := range sh.ss.items {
				consider(it.k, &it.s, it.err, it.late)
			}
		}
		sh.mu.Unlock()
	}
	if len(sel.h) == 0 {
		return nil, zero
	}
	out := make([]Row, len(sel.h))
	for i, it := range sel.h {
		out[i] = it.row
	}
	sortRows(out, a.metric)
	return out, zero
}

func sortRows(rows []Row, metric string) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i].Metric(metric), rows[j].Metric(metric)
		if a != b {
			return a > b
		}
		return rows[i].Key < rows[j].Key
	})
}

// topSel keeps the best n: a heap with the worst (least metric, then
// greatest key) at its root.
type topSel struct {
	metric string
	n      int
	h      []selItem
}

type selItem struct {
	m   int64
	key string
	row Row
}

func worse(a, b *selItem) bool { return a.m < b.m || a.m == b.m && a.key > b.key }

func (t *topSel) push(it selItem) {
	if len(t.h) < t.n {
		t.h = append(t.h, it)
		for i := len(t.h) - 1; i > 0; {
			p := (i - 1) / 2
			if !worse(&t.h[i], &t.h[p]) {
				break
			}
			t.h[i], t.h[p] = t.h[p], t.h[i]
			i = p
		}
		return
	}
	t.h[0] = it
	for i := 0; ; {
		l, r, m := 2*i+1, 2*i+2, i
		if l < len(t.h) && worse(&t.h[l], &t.h[m]) {
			m = l
		}
		if r < len(t.h) && worse(&t.h[r], &t.h[m]) {
			m = r
		}
		if m == i {
			return
		}
		t.h[i], t.h[m] = t.h[m], t.h[i]
		i = m
	}
}

// appendKey appends keyLabel's key form without allocating.
func appendKey(dst []byte, by string, k key) []byte {
	switch by {
	case "src", "dst", "post_nat_src", "post_nat_dst":
		return k.a.AppendTo(dst)
	case "conversation":
		dst = k.a.AppendTo(dst)
		dst = append(dst, " ↔ "...)
		return k.b.AppendTo(dst)
	case "dst_port", "src_port":
		dst = append(dst, flow.ProtoName(uint8(k.n>>16))...)
		dst = append(dst, '/')
		return strconv.AppendUint(dst, k.n&0xffff, 10)
	case "proto", "in_if", "out_if":
		return strconv.AppendUint(dst, k.n, 10)
	case "fw_event":
		return append(dst, flow.FwEventName(uint8(k.n))...)
	case "rule_id":
		return append(dst, k.s...)
	}
	return dst
}

// ---- a worker's side ----

type centry[K comparable] struct {
	k    K
	h    uint64
	s    Sums
	used bool
}

type kvs[K comparable] struct {
	k K
	h uint64
	s Sums
}

type aggLocal[K comparable] struct {
	a     *agg[K]
	cache []centry[K]
	buf   [][]kvs[K]
}

func (a *agg[K]) newLocal() local {
	l := &aggLocal[K]{a: a, cache: make([]centry[K], cacheSize), buf: make([][]kvs[K], len(a.shards))}
	back := make([]kvs[K], len(a.shards)*batchSize)
	for i := range l.buf {
		l.buf[i] = back[i*batchSize : i*batchSize : (i+1)*batchSize]
	}
	return l
}

func (l *aggLocal[K]) add(r *flow.Record) {
	k, ok := l.a.k.of(r)
	if !ok {
		return
	}
	h := l.a.k.hash(k)
	c := &l.cache[h&(cacheSize-1)]
	if c.used && c.h == h && c.k == k {
		c.s.add(r, l.a.conv)
		return
	}
	if c.used {
		l.push(c.k, c.h, &c.s)
	}
	c.k, c.h, c.used = k, h, true
	c.s = Sums{}
	c.s.add(r, l.a.conv)
}

func (l *aggLocal[K]) push(k K, h uint64, s *Sums) {
	si := l.a.shardOf(h)
	b := append(l.buf[si], kvs[K]{k: k, h: h, s: *s})
	if len(b) == batchSize {
		l.apply(si, b)
		b = b[:0]
	}
	l.buf[si] = b
}

func (l *aggLocal[K]) apply(si int, b []kvs[K]) {
	sh := &l.a.shards[si]
	sh.mu.Lock()
	if !l.a.freed.Load() {
		for i := range b {
			l.a.addLocked(sh, b[i].k, b[i].h, &b[i].s)
		}
	}
	sh.mu.Unlock()
}

func (l *aggLocal[K]) flush() {
	for i := range l.cache {
		c := &l.cache[i]
		if c.used {
			l.push(c.k, c.h, &c.s)
			c.used = false
		}
	}
	for si, b := range l.buf {
		if len(b) > 0 {
			l.apply(si, b)
			l.buf[si] = b[:0]
		}
	}
}

// ---- space-saving with a count-min check ----

type ssItem[K comparable] struct {
	k   K
	h   uint64
	s   Sums
	err int64 // the ranked metric's possible overestimate
	// late: admitted once the table was full, so records before (some
	// uncounted: those adding nothing to the metric aren't sketched) may be
	// missing from its other counts. Never exact.
	late bool
	idx  int
}

type ssTable[K comparable] struct {
	metric string
	max    int
	items  []*ssItem[K] // a min-heap by the metric
	pos    map[K]*ssItem[K]
	cms    []int64 // cmsDepth rows of w
	w      int
}

func newSSTable[K comparable](metric string, max, w int) *ssTable[K] {
	return &ssTable[K]{metric: metric, max: max, pos: make(map[K]*ssItem[K], max), cms: make([]int64, cmsDepth*w), w: w}
}

func (t *ssTable[K]) m(i int) int64 { return t.items[i].s.Metric(t.metric) }

func (t *ssTable[K]) swap(i, j int) {
	t.items[i], t.items[j] = t.items[j], t.items[i]
	t.items[i].idx, t.items[j].idx = i, j
}

func (t *ssTable[K]) up(i int) {
	for i > 0 {
		p := (i - 1) / 2
		if t.m(p) <= t.m(i) {
			return
		}
		t.swap(i, p)
		i = p
	}
}

func (t *ssTable[K]) down(i int) {
	for {
		l, r, m := 2*i+1, 2*i+2, i
		if l < len(t.items) && t.m(l) < t.m(m) {
			m = l
		}
		if r < len(t.items) && t.m(r) < t.m(m) {
			m = r
		}
		if m == i {
			return
		}
		t.swap(i, m)
		i = m
	}
}

func (t *ssTable[K]) push(it *ssItem[K]) {
	it.idx = len(t.items)
	t.items = append(t.items, it)
	t.pos[it.k] = it
	t.up(it.idx)
}

func (t *ssTable[K]) cmsIdx(h uint64, row int) int {
	h2 := mix(h ^ 0x5851f42d4c957f2d)
	return row*t.w + int((h+uint64(row)*h2)&uint64(t.w-1))
}

func (t *ssTable[K]) cmsEst(h uint64) int64 {
	est := int64(-1)
	for r := 0; r < cmsDepth; r++ {
		if v := t.cms[t.cmsIdx(h, r)]; est < 0 || v < est {
			est = v
		}
	}
	return est
}

func (t *ssTable[K]) cmsAdd(h uint64, v int64) {
	if v == 0 {
		return
	}
	for r := 0; r < cmsDepth; r++ {
		t.cms[t.cmsIdx(h, r)] += v
	}
}

// add counts an entry; it reports whether the table is full (from then on
// a key may be left out or overestimated).
func (t *ssTable[K]) add(k K, h uint64, s *Sums) bool {
	v := s.Metric(t.metric)
	prev := t.cmsEst(h)
	t.cmsAdd(h, v)
	if it := t.pos[k]; it != nil {
		it.s.merge(s)
		t.down(it.idx)
		return len(t.items) >= t.max
	}
	if len(t.items) < t.max {
		// Not full: every key that came here is in it, exactly.
		t.push(&ssItem[K]{k: k, h: h, s: *s})
		return len(t.items) >= t.max
	}
	minIt := t.items[0]
	mc := minIt.s.Metric(t.metric)
	est := min(prev, mc) // an upper bound of k's earlier count
	if est+v <= mc {
		return true // it can't outrank the lightest; its count is in the sketch
	}
	delete(t.pos, minIt.k)
	minIt.k, minIt.h, minIt.s, minIt.err, minIt.late = k, h, *s, est, true
	minIt.s.addMetric(t.metric, est)
	t.pos[k] = minIt
	t.down(0)
	return true
}
