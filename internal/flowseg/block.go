package flowseg

import (
	"bytes"
	"compress/flate"
	"io"
	"math"
	"math/bits"
	"net/netip"
	"slices"
	"sync"

	"github.com/gmccollu/woodshed/internal/flow"
)

// MaxBlockRows is a block's row limit (SPEC §13.2).
const MaxBlockRows = 65536

// flateLevel is the columns' DEFLATE level: BestSpeed is a few percent larger
// than the default level and several times cheaper (bench_test.go).
const flateLevel = flate.BestSpeed

// Column directory flags.
const colDeflated = 1

// maxColumnRaw bounds one column's decoded size.
const maxColumnRaw = 256 << 20

// EffectiveTimes is a record's flow time as the segment indexes it (SPEC
// §13.2.1): end is End, else the event time, else the received time; start is
// Start, else end; a start after the end is the end. Queries match windows
// against [start, end].
func EffectiveTimes(r *flow.Record) (start, end int64) {
	switch {
	case r.Is(flow.HasEnd):
		end = r.End
	case r.Is(flow.HasEventTime):
		end = r.EventTime
	default:
		end = r.Received
	}
	start = end
	if r.Is(flow.HasStart) && r.Start < end {
		start = r.Start
	}
	return start, end
}

// Totals are counts over a block, a minute or a segment. Bytes and Packets
// follow the no-double-count rule (flow.Record.SumBytes); Scaled* multiply
// each record's by its sampling rate where it's known. UnknownSampling
// counts records with sampling 0, so ScaledComplete is UnknownSampling == 0.
type Totals struct {
	Records         int64
	Bytes           int64
	Packets         int64
	ScaledBytes     int64
	ScaledPackets   int64
	UnknownSampling int64
	// Status counts records by flow.Status (raw sets aren't records: see
	// Footer.Raw).
	Status [4]int64
}

// ScaledComplete reports whether every record's sampling rate was known.
func (t *Totals) ScaledComplete() bool { return t.UnknownSampling == 0 }

func (t *Totals) add(o *Totals) {
	t.Records = sat64(t.Records, o.Records)
	t.Bytes = sat64(t.Bytes, o.Bytes)
	t.Packets = sat64(t.Packets, o.Packets)
	t.ScaledBytes = sat64(t.ScaledBytes, o.ScaledBytes)
	t.ScaledPackets = sat64(t.ScaledPackets, o.ScaledPackets)
	t.UnknownSampling = sat64(t.UnknownSampling, o.UnknownSampling)
	for i := range t.Status {
		t.Status[i] = sat64(t.Status[i], o.Status[i])
	}
}

func sat64(a, b int64) int64 {
	if s := a + b; s >= a {
		return s
	}
	return math.MaxInt64
}

func appendTotals(b []byte, t *Totals) []byte {
	for _, v := range []int64{t.Records, t.Bytes, t.Packets, t.ScaledBytes, t.ScaledPackets, t.UnknownSampling} {
		b = putUvarint(b, uint64(v))
	}
	for _, v := range t.Status {
		b = putUvarint(b, uint64(v))
	}
	return b
}

func readTotals(d *dec) Totals {
	var t Totals
	for _, p := range []*int64{&t.Records, &t.Bytes, &t.Packets, &t.ScaledBytes, &t.ScaledPackets, &t.UnknownSampling} {
		*p = int64(d.limit(math.MaxInt64))
	}
	for i := range t.Status {
		t.Status[i] = int64(d.limit(math.MaxInt64))
	}
	return t
}

// Minute is one flow-time minute's counts (the flow_minute table, SPEC §13.2).
// A record counts once (Records, Status), in the minute holding its effective
// end; its bytes and packets (as summed: flow.Record.SumBytes) are spread
// evenly over the minutes its [start, end] covers, at most MaxSpreadMinutes (a
// longer flow's start is clamped), the remainder going to the last minute.
// Scaled values are the scaled total spread the same way. UnknownSampling
// counts the records with sampling 0 that count or spread into the minute, so
// a minute's scaled values are complete when it's 0.
type Minute struct {
	Minute int64 // unix ms of the minute's start
	Totals
}

// MaxSpreadMinutes caps how many minutes one record's counts spread over.
const MaxSpreadMinutes = 120

const minuteMs = 60000

func floorMinute(ms int64) int64 {
	m := ms / minuteMs
	if ms%minuteMs < 0 {
		m--
	}
	return m
}

// minuteAcc accumulates minutes keyed by minute number.
type minuteAcc map[int64]*Totals

func (m minuteAcc) at(k int64) *Totals {
	t := m[k]
	if t == nil {
		t = &Totals{}
		m[k] = t
	}
	return t
}

// addRecord spreads one record over its minutes.
func (m minuteAcc) addRecord(r *flow.Record) {
	start, end := EffectiveTimes(r)
	em := floorMinute(end)
	sm := floorMinute(start)
	if em-sm >= MaxSpreadMinutes {
		sm = em - MaxSpreadMinutes + 1
	}
	n := uint64(em - sm + 1)
	last := m.at(em)
	last.Records++
	if r.Sampling == 0 {
		last.UnknownSampling++
	}
	if int(r.Status) < len(last.Status) {
		last.Status[r.Status]++
	}
	b, p := r.SumBytes(), r.SumPackets()
	var sb, sp uint64
	if r.Sampling > 0 {
		sb, sp = satMul(b, uint64(r.Sampling)), satMul(p, uint64(r.Sampling))
	}
	if b == 0 && p == 0 {
		return
	}
	for k := sm; k <= em; k++ {
		t := last
		if k != em {
			t = m.at(k)
		}
		share := func(v uint64) int64 {
			q := v / n
			if k == em {
				q += v % n
			}
			return toI64(q)
		}
		t.Bytes = sat64(t.Bytes, share(b))
		t.Packets = sat64(t.Packets, share(p))
		t.ScaledBytes = sat64(t.ScaledBytes, share(sb))
		t.ScaledPackets = sat64(t.ScaledPackets, share(sp))
		if k != em && r.Sampling == 0 {
			// Unknown sampling also marks the minutes a record only spreads over.
			t.UnknownSampling++
		}
	}
}

// addRecordTotals adds one record to segment-style totals.
func addRecordTotals(t *Totals, r *flow.Record) {
	t.Records++
	if int(r.Status) < len(t.Status) {
		t.Status[r.Status]++
	}
	b, p := r.SumBytes(), r.SumPackets()
	t.Bytes = sat64(t.Bytes, toI64(b))
	t.Packets = sat64(t.Packets, toI64(p))
	if r.Sampling == 0 {
		t.UnknownSampling++
		return
	}
	t.ScaledBytes = sat64(t.ScaledBytes, toI64(satMul(b, uint64(r.Sampling))))
	t.ScaledPackets = sat64(t.ScaledPackets, toI64(satMul(p, uint64(r.Sampling))))
}

func (m minuteAcc) sorted() []Minute {
	out := make([]Minute, 0, len(m))
	for k, t := range m {
		out = append(out, Minute{Minute: k * minuteMs, Totals: *t})
	}
	slices.SortFunc(out, func(a, b Minute) int {
		switch {
		case a.Minute < b.Minute:
			return -1
		case a.Minute > b.Minute:
			return 1
		}
		return 0
	})
	return out
}

func (m minuteAcc) merge(ms []Minute) {
	for i := range ms {
		m.at(floorMinute(ms[i].Minute)).add(&ms[i].Totals)
	}
}

func appendMinutes(b []byte, ms []Minute) []byte {
	b = putUvarint(b, uint64(len(ms)))
	prev := int64(0)
	for i := range ms {
		k := ms[i].Minute / minuteMs
		b = putVarint(b, k-prev)
		prev = k
		b = appendTotals(b, &ms[i].Totals)
	}
	return b
}

func readMinutes(d *dec) []Minute {
	n := d.count(11)
	out := make([]Minute, 0, n)
	prev := int64(0)
	for i := 0; i < n && d.err == nil; i++ {
		k := prev + d.varint()
		prev = k
		if k > math.MaxInt64/minuteMs || k < math.MinInt64/minuteMs {
			d.fail()
			break
		}
		out = append(out, Minute{Minute: k * minuteMs, Totals: readTotals(d)})
	}
	return out
}

// ifSet is a block's distinct interfaces in one direction: a list up to
// maxIfList, else a Bloom filter.
type ifSet struct {
	list  []uint32
	bloom bloom
	any   bool // some record had the column
}

const maxIfList = 64

func (s *ifSet) has(i uint32) bool {
	if !s.any {
		return false
	}
	if s.bloom.k > 0 {
		return s.bloom.has(ifKey(i))
	}
	_, ok := slices.BinarySearch(s.list, i)
	return ok
}

func buildIfSet(vals map[uint32]struct{}) ifSet {
	if len(vals) == 0 {
		return ifSet{}
	}
	if len(vals) <= maxIfList {
		l := make([]uint32, 0, len(vals))
		for v := range vals {
			l = append(l, v)
		}
		slices.Sort(l)
		return ifSet{list: l, any: true}
	}
	f := newBloom(len(vals))
	for v := range vals {
		f.add(ifKey(v))
	}
	return ifSet{bloom: f, any: true}
}

func appendIfSet(b []byte, s *ifSet) []byte {
	switch {
	case !s.any:
		return append(b, 0)
	case s.bloom.k > 0:
		b = append(b, 2)
		return appendBloom(b, s.bloom)
	}
	b = append(b, 1)
	b = putUvarint(b, uint64(len(s.list)))
	for _, v := range s.list {
		b = putUvarint(b, uint64(v))
	}
	return b
}

func readIfSet(d *dec) ifSet {
	switch d.byte1() {
	case 0:
		return ifSet{}
	case 1:
		n := d.count(1)
		if n > maxIfList {
			d.fail()
			return ifSet{}
		}
		l := make([]uint32, 0, n)
		for i := 0; i < n; i++ {
			l = append(l, uint32(d.limit(math.MaxUint32)))
		}
		if !slices.IsSorted(l) {
			d.fail()
		}
		return ifSet{list: l, any: true}
	case 2:
		f := readBloom(d)
		if f.k == 0 {
			d.fail()
		}
		return ifSet{bloom: f, any: true}
	}
	d.fail()
	return ifSet{}
}

// BlockInfo is one block's directory entry and index (SPEC §13.2): its place
// in the file, row count, time ranges, stored columns, totals, minutes and
// the index a query skips it by. Readers fill the index fields; see
// Reader.Block.
type BlockInfo struct {
	Offset, Length int64 // the block's section, prefix included
	Rows           int
	MinReceived    int64
	MaxReceived    int64
	// Effective flow times (EffectiveTimes) of the block's records.
	MinStart, MaxStart int64
	MinEnd, MaxEnd     int64
	Columns            Cols // the columns stored (ColReceived and the rest always decode)
	Totals             Totals
	Samplings          []uint32 // distinct sampling rates, sorted (at most maxDistinct)
	Domains            []uint32 // distinct domains, sorted (at most maxDistinct)
	Minutes            []Minute

	protos [4]uint64
	inIfs  ifSet
	outIfs ifSet
	keys   bloom
	hdr    []byte // the encoded header (the footer repeats it)
	loaded bool   // the index fields above are set
}

// maxDistinct caps the sampling and domain lists a block or footer keeps.
const maxDistinct = 256

// HasProto reports whether a record of the block has protocol p.
func (b *BlockInfo) HasProto(p uint8) bool { return b.protos[p>>6]&(1<<(p&63)) != 0 }

// AnyProto reports whether any record of the block has a protocol.
func (b *BlockInfo) AnyProto() bool {
	return b.protos[0]|b.protos[1]|b.protos[2]|b.protos[3] != 0
}

// MayHaveAddr reports whether a record of the block may have a as its source,
// destination, or post-NAT source or destination (false means certainly not).
func (b *BlockInfo) MayHaveAddr(a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	return b.keys.has(addrKey(a))
}

// MayHavePrefix is MayHaveAddr for a prefix. Only prefixes of /24 or longer
// (IPv4) or /48 or longer (IPv6) can rule a block out; shorter ones return
// true.
func (b *BlockInfo) MayHavePrefix(p netip.Prefix) bool {
	if !p.IsValid() {
		return false
	}
	a := p.Addr().Unmap()
	nb := p.Bits()
	if p.Addr().Is4In6() {
		nb -= 96
	}
	full := 32
	need := 24
	if !a.Is4() {
		full, need = 128, 48
	}
	switch {
	case nb >= full:
		return b.MayHaveAddr(a)
	case nb >= need:
		m, err := a.Prefix(nb)
		if err != nil {
			return true
		}
		return b.keys.has(prefixKey(m.Addr()))
	}
	return true
}

// MayHavePort reports whether a record of the block may have port p (source,
// destination or post-NAT).
func (b *BlockInfo) MayHavePort(p uint16) bool { return b.keys.has(portKey(p)) }

// MayHaveInIf and MayHaveOutIf report whether a record of the block may have
// that input or output interface index.
func (b *BlockInfo) MayHaveInIf(i uint32) bool  { return b.inIfs.has(i) }
func (b *BlockInfo) MayHaveOutIf(i uint32) bool { return b.outIfs.has(i) }

// Overlaps reports whether a record of the block may overlap [from, to] in
// flow time (unix ms, inclusive).
func (b *BlockInfo) Overlaps(from, to int64) bool { return b.MinStart <= to && b.MaxEnd >= from }

// ---- the block header ----

// appendHeader writes the header fields shared by the block and the footer's
// copy (everything but the column directory).
func appendHeader(b []byte, bi *BlockInfo) []byte {
	b = putUvarint(b, uint64(bi.Rows))
	b = putVarint(b, bi.MinReceived)
	b = putUvarint(b, uint64(bi.MaxReceived-bi.MinReceived))
	b = putVarint(b, bi.MinStart)
	b = putUvarint(b, uint64(bi.MaxStart-bi.MinStart))
	b = putVarint(b, bi.MinEnd)
	b = putUvarint(b, uint64(bi.MaxEnd-bi.MinEnd))
	b = putUvarint(b, uint64(bi.Columns))
	b = appendTotals(b, &bi.Totals)
	b = appendU32s(b, bi.Samplings)
	b = appendU32s(b, bi.Domains)
	for _, w := range bi.protos {
		b = putU64(b, w)
	}
	b = appendIfSet(b, &bi.inIfs)
	b = appendIfSet(b, &bi.outIfs)
	b = appendBloom(b, bi.keys)
	return appendMinutes(b, bi.Minutes)
}

func appendU32s(b []byte, v []uint32) []byte {
	b = putUvarint(b, uint64(len(v)))
	for _, x := range v {
		b = putUvarint(b, uint64(x))
	}
	return b
}

func readU32s(d *dec) []uint32 {
	n := d.count(1)
	if n > maxDistinct {
		d.fail()
		return nil
	}
	out := make([]uint32, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, uint32(d.limit(math.MaxUint32)))
	}
	return out
}

// readHeader parses appendHeader's fields into bi (loaded).
func readHeader(d *dec, bi *BlockInfo) {
	bi.Rows = int(d.limit(MaxBlockRows))
	bi.MinReceived = d.varint()
	bi.MaxReceived = addSpan(d, bi.MinReceived)
	bi.MinStart = d.varint()
	bi.MaxStart = addSpan(d, bi.MinStart)
	bi.MinEnd = d.varint()
	bi.MaxEnd = addSpan(d, bi.MinEnd)
	bi.Columns = Cols(d.uvarint())
	bi.Totals = readTotals(d)
	bi.Samplings = readU32s(d)
	bi.Domains = readU32s(d)
	for i := range bi.protos {
		w := d.next(8)
		if w != nil {
			bi.protos[i] = uint64(w[0]) | uint64(w[1])<<8 | uint64(w[2])<<16 | uint64(w[3])<<24 |
				uint64(w[4])<<32 | uint64(w[5])<<40 | uint64(w[6])<<48 | uint64(w[7])<<56
		}
	}
	bi.inIfs = readIfSet(d)
	bi.outIfs = readIfSet(d)
	bi.keys = readBloom(d)
	bi.Minutes = readMinutes(d)
	if d.err == nil && (bi.Rows == 0 || bi.Totals.Records != int64(bi.Rows)) {
		d.fail()
	}
	bi.loaded = d.err == nil
}

func addSpan(d *dec, base int64) int64 {
	s := d.uvarint()
	if s > math.MaxInt64 || base > math.MaxInt64-int64(s) {
		d.fail()
		return base
	}
	return base + int64(s)
}

// ---- encoding a block ----

var flatePool = sync.Pool{New: func() any {
	w, _ := flate.NewWriter(nil, flateLevel)
	return w
}}

// encoder is the reusable state for encoding blocks (one per writer).
type encoder struct {
	dict     map[[16]byte]uint32
	dictList [][16]byte
	strs     map[string]uint32
	pres     []bool
	raw      []byte
	cols     []byte // stored payloads
	dir      []byte
	cbuf     bytes.Buffer
}

// colPayload compresses raw into e.cols and adds its directory entry.
func (e *encoder) colPayload(id int, raw []byte) {
	e.cbuf.Reset()
	fw := flatePool.Get().(*flate.Writer)
	fw.Reset(&e.cbuf)
	fw.Write(raw)
	fw.Close()
	flatePool.Put(fw)
	flags := byte(0)
	stored := raw
	if e.cbuf.Len() < len(raw) {
		flags = colDeflated
		stored = e.cbuf.Bytes()
	}
	e.dir = append(e.dir, byte(id), flags)
	e.dir = putUvarint(e.dir, uint64(len(raw)))
	e.dir = putUvarint(e.dir, uint64(len(stored)))
	e.cols = append(e.cols, stored...)
}

// rowMeta is a record's always-present column values, as the writer resolved
// them.
type rowMeta struct {
	tmpl uint32 // template table index + 1 (0: none)
}

// encodeBlock encodes rows as a block body (header, directory, payloads) and
// returns its info (index loaded) with hdr set.
func (e *encoder) encodeBlock(rows []flow.Record, meta []rowMeta) (body []byte, bi *BlockInfo) {
	bi = &BlockInfo{Rows: len(rows)}
	n := len(rows)
	keys := keySet{}
	inIfs, outIfs := map[uint32]struct{}{}, map[uint32]struct{}{}
	samp, doms := map[uint32]struct{}{}, map[uint32]struct{}{}
	mins := minuteAcc{}
	var has uint64
	for i := range rows {
		r := &rows[i]
		has |= r.Has
		s, en := EffectiveTimes(r)
		if i == 0 {
			bi.MinReceived, bi.MaxReceived = r.Received, r.Received
			bi.MinStart, bi.MaxStart, bi.MinEnd, bi.MaxEnd = s, s, en, en
		}
		bi.MinReceived, bi.MaxReceived = min(bi.MinReceived, r.Received), max(bi.MaxReceived, r.Received)
		bi.MinStart, bi.MaxStart = min(bi.MinStart, s), max(bi.MaxStart, s)
		bi.MinEnd, bi.MaxEnd = min(bi.MinEnd, en), max(bi.MaxEnd, en)
		if r.Is(flow.HasProto) {
			bi.protos[r.Proto>>6] |= 1 << (r.Proto & 63)
		}
		for _, c := range [...]struct {
			bit uint64
			a   netip.Addr
		}{{flow.HasSrc, r.Src}, {flow.HasDst, r.Dst}, {flow.HasPostNATSrc, r.PostNATSrc}, {flow.HasPostNATDst, r.PostNATDst}} {
			if r.Has&c.bit != 0 {
				keys.addAddr(c.a)
			}
		}
		for _, c := range [...]struct {
			bit uint64
			p   uint16
		}{{flow.HasSrcPort, r.SrcPort}, {flow.HasDstPort, r.DstPort}, {flow.HasPostNATSrcPort, r.PostNATSrcPort},
			{flow.HasPostNATDstPort, r.PostNATDstPort}} {
			if r.Has&c.bit != 0 {
				keys[portKey(c.p)] = struct{}{}
			}
		}
		if r.Is(flow.HasInIf) {
			inIfs[r.InIf] = struct{}{}
		}
		if r.Is(flow.HasOutIf) {
			outIfs[r.OutIf] = struct{}{}
		}
		if len(samp) < maxDistinct {
			samp[r.Sampling] = struct{}{}
		}
		if len(doms) < maxDistinct {
			doms[r.Domain] = struct{}{}
		}
		mins.addRecord(r)
		addRecordTotals(&bi.Totals, r)
	}
	bi.Samplings = sortedKeys(samp)
	bi.Domains = sortedKeys(doms)
	bi.inIfs, bi.outIfs = buildIfSet(inIfs), buildIfSet(outIfs)
	bi.keys = keys.bloom()
	bi.Minutes = mins.sorted()

	e.cols, e.dir = e.cols[:0], e.dir[:0]
	ncols := 0

	// The address dictionary, shared by every address column.
	clear(e.dict)
	if e.dict == nil {
		e.dict = map[[16]byte]uint32{}
	}
	e.dictList = e.dictList[:0]
	addrIdx := func(a netip.Addr) uint32 {
		k := a.Unmap().As16()
		if i, ok := e.dict[k]; ok {
			return i
		}
		i := uint32(len(e.dictList))
		e.dict[k] = i
		e.dictList = append(e.dictList, k)
		return i
	}
	addrCols := has & (flow.HasSrc | flow.HasDst | flow.HasNextHop | flow.HasPostNATSrc | flow.HasPostNATDst)
	var addrPayload [64][]byte
	for addrCols != 0 {
		id := bits.TrailingZeros64(addrCols)
		addrCols &^= 1 << id
		raw := e.presence(rows, uint64(1)<<id, nil)
		for i := range rows {
			if rows[i].Has&(1<<id) != 0 {
				raw = putUvarint(raw, uint64(addrIdx(addrOf(&rows[i], id))))
			}
		}
		addrPayload[id] = slices.Clone(raw)
	}
	if len(e.dictList) > 0 {
		raw := putUvarint(e.raw[:0], uint64(len(e.dictList)))
		for _, k := range e.dictList {
			raw = append(raw, k[:]...)
		}
		e.raw = raw
		e.colPayload(colDict, raw)
		ncols++
	}

	optional := has & uint64(ColOptional)
	for o := optional; o != 0; {
		id := bits.TrailingZeros64(o)
		o &^= 1 << id
		bit := uint64(1) << id
		var raw []byte
		switch kindOf[id] {
		case kindAddr:
			raw = addrPayload[id]
		case kindTime:
			raw = e.presence(rows, bit, nil)
			first := true
			var mn int64
			for i := range rows {
				if rows[i].Has&bit != 0 {
					v := timeOf(&rows[i], id)
					if first || v < mn {
						mn, first = v, false
					}
				}
			}
			raw = putVarint(raw, mn)
			for i := range rows {
				if rows[i].Has&bit != 0 {
					raw = putUvarint(raw, zigzag(timeOf(&rows[i], id)-mn))
				}
			}
		case kindUint:
			raw = e.presence(rows, bit, nil)
			for i := range rows {
				if rows[i].Has&bit != 0 {
					raw = putUvarint(raw, uintOf(&rows[i], id))
				}
			}
		case kindByte:
			raw = e.presence(rows, bit, nil)
			for i := range rows {
				if rows[i].Has&bit != 0 {
					raw = append(raw, byte(uintOf(&rows[i], id)))
				}
			}
		case kindString:
			raw = e.presence(rows, bit, nil)
			if e.strs == nil {
				e.strs = map[string]uint32{}
			}
			clear(e.strs)
			var list []string
			var idx []uint32
			for i := range rows {
				if rows[i].Has&bit != 0 {
					s := stringOf(&rows[i], id)
					j, ok := e.strs[s]
					if !ok {
						j = uint32(len(list))
						e.strs[s] = j
						list = append(list, s)
					}
					idx = append(idx, j)
				}
			}
			raw = putUvarint(raw, uint64(len(list)))
			for _, s := range list {
				raw = putBytes(raw, []byte(s))
			}
			for _, j := range idx {
				raw = putUvarint(raw, uint64(j))
			}
		case kindFlag:
			raw = e.presence(rows, bit, nil)
		}
		e.raw = raw
		e.colPayload(id, raw)
		ncols++
	}

	// Received: always stored.
	{
		raw := putVarint(e.raw[:0], bi.MinReceived)
		for i := range rows {
			raw = putUvarint(raw, zigzag(rows[i].Received-bi.MinReceived))
		}
		e.raw = raw
		e.colPayload(bitID(ColReceived), raw)
		ncols++
	}
	// The run-length columns, left out when every row is zero.
	rle := func(c Cols, width int, val func(i int) [3]uint64) {
		raw := e.raw[:0]
		nz := false
		for i := 0; i < n; {
			v := val(i)
			j := i + 1
			for j < n && val(j) == v {
				j++
			}
			nz = nz || v != [3]uint64{}
			raw = putUvarint(raw, uint64(j-i))
			for _, x := range v[:width] {
				raw = putUvarint(raw, x)
			}
			i = j
		}
		e.raw = raw
		if nz {
			e.colPayload(bitID(c), raw)
			ncols++
		}
	}
	rle(ColSampling, 1, func(i int) [3]uint64 { return [3]uint64{uint64(rows[i].Sampling)} })
	rle(ColDomain, 3, func(i int) [3]uint64 {
		return [3]uint64{uint64(rows[i].Version), uint64(rows[i].ExporterPort), uint64(rows[i].Domain)}
	})
	rle(ColTemplate, 2, func(i int) [3]uint64 { return [3]uint64{uint64(meta[i].tmpl), uint64(rows[i].TemplateID)} })
	rle(ColStatus, 1, func(i int) [3]uint64 { return [3]uint64{uint64(rows[i].Status)} })
	rle(ColTimeSource, 1, func(i int) [3]uint64 { return [3]uint64{uint64(rows[i].TimeSource)} })
	// Extras: a TLV list per record that has any.
	{
		raw := e.raw[:0]
		e.pres = e.pres[:0]
		anyX := false
		for i := range rows {
			x := len(rows[i].Extras) > 0
			e.pres = append(e.pres, x)
			anyX = anyX || x
		}
		if anyX {
			raw = appendPresence(raw, e.pres)
			for i := range rows {
				if xs := rows[i].Extras; len(xs) > 0 {
					raw = putUvarint(raw, uint64(len(xs)))
					for _, x := range xs {
						raw = putUvarint(raw, uint64(x.PEN))
						raw = putUvarint(raw, uint64(x.ID))
						raw = putBytes(raw, x.Value)
					}
				}
			}
			e.raw = raw
			e.colPayload(bitID(ColExtras), raw)
			ncols++
			has |= uint64(ColExtras)
		}
	}
	bi.Columns = Cols(has&uint64(ColOptional)) | ColReceived | ColSampling | ColDomain | ColMeta | ColTemplate |
		ColStatus | ColTimeSource | ColExtras&Cols(has)

	hdr := appendHeader(nil, bi)
	dirHdr := putUvarint(nil, uint64(ncols))
	dirHdr = append(dirHdr, e.dir...)
	body = putUvarint(make([]byte, 0, 10+len(hdr)+len(dirHdr)+len(e.cols)), uint64(len(hdr)))
	body = append(body, hdr...)
	body = append(body, dirHdr...)
	body = append(body, e.cols...)
	bi.hdr = hdr
	bi.loaded = true
	return body, bi
}

// presence appends the presence bitmap of bit over rows to e.raw (reset) and
// returns it.
func (e *encoder) presence(rows []flow.Record, bit uint64, _ []byte) []byte {
	e.pres = e.pres[:0]
	for i := range rows {
		e.pres = append(e.pres, rows[i].Has&bit != 0)
	}
	e.raw = appendPresence(e.raw[:0], e.pres)
	return e.raw
}

func bitID(c Cols) int { return bits.TrailingZeros64(uint64(c)) }

func sortedKeys(m map[uint32]struct{}) []uint32 {
	out := make([]uint32, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func addrOf(r *flow.Record, id int) netip.Addr {
	switch uint64(1) << id {
	case flow.HasSrc:
		return r.Src
	case flow.HasDst:
		return r.Dst
	case flow.HasNextHop:
		return r.NextHop
	case flow.HasPostNATSrc:
		return r.PostNATSrc
	}
	return r.PostNATDst
}

func setAddr(r *flow.Record, id int, a netip.Addr) {
	switch uint64(1) << id {
	case flow.HasSrc:
		r.Src = a
	case flow.HasDst:
		r.Dst = a
	case flow.HasNextHop:
		r.NextHop = a
	case flow.HasPostNATSrc:
		r.PostNATSrc = a
	default:
		r.PostNATDst = a
	}
}

// ---- decoding a block ----

var inflatePool sync.Pool

func inflate(stored []byte, rawLen int, out []byte) ([]byte, error) {
	var fr io.ReadCloser
	if v := inflatePool.Get(); v != nil {
		fr = v.(io.ReadCloser)
		fr.(flate.Resetter).Reset(bytes.NewReader(stored), nil)
	} else {
		fr = flate.NewReader(bytes.NewReader(stored))
	}
	defer inflatePool.Put(fr)
	if cap(out) < rawLen {
		out = make([]byte, rawLen)
	}
	out = out[:rawLen]
	if _, err := io.ReadFull(fr, out); err != nil {
		return nil, errCorrupt
	}
	return out, nil
}
