package flow

import (
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// Decode decodes one datagram (any version, on any port: the header's
// version field says which). emit gets each decoded record; it must not keep
// r itself after it returns (copy the struct; r.Extras and r.Template may be
// kept). raw gets each set or packet stored undecoded (SPEC §13.1.3); its Data
// and Header are the collector's own copies. Data that arrives before its
// template waits in the pending buffer and comes out later, through the emit
// of the Decode (or raw of the Expire) that resolves it.
func (c *Collector) Decode(p Packet, emit func(*Record), raw func(*RawSet)) {
	now := p.Received.UnixMilli()
	c.expireAt(now, raw)
	addr := p.From.Addr().Unmap()
	e := c.exporterFor(addr, now)
	ds := decState{c: c, e: e, port: p.From.Port(), received: now, emit: emit, raw: raw}
	b := p.Data
	if len(b) < 2 {
		ds.malformed(b, 0, nil, 0)
		ds.flush()
		return
	}
	switch v := binary.BigEndian.Uint16(b); v {
	case V5:
		ds.v5(b)
	case V9:
		ds.v9(b)
	case IPFIX:
		ds.ipfix(b)
	default:
		ds.malformed(b, uint8(min(v, 255)), nil, 0)
	}
	ds.flush()
}

// Expire moves data that has waited for its template longer than the
// template timeout out of the pending buffer, as raw sets (no_template).
func (c *Collector) Expire(now time.Time, raw func(*RawSet)) { c.expireAt(now.UnixMilli(), raw) }

func (c *Collector) expireAt(now int64, raw func(*RawSet)) {
	if c.pend.head >= len(c.pend.fifo) {
		return
	}
	cutoff := now - c.set.Load().timeout.Milliseconds()
	c.pend.expired(cutoff, func(s *pendSet) {
		rs := &RawSet{Received: s.received, Exporter: s.key.e.addr, ExporterPort: s.key.k.port, Domain: s.key.k.domain, Version: s.key.k.version,
			TemplateID: s.key.tid, Status: StatusNoTemplate, Header: s.header, Data: s.data}
		s.key.e.count(now, Counts{NoTemplate: 1})
		if raw != nil {
			raw(rs)
		}
	})
}

// decState is one datagram's decode.
type decState struct {
	c        *Collector
	e        *exporter
	port     uint16
	received int64
	emit     func(*Record)
	raw      func(*RawSet)
	counts   Counts
	off      TimeOffsets // records whose flow time is far from their arrival (timeoff.go)
}

func (ds *decState) flush() {
	if ds.counts != (Counts{}) {
		ds.e.count(ds.received, ds.counts)
	}
	if ds.off.Any() {
		ds.e.countOff(ds.received, ds.off)
	}
}

func clone(b []byte) []byte { return append([]byte(nil), b...) }

// malformed stores a packet (or set) raw as malformed.
func (ds *decState) malformed(data []byte, version uint8, header []byte, domain uint32) {
	ds.counts.Malformed++
	if ds.raw != nil {
		ds.raw(&RawSet{Received: ds.received, Exporter: ds.e.addr, ExporterPort: ds.port, Domain: domain, Version: version,
			Status: StatusMalformed, Header: clone(header), Data: clone(data)})
	}
}

// clock records the exporter's clock offset and reports whether it's more
// than ClockSkewLimit off.
func (ds *decState) clock(exportMs int64) bool {
	if ds.c.fileMode {
		return false
	}
	skew := ds.received - exportMs
	ds.e.skewMs.Store(skew)
	off := skew > ClockSkewLimit.Milliseconds() || -skew > ClockSkewLimit.Milliseconds()
	ds.e.skewed.Store(off)
	return off
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// ---- flow v5 ----

const (
	v5Header = 24
	v5Record = 48
)

func (ds *decState) v5(b []byte) {
	if len(b) < v5Header {
		ds.malformed(b, V5, nil, 0)
		return
	}
	count := int(binary.BigEndian.Uint16(b[2:]))
	up := binary.BigEndian.Uint32(b[4:])
	secs := binary.BigEndian.Uint32(b[8:])
	nsecs := binary.BigEndian.Uint32(b[12:])
	seq := binary.BigEndian.Uint32(b[16:])
	engType, engID := b[20], b[21]
	samp := binary.BigEndian.Uint16(b[22:])
	exportMs := int64(secs)*1000 + int64(nsecs/1e6)
	skewed := ds.clock(exportMs)
	// The header's 14-bit interval (the top 2 bits are the mode): 0 and 1
	// both mean every packet (decided (build, 2026-11-16)).
	rate := uint32(samp & 0x3fff)
	if rate == 0 {
		rate = 1
	}
	fit := (len(b) - v5Header) / v5Record
	n := min(count, fit)
	k := tkey{port: ds.port, version: V5}
	d := ds.c.domainFor(ds.e, k)
	// The domain reports the header's rate, as its records carry it
	// (/api/flows, woodshed flow status). Only Decode's goroutine writes it.
	if d.sampling != rate {
		ds.c.mu.Lock()
		d.sampling = rate
		ds.c.mu.Unlock()
		ds.e.metaVer.Add(1)
	}
	if gap, dup := d.seq.check(seq, uint32(count), n == count, ds.received); dup {
		ds.counts.Duplicates++
	} else if gap > 0 {
		ds.counts.SequenceGaps++
		ds.counts.LostEstimate += gap
	}
	r := &ds.c.scratch
	for i := 0; i < n; i++ {
		x := b[v5Header+i*v5Record:]
		*r = Record{
			Has: HasSrc | HasDst | HasNextHop | HasInIf | HasOutIf | HasPackets | HasBytes | HasStart | HasEnd |
				HasSrcPort | HasDstPort | HasTCPFlags | HasProto | HasToS | HasSrcAS | HasDstAS,
			Received: ds.received,
			Src:      addrOf(x[0:4]), Dst: addrOf(x[4:8]), NextHop: addrOf(x[8:12]),
			InIf: uint32(binary.BigEndian.Uint16(x[12:])), OutIf: uint32(binary.BigEndian.Uint16(x[14:])),
			Packets: uint64(binary.BigEndian.Uint32(x[16:])), Bytes: uint64(binary.BigEndian.Uint32(x[20:])),
			SrcPort: binary.BigEndian.Uint16(x[32:]), DstPort: binary.BigEndian.Uint16(x[34:]),
			TCPFlags: uint16(x[37]), Proto: x[38], ToS: x[39],
			SrcAS: uint32(binary.BigEndian.Uint16(x[40:])), DstAS: uint32(binary.BigEndian.Uint16(x[42:])),
			Sampling: rate, ExporterPort: ds.port, Version: V5,
		}
		first := binary.BigEndian.Uint32(x[24:])
		last := binary.BigEndian.Uint32(x[28:])
		r.Start = exportMs - int64(int32(up-first))
		r.End = exportMs - int64(int32(up-last))
		if r.End < r.Start {
			r.Start, r.End = r.End, r.Start
		}
		// The header's engine fields and the prefix lengths have no column.
		ex := make([]Extra, 0, 4)
		vals := make([]byte, 4)
		vals[0], vals[1], vals[2], vals[3] = engType, engID, x[44], x[45]
		ex = append(ex, Extra{ID: ieEngineType, Value: vals[0:1:1]}, Extra{ID: ieEngineID, Value: vals[1:2:2]})
		if x[44] != 0 {
			ex = append(ex, Extra{ID: ieSrcMaskV4, Value: vals[2:3:3]})
		}
		if x[45] != 0 {
			ex = append(ex, Extra{ID: ieDstMaskV4, Value: vals[3:4:4]})
		}
		r.Extras = ex
		ds.e.nameIfs(r, 0, false)
		if skewed {
			skewToReceived(r, ds.received)
		}
		ds.checkTime(r)
		ds.counts.Records++
		if ds.emit != nil {
			ds.emit(r)
		}
	}
	if count > fit {
		ds.malformed(b, V5, b[:v5Header], 0)
	}
}

// nameIfs fills a record's interface names from the exporter's options data.
func (e *exporter) nameIfs(r *Record, domain uint32, exact bool) {
	if len(e.ifNames) == 0 {
		return
	}
	if r.Is(HasInIf) {
		if n, ok := e.ifName(domain, r.InIf, exact); ok {
			r.InIfName, r.Has = n, r.Has|HasInIfName
		}
	}
	if r.Is(HasOutIf) {
		if n, ok := e.ifName(domain, r.OutIf, exact); ok {
			r.OutIfName, r.Has = n, r.Has|HasOutIfName
		}
	}
}

// ---- flow v9 and IPFIX ----

const (
	v9Header    = 20
	ipfixHeader = 16
)

// msg is one v9 or IPFIX message being decoded.
type msg struct {
	version  uint8
	domain   uint32
	header   []byte
	hdr      hdrCtx
	k        tkey
	d        *domainState
	records  int  // data records decoded (and options data records)
	unknown  bool // a data set waited or went raw: the record count is unknown
	brokeOff bool
}

func (ds *decState) v9(b []byte) {
	if len(b) < v9Header {
		ds.malformed(b, V9, nil, 0)
		return
	}
	up := binary.BigEndian.Uint32(b[4:])
	secs := binary.BigEndian.Uint32(b[8:])
	seq := binary.BigEndian.Uint32(b[12:])
	src := binary.BigEndian.Uint32(b[16:])
	m := &msg{version: V9, domain: src, header: b[:v9Header]}
	m.hdr = hdrCtx{exportMs: int64(secs) * 1000, uptimeMs: int64(up), received: ds.received}
	m.hdr.skewed = ds.clock(m.hdr.exportMs)
	m.k = tkey{port: ds.port, domain: src, version: V9}
	m.d = ds.c.domainFor(ds.e, m.k)
	ds.sets(m, b[v9Header:], b)
	if gap, dup := m.d.seq.check(seq, 1, true, ds.received); dup {
		ds.counts.Duplicates++
	} else if gap > 0 {
		ds.counts.SequenceGaps++
		avg := m.d.avgPerPkt
		if avg < 1 {
			avg = 1
		}
		ds.counts.LostEstimate += int64(float64(gap)*avg + 0.5)
	}
	if !m.unknown && m.records > 0 {
		if m.d.avgPerPkt == 0 {
			m.d.avgPerPkt = float64(m.records)
		} else {
			m.d.avgPerPkt = 0.9*m.d.avgPerPkt + 0.1*float64(m.records)
		}
	}
}

func (ds *decState) ipfix(b []byte) {
	if len(b) < ipfixHeader {
		ds.malformed(b, IPFIX, nil, 0)
		return
	}
	ln := int(binary.BigEndian.Uint16(b[2:]))
	secs := binary.BigEndian.Uint32(b[4:])
	seq := binary.BigEndian.Uint32(b[8:])
	dom := binary.BigEndian.Uint32(b[12:])
	if ln < ipfixHeader {
		ds.malformed(b, IPFIX, b[:ipfixHeader], dom)
		return
	}
	short := ln > len(b)
	if !short {
		b = b[:ln]
	}
	m := &msg{version: IPFIX, domain: dom, header: b[:ipfixHeader]}
	m.hdr = hdrCtx{exportMs: int64(secs) * 1000, uptimeMs: -1, received: ds.received}
	m.hdr.skewed = ds.clock(m.hdr.exportMs)
	m.k = tkey{port: ds.port, domain: dom, version: IPFIX}
	m.d = ds.c.domainFor(ds.e, m.k)
	m.hdr.sysInitMs = m.d.sysInitMs
	ds.sets(m, b[ipfixHeader:], b)
	if short && !m.brokeOff {
		ds.malformed(b, IPFIX, m.header, dom)
		m.unknown = true
	}
	if gap, dup := m.d.seq.check(seq, uint32(m.records), !m.unknown, ds.received); dup {
		ds.counts.Duplicates++
	} else if gap > 0 {
		ds.counts.SequenceGaps++
		ds.counts.LostEstimate += gap
	}
}

// sets walks a message's sets (flowsets). pkt is the whole packet, stored raw
// if the message breaks.
func (ds *decState) sets(m *msg, b, pkt []byte) {
	for len(b) > 0 {
		if len(b) < 4 {
			if !allZero(b) {
				ds.breakOff(m, pkt)
			}
			return
		}
		id := binary.BigEndian.Uint16(b)
		ln := int(binary.BigEndian.Uint16(b[2:]))
		if ln < 4 || ln > len(b) {
			if ln == 0 && allZero(b) {
				return // trailing padding
			}
			ds.breakOff(m, pkt)
			return
		}
		body := b[4:ln]
		b = b[ln:]
		var ok bool
		switch {
		case m.version == V9 && id == 0, m.version == IPFIX && id == 2:
			ok = ds.templates(m, body, false)
		case m.version == V9 && id == 1, m.version == IPFIX && id == 3:
			ok = ds.templates(m, body, true)
		case id < 256:
			ok = true // reserved set IDs are skipped
		default:
			ok = ds.dataSet(m, id, body)
		}
		if !ok {
			ds.breakOff(m, pkt)
			return
		}
	}
}

func (ds *decState) breakOff(m *msg, pkt []byte) {
	m.brokeOff, m.unknown = true, true
	ds.malformed(pkt, m.version, m.header, m.domain)
}

var errTemplate = errors.New("malformed template")

// templates reads a template or options template set; false if it's
// malformed (templates read before the break are kept).
func (ds *decState) templates(m *msg, b []byte, options bool) bool {
	for {
		if len(b) < 4 || allZero(b) {
			return len(b) == 0 || allZero(b)
		}
		tid := binary.BigEndian.Uint16(b)
		var t *Template
		var n int
		var err error
		if m.version == V9 {
			if options && len(b) < 6 {
				return false
			}
			t, n, err = parseV9Template(b, options)
		} else {
			if binary.BigEndian.Uint16(b[2:]) == 0 {
				// Withdrawal (RFC 7011 §8.1): one template, or with the set's
				// own ID (2 or 3) every template of that kind.
				ds.c.withdraw(m.d, tid, tid == 2 || tid == 3, options)
				b = b[4:]
				continue
			}
			if options && len(b) < 6 {
				return false
			}
			t, n, err = parseIPFIXTemplate(b, options)
		}
		if err != nil {
			return false
		}
		b = b[n:]
		t.Version, t.ExporterPort, t.Domain, t.Received = m.version, ds.port, m.domain, ds.received
		te := ds.c.addTemplate(ds.e, m.d, t, ds.received)
		// Data that arrived before this template.
		for _, s := range ds.c.pend.take(pendKey{ds.e, m.k, tid}) {
			s.hdr.sysInitMs = m.d.sysInitMs
			sm := &msg{version: m.version, domain: m.domain, header: s.header, hdr: s.hdr, k: m.k, d: m.d}
			ds.decodeSet(sm, te, s.data, StatusLate, s.received)
		}
	}
}

func parseV9Template(b []byte, options bool) (*Template, int, error) {
	t := &Template{ID: binary.BigEndian.Uint16(b), Options: options}
	var nf, ns, pos int
	if options {
		scopeLen := int(binary.BigEndian.Uint16(b[2:]))
		optLen := int(binary.BigEndian.Uint16(b[4:]))
		if scopeLen%4 != 0 || optLen%4 != 0 || scopeLen == 0 {
			return nil, 0, errTemplate
		}
		ns, nf, pos = scopeLen/4, (scopeLen+optLen)/4, 6
	} else {
		nf, pos = int(binary.BigEndian.Uint16(b[2:])), 4
	}
	if t.ID < 256 || nf == 0 || nf > MaxTemplateFields || len(b) < pos+4*nf {
		return nil, 0, errTemplate
	}
	t.ScopeCount = ns
	t.Fields = make([]TemplateField, nf)
	total := 0
	for i := range nf {
		f := TemplateField{ID: binary.BigEndian.Uint16(b[pos:]), Length: binary.BigEndian.Uint16(b[pos+2:])}
		if f.Length == 0 || f.Length == Varlen {
			return nil, 0, errTemplate
		}
		total += int(f.Length)
		t.Fields[i] = f
		pos += 4
	}
	if total > 65535 {
		return nil, 0, errTemplate
	}
	return t, pos, nil
}

func parseIPFIXTemplate(b []byte, options bool) (*Template, int, error) {
	t := &Template{ID: binary.BigEndian.Uint16(b), Options: options}
	nf := int(binary.BigEndian.Uint16(b[2:]))
	pos := 4
	if options {
		t.ScopeCount = int(binary.BigEndian.Uint16(b[4:]))
		pos = 6
		if t.ScopeCount == 0 || t.ScopeCount > nf {
			return nil, 0, errTemplate
		}
	}
	if t.ID < 256 || nf > MaxTemplateFields {
		return nil, 0, errTemplate
	}
	t.Fields = make([]TemplateField, nf)
	total := 0
	for i := range nf {
		if len(b) < pos+4 {
			return nil, 0, errTemplate
		}
		id := binary.BigEndian.Uint16(b[pos:])
		f := TemplateField{ID: id & 0x7fff, Length: binary.BigEndian.Uint16(b[pos+2:])}
		pos += 4
		if id&0x8000 != 0 {
			if len(b) < pos+4 {
				return nil, 0, errTemplate
			}
			f.PEN = binary.BigEndian.Uint32(b[pos:])
			pos += 4
			if f.PEN == VendorRangePEN {
				f.ID = id // a v9 vendor-range type, as the export file writes them (VendorRangePEN)
			}
		}
		if f.Length == 0 {
			return nil, 0, errTemplate
		}
		if f.Length == Varlen {
			total++
		} else {
			total += int(f.Length)
		}
		t.Fields[i] = f
	}
	if total > 65535 {
		return nil, 0, errTemplate
	}
	return t, pos, nil
}

// dataSet decodes a data set, or parks it until its template arrives (or
// stores it raw when the buffer has no room). False when it's malformed.
func (ds *decState) dataSet(m *msg, tid uint16, body []byte) bool {
	te := ds.c.lookup(m.d, tid, ds.received)
	if te == nil {
		m.unknown = true
		c := ds.c
		s := &pendSet{key: pendKey{ds.e, m.k, tid}, hdr: m.hdr, header: clone(m.header), data: clone(body), received: ds.received}
		n := c.pend.size(s)
		if c.pend.bytes+n > c.opts.PendingBytes || int(ds.e.pending.Load())+n > c.opts.PendingPerExporter {
			ds.counts.NoTemplate++
			if ds.raw != nil {
				ds.raw(&RawSet{Received: ds.received, Exporter: ds.e.addr, ExporterPort: ds.port, Domain: m.domain, Version: m.version,
					TemplateID: tid, Status: StatusNoTemplate, Header: s.header, Data: s.data})
			}
			return true
		}
		c.pend.add(s)
		return true
	}
	return ds.decodeSet(m, te, body, StatusOK, ds.received)
}

// decodeSet decodes a data set's records with te. False when the set is
// malformed (it's then stored raw, after the records decoded before the
// break).
func (ds *decState) decodeSet(m *msg, te *tmplEntry, body []byte, status Status, received int64) bool {
	p := ds.c.planOf(te)
	t := te.t
	r := &ds.c.scratch
	for len(body) > 0 {
		if len(body) < p.minLen {
			if allZero(body) || p.fixed {
				return true // padding
			}
			break
		}
		if t.Options {
			n, err := ds.optionsRecord(m, t, body)
			if err != nil {
				break
			}
			body = body[n:]
			m.records++
			continue
		}
		*r = Record{}
		h := m.hdr
		h.received = received
		n, samp, err := p.decodeRecord(body, r, &h)
		if err != nil {
			if allZero(body) {
				return true
			}
			break
		}
		body = body[n:]
		r.Received, r.Domain, r.ExporterPort, r.Version = received, m.domain, ds.port, m.version
		r.TemplateID, r.Template, r.Status = t.ID, t, status
		ds.sampling(r, m.d, &samp)
		ds.e.nameIfs(r, m.domain, ds.c.fileMode)
		if ds.c.fileMode {
			fileFixup(r)
		}
		ds.checkTime(r)
		m.records++
		ds.counts.Records++
		if status == StatusLate {
			ds.counts.Late++
		}
		if ds.emit != nil {
			ds.emit(r)
		}
	}
	if len(body) == 0 {
		return true
	}
	ds.counts.Malformed++
	if ds.raw != nil {
		ds.raw(&RawSet{Received: received, Exporter: ds.e.addr, ExporterPort: ds.port, Domain: m.domain, Version: m.version, TemplateID: t.ID,
			Status: StatusMalformed, Header: clone(m.header), Data: clone(body)})
	}
	m.unknown = true
	return true
}

// sampling resolves a record's sampling (SPEC §13.1.2): its own IEs, else
// its sampler's options data, else the domain's; 0 when unknown.
func (ds *decState) sampling(r *Record, d *domainState, s *recSampling) {
	rate := s.rate()
	if rate == 0 && s.hasSampler {
		rate = d.samplers[s.samplerID]
	}
	if rate == 0 {
		rate = d.sampling
	}
	r.Sampling = rate
}

// fieldVal is one field of an options record.
type fieldVal struct {
	f     TemplateField
	scope bool
	v     []byte
}

const maxSamplers = 1024

// optionsRecord reads one options data record into the exporter metadata:
// interface names, sampling, the system init time.
func (ds *decState) optionsRecord(m *msg, t *Template, b []byte) (int, error) {
	var buf [32]fieldVal
	vals := buf[:0]
	pos := 0
	for i, f := range t.Fields {
		off, l, err := fieldLen(b[pos:], f.Length)
		if err != nil {
			return 0, err
		}
		vals = append(vals, fieldVal{f: f, scope: i < t.ScopeCount, v: b[pos+off : pos+off+l]})
		pos += off + l
	}
	var (
		ifindex                    uint32
		haveIf                     bool
		name, desc                 string
		haveName, haveDesc         bool
		sampler                    uint32
		haveSampler                bool
		interval, pktInt, pktSpace uint64
		size, pop                  uint64
		prob                       float64
		sysInit                    int64
		haveSysInit                bool
		randInterval               uint64
	)
	for _, x := range vals {
		u := beUint(x.v)
		if x.f.PEN != 0 {
			continue
		}
		if x.scope && m.version == V9 {
			switch x.f.ID {
			case 2: // Interface
				ifindex, haveIf = uint32(u), true
			}
			continue
		}
		switch x.f.ID {
		case ieInIf, ieOutIf:
			if numOK(uint16(len(x.v))) {
				ifindex, haveIf = uint32(u), true
			}
		case ieIfName:
			name, haveName = string(x.v), true
		case ieIfDesc:
			desc, haveDesc = string(x.v), true
		case ieSamplerID, ieSelectorID:
			if numOK(uint16(len(x.v))) {
				sampler, haveSampler = uint32(u), true
			}
		case ieSamplingInterval:
			interval = u
		case ieSamplerRandomInterval:
			randInterval = u
		case ieSamplingPacketInterval:
			pktInt = u
		case ieSamplingPacketSpace:
			pktSpace = u
		case ieSamplingSize:
			size = u
		case ieSamplingPopulation:
			pop = u
		case ieSamplingProbability:
			switch len(x.v) {
			case 4:
				prob = float64(math.Float32frombits(uint32(u)))
			case 8:
				prob = math.Float64frombits(u)
			}
		case ieSysInitMs:
			if numOK(uint16(len(x.v))) {
				sysInit, haveSysInit = int64(u&(1<<62-1)), true
			}
		}
	}
	c := ds.c
	c.keepOptions(ds.e, m.d, t, vals, m.hdr.received)
	if haveIf && (haveName || haveDesc) {
		n := name
		if !haveName || n == "" {
			n = desc
		}
		c.setIfName(ds.e, m.domain, ifindex, trimNul(n))
	}
	if haveSysInit {
		c.mu.Lock()
		if m.d.sysInitMs != sysInit {
			ds.e.metaVer.Add(1)
		}
		m.d.sysInitMs = sysInit
		c.mu.Unlock()
		m.hdr.sysInitMs = sysInit
	}
	rs := recSampling{interval: interval, pktInterval: pktInt, pktSpace: pktSpace, size: size, pop: pop, prob: prob}
	if rs.interval == 0 {
		rs.interval = randInterval
	}
	if rate := rs.rate(); rate != 0 {
		c.mu.Lock()
		if haveSampler {
			if m.d.samplers == nil {
				m.d.samplers = map[uint32]uint32{}
			}
			if old, ok := m.d.samplers[sampler]; ok || len(m.d.samplers) < maxSamplers {
				if old != rate || !ok {
					ds.e.metaVer.Add(1)
				}
				m.d.samplers[sampler] = rate
			}
		} else {
			if m.d.sampling != rate {
				ds.e.metaVer.Add(1)
			}
			m.d.sampling = rate
		}
		c.mu.Unlock()
	}
	return pos, nil
}

func trimNul(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}
