package loadgen

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// The flow generators behind `woodshed send --proto netflow5|netflow9|ipfix`
// (SPEC §13.8). Every record carries the run ID and a sequence number, so a
// test can check that each was stored exactly once:
//   - IPFIX: enterprise IEs under 32473 (IANA's documentation enterprise
//     number, as the trap generator's OIDs): FlowRunIE (4 bytes, the run ID's
//     8 hex digits), FlowSeqIE (8 bytes), FlowRuleIE (4 bytes, --events);
//     --enterprise-ies adds fillers FlowFillerIE+i (4 bytes each).
//   - NetFlow v9 has no enterprise numbers, so the same values go in field
//     types from the vendor range: V9RunType, V9SeqType, V9RuleType and
//     V9FillerType+i (decided (build, 2026-11-16)).
//   - NetFlow v5: the sequence number's high 16 bits in src_as and its low 16
//     bits in dst_as, and the run ID's last 4 hex digits in the header's
//     engine_type and engine_id (v5 has no room for the whole run ID).
// Addresses are from 10/8 and the documentation ranges.

// Flow generator IEs.
const (
	FlowRunIE    = 1
	FlowSeqIE    = 2
	FlowRuleIE   = 3
	FlowFillerIE = 10

	V9RunType    = 40001
	V9SeqType    = 40002
	V9RuleType   = 40003
	V9FillerType = 40010
)

// Flow protocols.
const (
	ProtoNetFlow5 = "netflow5"
	ProtoNetFlow9 = "netflow9"
	ProtoIPFIX    = "ipfix"
)

// IsFlowProto reports whether p is one of the flow protocols.
func IsFlowProto(p string) bool { return p == ProtoNetFlow5 || p == ProtoNetFlow9 || p == ProtoIPFIX }

// FlowOptions configures a flow generator.
type FlowOptions struct {
	Proto  string // ProtoNetFlow5, ProtoNetFlow9 or ProtoIPFIX
	Addr   string // host:port (SendFlows)
	Source string // local IP to send from (SendFlows)

	// Count records are sent; with Count 0, Rate × Duration.
	Count    int
	Rate     float64 // records per second; 0 as fast as possible
	Duration time.Duration

	RecordsPerPacket int // default 30 (v5: at most 30)
	Domains          int // observation domains (v9 source IDs) 1..N, round robin by packet; default 1
	// Sampling is 1 in N on the sampled domains (0: send no sampling
	// information); SampledDomains how many of the domains, from 1 (0: all).
	Sampling       int
	SampledDomains int
	// TemplateEvery resends the templates (and options data) every N packets
	// of a domain (default 20); TemplateFirstDelay holds every template back
	// until that long after the start, so the data before it waits.
	TemplateEvery      int
	TemplateFirstDelay time.Duration
	EnterpriseIEs      int // filler IEs per record (v9, IPFIX)
	// Events sends firewall-event records (v9, IPFIX): per connection created,
	// an optional update and deleted with initiator and responder totals, plus
	// DenyRatio (default 0.1) of denied records with only an event time.
	Events    bool
	DenyRatio float64
	// Biflow sends RFC 5103 reverse counters (IPFIX); with Events, deltas and
	// reverse deltas instead of initiator and responder totals.
	Biflow bool

	RunID    string // default random
	FirstSeq int
	// Seed makes the generated traffic repeatable (default from RunID).
	Seed uint64
}

// FlowResult describes a SendFlows.
type FlowResult struct {
	RunID        string
	Records      int // data records sent
	Packets      int
	Elapsed      time.Duration
	Rate         float64 // records per second
	Backpressure int
}

func (o *FlowOptions) defaults() error {
	switch o.Proto {
	case ProtoNetFlow5, ProtoNetFlow9, ProtoIPFIX:
	default:
		return fmt.Errorf("loadgen: flow proto must be %s, %s or %s, not %q", ProtoNetFlow5, ProtoNetFlow9, ProtoIPFIX, o.Proto)
	}
	if o.RunID == "" {
		o.RunID = NewRunID()
	}
	if b, err := hex.DecodeString(o.RunID); err != nil || len(b) != 4 {
		return fmt.Errorf("loadgen: a flow run ID is 8 hex digits, not %q", o.RunID)
	}
	if o.RecordsPerPacket <= 0 {
		o.RecordsPerPacket = 30
	}
	if o.Proto == ProtoNetFlow5 && o.RecordsPerPacket > 30 {
		return errors.New("loadgen: NetFlow v5 carries at most 30 records a packet")
	}
	if o.RecordsPerPacket > 1000 {
		return errors.New("loadgen: at most 1000 records a packet")
	}
	if o.Domains <= 0 {
		o.Domains = 1
	}
	if o.Domains > 1000 {
		return errors.New("loadgen: at most 1000 domains")
	}
	if o.Sampling < 0 || o.Sampling > 1<<14-1 && o.Proto == ProtoNetFlow5 {
		return errors.New("loadgen: v5 sampling is at most 16383")
	}
	if o.SampledDomains <= 0 || o.SampledDomains > o.Domains {
		o.SampledDomains = o.Domains
	}
	if o.TemplateEvery <= 0 {
		o.TemplateEvery = 20
	}
	if o.EnterpriseIEs < 0 || o.EnterpriseIEs > 100 {
		return errors.New("loadgen: enterprise IEs are 0 to 100")
	}
	if (o.Events || o.EnterpriseIEs > 0) && o.Proto == ProtoNetFlow5 {
		return errors.New("loadgen: --events and --enterprise-ies need netflow9 or ipfix")
	}
	if o.Biflow && o.Proto != ProtoIPFIX {
		return errors.New("loadgen: --biflow needs ipfix (RFC 5103 uses enterprise IEs)")
	}
	if o.DenyRatio < 0 || o.DenyRatio > 1 {
		return errors.New("loadgen: the deny ratio is 0 to 1")
	}
	if o.Events && o.DenyRatio == 0 {
		o.DenyRatio = 0.1
	}
	if o.Count < 0 || o.Rate < 0 || o.Duration < 0 || o.FirstSeq < 0 {
		return errors.New("loadgen: count, rate, duration and first seq can't be negative")
	}
	if o.Count == 0 {
		if o.Rate > 0 && o.Duration > 0 {
			o.Count = int(o.Rate * o.Duration.Seconds())
		} else {
			o.Count = 1
		}
	}
	if o.Seed == 0 {
		h := fnv.New64a()
		h.Write([]byte(o.RunID))
		o.Seed = h.Sum64()
	}
	return nil
}

// FlowGen builds the packets of one run. Not safe for concurrent use.
type FlowGen struct {
	o       FlowOptions
	run     uint32
	rnd     *rand.Rand
	start   time.Time
	boot    time.Time // the simulated exporter's boot (v5, v9 uptimes)
	seq     uint64    // the next record's sequence number
	sent    int       // records generated
	dom     []genDomain
	nextDom int
	b       *flow.Builder
	conns   []genConn // open connections (events)
}

type genDomain struct {
	id       uint32
	packets  int    // packets sent
	hdrSeq   uint32 // v9 packets, IPFIX and v5 records
	sampling int
	tmplSent bool
}

type genConn struct {
	src, dst         netip.Addr
	sport, dport     uint16
	proto            uint8
	natSrc           netip.Addr
	natPort          uint16
	in, out          uint32
	start            int64
	ib, rb, ip, rp   uint64 // totals at the end
	updated, created bool
	rule             uint32
	dom              int
}

// NewFlowGen returns a generator; start is the run's start (times and the
// template delay are relative to it).
func NewFlowGen(o FlowOptions, start time.Time) (*FlowGen, error) {
	if err := o.defaults(); err != nil {
		return nil, err
	}
	run, _ := hex.DecodeString(o.RunID)
	g := &FlowGen{o: o, run: binary.BigEndian.Uint32(run), rnd: rand.New(rand.NewPCG(o.Seed, 0x5eed)), start: start,
		boot: start.Truncate(time.Second).Add(-time.Hour), seq: uint64(o.FirstSeq)}
	for i := range o.Domains {
		d := genDomain{id: uint32(i + 1)}
		if o.Sampling > 0 && i < o.SampledDomains {
			d.sampling = o.Sampling
		}
		g.dom = append(g.dom, d)
	}
	switch o.Proto {
	case ProtoNetFlow9:
		g.b = flow.NewBuilder(flow.V9)
	case ProtoIPFIX:
		g.b = flow.NewBuilder(flow.IPFIX)
	}
	return g, nil
}

// Options returns the generator's options with the defaults filled in.
func (g *FlowGen) Options() FlowOptions { return g.o }

// Done reports whether every record has been generated.
func (g *FlowGen) Done() bool { return g.sent >= g.o.Count }

// Expected is a sent record as Woodshed stores it: its columns, domain and
// sequence number (the run ID is the generator's).
type Expected struct {
	Seq    uint64
	Record flow.Record // columns, Domain, Sampling, Extras (no Received, Template or ExporterPort)
}

// Template IDs.
const (
	tmplFlow       = 256
	tmplConn       = 257
	tmplDeny       = 258
	tmplOptSamp    = 300
	tmplOptIfNames = 301
)

var ifNames = []string{"", "outside", "inside", "dmz", "mgmt"}

// Next builds the next packet at now, and the records it carries (none for a
// packet of templates only). It returns nil once every record is out.
func (g *FlowGen) Next(now time.Time) ([]byte, []Expected) {
	if g.Done() {
		return nil, nil
	}
	di := g.nextDom
	g.nextDom = (g.nextDom + 1) % len(g.dom)
	d := &g.dom[di]
	n := min(g.o.RecordsPerPacket, g.o.Count-g.sent)
	if g.o.Proto == ProtoNetFlow5 {
		return g.v5(now, d, n)
	}
	tmplDue := now.Sub(g.start) >= g.o.TemplateFirstDelay && (!d.tmplSent || d.packets%g.o.TemplateEvery == 0)
	if tmplDue {
		g.templates(d)
		d.tmplSent = true
	}
	optRecs := 0
	if tmplDue {
		optRecs = g.options(d)
	}
	exp := make([]Expected, 0, n)
	for range n {
		e := g.record(now, d, di)
		exp = append(exp, e)
	}
	// The v9 header's time is whole seconds; its uptime is given at that
	// second, so uptime-relative times convert back exactly.
	h := flow.Header{ExportTime: uint32(now.Unix()), Seq: d.hdrSeq, Domain: d.id,
		SysUptime: uint32(now.Truncate(time.Second).Sub(g.boot).Milliseconds())}
	pkt := g.b.Message(h)
	if g.o.Proto == ProtoNetFlow9 {
		d.hdrSeq++
	} else {
		d.hdrSeq += uint32(n + optRecs)
	}
	d.packets++
	return pkt, exp
}

func (g *FlowGen) v9() bool { return g.o.Proto == ProtoNetFlow9 }

// ie is a generator field: the IPFIX enterprise IE, or the v9 vendor type.
func (g *FlowGen) ie(id uint16, n uint16) flow.TemplateField {
	if g.v9() {
		t := map[uint16]uint16{FlowRunIE: V9RunType, FlowSeqIE: V9SeqType, FlowRuleIE: V9RuleType}[id]
		if t == 0 {
			t = V9FillerType + (id - FlowFillerIE)
		}
		return flow.TemplateField{ID: t, Length: n}
	}
	return flow.TemplateField{PEN: flow.PENDocumentation, ID: id, Length: n}
}

func fld(id, n uint16) flow.TemplateField { return flow.TemplateField{ID: id, Length: n} }

func (g *FlowGen) tail() []flow.TemplateField {
	t := []flow.TemplateField{g.ie(FlowRunIE, 4), g.ie(FlowSeqIE, 8)}
	for i := range g.o.EnterpriseIEs {
		t = append(t, g.ie(uint16(FlowFillerIE+i), 4))
	}
	return t
}

// FlowTemplate is the plain-flow template's fields (for tests).
func (g *FlowGen) flowTemplate() []flow.TemplateField {
	f := []flow.TemplateField{fld(8, 4), fld(12, 4), fld(7, 2), fld(11, 2), fld(4, 1), fld(6, 1), fld(5, 1)}
	if g.v9() {
		f = append(f, fld(1, 4), fld(2, 4), fld(22, 4), fld(21, 4), fld(10, 2), fld(14, 2))
	} else {
		f = append(f, fld(1, 8), fld(2, 8), fld(152, 8), fld(153, 8), fld(10, 4), fld(14, 4))
	}
	if g.o.Biflow {
		f = append(f, flow.TemplateField{PEN: flow.PENReverse, ID: 1, Length: 8}, flow.TemplateField{PEN: flow.PENReverse, ID: 2, Length: 8})
	}
	return append(f, g.tail()...)
}

func (g *FlowGen) connTemplate() []flow.TemplateField {
	f := []flow.TemplateField{fld(8, 4), fld(12, 4), fld(7, 2), fld(11, 2), fld(4, 1), fld(233, 1), fld(230, 1),
		fld(225, 4), fld(227, 2), fld(10, 4), fld(14, 4), fld(323, 8), fld(152, 8), fld(153, 8)}
	if g.o.Biflow {
		f = append(f, fld(1, 8), fld(2, 8), flow.TemplateField{PEN: flow.PENReverse, ID: 1, Length: 8},
			flow.TemplateField{PEN: flow.PENReverse, ID: 2, Length: 8})
	} else {
		f = append(f, fld(231, 8), fld(232, 8), fld(298, 8), fld(299, 8))
	}
	return append(append(f, g.ie(FlowRuleIE, 4)), g.tail()...)
}

func (g *FlowGen) denyTemplate() []flow.TemplateField {
	f := []flow.TemplateField{fld(8, 4), fld(12, 4), fld(7, 2), fld(11, 2), fld(4, 1), fld(233, 1), fld(10, 4), fld(14, 4),
		fld(323, 8)}
	return append(append(f, g.ie(FlowRuleIE, 4)), g.tail()...)
}

func (g *FlowGen) templates(d *genDomain) {
	if g.o.Events {
		g.b.Template(tmplConn, g.connTemplate())
		g.b.Template(tmplDeny, g.denyTemplate())
	} else {
		g.b.Template(tmplFlow, g.flowTemplate())
	}
	if d.sampling > 0 {
		if g.v9() {
			g.b.OptionsTemplate(tmplOptSamp, 1, []flow.TemplateField{fld(1, 4), fld(34, 4), fld(35, 1)})
		} else {
			g.b.OptionsTemplate(tmplOptSamp, 1, []flow.TemplateField{fld(149, 4), fld(305, 4), fld(306, 4)})
		}
	}
	if g.v9() {
		g.b.OptionsTemplate(tmplOptIfNames, 1, []flow.TemplateField{fld(2, 4), fld(82, 16)})
	} else {
		g.b.OptionsTemplate(tmplOptIfNames, 1, []flow.TemplateField{fld(10, 4), fld(82, flow.Varlen)})
	}
}

// options adds the options data (sampling, interface names) and returns how
// many records it added.
func (g *FlowGen) options(d *genDomain) int {
	n := 0
	if d.sampling > 0 {
		if g.v9() {
			g.b.Data(tmplOptSamp, flow.Values{}.U32(0).U32(uint32(d.sampling)).U8(2))
		} else {
			g.b.Data(tmplOptSamp, flow.Values{}.U32(d.id).U32(1).U32(uint32(d.sampling-1)))
		}
		n++
	}
	for i := 1; i < len(ifNames); i++ {
		v := flow.Values{}.U32(uint32(i))
		if g.v9() {
			name := make([]byte, 16)
			copy(name, ifNames[i])
			v = v.Bytes(name)
		} else {
			v = v.Var([]byte(ifNames[i]))
		}
		g.b.Data(tmplOptIfNames, v)
		n++
	}
	return n
}

// talker picks a source address: a few heavy talkers, then a long tail.
func (g *FlowGen) talker() netip.Addr {
	if g.rnd.IntN(3) == 0 {
		return netip.AddrFrom4([4]byte{10, 20, 0, byte(5 + g.rnd.IntN(4))})
	}
	return netip.AddrFrom4([4]byte{10, 20, byte(g.rnd.IntN(16)), byte(1 + g.rnd.IntN(250))})
}

func (g *FlowGen) server() netip.Addr {
	if g.rnd.IntN(2) == 0 {
		return netip.AddrFrom4([4]byte{198, 51, 100, byte(1 + g.rnd.IntN(20))})
	}
	return netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + g.rnd.IntN(250))})
}

var services = []struct {
	port  uint16
	proto uint8
	w     int
}{{443, 6, 50}, {53, 17, 15}, {80, 6, 10}, {22, 6, 5}, {123, 17, 5}, {445, 6, 5}, {8443, 6, 5}, {23, 6, 5}}

func (g *FlowGen) service() (uint16, uint8) {
	n := g.rnd.IntN(100)
	for _, s := range services {
		if n < s.w {
			return s.port, s.proto
		}
		n -= s.w
	}
	return 443, 6
}

func (g *FlowGen) tailValues(v flow.Values, seq uint64) flow.Values {
	v = v.U32(g.run).U64(seq)
	for i := range g.o.EnterpriseIEs {
		v = v.U32(uint32(i))
	}
	return v
}

func (g *FlowGen) tailExtras(seq uint64) []flow.Extra {
	b4 := func(x uint32) []byte { return binary.BigEndian.AppendUint32(nil, x) }
	ie := func(id uint16, v []byte) flow.Extra {
		f := g.ie(id, 0)
		return flow.Extra{PEN: f.PEN, ID: f.ID, Value: v}
	}
	ex := []flow.Extra{ie(FlowRunIE, b4(g.run)), ie(FlowSeqIE, binary.BigEndian.AppendUint64(nil, seq))}
	for i := range g.o.EnterpriseIEs {
		ex = append(ex, ie(uint16(FlowFillerIE+i), b4(uint32(i))))
	}
	return ex
}

// record adds one data record to the open message and returns what's
// expected of it.
func (g *FlowGen) record(now time.Time, d *genDomain, di int) Expected {
	seq := g.seq
	g.seq++
	g.sent++
	ms := now.UnixMilli()
	if g.o.Events {
		return g.event(ms, d, di, seq)
	}
	dport, proto := g.service()
	r := flow.Record{Src: g.talker(), Dst: g.server(), SrcPort: uint16(32768 + g.rnd.IntN(28000)), DstPort: dport,
		Proto: proto, ToS: 0, Packets: uint64(1 + g.rnd.IntN(2000)), InIf: uint32(1 + g.rnd.IntN(2)),
		OutIf: uint32(3 + g.rnd.IntN(2)), Domain: d.id, Sampling: uint32(d.sampling)}
	if proto == 6 {
		r.TCPFlags = 0x1b
	}
	r.Bytes = r.Packets * uint64(60+g.rnd.IntN(1400))
	r.End = ms - int64(g.rnd.IntN(2000))
	r.Start = r.End - int64(g.rnd.IntN(30000))
	r.Has = flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto | flow.HasTCPFlags | flow.HasToS |
		flow.HasBytes | flow.HasPackets | flow.HasStart | flow.HasEnd | flow.HasInIf | flow.HasOutIf |
		flow.HasInIfName | flow.HasOutIfName
	r.InIfName, r.OutIfName = ifNames[r.InIf], ifNames[r.OutIf]
	v := flow.Values{}.Addr(r.Src).Addr(r.Dst).U16(r.SrcPort).U16(r.DstPort).U8(r.Proto).U8(uint8(r.TCPFlags)).U8(r.ToS)
	if g.v9() {
		up := func(t int64) uint32 { return uint32(t - g.boot.UnixMilli()) }
		v = v.U32(uint32(r.Bytes)).U32(uint32(r.Packets)).U32(up(r.Start)).U32(up(r.End)).U16(uint16(r.InIf)).U16(uint16(r.OutIf))
		r.Bytes = uint64(uint32(r.Bytes))
	} else {
		v = v.U64(r.Bytes).U64(r.Packets).U64(uint64(r.Start)).U64(uint64(r.End)).U32(r.InIf).U32(r.OutIf)
	}
	if g.o.Biflow {
		r.RevPackets = uint64(1 + g.rnd.IntN(2000))
		r.RevBytes = r.RevPackets * uint64(60+g.rnd.IntN(1400))
		r.Has |= flow.HasRevBytes | flow.HasRevPackets
		v = v.U64(r.RevBytes).U64(r.RevPackets)
	}
	v = g.tailValues(v, seq)
	r.Extras = g.tailExtras(seq)
	g.b.Data(tmplFlow, v)
	return Expected{Seq: seq, Record: r}
}

// event adds one firewall-event record: a denied one, or the next step of a
// connection (created, maybe update, deleted).
func (g *FlowGen) event(ms int64, d *genDomain, di int, seq uint64) Expected {
	rule := uint32(100 + g.rnd.IntN(8))
	if g.rnd.Float64() < g.o.DenyRatio {
		src := netip.AddrFrom4([4]byte{203, 0, 113, byte(50 + g.rnd.IntN(6))})
		dport, proto := []uint16{23, 445, 3389, 22}[g.rnd.IntN(4)], uint8(6)
		r := flow.Record{Src: src, Dst: netip.AddrFrom4([4]byte{10, 20, 0, byte(5 + g.rnd.IntN(4))}),
			SrcPort: uint16(1024 + g.rnd.IntN(60000)), DstPort: dport, Proto: proto, FwEvent: flow.FwDenied, InIf: 1, OutIf: 3,
			EventTime: ms - int64(g.rnd.IntN(500)), Domain: d.id, Sampling: uint32(d.sampling),
			RuleID: strconv.FormatUint(uint64(rule+1000), 10)}
		r.Start, r.End = r.EventTime, r.EventTime
		r.Has = flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto | flow.HasFwEvent |
			flow.HasInIf | flow.HasOutIf | flow.HasEventTime | flow.HasStart | flow.HasEnd | flow.HasRuleID |
			flow.HasInIfName | flow.HasOutIfName
		r.InIfName, r.OutIfName = ifNames[1], ifNames[3]
		v := flow.Values{}.Addr(r.Src).Addr(r.Dst).U16(r.SrcPort).U16(r.DstPort).U8(r.Proto).U8(r.FwEvent).U32(1).U32(3).
			U64(uint64(r.EventTime)).U32(rule + 1000)
		v = g.tailValues(v, seq)
		r.Extras = append([]flow.Extra{g.ruleExtra(rule + 1000)}, g.tailExtras(seq)...)
		g.b.Data(tmplDeny, v)
		return Expected{Seq: seq, Record: r}
	}
	// Advance an open connection of this domain, or open one.
	var c *genConn
	ci := -1
	for i := range g.conns {
		if g.conns[i].dom == di && (len(g.conns) > 16 || g.rnd.IntN(2) == 0) {
			c, ci = &g.conns[i], i
			break
		}
	}
	var ev uint8
	if c == nil {
		dport, proto := g.service()
		pk := uint64(2 + g.rnd.IntN(500))
		nc := genConn{src: g.talker(), dst: g.server(), sport: uint16(32768 + g.rnd.IntN(28000)), dport: dport, proto: proto,
			natSrc: netip.AddrFrom4([4]byte{192, 0, 2, byte(10 + g.rnd.IntN(4))}), natPort: uint16(1024 + g.rnd.IntN(60000)),
			in: 2, out: 1, start: ms - int64(g.rnd.IntN(1000)), ip: pk, rp: pk + uint64(g.rnd.IntN(100)), rule: rule, dom: di}
		nc.ib, nc.rb = nc.ip*uint64(80+g.rnd.IntN(1300)), nc.rp*uint64(80+g.rnd.IntN(1300))
		g.conns = append(g.conns, nc)
		c, ci = &g.conns[len(g.conns)-1], len(g.conns)-1
		ev = flow.FwCreated
	} else if !c.updated && g.rnd.IntN(2) == 0 {
		ev, c.updated = flow.FwUpdate, true
	} else {
		ev = flow.FwDeleted
	}
	r := flow.Record{Src: c.src, Dst: c.dst, SrcPort: c.sport, DstPort: c.dport, Proto: c.proto, FwEvent: ev,
		PostNATSrc: c.natSrc, PostNATSrcPort: c.natPort, InIf: c.in, OutIf: c.out, EventTime: ms, Start: c.start,
		Domain: d.id, Sampling: uint32(d.sampling), RuleID: strconv.FormatUint(uint64(c.rule), 10)}
	r.Has = flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto | flow.HasFwEvent | flow.HasNatEvent |
		flow.HasPostNATSrc | flow.HasPostNATSrcPort | flow.HasInIf | flow.HasOutIf | flow.HasEventTime | flow.HasStart |
		flow.HasEnd | flow.HasRuleID | flow.HasInIfName | flow.HasOutIfName
	r.InIfName, r.OutIfName = ifNames[c.in], ifNames[c.out]
	frac := map[uint8]uint64{flow.FwCreated: 0, flow.FwUpdate: 2, flow.FwDeleted: 4}[ev] // quarters of the totals
	switch ev {
	case flow.FwCreated:
		r.NatEvent, r.End = 4, c.start
	case flow.FwUpdate:
		r.End = ms
	default:
		r.NatEvent, r.End = 5, ms
	}
	part := func(x uint64) uint64 { return x * frac / 4 }
	v := flow.Values{}.Addr(r.Src).Addr(r.Dst).U16(r.SrcPort).U16(r.DstPort).U8(r.Proto).U8(ev).U8(r.NatEvent).
		Addr(r.PostNATSrc).U16(r.PostNATSrcPort).U32(r.InIf).U32(r.OutIf).U64(uint64(r.EventTime)).U64(uint64(r.Start)).
		U64(uint64(r.End))
	if g.o.Biflow {
		// Deltas: each record carries what's new since the last one.
		prev := map[uint8]uint64{flow.FwCreated: 0, flow.FwUpdate: 0, flow.FwDeleted: 2}[ev]
		if ev == flow.FwDeleted && !c.updated {
			prev = 0
		}
		delta := func(x uint64) uint64 { return part(x) - x*prev/4 }
		r.Bytes, r.Packets, r.RevBytes, r.RevPackets = delta(c.ib), delta(c.ip), delta(c.rb), delta(c.rp)
		r.Has |= flow.HasBytes | flow.HasPackets | flow.HasRevBytes | flow.HasRevPackets
		v = v.U64(r.Bytes).U64(r.Packets).U64(r.RevBytes).U64(r.RevPackets)
	} else {
		r.InitiatorBytes, r.ResponderBytes, r.InitiatorPackets, r.ResponderPackets = part(c.ib), part(c.rb), part(c.ip), part(c.rp)
		r.Has |= flow.HasInitiatorBytes | flow.HasResponderBytes | flow.HasInitiatorPackets | flow.HasResponderPackets
		v = v.U64(r.InitiatorBytes).U64(r.ResponderBytes).U64(r.InitiatorPackets).U64(r.ResponderPackets)
	}
	v = v.U32(c.rule)
	v = g.tailValues(v, seq)
	r.Extras = append([]flow.Extra{g.ruleExtra(c.rule)}, g.tailExtras(seq)...)
	if ev == flow.FwDeleted {
		g.conns = append(g.conns[:ci], g.conns[ci+1:]...)
	}
	g.b.Data(tmplConn, v)
	return Expected{Seq: seq, Record: r}
}

func (g *FlowGen) ruleExtra(rule uint32) flow.Extra {
	f := g.ie(FlowRuleIE, 0)
	return flow.Extra{PEN: f.PEN, ID: f.ID, Value: binary.BigEndian.AppendUint32(nil, rule)}
}

// RuleIE is the IE the generator's rule IDs are in, as listeners.flow.rule_id_ies
// takes it ("32473:3" for IPFIX, "0:40003" for v9).
func RuleIE(proto string) flow.IEKey {
	if proto == ProtoNetFlow9 {
		return flow.IEKey{ID: V9RuleType}
	}
	return flow.IEKey{PEN: flow.PENDocumentation, ID: FlowRuleIE}
}

func (g *FlowGen) v5(now time.Time, d *genDomain, n int) ([]byte, []Expected) {
	up := uint32(now.Sub(g.boot).Milliseconds())
	samp := uint16(0)
	if d.sampling > 0 {
		samp = 1<<14 | uint16(d.sampling)
	}
	h := flow.V5Header{SysUptime: up, UnixSecs: uint32(now.Unix()), Nsecs: uint32(now.Nanosecond()), Seq: d.hdrSeq,
		EngineType: uint8(g.run >> 8), EngineID: uint8(g.run), SamplingInterval: samp}
	exportMs := now.Unix()*1000 + int64(now.Nanosecond()/1e6)
	recs := make([]flow.V5Record, n)
	exp := make([]Expected, n)
	for i := range recs {
		seq := g.seq
		g.seq++
		g.sent++
		dport, proto := g.service()
		pk := uint32(1 + g.rnd.IntN(2000))
		last := up - uint32(g.rnd.IntN(2000))
		first := last - uint32(g.rnd.IntN(30000))
		vr := flow.V5Record{Src: g.talker(), Dst: g.server(), NextHop: netip.AddrFrom4([4]byte{10, 0, 0, 1}), In: 1, Out: 3,
			Packets: pk, Bytes: pk * uint32(60+g.rnd.IntN(1400)), First: first, Last: last,
			SrcPort: uint16(32768 + g.rnd.IntN(28000)), DstPort: dport, Proto: proto, SrcAS: uint16(seq >> 16), DstAS: uint16(seq)}
		if proto == 6 {
			vr.TCPFlags = 0x1b
		}
		recs[i] = vr
		rate := uint32(d.sampling)
		if rate == 0 {
			rate = 1
		}
		r := flow.Record{Src: vr.Src, Dst: vr.Dst, NextHop: vr.NextHop, InIf: 1, OutIf: 3, Packets: uint64(pk),
			Bytes: uint64(vr.Bytes), Start: exportMs - int64(up-first), End: exportMs - int64(up-last), SrcPort: vr.SrcPort,
			DstPort: dport, TCPFlags: uint16(vr.TCPFlags), Proto: proto, SrcAS: uint32(vr.SrcAS), DstAS: uint32(vr.DstAS),
			Sampling: rate,
			Has: flow.HasSrc | flow.HasDst | flow.HasNextHop | flow.HasInIf | flow.HasOutIf | flow.HasPackets | flow.HasBytes |
				flow.HasStart | flow.HasEnd | flow.HasSrcPort | flow.HasDstPort | flow.HasTCPFlags | flow.HasProto |
				flow.HasToS | flow.HasSrcAS | flow.HasDstAS,
			Extras: []flow.Extra{{ID: 38, Value: []byte{h.EngineType}}, {ID: 39, Value: []byte{h.EngineID}}}}
		exp[i] = Expected{Seq: seq, Record: r}
	}
	d.hdrSeq += uint32(n)
	d.packets++
	return flow.EncodeV5(h, recs), exp
}

// FlowSeq reads the run and sequence number a stored record carries: for v9
// and IPFIX the run ID's 8 hex digits, for v5 its last 4 (and the sequence
// number modulo 2^32).
func FlowSeq(r *flow.Record) (run string, seq uint64, ok bool) {
	var haveRun, haveSeq bool
	var eng [2]byte
	var haveEng int
	for _, e := range r.Extras {
		switch {
		case (e.PEN == flow.PENDocumentation && e.ID == FlowRunIE) || (e.PEN == 0 && e.ID == V9RunType):
			if len(e.Value) == 4 {
				run, haveRun = hex.EncodeToString(e.Value), true
			}
		case (e.PEN == flow.PENDocumentation && e.ID == FlowSeqIE) || (e.PEN == 0 && e.ID == V9SeqType):
			if len(e.Value) == 8 {
				seq, haveSeq = binary.BigEndian.Uint64(e.Value), true
			}
		case e.PEN == 0 && e.ID == 38 && len(e.Value) == 1:
			eng[0] = e.Value[0]
			haveEng |= 1
		case e.PEN == 0 && e.ID == 39 && len(e.Value) == 1:
			eng[1] = e.Value[0]
			haveEng |= 2
		}
	}
	if haveRun && haveSeq {
		return run, seq, true
	}
	if r.Version == flow.V5 && haveEng == 3 {
		return hex.EncodeToString(eng[:]), uint64(r.SrcAS)<<16 | uint64(r.DstAS), true
	}
	return "", 0, false
}

// MatchRun reports whether a run tag from FlowSeq is runID's (the v5 form is
// its last 4 hex digits).
func MatchRun(tag, runID string) bool {
	return tag == runID || (len(tag) == 4 && strings.HasSuffix(runID, tag))
}

// SendFlows sends a flow run to o.Addr over UDP, paced at o.Rate records a
// second. log, if set, gets each packet's expected records as it goes out.
func SendFlows(ctx context.Context, o FlowOptions, log func([]Expected)) (FlowResult, error) {
	g, err := NewFlowGen(o, time.Now())
	if err != nil {
		return FlowResult{}, err
	}
	o = g.o
	res := FlowResult{RunID: o.RunID}
	var d net.Dialer
	if o.Source != "" {
		a, err := netip.ParseAddr(o.Source)
		if err != nil {
			return res, fmt.Errorf("loadgen: Source %q is not an IP address", o.Source)
		}
		d.LocalAddr = &net.UDPAddr{IP: net.IP(a.AsSlice())}
	}
	c, err := d.DialContext(ctx, "udp", o.Addr)
	if err != nil {
		return res, fmt.Errorf("loadgen: %w", err)
	}
	defer c.Close()
	start := time.Now()
	p := pacer{start: start, rate: o.Rate}
	for !g.Done() {
		for g.sent < p.due(o.Count) && !g.Done() {
			pkt, exp := g.Next(time.Now())
			for {
				_, err := c.Write(pkt)
				if err == nil {
					break
				}
				if isNoBufs(err) {
					res.Backpressure++
					time.Sleep(50 * time.Microsecond)
					if ctx.Err() != nil {
						return res, ctx.Err()
					}
					continue
				}
				if isConnRefused(err) {
					return res, fmt.Errorf("loadgen: %s: nothing is listening (connection refused)", o.Addr)
				}
				return res, fmt.Errorf("loadgen: %w", err)
			}
			res.Packets++
			res.Records += len(exp)
			if log != nil {
				log(exp)
			}
		}
		if err := p.wait(ctx, g.sent); err != nil {
			res.Elapsed = time.Since(start)
			return res, err
		}
	}
	res.Elapsed = time.Since(start)
	if s := res.Elapsed.Seconds(); s > 0 {
		res.Rate = float64(res.Records) / s
	}
	return res, nil
}
