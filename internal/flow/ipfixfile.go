package flow

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"
)

// The IPFIX file (RFC 5655) in exports and bundles (SPEC §13.4): stored
// records re-encoded as IPFIX messages, one observation domain per original
// domain, with templates carrying every field the records had.
//
// How each record is written (decided (build, 2026-11-16)):
//   - columns as their IANA IEs at fixed lengths: flowStart/EndMilliseconds,
//     observationTimeMilliseconds, the v4 or v6 address IEs, ports, protocol,
//     tcpControlBits (2 bytes), ipClassOfService, octet/packetDeltaCount (or
//     the Total forms for records that carried totals), interfaces, AS numbers,
//     next hop, vlanId, flowDirection, flowEndReason, firewallEvent, natEvent,
//     the post-NAT IEs, initiator/responder counts, RFC 5103's reverse counters,
//     samplingInterval (when the rate is known);
//   - the received time as collectionTimeMilliseconds (258);
//   - then every extra (enterprise IEs included) as a variable-length IE with
//     its bytes as stored, in order (the rule_id IE is one of them);
//   - interface names as options data (scope ingressInterface, interfaceName)
//     before the records that use them;
//   - and, first in each domain, an options record (scope observationDomainId)
//     whose observationDomainName says the file was written by Woodshed from
//     stored records, not captured off the wire.
// v5 and v9 records come out as IPFIX. What a file doesn't carry: the decode
// status (late), the exporter's source port and the original version and
// template IDs.

// FileOptions configures a FileWriter.
type FileOptions struct {
	Version    string    // Woodshed's version, for the note
	ExportTime time.Time // every message's export time (default now)
}

// FileNote is the note's text (the observationDomainName of each domain).
func FileNote(version string) string {
	if version == "" {
		version = "(unknown version)"
	}
	return "Written by Woodshed " + version + " from stored flow records; not captured off the wire."
}

const (
	maxMessage   = 65535
	fileIfTmplID = 256
	fileNoteID   = 257
	fileFirstID  = 258
)

// FileWriter writes records as an IPFIX file. Not safe for concurrent use.
type FileWriter struct {
	w      io.Writer
	o      FileOptions
	export uint32
	doms   map[uint32]*fileDom
	order  []uint32
	err    error
	fields []TemplateField
	sig    []byte
	vals   []byte

	// Records counts records written; Truncated those whose extras were cut
	// so the record fits one message.
	Records, Truncated int
}

type fileDom struct {
	id      uint32
	buf     []byte
	setOpen int // the open data set's offset in buf, or -1
	setTID  uint16
	nrec    uint32 // data records in buf
	seq     uint32 // data records written before buf
	tmpls   map[string]uint16
	tdef    map[uint16][]TemplateField
	inMsg   map[uint16]bool // templates written in the current message's history (any earlier message counts)
	nextID  uint16
	ifNames map[uint32]string
	noted   bool
}

// NewFileWriter returns a writer on w.
func NewFileWriter(w io.Writer, o FileOptions) *FileWriter {
	if o.ExportTime.IsZero() {
		o.ExportTime = time.Now()
	}
	return &FileWriter{w: w, o: o, export: uint32(o.ExportTime.Unix()), doms: map[uint32]*fileDom{}}
}

func (fw *FileWriter) dom(id uint32) *fileDom {
	d := fw.doms[id]
	if d == nil {
		d = &fileDom{id: id, setOpen: -1, tmpls: map[string]uint16{}, tdef: map[uint16][]TemplateField{},
			inMsg: map[uint16]bool{}, nextID: fileFirstID, ifNames: map[uint32]string{}}
		fw.doms[id] = d
		fw.order = append(fw.order, id)
	}
	return d
}

func putVarlen(b []byte, v []byte) []byte {
	if len(v) < 255 {
		b = append(b, byte(len(v)))
	} else {
		b = append(b, 255, byte(len(v)>>8), byte(len(v)))
	}
	return append(b, v...)
}

func varlenSize(n int) int {
	if n < 255 {
		return 1 + n
	}
	return 3 + n
}

// fieldsOf builds a record's field list and values.
func (fw *FileWriter) fieldsOf(r *Record, maxExtras int) {
	f := fw.fields[:0]
	v := fw.vals[:0]
	add := func(pen uint32, id, n uint16) { f = append(f, TemplateField{PEN: pen, ID: id, Length: n}) }
	u8 := func(x uint8) { v = append(v, x) }
	u16 := func(x uint16) { v = binary.BigEndian.AppendUint16(v, x) }
	u32 := func(x uint32) { v = binary.BigEndian.AppendUint32(v, x) }
	u64 := func(x uint64) { v = binary.BigEndian.AppendUint64(v, x) }
	addr := func(a netip.Addr, id4, id6 uint16) {
		if a.Is4() {
			add(0, id4, 4)
			b := a.As4()
			v = append(v, b[:]...)
		} else {
			add(0, id6, 16)
			b := a.As16()
			v = append(v, b[:]...)
		}
	}
	noTime := r.TimeSource == TimeReceived && !hasTimeExtra(r) && r.Start == r.Received && r.End == r.Received
	if r.Is(HasStart) && !noTime {
		add(0, ieStartMs, 8)
		u64(uint64(r.Start))
	}
	if r.Is(HasEnd) && !noTime {
		add(0, ieEndMs, 8)
		u64(uint64(r.End))
	}
	if r.Is(HasEventTime) {
		add(0, ieObsTimeMs, 8)
		u64(uint64(r.EventTime))
	}
	if r.Is(HasSrc) {
		addr(r.Src, ieSrcV4, ieSrcV6)
	}
	if r.Is(HasDst) {
		addr(r.Dst, ieDstV4, ieDstV6)
	}
	if r.Is(HasSrcPort) {
		add(0, ieSrcPort, 2)
		u16(r.SrcPort)
	}
	if r.Is(HasDstPort) {
		add(0, ieDstPort, 2)
		u16(r.DstPort)
	}
	if r.Is(HasProto) {
		add(0, ieProto, 1)
		u8(r.Proto)
	}
	if r.Is(HasTCPFlags) {
		add(0, ieTCPFlags, 2)
		u16(r.TCPFlags)
	}
	if r.Is(HasToS) {
		add(0, ieToS, 1)
		u8(r.ToS)
	}
	bytesID, pktsID := uint16(ieOctetDelta), uint16(iePacketDelta)
	if r.Is(HasTotals) {
		bytesID, pktsID = ieOctetTotal, iePacketTotal
	}
	if r.Is(HasBytes) {
		add(0, bytesID, 8)
		u64(r.Bytes)
	}
	if r.Is(HasPackets) {
		add(0, pktsID, 8)
		u64(r.Packets)
	}
	for _, x := range []struct {
		bit uint64
		id  uint16
		val uint32
	}{{HasInIf, ieInIf, r.InIf}, {HasOutIf, ieOutIf, r.OutIf}, {HasSrcAS, ieSrcAS, r.SrcAS}, {HasDstAS, ieDstAS, r.DstAS}} {
		if r.Is(x.bit) {
			add(0, x.id, 4)
			u32(x.val)
		}
	}
	if r.Is(HasNextHop) {
		addr(r.NextHop, ieNextHopV4, ieNextHopV6)
	}
	if r.Is(HasVLAN) {
		add(0, ieVLAN, 2)
		u16(r.VLAN)
	}
	if r.Is(HasDirection) {
		add(0, ieDirection, 1)
		u8(r.Direction)
	}
	if r.Is(HasEndReason) {
		add(0, ieEndReason, 1)
		u8(r.EndReason)
	}
	if r.Is(HasFwEvent) {
		add(0, ieFwEvent, 1)
		u8(r.FwEvent)
	}
	if r.Is(HasNatEvent) {
		add(0, ieNatEvent, 1)
		u8(r.NatEvent)
	}
	if r.Is(HasPostNATSrc) {
		addr(r.PostNATSrc, iePostNATSrcV4, iePostNATSrcV6)
	}
	if r.Is(HasPostNATDst) {
		addr(r.PostNATDst, iePostNATDstV4, iePostNATDstV6)
	}
	if r.Is(HasPostNATSrcPort) {
		add(0, iePostNAPTSrcPort, 2)
		u16(r.PostNATSrcPort)
	}
	if r.Is(HasPostNATDstPort) {
		add(0, iePostNAPTDstPort, 2)
		u16(r.PostNATDstPort)
	}
	for _, x := range []struct {
		bit uint64
		pen uint32
		id  uint16
		val uint64
	}{{HasInitiatorBytes, 0, ieInitiatorOctets, r.InitiatorBytes}, {HasResponderBytes, 0, ieResponderOctets, r.ResponderBytes},
		{HasInitiatorPackets, 0, ieInitiatorPackets, r.InitiatorPackets}, {HasResponderPackets, 0, ieResponderPackets, r.ResponderPackets},
		{HasRevBytes, PENReverse, ieOctetDelta, r.RevBytes}, {HasRevPackets, PENReverse, iePacketDelta, r.RevPackets}} {
		if r.Is(x.bit) {
			add(x.pen, x.id, 8)
			u64(x.val)
		}
	}
	if r.Sampling != 0 {
		add(0, ieSamplingInterval, 4)
		u32(r.Sampling)
	}
	add(0, ieCollectionTimeMs, Varlen)
	var rb [8]byte
	binary.BigEndian.PutUint64(rb[:], uint64(r.Received))
	v = putVarlen(v, rb[:])
	for i, e := range r.Extras {
		if i >= maxExtras {
			break
		}
		if extraFixed(r, &e) {
			add(e.PEN, e.ID, uint16(len(e.Value)))
			v = append(v, e.Value...)
		} else {
			add(e.PEN, e.ID, Varlen)
			v = putVarlen(v, e.Value)
		}
	}
	fw.fields, fw.vals = f, v
}

// extraFixed says how an extra is written: an enterprise IE at its own
// length (as exporters send them), an IANA or reverse IE as variable length
// (so a reader never takes it for a column). The IE behind rule_id is
// written whichever way reproduces its rendering (RuleIDText depends on it).
func extraFixed(r *Record, e *Extra) bool {
	fixed := e.PEN != 0 && e.PEN != PENReverse
	if r.Is(HasRuleID) {
		asFixed, asVar := RuleIDText(e.Value, false), RuleIDText(e.Value, true)
		if asFixed != asVar {
			switch r.RuleID {
			case asFixed:
				fixed = true
			case asVar:
				fixed = false
			}
		}
	}
	return fixed && len(e.Value) >= 1 && len(e.Value) < Varlen
}

func hasTimeExtra(r *Record) bool {
	for _, e := range r.Extras {
		if e.PEN == 0 && isTimeIE(e.ID) {
			return true
		}
	}
	return false
}

func templateBytes(fields []TemplateField) int {
	n := 4 + 4 // set header + record header
	for _, f := range fields {
		n += 4
		if f.PEN != 0 {
			n += 4
		}
	}
	return n
}

func sigOf(dst []byte, fields []TemplateField) []byte {
	for _, f := range fields {
		dst = binary.BigEndian.AppendUint32(dst, f.PEN)
		dst = binary.BigEndian.AppendUint16(dst, f.ID)
		dst = binary.BigEndian.AppendUint16(dst, f.Length)
	}
	return dst
}

// Write adds a record.
func (fw *FileWriter) Write(r *Record) error {
	if fw.err != nil {
		return fw.err
	}
	d := fw.dom(r.Domain)
	if !d.noted {
		d.noted = true
		fw.note(d)
	}
	for _, x := range []struct {
		bit, nameBit uint64
		ifx          uint32
		name         string
	}{{HasInIf, HasInIfName, r.InIf, r.InIfName}, {HasOutIf, HasOutIfName, r.OutIf, r.OutIfName}} {
		if !r.Is(x.bit) {
			continue
		}
		want := ""
		if r.Is(x.nameBit) {
			want = x.name
		}
		if old, ok := d.ifNames[x.ifx]; (ok && old != want) || (!ok && want != "") {
			fw.ifName(d, x.ifx, want)
		}
	}
	maxEx := len(r.Extras)
	for {
		fw.fieldsOf(r, maxEx)
		need := ipfixHeader + templateBytes(fw.fields) + 4 + len(fw.vals)
		if need <= maxMessage || maxEx == 0 {
			if need > maxMessage {
				return fw.fail(fmt.Errorf("flow: a record too large for an IPFIX message (%d bytes)", need))
			}
			break
		}
		maxEx--
		if maxEx == len(r.Extras)-1 {
			fw.Truncated++
		}
	}
	fw.sig = sigOf(fw.sig[:0], fw.fields)
	tid, ok := d.tmpls[string(fw.sig)]
	if !ok {
		if d.nextID == 0 {
			return fw.fail(errors.New("flow: too many templates in one domain"))
		}
		tid = d.nextID
		d.nextID++
		d.tmpls[string(fw.sig)] = tid
		d.tdef[tid] = slices.Clone(fw.fields)
	}
	fw.data(d, tid, fw.vals)
	fw.Records++
	return fw.err
}

func (fw *FileWriter) fail(err error) error {
	if fw.err == nil {
		fw.err = err
	}
	return fw.err
}

// note writes the domain's "written by Woodshed" options record.
func (fw *FileWriter) note(d *fileDom) {
	fields := []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieObsDomainName, Length: Varlen}}
	d.tdef[fileNoteID] = fields
	v := binary.BigEndian.AppendUint32(nil, d.id)
	v = putVarlen(v, []byte(FileNote(fw.o.Version)))
	fw.data(d, fileNoteID, v)
}

// ifName writes an interface-name options record ("" withdraws the name).
func (fw *FileWriter) ifName(d *fileDom, ifx uint32, name string) {
	if len(name) > maxIfName {
		name = name[:maxIfName]
	}
	d.tdef[fileIfTmplID] = []TemplateField{{ID: ieInIf, Length: 4}, {ID: ieIfName, Length: Varlen}}
	v := binary.BigEndian.AppendUint32(nil, ifx)
	v = putVarlen(v, []byte(name))
	fw.data(d, fileIfTmplID, v)
	if name == "" {
		delete(d.ifNames, ifx)
	} else {
		d.ifNames[ifx] = name
	}
}

// data appends one data record of template tid to the domain's message,
// writing the template first when the file hasn't had it, and starting a new
// message when this one is full.
func (fw *FileWriter) data(d *fileDom, tid uint16, vals []byte) {
	fields := d.tdef[tid]
	options := tid == fileIfTmplID || tid == fileNoteID
	need := len(vals)
	if d.setOpen < 0 || d.setTID != tid {
		need += 4
	}
	if !d.inMsg[tid] {
		need += templateBytes(fields) + 2*boolInt(options)
	}
	if len(d.buf) > 0 && len(d.buf)+need > maxMessage {
		fw.flush(d)
	}
	if len(d.buf) == 0 {
		d.buf = make([]byte, ipfixHeader, 8192)
		d.setOpen = -1
	}
	if !d.inMsg[tid] {
		fw.closeSet(d)
		setID := uint16(2)
		if options {
			setID = 3
		}
		s := len(d.buf)
		d.buf = binary.BigEndian.AppendUint16(d.buf, setID)
		d.buf = append(d.buf, 0, 0)
		d.buf = binary.BigEndian.AppendUint16(d.buf, tid)
		d.buf = binary.BigEndian.AppendUint16(d.buf, uint16(len(fields)))
		if options {
			d.buf = binary.BigEndian.AppendUint16(d.buf, 1)
		}
		for _, f := range fields {
			id := f.ID
			if f.PEN != 0 {
				id |= 0x8000
			}
			d.buf = binary.BigEndian.AppendUint16(d.buf, id)
			d.buf = binary.BigEndian.AppendUint16(d.buf, f.Length)
			if f.PEN != 0 {
				d.buf = binary.BigEndian.AppendUint32(d.buf, f.PEN)
			}
		}
		binary.BigEndian.PutUint16(d.buf[s+2:], uint16(len(d.buf)-s))
		d.inMsg[tid] = true
	}
	if d.setOpen < 0 || d.setTID != tid {
		fw.closeSet(d)
		d.setOpen, d.setTID = len(d.buf), tid
		d.buf = binary.BigEndian.AppendUint16(d.buf, tid)
		d.buf = append(d.buf, 0, 0)
	}
	d.buf = append(d.buf, vals...)
	d.nrec++
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (fw *FileWriter) closeSet(d *fileDom) {
	if d.setOpen >= 0 {
		binary.BigEndian.PutUint16(d.buf[d.setOpen+2:], uint16(len(d.buf)-d.setOpen))
		d.setOpen = -1
	}
}

// flush writes the domain's message.
func (fw *FileWriter) flush(d *fileDom) {
	if len(d.buf) == 0 {
		return
	}
	fw.closeSet(d)
	b := d.buf
	binary.BigEndian.PutUint16(b[0:], IPFIX)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	binary.BigEndian.PutUint32(b[4:], fw.export)
	binary.BigEndian.PutUint32(b[8:], d.seq)
	binary.BigEndian.PutUint32(b[12:], d.id)
	if fw.err == nil {
		if _, err := fw.w.Write(b); err != nil {
			fw.fail(err)
		}
	}
	d.seq += d.nrec
	d.nrec = 0
	d.buf = d.buf[:0]
	d.setOpen = -1
}

// Close writes what's buffered. It doesn't close the underlying writer.
func (fw *FileWriter) Close() error {
	for _, id := range fw.order {
		fw.flush(fw.doms[id])
	}
	return fw.err
}

// FileReadOptions configures ReadFile.
type FileReadOptions struct {
	RuleIDIEs []IEKey // fill rule_id as the collector did
}

// ErrFileMalformed is ReadFile's error for a file that isn't valid IPFIX (or
// whose data has no template).
var ErrFileMalformed = errors.New("flow: malformed IPFIX file")

// ReadFile reads an IPFIX file (as FileWriter writes them) and calls fn with
// each record (fn mustn't keep r itself; see Collector.Decode). The note and
// interface names are options data, not records.
func ReadFile(r io.Reader, o FileReadOptions, fn func(*Record)) error {
	// A file is one session: every template stays (no caps, no timeout).
	c := NewCollector(Options{RuleIDIEs: o.RuleIDIEs, TemplateTimeout: 1<<63 - 1, PendingBytes: 1, PendingPerExporter: 1,
		MaxTemplatesPerKey: 1 << 16, MaxTemplates: 1 << 30})
	c.fileMode = true
	from := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	var bad int
	hdr := make([]byte, ipfixHeader)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("%w: %v", ErrFileMalformed, err)
		}
		if binary.BigEndian.Uint16(hdr) != IPFIX {
			return fmt.Errorf("%w: a message with version %d", ErrFileMalformed, binary.BigEndian.Uint16(hdr))
		}
		n := int(binary.BigEndian.Uint16(hdr[2:]))
		if n < ipfixHeader {
			return fmt.Errorf("%w: a message of %d bytes", ErrFileMalformed, n)
		}
		m := make([]byte, n)
		copy(m, hdr)
		if _, err := io.ReadFull(r, m[ipfixHeader:]); err != nil {
			return fmt.Errorf("%w: %v", ErrFileMalformed, err)
		}
		at := time.Unix(int64(binary.BigEndian.Uint32(hdr[4:])), 0)
		c.Decode(Packet{Data: m, From: from, Received: at}, fn, func(*RawSet) { bad++ })
	}
	if bad > 0 {
		return fmt.Errorf("%w: %d sets couldn't be decoded", ErrFileMalformed, bad)
	}
	return nil
}

// fileFixup applies the file's conventions to a record ReadFile decoded: the
// received time from the first collectionTimeMilliseconds, and received-time
// records recognised by their kept exporter times (or by having no time).
func fileFixup(r *Record) {
	for i, e := range r.Extras {
		if e.PEN == 0 && e.ID == ieCollectionTimeMs && len(e.Value) == 8 {
			r.Received = int64(binary.BigEndian.Uint64(e.Value))
			r.Extras = slices.Delete(slices.Clone(r.Extras), i, i+1)
			break
		}
	}
	if len(r.Extras) == 0 {
		r.Extras = nil
	}
	if r.TimeSource == TimeReceived {
		// No time at all: the start and end are the received time.
		r.Start, r.End = r.Received, r.Received
		return
	}
	if hasTimeExtra(r) {
		r.TimeSource = TimeReceived
	}
}
