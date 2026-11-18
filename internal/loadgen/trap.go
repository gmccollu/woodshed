package loadgen

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// The trap generator's OIDs, under 32473, IANA's enterprise number for
// documentation (RFC 5612): nothing real uses them.
var (
	TrapEnterprise = snmp.OID{1, 3, 6, 1, 4, 1, 32473, 1}
	// DefaultTrapOID is the snmpTrapOID of a test trap (enterprise-specific 1).
	DefaultTrapOID = snmp.OID{1, 3, 6, 1, 4, 1, 32473, 1, 0, 1}
	// SeqOID is the varbind that carries the run tag and sequence number
	// ("seq=<run>:<n>", an OCTET STRING), so verifyseq can count delivery.
	SeqOID = snmp.OID{1, 3, 6, 1, 4, 1, 32473, 1, 1, 1, 0}
	// FillerOID is the prefix of the extra varbinds (--varbinds): FillerOID.<i>.
	FillerOID = snmp.OID{1, 3, 6, 1, 4, 1, 32473, 1, 1, 2}
)

// DefaultInformTimeout is how long an inform waits for its Response.
const DefaultInformTimeout = 2 * time.Second

// TrapOptions configures Send with Proto "trap" (SPEC §11.6). Secrets are bytes
// the caller read from a file or the environment, never from a command line.
type TrapOptions struct {
	Version string // "1", "2c" (default) or "3"
	Inform  bool   // send InformRequests and wait for each Response (v2c, v3)

	Community []byte // v1 and v2c (default "public")

	// v3: the user and its protocols. The level follows: authPriv with Priv,
	// authNoPriv with Auth only, noAuthNoPriv otherwise.
	User     string
	Auth     snmp.AuthProtocol
	Priv     snmp.PrivProtocol
	KeyExt   snmp.KeyExt
	AuthPass []byte
	PrivPass []byte
	// EngineID: for traps the sender's own engine ID (default a random one); for
	// informs the receiver's (default: discovered, RFC 3414 §4).
	EngineID []byte

	TrapOID  snmp.OID      // default DefaultTrapOID
	Varbinds int           // varbinds after the header, the sequence one first (default 1)
	Timeout  time.Duration // informs: the wait for each Response (default DefaultInformTimeout)
}

// InformStats are an inform run's results.
type InformStats struct {
	Answered int
	TimedOut int
	// Resent counts informs sent again after a Report (a time-window resync or
	// a new engine ID); each is answered or times out once.
	Resent  int
	Reports int
	RTTs    []time.Duration // per answered inform, in answer order
}

// Percentile returns the p-th percentile round trip (0 < p ≤ 100).
func (s *InformStats) Percentile(p float64) time.Duration {
	if len(s.RTTs) == 0 {
		return 0
	}
	r := slices.Clone(s.RTTs)
	slices.Sort(r)
	i := int(float64(len(r))*p/100+0.999999) - 1
	return r[min(max(i, 0), len(r)-1)]
}

func (t *TrapOptions) level() snmp.Level {
	switch {
	case t.Priv != snmp.PrivNone:
		return snmp.AuthPriv
	case t.Auth != snmp.AuthNone:
		return snmp.AuthNoPriv
	}
	return snmp.NoAuthNoPriv
}

// Describe is the run's protocol for messages: "SNMPv2c", "SNMPv3 authPriv sha-256/aes-128".
func (t *TrapOptions) Describe() string {
	s := "SNMPv" + t.Version
	if t.Version == "3" {
		s += " " + t.level().String()
		if t.Auth != snmp.AuthNone {
			s += " " + t.Auth.String()
			if t.Priv != snmp.PrivNone {
				s += "/" + t.Priv.String()
				if t.Priv == snmp.PrivAES192 || t.Priv == snmp.PrivAES256 {
					s += " (" + t.KeyExt.String() + " key extension)"
				}
			}
		}
	}
	return s
}

func (t *TrapOptions) defaults() error {
	switch t.Version {
	case "":
		t.Version = "2c"
	case "1", "2c", "3":
	default:
		return fmt.Errorf("loadgen: SNMP version %q (1, 2c or 3)", t.Version)
	}
	if t.Inform && t.Version == "1" {
		return errors.New("loadgen: SNMPv1 has no informs")
	}
	if t.Version != "3" {
		if t.Community == nil {
			t.Community = []byte("public")
		}
		if t.User != "" || t.Auth != snmp.AuthNone || t.Priv != snmp.PrivNone || t.EngineID != nil {
			return errors.New("loadgen: a user, protocols and an engine ID are for SNMPv3")
		}
	} else {
		if t.User == "" {
			return errors.New("loadgen: SNMPv3 needs a user name")
		}
		u := snmp.User{Name: t.User, Level: t.level(), Auth: t.Auth, Priv: t.Priv, KeyExt: t.KeyExt, AuthPass: t.AuthPass, PrivPass: t.PrivPass}
		if err := u.Validate(); err != nil {
			return fmt.Errorf("loadgen: %w", err)
		}
	}
	if t.TrapOID == nil {
		t.TrapOID = DefaultTrapOID
	}
	if t.Varbinds <= 0 {
		t.Varbinds = 1
	}
	if t.Varbinds > 1000 {
		return errors.New("loadgen: at most 1000 varbinds")
	}
	if t.Timeout <= 0 {
		t.Timeout = DefaultInformTimeout
	}
	return nil
}

// trapSender sends one run's traps or informs on one connected UDP socket.
type trapSender struct {
	o     *SendOptions
	t     *TrapOptions
	c     net.Conn
	start time.Time
	agent []byte // v1 agent-addr: the local IPv4 address

	mu       sync.Mutex
	nextID   int64
	salt     uint64
	engineID []byte // the authoritative engine (ours for traps, the receiver's for informs)
	boots    int64
	timeBase int64     // the authoritative engine's time at timeAt
	timeAt   time.Time // when timeBase was learned
	sec      snmp.Security
	client   *snmp.USM // decodes Responses and Reports
	pending  map[int64]*pendingInform
	stats    InformStats
	readErr  error
	ref      refusals // shared by the sender and the reply reader
}

type pendingInform struct {
	seq    int
	sent   time.Time
	resent bool
}

func randUint64() uint64 {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

func sendTrap(ctx context.Context, o *SendOptions, res *SendResult) error {
	t := &o.Trap
	d := o.dialer("udp")
	c, err := d.DialContext(ctx, "udp", o.Addr)
	if err != nil {
		return fmt.Errorf("loadgen: %w", err)
	}
	defer c.Close()
	s := &trapSender{o: o, t: t, c: c, start: time.Now(), pending: map[int64]*pendingInform{},
		nextID: int64(randUint64() & 0x3fffffff), salt: randUint64(), agent: []byte{0, 0, 0, 0}}
	if la, ok := c.LocalAddr().(*net.UDPAddr); ok {
		if ip4 := la.IP.To4(); ip4 != nil {
			s.agent = ip4
		}
	}
	if t.Version == "3" {
		if err := s.setupV3(ctx); err != nil {
			return err
		}
	}
	var wg sync.WaitGroup
	readCtx, stopRead := context.WithCancel(ctx)
	if t.Inform {
		wg.Add(1)
		go func() { defer wg.Done(); s.readReplies(readCtx) }()
	}
	err = s.sendAll(ctx, res)
	if t.Inform {
		s.waitPending(ctx)
	}
	stopRead()
	wg.Wait()
	res.Refused = s.ref.result()
	if t.Inform {
		s.mu.Lock()
		st := s.stats
		st.RTTs = slices.Clone(st.RTTs)
		st.TimedOut += len(s.pending)
		rerr := s.readErr
		s.mu.Unlock()
		res.Informs = &st
		if err == nil && rerr != nil {
			err = rerr
		}
	}
	return err
}

// setupV3 sets the authoritative engine and the keys: the sender's own engine
// for traps; for informs the receiver's, discovered unless given.
func (s *trapSender) setupV3(ctx context.Context) error {
	t := s.t
	s.boots, s.timeAt = 1, s.start
	switch {
	case !t.Inform:
		s.engineID = t.EngineID
		if s.engineID == nil {
			s.engineID = snmp.NewEngineID()
		}
	case t.EngineID != nil:
		// The receiver's boots and time are learned from its first Report.
		s.engineID, s.boots = t.EngineID, 0
	default:
		if err := s.discover(ctx); err != nil {
			return err
		}
	}
	if err := s.localize(); err != nil {
		return err
	}
	// The client side decodes the receiver's Responses and Reports: as the
	// receiver's engine is authoritative there, any engine ID of ours will do.
	s.client = snmp.NewUSM(&snmp.Engine{ID: snmp.NewEngineID(), Boots: 1, Start: s.start})
	return s.client.SetUsers([]snmp.User{{Name: t.User, Level: snmp.NoAuthNoPriv, Auth: t.Auth, Priv: t.Priv, KeyExt: t.KeyExt, AuthPass: t.AuthPass, PrivPass: t.PrivPass}})
}

func (s *trapSender) localize() error {
	t := s.t
	k, err := snmp.LocalizeKeys(t.Auth, t.Priv, t.KeyExt, t.AuthPass, t.PrivPass, s.engineID)
	if err != nil {
		return fmt.Errorf("loadgen: %w", err)
	}
	s.sec = snmp.Security{Auth: t.Auth, Priv: t.Priv, Keys: k}
	return nil
}

// discover sends RFC 3414 §4 discovery probes until a Report gives the
// receiver's engine ID, boots and time.
func (s *trapSender) discover(ctx context.Context) error {
	buf := make([]byte, 65536)
	for try := 0; try < 3; try++ {
		id := s.newID()
		probe, err := snmp.EncodeV3(snmp.V3Header{MsgID: id, Reportable: true, Level: snmp.NoAuthNoPriv}, snmp.Security{}, 0,
			snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUGet, RequestID: id}))
		if err != nil {
			return err
		}
		if _, err := s.c.Write(probe); err != nil {
			return s.writeErr(err)
		}
		deadline := time.Now().Add(s.t.Timeout)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			_ = s.c.SetReadDeadline(deadline)
			n, err := s.c.Read(buf)
			if err != nil {
				if isConnRefused(err) {
					return fmt.Errorf("loadgen: %s: nothing is listening (connection refused)", s.o.Addr)
				}
				break
			}
			m := snmp.Decode(buf[:n:n], nil, time.Now())
			if m.HeaderRead && m.MsgID == id && len(m.EngineID) > 0 {
				s.engineID = append([]byte(nil), m.EngineID...)
				s.boots, s.timeBase, s.timeAt = m.EngineBoots, m.EngineTime, time.Now()
				_ = s.c.SetReadDeadline(time.Time{})
				return nil
			}
		}
	}
	_ = s.c.SetReadDeadline(time.Time{})
	return fmt.Errorf("loadgen: no discovery Report from %s (is it an SNMPv3 receiver?)", s.o.Addr)
}

func (s *trapSender) newID() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID = (s.nextID + 1) & 0x7fffffff
	return s.nextID
}

func (s *trapSender) writeErr(err error) error {
	if isConnRefused(err) {
		return fmt.Errorf("loadgen: %s: nothing is listening (connection refused)", s.o.Addr)
	}
	return fmt.Errorf("loadgen: %w", err)
}

func (s *trapSender) sendAll(ctx context.Context, res *SendResult) error {
	o := s.o
	p := pacer{start: time.Now(), rate: o.Rate}
	for res.Sent < o.Count {
		for due := p.due(o.Count); res.Sent < due; {
			seq := o.FirstSeq + res.Sent
			if err := s.send(seq, false); err != nil {
				if isNoBufs(err) {
					res.Backpressure++
					time.Sleep(50 * time.Microsecond)
					if ctx.Err() != nil {
						return ctx.Err()
					}
					continue
				}
				// A refusal after the receiver had been listening (a restart):
				// counted, and this one sent again (RefusedGrace).
				if isConnRefused(err) && !s.ref.refused(time.Now()) {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					continue
				}
				return s.writeErr(err)
			}
			s.ref.wrote(time.Now())
			res.Sent++
		}
		if err := p.wait(ctx, res.Sent); err != nil {
			return err
		}
	}
	return nil
}

// send builds and sends the message for seq; informs are registered as pending.
func (s *trapSender) send(seq int, resend bool) error {
	id := s.newID()
	b, err := s.build(seq, id)
	if err != nil {
		return err
	}
	if s.t.Inform {
		s.mu.Lock()
		s.pending[id] = &pendingInform{seq: seq, sent: time.Now(), resent: resend}
		s.mu.Unlock()
	}
	if _, err := s.c.Write(b); err != nil {
		if s.t.Inform {
			s.mu.Lock()
			delete(s.pending, id)
			s.mu.Unlock()
		}
		return err
	}
	return nil
}

func (s *trapSender) varbinds(seq int, now time.Time) (uptime uint64, vbs []snmp.Varbind) {
	t := s.t
	uptime = uint64(now.Sub(s.start) / (10 * time.Millisecond))
	text := SeqTag(s.o.RunID) + fmt.Sprint(seq)
	if s.o.Message != "" {
		text += " " + s.o.Message
	}
	vbs = append(vbs, snmp.Varbind{OID: SeqOID, Value: snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(text)}})
	for i := 1; i < t.Varbinds; i++ {
		o := append(FillerOID[:len(FillerOID):len(FillerOID)], uint32(i))
		var v snmp.Value
		switch i % 8 {
		case 1:
			v = snmp.Value{Kind: snmp.KindInteger, Int: int64(seq) * int64(i)}
		case 2:
			v = snmp.Value{Kind: snmp.KindOctetString, Bytes: fmt.Appendf(nil, "filler %d of message %d", i, seq)}
		case 3:
			v = snmp.Value{Kind: snmp.KindCounter32, Uint: uint64(seq) & 0xffffffff}
		case 4:
			v = snmp.Value{Kind: snmp.KindGauge32, Uint: uint64(i)}
		case 5:
			v = snmp.Value{Kind: snmp.KindTimeTicks, Uint: uptime}
		case 6:
			v = snmp.Value{Kind: snmp.KindOID, OID: t.TrapOID}
		case 7:
			v = snmp.Value{Kind: snmp.KindIPAddress, Bytes: []byte{192, 0, 2, byte(i)}}
		default:
			v = snmp.Value{Kind: snmp.KindCounter64, Uint: uint64(seq) << 32}
		}
		vbs = append(vbs, snmp.Varbind{OID: o, Value: v})
	}
	return uptime, vbs
}

func (s *trapSender) build(seq int, id int64) ([]byte, error) {
	t := s.t
	now := time.Now()
	uptime, vbs := s.varbinds(seq, now)
	if t.Version == "1" {
		ent, gen, spec := snmp.V1Fields(t.TrapOID, TrapEnterprise)
		return snmp.EncodeCommunity(snmp.V1, t.Community, snmp.EncodePDU(&snmp.PDU{
			Type: snmp.PDUV1Trap, Enterprise: ent, AgentAddr: s.agent, Generic: gen, Specific: spec, Timestamp: uptime, Varbinds: vbs,
		})), nil
	}
	typ := snmp.PDUTrap
	if t.Inform {
		typ = snmp.PDUInform
	}
	all := append([]snmp.Varbind{
		{OID: snmp.OIDSysUpTime, Value: snmp.Value{Kind: snmp.KindTimeTicks, Uint: uptime}},
		{OID: snmp.OIDSnmpTrapOID, Value: snmp.Value{Kind: snmp.KindOID, OID: t.TrapOID}},
	}, vbs...)
	pdu := snmp.EncodePDU(&snmp.PDU{Type: typ, RequestID: id, Varbinds: all})
	if t.Version == "2c" {
		return snmp.EncodeCommunity(snmp.V2c, t.Community, pdu), nil
	}
	s.mu.Lock()
	h := snmp.V3Header{
		MsgID: id, Level: t.level(), Reportable: t.Inform,
		EngineID: s.engineID, EngineBoots: s.boots, EngineTime: s.timeBase + int64(now.Sub(s.timeAt)/time.Second),
		User: []byte(t.User), ContextEngineID: s.engineID,
	}
	sec := s.sec
	s.salt++
	salt := s.salt
	s.mu.Unlock()
	return snmp.EncodeV3(h, sec, salt, pdu)
}

// readReplies matches Responses to pending informs, resyncs on Reports, and
// expires informs that waited too long.
func (s *trapSender) readReplies(ctx context.Context) {
	buf := make([]byte, 65536)
	for ctx.Err() == nil {
		_ = s.c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		n, err := s.c.Read(buf)
		now := time.Now()
		s.expire(now)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if isConnRefused(err) && s.ref.refused(time.Now()) {
				s.mu.Lock()
				s.readErr = notListening(s.o.Addr)
				s.mu.Unlock()
				return
			}
			continue
		}
		s.handleReply(buf[:n:n], now)
	}
}

func (s *trapSender) handleReply(b []byte, now time.Time) {
	m := snmp.Decode(b, s.client, now)
	var id int64
	var pdu *snmp.PDU
	switch m.Version {
	case snmp.V2c:
		if m.PDU == nil {
			return
		}
		pdu, id = m.PDU, m.PDU.RequestID
	case snmp.V3:
		if !m.HeaderRead {
			return
		}
		pdu, id = m.PDU, m.MsgID
		if pdu == nil && m.Level == snmp.NoAuthNoPriv {
			pdu, _ = m.PlainPDU() // a Report to an empty or unknown user
		}
		if pdu == nil {
			return
		}
	default:
		return
	}
	s.mu.Lock()
	p := s.pending[id]
	if p == nil {
		s.mu.Unlock()
		return
	}
	switch pdu.Type {
	case snmp.PDUResponse:
		delete(s.pending, id)
		s.stats.Answered++
		s.stats.RTTs = append(s.stats.RTTs, now.Sub(p.sent))
		s.mu.Unlock()
	case snmp.PDUReport:
		s.stats.Reports++
		delete(s.pending, id)
		// Resync to the receiver's engine (its boots and time, or a new ID) and
		// send the inform once more.
		changed := !equalBytes(m.EngineID, s.engineID)
		if len(m.EngineID) > 0 {
			s.engineID = append([]byte(nil), m.EngineID...)
			s.boots, s.timeBase, s.timeAt = m.EngineBoots, m.EngineTime, now
		}
		retry := !p.resent
		if retry {
			s.stats.Resent++
		} else {
			s.stats.TimedOut++
		}
		s.mu.Unlock()
		if changed {
			s.mu.Lock()
			err := s.localize()
			s.mu.Unlock()
			if err != nil {
				return
			}
		}
		if retry {
			_ = s.send(p.seq, true)
		}
	default:
		s.mu.Unlock()
	}
}

func equalBytes(a, b []byte) bool { return string(a) == string(b) }

func (s *trapSender) expire(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, p := range s.pending {
		if now.Sub(p.sent) > s.t.Timeout {
			delete(s.pending, id)
			s.stats.TimedOut++
		}
	}
}

// waitPending waits until every inform is answered or has timed out (it
// expires them itself, so it ends even when the reader has stopped).
func (s *trapSender) waitPending(ctx context.Context) {
	for ctx.Err() == nil {
		s.expire(time.Now())
		s.mu.Lock()
		n, stopped := len(s.pending), s.readErr != nil
		s.mu.Unlock()
		if n == 0 || stopped {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}
