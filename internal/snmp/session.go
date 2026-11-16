package snmp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync/atomic"
	"time"
)

// A Session is the requester's state for one polled agent (SPEC §12.2): its
// version and credential, and for v3 the agent's engine ID, boots and clock
// as last learned (RFC 3414 §4 discovery, then time synchronization from an
// authenticated Report). It sends through a Transport, one request at a time,
// retrying on timeout, halving on tooBig, and rediscovering once when a Report
// says the engine ID or the time window is stale.
//
// A Session isn't safe for concurrent use: the poller keeps one request in
// flight per device.

// Transport sends a request and waits for its reply.
type Transport interface {
	// Exchange sends req and returns the first datagram from the target whose
	// ID (PeekID) is id, or ErrTimeout after timeout. The transport drops
	// (and counts) datagrams from any other address or with another ID.
	Exchange(ctx context.Context, req []byte, id int64, timeout time.Duration) ([]byte, error)
}

// ErrTimeout is a Transport's "no answer in time".
var ErrTimeout = errors.New("snmp: no answer")

// ErrUnreachable is a Transport's "the send failed: no route" (a host or
// network unreachable error from the OS).
var ErrUnreachable = errors.New("snmp: unreachable")

// Request failure statuses (the poll record's status=, SPEC §12.3).
const (
	FailTimeout       = "timeout"
	FailUnreachable   = "unreachable"
	FailAuth          = "auth_failed"
	FailUnknownUser   = "unknown_user"
	FailUnknownEngine = "unknown_engine"
	FailNotInTime     = "not_in_time"
	FailDecrypt       = "decrypt_failed"
	FailError         = "error"
)

// RequestError is a failed request: a status and the detail (never a secret).
type RequestError struct {
	Status string
	Detail string
}

func (e *RequestError) Error() string { return e.Status + ": " + e.Detail }

// FailStatus is err's status ("error" for an error that isn't a RequestError).
func FailStatus(err error) string {
	var re *RequestError
	if errors.As(err, &re) {
		return re.Status
	}
	return FailError
}

// EngineInfo is an agent's engine as the session knows it: its ID, boots, and
// time at At (the local clock, monotonic).
type EngineInfo struct {
	ID    []byte
	Boots int64
	Time  int64
	At    time.Time
}

// Known reports whether discovery has run.
func (e EngineInfo) Known() bool { return len(e.ID) > 0 }

// timeAt estimates the agent's engine time at now.
func (e EngineInfo) timeAt(now time.Time) int64 {
	t := e.Time + int64(now.Sub(e.At)/time.Second)
	return min(max(t, 0), maxBoots)
}

// SessionConfig configures a Session.
type SessionConfig struct {
	Version   Version
	Community []byte // v1, v2c
	User      *User  // v3; its Level is the level requests are sent at
	Context   []byte // v3 context name ("" by default)
	Timeout   time.Duration
	Retries   int
	// Now is the clock (time.Now when nil); its readings carry the monotonic
	// clock, which round-trip times and the engine time estimate use.
	Now func() time.Time
	// Engine is a cached engine (from the index), so a normal cycle needs no
	// discovery.
	Engine EngineInfo
}

// Session is one agent's requester state.
type Session struct {
	cfg SessionConfig
	tr  Transport
	now func() time.Time
	eng EngineInfo
	// pub is eng for readers on other goroutines (Engine): the session's own
	// requests read and write eng; every write publishes a copy here.
	pub  atomic.Pointer[EngineInfo]
	keys Security // v3, localized to eng.ID
	kfor []byte   // the engine ID keys is localized to
	salt atomic.Uint64

	lastRTT   time.Duration
	bootsUp   bool  // engineBoots went up since TakeBootsUp
	prevBoots int64 // the boots before the rise
	requests  int
}

// NewSession checks the configuration and returns a session.
func NewSession(cfg SessionConfig, tr Transport) (*Session, error) {
	switch cfg.Version {
	case V1, V2c:
		if len(cfg.Community) == 0 {
			return nil, errors.New("snmp: a v1 or v2c session needs a community")
		}
	case V3:
		if cfg.User == nil {
			return nil, errors.New("snmp: a v3 session needs a user")
		}
		if err := cfg.User.Validate(); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("snmp: unsupported version %s", cfg.Version)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	if cfg.Retries < 0 {
		cfg.Retries = 0
	}
	s := &Session{cfg: cfg, tr: tr, now: cfg.Now, eng: cfg.Engine}
	s.publishEngine()
	if s.now == nil {
		s.now = time.Now
	}
	s.salt.Store(uint64(RandomID())<<32 | uint64(RandomID()))
	return s, nil
}

// Version is the session's SNMP version.
func (s *Session) Version() Version { return s.cfg.Version }

// Engine is the agent's engine as last learned (v3).
// Safe to call from any goroutine.
func (s *Session) Engine() EngineInfo {
	if p := s.pub.Load(); p != nil {
		return *p
	}
	return EngineInfo{}
}

// publishEngine makes eng visible to Engine.
func (s *Session) publishEngine() {
	e := s.eng
	e.ID = append([]byte(nil), e.ID...)
	s.pub.Store(&e)
}

// LastRTT is the last answered request's round trip.
func (s *Session) LastRTT() time.Duration { return s.lastRTT }

// Requests counts the requests sent (retries included).
func (s *Session) Requests() int { return s.requests }

// TakeBootsUp reports whether the agent's engineBoots went up since the last
// call (an agent restart, SPEC §12.2.2), with the boots before and after.
func (s *Session) TakeBootsUp() (bool, int64, int64) {
	up, prev := s.bootsUp, s.prevBoots
	s.bootsUp = false
	return up, prev, s.eng.Boots
}

// level is the level v3 requests go at.
func (s *Session) level() Level {
	if s.cfg.User == nil {
		return NoAuthNoPriv
	}
	if s.cfg.User.Level != 0 {
		return s.cfg.User.Level
	}
	return s.cfg.User.MaxLevel()
}

// localize makes the keys for the agent's engine ID: from the user's keys
// stored for that engine, or from its passphrases.
func (s *Session) localize(engineID []byte) error {
	if s.kfor != nil && equalBytes(s.kfor, engineID) {
		return nil
	}
	u := s.cfg.User
	sec := Security{Auth: u.Auth, Priv: u.Priv}
	if s.level() == NoAuthNoPriv {
		s.keys, s.kfor = sec, append([]byte(nil), engineID...)
		return nil
	}
	if len(u.EngineKeys) > 0 {
		for _, ek := range u.EngineKeys {
			if equalBytes(ek.EngineID, engineID) {
				sec.Keys = ek.Keys
				s.keys, s.kfor = sec, append([]byte(nil), engineID...)
				return nil
			}
		}
		return &RequestError{Status: FailUnknownEngine, Detail: fmt.Sprintf(
			"user %q has keys stored only for other engine IDs; add this agent's engine ID %x to the user", u.Name, engineID)}
	}
	k, err := LocalizeKeys(u.Auth, u.Priv, u.KeyExt, u.AuthPass, u.PrivPass, engineID)
	if err != nil {
		return &RequestError{Status: FailError, Detail: err.Error()}
	}
	sec.Keys = k
	s.keys, s.kfor = sec, append([]byte(nil), engineID...)
	return nil
}

// exchange sends one encoded request, retrying on timeout, and decodes the
// reply. build is called once per attempt (v3 needs the time at send).
func (s *Session) exchange(ctx context.Context, build func() ([]byte, int64, error)) (*Message, error) {
	for attempt := 0; attempt <= s.cfg.Retries; attempt++ {
		req, id, err := build()
		if err != nil {
			return nil, &RequestError{Status: FailError, Detail: err.Error()}
		}
		s.requests++
		start := s.now()
		raw, err := s.tr.Exchange(ctx, req, id, s.cfg.Timeout)
		if err != nil {
			if errors.Is(err, ErrTimeout) {
				continue
			}
			if errors.Is(err, ErrUnreachable) {
				return nil, &RequestError{Status: FailUnreachable, Detail: err.Error()}
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, &RequestError{Status: FailError, Detail: err.Error()}
		}
		s.lastRTT = s.now().Sub(start)
		m := DecodeResponse(raw, s.keyFn)
		return m, nil
	}
	n := s.cfg.Retries
	detail := fmt.Sprintf("no answer after %d retries", n)
	if n == 1 {
		detail = "no answer after 1 retry"
	} else if n == 0 {
		detail = "no answer"
	}
	return nil, &RequestError{Status: FailTimeout, Detail: detail}
}

func (s *Session) keyFn(engineID []byte) (Security, bool) {
	if s.kfor == nil || !equalBytes(engineID, s.kfor) {
		return Security{}, false
	}
	return s.keys, true
}

// Discover runs RFC 3414 §4's discovery: a probe with an empty engine ID; the
// Report gives the engine ID, boots and time. Then, for an authenticated
// user, it synchronizes the time window with one authenticated request (the
// agent's notInTimeWindows Report carries its clock), unless the first
// Report's clock was already accepted.
func (s *Session) Discover(ctx context.Context) (EngineInfo, error) {
	if s.cfg.Version != V3 {
		return EngineInfo{}, errors.New("snmp: discovery is for SNMPv3")
	}
	m, err := s.exchange(ctx, func() ([]byte, int64, error) {
		id := RandomID()
		b, err := EncodeDiscovery(id, RandomID())
		return b, int64(id), err
	})
	if err != nil {
		return EngineInfo{}, err
	}
	if m.Status != StatusOK || m.PDU == nil || m.PDU.Type != PDUReport {
		return EngineInfo{}, &RequestError{Status: FailError, Detail: "the discovery probe got no Report: " + m.describe()}
	}
	if len(m.EngineID) == 0 {
		return EngineInfo{}, &RequestError{Status: FailError, Detail: "the discovery Report has no engine ID"}
	}
	prev := s.eng
	s.setEngine(EngineInfo{ID: append([]byte(nil), m.EngineID...), Boots: m.EngineBoots, Time: m.EngineTime, At: s.now()}, prev)
	if err := s.localize(s.eng.ID); err != nil {
		return s.eng, err
	}
	if s.level() >= AuthNoPriv && (m.EngineBoots == 0 && m.EngineTime == 0) {
		// The agent didn't give its clock: one authenticated request gets the
		// notInTimeWindows Report that does.
		if _, err := s.request(ctx, Request{Kind: ReqGet, OIDs: []OID{OIDSysUpTime}}, false); err != nil {
			var re *RequestError
			if !errors.As(err, &re) || re.Status != FailNotInTime {
				return s.eng, err
			}
		}
	}
	return s.eng, nil
}

// setEngine adopts an engine; boots higher than before for the same engine
// ID mark an agent restart.
func (s *Session) setEngine(e EngineInfo, prev EngineInfo) {
	if prev.Known() && equalBytes(prev.ID, e.ID) && e.Boots > prev.Boots {
		if !s.bootsUp {
			s.prevBoots = prev.Boots
		}
		s.bootsUp = true
	}
	s.eng = e
	s.publishEngine()
}

// reportFailure maps a Report's usmStats counter to a failure.
func reportFailure(m *Message, user string) *RequestError {
	o := m.PDU.reportOID()
	switch {
	case o.Equal(OIDUsmStatsUnknownEngineIDs):
		return &RequestError{Status: FailUnknownEngine, Detail: fmt.Sprintf("the agent doesn't know engine ID %x as its own", m.EngineID)}
	case o.Equal(OIDUsmStatsNotInTimeWindows):
		return &RequestError{Status: FailNotInTime, Detail: "the request was outside the agent's time window"}
	case o.Equal(OIDUsmStatsUnknownUserNames):
		return &RequestError{Status: FailUnknownUser, Detail: fmt.Sprintf("the agent doesn't know user %q", user)}
	case o.Equal(OIDUsmStatsWrongDigests):
		return &RequestError{Status: FailAuth, Detail: "wrong digest: a wrong authentication passphrase or protocol"}
	case o.Equal(OIDUsmStatsDecryptionErrors):
		return &RequestError{Status: FailDecrypt, Detail: "the agent couldn't decrypt the request: a wrong privacy passphrase, protocol or key extension"}
	case o.Equal(OIDUsmStatsUnsupportedSecLevels):
		return &RequestError{Status: FailError, Detail: "the agent doesn't support this security level for the user"}
	}
	return &RequestError{Status: FailError, Detail: "a Report: " + o.String()}
}

// request sends one request PDU and returns the Response. With retryReport, a
// stale engine ID or time window starts discovery again once, then retries.
func (s *Session) request(ctx context.Context, r Request, retryReport bool) (*PDU, error) {
	if s.cfg.Version == V3 && !s.eng.Known() {
		if _, err := s.Discover(ctx); err != nil {
			return nil, err
		}
	}
	if s.cfg.Version == V3 {
		if err := s.localize(s.eng.ID); err != nil {
			return nil, err
		}
	}
	for round := 0; ; round++ {
		reqID := RandomID()
		r.RequestID = reqID
		var msgID int32
		m, err := s.exchange(ctx, func() ([]byte, int64, error) {
			if s.cfg.Version != V3 {
				b, err := EncodeRequest(s.cfg.Version, s.cfg.Community, r)
				return b, int64(reqID), err
			}
			msgID = RandomID()
			b, err := EncodeRequestV3(RequestV3{MsgID: msgID, Level: s.level(), EngineID: s.eng.ID, EngineBoots: s.eng.Boots,
				EngineTime: s.eng.timeAt(s.now()), User: []byte(s.cfg.User.Name), ContextName: s.cfg.Context},
				s.keys, s.salt.Add(1), r)
			return b, int64(msgID), err
		})
		if err != nil {
			return nil, err
		}
		if err := s.replyStatus(m); err != nil {
			return nil, err
		}
		if m.Version != s.cfg.Version {
			return nil, &RequestError{Status: FailError, Detail: fmt.Sprintf("the reply is SNMPv%s, the request SNMPv%s", m.Version, s.cfg.Version)}
		}
		if s.cfg.Version == V3 {
			if m.PDU.Type == PDUReport {
				fail := reportFailure(m, s.cfg.User.Name)
				// An authenticated Report carries the agent's clock (time sync).
				if m.Level >= AuthNoPriv && len(m.EngineID) > 0 && equalBytes(m.EngineID, s.eng.ID) {
					s.setEngine(EngineInfo{ID: s.eng.ID, Boots: m.EngineBoots, Time: m.EngineTime, At: s.now()}, s.eng)
				}
				if fail.Status == FailUnknownEngine || fail.Status == FailNotInTime {
					if round == 0 && retryReport {
						if fail.Status == FailUnknownEngine {
							if _, err := s.Discover(ctx); err != nil {
								return nil, err
							}
						} else if m.Level == NoAuthNoPriv {
							// An unauthenticated notInTimeWindows Report can't be
							// trusted for the clock: rediscover.
							if _, err := s.Discover(ctx); err != nil {
								return nil, err
							}
						}
						continue
					}
				}
				return nil, fail
			}
			if m.Level != s.level() {
				return nil, &RequestError{Status: FailError, Detail: fmt.Sprintf("the Response is %s, the request %s", m.Level, s.level())}
			}
			if !equalBytes(m.EngineID, s.eng.ID) {
				return nil, &RequestError{Status: FailUnknownEngine, Detail: fmt.Sprintf("the Response names engine %x, not %x", m.EngineID, s.eng.ID)}
			}
			// Non-authoritative timeliness (RFC 3414 §3.2 step 7b): a later
			// clock is adopted; boots going up is an agent restart.
			if m.Level >= AuthNoPriv && (m.EngineBoots > s.eng.Boots || (m.EngineBoots == s.eng.Boots && m.EngineTime > s.eng.timeAt(s.now()))) {
				s.setEngine(EngineInfo{ID: s.eng.ID, Boots: m.EngineBoots, Time: m.EngineTime, At: s.now()}, s.eng)
			}
		}
		if s.cfg.Version == V3 && m.MsgID != int64(msgID) {
			return nil, &RequestError{Status: FailError, Detail: "the reply's msgID doesn't match the request's"}
		}
		if m.PDU.RequestID != int64(reqID) {
			return nil, &RequestError{Status: FailError, Detail: "the Response's request ID doesn't match the request's"}
		}
		return m.PDU, nil
	}
}

// replyStatus turns a reply that didn't decode into a failure.
func (s *Session) replyStatus(m *Message) error {
	switch m.Status {
	case StatusOK:
		if m.PDU == nil {
			return &RequestError{Status: FailError, Detail: "an empty reply"}
		}
		return nil
	case StatusAuthFailed:
		return &RequestError{Status: FailAuth, Detail: "the reply's " + m.Err}
	case StatusDecryptFailed:
		return &RequestError{Status: FailDecrypt, Detail: m.Err}
	case StatusUnknownEngine:
		return &RequestError{Status: FailUnknownEngine, Detail: "the reply: " + m.Err}
	}
	return &RequestError{Status: FailError, Detail: "the reply doesn't decode: " + m.describe()}
}

func (m *Message) describe() string {
	if m.Status == StatusOK {
		if m.PDU != nil {
			return "a " + m.PDU.Type.String() + " PDU"
		}
		return "no PDU"
	}
	return m.Status.String() + ": " + m.Err
}

// PDUError is a Response with a non-zero error-status.
type PDUError struct {
	Status int64
	Index  int64
}

func (e *PDUError) Error() string {
	return fmt.Sprintf("the agent answered %s (varbind %d)", ErrorStatusName(e.Status), e.Index)
}

// Get requests the OIDs' values, at most MaxRequestVarbinds per request,
// halving a request the agent answers tooBig. The result has one varbind per
// OID, in order; an OID the agent lacks has a NoSuchObject or NoSuchInstance
// value (v1's noSuchName becomes NoSuchObject).
func (s *Session) Get(ctx context.Context, oids []OID) ([]Varbind, error) {
	out := make([]Varbind, 0, len(oids))
	for i := 0; i < len(oids); i += MaxRequestVarbinds {
		chunk := oids[i:min(i+MaxRequestVarbinds, len(oids))]
		vbs, err := s.get(ctx, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, vbs...)
	}
	return out, nil
}

func (s *Session) get(ctx context.Context, oids []OID) ([]Varbind, error) {
	p, err := s.request(ctx, Request{Kind: ReqGet, OIDs: oids}, true)
	if err != nil {
		return nil, err
	}
	switch p.ErrorStatus {
	case 0:
	case ErrStatusTooBig:
		if len(oids) == 1 {
			return nil, &RequestError{Status: FailError, Detail: "tooBig for a single varbind (" + oids[0].String() + ")"}
		}
		h := len(oids) / 2
		a, err := s.get(ctx, oids[:h])
		if err != nil {
			return nil, err
		}
		b, err := s.get(ctx, oids[h:])
		if err != nil {
			return nil, err
		}
		return append(a, b...), nil
	case ErrStatusNoSuchName:
		// v1: the varbind at ErrorIndex doesn't exist; ask again without it.
		i := int(p.ErrorIndex) - 1
		if i < 0 || i >= len(oids) {
			return nil, &RequestError{Status: FailError, Detail: (&PDUError{p.ErrorStatus, p.ErrorIndex}).Error()}
		}
		out := make([]Varbind, len(oids))
		rest := slices.Concat(oids[:i], oids[i+1:])
		var got []Varbind
		if len(rest) > 0 {
			if got, err = s.get(ctx, rest); err != nil {
				return nil, err
			}
		}
		j := 0
		for k := range oids {
			if k == i {
				out[k] = Varbind{OID: oids[k], Value: Value{Kind: KindNoSuchObject}}
				continue
			}
			out[k] = got[j]
			j++
		}
		return out, nil
	default:
		return nil, &RequestError{Status: FailError, Detail: (&PDUError{p.ErrorStatus, p.ErrorIndex}).Error()}
	}
	if len(p.Varbinds) != len(oids) {
		return nil, &RequestError{Status: FailError, Detail: fmt.Sprintf("the Response has %d varbinds for %d requested", len(p.Varbinds), len(oids))}
	}
	for i, vb := range p.Varbinds {
		if !vb.OID.Equal(oids[i]) {
			return nil, &RequestError{Status: FailError, Detail: fmt.Sprintf("the Response's varbind %d is %s, not %s", i+1, vb.OID, oids[i])}
		}
	}
	return p.Varbinds, nil
}

// Walk reads the subtree under base, in order, with GetBulk (max-repetitions
// 25, halved on tooBig) or, for v1, GetNext; at most maxRows rows. capped
// reports that the subtree had more rows than that.
func (s *Session) Walk(ctx context.Context, base OID, maxRows int) (rows []Varbind, capped bool, err error) {
	cur := base
	reps := BulkRepetitions
	for {
		var p *PDU
		if s.cfg.Version == V1 {
			p, err = s.request(ctx, Request{Kind: ReqGetNext, OIDs: []OID{cur}}, true)
		} else {
			p, err = s.request(ctx, Request{Kind: ReqGetBulk, MaxRepetitions: reps, OIDs: []OID{cur}}, true)
		}
		if err != nil {
			return rows, false, err
		}
		if p.ErrorStatus == ErrStatusTooBig && s.cfg.Version != V1 && reps > 1 {
			reps /= 2
			continue
		}
		if p.ErrorStatus == ErrStatusNoSuchName && s.cfg.Version == V1 {
			return rows, false, nil // the end of the MIB view
		}
		if p.ErrorStatus != 0 {
			return rows, false, &RequestError{Status: FailError, Detail: (&PDUError{p.ErrorStatus, p.ErrorIndex}).Error()}
		}
		if len(p.Varbinds) == 0 {
			return rows, false, nil
		}
		for _, vb := range p.Varbinds {
			if !vb.OID.HasPrefix(base) || len(vb.OID) == len(base) || vb.Value.Kind == KindEndOfMibView {
				return rows, false, nil
			}
			if compareOID(vb.OID, cur) <= 0 {
				return rows, false, &RequestError{Status: FailError, Detail: "the agent's walk went backwards at " + vb.OID.String()}
			}
			if len(rows) == maxRows {
				return rows, true, nil
			}
			rows = append(rows, vb)
			cur = vb.OID
		}
	}
}

// compareOID orders OIDs lexicographically.
func compareOID(a, b OID) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return len(a) - len(b)
}

// CompareOID orders OIDs lexicographically (for sorting).
func CompareOID(a, b OID) int { return compareOID(a, b) }
