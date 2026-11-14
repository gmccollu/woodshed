package snmp

import (
	"bytes"
	"container/list"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// TimeWindow is RFC 3414's timeliness window.
const TimeWindow = 150 // seconds

// Cache and limit sizes (SPEC §11.2.3).
const (
	KeyCacheSize       = 10000 // localized keys kept, least recently used out
	EngineCacheSize    = 10000 // remote engines' boots and time kept for the time window
	SlowLocalizePerSec = 20    // at most this many 1 MiB key hashes a second at receive time
)

// maxBoots is snmpEngineBoots' latch value (RFC 3414 §2.2.2).
const maxBoots = math.MaxInt32

// User is a v3 user as configured (SPEC §11.2.6).
type User struct {
	Name   string
	Level  Level // the lowest level accepted; must be set
	Auth   AuthProtocol
	Priv   PrivProtocol
	KeyExt KeyExt

	// AuthPass and PrivPass are the passphrases (at least 8 octets, RFC 3414
	// §11.2). They may be empty when EngineKeys holds the keys for every engine the
	// user applies to.
	AuthPass []byte
	PrivPass []byte

	// EngineKeys are keys already localized to the listed engine IDs. When set,
	// only those engines are accepted for this user, whatever the passphrases.
	EngineKeys []EngineKeys
}

// EngineKeys are a user's keys for one sender engine ID.
type EngineKeys struct {
	EngineID []byte
	Keys     Keys
}

// MaxLevel is the highest level the user's protocols allow.
func (u *User) MaxLevel() Level {
	switch {
	case u.Priv != PrivNone:
		return AuthPriv
	case u.Auth != AuthNone:
		return AuthNoPriv
	}
	return NoAuthNoPriv
}

// Validate checks the user's settings.
func (u *User) Validate() error {
	if u.Name == "" || len(u.Name) > 32 {
		return fmt.Errorf("snmp: a user name is 1 to 32 bytes")
	}
	if u.Priv != PrivNone && u.Auth == AuthNone {
		return fmt.Errorf("snmp: user %q: privacy needs authentication", u.Name)
	}
	if u.Auth.newHash() == nil && u.Auth != AuthNone {
		return fmt.Errorf("snmp: user %q: unknown authentication protocol", u.Name)
	}
	if u.Priv > PrivAES256 || u.KeyExt > KeyExtAlt {
		return fmt.Errorf("snmp: user %q: unknown privacy protocol or key extension", u.Name)
	}
	if u.Level < NoAuthNoPriv || u.Level > u.MaxLevel() {
		return fmt.Errorf("snmp: user %q: level %q isn't one its protocols allow (at most %s)", u.Name, u.Level, u.MaxLevel())
	}
	if len(u.EngineKeys) == 0 {
		if u.Auth != AuthNone && len(u.AuthPass) < 8 {
			return fmt.Errorf("snmp: user %q: the authentication passphrase needs at least 8 characters", u.Name)
		}
		if u.Priv != PrivNone && len(u.PrivPass) < 8 {
			return fmt.Errorf("snmp: user %q: the privacy passphrase needs at least 8 characters", u.Name)
		}
	}
	for _, ek := range u.EngineKeys {
		if len(ek.EngineID) == 0 {
			return fmt.Errorf("snmp: user %q: an engine key without an engine ID", u.Name)
		}
		if u.Auth != AuthNone && len(ek.Keys.Auth) != len(u.Auth.newHash()().Sum(nil)) {
			return fmt.Errorf("snmp: user %q: the authentication key for engine %x has the wrong length", u.Name, ek.EngineID)
		}
		if u.Priv != PrivNone && len(ek.Keys.Priv) != u.Priv.KeyLen() {
			return fmt.Errorf("snmp: user %q: the privacy key for engine %x has the wrong length", u.Name, ek.EngineID)
		}
	}
	return nil
}

// Localize returns the user's keys for each engine ID, from its passphrases
// (for storing engine-bound keys and discarding the passphrases, §11.2.6).
func (u *User) Localize(engineIDs [][]byte) ([]EngineKeys, error) {
	var out []EngineKeys
	for _, id := range engineIDs {
		k, err := LocalizeKeys(u.Auth, u.Priv, u.KeyExt, u.AuthPass, u.PrivPass, id)
		if err != nil {
			return nil, fmt.Errorf("snmp: user %q: %w", u.Name, err)
		}
		out = append(out, EngineKeys{EngineID: append([]byte(nil), id...), Keys: k})
	}
	return out, nil
}

// userState is a user as USM holds it: the passphrases are reduced to their
// password-to-key results (Ku), so localizing to a new engine is one small hash.
type userState struct {
	User
	gen    uint64
	authKu []byte
	privKu []byte
	fixed  map[string]Keys // engine ID → keys, for EngineKeys users
}

// Engine is the local SNMP engine (authoritative for informs).
type Engine struct {
	ID    []byte
	Boots int64
	Start time.Time
}

// Time is snmpEngineTime: seconds since Start, at most 2^31-1.
func (e *Engine) Time(now time.Time) int64 {
	t := int64(now.Sub(e.Start) / time.Second)
	return min(max(t, 0), math.MaxInt32)
}

// Counters are USM's statistics (usmStats, RFC 3414 §5).
type Counters struct {
	UnsupportedSecLevels uint64
	NotInTimeWindows     uint64
	UnknownUserNames     uint64
	UnknownEngineIDs     uint64
	WrongDigests         uint64
	DecryptionErrors     uint64
	SlowLocalizeLimited  uint64 // receive-time key hashes refused by the rate limit
	// TimeResyncs counts authenticated traps outside the window whose boots and
	// time were adopted (not in strict mode); a burst of them is what a replay
	// looks like.
	TimeResyncs uint64
}

// USM is the User-based Security Model for the receiver: users, localized keys,
// the remote engines' times, the local engine, and the replies. It is safe for
// concurrent use.
type USM struct {
	engine *Engine

	mu      sync.Mutex
	users   map[string]*userState
	gen     uint64
	keys    *lru[Keys]
	engines *lru[*remoteTime]
	bucket  tokenBucket

	unsupportedSecLevels, notInTimeWindows, unknownUserNames,
	unknownEngineIDs, wrongDigests, decryptionErrors, slowLimited, timeResyncs atomic.Uint64

	strictTime atomic.Bool
	salt       atomic.Uint64
}

// remoteTime is RFC 3414 §2.3's notion of a remote authoritative engine's
// clock: its boots, its time when last updated, and when that was.
type remoteTime struct {
	boots   int64
	time    int64 // latestReceivedEngineTime
	updated time.Time
}

func (r *remoteTime) estimate(now time.Time) int64 {
	return r.time + int64(now.Sub(r.updated)/time.Second)
}

// NewUSM returns a USM for the local engine e, with no users.
func NewUSM(e *Engine) *USM {
	u := &USM{
		engine:  e,
		users:   map[string]*userState{},
		keys:    newLRU[Keys](KeyCacheSize),
		engines: newLRU[*remoteTime](EngineCacheSize),
		bucket:  tokenBucket{rate: SlowLocalizePerSec, burst: SlowLocalizePerSec},
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	u.salt.Store(binary.BigEndian.Uint64(b[:]))
	return u
}

// SetStrictTime turns RFC 3414's timeliness rule for traps on (true) or off
// (false, the default; config listeners.snmp.v3_strict_time).
//
// Off: an authenticated trap that fails only the time window is still decrypted
// and decoded, kept whole with status not_in_time (Message.TimeResync set), and
// its boots and time are adopted as the sender's clock, so a device that
// rebooted without raising its boots is in time again from its next trap.
// On: such a trap keeps only its header and the sender's clock isn't changed,
// so that device stays not_in_time until it raises its boots. Informs are the
// same either way (the authenticated Report resyncs the sender).
func (u *USM) SetStrictTime(strict bool) { u.strictTime.Store(strict) }

// Engine returns the local engine.
func (u *USM) Engine() *Engine { return u.engine }

// SetUsers replaces the users. Each is validated; the passphrases are hashed
// here (a 1 MiB hash each) and not kept.
func (u *USM) SetUsers(users []User) error {
	m := make(map[string]*userState, len(users))
	u.mu.Lock()
	gen := u.gen + 1
	u.mu.Unlock()
	for _, usr := range users {
		if err := usr.Validate(); err != nil {
			return err
		}
		if _, dup := m[usr.Name]; dup {
			return fmt.Errorf("snmp: user %q is listed twice", usr.Name)
		}
		st := &userState{User: usr, gen: gen}
		st.AuthPass, st.PrivPass = nil, nil
		st.EngineKeys = nil
		if len(usr.EngineKeys) > 0 {
			st.fixed = map[string]Keys{}
			for _, ek := range usr.EngineKeys {
				st.fixed[string(ek.EngineID)] = ek.Keys
			}
		} else if usr.Auth != AuthNone {
			var err error
			if st.authKu, err = PasswordToKey(usr.Auth, usr.AuthPass); err != nil {
				return fmt.Errorf("snmp: user %q: %w", usr.Name, err)
			}
			if usr.Priv != PrivNone {
				if st.privKu, err = PasswordToKey(usr.Auth, usr.PrivPass); err != nil {
					return fmt.Errorf("snmp: user %q: %w", usr.Name, err)
				}
			}
		}
		m[usr.Name] = st
	}
	u.mu.Lock()
	u.users, u.gen = m, gen
	u.keys.clear()
	u.mu.Unlock()
	return nil
}

// Counters returns the usmStats counters.
func (u *USM) Counters() Counters {
	return Counters{
		UnsupportedSecLevels: u.unsupportedSecLevels.Load(),
		NotInTimeWindows:     u.notInTimeWindows.Load(),
		UnknownUserNames:     u.unknownUserNames.Load(),
		UnknownEngineIDs:     u.unknownEngineIDs.Load(),
		WrongDigests:         u.wrongDigests.Load(),
		DecryptionErrors:     u.decryptionErrors.Load(),
		SlowLocalizeLimited:  u.slowLimited.Load(),
		TimeResyncs:          u.timeResyncs.Load(),
	}
}

var errNoEngineKeys = errors.New("no keys for this engine ID")

// keysFor returns st's keys localized to engineID, from the cache when it can.
func (u *USM) keysFor(st *userState, engineID []byte, now time.Time) (Keys, error) {
	if st.fixed != nil {
		k, ok := st.fixed[string(engineID)]
		if !ok {
			return Keys{}, errNoEngineKeys
		}
		return k, nil
	}
	if len(engineID) == 0 {
		return Keys{}, errNoEngineKeys
	}
	ck := fmt.Sprintf("%d\x00%s\x00%s", st.gen, st.Name, engineID)
	u.mu.Lock()
	k, ok := u.keys.get(ck)
	u.mu.Unlock()
	if ok {
		return k, nil
	}
	k.Auth = LocalizeKey(st.Auth, st.authKu, engineID)
	if st.Priv != PrivNone {
		kul := LocalizeKey(st.Auth, st.privKu, engineID)
		if len(kul) < st.Priv.KeyLen() && st.KeyExt == KeyExtAlt {
			// The alt extension costs a 1 MiB hash per engine: rate-limited, so
			// spoofed engine IDs can't burn the CPU.
			u.mu.Lock()
			allowed := u.bucket.take(now)
			u.mu.Unlock()
			if !allowed {
				u.slowLimited.Add(1)
				return Keys{}, fmt.Errorf("key localization limit reached (%d a second)", SlowLocalizePerSec)
			}
		}
		var err error
		if k.Priv, err = extendPrivKey(st.Auth, st.KeyExt, kul, engineID, st.Priv.KeyLen()); err != nil {
			return Keys{}, err
		}
	}
	u.mu.Lock()
	u.keys.put(ck, k)
	u.mu.Unlock()
	return k, nil
}

// process runs RFC 3414 §3.2's checks on a v3 message whose header decoded,
// then decrypts and decodes the scoped PDU. u may be nil.
func (u *USM) process(m *Message, now time.Time) {
	if len(m.EngineID) == 0 && m.Reportable {
		// Discovery (RFC 3414 §4): answer with the local engine ID, boots and
		// time. The probe is noAuthNoPriv; its plaintext request ID goes back.
		m.Discovery = true
		if u != nil {
			u.unknownEngineIDs.Add(1)
			m.Reply, m.reportOID = ReplyReport, oidUnknownEngineIDs
		}
		if m.Level == NoAuthNoPriv {
			m.reportReqID, _ = peekRequestID(m.Raw[m.data.off:m.data.end()])
		}
		return
	}
	if u == nil {
		m.fail(StatusUnknownUser, "no v3 users are configured")
		return
	}
	authoritative := bytes.Equal(m.EngineID, u.engine.ID)
	if m.Reportable && !authoritative {
		// An inform (or any request) names its receiver as authoritative; this
		// one names another engine. The Report tells the sender ours.
		u.unknownEngineIDs.Add(1)
		m.fail(StatusUnknownEngine, "the message is for engine %x, not this receiver's (%x)", m.EngineID, u.engine.ID)
		m.Reply, m.reportOID = ReplyReport, oidUnknownEngineIDs
		if m.Level == NoAuthNoPriv {
			m.reportReqID, _ = peekRequestID(m.Raw[m.data.off:m.data.end()])
		}
		return
	}
	u.mu.Lock()
	st := u.users[string(m.User)]
	u.mu.Unlock()
	if st == nil {
		u.unknownUserNames.Add(1)
		m.fail(StatusUnknownUser, "unknown user %s", quoteBytes(m.User))
		return
	}
	m.user = st
	if m.Level < st.Level {
		u.unsupportedSecLevels.Add(1)
		m.fail(StatusLevel, "%s is below user %s's level, %s", m.Level, quoteBytes(m.User), st.Level)
		return
	}
	if m.Level > st.MaxLevel() {
		u.unsupportedSecLevels.Add(1)
		m.fail(StatusLevel, "%s is above what user %s has keys for (%s)", m.Level, quoteBytes(m.User), st.MaxLevel())
		return
	}
	if m.Level == NoAuthNoPriv {
		m.decodeScoped(m.Raw[m.data.off:m.data.end()], m.data.off, StatusMalformed, "")
		return
	}
	keys, err := u.keysFor(st, m.EngineID, now)
	if err != nil {
		u.unknownEngineIDs.Add(1)
		if errors.Is(err, errNoEngineKeys) {
			if len(m.EngineID) == 0 {
				m.fail(StatusUnknownEngine, "an empty engine ID, so no key can be localized")
			} else {
				m.fail(StatusUnknownEngine, "user %s has no keys for engine %x", quoteBytes(m.User), m.EngineID)
			}
		} else {
			m.fail(StatusUnknownEngine, "%v", err)
		}
		return
	}
	if n := st.Auth.MACLen(); len(m.authParams) != n {
		u.wrongDigests.Add(1)
		m.fail(StatusAuthFailed, "authentication parameters are %d bytes; %s uses %d", len(m.authParams), st.Auth, n)
		return
	}
	if !checkMAC(st.Auth, keys.Auth, m.whole, m.authOff, m.authParams) {
		u.wrongDigests.Add(1)
		m.fail(StatusAuthFailed, "wrong digest (%s): a wrong authentication passphrase or protocol", st.Auth)
		return
	}
	if !u.timely(m, authoritative, now) {
		u.notInTimeWindows.Add(1)
		if authoritative && m.Reportable {
			m.Reply, m.reportOID, m.reportAuth = ReplyReport, oidNotInTimeWindows, true
			if m.Level == AuthNoPriv {
				m.reportReqID, _ = peekRequestID(m.Raw[m.data.off:m.data.end()])
			}
		}
		if !m.TimeResync {
			return
		}
		// A trap that failed only the window (the sender's clock was adopted):
		// decode it in full, and keep the not_in_time status.
		u.timeResyncs.Add(1)
		status, why := m.Status, m.Err
		defer func() {
			if m.Status == StatusOK {
				m.Status, m.Err = status, why
			}
		}()
	}
	if m.Level == AuthNoPriv {
		m.decodeScoped(m.Raw[m.data.off:m.data.end()], m.data.off, StatusMalformed, "")
		return
	}
	plain, err := decrypt(st.Priv, keys.Priv, m.privParams, m.data.content, m.EngineBoots, m.EngineTime)
	if err != nil {
		u.decryptionErrors.Add(1)
		m.fail(StatusDecryptFailed, "%v", err)
		return
	}
	m.decodeScoped(plain, 0, StatusDecryptFailed, "the decrypted data doesn't decode (a wrong privacy passphrase, protocol or key extension?): ")
	if m.Status == StatusDecryptFailed {
		u.decryptionErrors.Add(1)
	}
}

// timely is RFC 3414 §3.2 step 7: against the local clock when Woodshed is
// authoritative (informs), against the sender's clock as last seen otherwise
// (traps), updating that from this authenticated message. It sets the failure.
// It's only called once the digest has verified, so only authenticated messages
// ever move a sender's clock. Outside strict mode a trap outside the window
// replaces the sender's clock with its own boots and time (m.TimeResync).
func (u *USM) timely(m *Message, authoritative bool, now time.Time) bool {
	if authoritative {
		e := u.engine
		t := e.Time(now)
		switch {
		case e.Boots >= maxBoots:
			m.fail(StatusNotInTime, "this engine's boots counter is latched at its maximum")
		case m.EngineBoots != e.Boots:
			m.fail(StatusNotInTime, "boots %d, this engine's is %d", m.EngineBoots, e.Boots)
		case m.EngineTime < t-TimeWindow || m.EngineTime > t+TimeWindow:
			m.fail(StatusNotInTime, "time %d, this engine's is %d (window %d s)", m.EngineTime, t, TimeWindow)
		default:
			return true
		}
		return false
	}
	key := string(m.EngineID)
	u.mu.Lock()
	defer u.mu.Unlock()
	r, ok := u.engines.get(key)
	if !ok {
		u.engines.put(key, &remoteTime{boots: m.EngineBoots, time: m.EngineTime, updated: now})
		return true
	}
	if m.EngineBoots > r.boots || (m.EngineBoots == r.boots && m.EngineTime > r.time) {
		r.boots, r.time, r.updated = m.EngineBoots, m.EngineTime, now
	}
	est := r.estimate(now)
	switch {
	case r.boots >= maxBoots:
		m.fail(StatusNotInTime, "the sender's boots counter is latched at its maximum")
	case m.EngineBoots < r.boots:
		m.fail(StatusNotInTime, "boots %d, but the sender was at %d", m.EngineBoots, r.boots)
	case m.EngineTime < est-TimeWindow:
		m.fail(StatusNotInTime, "time %d, but the sender's clock is about %d (window %d s)", m.EngineTime, est, TimeWindow)
	default:
		return true
	}
	if !u.strictTime.Load() {
		r.boots, r.time, r.updated = m.EngineBoots, m.EngineTime, now
		m.TimeResync = true
		m.Err += "; the sender's clock was reset to this trap's (a reboot without raising its boots, or a replay)"
	}
	return false
}

// usmStats OIDs (RFC 3414 §5).
var (
	oidNotInTimeWindows = OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0}
	oidUnknownEngineIDs = OID{1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0}
)

func (u *USM) reportCount(oid OID) uint64 {
	switch {
	case oid.Equal(oidNotInTimeWindows):
		return u.notInTimeWindows.Load()
	case oid.Equal(oidUnknownEngineIDs):
		return u.unknownEngineIDs.Load()
	}
	return 0
}

// NewEngineID returns a fresh engine ID in RFC 3411's "administratively
// assigned octets" format: 80000000 (enterprise 0, a placeholder, §11.9), 05,
// then 8 random octets.
func NewEngineID() []byte {
	id := []byte{0x80, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0}
	_, _ = rand.Read(id[5:])
	return id
}

// ParseEngineID parses a hex engine ID (5 to 32 octets, RFC 3411; a leading
// 0x and colons are allowed).
func ParseEngineID(s string) ([]byte, error) {
	t := s
	if len(t) > 2 && (t[:2] == "0x" || t[:2] == "0X") {
		t = t[2:]
	}
	t = string(bytes.ReplaceAll([]byte(t), []byte(":"), nil))
	b, err := hex.DecodeString(t)
	if err != nil {
		return nil, fmt.Errorf("snmp: engine ID %q isn't hex", s)
	}
	if len(b) < 5 || len(b) > 32 {
		return nil, fmt.Errorf("snmp: engine ID %q is %d octets; RFC 3411 allows 5 to 32", s, len(b))
	}
	return b, nil
}

// --- small helpers ---

// lru is a fixed-size least-recently-used map. Not safe for concurrent use.
type lru[V any] struct {
	max int
	l   *list.List
	m   map[string]*list.Element
}

type lruEntry[V any] struct {
	k string
	v V
}

func newLRU[V any](max int) *lru[V] {
	return &lru[V]{max: max, l: list.New(), m: map[string]*list.Element{}}
}

func (c *lru[V]) get(k string) (V, bool) {
	if e, ok := c.m[k]; ok {
		c.l.MoveToFront(e)
		return e.Value.(*lruEntry[V]).v, true
	}
	var zero V
	return zero, false
}

func (c *lru[V]) put(k string, v V) {
	if e, ok := c.m[k]; ok {
		e.Value.(*lruEntry[V]).v = v
		c.l.MoveToFront(e)
		return
	}
	c.m[k] = c.l.PushFront(&lruEntry[V]{k, v})
	for c.l.Len() > c.max {
		last := c.l.Back()
		c.l.Remove(last)
		delete(c.m, last.Value.(*lruEntry[V]).k)
	}
}

func (c *lru[V]) len() int { return c.l.Len() }

func (c *lru[V]) clear() {
	c.l.Init()
	c.m = map[string]*list.Element{}
}

// tokenBucket is a simple rate limiter. Not safe for concurrent use.
type tokenBucket struct {
	rate, burst float64
	tokens      float64
	last        time.Time
}

func (b *tokenBucket) take(now time.Time) bool {
	if b.last.IsZero() {
		b.tokens = b.burst
	} else if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(b.burst, b.tokens+d*b.rate)
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}
