package snmp_test

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

// The requester side against the in-repo test agent (SPEC §12.8): every
// version, every v3 level and protocol, discovery, time sync, rediscovery,
// tooBig, missing objects, replies from the wrong address and silence.

// udpTransport is a minimal Transport for these tests: one socket, replies
// only from the target address with the request's ID (the poller's shared
// socket does the same for many targets).
type udpTransport struct {
	conn      *net.UDPConn
	to        netip.AddrPort
	unmatched atomic.Int64
}

func newTransport(t *testing.T, to netip.AddrPort) *udpTransport {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &udpTransport{conn: c, to: to}
}

func (u *udpTransport) Exchange(ctx context.Context, req []byte, id int64, timeout time.Duration) ([]byte, error) {
	if _, err := u.conn.WriteToUDPAddrPort(req, u.to); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65535)
	for {
		_ = u.conn.SetReadDeadline(deadline)
		n, from, err := u.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return nil, snmp.ErrTimeout
			}
			return nil, err
		}
		if _, got, ok := snmp.PeekID(buf[:n]); !ok || got != id || from != u.to {
			u.unmatched.Add(1)
			continue
		}
		return append([]byte(nil), buf[:n]...), nil
	}
}

var (
	authPass = []byte("maplesyrup-test")
	privPass = []byte("privpass-for-tests")
	oidName  = snmp.OID{1, 3, 6, 1, 2, 1, 1, 5, 0}
	oidIfNm  = snmp.OID{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1}
	oidHCIn  = snmp.OID{1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6}
	oidHrUp  = snmp.OID{1, 3, 6, 1, 2, 1, 25, 1, 1, 0}
)

func ifaces(n int) []agenttest.Interface {
	var out []agenttest.Interface
	for i := 1; i <= n; i++ {
		out = append(out, agenttest.Interface{Index: i, Name: "eth" + string(rune('0'+i%10)), SpeedMbps: 1000, InBps: 8e6, OutBps: 4e6})
	}
	return out
}

func startAgent(t *testing.T, o agenttest.Options) *agenttest.Agent {
	t.Helper()
	a, err := agenttest.Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func session(t *testing.T, a *agenttest.Agent, cfg snmp.SessionConfig) (*snmp.Session, *udpTransport) {
	t.Helper()
	tr := newTransport(t, a.Addr())
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Second // generous: answers are what's tested; a loaded runner is slow
	}
	s, err := snmp.NewSession(cfg, tr)
	if err != nil {
		t.Fatal(err)
	}
	return s, tr
}

func TestSessionCommunity(t *testing.T) {
	a := startAgent(t, agenttest.Options{Community: "testcomm", Interfaces: ifaces(3), SysName: "edge-fw-01"})
	for _, v := range []snmp.Version{snmp.V1, snmp.V2c} {
		s, _ := session(t, a, snmp.SessionConfig{Version: v, Community: []byte("testcomm"), Retries: 1})
		vbs, err := s.Get(context.Background(), []snmp.OID{snmp.OIDSysUpTime, oidName})
		if err != nil {
			t.Fatalf("%s: %v", v, err)
		}
		if string(vbs[1].Value.Bytes) != "edge-fw-01" || vbs[0].Value.Kind != snmp.KindTimeTicks {
			t.Errorf("%s: %+v", v, vbs)
		}
		rows, capped, err := s.Walk(context.Background(), oidIfNm, 128)
		if err != nil || capped || len(rows) != 3 {
			t.Errorf("%s walk: %d rows, capped %v, %v", v, len(rows), capped, err)
		}
		// v1 has no Counter64: the HC column is missing (noSuchName -> NoSuchObject).
		hc := append(snmp.OID(nil), oidHCIn...)
		vbs, err = s.Get(context.Background(), []snmp.OID{append(hc, 1), snmp.OIDSysUpTime})
		if err != nil {
			t.Fatalf("%s HC: %v", v, err)
		}
		if v == snmp.V1 && vbs[0].Value.Kind != snmp.KindNoSuchObject {
			t.Errorf("v1 HC counter: %+v", vbs[0].Value)
		}
		if v == snmp.V2c && vbs[0].Value.Kind != snmp.KindCounter64 {
			t.Errorf("v2c HC counter: %+v", vbs[0].Value)
		}
		if vbs[1].Value.Kind != snmp.KindTimeTicks {
			t.Errorf("%s: the other varbind %+v", v, vbs[1])
		}
	}
	// A wrong community gets no answer.
	s, _ := session(t, a, snmp.SessionConfig{Version: snmp.V2c, Community: []byte("wrong"), Timeout: 100 * time.Millisecond, Retries: 1})
	_, err := s.Get(context.Background(), []snmp.OID{snmp.OIDSysUpTime})
	if snmp.FailStatus(err) != snmp.FailTimeout || err.Error() != "timeout: no answer after 1 retry" {
		t.Errorf("wrong community: %v", err)
	}
	if s.Requests() != 2 {
		t.Errorf("%d requests, want 2 (one retry)", s.Requests())
	}
}

type combo struct {
	a   snmp.AuthProtocol
	p   snmp.PrivProtocol
	ext snmp.KeyExt
}

func allCombos() []combo {
	out := []combo{{snmp.AuthNone, snmp.PrivNone, 0}}
	auths := []snmp.AuthProtocol{snmp.AuthMD5, snmp.AuthSHA1, snmp.AuthSHA224, snmp.AuthSHA256, snmp.AuthSHA384, snmp.AuthSHA512}
	for _, a := range auths {
		out = append(out, combo{a, snmp.PrivNone, 0})
		for _, p := range []snmp.PrivProtocol{snmp.PrivDES, snmp.PrivAES128, snmp.PrivAES192, snmp.PrivAES256} {
			out = append(out, combo{a, p, snmp.KeyExtDraft})
			if p == snmp.PrivAES192 || p == snmp.PrivAES256 {
				out = append(out, combo{a, p, snmp.KeyExtAlt})
			}
		}
	}
	return out
}

func user(c combo) snmp.User {
	u := snmp.User{Name: "monitor", Auth: c.a, Priv: c.p, KeyExt: c.ext}
	if c.a != snmp.AuthNone {
		u.AuthPass = authPass
	}
	if c.p != snmp.PrivNone {
		u.PrivPass = privPass
	}
	u.Level = u.MaxLevel()
	return u
}

func TestSessionV3EveryProtocol(t *testing.T) {
	for _, c := range allCombos() {
		u := user(c)
		name := u.Auth.String() + "/" + u.Priv.String() + "/" + u.KeyExt.String()
		a := startAgent(t, agenttest.Options{Users: []snmp.User{u}, Interfaces: ifaces(2), HostResources: true, MemTotal: 1 << 30})
		s, _ := session(t, a, snmp.SessionConfig{Version: snmp.V3, User: &u, Retries: 1})
		vbs, err := s.Get(context.Background(), []snmp.OID{snmp.OIDSysUpTime, oidHrUp})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if vbs[0].Value.Kind != snmp.KindTimeTicks || vbs[1].Value.Kind != snmp.KindTimeTicks {
			t.Errorf("%s: %+v", name, vbs)
		}
		e := s.Engine()
		if string(e.ID) != string(a.EngineID()) || e.Boots != 1 {
			t.Errorf("%s: engine %x boots %d", name, e.ID, e.Boots)
		}
		if _, _, err := s.Walk(context.Background(), oidIfNm, 10); err != nil {
			t.Errorf("%s walk: %v", name, err)
		}
	}
}

func TestSessionV3Failures(t *testing.T) {
	good := user(combo{snmp.AuthSHA256, snmp.PrivAES128, snmp.KeyExtDraft})
	a := startAgent(t, agenttest.Options{Users: []snmp.User{good}})
	cases := []struct {
		name string
		u    snmp.User
		want string
	}{
		{"unknown user", func() snmp.User { u := good; u.Name = "nobody"; return u }(), snmp.FailUnknownUser},
		{"wrong auth pass", func() snmp.User { u := good; u.AuthPass = []byte("not-the-pass"); return u }(), snmp.FailAuth},
		{"wrong priv pass", func() snmp.User { u := good; u.PrivPass = []byte("not-the-pass"); return u }(), snmp.FailDecrypt},
	}
	for _, c := range cases {
		s, _ := session(t, a, snmp.SessionConfig{Version: snmp.V3, User: &c.u, Retries: 0})
		_, err := s.Get(context.Background(), []snmp.OID{snmp.OIDSysUpTime})
		if got := snmp.FailStatus(err); got != c.want {
			t.Errorf("%s: %v, want %s", c.name, err, c.want)
		}
	}
	// Keys stored for another engine only: unknown_engine, naming the agent's engine.
	keyed := good
	ek, err := good.Localize([][]byte{{0x80, 0, 0, 0, 5, 1, 2, 3, 4, 5}})
	if err != nil {
		t.Fatal(err)
	}
	keyed.AuthPass, keyed.PrivPass, keyed.EngineKeys = nil, nil, ek
	s, _ := session(t, a, snmp.SessionConfig{Version: snmp.V3, User: &keyed})
	_, err = s.Get(context.Background(), []snmp.OID{snmp.OIDSysUpTime})
	var re *snmp.RequestError
	if !errors.As(err, &re) || re.Status != snmp.FailUnknownEngine {
		t.Errorf("other engine's keys: %v", err)
	}
}

func TestSessionRestartAndRediscovery(t *testing.T) {
	u := user(combo{snmp.AuthSHA1, snmp.PrivAES128, snmp.KeyExtDraft})
	a := startAgent(t, agenttest.Options{Users: []snmp.User{u}})
	s, _ := session(t, a, snmp.SessionConfig{Version: snmp.V3, User: &u, Retries: 1})
	ctx := context.Background()
	if _, err := s.Get(ctx, []snmp.OID{snmp.OIDSysUpTime}); err != nil {
		t.Fatal(err)
	}
	if up, _, _ := s.TakeBootsUp(); up {
		t.Error("boots up on the first poll")
	}
	before := a.Requests()["discovery"]
	// A normal cycle needs no discovery.
	if _, err := s.Get(ctx, []snmp.OID{snmp.OIDSysUpTime}); err != nil {
		t.Fatal(err)
	}
	if a.Requests()["discovery"] != before {
		t.Error("a normal cycle ran discovery")
	}
	// Restart: boots 2. The stale request gets an authenticated notInTimeWindows
	// Report; the session adopts the clock, retries, and marks the restart.
	a.Restart()
	if _, err := s.Get(ctx, []snmp.OID{snmp.OIDSysUpTime}); err != nil {
		t.Fatalf("after restart: %v", err)
	}
	if up, prev, now := s.TakeBootsUp(); !up || prev != 1 || now != 2 {
		t.Errorf("boots up %v %d -> %d", up, prev, now)
	}
	// A cached engine (from the index) is used without discovery.
	s2, _ := session(t, a, snmp.SessionConfig{Version: snmp.V3, User: &u, Engine: s.Engine()})
	d := a.Requests()["discovery"]
	if _, err := s2.Get(ctx, []snmp.OID{snmp.OIDSysUpTime}); err != nil {
		t.Fatal(err)
	}
	if a.Requests()["discovery"] != d {
		t.Error("a cached engine ran discovery")
	}
	// Another agent on the same port with a new engine ID: unknownEngineIDs,
	// so discovery once and the request again.
	addr := a.Addr()
	a.Close()
	b := startAgent(t, agenttest.Options{Addr: addr.String(), Users: []snmp.User{u}})
	if _, err := s.Get(ctx, []snmp.OID{snmp.OIDSysUpTime}); err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if string(s.Engine().ID) != string(b.EngineID()) || b.Requests()["discovery"] != 1 {
		t.Errorf("engine %x, discoveries %d", s.Engine().ID, b.Requests()["discovery"])
	}
}

func TestSessionTooBigNoSuchSilence(t *testing.T) {
	a := startAgent(t, agenttest.Options{Community: "c", Interfaces: ifaces(8)})
	s, tr := session(t, a, snmp.SessionConfig{Version: snmp.V2c, Community: []byte("c"), Retries: 1})
	ctx := context.Background()
	a.SetMaxVarbinds(3)
	var oids []snmp.OID
	for i := 1; i <= 8; i++ {
		oids = append(oids, append(append(snmp.OID(nil), oidHCIn...), uint32(i)))
	}
	vbs, err := s.Get(ctx, oids)
	if err != nil || len(vbs) != 8 {
		t.Fatalf("tooBig get: %d %v", len(vbs), err)
	}
	rows, _, err := s.Walk(ctx, oidIfNm, 100)
	if err != nil || len(rows) != 8 {
		t.Errorf("tooBig walk: %d %v", len(rows), err)
	}
	a.SetMaxVarbinds(0)
	// Walk caps.
	rows, capped, err := s.Walk(ctx, oidIfNm, 5)
	if err != nil || !capped || len(rows) != 5 {
		t.Errorf("capped walk: %d %v %v", len(rows), capped, err)
	}
	// Missing objects.
	a.SetNoSuchObject(snmp.OID{1, 3, 6, 1, 2, 1, 25})
	vbs, err = s.Get(ctx, []snmp.OID{oidHrUp})
	if err != nil || vbs[0].Value.Kind != snmp.KindNoSuchObject {
		t.Errorf("missing: %+v %v", vbs, err)
	}
	// Replies from another address are dropped (counted) and time out.
	a.SetWrongSource(true)
	s, tr = session(t, a, snmp.SessionConfig{Version: snmp.V2c, Community: []byte("c"), Timeout: 300 * time.Millisecond})
	_, err = s.Get(ctx, []snmp.OID{snmp.OIDSysUpTime})
	if snmp.FailStatus(err) != snmp.FailTimeout || tr.unmatched.Load() == 0 {
		t.Errorf("wrong source: %v, unmatched %d", err, tr.unmatched.Load())
	}
	a.SetWrongSource(false)
	a.SetSilent(true)
	if _, err = s.Get(ctx, []snmp.OID{snmp.OIDSysUpTime}); snmp.FailStatus(err) != snmp.FailTimeout {
		t.Errorf("silence: %v", err)
	}
	a.SetSilent(false)
	s, _ = session(t, a, snmp.SessionConfig{Version: snmp.V2c, Community: []byte("c"), Retries: 1})
	if _, err = s.Get(ctx, []snmp.OID{snmp.OIDSysUpTime}); err != nil {
		t.Errorf("after silence: %v", err)
	}
}
