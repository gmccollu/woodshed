package loadgen

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// Test passphrases: fixed test values, not secrets.
var (
	trapAuthPass = []byte("auth-pass-for-tests")
	trapPrivPass = []byte("priv-pass-for-tests")
)

// trapReceiver is a test receiver built on the codec: it decodes, answers
// informs and Reports, and keeps every message.
type trapReceiver struct {
	c    *net.UDPConn
	usm  *snmp.USM
	mu   sync.Mutex
	msgs []*snmp.Message
	// drop, when set, says not to answer the n-th inform (counting from 0).
	drop func(n int) bool
	nInf int
}

func startTrapReceiver(t *testing.T, users ...snmp.User) *trapReceiver {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	u := snmp.NewUSM(&snmp.Engine{ID: snmp.NewEngineID(), Boots: 3, Start: time.Now().Add(-time.Hour)})
	if err := u.SetUsers(users); err != nil {
		t.Fatal(err)
	}
	r := &trapReceiver{c: c, usm: u}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, from, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			now := time.Now()
			m := snmp.Decode(append([]byte(nil), buf[:n]...), u, now)
			r.mu.Lock()
			answer := true
			if m.Reply == snmp.ReplyResponse {
				if r.drop != nil && r.drop(r.nInf) {
					answer = false
				}
				r.nInf++
			}
			if !m.Discovery {
				r.msgs = append(r.msgs, m)
			}
			r.mu.Unlock()
			if answer {
				if rep, err := u.Reply(m, now); err == nil && rep != nil {
					c.WriteToUDP(rep, from)
				}
			}
		}
	}()
	t.Cleanup(func() { c.Close() })
	return r
}

func (r *trapReceiver) addr() string { return r.c.LocalAddr().String() }

// seqs waits for n stored messages and returns the sequence numbers of the ok
// ones, counted.
func (r *trapReceiver) wait(t *testing.T, n int) []*snmp.Message {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		got := len(r.msgs)
		msgs := append([]*snmp.Message(nil), r.msgs...)
		r.mu.Unlock()
		if got >= n || time.Now().After(deadline) {
			return msgs
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func seqCounts(t *testing.T, run string, msgs []*snmp.Message) map[int]int {
	t.Helper()
	counts := map[int]int{}
	for _, m := range msgs {
		if m.Status != snmp.StatusOK {
			continue
		}
		for _, vb := range m.PDU.Varbinds {
			if vb.OID.Equal(SeqOID) {
				var seq int
				if _, err := fmt.Sscanf(string(vb.Value.Bytes), SeqTag(run)+"%d", &seq); err != nil {
					t.Fatalf("seq varbind %q", vb.Value.Bytes)
				}
				counts[seq]++
			}
		}
	}
	return counts
}

func TestSendTrapVersions(t *testing.T) {
	type tc struct {
		name string
		opt  TrapOptions
		user snmp.User
	}
	user := func(name string, a snmp.AuthProtocol, p snmp.PrivProtocol, ext snmp.KeyExt) snmp.User {
		u := snmp.User{Name: name, Level: snmp.NoAuthNoPriv, Auth: a, Priv: p, KeyExt: ext}
		if a != snmp.AuthNone {
			u.AuthPass, u.Level = trapAuthPass, snmp.AuthNoPriv
		}
		if p != snmp.PrivNone {
			u.PrivPass, u.Level = trapPrivPass, snmp.AuthPriv
		}
		return u
	}
	var cases []tc
	cases = append(cases, tc{"v1", TrapOptions{Version: "1"}, snmp.User{}}, tc{"v2c", TrapOptions{Version: "2c", Community: []byte("lab")}, snmp.User{}},
		tc{"v2c inform", TrapOptions{Version: "2c", Inform: true}, snmp.User{}})
	for _, c := range []struct {
		a   snmp.AuthProtocol
		p   snmp.PrivProtocol
		ext snmp.KeyExt
	}{
		{snmp.AuthNone, snmp.PrivNone, 0}, {snmp.AuthMD5, snmp.PrivNone, 0}, {snmp.AuthSHA512, snmp.PrivNone, 0},
		{snmp.AuthMD5, snmp.PrivDES, 0}, {snmp.AuthSHA1, snmp.PrivAES128, 0}, {snmp.AuthSHA256, snmp.PrivAES256, 0},
		{snmp.AuthSHA1, snmp.PrivAES192, snmp.KeyExtAlt}, {snmp.AuthMD5, snmp.PrivAES256, snmp.KeyExtDraft},
	} {
		u := user("u", c.a, c.p, c.ext)
		o := TrapOptions{Version: "3", User: "u", Auth: c.a, Priv: c.p, KeyExt: c.ext, AuthPass: u.AuthPass, PrivPass: u.PrivPass}
		name := o.Describe()
		cases = append(cases, tc{name + " trap", o, u})
		o.Inform = true
		cases = append(cases, tc{name + " inform", o, u})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var users []snmp.User
			if c.user.Name != "" {
				users = append(users, c.user)
			}
			r := startTrapReceiver(t, users...)
			const n = 20
			c.opt.Varbinds = 9
			res, err := Send(context.Background(), SendOptions{Addr: r.addr(), Proto: "trap", Count: n, RunID: "run1", Trap: c.opt})
			if err != nil {
				t.Fatal(err)
			}
			if res.Sent != n {
				t.Fatalf("sent %d", res.Sent)
			}
			msgs := r.wait(t, n)
			counts := seqCounts(t, "run1", msgs)
			for i := 0; i < n; i++ {
				if counts[i] != 1 {
					t.Errorf("seq %d stored %d times", i, counts[i])
				}
			}
			for _, m := range msgs {
				if m.Status != snmp.StatusOK {
					t.Errorf("%v %q", m.Status, m.Err)
					continue
				}
				if want := 9 + 2; c.opt.Version != "1" && len(m.PDU.Varbinds) != want {
					t.Errorf("%d varbinds, want %d", len(m.PDU.Varbinds), want)
				}
				if n := m.PDU.Notification(); !n.TrapOID.Equal(DefaultTrapOID) {
					t.Errorf("trap OID %s", n.TrapOID)
				}
			}
			if c.opt.Inform {
				st := res.Informs
				if st == nil || st.Answered != n || st.TimedOut != 0 || len(st.RTTs) != n || st.Percentile(99) <= 0 {
					t.Errorf("informs: %+v", st)
				}
			} else if res.Informs != nil {
				t.Error("inform stats for traps")
			}
		})
	}
}

// TestSendInformResync: with the receiver's engine ID given (no discovery), the
// first informs carry the wrong boots and time; the receiver's authenticated
// Report resyncs the sender, which sends each such inform once more.
func TestSendInformResync(t *testing.T) {
	u := snmp.User{Name: "u", Level: snmp.AuthPriv, Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128, AuthPass: trapAuthPass, PrivPass: trapPrivPass}
	r := startTrapReceiver(t, u)
	const n = 10
	res, err := Send(context.Background(), SendOptions{Addr: r.addr(), Proto: "trap", Count: n, Rate: 200, RunID: "run2", Trap: TrapOptions{
		Version: "3", Inform: true, User: "u", Auth: u.Auth, Priv: u.Priv, AuthPass: u.AuthPass, PrivPass: u.PrivPass, EngineID: r.usm.Engine().ID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	st := res.Informs
	if st.Answered != n || st.TimedOut != 0 || st.Resent == 0 || st.Reports != st.Resent {
		t.Fatalf("%+v", st)
	}
	msgs := r.wait(t, n+st.Resent)
	counts := seqCounts(t, "run2", msgs)
	notInTime := 0
	for _, m := range msgs {
		if m.Status == snmp.StatusNotInTime {
			notInTime++
		}
	}
	if len(counts) != n || notInTime != st.Resent {
		t.Errorf("stored %d ok, %d not_in_time; resent %d", len(counts), notInTime, st.Resent)
	}
	for i, c := range counts {
		if c != 1 {
			t.Errorf("seq %d stored %d times", i, c)
		}
	}
}

func TestSendInformTimeouts(t *testing.T) {
	r := startTrapReceiver(t)
	r.mu.Lock()
	r.drop = func(n int) bool { return n%3 == 0 }
	r.mu.Unlock()
	res, err := Send(context.Background(), SendOptions{Addr: r.addr(), Proto: "trap", Count: 9, RunID: "run3",
		Trap: TrapOptions{Version: "2c", Inform: true, Timeout: 200 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	if st := res.Informs; st.Answered != 6 || st.TimedOut != 3 {
		t.Errorf("%+v", st)
	}
}

func TestSendTrapErrors(t *testing.T) {
	for name, o := range map[string]TrapOptions{
		"v1 inform":         {Version: "1", Inform: true},
		"bad version":       {Version: "2"},
		"v3 without user":   {Version: "3"},
		"short passphrase":  {Version: "3", User: "u", Auth: snmp.AuthMD5, AuthPass: []byte("short")},
		"priv without auth": {Version: "3", User: "u", Priv: snmp.PrivDES, PrivPass: trapPrivPass},
		"user on v2c":       {Version: "2c", User: "u"},
		"too many varbinds": {Varbinds: 1001},
	} {
		if _, err := Send(context.Background(), SendOptions{Addr: "127.0.0.1:9", Proto: "trap", Count: 1, Trap: o}); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	// No receiver: discovery fails clearly.
	c, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	addr := c.LocalAddr().String()
	c.Close()
	_, err := Send(context.Background(), SendOptions{Addr: addr, Proto: "trap", Count: 1, Trap: TrapOptions{
		Version: "3", Inform: true, User: "u", Auth: snmp.AuthMD5, AuthPass: trapAuthPass, Timeout: 100 * time.Millisecond}})
	if err == nil || !(strings.Contains(err.Error(), "discovery") || strings.Contains(err.Error(), "nothing is listening")) {
		t.Errorf("no receiver: %v", err)
	}
}

// TestVerifyTrapRecords: verifyseq's counting reads a trap record's sequence
// varbind (the number ends at the closing quote, or a space before --message).
func TestVerifyTrapRecords(t *testing.T) {
	dir := t.TempDir()
	m := snmp.Decode(snmp.EncodeCommunity(snmp.V2c, []byte("public"), snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUTrap, RequestID: 1, Varbinds: []snmp.Varbind{
		{OID: SeqOID, Value: snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(SeqTag("run4") + "1")}},
	}})), nil, time.Now())
	rec := string(snmp.FormatRecord(nil, m, snmp.RecordOptions{}))
	m2 := snmp.Decode(snmp.EncodeCommunity(snmp.V2c, []byte("public"), snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUTrap, RequestID: 2, Varbinds: []snmp.Varbind{
		{OID: SeqOID, Value: snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(SeqTag("run4") + "0 with a message")}},
	}})), nil, time.Now())
	rec2 := string(snmp.FormatRecord(nil, m2, snmp.RecordOptions{}))
	writeLog(t, dir, "192.0.2.9", rec, rec2, `v=2c status=ok vb=1.3:str:"seq=run4:2x"`)
	v, err := Verify(dir, "run4", 3)
	if err != nil {
		t.Fatal(err)
	}
	if v.Received != 2 || v.Missing != 1 || v.Duplicates != 0 || v.Foreign != 1 {
		t.Errorf("%+v", v)
	}
}
