package listen

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
)

// The SNMP listener: its own queue and drainer hand each datagram, whole, to
// Trap in arrival order; Reply answers on the same socket; the allowlist and
// blocklist apply in the reader; Refuse counts a community refusal.
func TestSNMPListener(t *testing.T) {
	cfg := config.Listeners{SNMP: config.SNMPListener{Enabled: true, Addr: "127.0.0.1", Port: 0}, Blocklist: []string{"192.0.2.99"},
		MaxMessageBytes: 2048} // syslog's limit; traps are never cut
	var mu sync.Mutex
	var got [][]byte
	s, _, ev := start(t, cfg, func(o *Options) {
		o.Trap = func(p *TrapPacket) {
			mu.Lock()
			got = append(got, p.Raw)
			mu.Unlock()
			if bytes.HasPrefix(p.Raw, []byte("refuse")) {
				p.Refuse(RejectCommunity)
				return
			}
			if err := p.Reply(append([]byte("re:"), p.Raw...)); err != nil {
				t.Errorf("reply: %v", err)
			}
		}
	})
	ap, ok := s.SNMPAddr()
	if !ok {
		t.Fatalf("not running: %+v", s.Status().Listeners)
	}
	if _, ok := ev.find(KindStart); !ok {
		t.Fatal("no start event")
	}
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(ap))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	big := bytes.Repeat([]byte{'x'}, 9000) // never truncated (macOS's loopback takes at most 9216 by default)
	for _, m := range [][]byte{[]byte("one"), big, []byte("refuse this")} {
		if _, err := c.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	buf := make([]byte, 70000)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	for _, want := range [][]byte{[]byte("re:one"), append([]byte("re:"), big...)} {
		n, err := c.Read(buf)
		if err != nil || !bytes.Equal(buf[:n], want) {
			t.Fatalf("reply %d bytes, %v", n, err)
		}
	}
	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 3 })
	if len(got[1]) != 9000 {
		t.Fatalf("truncated to %d", len(got[1]))
	}
	st := s.Status()
	var listed, queued bool
	for _, l := range st.Listeners {
		listed = listed || (l.Proto == "snmp" && l.OK)
	}
	for _, q := range st.UDPQueues {
		queued = queued || q.Listener == "snmp"
	}
	if !listed || !queued {
		t.Fatalf("status %+v", st)
	}
	rej := s.Rejected()
	if len(rej) != 1 || rej[0].Reason != RejectCommunity {
		t.Fatalf("rejected %+v", rej)
	}
	// Reconfigure off stops it; on rebinds.
	cfg.SNMP.Enabled = false
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.SNMPAddr(); ok {
		t.Fatal("still running")
	}
	cfg.SNMP.Enabled = true
	s.Reconfigure(cfg)
	if _, ok := s.SNMPAddr(); !ok {
		t.Fatal("not rebound")
	}
}

// A port in use is a bind failure in the status with Retry, like the others.
func TestSNMPBindFailure(t *testing.T) {
	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	port := hold.LocalAddr().(*net.UDPAddr).Port
	cfg := config.Listeners{SNMP: config.SNMPListener{Enabled: true, Addr: "127.0.0.1", Port: port}}
	s, _, _ := start(t, cfg, func(o *Options) { o.Trap = func(*TrapPacket) {} })
	st := s.Status()
	if len(st.Listeners) != 1 || st.Listeners[0].OK || st.Listeners[0].Proto != "snmp" || !strings.Contains(st.Listeners[0].Error, "in use") {
		t.Fatalf("%+v", st.Listeners)
	}
	hold.Close()
	s.Retry()
	if _, ok := s.SNMPAddr(); !ok {
		t.Fatal("retry didn't bind")
	}
	_ = netip.Addr{}
}

func waitUntil(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
