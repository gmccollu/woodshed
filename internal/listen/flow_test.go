package listen

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/gmccollu/woodshed/internal/config"
)

func flowCfg() config.Listeners {
	return config.Listeners{Flow: config.FlowListener{Enabled: true, Addr: "127.0.0.1", FlowPort: -1, IPFIXPort: -1},
		Blocklist: []string{"192.0.2.99"}, MaxMessageBytes: 2048} // syslog's limit; flow packets are never cut
}

// The flow listener: both sockets feed one queue and one drainer, which hand
// each datagram, whole and in arrival order per socket, to Flow with the
// socket it came in on and the exporter's source port.
func TestFlowListener(t *testing.T) {
	cfg := flowCfg()
	var mu sync.Mutex
	var got []*FlowPacket
	s, _, ev := start(t, cfg, func(o *Options) {
		o.Flow = func(p *FlowPacket) {
			mu.Lock()
			got = append(got, p)
			mu.Unlock()
		}
	})
	addrs := s.FlowAddrs()
	if len(addrs) != 2 || addrs["flow"].Port() == 0 || addrs["ipfix"].Port() == 0 || addrs["flow"] == addrs["ipfix"] {
		t.Fatalf("addrs %v, status %+v", addrs, s.Status().Listeners)
	}
	if _, ok := ev.find(KindStart); !ok {
		t.Fatal("no start event")
	}
	big := bytes.Repeat([]byte{'x'}, 9000)
	send := func(proto string, msgs ...[]byte) net.Conn {
		c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(addrs[proto]))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		for _, m := range msgs {
			if _, err := c.Write(m); err != nil {
				t.Fatal(err)
			}
		}
		return c
	}
	nf := send("flow", []byte("v5"), big)
	ix := send("ipfix", []byte("v10"))
	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(got) == 3 })
	mu.Lock()
	var nfGot [][]byte
	for _, p := range got {
		switch p.Proto {
		case "flow":
			nfGot = append(nfGot, p.Data)
			if p.From.Port() != uint16(nf.LocalAddr().(*net.UDPAddr).Port) {
				t.Errorf("flow port source %v", p.From)
			}
		case "ipfix":
			if string(p.Data) != "v10" || p.From.Port() != uint16(ix.LocalAddr().(*net.UDPAddr).Port) {
				t.Errorf("ipfix packet %q from %v", p.Data, p.From)
			}
		default:
			t.Errorf("proto %q", p.Proto)
		}
	}
	mu.Unlock()
	if len(nfGot) != 2 || string(nfGot[0]) != "v5" || len(nfGot[1]) != 9000 {
		t.Fatalf("flow port packets in order and whole: %d", len(nfGot))
	}
	st := s.Status()
	var listed, queued int
	for _, l := range st.Listeners {
		if (l.Proto == "flow" || l.Proto == "ipfix") && l.OK {
			listed++
		}
	}
	for _, q := range st.UDPQueues {
		if q.Listener == "flow" {
			queued++
			if q.CapacityMessages != config.DefaultFlowQueueMessages || q.CapacityBytes != config.DefaultFlowQueueBytes {
				t.Errorf("flow queue capacity %+v", q)
			}
		}
	}
	if listed != 2 || queued != 1 {
		t.Fatalf("status %+v", st)
	}
	// One port off: only the other is bound. Off: nothing.
	cfg.Flow.IPFIXPort = 0
	if err := s.Reconfigure(cfg); err != nil {
		t.Fatal(err)
	}
	if a := s.FlowAddrs(); len(a) != 1 || a["flow"].Port() == 0 {
		t.Fatalf("flow port only: %v", a)
	}
	cfg.Flow.Enabled = false
	s.Reconfigure(cfg)
	if a := s.FlowAddrs(); len(a) != 0 {
		t.Fatalf("still running: %v", a)
	}
	for _, l := range s.Status().Listeners {
		if l.Proto == "flow" || l.Proto == "ipfix" {
			t.Fatalf("disabled listener in status: %+v", l)
		}
	}
}

// The blocklist applies in the flow readers: a refused packet never reaches
// Flow and is counted.
func TestFlowListenerBlocklist(t *testing.T) {
	cfg := flowCfg()
	cfg.Blocklist = []string{"127.0.0.1"}
	var mu sync.Mutex
	n := 0
	s, _, _ := start(t, cfg, func(o *Options) {
		o.Flow = func(*FlowPacket) { mu.Lock(); n++; mu.Unlock() }
	})
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(s.FlowAddrs()["ipfix"]))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	waitUntil(t, func() bool { return len(s.Rejected()) == 1 })
	if r := s.Rejected(); r[0].Reason != "blocked" {
		t.Fatalf("rejected %+v", r)
	}
	mu.Lock()
	defer mu.Unlock()
	if n != 0 {
		t.Fatalf("delivered %d", n)
	}
}

// A port in use is a bind failure in the status; the other port still runs,
// and Retry binds the failed one once it's free.
func TestFlowBindFailure(t *testing.T) {
	hold, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	port := hold.LocalAddr().(*net.UDPAddr).Port
	cfg := flowCfg()
	cfg.Flow.FlowPort = port
	s, _, _ := start(t, cfg, func(o *Options) { o.Flow = func(*FlowPacket) {} })
	var bad, ok int
	for _, l := range s.Status().Listeners {
		switch {
		case l.Proto == "flow" && !l.OK && strings.Contains(l.Error, "in use"):
			bad++
		case l.Proto == "ipfix" && l.OK:
			ok++
		}
	}
	if bad != 1 || ok != 1 {
		t.Fatalf("%+v", s.Status().Listeners)
	}
	hold.Close()
	s.Retry()
	if a := s.FlowAddrs(); a["flow"].Port() != uint16(port) || a["ipfix"].Port() == 0 {
		t.Fatalf("retry: %v %+v", a, s.Status().Listeners)
	}
}
