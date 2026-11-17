package loadgen

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRefusalsState(t *testing.T) {
	var r refusals
	t0 := time.Now()
	r.wrote(t0)
	r.wrote(t0.Add(RefusedGrace / 2))
	if !r.refused() {
		t.Fatal("a refusal before the grace isn't fatal")
	}
	r.wrote(t0.Add(RefusedGrace))
	if r.refused() || r.refused() || r.count() != 2 {
		t.Fatalf("after the grace: count %d", r.count())
	}
	if RefusedText(0) != "" || !strings.HasPrefix(RefusedText(3), "3 refused (ICMP port unreachable") {
		t.Fatalf("%q", RefusedText(3))
	}
}

// flakyUDP is a UDP receiver that stops listening for a while (a restart) on
// the same port, counting what it gets.
type flakyUDP struct {
	addr string
	got  atomic.Int64
	done chan struct{}
}

func startFlaky(t *testing.T, downAt, upAt time.Duration) *flakyUDP {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	f := &flakyUDP{addr: c.LocalAddr().String(), done: make(chan struct{})}
	read := func(c *net.UDPConn) {
		buf := make([]byte, 65536)
		for {
			if _, _, err := c.ReadFromUDP(buf); err != nil {
				return
			}
			f.got.Add(1)
		}
	}
	go read(c)
	go func() {
		defer close(f.done)
		time.Sleep(downAt)
		c.Close()
		time.Sleep(upAt - downAt)
		c2, err := net.ListenUDP("udp", c.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Errorf("listen again: %v", err)
			return
		}
		t.Cleanup(func() { c2.Close() })
		go read(c2)
	}()
	return f
}

// A UDP sender (syslog, traps, flows) keeps going through a receiver's
// restart once it has been sending for RefusedGrace, counting the refusals
// (lab phase 8: `woodshed send` stopped with "nothing is listening" whenever
// the receiver restarted); a port that refuses from the start still fails
// at once.
func TestSendThroughReceiverRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("about 3 s")
	}
	ctx := context.Background()
	for _, c := range []struct {
		name string
		run  func(addr string, count int, rate float64) (refused, sent int, err error)
	}{
		{"syslog", func(addr string, n int, rate float64) (int, int, error) {
			res, err := Send(ctx, SendOptions{Addr: addr, Proto: "udp", Count: n, Rate: rate, RunID: "0000bbbb"})
			return res.Refused, res.Sent, err
		}},
		{"trap", func(addr string, n int, rate float64) (int, int, error) {
			res, err := Send(ctx, SendOptions{Addr: addr, Proto: "trap", Count: n, Rate: rate, RunID: "0000cccc", Trap: TrapOptions{Version: "2c"}})
			return res.Refused, res.Sent, err
		}},
		{"flows", func(addr string, n int, rate float64) (int, int, error) {
			res, err := SendFlows(ctx, FlowOptions{Proto: ProtoIPFIX, Addr: addr, Count: n, Rate: rate, RecordsPerPacket: 1, RunID: "0000dddd"}, nil)
			return res.Refused, res.Packets, err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			f := startFlaky(t, 1300*time.Millisecond, 1700*time.Millisecond)
			refused, sent, err := c.run(f.addr, 1200, 500) // 2.4 s
			<-f.done
			if err != nil || refused == 0 || sent != 1200 {
				t.Fatalf("through a restart: err %v, refused %d, sent %d", err, refused, sent)
			}
			if f.got.Load() == 0 || f.got.Load() >= 1200 {
				t.Fatalf("received %d of 1200", f.got.Load())
			}
			// Nothing ever listening: the old fast failure.
			l, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			dead := l.LocalAddr().String()
			l.Close()
			start := time.Now()
			_, _, err = c.run(dead, 1000, 1000)
			if err == nil || !strings.Contains(err.Error(), "nothing is listening") || time.Since(start) > RefusedGrace {
				t.Fatalf("closed port: %v after %v", err, time.Since(start))
			}
		})
	}
}
