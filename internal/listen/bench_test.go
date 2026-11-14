package listen

import (
	"net"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/model"
)

// BenchmarkUDPReceive measures the UDP receive path per message, end to end:
// a datagram sent on loopback until the sink has it (read, allowlist, parse and
// hand-off). The sender keeps at most udpBenchWindow datagrams in flight, so the
// socket buffer never overflows and every one is counted.
func BenchmarkUDPReceive(b *testing.B) {
	const udpBenchWindow = 256
	var got atomic.Int64
	cfg := config.Listeners{UDP: config.Listener{Enabled: true, Addr: "127.0.0.1", Port: 0}}
	s, err := Start(cfg, Options{Sink: func(model.Message) { got.Add(1) }, Logger: quiet,
		Holder: func(string, int) string { return "" }})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	ap, _ := s.UDPAddr()
	conn, err := net.Dial("udp", ap.String())
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("<134>1 2026-11-14T09:30:58.112Z fw01 app 4242 ID47 - " + strings.Repeat("x", 140))
	b.SetBytes(int64(len(msg)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for int64(i)-got.Load() >= udpBenchWindow {
			runtime.Gosched()
		}
		if _, err := conn.Write(msg); err != nil {
			b.Fatal(err)
		}
	}
	for got.Load() < int64(b.N) {
		runtime.Gosched()
	}
}
