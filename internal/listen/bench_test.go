package listen

import (
	"net"
	"net/netip"
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

// BenchmarkReaderPath compares the UDP reader's own work per datagram, without
// the socket: "inline" is 1.1's (blocklist and allowlist, truncation, copy,
// parse and the sink call, here a no-op), "queued" is 1.2's (the same up to the
// copy, then a push; a drainer pops, parses and calls the sink concurrently).
// "drained" is the queue's whole cost per message: push, pop, parse and sink.
func BenchmarkReaderPath(b *testing.B) {
	msg := []byte("<134>1 2026-11-14T09:30:58.112Z fw01 app 4242 ID47 - " + strings.Repeat("x", 140))
	from := netip.MustParseAddr("192.0.2.10")
	newServer := func(b *testing.B, sink Sink) *Server {
		s, err := Start(config.Listeners{}, Options{Sink: sink, Logger: quiet, Holder: func(string, int) string { return "" }})
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() { s.Close() })
		return s
	}
	b.Run("inline", func(b *testing.B) {
		s := newServer(b, func(model.Message) {})
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.deliver(msg, from, false)
		}
	})
	b.Run("queued", func(b *testing.B) {
		var got atomic.Int64
		s := newServer(b, func(model.Message) { got.Add(1) })
		q := newUDPQueue(config.MaxUDPQueueMessages, config.MaxUDPQueueBytes, &queueHist{})
		done := make(chan struct{})
		go func() { defer close(done); s.drainQueue(q) }()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.enqueue(q, msg, from)
		}
		b.StopTimer()
		q.close()
		<-done
		if got.Load() != int64(b.N) {
			b.Fatalf("delivered %d of %d", got.Load(), b.N)
		}
	})
	b.Run("drained", func(b *testing.B) {
		var got atomic.Int64
		s := newServer(b, func(model.Message) { got.Add(1) })
		q := newUDPQueue(config.MaxUDPQueueMessages, config.MaxUDPQueueBytes, &queueHist{})
		done := make(chan struct{})
		go func() { defer close(done); s.drainQueue(q) }()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			s.enqueue(q, msg, from)
		}
		q.close()
		<-done
		if got.Load() != int64(b.N) {
			b.Fatalf("delivered %d of %d", got.Load(), b.N)
		}
	})
}
