package poller

import (
	"bytes"
	"compress/gzip"
	"math/rand/v2"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// fileSink writes records in the store's line envelope, as the poll files
// hold them.
type fileSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *fileSink) Write(dev netip.Addr, at time.Time, rec []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Write(logfile.AppendLine(nil, at, dev, rec))
	return nil
}
func (s *fileSink) Paused() bool               { return false }
func (s *fileSink) AddHourly([]pollrec.Hourly) {}

// TestPollStoragePerDay measures what one device with 24 interfaces writes in
// a day at the default 60 s interval with the default presets (SPEC §12.11
// #4): 1,440 cycles on a fake clock against the test agent, with traffic that
// varies, then the day's file gzipped as the store compresses it. Run with
// WOODSHED_POLL_STORAGE=1; it logs the numbers.
func TestPollStoragePerDay(t *testing.T) {
	if os.Getenv("WOODSHED_POLL_STORAGE") == "" {
		t.Skip("set WOODSHED_POLL_STORAGE=1 to measure the poll storage per device per day")
	}
	var ifs []agenttest.Interface
	for i := 1; i <= 24; i++ {
		ifs = append(ifs, agenttest.Interface{Index: i, Name: "GigabitEthernet0/" + itoa(i), Descr: "GigabitEthernet0/" + itoa(i),
			Alias: "uplink to rack " + itoa(i), SpeedMbps: 1000, InBps: float64(i) * 3e6, OutBps: float64(i) * 1e6,
			InUcastPps: float64(i) * 400, OutUcastPps: float64(i) * 150, InMcastPps: 3, InBcastPps: 1, InErrPs: 0.01})
	}
	h := newHarness(t, agenttest.Options{Interfaces: ifs, HostResources: true, CPUs: []int{12, 30, 7, 19}, MemUsed: 3 << 30,
		MemTotal: 8 << 30, SysName: "edge-fw-01", SysDescr: "Test switch, 24 ports, software 1.2.3"}, defaultSettings())
	sink := &fileSink{}
	h.p.o.Sink = sink
	rng := rand.New(rand.NewPCG(1, 2))
	for c := 0; c < 1440; c++ {
		h.cycle()
		h.clock.Advance(60 * time.Second)
		if c%10 == 0 { // traffic changes every 10 minutes
			for i := 1; i <= 24; i++ {
				h.a.SetRates(i, rng.Float64()*200e6, rng.Float64()*50e6)
			}
			h.a.SetCPU(rng.IntN(100), rng.IntN(100), rng.IntN(100), rng.IntN(100))
		}
	}
	raw := sink.buf.Len()
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.DefaultCompression)
	zw.Write(sink.buf.Bytes())
	zw.Close()
	lines := bytes.Count(sink.buf.Bytes(), []byte{'\n'})
	t.Logf("one device, 24 interfaces, 60 s, presets system+system-info+interfaces, one day: %d lines, %.2f MB uncompressed, %.2f MB gzipped (%.1fx)",
		lines, float64(raw)/1e6, float64(gz.Len())/1e6, float64(raw)/float64(gz.Len()))
	if raw == 0 || gz.Len() == 0 {
		t.Fatal("nothing written")
	}
}

func itoa(i int) string { return string(rune('0'+i/10)) + string(rune('0'+i%10)) }
