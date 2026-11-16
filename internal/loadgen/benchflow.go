package loadgen

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store"
)

// The flow bench (SPEC §13.6, §13.8: `woodshed bench --proto ipfix`): an
// in-process flow listener, collector and store in a temporary data folder,
// fed by the flow generator (optionally beside syslog), then the segments read
// back: every record exactly once by sequence number, the pipeline's CPU and
// memory, and the bytes per stored record.

// FlowBenchOptions configures BenchFlows.
type FlowBenchOptions struct {
	Flow    FlowOptions   // the generator (Proto, Rate, Count or Duration, …); Addr is set by the bench
	Settle  time.Duration // wait this long with nothing new arriving before giving up (default 10 s)
	DataDir string
	Keep    bool
	Logger  *slog.Logger
	// SyslogRate sends UDP syslog at this many messages a second beside the
	// flows (0: none).
	SyslogRate float64
	// Sender, if set, sends the flows instead of SendFlows (from another
	// process, so its CPU isn't counted with the pipeline's).
	Sender func(ctx context.Context, o FlowOptions) (FlowResult, error)
}

// FlowBenchResult is what BenchFlows measured.
type FlowBenchResult struct {
	Proto      string
	RunID      string
	Sent       int64 // records the generator sent
	Stored     int64 // distinct sequence numbers in the segments
	Missing    int64
	Duplicates int64
	QueueFull  int64 // datagrams the flow queue dropped (counted)

	TargetRate   float64
	AchievedRate float64 // records a second, as sent
	SendTime     time.Duration
	Elapsed      time.Duration

	CPUSeconds  float64 // this process's CPU while sending (the pipeline; the sender too when in-process)
	Cores       float64 // CPUSeconds / SendTime
	PeakRSS     int64   // the process's peak resident set
	PeakHeap    int64   // the Go heap's peak in use, sampled
	SegmentByte int64   // bytes of .wsf files
	BytesPerRec float64 // SegmentByte / Stored

	SyslogSent   int64 `json:",omitempty"`
	SyslogStored int64 `json:",omitempty"`

	DataDir string
}

// OK reports whether every record arrived exactly once.
func (r FlowBenchResult) OK() bool { return r.Missing == 0 && r.Duplicates == 0 && r.Stored == r.Sent }

func (r FlowBenchResult) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  %s: sent %d records in %v (%.0f rec/s, target %.0f)\n", strings.ToUpper(r.Proto), r.Sent, r.SendTime.Round(time.Millisecond),
		r.AchievedRate, r.TargetRate)
	fmt.Fprintf(&b, "  stored %d, missing %d, duplicates %d, flow queue full %d\n", r.Stored, r.Missing, r.Duplicates, r.QueueFull)
	fmt.Fprintf(&b, "  CPU %.1f s (%.2f cores), peak RSS %.0f MiB, peak heap %.0f MiB\n", r.CPUSeconds, r.Cores,
		float64(r.PeakRSS)/(1<<20), float64(r.PeakHeap)/(1<<20))
	fmt.Fprintf(&b, "  segments %.1f MiB, %.1f bytes per record\n", float64(r.SegmentByte)/(1<<20), r.BytesPerRec)
	if r.SyslogSent > 0 {
		fmt.Fprintf(&b, "  syslog beside it: sent %d, stored %d\n", r.SyslogSent, r.SyslogStored)
	}
	return b.String()
}

// BenchFlows runs the flow bench.
func BenchFlows(ctx context.Context, o FlowBenchOptions) (FlowBenchResult, error) {
	t0 := time.Now()
	if o.Flow.Proto == "" {
		o.Flow.Proto = ProtoIPFIX
	}
	if o.Flow.RunID == "" {
		o.Flow.RunID = NewRunID()[:8]
	}
	if o.Settle <= 0 {
		o.Settle = 10 * time.Second
	}
	if o.Logger == nil {
		o.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	res := FlowBenchResult{Proto: o.Flow.Proto, RunID: o.Flow.RunID, TargetRate: o.Flow.Rate}
	dir := o.DataDir
	if dir == "" {
		d, err := os.MkdirTemp("", "woodshed-flowbench-*")
		if err != nil {
			return res, err
		}
		dir = d
		if !o.Keep {
			defer os.RemoveAll(dir)
		}
	}
	res.DataDir = dir
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		return res, err
	}
	defer idx.Close()
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Logger: o.Logger, Version: "bench"})
	if err != nil {
		return res, err
	}
	storeOpen := true
	defer func() {
		if storeOpen {
			st.Close()
		}
	}()
	coll := flow.NewCollector(flow.Options{})
	var decoded atomic.Int64
	var syslogStored atomic.Int64
	var mu sync.Mutex // the collector's Decode is one goroutine's at a time
	handle := func(p *listen.FlowPacket) {
		addr := p.From.Addr().Unmap()
		var recs []*flow.Record
		var raws []*flow.RawSet
		mu.Lock()
		coll.Decode(flow.Packet{Data: p.Data, From: p.From, Received: p.Received}, func(r *flow.Record) {
			c := *r
			recs = append(recs, &c)
		}, func(rs *flow.RawSet) { raws = append(raws, rs) })
		mu.Unlock()
		if len(recs) > 0 || len(raws) > 0 {
			if st.WriteFlows(addr, store.FlowBatch{Received: p.Received, Size: len(p.Data), Records: recs, Raw: raws}) == nil {
				decoded.Add(int64(len(recs)))
			}
		}
	}
	cfg := config.Listeners{Flow: config.FlowListener{Enabled: true, Addr: "127.0.0.1", IPFIXPort: -1,
		QueueMessages: config.DefaultFlowQueueMessages, QueueBytes: config.DefaultFlowQueueBytes},
		MaxMessageBytes: config.DefaultMaxMessageBytes, UDPRcvbufBytes: config.DefaultUDPRcvbufBytes}
	if o.SyslogRate > 0 {
		cfg.UDP = config.Listener{Enabled: true, Addr: "127.0.0.1", Port: 0}
	}
	ln, err := listen.Start(cfg, listen.Options{Logger: o.Logger, Flow: handle, OnFlowQueueDrop: st.DropQueuedFlows,
		Sink: func(m model.Message) {
			if st.Write(m) == nil {
				syslogStored.Add(1)
			}
		}})
	if err != nil {
		return res, err
	}
	lnOpen := true
	defer func() {
		if lnOpen {
			ln.Close()
		}
	}()
	ap, ok := ln.FlowAddrs()["ipfix"]
	if !ok {
		return res, errors.New("loadgen: the flow listener didn't bind")
	}
	o.Flow.Addr = ap.String()

	// Sample the heap while it runs.
	var peakHeap atomic.Int64
	sampleStop := make(chan struct{})
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		var ms runtime.MemStats
		for {
			select {
			case <-sampleStop:
				return
			case <-t.C:
				runtime.ReadMemStats(&ms)
				if v := int64(ms.HeapInuse); v > peakHeap.Load() {
					peakHeap.Store(v)
				}
			}
		}
	}()

	// Syslog beside it.
	var syslogSent int64
	sysCtx, sysCancel := context.WithCancel(ctx)
	sysDone := make(chan struct{})
	if o.SyslogRate > 0 {
		uap, _ := ln.UDPAddr()
		go func() {
			defer close(sysDone)
			r, _ := Send(sysCtx, SendOptions{Addr: uap.String(), Proto: "udp", Rate: o.SyslogRate, Duration: 24 * time.Hour})
			syslogSent = int64(r.Sent)
		}()
	} else {
		close(sysDone)
	}

	cpu0 := cpuTimes()
	send := o.Sender
	if send == nil {
		send = func(ctx context.Context, fo FlowOptions) (FlowResult, error) { return SendFlows(ctx, fo, nil) }
	}
	sendStart := time.Now()
	fr, err := send(ctx, o.Flow)
	res.SendTime = time.Since(sendStart)
	res.Sent = int64(fr.Records)
	if err != nil {
		sysCancel()
		<-sysDone
		close(sampleStop)
		<-sampleDone
		return res, err
	}
	// Wait for the pipeline: everything decoded, or nothing new for Settle.
	last, lastAt := decoded.Load(), time.Now()
	for decoded.Load() < res.Sent && time.Since(lastAt) < o.Settle && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
		if n := decoded.Load(); n != last {
			last, lastAt = n, time.Now()
		}
	}
	cpu := time.Duration(cpuTimes() - cpu0)
	sysCancel()
	<-sysDone
	res.SyslogSent = syslogSent
	close(sampleStop)
	<-sampleDone
	res.CPUSeconds = cpu.Seconds()
	if res.SendTime > 0 {
		res.AchievedRate = float64(res.Sent) / res.SendTime.Seconds()
		res.Cores = cpu.Seconds() / res.SendTime.Seconds()
	}
	res.PeakHeap = peakHeap.Load()
	lst := ln.Status()
	for _, q := range lst.UDPQueues {
		if q.Listener == "flow" {
			res.QueueFull = q.Dropped
		}
	}
	ln.Close()
	lnOpen = false
	if err := st.Close(); err != nil {
		return res, err
	}
	storeOpen = false
	res.SyslogStored = syslogStored.Load()
	res.PeakRSS = maxRSS()

	// Read the segments back.
	files, err := index.ListFlowFiles(dir)
	if err != nil {
		return res, err
	}
	seen := map[uint64]int{}
	for _, ff := range files {
		res.SegmentByte += ff.Size
		r, err := flowseg.Open(ff.Path)
		if err != nil {
			return res, fmt.Errorf("loadgen: %s: %w", ff.Rel, err)
		}
		var blk flowseg.Block
		var rec flow.Record
		for i := 0; i < r.Blocks(); i++ {
			if err := r.Decode(i, flowseg.ColExtras|flowseg.Cols(flow.HasSrcAS|flow.HasDstAS)|flowseg.ColMeta, &blk); err != nil {
				r.Close()
				return res, err
			}
			for row := 0; row < blk.Rows; row++ {
				blk.Record(row, &rec)
				if tag, seq, ok := FlowSeq(&rec); ok && MatchRun(tag, o.Flow.RunID) {
					seen[seq]++
				}
			}
		}
		r.Close()
	}
	first := uint64(o.Flow.FirstSeq)
	for i := int64(0); i < res.Sent; i++ {
		switch n := seen[first+uint64(i)]; {
		case n == 0:
			res.Missing++
		case n > 1:
			res.Duplicates += int64(n - 1)
		}
	}
	res.Stored = int64(len(seen))
	if res.Stored > 0 {
		res.BytesPerRec = float64(res.SegmentByte) / float64(res.Stored)
	}
	res.Elapsed = time.Since(t0)
	return res, nil
}
