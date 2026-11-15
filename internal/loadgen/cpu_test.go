package loadgen

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestCPUPerMessage measures the receiving pipeline's process CPU (listener,
// UDP queue and drainer, store, live hub, in this process) per message at low
// rates, for UDP syslog and SNMP traps, with the sender in a child process so
// its CPU isn't counted. It prints a table; it fails only if messages go
// missing, or if WOODSHED_CPU_MAX_PCT is set and a row's CPU (% of one core)
// exceeds it.
//
// Each rate runs twice: this build ("fast") and every datagram through the
// queue as in 1.2.0-rc1 ("queue", BenchOptions.NoFastPath), so one run on any
// OS shows what the fast path saves there.
//
// It's slow (about 6 s a row), so it runs only with WOODSHED_CPU=1; CI runs it
// on every OS and prints the numbers. WOODSHED_CPU_DURATION (default 5s) sets
// each row's length and WOODSHED_CPU_RATES (default "0,10,100,500,2000") the
// rates; 0 is idle.
func TestCPUPerMessage(t *testing.T) {
	if os.Getenv("WOODSHED_CPU") != "1" {
		t.Skip("set WOODSHED_CPU=1 to measure CPU per message")
	}
	if raceEnabled {
		t.Skip("CPU under -race says nothing")
	}
	dur := 5 * time.Second
	if v := os.Getenv("WOODSHED_CPU_DURATION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatal(err)
		}
		dur = d
	}
	rates := []float64{0, 10, 100, 500, 2000}
	if v := os.Getenv("WOODSHED_CPU_RATES"); v != "" {
		rates = nil
		for _, f := range strings.Split(v, ",") {
			r, err := strconv.ParseFloat(strings.TrimSpace(f), 64)
			if err != nil {
				t.Fatal(err)
			}
			rates = append(rates, r)
		}
	}
	maxPct := 0.0
	if v := os.Getenv("WOODSHED_CPU_MAX_PCT"); v != "" {
		maxPct, _ = strconv.ParseFloat(v, 64)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\nprocess CPU on %s/%s, %d CPUs, GOMAXPROCS %d, %v a row (sender in a child process)\n",
		runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), dur)
	fmt.Fprintln(&b, "path: \"fast\" is this build (a lone datagram is stored by the reader); \"queue\" sends every datagram through the drainer, as 1.2.0-rc1 did")
	fmt.Fprintf(&b, "%-5s %-5s %8s %8s %9s %9s %8s %10s %8s\n", "proto", "path", "msg/s", "sent", "user", "kernel", "% core", "µs/msg", "inline")
	for _, proto := range []string{"udp", "trap"} {
		for _, rate := range rates {
			for _, path := range []string{"fast", "queue"} {
				if rate == 0 && (proto == "trap" || path == "queue") {
					continue // idle is idle
				}
				var cpu cpuWindow
				o := BenchOptions{Proto: proto, Rate: rate, Duration: dur, Settle: 2 * time.Second, Sender: childSender(t, &cpu),
					NoFastPath: path == "queue"}
				if rate == 0 {
					o.Rate, o.Sender = 1, idleSender(dur, &cpu)
				}
				res, err := Bench(context.Background(), o)
				if err != nil {
					t.Fatalf("%s at %v/s: %v", proto, rate, err)
				}
				if rate > 0 && !res.OK() {
					t.Errorf("%s at %v/s: %d missing, %d duplicates of %d", proto, rate, res.Missing, res.Duplicates, res.Sent)
				}
				pct := 100 * (cpu.user + cpu.sys).Seconds() / cpu.wall.Seconds()
				per := "-"
				if res.Sent > 0 {
					per = fmt.Sprintf("%.1f", float64((cpu.user+cpu.sys).Microseconds())/float64(res.Sent))
				}
				fmt.Fprintf(&b, "%-5s %-5s %8.0f %8d %9v %9v %7.1f%% %10s %8d\n", proto, path, rate, res.Sent,
					cpu.user.Round(time.Millisecond), cpu.sys.Round(time.Millisecond), pct, per, res.Inline)
				if maxPct > 0 && path == "fast" && pct > maxPct {
					t.Errorf("%s at %v/s: %.1f%% of a core, over WOODSHED_CPU_MAX_PCT=%v", proto, rate, pct, maxPct)
				}
			}
		}
	}
	t.Log(b.String())
}

// cpuWindow is this process's CPU over one send.
type cpuWindow struct{ user, sys, wall time.Duration }

func measure(w *cpuWindow, f func()) {
	u0, s0 := processCPU()
	t0 := time.Now()
	f()
	u1, s1 := processCPU()
	w.user, w.sys, w.wall = u1-u0, s1-s0, time.Since(t0)
}

// idleSender sends nothing for d, measuring the idle pipeline.
func idleSender(d time.Duration, w *cpuWindow) func(context.Context, SendOptions) (SendResult, error) {
	return func(ctx context.Context, o SendOptions) (SendResult, error) {
		measure(w, func() { time.Sleep(d) })
		return SendResult{RunID: o.RunID, Elapsed: d}, nil
	}
}

// childSender runs Send in a child process (this test binary, running
// TestCPUChildSender) and measures this process's CPU meanwhile.
func childSender(t *testing.T, w *cpuWindow) func(context.Context, SendOptions) (SendResult, error) {
	return func(ctx context.Context, o SendOptions) (SendResult, error) {
		o.TLS = nil
		in, err := json.Marshal(o)
		if err != nil {
			return SendResult{}, err
		}
		out := filepath.Join(t.TempDir(), "result.json")
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCPUChildSender$")
		cmd.Env = append(os.Environ(), "WOODSHED_CPU_CHILD="+string(in), "WOODSHED_CPU_CHILD_OUT="+out)
		var runErr error
		var output []byte
		measure(w, func() { output, runErr = cmd.CombinedOutput() })
		if runErr != nil {
			return SendResult{}, fmt.Errorf("child sender: %v\n%s", runErr, output)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			return SendResult{}, fmt.Errorf("child sender wrote no result: %v\n%s", err, output)
		}
		var res SendResult
		return res, json.Unmarshal(b, &res)
	}
}

// TestCPUChildSender is TestCPUPerMessage's sender, run in a child process.
func TestCPUChildSender(t *testing.T) {
	in := os.Getenv("WOODSHED_CPU_CHILD")
	if in == "" {
		t.Skip("only as TestCPUPerMessage's child")
	}
	var o SendOptions
	if err := json.Unmarshal([]byte(in), &o); err != nil {
		t.Fatal(err)
	}
	res, err := Send(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if err := os.WriteFile(os.Getenv("WOODSHED_CPU_CHILD_OUT"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}
