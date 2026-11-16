//go:build !windows

package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/poller"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

// The poller under load (SPEC §12.8): N test agents with M interfaces each, in
// a child process (so this process's CPU is the server's alone), polled every
// interval through a real server; then syslog at 10,000 msg/s from the child
// beside the polling, which must lose nothing. It reports the server's CPU
// (user + system time over wall time) and memory.
//
//	WOODSHED_POLL_LOAD=500,64,60,2c go test -run TestPollLoad -v -timeout 30m ./internal/server/
//	WOODSHED_POLL_LOAD=100,64,30,3 ...                (v3 authPriv: SHA-256, AES-128)
//
// Optional: WOODSHED_POLL_LOAD_MEASURE (default 120s), WOODSHED_POLL_LOAD_SYSLOG
// (default 60s at 10,000 msg/s; 0 skips it).

const (
	pollLoadChildEnv = "WOODSHED_POLL_LOAD_CHILD"
	loadAuthPass     = "load-auth-pass-test"
	loadPrivPass     = "load-priv-pass-test"
	loadCommunity    = "load-community-test"
)

func loadUser() snmp.User {
	return snmp.User{Name: "loadtest", Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128, AuthPass: []byte(loadAuthPass),
		PrivPass: []byte(loadPrivPass), Level: snmp.AuthPriv}
}

// TestPollLoadChild is the child: it starts the agents, prints their ports,
// then runs syslog bursts on request and exits when stdin closes.
func TestPollLoadChild(t *testing.T) {
	spec := os.Getenv(pollLoadChildEnv)
	if spec == "" {
		t.Skip("the load test's child process")
	}
	var n, ifs int
	fmt.Sscanf(spec, "%d,%d", &n, &ifs)
	noIfX := os.Getenv("WOODSHED_POLL_LOAD_CHILD_32BIT") != "" // 32-bit counters only (for a wrap)
	var ports []int
	var agents []*agenttest.Agent
	for i := range n {
		var list []agenttest.Interface
		for j := 1; j <= ifs; j++ {
			list = append(list, agenttest.Interface{Index: j, Name: fmt.Sprintf("ge0/%d", j), Descr: fmt.Sprintf("ge0/%d", j),
				SpeedMbps: 1000, InBps: float64(1+(i+j)%50) * 1e6, OutBps: float64(1+(i*j)%20) * 1e6, InUcastPps: 1000, OutUcastPps: 500})
		}
		a, err := agenttest.Start(agenttest.Options{Community: loadCommunity, Users: []snmp.User{loadUser()}, Interfaces: list,
			NoIfXTable:    noIfX && i == 0,
			HostResources: true, CPUs: []int{10, 20}, MemUsed: 1 << 30, MemTotal: 4 << 30, SysName: fmt.Sprintf("load-%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		agents = append(agents, a)
		ports = append(ports, int(a.Addr().Port()))
	}
	b, _ := json.Marshal(ports)
	fmt.Printf("PORTS %s\n", b)
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// Hooks for a manual end-to-end run against a real binary: "reboot I",
		// "restart I", "wrap I IF" (a Counter32 wrap), "down I IF", "up I IF".
		if len(f) >= 2 && f[0] != "syslog" {
			i, _ := strconv.Atoi(f[1])
			if i < 0 || i >= len(agents) {
				fmt.Printf("ERR no agent %d\n", i)
				continue
			}
			ifx := 1
			if len(f) >= 3 {
				ifx, _ = strconv.Atoi(f[2])
			}
			switch f[0] {
			case "reboot":
				agents[i].Reboot()
			case "restart":
				agents[i].Restart()
			case "wrap":
				agents[i].WrapCounter32(ifx, 1000)
			case "down":
				agents[i].SetOper(ifx, 2)
			case "up":
				agents[i].SetOper(ifx, 1)
			}
			fmt.Printf("OK %s\n", sc.Text())
			continue
		}
		if len(f) == 4 && f[0] == "syslog" {
			rate, _ := strconv.ParseFloat(f[2], 64)
			secs, _ := strconv.Atoi(f[3])
			res, err := loadgen.Send(context.Background(), loadgen.SendOptions{Addr: f[1], Proto: "udp", Rate: rate,
				Count: int(rate) * secs})
			if err != nil {
				fmt.Printf("SYSLOG-ERR %v\n", err)
				continue
			}
			fmt.Printf("SYSLOG %s %d\n", res.RunID, res.Sent)
		}
	}
	for _, a := range agents {
		a.Close()
	}
}

type cpuSample struct {
	at       time.Time
	cpu      time.Duration
	maxRSSkB int64
}

func sampleCPU() cpuSample {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	tv := func(t syscall.Timeval) time.Duration {
		return time.Duration(t.Sec)*time.Second + time.Duration(t.Usec)*time.Microsecond
	}
	rss := int64(ru.Maxrss)
	if runtime.GOOS == "darwin" {
		rss /= 1024 // bytes on macOS, kB on Linux
	}
	return cpuSample{at: time.Now(), cpu: tv(ru.Utime) + tv(ru.Stime), maxRSSkB: rss}
}

func TestPollLoad(t *testing.T) {
	spec := os.Getenv("WOODSHED_POLL_LOAD")
	if spec == "" {
		t.Skip("set WOODSHED_POLL_LOAD=devices,interfaces,interval_s,version (e.g. 500,64,60,2c)")
	}
	parts := strings.Split(spec, ",")
	if len(parts) != 4 {
		t.Fatal("WOODSHED_POLL_LOAD is devices,interfaces,interval_s,version")
	}
	n, _ := strconv.Atoi(parts[0])
	ifs, _ := strconv.Atoi(parts[1])
	interval, _ := strconv.Atoi(parts[2])
	version := parts[3]
	measure := 120 * time.Second
	if v := os.Getenv("WOODSHED_POLL_LOAD_MEASURE"); v != "" {
		measure, _ = time.ParseDuration(v)
	}
	syslogFor := 60 * time.Second
	if v := os.Getenv("WOODSHED_POLL_LOAD_SYSLOG"); v != "" {
		syslogFor, _ = time.ParseDuration(v)
	}

	// The agents, in a child process.
	exe, _ := os.Executable()
	cmd := exec.Command(exe, "-test.run", "^TestPollLoadChild$", "-test.timeout", "0")
	cmd.Env = append(os.Environ(), pollLoadChildEnv+"="+parts[0]+","+parts[1])
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); cmd.Wait() }()
	lines := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	var ports []int
	for l := range lines {
		if strings.HasPrefix(l, "PORTS ") {
			json.Unmarshal([]byte(l[6:]), &ports)
			break
		}
	}
	if len(ports) != n {
		t.Fatalf("%d agents started, want %d", len(ports), n)
	}

	dir := t.TempDir()
	syslogPort := freePort(t)
	cfgPath := writeConfig(t, dir, syslogPort, 0, func(c *config.Config) {
		c.Poll.MaxTargets = max(n, 500)
	})
	srv, err := Open(cfgPath, Options{Version: "1.3.0", Commit: "load", Logger: testLogger(t)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{srv: srv, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- srv.Run(ctx) }()
	waitFor(t, "the UI", func() bool { return srv.UIState().Listening })
	r.base = "http://" + srv.UIState().Addr
	defer r.stop(t)
	if version == "3" {
		if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "loadtest", "auth": "sha-256", "auth_pass": loadAuthPass,
			"priv": "aes-128", "priv_pass": loadPrivPass}, nil); code != 201 {
			t.Fatalf("user %d", code)
		}
	}
	for i, p := range ports {
		body := map[string]any{"address": "127.0.0.1", "port": p, "device_id": fmt.Sprintf("10.%d.%d.%d", 200+i/65536, i/256%256, i%256),
			"version": version, "interval_s": interval}
		if version == "3" {
			body["v3_user"] = "loadtest"
		} else {
			body["community"] = loadCommunity
		}
		if code := r.do(t, "POST", "/api/poll/targets", body, nil); code != 201 {
			t.Fatalf("target %d: %d", i, code)
		}
	}
	t.Logf("%d targets added; warming up for %d s (the start offsets spread over one interval)", n, interval+15)
	time.Sleep(time.Duration(interval+15) * time.Second)

	summary := func() poller.Summary {
		var s poller.Summary
		r.do(t, "GET", "/api/poll", nil, &s)
		return s
	}
	report := func(phase string, a, b cpuSample, s0, s1 poller.Summary) {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		wall := b.at.Sub(a.at)
		cores := float64(b.cpu-a.cpu) / float64(wall)
		fails := map[string]int64{}
		for k, v := range s1.Hour.Failures {
			fails[k] = v - s0.Hour.Failures[k]
		}
		t.Logf("%s: %d devices x %d interfaces every %d s (v%s), %v: CPU %.3f cores (user+system / wall), "+
			"max RSS %.0f MiB, Go heap in use %.0f MiB (sys %.0f MiB); cycles %d, failures %v, overruns %d, unmatched %d; answering %d/%d",
			phase, n, ifs, interval, version, wall.Round(time.Second), cores, float64(b.maxRSSkB)/1024, float64(ms.HeapInuse)/(1<<20),
			float64(ms.Sys)/(1<<20), s1.Hour.Cycles-s0.Hour.Cycles, fails, s1.Hour.Overruns-s0.Hour.Overruns,
			s1.Hour.Unmatched-s0.Hour.Unmatched, s1.Answering, s1.Targets)
	}
	// Polling alone.
	s0, c0 := summary(), sampleCPU()
	time.Sleep(measure)
	s1, c1 := summary(), sampleCPU()
	report("polling", c0, c1, s0, s1)
	if s1.Hour.Overruns != s0.Hour.Overruns {
		t.Errorf("%d overruns", s1.Hour.Overruns-s0.Hour.Overruns)
	}
	if s1.Answering != n {
		t.Errorf("%d of %d answering", s1.Answering, n)
	}
	want := int64(float64(n) * measure.Seconds() / float64(interval))
	if got := s1.Hour.Cycles - s0.Hour.Cycles; got < want*9/10 {
		t.Errorf("%d cycles in %v, want about %d (every cycle on time)", got, measure, want)
	}

	// Syslog at 10,000 msg/s beside it: nothing lost.
	if syslogFor <= 0 {
		return
	}
	s2, c2 := summary(), sampleCPU()
	fmt.Fprintf(stdin, "syslog 127.0.0.1:%d 10000 %d\n", syslogPort, int(syslogFor/time.Second))
	var runID string
	var sent int
	for l := range lines {
		if strings.HasPrefix(l, "SYSLOG ") {
			f := strings.Fields(l)
			runID, _ = f[1], 0
			sent, _ = strconv.Atoi(f[2])
			break
		}
		if strings.HasPrefix(l, "SYSLOG-ERR") {
			t.Fatal(l)
		}
	}
	s3, c3 := summary(), sampleCPU()
	report("polling + syslog 10,000 msg/s", c2, c3, s2, s3)
	var v loadgen.VerifyResult
	waitFor(t, "the syslog run stored", func() bool {
		srv.store.Flush()
		var err error
		v, err = loadgen.Verify(filepath.Join(dir, "data"), runID, sent)
		return err == nil && v.Missing == 0
	})
	t.Logf("syslog beside the polling: %d sent, %d missing, %d duplicates", sent, v.Missing, v.Duplicates)
	if v.Missing != 0 || v.Duplicates != 0 {
		t.Errorf("syslog lost %d (dup %d)", v.Missing, v.Duplicates)
	}
	if s3.Hour.Overruns != s2.Hour.Overruns {
		t.Errorf("%d overruns beside syslog", s3.Hour.Overruns-s2.Hour.Overruns)
	}
	_ = io.Discard
}
