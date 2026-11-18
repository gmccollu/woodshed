package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/pprofsrv"
	"github.com/gmccollu/woodshed/internal/server"
)

// ---- profile ----

// profileKinds are the captures, with each one's default file extension.
var profileKinds = map[string]struct{ path, ext, what string }{
	"cpu":       {pprofsrv.PathCPU, ".pprof", "CPU profile"},
	"trace":     {pprofsrv.PathTrace, ".trace", "runtime trace"},
	"heap":      {pprofsrv.PathHeap, ".pprof", "heap profile"},
	"goroutine": {pprofsrv.PathGoroutine, ".txt", "goroutine dump"},
}

// maxProfileBytes caps what profile writes from the server.
const maxProfileBytes = 1 << 30

// profileNow is the clock for default file names (tests replace it).
var profileNow = time.Now

// cmdProfile is `woodshed profile` (SPEC §13.10 decision 85).
func cmdProfile(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("profile", "on|off|cpu|trace|heap|goroutine", `
Capture a profile of the running Woodshed on this machine, to find out where
its CPU or memory goes. Profiling is off until you turn it on:

  on         set debug.pprof = true in the config and restart a running
             service. Woodshed then listens on 127.0.0.1 only, on a port the
             OS picks, and answers only requests carrying the token it writes
             into the data folder, so only an administrator of this machine can
             use it.
  off        turn it off again (and restart the service).
  cpu        a CPU profile over --seconds (default 30): which functions use
             the CPU. --trace also captures a runtime trace over the first
             --trace-seconds of it.
  trace      a runtime trace over --seconds (default 5): scheduler, syscall,
             timer and GC waits, for go tool trace.
  heap       a heap profile: where the memory in use was allocated.
  goroutine  every goroutine's stack, as text.

The file goes to --out (default woodshed-<kind>-<time> in this folder). Read a
profile or trace with Go's own tools on any machine with Go: go tool pprof -top
FILE, or go tool trace FILE. None of them holds log contents, but share heap
profiles and goroutine dumps privately, not in a public issue.

Run it as an administrator (sudo): it reads the config and the data folder.

Exit status: 0 when the file is written (or on/off is done), 1 when Woodshed
isn't running, profiling is off, or the capture failed, 2 for a usage error.`, stderr)
	cfgPath := configFlag(fs)
	secs := fs.Int("seconds", 0, "how long a cpu or trace capture runs, in `seconds` (cpu: default 30, at most 300; trace: default 5, at most 60)")
	out := fs.String("out", "", "write it to this `file` (default woodshed-<kind>-<time> with .pprof, .trace or .txt)")
	withTrace := fs.Bool("trace", false, "with cpu: also capture a runtime trace, to the same name with .trace")
	traceSecs := fs.Int("trace-seconds", pprofsrv.DefaultTraceSeconds, "with cpu --trace: the trace's length in `seconds` (at most 60, and at most --seconds)")
	var mode string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		mode, args = args[0], args[1:]
	}
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	if mode == "" && fs.NArg() == 1 {
		mode = fs.Arg(0)
	} else if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "woodshed profile: unexpected argument %q\n\n%s", fs.Arg(0), fs.help())
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	usage := func(msg string) int {
		fmt.Fprintf(stderr, "woodshed profile: %s\n\n%s", msg, fs.help())
		return 2
	}
	switch mode {
	case "on", "off":
		for _, f := range []string{"seconds", "out", "trace", "trace-seconds"} {
			if set[f] {
				return usage("--" + f + " goes with a capture (cpu, trace, heap or goroutine)")
			}
		}
		return profileSwitch(mode == "on", *cfgPath, stdout, stderr)
	case "cpu", "trace", "heap", "goroutine":
	default:
		return usage("say on, off, cpu, trace, heap or goroutine")
	}
	if set["seconds"] && mode != "cpu" && mode != "trace" {
		return usage("--seconds goes with cpu or trace")
	}
	if (*withTrace || set["trace-seconds"]) && mode != "cpu" {
		return usage("--trace and --trace-seconds go with cpu")
	}
	if set["trace-seconds"] && !*withTrace {
		return usage("--trace-seconds goes with --trace")
	}
	n := *secs
	switch mode {
	case "cpu":
		if !set["seconds"] {
			n = pprofsrv.DefaultCPUSeconds
		}
		if n < 1 || n > pprofsrv.MaxCPUSeconds {
			return usage(fmt.Sprintf("--seconds must be from 1 to %d for cpu", pprofsrv.MaxCPUSeconds))
		}
		if *withTrace && (*traceSecs < 1 || *traceSecs > pprofsrv.MaxTraceSeconds || *traceSecs > n) {
			return usage(fmt.Sprintf("--trace-seconds must be from 1 to %d, and at most --seconds", pprofsrv.MaxTraceSeconds))
		}
	case "trace":
		if !set["seconds"] {
			n = pprofsrv.DefaultTraceSeconds
		}
		if n < 1 || n > pprofsrv.MaxTraceSeconds {
			return usage(fmt.Sprintf("--seconds must be from 1 to %d for trace", pprofsrv.MaxTraceSeconds))
		}
	}

	in, code := profileTarget(*cfgPath, stderr)
	if code != 0 {
		return code
	}
	k := profileKinds[mode]
	file := *out
	if file == "" {
		file = fmt.Sprintf("woodshed-%s-%s%s", mode, profileNow().Format("20060102-150405"), k.ext)
	}
	var traceFile string
	if *withTrace {
		traceFile = strings.TrimSuffix(file, filepath.Ext(file)) + ".trace"
		if traceFile == file {
			traceFile = file + ".trace"
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	switch mode {
	case "cpu", "trace":
		fmt.Fprintf(stdout, "Capturing a %d s %s of Woodshed (pid %d)...\n", n, k.what, in.PID)
	default:
		fmt.Fprintf(stdout, "Writing a %s of Woodshed (pid %d)...\n", k.what, in.PID)
	}
	q := ""
	if mode == "cpu" || mode == "trace" {
		q = "?seconds=" + strconv.Itoa(n)
	}
	type result struct {
		size int64
		err  error
	}
	traceDone := make(chan result, 1)
	if traceFile != "" {
		fmt.Fprintf(stdout, "and a %d s runtime trace over its start...\n", *traceSecs)
		go func() {
			n, err := fetchProfile(ctx, in, pprofsrv.PathTrace+"?seconds="+strconv.Itoa(*traceSecs), traceFile)
			traceDone <- result{n, err}
		}()
	}
	size, err := fetchProfile(ctx, in, k.path+q, file)
	if err != nil {
		stop() // the trace too
		if traceFile != "" {
			<-traceDone
		}
		return fail(stderr, "profile", err)
	}
	fmt.Fprintf(stdout, "Wrote %s (%s).\n", file, sizeText(size))
	failed := false
	if traceFile != "" {
		if r := <-traceDone; r.err != nil {
			fmt.Fprintf(stderr, "woodshed profile: the trace: %v\n", r.err)
			failed = true
		} else {
			fmt.Fprintf(stdout, "Wrote %s (%s).\n", traceFile, sizeText(r.size))
		}
	}
	switch mode {
	case "cpu":
		fmt.Fprintf(stdout, "Read it with Go's tools on any machine: go tool pprof -top %s\n", shellQuote(file))
		if traceFile != "" && !failed {
			fmt.Fprintf(stdout, "and go tool trace %s\n", shellQuote(traceFile))
		}
	case "trace":
		fmt.Fprintf(stdout, "Read it with Go's tools on any machine: go tool trace %s\n", shellQuote(file))
	case "heap":
		fmt.Fprintf(stdout, "Read it with Go's tools on any machine: go tool pprof -sample_index=inuse_space -top %s\n", shellQuote(file))
		fmt.Fprintln(stdout, "It shows where memory was allocated, not what it holds; still, share it privately, not in a public issue.")
	case "goroutine":
		fmt.Fprintln(stdout, "It's a text file. Share it privately, not in a public issue.")
	}
	if failed {
		return 1
	}
	return 0
}

// profileTarget reads the config and the profiling listener's file, and says
// why it can't when it can't.
func profileTarget(cfgPath string, stderr io.Writer) (pprofsrv.Info, int) {
	cfg, err := readConfig(cfgPath)
	if err != nil {
		return pprofsrv.Info{}, fail(stderr, "profile", err)
	}
	dataDir := cfg.Storage.DataDir
	in, err := pprofsrv.ReadInfo(dataDir)
	switch {
	case err == nil:
	case errors.Is(err, os.ErrPermission):
		return in, fail(stderr, "profile", adminErr(err))
	case errors.Is(err, os.ErrNotExist):
		if inUse, _ := server.DataDirInUse(dataDir); !inUse {
			return in, fail(stderr, "profile", fmt.Errorf("Woodshed isn't running on %s", dataDir))
		}
		return in, fail(stderr, "profile", fmt.Errorf("profiling is off. Turn it on with %s (it restarts the service), "+
			"capture, then turn it off with woodshed profile off", asAdmin("profile on")))
	default:
		return in, fail(stderr, "profile", err)
	}
	// Never send the token anywhere but this machine, whatever the file says.
	ap, err := netip.ParseAddrPort(in.Addr)
	if err != nil || !ap.Addr().Unmap().IsLoopback() {
		return in, fail(stderr, "profile", fmt.Errorf("%s names %q, not a loopback address; not connecting", pprofsrv.InfoFile, in.Addr))
	}
	return in, 0
}

// fetchProfile GETs path from the profiling listener and writes the body to
// file (through file.part, so a failed capture leaves no half file).
func fetchProfile(ctx context.Context, in pprofsrv.Info, path, file string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+in.Addr+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+in.Token)
	// Loopback only, and never through a proxy.
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
		Timeout: (pprofsrv.MaxCPUSeconds + 60) * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, errors.New("interrupted; nothing written")
		}
		return 0, fmt.Errorf("Woodshed's profiling listener at %s didn't answer (%v). Is the service running with profiling on? "+
			"woodshed status shows it", in.Addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return 0, fmt.Errorf("the server answered %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	part := file + ".part"
	f, err := os.OpenFile(part, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxProfileBytes+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	switch {
	case err == nil && n > maxProfileBytes:
		err = fmt.Errorf("the profile is over %s; not kept", sizeText(maxProfileBytes))
	case err == nil && n == 0:
		err = errors.New("the server sent an empty profile")
	case err != nil && ctx.Err() != nil:
		err = errors.New("interrupted; nothing written")
	}
	if err != nil {
		os.Remove(part)
		return 0, err
	}
	if err := os.Rename(part, file); err != nil {
		os.Remove(part)
		return 0, err
	}
	return n, nil
}

// sizeText is a byte count for people (KiB, MiB).
func sizeText(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// profileSwitch is `woodshed profile on|off`: debug.pprof in the config, and a
// restart of a running service.
func profileSwitch(on bool, cfgPath string, stdout, stderr io.Writer) int {
	word := map[bool]string{true: "on", false: "off"}[on]
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return fail(stderr, "profile", err)
	}
	cfg, err := readConfig(abs)
	if err != nil {
		return fail(stderr, "profile", err)
	}
	dataDir := cfg.Storage.DataDir
	if err := checkWritable(filepath.Dir(abs)); err != nil {
		return fail(stderr, "profile", adminErr(err))
	}
	if cfg.Debug.PProf == on {
		fmt.Fprintf(stdout, "debug.pprof is already %s in %s.\n", map[bool]string{true: "true", false: "false"}[on], abs)
		profileState(stdout, dataDir, on)
		return 0
	}
	next := cfg.Clone()
	next.Debug.PProf = on
	if errs := next.Validate(&cfg); len(errs) > 0 {
		return fail(stderr, "profile", fmt.Errorf("%s: %w", abs, errs))
	}
	if err := saveConfigKeepingOwner(abs, next); err != nil {
		return fail(stderr, "profile", adminErr(err))
	}
	fmt.Fprintf(stdout, "Turned profiling %s (debug.pprof in %s).\n", word, abs)
	before, _ := server.ReadState(dataDir)
	switch a := applyToRunning("profile", dataDir, stderr); a {
	case restarted:
		fmt.Fprintln(stdout, "Restarted the service to use it.")
		if _, ok := waitForRestart(dataDir, before, 20*time.Second); ok {
			profileState(stdout, dataDir, on)
		}
	case applyFailed:
		return 1
	default:
		applyHint(stdout, a, "it uses the change")
	}
	return 0
}

// profileState says what the running server's listener is doing, after on or
// off.
func profileState(stdout io.Writer, dataDir string, want bool) {
	if inUse, _ := server.DataDirInUse(dataDir); !inUse {
		return
	}
	in, err := pprofsrv.ReadInfo(dataDir)
	switch {
	case err == nil && want:
		fmt.Fprintf(stdout, "The profiling listener is on %s (this machine only). Capture with: %s\n", in.Addr, asAdmin("profile cpu --seconds 60"))
	case err == nil && !want && in.Source == "env":
		fmt.Fprintf(stdout, "It's still on: %s is set in the service's environment. Remove it there and restart the service.\n", pprofsrv.EnvVar)
	case err == nil && !want:
		fmt.Fprintln(stdout, "The running server still has it on; restart it to turn it off.")
	case want:
		fmt.Fprintln(stdout, "The running server hasn't turned it on (yet): woodshed status and its log say why.")
	}
}
