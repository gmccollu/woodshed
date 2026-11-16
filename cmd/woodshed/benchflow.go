package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/loadgen"
)

// `woodshed bench --proto ipfix|flow-v9|flow-v5` (SPEC §13.6, §13.8): the
// flow bench, with the sender in a child process (`woodshed send`) so the
// CPU measured is the pipeline's.

// benchFlowProto returns the flow protocol a bench's args ask for, or "".
func benchFlowProto(args []string) string {
	for i, a := range args {
		v := ""
		switch {
		case a == "--proto" || a == "-proto":
			if i+1 < len(args) {
				v = args[i+1]
			}
		case strings.HasPrefix(a, "--proto="), strings.HasPrefix(a, "-proto="):
			v = a[strings.Index(a, "=")+1:]
		}
		if v = strings.ToLower(v); loadgen.IsFlowProto(v) {
			return v
		}
	}
	return ""
}

func cmdBenchFlow(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("bench", "", `
The flow bench: run an in-process flow listener, collector and store in a
temporary data folder, send flow records to it from a child process (woodshed
send, so its CPU isn't counted) at --rate for --duration, then read the
segments back and check that every record arrived exactly once. It reports the
pipeline's CPU (cores), peak memory and the bytes per stored record. It doesn't
touch a running Woodshed or its data.

Exit status: 0 when every record arrived exactly once, 1 otherwise.`, stderr)
	proto := fs.String("proto", "ipfix", "`protocol`: ipfix, flow-v9 or flow-v5")
	rate := fs.Float64("rate", 50000, "target `records` per second")
	duration := fs.Duration("duration", 30*time.Second, "how long to send (a `duration` such as 30s or 10m)")
	rpp := fs.Int("records-per-packet", 30, "records per `packet`")
	domains := fs.Int("domains", 2, "observation `domains`")
	sampling := fs.Int("sampling", 0, "sampled 1 in `N` on the first domain (0: no sampling information)")
	events := fs.Bool("events", false, "send firewall-event records")
	syslogRate := fs.Float64("syslog-rate", 0, "also send UDP syslog at this many `messages` a second")
	inProcess := fs.Bool("in-process", false, "send from this process (its CPU is then counted too)")
	dataDir := fs.String("data-dir", "", "write here instead of a temporary `folder` (kept afterwards)")
	keep := fs.Bool("keep", false, "keep the temporary data folder")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	if *rate <= 0 || *duration <= 0 {
		fmt.Fprintln(stderr, "woodshed bench: --rate and --duration must be positive")
		return 2
	}
	fo := loadgen.FlowOptions{Proto: strings.ToLower(*proto), Rate: *rate, Duration: *duration, RecordsPerPacket: *rpp,
		Domains: *domains, Sampling: *sampling, SampledDomains: 1, Events: *events}
	if *sampling == 0 {
		fo.SampledDomains = 0
	}
	fo.Count = int(*rate * duration.Seconds())
	o := loadgen.FlowBenchOptions{Flow: fo, DataDir: *dataDir, Keep: *keep, SyslogRate: *syslogRate}
	if !*inProcess {
		o.Sender = childFlowSender
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if !*asJSON {
		fmt.Fprintf(stdout, "bench: %s at %.0f records/s for %v...\n", strings.ToUpper(fo.Proto), *rate, *duration)
	}
	res, err := loadgen.BenchFlows(ctx, o)
	if err != nil {
		fmt.Fprintf(stderr, "woodshed bench: %v\n", strings.TrimPrefix(err.Error(), "loadgen: "))
		return 1
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		fmt.Fprint(stdout, res.String())
		if *keep || *dataDir != "" {
			fmt.Fprintf(stdout, "  data kept in %s\n", res.DataDir)
		}
	}
	if !res.OK() {
		return 1
	}
	return 0
}

var sentRE = regexp.MustCompile(`Sent (\d+) `)

// childFlowSender runs `woodshed send` for the run in a child process.
func childFlowSender(ctx context.Context, o loadgen.FlowOptions) (loadgen.FlowResult, error) {
	exe, err := os.Executable()
	if err != nil {
		return loadgen.FlowResult{}, err
	}
	host, port, _ := strings.Cut(o.Addr, ":")
	args := []string{"send", "--proto", o.Proto, "--host", host, "--port", port, "--count", strconv.Itoa(o.Count),
		"--rate", strconv.FormatFloat(o.Rate, 'f', -1, 64), "--records-per-packet", strconv.Itoa(o.RecordsPerPacket),
		"--domains", strconv.Itoa(o.Domains), "--run", o.RunID}
	if o.Sampling > 0 {
		args = append(args, "--sampling", strconv.Itoa(o.Sampling), "--sampled-domains", strconv.Itoa(o.SampledDomains))
	}
	if o.Events {
		args = append(args, "--events")
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	start := time.Now()
	if err := cmd.Run(); err != nil {
		return loadgen.FlowResult{}, fmt.Errorf("the sender: %v: %s", err, strings.TrimSpace(errb.String()))
	}
	m := sentRE.FindStringSubmatch(out.String())
	if m == nil {
		return loadgen.FlowResult{}, fmt.Errorf("the sender said %q", out.String())
	}
	n, _ := strconv.Atoi(m[1])
	el := time.Since(start)
	return loadgen.FlowResult{RunID: o.RunID, Records: n, Elapsed: el, Rate: float64(n) / el.Seconds()}, nil
}
