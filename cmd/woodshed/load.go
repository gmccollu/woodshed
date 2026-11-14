package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/loadgen"
)

func cmdSend(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("send", "", `
Send test syslog messages to a syslog server (Woodshed or any other). Each
message is RFC 5424 and carries a run tag and a sequence number
("seq=<run>:<n>"), so you can find it in the logs.

With --proto trap it sends SNMP traps or informs (v1, v2c or v3) to a trap
receiver on UDP port 162 instead; the run tag and sequence number are in a
varbind. Communities and passphrases are read from files or the environment
($WOODSHED_SNMP_COMMUNITY, $WOODSHED_SNMP_AUTH_PASS, $WOODSHED_SNMP_PRIV_PASS),
never from the command line.

Examples:
  woodshed send --message "hello from woodshed"          one message to 127.0.0.1:514 over UDP
  woodshed send --host 192.0.2.10 --proto tcp --count 100
  woodshed send --port 15514 --rate 200 --duration 60s    a steady stream for a minute
  woodshed send --host logs-01.example.net --proto tls --ca woodshed-ca.pem
                                                         over TLS (port 6514), checking the
                                                         certificate against the downloaded CA
  woodshed send --proto trap --count 10                   ten SNMPv2c traps to 127.0.0.1:162
  WOODSHED_SNMP_AUTH_PASS=… WOODSHED_SNMP_PRIV_PASS=… woodshed send --proto trap --snmp-version 3 \
      --user monitor --auth sha-256 --priv aes-128 --inform
                                                         SNMPv3 authPriv informs, waiting for each Response`, stderr)
	host := fs.String("host", "127.0.0.1", "syslog server (or trap receiver) `host` name or IP")
	port := fs.Int("port", 514, "syslog server `port` (6514 with --proto tls, 162 with --proto trap)")
	proto := fs.String("proto", "udp", "`protocol`: udp, tcp, tls or trap (SNMP traps over UDP)")
	framing := fs.String("framing", "lf", "TCP and TLS `framing`: lf (newline) or octet (RFC 6587 octet counting)")
	caFile := fs.String("ca", "", "TLS: the CA certificate `file` to trust (PEM or DER, e.g. Woodshed's woodshed-ca.pem)")
	insecure := fs.Bool("insecure", false, "TLS: don't check the server's certificate (a quick test only)")
	serverName := fs.String("server-name", "", "TLS: the `name` to check the certificate for (default: --host)")
	count := fs.Int("count", 0, "`number` of messages (default 1, or rate x duration)")
	rate := fs.Float64("rate", 0, "`messages` per second (0: as fast as possible)")
	duration := fs.Duration("duration", 0, "send at --rate for this `duration` (e.g. 60s), instead of --count")
	message := fs.String("message", "", "message `text` after the sequence tag (default: padding to --size)")
	size := fs.Int("size", loadgen.DefaultSize, "approximate message size in `bytes` when --message isn't set")
	source := fs.String("source", "", "local `IP` to send from (default: chosen by the OS)")
	hostname := fs.String("hostname", loadgen.DefaultHostname, "the messages' HOSTNAME `field`")
	runID := fs.String("run", "", "run `id` carried in every message (default: random); with --first-seq, lets several sends share one numbered run")
	firstSeq := fs.Int("first-seq", 0, "sequence `number` of the first message")
	tf := addTrapFlags(fs)
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	usageErr := func(err error) int {
		fmt.Fprintf(stderr, "woodshed send: %v\n\n%s", err, fs.help())
		return 2
	}
	if *port < 1 || *port > 65535 {
		return usageErr(fmt.Errorf("--port %d is out of range (1-65535)", *port))
	}
	*proto = strings.ToLower(*proto)
	if *proto != "udp" && *proto != "tcp" && *proto != "tls" && *proto != "trap" {
		return usageErr(fmt.Errorf("--proto must be udp, tcp, tls or trap, not %q", *proto))
	}
	if err := checkTrapFlags(fs, *proto); err != nil {
		return usageErr(err)
	}
	portSet := false
	fs.Visit(func(f *flag.Flag) { portSet = portSet || f.Name == "port" })
	var trapOpts loadgen.TrapOptions
	if *proto == "trap" {
		if !portSet {
			*port = 162
		}
		var err error
		if trapOpts, err = tf.options(); err != nil {
			return usageErr(err)
		}
	}
	var tlsCfg *tls.Config
	if *proto == "tls" {
		if !portSet {
			*port = 6514
		}
		if *caFile != "" && *insecure {
			return usageErr(errors.New("give --ca or --insecure, not both"))
		}
		cfg, err := loadgen.ClientTLSConfig(*caFile, *serverName, *insecure)
		if err != nil {
			return usageErr(errors.New(strings.TrimPrefix(err.Error(), "loadgen: ")))
		}
		tlsCfg = cfg
	} else if *caFile != "" || *insecure || *serverName != "" {
		return usageErr(errors.New("--ca, --insecure and --server-name are for --proto tls"))
	}
	*framing = strings.ToLower(*framing)
	if *framing != "lf" && *framing != "octet" {
		return usageErr(fmt.Errorf("--framing must be lf or octet, not %q", *framing))
	}
	if *count < 0 || *rate < 0 || *duration < 0 {
		return usageErr(errors.New("--count, --rate and --duration can't be negative"))
	}
	if *duration > 0 && *rate == 0 {
		return usageErr(errors.New("--duration needs --rate"))
	}
	if *duration > 0 && *count > 0 {
		return usageErr(errors.New("give --count or --duration, not both"))
	}
	if *count == 0 && *duration == 0 {
		*count = 1
	}
	o := loadgen.SendOptions{
		Addr: net.JoinHostPort(*host, strconv.Itoa(*port)), Proto: *proto, Framing: *framing, TLS: tlsCfg,
		Count: *count, Rate: *rate, Duration: *duration, Size: *size,
		Message: *message, Source: *source, Hostname: *hostname,
		RunID: *runID, FirstSeq: *firstSeq, Trap: trapOpts,
	}
	if *firstSeq < 0 {
		return usageErr(errors.New("--first-seq can't be negative"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := loadgen.Send(ctx, o)
	if *proto == "trap" {
		return sendTrapResult(stdout, stderr, o, res, err)
	}
	what := strings.ToUpper(*proto)
	if *proto == "tcp" || *proto == "tls" {
		what += " (" + *framing + ")"
	}
	plural := "s"
	if res.Sent == 1 {
		plural = ""
	}
	switch {
	case res.Sent == 1 && err == nil:
		fmt.Fprintf(stdout, "Sent 1 message to %s over %s, run %s.\n", o.Addr, what, res.RunID)
	case res.Sent > 0 || err == nil:
		fmt.Fprintf(stdout, "Sent %d message%s to %s over %s in %v (%.0f msg/s), run %s.\n",
			res.Sent, plural, o.Addr, what, res.Elapsed.Round(time.Millisecond), res.Rate, res.RunID)
	}
	if res.Sent > 0 {
		fmt.Fprintf(stdout, "Find them by searching for %q.\n", loadgen.SeqTag(res.RunID))
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "woodshed send: interrupted")
			return 1
		}
		return fail(stderr, "send", err)
	}
	if *proto == "udp" {
		fmt.Fprintln(stdout, "(UDP has no delivery confirmation: check the receiver to see that they arrived.)")
	}
	return 0
}

func cmdBench(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("bench", "", `
Measure sustained throughput: run an in-process Woodshed (listener on
127.0.0.1, store and live hub) in a temporary data folder, send to it at --rate
for --duration, then read the files back and check that every message arrived
exactly once. It doesn't touch a running Woodshed or its data.

Exit status: 0 when every message arrived exactly once, 1 otherwise.`, stderr)
	proto := fs.String("proto", "udp", "`protocol`: udp, tcp, tls or all (udp, tcp lf, tcp octet, tls lf in turn)")
	framing := fs.String("framing", "lf", "TCP and TLS `framing`: lf or octet")
	rate := fs.Float64("rate", loadgen.DefaultBenchRate, "target `messages` per second")
	duration := fs.Duration("duration", loadgen.DefaultBenchDuration, "how long to send (a `duration` such as 30s or 10m)")
	size := fs.Int("size", loadgen.DefaultSize, "approximate message size in `bytes`")
	dataDir := fs.String("data-dir", "", "write the logs here instead of a temporary `folder` (kept afterwards)")
	keep := fs.Bool("keep", false, "keep the temporary data folder")
	asJSON := fs.Bool("json", false, "print the results as JSON")
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	type run struct{ proto, framing string }
	var runs []run
	switch strings.ToLower(*proto) {
	case "udp":
		runs = []run{{"udp", ""}}
	case "tcp", "tls":
		if *framing != "lf" && *framing != "octet" {
			fmt.Fprintf(stderr, "woodshed bench: --framing must be lf or octet, not %q\n", *framing)
			return 2
		}
		runs = []run{{strings.ToLower(*proto), *framing}}
	case "all":
		runs = []run{{"udp", ""}, {"tcp", "lf"}, {"tcp", "octet"}, {"tls", "lf"}}
	default:
		fmt.Fprintf(stderr, "woodshed bench: --proto must be udp, tcp, tls or all, not %q\n\n%s", *proto, fs.help())
		return 2
	}
	if *rate <= 0 || *duration <= 0 {
		fmt.Fprintln(stderr, "woodshed bench: --rate and --duration must be positive")
		return 2
	}
	if *dataDir != "" && len(runs) > 1 {
		fmt.Fprintln(stderr, "woodshed bench: --data-dir works with one protocol at a time")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ok := true
	var results []loadgen.BenchResult
	for _, r := range runs {
		if !*asJSON {
			fmt.Fprintf(stdout, "bench: %s %s at %.0f msg/s for %v...\n", strings.ToUpper(r.proto), r.framing, *rate, *duration)
		}
		res, err := loadgen.Bench(ctx, loadgen.BenchOptions{
			Proto: r.proto, Framing: r.framing, Rate: *rate, Duration: *duration, Size: *size,
			DataDir: *dataDir, Keep: *keep,
		})
		results = append(results, res)
		if err != nil {
			ok = false
			fmt.Fprintf(stderr, "woodshed bench: %s: %v\n", r.proto, strings.TrimPrefix(err.Error(), "loadgen: "))
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if !res.OK() {
			ok = false
		}
		if !*asJSON {
			fmt.Fprint(stdout, res.String())
			if *keep || *dataDir != "" {
				fmt.Fprintf(stdout, "  data kept in %s\n", res.DataDir)
			}
		}
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	}
	if !ok {
		return 1
	}
	return 0
}
