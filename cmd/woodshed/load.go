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

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/snmp"
)

func cmdSend(args []string, stdout, stderr io.Writer) int {
	if flowSendProto(args) != "" {
		return cmdSendFlow(args, stdout, stderr) // sendflow.go
	}
	fs := newFlagSet("send", "", `
Send test syslog messages to a syslog server (Woodshed or any other). Each
message is RFC 5424 and carries a run tag and a sequence number
("seq=<run>:<n>"), so you can find it in the logs.

With --proto trap it sends SNMP traps or informs (v1, v2c or v3) to a trap
receiver on UDP port 162 instead; the run tag and sequence number are in a
varbind. Communities and passphrases are read from files or the environment
($WOODSHED_SNMP_COMMUNITY, $WOODSHED_SNMP_AUTH_PASS, $WOODSHED_SNMP_PRIV_PASS),
never from the command line.

Over UDP (and for traps), a port that refuses (ICMP port unreachable) before a
second of sending stops the run: nothing is listening. A refusal after that is
the receiver going away for a while (a restart): it's counted, the message is
sent again, and sending goes on; the summary says how many.

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
	proto := fs.String("proto", "udp", "`protocol`: udp, tcp, tls or trap (SNMP traps over UDP); flow-v5, flow-v9 or ipfix for flows (see woodshed send --proto ipfix --help)")
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
	if t := loadgen.RefusedText(res.Refused); t != "" {
		fmt.Fprintf(stdout, "%s.\n", t)
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
	if benchFlowProto(args) != "" {
		return cmdBenchFlow(args, stdout, stderr) // benchflow.go
	}
	fs := newFlagSet("bench", "", `
Measure sustained throughput: run an in-process Woodshed (listener on
127.0.0.1, store and live hub) in a temporary data folder, send to it at --rate
for --duration, then read the files back and check that every message arrived
exactly once. It doesn't touch a running Woodshed or its data.

--proto ipfix, flow-v9 or flow-v5 runs the flow bench instead (woodshed bench
--proto ipfix --help).

--proto trap runs the SNMP trap listener and receiver instead (SPEC §11.6):
--snmp-version 1, 2c or 3, --inform to send InformRequests (each Response is
timed), and for v3 --auth and --priv (the run makes up its own user and
passphrases, in memory).

Exit status: 0 when every message arrived exactly once, 1 otherwise.`, stderr)
	proto := fs.String("proto", "udp", "`protocol`: udp, tcp, tls, trap or all (udp, tcp lf, tcp octet, tls lf in turn)")
	snmpVersion := fs.String("snmp-version", "2c", "trap: SNMP `version` 1, 2c or 3")
	inform := fs.Bool("inform", false, "trap: send InformRequests and time each Response (2c, 3)")
	authProto := fs.String("auth", "sha-256", "trap v3: authentication `protocol` (none, md5, sha, sha-224, sha-256, sha-384, sha-512)")
	privProto := fs.String("priv", "aes-128", "trap v3: privacy `protocol` (none, des, aes-128, aes-192, aes-256)")
	keyExt := fs.String("key-ext", "draft", "trap v3, AES-192/256: key extension `method`, draft or alt")
	varbinds := fs.Int("varbinds", 1, "trap: varbinds per trap after the header (`n`, the sequence one first)")
	framing := fs.String("framing", "lf", "TCP and TLS `framing`: lf or octet")
	rate := fs.Float64("rate", loadgen.DefaultBenchRate, "target `messages` per second")
	duration := fs.Duration("duration", loadgen.DefaultBenchDuration, "how long to send (a `duration` such as 30s or 10m)")
	size := fs.Int("size", loadgen.DefaultSize, "approximate message size in `bytes`")
	dataDir := fs.String("data-dir", "", "write the logs here instead of a temporary `folder` (kept afterwards)")
	keep := fs.Bool("keep", false, "keep the temporary data folder")
	asJSON := fs.Bool("json", false, "print the results as JSON")
	queue := fs.Int("udp-queue-messages", 0, "UDP receive queue capacity in `messages` (default 100000)")
	stallEvery := fs.Duration("stall-every", 0, "fake a slow disk: stall writes every `duration` (e.g. 1m) from the start")
	stallFor := fs.Duration("stall-for", 0, "for this `duration` each time (e.g. 3s)")
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	if *queue != 0 && (*queue < config.MinUDPQueueMessages || *queue > config.MaxUDPQueueMessages) {
		fmt.Fprintf(stderr, "woodshed bench: --udp-queue-messages must be between %d and %d\n", config.MinUDPQueueMessages, config.MaxUDPQueueMessages)
		return 2
	}
	if *stallEvery < 0 || *stallFor < 0 || (*stallEvery > 0) != (*stallFor > 0) || (*stallEvery > 0 && *stallFor >= *stallEvery) {
		fmt.Fprintln(stderr, "woodshed bench: --stall-every and --stall-for go together, and --stall-for must be shorter")
		return 2
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
	case "trap":
		runs = []run{{"trap", ""}}
	default:
		fmt.Fprintf(stderr, "woodshed bench: --proto must be udp, tcp, tls, trap or all, not %q\n\n%s", *proto, fs.help())
		return 2
	}
	var trapOpts loadgen.TrapOptions
	if runs[0].proto == "trap" {
		var err error
		if trapOpts, err = benchTrapOptions(*snmpVersion, *inform, *authProto, *privProto, *keyExt, *varbinds); err != nil {
			fmt.Fprintf(stderr, "woodshed bench: %v\n", err)
			return 2
		}
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
			what := strings.ToUpper(r.proto) + " " + r.framing
			if r.proto == "trap" {
				what = trapOpts.Describe()
				if trapOpts.Inform {
					what += " informs"
				}
			}
			fmt.Fprintf(stdout, "bench: %s at %.0f msg/s for %v...\n", strings.TrimSpace(what), *rate, *duration)
		}
		res, err := loadgen.Bench(ctx, loadgen.BenchOptions{
			Proto: r.proto, Framing: r.framing, Rate: *rate, Duration: *duration, Size: *size,
			DataDir: *dataDir, Keep: *keep, QueueMessages: *queue, StallEvery: *stallEvery, StallFor: *stallFor,
			Trap: trapOpts,
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

// benchTrapOptions reads `woodshed bench --proto trap`'s flags.
func benchTrapOptions(version string, inform bool, auth, priv, keyExt string, varbinds int) (loadgen.TrapOptions, error) {
	to := loadgen.TrapOptions{Version: version, Inform: inform, Varbinds: varbinds}
	switch version {
	case "1", "2c", "3":
	default:
		return to, fmt.Errorf("--snmp-version must be 1, 2c or 3, not %q", version)
	}
	if inform && version == "1" {
		return to, errors.New("--inform needs --snmp-version 2c or 3 (v1 has no informs)")
	}
	if varbinds < 1 || varbinds > 1000 {
		return to, fmt.Errorf("--varbinds must be from 1 to 1000, not %d", varbinds)
	}
	if version != "3" {
		return to, nil
	}
	var err error
	if to.Auth, err = snmp.ParseAuthProtocol(auth); err != nil {
		return to, fmt.Errorf("--auth: %v", strings.TrimPrefix(err.Error(), "snmp: "))
	}
	if to.Priv, err = snmp.ParsePrivProtocol(priv); err != nil {
		return to, fmt.Errorf("--priv: %v", strings.TrimPrefix(err.Error(), "snmp: "))
	}
	if to.KeyExt, err = snmp.ParseKeyExt(keyExt); err != nil {
		return to, fmt.Errorf("--key-ext: %v", strings.TrimPrefix(err.Error(), "snmp: "))
	}
	if to.Priv != snmp.PrivNone && to.Auth == snmp.AuthNone {
		return to, errors.New("--priv needs --auth (privacy needs authentication)")
	}
	return to, nil
}
