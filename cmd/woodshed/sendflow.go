package main

import (
	"bufio"
	"context"
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

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

// flowSendProto returns the flow protocol a `woodshed send` command line
// asks for ("" for syslog and traps), so cmdSend can hand it to
// cmdSendFlow.
func flowSendProto(args []string) string {
	for i, a := range args {
		if a == "--" {
			break
		}
		for _, p := range []string{"--proto", "-proto"} {
			if a == p && i+1 < len(args) {
				if v := strings.ToLower(args[i+1]); loadgen.IsFlowProto(v) {
					return v
				}
			}
			if v, ok := strings.CutPrefix(a, p+"="); ok && loadgen.IsFlowProto(strings.ToLower(v)) {
				return strings.ToLower(v)
			}
		}
	}
	return ""
}

// flowLogLine is one record of `woodshed send --log`, for checking a run
// against what Woodshed stored.
type flowLogLine struct {
	Seq       uint64 `json:"seq"`
	Domain    uint32 `json:"domain"`
	Start     string `json:"start"`
	End       string `json:"end"`
	Src       string `json:"src,omitempty"`
	Dst       string `json:"dst,omitempty"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Proto     uint8  `json:"proto"`
	Packets   uint64 `json:"packets"`
	Bytes     uint64 `json:"bytes"`
	SumBytes  uint64 `json:"sum_bytes"` // what the record adds to a byte sum (SPEC §13.2.1)
	Sampling  uint32 `json:"sampling"`
	FwEvent   string `json:"fw_event,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	PostNATIP string `json:"post_nat_src,omitempty"`
}

func cmdSendFlow(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("send", "", `
Send test flow records (flow v5, flow v9 (RFC 3954) or IPFIX (RFC 7011) over UDP) to a flow
collector (Woodshed or any other). Every record carries the run ID and a
sequence number: in IPFIX as enterprise IEs under 32473 (IANA's documentation
number), in v9 as field types 40001 and 40002, in v5 in src_as and dst_as
(the sequence number) and the header's engine fields (the run ID's last 4 hex
digits). With --events each record also carries a rule ID: IPFIX IE 32473:3,
v9 field type 40003 (listeners.flow.rule_id_ies "32473:3" or "0:40003" fills
rule_id from it). Addresses are from 10/8 and the documentation ranges.

If the port refuses (ICMP port unreachable) before a second of sending, it
stops: nothing is listening. A refusal after that is the collector going away
for a while (a restart): the packet is sent again and sending goes on, as an
exporter's would; the summary gives when the refusals came and how many were
reported, a lower bound on what was lost.

Examples:
  woodshed send --proto ipfix --count 1000                1,000 IPFIX records to 127.0.0.1:4739
  woodshed send --proto flow-v9 --port 12055 --rate 5000 --duration 60s
  woodshed send --proto ipfix --domains 2 --sampling 100 --sampled-domains 1
  woodshed send --proto ipfix --events --deny-ratio 0.2   firewall-event records (created, deleted, denied)
  woodshed send --proto ipfix --template-first-delay 5s   data before its template (it waits, then decodes late)`, stderr)
	host := fs.String("host", "127.0.0.1", "collector `host` name or IP")
	port := fs.Int("port", 0, "collector `port` (default 2055, the flow port, for flow-v5 and flow-v9; 4739 for ipfix)")
	proto := fs.String("proto", "", "`protocol`: flow-v5, flow-v9 or ipfix")
	count := fs.Int("count", 0, "`number` of records (default 1, or rate x duration)")
	rate := fs.Float64("rate", 0, "`records` per second (0: as fast as possible)")
	duration := fs.Duration("duration", 0, "send at --rate for this `duration`, instead of --count")
	rpp := fs.Int("records-per-packet", 30, "records per `packet` (v5: at most 30)")
	domains := fs.Int("domains", 1, "observation `domains` (v9 source IDs) 1..N, in turn")
	sampling := fs.Int("sampling", 0, "say the records are sampled 1 in `N` (0: no sampling information; in v5 a header interval of 0, which is unsampled)")
	sampled := fs.Int("sampled-domains", 0, "with --sampling, how many of the `domains` are sampled, from 1 (0: all)")
	every := fs.Int("template-every", 20, "resend the templates every `N` packets of a domain")
	firstDelay := fs.Duration("template-first-delay", 0, "send no template until this `long` after the start")
	enterprise := fs.Int("enterprise-ies", 0, "extra enterprise `IEs` per record (v9, IPFIX)")
	events := fs.Bool("events", false, "send firewall-event records (v9, IPFIX)")
	denyRatio := fs.Float64("deny-ratio", 0.1, "with --events, the `share` of denied records")
	biflow := fs.Bool("biflow", false, "send RFC 5103 reverse counters (IPFIX)")
	source := fs.String("source", "", "local `IP` to send from")
	runID := fs.String("run", "", "run `id` (8 hex digits; default random)")
	firstSeq := fs.Int("first-seq", 0, "sequence `number` of the first record")
	logFile := fs.String("log", "", "write every record sent to this `file`, one JSON object a line")
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	usageErr := func(err error) int {
		fmt.Fprintf(stderr, "woodshed send: %v\n\n%s", err, fs.help())
		return 2
	}
	*proto = strings.ToLower(*proto)
	if !loadgen.IsFlowProto(*proto) {
		return usageErr(fmt.Errorf("--proto must be flow-v5, flow-v9 or ipfix, not %q", *proto))
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if *port == 0 {
		*port = 2055
		if *proto == loadgen.ProtoIPFIX {
			*port = 4739
		}
	}
	if *port < 1 || *port > 65535 {
		return usageErr(fmt.Errorf("--port %d is out of range (1-65535)", *port))
	}
	if *duration > 0 && *rate == 0 {
		return usageErr(errors.New("--duration needs --rate"))
	}
	if *duration > 0 && *count > 0 {
		return usageErr(errors.New("give --count or --duration, not both"))
	}
	if given["deny-ratio"] && !*events {
		return usageErr(errors.New("--deny-ratio is for --events"))
	}
	if given["sampled-domains"] && *sampling == 0 {
		return usageErr(errors.New("--sampled-domains needs --sampling"))
	}
	o := loadgen.FlowOptions{Proto: *proto, Addr: net.JoinHostPort(*host, strconv.Itoa(*port)), Source: *source,
		Count: *count, Rate: *rate, Duration: *duration, RecordsPerPacket: *rpp, Domains: *domains, Sampling: *sampling,
		SampledDomains: *sampled, TemplateEvery: *every, TemplateFirstDelay: *firstDelay, EnterpriseIEs: *enterprise,
		Events: *events, Biflow: *biflow, RunID: *runID, FirstSeq: *firstSeq}
	if *events {
		o.DenyRatio = *denyRatio
	}
	if _, err := loadgen.NewFlowGen(o, time.Now()); err != nil {
		return usageErr(errors.New(strings.TrimPrefix(err.Error(), "loadgen: ")))
	}
	var logw *bufio.Writer
	var logErr error
	if *logFile != "" {
		f, err := os.Create(*logFile)
		if err != nil {
			return fail(stderr, "send", err)
		}
		defer f.Close()
		logw = bufio.NewWriter(f)
	}
	enc := json.NewEncoder(logw)
	logf := func(exp []loadgen.Expected) {
		if logw == nil || logErr != nil {
			return
		}
		for _, e := range exp {
			r := &e.Record
			l := flowLogLine{Seq: e.Seq, Domain: r.Domain, Start: ms3339(r.Start), End: ms3339(r.End),
				SrcPort: r.SrcPort, DstPort: r.DstPort, Proto: r.Proto, Packets: r.Packets, Bytes: r.Bytes,
				SumBytes: r.SumBytes(), Sampling: r.Sampling, RuleID: r.RuleID}
			if r.Is(flow.HasSrc) {
				l.Src = r.Src.String()
			}
			if r.Is(flow.HasDst) {
				l.Dst = r.Dst.String()
			}
			if r.Is(flow.HasFwEvent) {
				l.FwEvent = flow.FwEventName(r.FwEvent)
			}
			if r.Is(flow.HasPostNATSrc) {
				l.PostNATIP = r.PostNATSrc.String()
			}
			if err := enc.Encode(l); err != nil {
				logErr = err
			}
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := loadgen.SendFlows(ctx, o, logf)
	if logw != nil {
		if ferr := logw.Flush(); ferr != nil && logErr == nil {
			logErr = ferr
		}
	}
	if res.RunID != "" && (res.Records > 0 || err == nil) {
		plural := "s"
		if res.Records == 1 {
			plural = ""
		}
		fmt.Fprintf(stdout, "Sent %d %s record%s in %d packets to %s in %v (%.0f records/s), run %s.\n", res.Records,
			strings.ToUpper(*proto), plural, res.Packets, o.Addr, res.Elapsed.Round(time.Millisecond), res.Rate, res.RunID)
		if t := loadgen.RefusedText(res.Refused); t != "" {
			fmt.Fprintf(stdout, "%s.\n", t)
		}
		fmt.Fprintln(stdout, "(UDP has no delivery confirmation: check the collector to see that they arrived.)")
	}
	if logErr != nil {
		return fail(stderr, "send", fmt.Errorf("--log: %w", logErr))
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "woodshed send: interrupted")
			return 1
		}
		return fail(stderr, "send", err)
	}
	return 0
}

func ms3339(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z07:00")
}
