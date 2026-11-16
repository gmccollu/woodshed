package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/poller"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// `woodshed poll test` (SPEC §12.7): a standalone diagnostic like `woodshed
// send`. It doesn't read the credentials store (on Windows only the service
// account can decrypt it) or talk to the service; secrets come from files or
// the environment, never the command line.

func cmdPoll(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "test" && !strings.HasPrefix(args[0], "-")) {
		fmt.Fprint(stderr, "usage: woodshed poll test <address> [flags]\n\nRun \"woodshed poll test --help\" for the flags.\n")
		return 2
	}
	if args[0] == "test" {
		args = args[1:]
	}
	return cmdPollTest(args, stdout, stderr)
}

func cmdPollTest(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("poll test", "<address>", `
Poll one device once, from here, with what a poll target would ask: v3
discovery (engine ID, boots, time), sysName, sysDescr, sysUpTime, whether the
64-bit interface counters and HOST-RESOURCES answer, how many interfaces it
would poll, and each custom OID, with round-trip times; then what's missing
and why. Nothing is saved, and the service isn't involved.

Communities and passphrases come from files or $`+envSNMPCommunity+`, $`+envSNMPAuthPass+` and
$`+envSNMPPrivPass+`, never the command line. Polled devices themselves are set up
in the web UI (Devices → Polling).

Exit codes: 0 everything answered; 1 no answer; 2 usage; 3 authentication or
privacy error; 4 answered, but some OIDs aren't supported.`, stderr)
	port := fs.Int("port", 161, "the agent's UDP `port`")
	version := fs.String("version", "2c", "SNMP `version`: 1, 2c or 3")
	communityFile := fs.String("community-file", "", "read the v1/v2c community from this `file` (else $"+envSNMPCommunity+")")
	user := fs.String("v3-user", "", "the SNMPv3 user `name`")
	auth := fs.String("auth", "none", "v3 authentication `protocol`: none, md5, sha, sha-224, sha-256, sha-384 or sha-512")
	priv := fs.String("priv", "none", "v3 privacy `protocol`: none, des, aes-128, aes-192 or aes-256")
	keyExt := fs.String("key-ext", "draft", "AES-192/256 key extension `method`: draft or alt")
	authPassFile := fs.String("auth-pass-file", "", "read the v3 authentication passphrase from this `file` (else $"+envSNMPAuthPass+")")
	privPassFile := fs.String("priv-pass-file", "", "read the v3 privacy passphrase from this `file` (else $"+envSNMPPrivPass+")")
	presets := fs.String("preset", "system,system-info,interfaces", "the `presets` to test: system, system-info, interfaces")
	var oids, walks listFlag
	fs.Var(&oids, "oid", "a custom scalar `OID` to read (repeatable)")
	fs.Var(&walks, "walk", "a custom `OID` to walk, at most 128 rows (repeatable)")
	timeout := fs.Duration("timeout", 2*time.Second, "how long to wait for each answer (a `duration`)")
	retries := fs.Int("retries", 1, "how many times to retry an unanswered request")
	asJSON := fs.Bool("json", false, "print the result as JSON (the shape of POST /api/poll/test)")
	for _, a := range args {
		if a == "-h" || a == "-help" || a == "--help" {
			fmt.Fprint(stdout, fs.help())
			return 0
		}
	}
	var addr string
	if err := parseInterleaved(fs.FlagSet, args, &addr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, fs.help())
			return 0
		}
		fmt.Fprintf(stderr, "woodshed poll test: %v\n\n%s", err, fs.help())
		return 2
	}
	usage := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "woodshed poll test: "+format+"\n", a...)
		return 2
	}
	if addr == "" {
		return usage("the device's address is required (woodshed poll test 192.0.2.1)")
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return usage("%q isn't an IP address (names aren't looked up)", addr)
	}
	if *port < 1 || *port > 65535 {
		return usage("--port must be 1 to 65535")
	}
	if *timeout < 100*time.Millisecond || *timeout > time.Minute {
		return usage("--timeout must be 100ms to 1m")
	}
	if *retries < 0 || *retries > 5 {
		return usage("--retries must be 0 to 5")
	}
	s := poller.Settings{Address: ip.Unmap().String(), Port: *port, Enabled: true, Version: strings.ToLower(*version),
		TimeoutMS: int(*timeout / time.Millisecond), Retries: *retries, Interfaces: poller.Interfaces{All: true},
		MaxInterfaces: config.DefaultPollMaxInterfaces}
	if s.Version == "2" {
		s.Version = "2c"
	}
	for _, p := range strings.Split(*presets, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		valid := false
		for _, q := range config.PollPresets() {
			valid = valid || p == q
		}
		if !valid {
			return usage("--preset %q isn't system, system-info or interfaces", p)
		}
		s.Presets = append(s.Presets, p)
	}
	for _, o := range oids {
		if _, err := snmp.ParseOID(o); err != nil {
			return usage("--oid %q isn't a numeric OID", o)
		}
		s.Custom = append(s.Custom, poller.Custom{OID: o, Kind: poller.CustomScalar})
	}
	for _, o := range walks {
		if _, err := snmp.ParseOID(o); err != nil {
			return usage("--walk %q isn't a numeric OID", o)
		}
		s.Custom = append(s.Custom, poller.Custom{OID: o, Kind: poller.CustomWalk, MaxRows: poller.DefaultMaxRows})
	}
	var community []byte
	var u *snmp.User
	switch s.Version {
	case "1", "2c":
		if *user != "" || *auth != "none" || *priv != "none" || *authPassFile != "" || *privPassFile != "" {
			return usage("--v3-user, --auth, --priv and the passphrase files are for --version 3")
		}
		if community, err = readSNMPSecret(*communityFile, envSNMPCommunity); err != nil {
			return usage("--community-file: %v", err)
		}
		if community == nil {
			return usage("a community is needed: --community-file FILE or $%s", envSNMPCommunity)
		}
	case "3":
		if *communityFile != "" {
			return usage("--community-file is for --version 1 and 2c")
		}
		if *user == "" {
			return usage("--version 3 needs --v3-user")
		}
		uu := snmp.User{Name: *user}
		if uu.Auth, err = snmp.ParseAuthProtocol(*auth); err != nil {
			return usage("%s", strings.TrimPrefix(err.Error(), "snmp: "))
		}
		if uu.Priv, err = snmp.ParsePrivProtocol(*priv); err != nil {
			return usage("%s", strings.TrimPrefix(err.Error(), "snmp: "))
		}
		if uu.KeyExt, err = snmp.ParseKeyExt(*keyExt); err != nil {
			return usage("%s", strings.TrimPrefix(err.Error(), "snmp: "))
		}
		if uu.Auth != snmp.AuthNone {
			if uu.AuthPass, err = readSNMPSecret(*authPassFile, envSNMPAuthPass); err != nil {
				return usage("--auth-pass-file: %v", err)
			}
			if uu.AuthPass == nil {
				return usage("--auth needs a passphrase: --auth-pass-file FILE or $%s", envSNMPAuthPass)
			}
		}
		if uu.Priv != snmp.PrivNone {
			if uu.PrivPass, err = readSNMPSecret(*privPassFile, envSNMPPrivPass); err != nil {
				return usage("--priv-pass-file: %v", err)
			}
			if uu.PrivPass == nil {
				return usage("--priv needs a passphrase: --priv-pass-file FILE or $%s", envSNMPPrivPass)
			}
		}
		uu.Level = uu.MaxLevel()
		if err := uu.Validate(); err != nil {
			return usage("%s", strings.TrimPrefix(err.Error(), "snmp: "))
		}
		u = &uu
	default:
		return usage("--version must be 1, 2c or 3, not %q", *version)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res := poller.StandaloneTest(ctx, s, community, u)
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return poller.ExitCode(res.Exit)
	}
	fmt.Fprintf(stdout, "Test poll of %s port %d (SNMPv%s)\n", s.Address, s.Port, s.Version)
	var missing []string
	for _, st := range res.Steps {
		mark := "ok  "
		if !st.OK {
			mark = "FAIL"
			if st.Step != "replies" {
				missing = append(missing, st.Step+": "+st.Detail)
			}
		}
		rtt := ""
		if st.RTTms > 0 {
			rtt = fmt.Sprintf(" (%d ms)", st.RTTms)
		}
		fmt.Fprintf(stdout, "  %s %-16s %s%s\n", mark, st.Step, st.Detail, rtt)
	}
	switch res.Exit {
	case poller.ExitOK:
		fmt.Fprintln(stdout, "Everything answered.")
	case poller.ExitNoAnswer:
		fmt.Fprintln(stdout, "No answer: check the address and port, the community or user, and that the agent allows this host.")
	case poller.ExitAuth:
		fmt.Fprintln(stdout, "Authentication or privacy failed: check the user, its protocols and passphrases (and the key extension for AES-192/256).")
	default:
		fmt.Fprintf(stdout, "Answered, but not everything is available (%d):\n", len(missing))
		for _, m := range missing {
			fmt.Fprintf(stdout, "  - %s\n", m)
		}
	}
	return poller.ExitCode(res.Exit)
}

// statusPollRows adds the Polling row to `woodshed status` (SPEC §12.7),
// from the run-state file, when any target is configured:
//
//	Polling   12 devices: 11 answering, 1 not answering since 09:02 (10.1.0.9); last cycle 4 s ago
func statusPollRows(w *tabw, cfg config.Config, rs *server.RunState, now time.Time) {
	if rs == nil {
		if got, err := server.ReadState(cfg.Storage.DataDir); err == nil {
			rs = &got
		}
	}
	if rs == nil || rs.Poll == nil || rs.Poll.Targets == 0 {
		return
	}
	p := rs.Poll
	devices := "devices"
	if p.Targets == 1 {
		devices = "device"
	}
	text := fmt.Sprintf("%d %s: %d answering", p.Targets, devices, p.Answering)
	if n := len(p.NotAnswering); n > 0 {
		first := p.NotAnswering[0]
		for _, na := range p.NotAnswering[1:] {
			if !na.Since.IsZero() && (first.Since.IsZero() || na.Since.Before(first.Since)) {
				first = na
			}
		}
		names := []string{}
		for i, na := range p.NotAnswering {
			if i == 3 {
				names = append(names, fmt.Sprintf("and %d more", n-3))
				break
			}
			names = append(names, na.Address)
		}
		since := ""
		if !first.Since.IsZero() {
			since = " since " + first.Since.Local().Format("15:04")
		}
		text += fmt.Sprintf(", %d not answering%s (%s)", n, since, strings.Join(names, ", "))
	}
	if p.LastCycle != nil {
		ago := now.Sub(*p.LastCycle).Round(time.Second)
		text += fmt.Sprintf("; last cycle %s ago", formatAgo(ago))
	}
	w.row("Polling", text)
}

func formatAgo(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(max(d, 0)/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return fmt.Sprintf("%d h", int(d/time.Hour))
}
