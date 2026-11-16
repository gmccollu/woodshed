package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/server"
	"github.com/gmccollu/woodshed/internal/setuphelper"
	"github.com/gmccollu/woodshed/internal/tlscert"
)

// `woodshed setup families|snippet` (SPEC §13.5): the Set up a device page for
// servers without a browser. It reads the config file (and the TLS
// certificate's names when this account can), never a stored secret, and
// changes nothing.

func cmdSetup(args []string, stdout, stderr io.Writer) int {
	const use = "usage: woodshed setup families | woodshed setup snippet --family F --what W [flags]\n\nRun \"woodshed setup snippet --help\" for the flags.\n"
	if len(args) == 0 {
		fmt.Fprint(stderr, use)
		return 2
	}
	switch args[0] {
	case "families":
		return cmdSetupFamilies(args[1:], stdout, stderr)
	case "snippet":
		return cmdSetupSnippet(args[1:], stdout, stderr)
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, use)
		return 0
	}
	fmt.Fprintf(stderr, "woodshed setup: unknown subcommand %q\n\n%s", args[0], use)
	return 2
}

func cmdSetupFamilies(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("setup families", "", "List the setup families, the data types each one covers and how it's verified.", stderr)
	asJSON := fs.Bool("json", false, "print the list as JSON (the shape of GET /api/setup/families)")
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	fams := setuphelper.Families()
	if *asJSON {
		b, _ := json.MarshalIndent(fams, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	w := &tabw{w: stdout}
	for _, f := range fams {
		var whats []string
		for _, wt := range f.What {
			whats = append(whats, wt+" ("+strings.Join(f.Transports[wt], ", ")+")")
		}
		w.row(f.ID, f.Label)
		w.row("", "  "+strings.Join(whats, "; "))
		w.row("", "  "+verificationText(f.Verification, f.CheckedOn))
	}
	return 0
}

func verificationText(level, on string) string {
	switch level {
	case setuphelper.Tested:
		return "Tested: CI applies it to the real tool and checks the data arrives."
	case setuphelper.LabChecked:
		return "Lab-checked on " + on + "."
	}
	return setuphelper.ReferenceOnlyNote
}

func cmdSetupSnippet(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("setup snippet", "", `
Print the configuration a device needs to send its syslog, traps or flows to
this Woodshed, or to let Woodshed poll it, filled in from this server's
config: its addresses, ports, which listeners are on, and the names on its
TLS certificate. The snippet goes to stdout; its verification level and
notes go to stderr, so "> file" keeps only the snippet.

Secrets are always placeholders (<COMMUNITY>, <AUTH-PASSPHRASE>): replace
them on the device. Nothing on the server changes.

Families: line-cli, set-cli, rsyslog, net-snmp, softflowd, web-ui ("woodshed
setup families" lists what each covers).`, stderr)
	cfgPath := configFlag(fs)
	var r setuphelper.Request
	fs.StringVar(&r.Family, "family", "", "the syntax `family` (see woodshed setup families)")
	fs.StringVar(&r.What, "what", "", "the data `type`: syslog, trap, poll or flow")
	typ := fs.String("type", "", "the same as --what")
	fs.StringVar(&r.Transport, "transport", "", "syslog: udp, tcp or tls; trap and poll: v2c or v3; flow: v9 or ipfix (default: the first whose listener is on)")
	fs.StringVar(&r.Address, "address", "", "this Woodshed's `address` as the device should use it (default: this machine's first address)")
	fs.StringVar(&r.SourceInterface, "source-interface", "", "the device's `interface` its packets leave from (CLI families)")
	fs.StringVar(&r.Interface, "interface", "", "the `interface` softflowd watches")
	fs.StringVar(&r.Severity, "severity", "", "syslog: the lowest `severity` to send: "+strings.Join(setuphelper.Severities(), ", ")+" (default info)")
	fs.StringVar(&r.Facility, "facility", "", "syslog: local0 to local7 (default: the device's own)")
	fs.StringVar(&r.V3User, "v3-user", "", "v3: the user `name` (default: a placeholder)")
	fs.StringVar(&r.Auth, "auth", "", "v3: the authentication `protocol`: "+strings.Join(setuphelper.AuthChoices(), " or ")+" (default sha-256)")
	fs.StringVar(&r.Priv, "priv", "", "v3: the privacy `protocol`: "+strings.Join(setuphelper.PrivChoices(), ", "))
	fs.IntVar(&r.AgentPort, "agent-port", 0, "poll: the `port` the device's SNMP agent listens on (default 161)")
	asJSON := fs.Bool("json", false, "print the whole snippet as JSON (the shape of POST /api/setup/snippet)")
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	if *typ != "" {
		if r.What != "" && r.What != *typ {
			fmt.Fprintln(stderr, "woodshed setup snippet: --type and --what say different things; give one")
			return 2
		}
		r.What = *typ
	}
	if r.Family == "" || r.What == "" {
		fmt.Fprintf(stderr, "woodshed setup snippet: --family and --what are required\n\n%s", fs.help())
		return 2
	}
	cfg, err := readConfig(*cfgPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) && !strings.HasPrefix(err.Error(), "no config file") {
			return fail(stderr, "setup snippet", err)
		}
		fmt.Fprintf(stderr, "woodshed setup snippet: %v; using the default settings\n", err)
		cfg = config.Default()
		cfg.Storage.DataDir = "" // no data folder to read a certificate from
	}
	sn, err := setuphelper.Generate(setupServerFromConfig(cfg), r)
	var bad *setuphelper.Error
	if errors.As(err, &bad) {
		flag := "--" + strings.ReplaceAll(bad.Field, "_", "-")
		fmt.Fprintf(stderr, "woodshed setup snippet: %s %s\n", flag, bad.Msg)
		return 2
	}
	if err != nil {
		return fail(stderr, "setup snippet", err)
	}
	if *asJSON {
		b, _ := json.MarshalIndent(sn, "", "  ")
		fmt.Fprintln(stdout, string(b))
		return 0
	}
	fmt.Fprint(stdout, sn.Text)
	fmt.Fprintf(stderr, "\n%s\n%s\n", sn.Does, verificationText(sn.Verification, sn.CheckedOn))
	for _, n := range sn.Notes {
		if n != setuphelper.ReferenceOnlyNote {
			fmt.Fprintf(stderr, "- %s\n", n)
		}
	}
	if len(sn.Placeholders) > 0 {
		fmt.Fprintf(stderr, "Fill in: %s\n", strings.Join(sn.Placeholders, " "))
	}
	fmt.Fprintf(stderr, "Check: %s\n", sn.Check)
	return 0
}

// setupServerFromConfig describes this Woodshed from its config file, the
// machine's addresses, and the TLS certificate in the data folder when this
// account can read it.
func setupServerFromConfig(cfg config.Config) setuphelper.Server {
	l := cfg.Listeners
	srv := setuphelper.Server{
		HostIPs: server.HostAddrs(),
		UDP:     setuphelper.Listener{Enabled: l.UDP.Enabled, Addr: l.UDP.Addr, Port: l.UDP.Port},
		TCP:     setuphelper.Listener{Enabled: l.TCP.Enabled, Addr: l.TCP.Addr, Port: l.TCP.Port},
		TLS:     setuphelper.Listener{Enabled: l.TLS.Enabled, Addr: l.TLS.Addr, Port: l.TLS.Port},
		Trap:    setuphelper.Listener{Enabled: l.SNMP.Enabled, Addr: l.SNMP.Addr, Port: l.SNMP.Port},
		Flow:    &setuphelper.FlowListener{Enabled: l.Flow.Enabled, Addr: l.Flow.Addr, FlowPort: l.Flow.FlowPort, IPFIXPort: l.Flow.IPFIXPort},
	}
	var st tlscert.Status
	if cfg.Storage.DataDir != "" {
		st = tlscert.New(tlscert.Options{DataDir: cfg.Storage.DataDir, CertFile: l.TLS.CertFile, KeyFile: l.TLS.KeyFile}).Status()
	}
	if st.Cert != nil {
		srv.TLSSource = st.Source
		srv.TLSNames = st.Cert.DNSNames
		srv.Names = append(srv.Names, st.Cert.DNSNames...)
	}
	if st.CA != nil {
		srv.CASHA256 = st.CA.SHA256
	}
	srv.Names = append(srv.Names, cfg.UI.ExtraHostnames...)
	return srv
}
