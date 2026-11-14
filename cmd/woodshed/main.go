// Command woodshed is a simple, reliable syslog server with a web UI.
package main

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Set at build time with -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "0.0.0-dev"
	commit  = "none"
	// releasesURL is the releases page: the About page links to it, and the
	// update check's banner links to a release on it (SPEC §10.2).
	releasesURL = "https://github.com/gmccollu/woodshed/releases"
)

const usage = `usage: woodshed [<command> [flags]]

With no command (or a double-click), Woodshed runs in portable mode: right
here, with nothing installed, keeping its logs in woodshed-data next to it.

commands:
  portable        run in portable mode (the default with no command)
  run             run the server in the foreground with a given config
  install         install and start the system service
  uninstall       stop and remove the system service (keeps logs)
  status          show service and listener status
  reindex         rebuild the index from the log files
  search          search the stored logs from the command line
  set-password    set the UI password (for servers without a browser)
  lan-mode        turn LAN mode on or off (HTTPS on the network, with a login)
  tls             syslog over TLS: on, off, renew the certificate, status
  update-check    turn the daily update check on or off (or back to asking)
  reset-password  remove the UI password and turn LAN mode off
  send            send test messages to a syslog server
  bench           measure sustained throughput
  version         print the version

Run "woodshed <command> --help" for a command's flags.
`

// command is one subcommand. run returns the process exit code.
type command struct {
	name string
	run  func(args []string, stdout, stderr io.Writer) int
}

var commands []command

func init() {
	commands = []command{
		{"portable", cmdPortable},
		{"run", cmdRun},
		{"install", cmdInstall},
		{"uninstall", cmdUninstall},
		{"status", cmdStatus},
		{"reindex", cmdReindex},
		{"search", cmdSearch},
		{"set-password", cmdSetPassword},
		{"lan-mode", cmdLANMode},
		{"tls", cmdTLS},
		{"update-check", cmdUpdateCheck},
		{"reset-password", cmdResetPassword},
		{"send", cmdSend},
		{"bench", cmdBench},
		{"version", cmdVersion},
	}
}

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		return startPortable(stdout, stderr)
	}
	name := args[0]
	switch name {
	case "-h", "-help", "--help", "help":
		if len(args) > 1 && name == "help" {
			// "woodshed help send" is "woodshed send --help".
			return realMain([]string{args[1], "--help"}, stdout, stderr)
		}
		fmt.Fprint(stdout, usage)
		return 0
	case "-v", "-version", "--version":
		name = "version"
	}
	for _, c := range commands {
		if c.name == name {
			return c.run(args[1:], stdout, stderr)
		}
	}
	fmt.Fprintf(stderr, "woodshed: unknown command %q\n\n%s", name, usage)
	return 2
}

// fail prints a "woodshed <cmd>: <err>" line and returns exit code 1.
func fail(stderr io.Writer, cmd string, err error) int {
	msg := err.Error()
	// Package prefixes ("config: ", "loadgen: ") don't help a user.
	for _, p := range []string{"config: ", "loadgen: ", "listen: ", "store: ", "index: "} {
		msg = strings.TrimPrefix(msg, p)
	}
	fmt.Fprintf(stderr, "woodshed %s: %s\n", cmd, msg)
	return 1
}

func cmdVersion(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("version", "", "Print the version.", stderr)
	if code, done := parse(fs, args, stdout); done {
		return code
	}
	fmt.Fprintf(stdout, "woodshed %s (%s) %s\n", version, commit, platform())
	return 0
}
