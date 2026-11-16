// Package fwrule opens and closes the host firewall for the TLS syslog listener
// (SPEC §10.3.6) and the SNMP trap receiver (SPEC §11.2.7, snmp.go), and reads
// the Windows rules' state for the tls_firewall and snmp_firewall banners. The service account can't change the firewall, so only `woodshed tls
// on|off`, `woodshed install` and the MSI (as an administrator or SYSTEM) call
// the changing functions; the running service only reads.
//
//   - Windows: one rule, RuleName, inbound TCP for woodshed.exe on every profile.
//     The MSI and `woodshed install` create it disabled; `tls on` enables it on
//     listeners.tls.port and `tls off` disables it. Its state survives upgrades.
//   - Linux: `tls on` opens the port in ufw when it's active, else in firewalld
//     when it's running (permanent, default zone, then a reload), and records
//     what it added in <data>/RecordFile; `tls off` removes only that.
//   - macOS: nothing (the application firewall works per program, not per port).
//
// The SNMP rule (SNMPRuleName, inbound UDP 162, SNMPRecordFile) follows the
// same pattern with `snmp on|off`.
//
// Every command goes through a Runner, so the logic is tested with fakes.
package fwrule

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/gmccollu/woodshed/internal/atomicfile"
)

// RuleName is the Windows rule (the MSI's and `woodshed install`'s).
const RuleName = "Woodshed syslog (TLS 6514)"

// RecordFile is where `tls on` records what it added to a Linux firewall.
const RecordFile = "tls-firewall.json"

// Windows rule states (GET /api/tls firewall.state).
const (
	StateOK        = "ok"
	StateMissing   = "missing"
	StateDisabled  = "disabled"
	StateWrongPort = "wrong_port"
	StateUnknown   = "unknown"
)

// Runner runs a program and returns its combined output; a non-zero exit is an
// error (with the output still returned).
type Runner func(name string, args ...string) (string, error)

// Exec is the real Runner.
func Exec(name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	s := strings.TrimSpace(out.String())
	if err != nil {
		return s, fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return s, nil
}

// linuxTool returns ufw's or firewall-cmd's path from the system directories, so
// `woodshed tls on`, which runs as root, never runs a same-named program found
// earlier on PATH. It falls back to the bare name (PATH) only when none exists.
func linuxTool(name string) string {
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		if p := filepath.Join(dir, name); isFile(p) {
			return p
		}
	}
	return name
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// Netsh is netsh's path (System32, never a netsh.exe found on PATH).
func Netsh() string {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	return filepath.Join(root, "System32", "netsh.exe")
}

// ---- Windows ----

// rule is the part of `netsh advfirewall firewall show rule ... verbose` we read.
type rule struct {
	enabled bool
	port    string // LocalPort
	program string
}

// parseRules reads netsh's verbose rule listing (English field names). It
// returns nil when no block has a Rule Name field (no rule, or another
// language).
func parseRules(out string) []rule {
	out = strings.ReplaceAll(out, "\r\n", "\n")
	var rules []rule
	for _, block := range strings.Split(out, "\n\n") {
		f := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok {
				f[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		if _, ok := f["Rule Name"]; !ok {
			continue
		}
		rules = append(rules, rule{enabled: strings.EqualFold(f["Enabled"], "Yes"), port: f["LocalPort"], program: f["Program"]})
	}
	return rules
}

// noMatch is netsh's answer when no rule has the name (English).
func noMatch(out string) bool { return strings.Contains(out, "No rules match") }

// spec is one Woodshed firewall rule: the TLS syslog listener's or the SNMP
// trap receiver's. The exported TLS functions keep their 1.1 names; the SNMP
// ones carry the SNMP prefix.
type spec struct {
	name    string // the Windows rule's name
	proto   string // "TCP" or "UDP"
	defPort int    // the port a rule is created on, disabled
	desc    string // the Windows rule's description
	record  string // the Linux record file in the data folder
}

var (
	tlsSpec = spec{name: RuleName, proto: "TCP", defPort: 6514, record: RecordFile,
		desc: "Lets devices send syslog to Woodshed over TLS. Turned on by `woodshed tls on`."}
	snmpSpec = spec{name: SNMPRuleName, proto: "UDP", defPort: 162, record: SNMPRecordFile,
		desc: "Lets devices send SNMP traps and informs to Woodshed. Turned on by `woodshed snmp on`."}
)

// WindowsState reads the rule's state for port. It needs no administrator
// rights. Output it can't read (another language, an error) is StateUnknown.
func WindowsState(run Runner, port int) string { return tlsSpec.windowsState(run, port) }

func (sp spec) windowsState(run Runner, port int) string {
	out, err := run(Netsh(), "advfirewall", "firewall", "show", "rule", "name="+sp.name, "verbose")
	if noMatch(out) {
		return StateMissing
	}
	rules := parseRules(out)
	if err != nil || len(rules) == 0 {
		return StateUnknown
	}
	return stateOf(rules, port)
}

func stateOf(rules []rule, port int) string {
	p := strconv.Itoa(port)
	state := StateDisabled
	for _, r := range rules {
		if !r.enabled {
			continue
		}
		if r.port == p {
			return StateOK
		}
		state = StateWrongPort
	}
	return state
}

func (sp spec) addArgs(exe string, port int, enable bool) []string {
	en := "no"
	if enable {
		en = "yes"
	}
	return []string{"advfirewall", "firewall", "add", "rule", "name=" + sp.name, "dir=in", "action=allow",
		"program=" + exe, "protocol=" + sp.proto, "localport=" + strconv.Itoa(port), "profile=any", "enable=" + en,
		"description=" + sp.desc}
}

// exists reports whether the rule is there, and an error when netsh's answer
// can't be read.
func (sp spec) exists(run Runner) (bool, error) {
	out, err := run(Netsh(), "advfirewall", "firewall", "show", "rule", "name="+sp.name)
	if noMatch(out) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// WindowsEnsure creates the rule, disabled on 6514, unless it exists (then it's
// left exactly as it is, so a reinstall keeps its state). For `woodshed
// install` and the MSI.
func WindowsEnsure(run Runner, exe string) (created bool, err error) {
	return tlsSpec.windowsEnsure(run, exe)
}

func (sp spec) windowsEnsure(run Runner, exe string) (created bool, err error) {
	ok, err := sp.exists(run)
	if err != nil || ok {
		return false, err
	}
	if _, err := run(Netsh(), sp.addArgs(exe, sp.defPort, false)...); err != nil {
		return false, err
	}
	return true, nil
}

// WindowsEnable enables the rule on port for exe, creating it if it's missing
// (portable copies and older installs).
func WindowsEnable(run Runner, exe string, port int) error {
	return tlsSpec.windowsEnable(run, exe, port)
}

func (sp spec) windowsEnable(run Runner, exe string, port int) error {
	ok, err := sp.exists(run)
	if err != nil {
		return err
	}
	if !ok {
		_, err := run(Netsh(), sp.addArgs(exe, port, true)...)
		return err
	}
	_, err = run(Netsh(), "advfirewall", "firewall", "set", "rule", "name="+sp.name, "new",
		"enable=yes", "localport="+strconv.Itoa(port), "program="+exe)
	return err
}

// WindowsDisable disables the rule (it stays, for the next `tls on`).
func WindowsDisable(run Runner) error { return tlsSpec.windowsDisable(run) }

func (sp spec) windowsDisable(run Runner) error {
	ok, err := sp.exists(run)
	if err != nil || !ok {
		return err
	}
	_, err = run(Netsh(), "advfirewall", "firewall", "set", "rule", "name="+sp.name, "new", "enable=no")
	return err
}

// WindowsRemove deletes the rule (uninstall). A missing rule isn't an error.
func WindowsRemove(run Runner) error { return tlsSpec.windowsRemove(run) }

func (sp spec) windowsRemove(run Runner) error {
	ok, err := sp.exists(run)
	if err != nil || !ok {
		return err
	}
	_, err = run(Netsh(), "advfirewall", "firewall", "delete", "rule", "name="+sp.name)
	return err
}

// ---- Linux ----

// Record is what `tls on` added, by firewall ("6514/tcp" entries).
type Record struct {
	Ufw       []string `json:"ufw,omitempty"`
	Firewalld []string `json:"firewalld,omitempty"`
}

func readRecord(dataDir, file string) (Record, error) {
	var r Record
	b, err := atomicfile.ReadFile(filepath.Join(dataDir, file))
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("%s: %w", file, err)
	}
	return r, nil
}

func writeRecord(dataDir, file string, r Record) error {
	p := filepath.Join(dataDir, file)
	if len(r.Ufw) == 0 && len(r.Firewalld) == 0 {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return atomicfile.WriteFile(p, append(b, '\n'), 0o640)
}

func ufwActive(run Runner) bool {
	out, err := run(linuxTool("ufw"), "status")
	return err == nil && strings.Contains(out, "Status: active")
}

func firewalldRunning(run Runner) bool {
	out, err := run(linuxTool("firewall-cmd"), "--state")
	return err == nil && strings.TrimSpace(out) == "running"
}

// LinuxCommands are the commands for the common firewalls, for when neither
// is active (and for Settings).
func LinuxCommands(port int) string { return tlsSpec.linuxCommands(port) }

// LinuxOpened is what `tls on` recorded opening in ufw or firewalld (empty when it opened nothing).
func LinuxOpened(dataDir string) (Record, error) { return readRecord(dataDir, tlsSpec.record) }

func (sp spec) linuxCommands(port int) string {
	p := strconv.Itoa(port) + "/" + strings.ToLower(sp.proto)
	return "  ufw:       sudo ufw allow " + p + "\n" +
		"  firewalld: sudo firewall-cmd --permanent --add-port=" + p + " && sudo firewall-cmd --reload\n" +
		"  Other rules (nftables, iptables): allow inbound " + sp.proto + " port " + strconv.Itoa(port) + ".\n"
}

// LinuxOpen opens port in ufw (when active) or firewalld (when running), and
// records it unless it was already open (then `tls off` leaves it alone). It
// returns what it did, for the user.
func LinuxOpen(run Runner, dataDir string, port int) (string, error) {
	return tlsSpec.linuxOpen(run, dataDir, port)
}

func (sp spec) linuxOpen(run Runner, dataDir string, port int) (string, error) {
	p := strconv.Itoa(port) + "/" + strings.ToLower(sp.proto)
	rec, err := readRecord(dataDir, sp.record)
	if err != nil {
		return "", err
	}
	switch {
	case ufwActive(run):
		out, err := run(linuxTool("ufw"), "allow", p)
		if err != nil {
			return "", err
		}
		if strings.Contains(out, "Skipping") {
			return "ufw already allows " + p + "; left as it is.", nil
		}
		if !slices.Contains(rec.Ufw, p) {
			rec.Ufw = append(rec.Ufw, p)
		}
		return "Opened " + p + " in ufw.", writeRecord(dataDir, sp.record, rec)
	case firewalldRunning(run):
		if _, err := run(linuxTool("firewall-cmd"), "--permanent", "--query-port="+p); err == nil {
			return "firewalld already allows " + p + "; left as it is.", nil
		}
		if _, err := run(linuxTool("firewall-cmd"), "--permanent", "--add-port="+p); err != nil {
			return "", err
		}
		if _, err := run(linuxTool("firewall-cmd"), "--reload"); err != nil {
			return "", err
		}
		if !slices.Contains(rec.Firewalld, p) {
			rec.Firewalld = append(rec.Firewalld, p)
		}
		return "Opened " + p + " in firewalld (default zone).", writeRecord(dataDir, sp.record, rec)
	}
	what := "connect"
	if sp.proto == "UDP" {
		what = "reach it"
	}
	return "No active ufw or firewalld found, so the firewall wasn't changed. If devices can't " + what + ", open the port:\n" +
		sp.linuxCommands(port), nil
}

// LinuxClose removes what LinuxOpen recorded, and nothing else.
func LinuxClose(run Runner, dataDir string) (string, error) { return tlsSpec.linuxClose(run, dataDir) }

func (sp spec) linuxClose(run Runner, dataDir string) (string, error) {
	rec, err := readRecord(dataDir, sp.record)
	if err != nil {
		return "", err
	}
	if len(rec.Ufw) == 0 && len(rec.Firewalld) == 0 {
		return "Woodshed didn't open a firewall port, so none was closed.", nil
	}
	var did []string
	var errs []error
	var keep Record
	for _, p := range rec.Ufw {
		if _, err := run(linuxTool("ufw"), "delete", "allow", p); err != nil {
			errs = append(errs, err)
			keep.Ufw = append(keep.Ufw, p)
			continue
		}
		did = append(did, "closed "+p+" in ufw")
	}
	reload := false
	for _, p := range rec.Firewalld {
		if _, err := run(linuxTool("firewall-cmd"), "--permanent", "--remove-port="+p); err != nil {
			errs = append(errs, err)
			keep.Firewalld = append(keep.Firewalld, p)
			continue
		}
		reload = true
		did = append(did, "closed "+p+" in firewalld")
	}
	if reload {
		if _, err := run(linuxTool("firewall-cmd"), "--reload"); err != nil {
			errs = append(errs, err)
		}
	}
	if err := writeRecord(dataDir, sp.record, keep); err != nil {
		errs = append(errs, err)
	}
	msg := ""
	if len(did) > 0 {
		msg = strings.ToUpper(did[0][:1]) + strings.Join(did, ", ")[1:] + "."
	}
	return msg, errors.Join(errs...)
}
