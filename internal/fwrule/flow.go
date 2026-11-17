package fwrule

import (
	"slices"
	"strconv"
	"strings"
)

// The flow listener's firewall rules (SPEC §13.1), the trap receiver's pattern
// (snmp.go) with one rule per port: the MSI and `woodshed install` create both
// disabled when they're missing and leave their state alone otherwise;
// `woodshed flow on` enables each on its port (listeners.flow.flow_port and
// ipfix_port; a port of 0 keeps its rule disabled) and `flow off` disables
// both. On Linux `flow on` opens the ports in ufw or firewalld and records
// each in its own file; `flow off` removes only those.

// The Windows rules' names.
const (
	FlowPortRuleName  = "Woodshed flows (UDP 2055)"
	FlowIPFIXRuleName = "Woodshed flows (UDP 4739)"
)

// The Linux record files.
const (
	FlowPortRecordFile  = "flow-firewall.json"
	FlowIPFIXRecordFile = "flow-ipfix-firewall.json"
)

var (
	flowPortSpec = spec{name: FlowPortRuleName, proto: "UDP", defPort: 2055, record: FlowPortRecordFile,
		desc: "Lets devices send flows (v5, v9) to Woodshed. Turned on by `woodshed flow on`."}
	flowIPFIXSpec = spec{name: FlowIPFIXRuleName, proto: "UDP", defPort: 4739, record: FlowIPFIXRecordFile,
		desc: "Lets devices send IPFIX to Woodshed. Turned on by `woodshed flow on`."}
)

// flowSpecs pairs each flow rule with the port it should be on.
func flowSpecs(flowPort, ipfixPort int) []struct {
	sp   spec
	port int
} {
	return []struct {
		sp   spec
		port int
	}{{flowPortSpec, flowPort}, {flowIPFIXSpec, ipfixPort}}
}

// FlowRuleState is one flow rule's name and state.
type FlowRuleState struct {
	Rule, State string
}

// FlowWindowsStates reads the flow rules' states for the two ports (a port of
// 0 is off and not checked): every rule that isn't StateOK, in order (the
// flow port's, then IPFIX's); none when all are.
func FlowWindowsStates(run Runner, flowPort, ipfixPort int) []FlowRuleState {
	var out []FlowRuleState
	for _, s := range flowSpecs(flowPort, ipfixPort) {
		if s.port == 0 {
			continue
		}
		if st := s.sp.windowsState(run, s.port); st != StateOK {
			out = append(out, FlowRuleState{Rule: s.sp.name, State: st})
		}
	}
	return out
}

// FlowWindowsEnsure creates each flow rule, disabled on its default port,
// unless it exists. For `woodshed install` and the MSI.
func FlowWindowsEnsure(run Runner, exe string) (created []string, err error) {
	for _, sp := range []spec{flowPortSpec, flowIPFIXSpec} {
		c, err := sp.windowsEnsure(run, exe)
		if err != nil {
			return created, err
		}
		if c {
			created = append(created, sp.name)
		}
	}
	return created, nil
}

// FlowWindowsEnable enables each rule on its port for exe (creating it if
// it's missing); a port of 0 disables its rule.
func FlowWindowsEnable(run Runner, exe string, flowPort, ipfixPort int) error {
	for _, s := range flowSpecs(flowPort, ipfixPort) {
		var err error
		if s.port == 0 {
			if ok, _ := s.sp.exists(run); ok {
				err = s.sp.windowsDisable(run)
			}
		} else {
			err = s.sp.windowsEnable(run, exe, s.port)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// FlowWindowsDisable disables both rules (they stay, for the next `flow on`).
func FlowWindowsDisable(run Runner) error {
	for _, sp := range []spec{flowPortSpec, flowIPFIXSpec} {
		if err := sp.windowsDisable(run); err != nil {
			return err
		}
	}
	return nil
}

// FlowWindowsRemove deletes both rules (uninstall); missing ones aren't an
// error.
func FlowWindowsRemove(run Runner) error {
	for _, sp := range []spec{flowPortSpec, flowIPFIXSpec} {
		if err := sp.windowsRemove(run); err != nil {
			return err
		}
	}
	return nil
}

// FlowLinuxCommands are the commands to open the flow ports in the common
// firewalls (a port of 0 left out).
func FlowLinuxCommands(flowPort, ipfixPort int) string {
	var parts []string
	for _, s := range flowSpecs(flowPort, ipfixPort) {
		if s.port != 0 {
			parts = append(parts, s.sp.linuxCommands(s.port))
		}
	}
	return strings.Join(parts, "\n")
}

// FlowLinuxOpen opens the flow ports (UDP) in ufw or firewalld and records
// each, unless it was open already, and closes what an earlier `flow on`
// recorded for a port that's now 0. It returns what it did.
func FlowLinuxOpen(run Runner, dataDir string, flowPort, ipfixPort int) (string, error) {
	var msgs []string
	for _, s := range flowSpecs(flowPort, ipfixPort) {
		var msg string
		var err error
		if s.port == 0 {
			msg, err = s.sp.linuxClose(run, dataDir)
		} else {
			msg, err = s.sp.linuxOpen(run, dataDir, s.port)
		}
		if msg != "" {
			msgs = append(msgs, msg)
		}
		if err != nil {
			return strings.Join(msgs, "\n"), err
		}
	}
	return strings.Join(msgs, "\n"), nil
}

// FlowLinuxClose removes what FlowLinuxOpen recorded, and nothing else.
func FlowLinuxClose(run Runner, dataDir string) (string, error) {
	var msgs []string
	for _, sp := range []spec{flowPortSpec, flowIPFIXSpec} {
		msg, err := sp.linuxClose(run, dataDir)
		if msg != "" {
			msgs = append(msgs, msg)
		}
		if err != nil {
			return strings.Join(msgs, "\n"), err
		}
	}
	return strings.Join(msgs, "\n"), nil
}

// FlowLinuxPort is one flow port's Linux firewall state, for `woodshed flow
// status`.
type FlowLinuxPort struct {
	Port int
	// Opened is the firewall `flow on` recorded opening the port in ("ufw",
	// "firewalld"); "" when it didn't.
	Opened string
	// Allowed is, when it isn't Opened, the firewall that allows the port now
	// (opened some other way, or before `flow on`); "" when none does or
	// the firewall can't be read (ufw needs root to show its rules).
	Allowed string
}

// Proto is the port as the firewalls write it ("2055/udp").
func (p FlowLinuxPort) Proto() string { return strconv.Itoa(p.Port) + "/udp" }

// FlowLinuxState reads, for each flow port that's on, what `flow on`
// recorded opening and, failing that, whether ufw or firewalld allows it now.
// It changes nothing.
func FlowLinuxState(run Runner, dataDir string, flowPort, ipfixPort int) []FlowLinuxPort {
	var out []FlowLinuxPort
	for _, s := range flowSpecs(flowPort, ipfixPort) {
		if s.port == 0 {
			continue
		}
		fp := FlowLinuxPort{Port: s.port}
		p := fp.Proto()
		if rec, err := readRecord(dataDir, s.sp.record); err == nil {
			switch {
			case slices.Contains(rec.Ufw, p):
				fp.Opened = "ufw"
			case slices.Contains(rec.Firewalld, p):
				fp.Opened = "firewalld"
			}
		}
		if fp.Opened == "" {
			fp.Allowed = linuxAllows(run, s.port, p)
		}
		out = append(out, fp)
	}
	return out
}

// linuxAllows is the firewall that allows p ("2055/udp") now: "ufw" when it's
// active and lists an ALLOW rule for p (or the bare port), "firewalld" when
// it's running and its permanent config has p; else "".
func linuxAllows(run Runner, port int, p string) string {
	if out, err := run(linuxTool("ufw"), "status"); err == nil && strings.Contains(out, "Status: active") {
		bare := strconv.Itoa(port)
		for _, line := range strings.Split(out, "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && (f[0] == p || f[0] == bare) && f[1] == "ALLOW" {
				return "ufw"
			}
		}
		return ""
	}
	if firewalldRunning(run) {
		if _, err := run(linuxTool("firewall-cmd"), "--permanent", "--query-port="+p); err == nil {
			return "firewalld"
		}
	}
	return ""
}
