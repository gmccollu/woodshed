package fwrule

import "strings"

// The flow listener's firewall rules (SPEC §13.1), the trap receiver's pattern
// (snmp.go) with one rule per port: the MSI and `woodshed install` create both
// disabled when they're missing and leave their state alone otherwise;
// `woodshed flow on` enables each on its port (listeners.flow.netflow_port and
// ipfix_port; a port of 0 keeps its rule disabled) and `flow off` disables
// both. On Linux `flow on` opens the ports in ufw or firewalld and records
// each in its own file; `flow off` removes only those.

// The Windows rules' names.
const (
	FlowNetFlowRuleName = "Woodshed flows (UDP 2055)"
	FlowIPFIXRuleName   = "Woodshed flows (UDP 4739)"
)

// The Linux record files.
const (
	FlowNetFlowRecordFile = "flow-netflow-firewall.json"
	FlowIPFIXRecordFile   = "flow-ipfix-firewall.json"
)

var (
	flowNetFlowSpec = spec{name: FlowNetFlowRuleName, proto: "UDP", defPort: 2055, record: FlowNetFlowRecordFile,
		desc: "Lets devices send NetFlow to Woodshed. Turned on by `woodshed flow on`."}
	flowIPFIXSpec = spec{name: FlowIPFIXRuleName, proto: "UDP", defPort: 4739, record: FlowIPFIXRecordFile,
		desc: "Lets devices send IPFIX to Woodshed. Turned on by `woodshed flow on`."}
)

// flowSpecs pairs each flow rule with the port it should be on.
func flowSpecs(netflowPort, ipfixPort int) []struct {
	sp   spec
	port int
} {
	return []struct {
		sp   spec
		port int
	}{{flowNetFlowSpec, netflowPort}, {flowIPFIXSpec, ipfixPort}}
}

// FlowWindowsState reads the flow rules' states for the two ports (a port of
// 0 is off and not checked): the first rule that isn't StateOK decides, with
// its name, or StateOK and "".
func FlowWindowsState(run Runner, netflowPort, ipfixPort int) (state, rule string) {
	for _, s := range flowSpecs(netflowPort, ipfixPort) {
		if s.port == 0 {
			continue
		}
		if st := s.sp.windowsState(run, s.port); st != StateOK {
			return st, s.sp.name
		}
	}
	return StateOK, ""
}

// FlowWindowsEnsure creates each flow rule, disabled on its default port,
// unless it exists. For `woodshed install` and the MSI.
func FlowWindowsEnsure(run Runner, exe string) (created []string, err error) {
	for _, sp := range []spec{flowNetFlowSpec, flowIPFIXSpec} {
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
func FlowWindowsEnable(run Runner, exe string, netflowPort, ipfixPort int) error {
	for _, s := range flowSpecs(netflowPort, ipfixPort) {
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
	for _, sp := range []spec{flowNetFlowSpec, flowIPFIXSpec} {
		if err := sp.windowsDisable(run); err != nil {
			return err
		}
	}
	return nil
}

// FlowWindowsRemove deletes both rules (uninstall); missing ones aren't an
// error.
func FlowWindowsRemove(run Runner) error {
	for _, sp := range []spec{flowNetFlowSpec, flowIPFIXSpec} {
		if err := sp.windowsRemove(run); err != nil {
			return err
		}
	}
	return nil
}

// FlowLinuxCommands are the commands to open the flow ports in the common
// firewalls (a port of 0 left out).
func FlowLinuxCommands(netflowPort, ipfixPort int) string {
	var parts []string
	for _, s := range flowSpecs(netflowPort, ipfixPort) {
		if s.port != 0 {
			parts = append(parts, s.sp.linuxCommands(s.port))
		}
	}
	return strings.Join(parts, "\n")
}

// FlowLinuxOpen opens the flow ports (UDP) in ufw or firewalld and records
// each, unless it was open already, and closes what an earlier `flow on`
// recorded for a port that's now 0. It returns what it did.
func FlowLinuxOpen(run Runner, dataDir string, netflowPort, ipfixPort int) (string, error) {
	var msgs []string
	for _, s := range flowSpecs(netflowPort, ipfixPort) {
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
	for _, sp := range []spec{flowNetFlowSpec, flowIPFIXSpec} {
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
