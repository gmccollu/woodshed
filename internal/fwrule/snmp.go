package fwrule

// The SNMP trap receiver's firewall rule (SPEC §11.2.7): the same pattern as
// the TLS rule, for inbound UDP. The MSI and `woodshed install` create it
// disabled on 162 when it's missing and leave its state alone otherwise;
// `woodshed snmp on` enables it on listeners.snmp.port and `snmp off` disables
// it. On Linux `snmp on` opens the port in ufw or firewalld and records it in
// <data>/SNMPRecordFile; `snmp off` removes only that.

// SNMPRuleName is the Windows rule (the MSI's and `woodshed install`'s).
const SNMPRuleName = "Woodshed SNMP traps (UDP 162)"

// SNMPRecordFile is where `snmp on` records what it added to a Linux firewall.
const SNMPRecordFile = "snmp-firewall.json"

// SNMPWindowsState reads the SNMP rule's state for port (no administrator
// rights needed). Output it can't read is StateUnknown.
func SNMPWindowsState(run Runner, port int) string { return snmpSpec.windowsState(run, port) }

// SNMPWindowsEnsure creates the SNMP rule, disabled on 162, unless it exists
// (then it's left exactly as it is). For `woodshed install` and the MSI.
func SNMPWindowsEnsure(run Runner, exe string) (created bool, err error) {
	return snmpSpec.windowsEnsure(run, exe)
}

// SNMPWindowsEnable enables the SNMP rule on port for exe, creating it if it's
// missing.
func SNMPWindowsEnable(run Runner, exe string, port int) error {
	return snmpSpec.windowsEnable(run, exe, port)
}

// SNMPWindowsDisable disables the SNMP rule (it stays, for the next `snmp on`).
func SNMPWindowsDisable(run Runner) error { return snmpSpec.windowsDisable(run) }

// SNMPWindowsRemove deletes the SNMP rule (uninstall). A missing rule isn't an
// error.
func SNMPWindowsRemove(run Runner) error { return snmpSpec.windowsRemove(run) }

// SNMPLinuxCommands are the commands to open the SNMP port in the common
// firewalls, for when neither is active (and for Settings).
func SNMPLinuxCommands(port int) string { return snmpSpec.linuxCommands(port) }

// SNMPLinuxOpen opens the SNMP port (UDP) in ufw or firewalld and records it,
// unless it was already open. It returns what it did, for the user.
func SNMPLinuxOpen(run Runner, dataDir string, port int) (string, error) {
	return snmpSpec.linuxOpen(run, dataDir, port)
}

// SNMPLinuxClose removes what SNMPLinuxOpen recorded, and nothing else.
func SNMPLinuxClose(run Runner, dataDir string) (string, error) {
	return snmpSpec.linuxClose(run, dataDir)
}
