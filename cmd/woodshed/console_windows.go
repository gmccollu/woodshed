//go:build windows

package main

import (
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/gmccollu/woodshed/internal/fwrule"
)

var procGetConsoleProcessList = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// consoleProcessCount is GetConsoleProcessList's count (0 on error).
func consoleProcessCount() int {
	var pids [4]uint32
	n, _, _ := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return int(n)
}

// windowsFirewallNotes explains the first-run firewall dialog and, unless an
// enabled inbound rule allows this program, gives the command an administrator
// can run. (Windows adds a block rule when the dialog is dismissed, or shown
// where nobody can answer it.)
func windowsFirewallNotes(port int) string {
	var s strings.Builder
	s.WriteString("\n  Windows may ask whether to allow Woodshed through the firewall. Choose Allow so devices can\n")
	s.WriteString("  reach it (it may need an administrator).\n")
	exe, err := os.Executable()
	if err != nil {
		return s.String()
	}
	state := ruleUnknown
	if rules, err := fwrule.ListRules(); err == nil {
		state = firewallRuleState(rules, exe)
	}
	switch state {
	case ruleAllows:
		s.WriteString("  A firewall rule already lets devices reach this copy.\n")
		return s.String()
	case ruleBlocks:
		s.WriteString("  A firewall rule blocks this copy (the dialog was dismissed, or couldn't be shown).\n")
	default:
		s.WriteString("  No firewall rule lets devices reach this copy yet.\n")
	}
	if windows.GetCurrentProcessToken().IsElevated() {
		s.WriteString("  To allow it now:\n")
	} else {
		s.WriteString("  If devices can't reach it, run this in an administrator prompt:\n")
	}
	s.WriteString(firewallCommands(exe, port))
	return s.String()
}
