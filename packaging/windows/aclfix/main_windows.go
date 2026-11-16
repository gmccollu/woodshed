//go:build windows

// Command woodshed-aclfix resets the ACL of Woodshed's Windows data folder and everything
// in it (winacl.PrepareDataDir: a folder an ordinary user created is moved aside first, then
// the same reset `woodshed install` runs). The MSI runs it from its Binary table as a deferred
// custom action, as SYSTEM, before the installer creates its folders (so it still sees who
// created an existing one) and before the service starts:
//
//	woodshed-aclfix.exe "C:\ProgramData\Woodshed"
//
// It exits non-zero (failing the install) if the folder is a link or can't be reset.
//
// The MSI also runs it after installing the files, to give them the release commit's time:
//
//	woodshed-aclfix.exe --file-times "C:\Program Files\Woodshed\." <unix seconds>
//
// An MSI cabinet stores file times as local time with no zone, and Windows Installer applies
// them as the target machine's local time, so without this a file can look hours newer (or
// older) than it is. Only regular files directly in the folder are touched; links are skipped.
//
// And it manages the TLS syslog firewall rule (fwrule.RuleName, SPEC §10.3.6), which the WiX
// firewall extension can't keep across a major upgrade (its uninstall step deletes the rule
// when the old product is removed):
//
//	woodshed-aclfix.exe --tls-firewall ensure "C:\Program Files\Woodshed\woodshed.exe"
//	woodshed-aclfix.exe --tls-firewall remove
//
// ensure creates the rule disabled on TCP 6514 if it doesn't exist, and otherwise leaves it
// exactly as it is (enabled or not, its port); remove deletes it (a real uninstall only).
//
// The SNMP trap rule (fwrule.SNMPRuleName, SPEC §11.2.7) works the same way, on UDP 162:
//
//	woodshed-aclfix.exe --snmp-firewall ensure "C:\Program Files\Woodshed\woodshed.exe"
//	woodshed-aclfix.exe --snmp-firewall remove
//
// The flow rules (fwrule.FlowPortRuleName and FlowIPFIXRuleName, SPEC §13.1), UDP 2055 and 4739:
//
//	woodshed-aclfix.exe --flow-firewall ensure "C:\Program Files\Woodshed\woodshed.exe"
//	woodshed-aclfix.exe --flow-firewall remove
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/winacl"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "--file-times" {
		os.Exit(fileTimes(os.Args[2], os.Args[3]))
	}
	if len(os.Args) >= 3 && os.Args[1] == "--tls-firewall" {
		os.Exit(tlsFirewall(os.Args[2:]))
	}
	if len(os.Args) >= 3 && os.Args[1] == "--snmp-firewall" {
		os.Exit(snmpFirewall(os.Args[2:]))
	}
	if len(os.Args) >= 3 && os.Args[1] == "--flow-firewall" {
		os.Exit(flowFirewall(os.Args[2:]))
	}
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: woodshed-aclfix <data folder>")
		os.Exit(2)
	}
	logf := func(f string, a ...any) { fmt.Printf("woodshed-aclfix: "+f+"\n", a...) }
	if err := winacl.PrepareDataDir(os.Args[1], logf); err != nil {
		fmt.Fprintln(os.Stderr, "woodshed-aclfix:", err)
		os.Exit(1)
	}
	logf("reset %s", os.Args[1])
}

// fileTimes sets the modified and access time of every regular file directly in dir to the
// Unix time secs. It's cosmetic, so problems are reported and it still exits 0.
func fileTimes(dir, secs string) int {
	n, err := strconv.ParseInt(secs, 10, 64)
	if err != nil || n <= 0 {
		fmt.Fprintf(os.Stderr, "woodshed-aclfix: --file-times: bad time %q\n", secs)
		return 0
	}
	t := time.Unix(n, 0)
	entries, err := os.ReadDir(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "woodshed-aclfix: --file-times:", err)
		return 0
	}
	done := 0
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := os.Chtimes(filepath.Join(dir, e.Name()), t, t); err != nil {
			fmt.Fprintln(os.Stderr, "woodshed-aclfix: --file-times:", err)
			continue
		}
		done++
	}
	fmt.Printf("woodshed-aclfix: set %d files in %s to %s\n", done, dir, t.UTC().Format(time.RFC3339))
	return 0
}

// tlsFirewall is --tls-firewall ensure <exe> | remove.
func tlsFirewall(args []string) int {
	switch {
	case len(args) == 2 && args[0] == "ensure":
		created, err := fwrule.WindowsEnsure(fwrule.Exec, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "woodshed-aclfix: --tls-firewall ensure:", err)
			return 1
		}
		if created {
			fmt.Printf("woodshed-aclfix: added the firewall rule %q, disabled\n", fwrule.RuleName)
		} else {
			fmt.Printf("woodshed-aclfix: the firewall rule %q exists; left as it is\n", fwrule.RuleName)
		}
		return 0
	case len(args) == 1 && args[0] == "remove":
		if err := fwrule.WindowsRemove(fwrule.Exec); err != nil {
			fmt.Fprintln(os.Stderr, "woodshed-aclfix: --tls-firewall remove:", err)
			return 1
		}
		fmt.Printf("woodshed-aclfix: removed the firewall rule %q\n", fwrule.RuleName)
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: woodshed-aclfix --tls-firewall ensure <woodshed.exe> | remove")
	return 2
}

// snmpFirewall is --snmp-firewall ensure <exe> | remove.
func snmpFirewall(args []string) int {
	switch {
	case len(args) == 2 && args[0] == "ensure":
		created, err := fwrule.SNMPWindowsEnsure(fwrule.Exec, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "woodshed-aclfix: --snmp-firewall ensure:", err)
			return 1
		}
		if created {
			fmt.Printf("woodshed-aclfix: added the firewall rule %q, disabled\n", fwrule.SNMPRuleName)
		} else {
			fmt.Printf("woodshed-aclfix: the firewall rule %q exists; left as it is\n", fwrule.SNMPRuleName)
		}
		return 0
	case len(args) == 1 && args[0] == "remove":
		if err := fwrule.SNMPWindowsRemove(fwrule.Exec); err != nil {
			fmt.Fprintln(os.Stderr, "woodshed-aclfix: --snmp-firewall remove:", err)
			return 1
		}
		fmt.Printf("woodshed-aclfix: removed the firewall rule %q\n", fwrule.SNMPRuleName)
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: woodshed-aclfix --snmp-firewall ensure <woodshed.exe> | remove")
	return 2
}

// flowFirewall is --flow-firewall ensure <exe> | remove.
func flowFirewall(args []string) int {
	switch {
	case len(args) == 2 && args[0] == "ensure":
		created, err := fwrule.FlowWindowsEnsure(fwrule.Exec, args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "woodshed-aclfix: --flow-firewall ensure:", err)
			return 1
		}
		for _, name := range created {
			fmt.Printf("woodshed-aclfix: added the firewall rule %q, disabled\n", name)
		}
		if len(created) == 0 {
			fmt.Println("woodshed-aclfix: the flow firewall rules exist; left as they are")
		}
		return 0
	case len(args) == 1 && args[0] == "remove":
		if err := fwrule.FlowWindowsRemove(fwrule.Exec); err != nil {
			fmt.Fprintln(os.Stderr, "woodshed-aclfix: --flow-firewall remove:", err)
			return 1
		}
		fmt.Printf("woodshed-aclfix: removed the firewall rules %q and %q\n", fwrule.FlowPortRuleName, fwrule.FlowIPFIXRuleName)
		return 0
	}
	fmt.Fprintln(os.Stderr, "usage: woodshed-aclfix --flow-firewall ensure <woodshed.exe> | remove")
	return 2
}
