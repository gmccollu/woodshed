package main

import (
	"fmt"
	"strings"

	"github.com/gmccollu/woodshed/internal/fwrule"
)

type ruleState int

const (
	ruleUnknown ruleState = iota // no rule names this program (or the firewall couldn't be read)
	ruleAllows                   // an enabled inbound rule allows it
	ruleBlocks                   // only block (or disabled) rules name it
)

// firewallRuleState reads the inbound rules whose program is exe from the
// firewall's rules (fwrule.ListRules: the same in every display language).
func firewallRuleState(rules []fwrule.WinRule, exe string) ruleState {
	state := ruleUnknown
	for _, r := range rules {
		if r.Direction != fwrule.RuleDirIn || !strings.EqualFold(r.ApplicationName, exe) {
			continue
		}
		if r.Enabled && r.Action == fwrule.RuleActionAllow {
			return ruleAllows
		}
		state = ruleBlocks
	}
	return state
}

// firewallCommands are the netsh commands that let devices reach this copy (re-test
// N17): this program only, UDP and TCP on the syslog port only, on Private and
// Domain networks only.
func firewallCommands(exe string, port int) string {
	var s strings.Builder
	for _, proto := range []string{"UDP", "TCP"} {
		fmt.Fprintf(&s, "      netsh advfirewall firewall add rule name=\"Woodshed (portable) %s %d\" dir=in action=allow "+
			"program=\"%s\" protocol=%s localport=%d profile=private,domain enable=yes\n", proto, port, exe, proto, port)
	}
	s.WriteString("  These allow Private and Domain networks only. If the devices are on a network Windows calls\n" +
		"  Public, mark that network Private in Settings, or add profile=public to the commands.\n")
	return s.String()
}
