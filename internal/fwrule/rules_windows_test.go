//go:build windows

package fwrule

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// englishNetsh reads `netsh advfirewall firewall show rule name=all verbose`
// when it's in English (CI's runners), by rule name; nil otherwise. Only this
// test parses netsh: it's the independent reading the COM walk is checked
// against.
func englishNetsh(out string) map[string][]map[string]string {
	rules := map[string][]map[string]string{}
	for _, block := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n\n") {
		f := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok {
				f[strings.TrimSpace(k)] = strings.TrimSpace(v)
			}
		}
		if name, ok := f["Rule Name"]; ok {
			rules[name] = append(rules[name], f)
		}
	}
	return rules
}

func allDigits(s string) bool {
	_, err := strconv.ParseUint(s, 10, 16)
	return err == nil
}

// The real COM walk, read-only, over this machine's rules: a name no rule has
// finds none, and every rule whose name is unique reads as netsh shows it
// (enabled, direction, action, local port, program), which checks each
// property's vtable slot and value mapping. It changes nothing.
func TestListRulesMatchesNetsh(t *testing.T) {
	out, nerr := exec.Command(Netsh(), "advfirewall", "firewall", "show", "rule", "name=all", "verbose").Output()
	none, err := listRules("Woodshed test: no rule has this name " + strconv.FormatInt(time.Now().UnixNano(), 36))
	if err != nil {
		if nerr != nil {
			t.Skipf("the firewall can't be read here (COM: %v; netsh: %v)", err, nerr)
		}
		t.Fatalf("COM: %v, but netsh reads the rules", err)
	}
	if len(none) != 0 {
		t.Fatalf("a name no rule has: %+v", none)
	}
	all, err := listRules()
	if err != nil || len(all) == 0 {
		t.Fatalf("every rule: %d, %v", len(all), err)
	}
	byName := englishNetsh(string(out))
	if len(byName) == 0 {
		t.Skipf("netsh's output isn't English here (%d rules through COM); nothing to compare", len(all))
	}
	counts := map[string]int{}
	for _, r := range all {
		counts[strings.ToLower(r.Name)]++
	}
	compared, ports, programs := 0, 0, 0
	var unique *WinRule
	for i, r := range all {
		ns := byName[r.Name]
		if counts[strings.ToLower(r.Name)] != 1 || len(ns) != 1 {
			continue
		}
		n := ns[0]
		action := map[string]int32{"Allow": RuleActionAllow, "Block": 0}
		want, ok := action[n["Action"]]
		if !ok { // Bypass: no NET_FW_ACTION for it
			continue
		}
		if unique == nil {
			unique = &all[i]
		}
		compared++
		if r.Enabled != (n["Enabled"] == "Yes") || r.Action != want ||
			r.Direction != map[string]int32{"In": RuleDirIn, "Out": 2}[n["Direction"]] {
			t.Errorf("%q: COM %+v; netsh Enabled %q, Direction %q, Action %q", r.Name, r, n["Enabled"], n["Direction"], n["Action"])
		}
		if p, ok := map[string]int32{"TCP": 6, "UDP": 17}[n["Protocol"]]; ok && r.Protocol != p {
			t.Errorf("%q: COM Protocol %d, netsh Protocol %q", r.Name, r.Protocol, n["Protocol"])
		}
		if allDigits(r.LocalPorts) {
			ports++
			if n["LocalPort"] != r.LocalPorts {
				t.Errorf("%q: COM LocalPorts %q, netsh LocalPort %q", r.Name, r.LocalPorts, n["LocalPort"])
			}
		}
		if p := n["Program"]; r.ApplicationName != "" && p != "" && p != "Any" && !strings.Contains(p+r.ApplicationName, "%") {
			programs++
			if !strings.EqualFold(p, r.ApplicationName) {
				t.Errorf("%q: COM ApplicationName %q, netsh Program %q", r.Name, r.ApplicationName, p)
			}
		}
	}
	t.Logf("%d rules through COM, %d compared with netsh (%d by port, %d by program)", len(all), compared, ports, programs)
	if compared < 10 {
		t.Fatalf("only %d rules to compare", compared)
	}
	// Names match in any case, as netsh's name= does.
	got, err := listRules(strings.ToUpper(unique.Name))
	if err != nil || len(got) != 1 || got[0] != *unique {
		t.Errorf("by name %q: %+v %v, want %+v", strings.ToUpper(unique.Name), got, err, *unique)
	}
}
