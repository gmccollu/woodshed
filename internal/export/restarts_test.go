package export

import (
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
)

// Restarts that were the SNMP agent's alone (reboot=0) aren't counted as
// reboots (the 1.3 lab: three agent restarts were titled "Reboots 3"). Every
// restart is still listed (SPEC §12.10 #14); with none it's "Reboots none".
func TestReadmeRestartsVsReboots(t *testing.T) {
	at := time.Date(2026, 11, 15, 9, 40, 0, 0, time.UTC)
	info := Info{From: at.Add(-time.Hour), To: at.Add(5 * time.Minute),
		Filters: Filters{Kind: KindBundle, At: &at, Before: time.Hour, After: 5 * time.Minute, Types: []string{datatype.Syslog, datatype.Poll}}}
	agent := func(min int) datatype.Reboot {
		return datatype.Reboot{Time: at.Add(-time.Duration(min) * time.Minute), Source: "poll", Reboot: "0",
			Detail: "sysUpTime reset; the agent restarted, not the device"}
	}
	b := newBuilder(Options{Location: time.UTC})
	readme := func(rs ...datatype.Reboot) (string, string) {
		d := DeviceSummary{DeviceID: "10.1.0.1", IP: "10.1.0.1", Types: map[string]TypeSummary{}, Reboots: rs}
		return b.bundleReadme(info, []DeviceSummary{d}), d.Line([]string{datatype.Syslog, datatype.Poll})
	}

	r, line := readme(agent(50), agent(30), agent(10))
	if !strings.Contains(r, "\n  Restarts     3 (0 reboots): 08:50:00.000 (poll: sysUpTime reset; the agent restarted, not the device), 09:10:00.000") ||
		strings.Contains(r, "Reboots      3") {
		t.Errorf("three agent restarts:\n%s", r)
	}
	if !strings.Contains(line, "restarts 3, reboots 0") {
		t.Errorf("line %q", line)
	}

	reboot := datatype.Reboot{Time: at.Add(-20 * time.Minute), Source: "poll, coldStart trap", Reboot: "1", Detail: "sysUpTime and hrSystemUptime reset"}
	r, line = readme(agent(50), reboot)
	if !strings.Contains(r, "\n  Restarts     2 (1 reboot): 08:50:00.000 (poll: ") || !strings.Contains(line, "restarts 2, reboots 1") {
		t.Errorf("an agent restart and a reboot:\n%s\n%s", r, line)
	}

	// Only reboots (and unknowns, and traps): as before.
	unknown := datatype.Reboot{Time: at.Add(-5 * time.Minute), Source: "poll", Reboot: "?", Detail: "sysUpTime reset; the device may have rebooted"}
	trap := datatype.Reboot{Time: at.Add(-2 * time.Minute), Source: "coldStart trap"}
	r, line = readme(reboot, unknown, trap)
	if !strings.Contains(r, "\n  Reboots      3: 09:20:00.000") || strings.Contains(r, "Restarts") || !strings.Contains(line, "reboots 3") ||
		strings.Contains(line, "restarts") {
		t.Errorf("reboots only:\n%s\n%s", r, line)
	}

	r, line = readme()
	if !strings.Contains(r, "\n  Reboots      none (no restart in the polls)") || !strings.Contains(line, "reboots 0") {
		t.Errorf("none:\n%s\n%s", r, line)
	}
}
