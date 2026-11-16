package poller

import (
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/pollrec"
)

// A restart's reason reads the same on the charts (the marker) as in the
// bundle's README and CSV (datatype.RestartDetail), and an uptime that rose
// too little isn't called a reset in either.
func TestRestartWordsAgree(t *testing.T) {
	for _, c := range []struct{ line, reason string }{
		{"kind=restart cycle=2 reboot=? uptime=650 prev_uptime=640 source=sysUpTime", "sysUpTime rose less than the time since the last poll"},
		{"kind=restart cycle=2 reboot=1 uptime=1532 prev_uptime=104518345 hr_uptime=1600 prev_hr_uptime=104519000 source=sysUpTime,hrSystemUptime",
			"sysUpTime and hrSystemUptime reset"},
		{"kind=restart cycle=2 reboot=0 uptime=650 prev_uptime=640 boots=8 prev_boots=7 source=sysUpTime,engineBoots",
			"sysUpTime rose less than the time since the last poll, engineBoots went up"},
	} {
		r, err := pollrec.Parse([]byte(c.line))
		if err != nil {
			t.Fatal(err)
		}
		m := restartMarker("", time.Now(), &r)
		d := datatype.RestartDetail(&r)
		if !strings.HasPrefix(m.Detail, c.reason) || !strings.HasPrefix(d, c.reason) {
			t.Errorf("%s:\n marker %q\n README %q\n  want  %q…", c.line, m.Detail, d, c.reason)
		}
		if strings.Contains(c.line, "prev_uptime=640") && (strings.Contains(m.Detail, "sysUpTime reset") || strings.Contains(d, "sysUpTime reset")) {
			t.Errorf("%s: an uptime that rose is called a reset: %q / %q", c.line, m.Detail, d)
		}
	}
}
