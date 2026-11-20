package config

import "testing"

// Every event text the server writes reads back as what it says, whatever the
// device's name holds; so do 2.1.0-rc1's device events (no "was"), and other
// texts don't parse.
func TestParseSeverityEvent(t *testing.T) {
	levels := []int{-1, 0, 4, 6, 7}
	for _, stopped := range []bool{false, true} {
		for l := SeverityEmerg; l <= SeverityDebug; l++ {
			for w := SeverityEmerg; w <= SeverityDebug; w++ {
				text := DefaultSeverityEvent(l, w, 2, stopped)
				e, ok := ParseSeverityEvent(text)
				if !ok || !e.Default || e.Level != l || e.Was != w || !e.WasKnown {
					t.Errorf("%q: %+v %v", text, e, ok)
				}
			}
		}
		for _, who := range []string{"192.0.2.10", "192.0.2.10 (ap)", "2001:db8::1 (lab, was set to info and above)"} {
			for _, l := range levels {
				for _, w := range levels {
					if l == w && l < 0 {
						continue
					}
					text := DeviceSeverityEvent(who, l, 4, w, 6, stopped)
					e, ok := ParseSeverityEvent(text)
					if !ok || e.Default || e.Level != l || e.Was != w || !e.WasKnown {
						t.Errorf("%q: %+v %v", text, e, ok)
					}
				}
			}
		}
	}
	for text, want := range map[string]SeverityEvent{
		"severity filter for 192.0.2.10 (ap) set to info and above":                                                {Level: 6},
		"severity filter for 192.0.2.10 set to store everything":                                                   {Level: 7},
		"severity filter for 192.0.2.10 set to the default (warning and above)":                                    {Level: -1},
		"severity filter for 192.0.2.10 set to emerg only (changed while Woodshed was stopped)":                    {Level: 0},
		"severity filter for 192.0.2.10 set to the default, store everything (changed while Woodshed was stopped)": {Level: -1},
		"default severity filter set to info and above (was everything); 1 device keeps its own setting":           {Default: true, Level: 6, Was: 7, WasKnown: true},
	} {
		if e, ok := ParseSeverityEvent(text); !ok || e != want {
			t.Errorf("%q: %+v %v, want %+v", text, e, ok, want)
		}
	}
	for _, text := range []string{"", "severity filter for 192.0.2.10 set to loud", "default severity filter set to info and above",
		"Woodshed started", "severity filter for  set to info and above, was"} {
		if e, ok := ParseSeverityEvent(text); ok {
			t.Errorf("%q parsed: %+v", text, e)
		}
	}
}
