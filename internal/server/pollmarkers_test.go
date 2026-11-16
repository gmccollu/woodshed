package server

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/poller"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

// The device panel's markers hold every interface's oper changes, charted or
// not, and the restarts (docs/api.md "Device panel"; a 1.3 UI bug showed only
// the charted interfaces' changes). Five busy interfaces fill the default
// chart set of 4 and leave a fifth busy one and an idle one out; both going
// down must be in the panel's markers, and so must a restart.
func TestPollPanelMarkersCoverUnchartedInterfaces(t *testing.T) {
	ifs := []agenttest.Interface{
		{Index: 1, Name: "eth1", Descr: "eth1", SpeedMbps: 1000, InBps: 90e6, OutBps: 9e6},
		{Index: 2, Name: "eth2", Descr: "eth2", SpeedMbps: 1000, InBps: 70e6, OutBps: 7e6},
		{Index: 3, Name: "eth3", Descr: "eth3", SpeedMbps: 1000, InBps: 50e6, OutBps: 5e6},
		{Index: 4, Name: "eth4", Descr: "eth4", SpeedMbps: 1000, InBps: 30e6, OutBps: 3e6},
		{Index: 5, Name: "eth5", Descr: "eth5", SpeedMbps: 1000, InBps: 1e6, OutBps: 1e5},
		{Index: 6, Name: "eth6", Descr: "eth6", SpeedMbps: 1000},
	}
	const community = "markers-Comm-Secret"
	a, err := agenttest.Start(agenttest.Options{Community: community, Interfaces: ifs, SysName: "edge-fw-02"})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	r := startPolling(t, writeConfig(t, t.TempDir(), freePort(t), 0, nil), nil)
	var tgt api.PollTarget
	if code := r.do(t, "POST", "/api/poll/targets", map[string]any{"address": "127.0.0.1", "port": a.Addr().Port(), "version": "2c",
		"community": community, "interval_s": 30}, &tgt); code != 201 {
		t.Fatalf("add: %d", code)
	}
	from := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	panel := func() poller.Panel {
		var p poller.Panel
		if code := r.do(t, "GET", "/api/poll/device/127.0.0.1?from="+from, nil, &p); code != 200 {
			t.Fatalf("panel: %d", code)
		}
		return p
	}
	// A cycle with every interface up and its rates, so the chart set is the 4 busiest.
	pollWait(t, "a cycle with rates", func() bool {
		p := panel()
		return len(p.Charted) == 4 && len(p.Interfaces) == 6
	})
	if p := panel(); !slices.Equal(p.Charted, []string{"eth1", "eth2", "eth3", "eth4"}) {
		t.Fatalf("charted %v", p.Charted)
	}

	a.SetOper(5, 2) // busy but not charted
	a.SetOper(6, 2) // idle
	has := func(p poller.Panel, name string) *poller.Marker {
		for i, m := range p.Markers {
			if m.Kind == "oper" && m.If == name && m.Oper == "down" && m.Was == "up" {
				return &p.Markers[i]
			}
		}
		return nil
	}
	var p poller.Panel
	pollWait(t, "both down markers in the panel", func() bool {
		p = panel()
		return has(p, "eth5") != nil && has(p, "eth6") != nil
	})
	if slices.Contains(p.Charted, "eth5") || slices.Contains(p.Charted, "eth6") {
		t.Errorf("an interface that went down is charted: %v", p.Charted)
	}
	if m := has(p, "eth6"); m.Detail != "eth6 down (was up)" || m.Time == "" {
		t.Errorf("eth6 marker %+v", *m)
	}
	for _, it := range p.Interfaces {
		if (it.Name == "eth5" || it.Name == "eth6") && (it.OperChanges != 1 || it.Oper != "down") {
			t.Errorf("%s row %+v", it.Name, it)
		}
	}

	// A reboot: a restart marker beside them, in time order. (Without
	// HOST-RESOURCES the agent can't tell a reboot from an agent restart, so
	// any restart marker counts.)
	a.Reboot()
	pollWait(t, "the restart marker in the panel", func() bool {
		p = panel()
		return slices.ContainsFunc(p.Markers, func(m poller.Marker) bool { return m.Kind == "restart" })
	})
	if has(p, "eth5") == nil || has(p, "eth6") == nil {
		b, _ := json.Marshal(p.Markers)
		t.Errorf("the down markers went after the restart: %s", b)
	}
	if !slices.IsSortedFunc(p.Markers, func(x, y poller.Marker) int { return compareTime(x.Time, y.Time) }) {
		b, _ := json.Marshal(p.Markers)
		t.Errorf("markers out of order: %s", b)
	}
}

func compareTime(a, b string) int {
	ta, _ := time.Parse(time.RFC3339Nano, a)
	tb, _ := time.Parse(time.RFC3339Nano, b)
	return ta.Compare(tb)
}
