package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/peer"
	"github.com/gmccollu/woodshed/internal/poller"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/snmp/agenttest"
)

// The poller end to end, in process (SPEC §12.8): test agents on loopback, poll
// targets added through the API, poll lines on disk, the device panel, the
// series and timeline strips with restart markers, type=poll search, and a
// bundle whose poll/ CSVs match the lines and whose README merges a poll
// restart with a coldStart trap; no community anywhere; requests only to the
// targets.

// pollUnit runs a 30 s interval in 600 ms.
const pollUnit = 20 * time.Millisecond

type sendLog struct {
	mu  sync.Mutex
	dst map[netip.AddrPort]int
}

func (s *sendLog) add(a netip.AddrPort) {
	s.mu.Lock()
	s.dst[a]++
	s.mu.Unlock()
}

func (s *sendLog) snapshot() map[netip.AddrPort]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[netip.AddrPort]int{}
	for k, v := range s.dst {
		out[k] = v
	}
	return out
}

func startPolling(t *testing.T, cfgPath string, sends *sendLog) *running {
	t.Helper()
	opts := Options{Version: "1.3.0", Commit: "abc1234", Logger: testLogger(t), pollUnit: pollUnit}
	if sends != nil {
		opts.pollOnSend = sends.add
	}
	srv, err := Open(cfgPath, opts)
	if err != nil {
		t.Fatal(err)
	}
	srv.be.peers.find = func(context.Context, peer.Options) (peer.Info, bool) { return peer.Info{}, false }
	srv.be.peers.readConfig = func(string) (config.Config, error) { return config.Config{}, os.ErrNotExist }
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{srv: srv, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- srv.Run(ctx) }()
	waitFor(t, "the UI", func() bool { return srv.UIState().Listening })
	r.base = "http://" + srv.UIState().Addr
	t.Cleanup(func() { r.stop(t) })
	return r
}

// doRaw sends a request with headers and returns the code, headers and body.
func (r *running) doRaw(t *testing.T, method, path string, body []byte, hdr ...string) (int, http.Header, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, r.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func pollIfs() []agenttest.Interface {
	return []agenttest.Interface{
		{Index: 1, Name: "eth1", Descr: "eth1", Alias: "uplink", SpeedMbps: 1000, InBps: 80e6, OutBps: 8e6, InUcastPps: 1000},
		{Index: 2, Name: "eth2", Descr: "eth2", SpeedMbps: 1000, InBps: 1e6, OutBps: 1e6},
		{Index: 3, Name: "eth3", Descr: "eth3", SpeedMbps: 100, InBps: 1e5, OutBps: 1e5, InErrPs: 2},
	}
}

func TestPollEndToEndInProcess(t *testing.T) {
	dir := t.TempDir()
	snmpPort := freeUDP(t)
	cfgPath := writeConfig(t, dir, freePort(t), 0, func(c *config.Config) {
		c.Listeners.SNMP.Enabled, c.Listeners.SNMP.Addr, c.Listeners.SNMP.Port = true, "127.0.0.1", snmpPort
	})
	const community, authPass, privPass = "poll-Comm-Secret", "poll-Auth-Secret1", "poll-Priv-Secret1"
	u := snmp.User{Name: "monitor", Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128, AuthPass: []byte(authPass),
		PrivPass: []byte(privPass), Level: snmp.AuthPriv}
	a1, err := agenttest.Start(agenttest.Options{Community: community, Interfaces: pollIfs(), HostResources: true, CPUs: []int{20, 40},
		MemUsed: 2 << 30, MemTotal: 8 << 30, SysName: "edge-fw-01"})
	if err != nil {
		t.Fatal(err)
	}
	defer a1.Close()
	a2, err := agenttest.Start(agenttest.Options{Users: []snmp.User{u}, Interfaces: pollIfs()[:1], SysName: "core-sw-02"})
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Close()
	sends := &sendLog{dst: map[netip.AddrPort]int{}}
	r := startPolling(t, cfgPath, sends)
	dataDir := filepath.Join(dir, "data")

	// With no targets, nothing is sent.
	time.Sleep(300 * time.Millisecond)
	if n := len(sends.snapshot()); n != 0 {
		t.Fatalf("%d destinations before any target", n)
	}
	if code := r.do(t, "POST", "/api/snmp/users", map[string]any{"name": "monitor", "auth": "sha-256", "auth_pass": authPass,
		"priv": "aes-128", "priv_pass": privPass}, nil); code != 201 {
		t.Fatalf("user: %d", code)
	}
	// A v2c target and a v3 one (on another address, a device of its own).
	var t1, t2 api.PollTarget
	if code := r.do(t, "POST", "/api/poll/targets", map[string]any{"address": "127.0.0.1", "port": a1.Addr().Port(), "version": "2c",
		"community": community, "interval_s": 30}, &t1); code != 201 {
		t.Fatalf("add v2c: %d %+v", code, t1)
	}
	if t1.DeviceID != "127.0.0.1" || !t1.CommunitySet || t1.MaxInterfaces != 64 || len(t1.Presets) != 3 || !t1.Interfaces.All {
		t.Errorf("v2c target %+v", t1)
	}
	if code := r.do(t, "POST", "/api/poll/targets", map[string]any{"address": "127.0.0.1", "port": a2.Addr().Port(), "version": "3",
		"v3_user": "monitor", "device_id": "127.0.0.2", "interval_s": 30, "presets": []string{"system", "interfaces"}}, &t2); code != 201 {
		t.Fatalf("add v3: %d", code)
	}
	// Validation, duplicates and an unknown user.
	var bad struct{ Errors map[string]string }
	if code := r.do(t, "POST", "/api/poll/targets", map[string]any{"address": "edge.example", "version": "3", "v3_user": "nobody",
		"custom": []map[string]any{{"oid": "x"}}}, &bad); code != 400 || bad.Errors["address"] == "" || bad.Errors["v3_user"] == "" ||
		bad.Errors["custom[0].oid"] == "" {
		t.Errorf("validation %d %v", code, bad.Errors)
	}
	if code := r.do(t, "POST", "/api/poll/targets", map[string]any{"address": "127.0.0.1", "port": a1.Addr().Port(),
		"community": "x"}, nil); code != 409 {
		t.Errorf("duplicate %d", code)
	}

	// GET -> PUT round trip with If-Match; a stale ETag is refused.
	code, hdr, body := r.doRaw(t, "GET", "/api/poll/targets/"+t1.ID, nil)
	if code != 200 || bytes.Contains(body, []byte(community)) || !bytes.Contains(body, []byte(`"community_set":true`)) {
		t.Fatalf("get %d %s", code, body)
	}
	etag := hdr.Get("ETag")
	code, hdr2, body2 := r.doRaw(t, "PUT", "/api/poll/targets/"+t1.ID, body, "If-Match", etag)
	if code != 200 || hdr2.Get("ETag") == etag {
		t.Fatalf("round trip %d %s", code, body2)
	}
	if code, _, _ := r.doRaw(t, "PUT", "/api/poll/targets/"+t1.ID, body, "If-Match", etag); code != 409 {
		t.Errorf("stale etag %d", code)
	}

	// Polling: a few cycles.
	var sum poller.Summary
	pollWait(t, "polled cycles", func() bool {
		sum = poller.Summary{}
		r.do(t, "GET", "/api/poll", nil, &sum)
		return sum.Answering == 2 && sum.Hour.Cycles >= 8
	})
	// Only the targets were sent to.
	for dst := range sends.snapshot() {
		if dst != a1.Addr() && dst != a2.Addr() {
			t.Errorf("a request to %s", dst)
		}
	}
	var ts []api.PollTarget
	r.do(t, "GET", "/api/poll/targets", nil, &ts)
	for _, x := range ts {
		if x.State.Status != poller.StateOK || (x.ID == t1.ID && x.State.SysName != "edge-fw-01") || x.State.InterfacesPolled == 0 {
			t.Errorf("state %+v", x.State)
		}
	}
	if ts[1].State.EngineID == "" {
		t.Errorf("v3 engine %+v", ts[1].State)
	}
	var devs struct{ Devices []api.Device }
	r.do(t, "GET", "/api/devices", nil, &devs)
	polled := 0
	for _, d := range devs.Devices {
		if d.Polled && d.PollStatus == "ok" {
			polled++
		}
	}
	if polled != 2 {
		t.Errorf("devices %+v", devs.Devices)
	}

	// The device panel and the series.
	now := time.Now().UTC()
	from := now.Add(-time.Hour).Format(time.RFC3339)
	var panel poller.Panel
	if code := r.do(t, "GET", "/api/poll/device/127.0.0.1?from="+from, nil, &panel); code != 200 {
		t.Fatalf("panel %d", code)
	}
	if panel.TargetID != t1.ID || panel.System.SysName != "edge-fw-01" || len(panel.Interfaces) != 3 || panel.Charted[0] != "eth1" ||
		panel.Interfaces[0].Alias != "uplink" || panel.System.CPU.Now == nil || *panel.System.CPU.Now != 30 ||
		panel.Interfaces[0].PeakInBps == nil || *panel.Interfaces[0].PeakInBps < 60e6 {
		b, _ := json.Marshal(panel)
		t.Errorf("panel %s", b)
	}
	var ser poller.SeriesResult
	q := url.Values{"device": {"127.0.0.1"}, "from": {from}, "bucket": {"60"}, "series": {"in_bps,cpu,if.eth3.in_err_d,mem_used_pct"}}
	if code := r.do(t, "GET", "/api/poll/series?"+q.Encode(), nil, &ser); code != 200 || ser.Source != "files" || len(ser.Series) != 4 {
		t.Fatalf("series %d %+v", code, ser)
	}
	last := func(s poller.Series) *poller.Point {
		for i := len(s.Points) - 1; i >= 0; i-- {
			if s.Points[i].Count > 0 {
				return &s.Points[i]
			}
		}
		return nil
	}
	if p := last(ser.Series[0]); p == nil || *p.Avg < 40e6 || *p.Avg > 160e6 { // 88 Mb/s; wide, since a loaded runner skews the reply times
		t.Errorf("in_bps %+v", p)
	}
	if p := last(ser.Series[3]); p == nil || *p.Avg != 25 {
		t.Errorf("mem %+v", p)
	}
	if code := r.do(t, "GET", "/api/poll/series?device=127.0.0.1&series=bogus", nil, nil); code != 400 {
		t.Errorf("bogus series %d", code)
	}

	// A reboot of the first agent, and a coldStart trap from it: one event.
	a1.Reboot()
	pollWait(t, "the restart marker", func() bool {
		var tl poller.Timeline
		r.do(t, "GET", "/api/poll/timeline?devices=127.0.0.1,127.0.0.2&from="+from+"&bucket=60", nil, &tl)
		return len(tl.Devices) == 2 && len(tl.Markers) > 0 && tl.Markers[0].Kind == "restart" && tl.Markers[0].Reboot == "1"
	})
	if _, err := loadgen.Send(context.Background(), loadgen.SendOptions{Addr: fmt.Sprintf("127.0.0.1:%d", snmpPort), Proto: "trap",
		Count: 1, Trap: loadgen.TrapOptions{Version: "2c", Community: []byte(community), TrapOID: snmp.OID{1, 3, 6, 1, 6, 3, 1, 1, 5, 1}}}); err != nil {
		t.Fatal(err)
	}
	var page struct {
		Results []struct {
			Type   string         `json:"type"`
			Fields map[string]any `json:"fields"`
		} `json:"results"`
	}
	pollWait(t, "the restart in search", func() bool {
		r.srv.store.Flush()
		r.do(t, "GET", "/api/search?type=poll&kinds=restart", nil, &page)
		return len(page.Results) == 1
	})
	if f := page.Results[0].Fields; f["kind"] != "restart" || f["reboot"] != "1" {
		t.Errorf("search %+v", f)
	}
	if code := r.do(t, "GET", "/api/search?type=poll&severities=3", nil, nil); code != 400 {
		t.Errorf("syslog filter with type=poll: %d", code)
	}
	// A few answered cycles after the reboot, so the bundle has rates on both sides.
	var afterReboot poller.Summary
	r.do(t, "GET", "/api/poll", nil, &afterReboot)
	pollWait(t, "cycles after the reboot", func() bool {
		var s poller.Summary
		r.do(t, "GET", "/api/poll", nil, &s)
		return s.Hour.Cycles >= afterReboot.Hour.Cycles+8
	})

	// The coldStart trap is stored (the bundle merges it with the restart).
	pollWait(t, "the coldStart trap stored", func() bool {
		r.srv.store.Flush()
		var tp struct{ Results []json.RawMessage }
		r.do(t, "GET", "/api/search?type=trap", nil, &tp)
		return len(tp.Results) == 1
	})
	// The bundle: poll CSVs, the README's Polls line, the merged reboot.
	r.srv.store.Flush()
	bodyB := map[string]any{"kind": "bundle", "at": time.Now().UTC().Format(time.RFC3339Nano), "before": "10m", "after": "0s",
		"active_devices": true}
	var created map[string]string
	if code := r.do(t, "POST", "/api/exports", bodyB, &created); code != 202 {
		t.Fatalf("bundle %d", code)
	}
	var info api.ExportInfo
	waitFor(t, "bundle ready", func() bool {
		r.do(t, "GET", "/api/exports/"+created["id"], nil, &info)
		return info.State == "ready"
	})
	resp, err := http.Get(r.base + "/api/exports/" + created["id"] + "/download")
	if err != nil {
		t.Fatal(err)
	}
	zb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(zb, []byte(community)) {
		t.Error("the community is in the bundle")
	}
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, zf := range zr.File {
		rc, _ := zf.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		files[zf.Name] = b
	}
	readme := string(files["README.txt"])
	if !strings.Contains(readme, "\n  Polls        9 of 9") && !strings.Contains(readme, "\n  Polls        ") || !strings.Contains(readme, "Reboots      1: ") ||
		!strings.Contains(readme, "coldStart trap") || !strings.Contains(readme, "(poll: ") {
		t.Errorf("README:\n%s", readme)
	}
	sys, ok := files["poll/127.0.0.1/system.csv"]
	if !ok {
		t.Fatalf("no system.csv in %v", keys(files))
	}
	rows, err := csv.NewReader(bytes.NewReader(sys)).ReadAll()
	if err != nil || strings.Join(rows[0], ",") != "time,cycle,uptime_s,hr_uptime_s,cpu_pct,mem_used_bytes,mem_total_bytes,rtt_ms,status,detail" {
		t.Fatalf("system.csv %v %v", rows[:1], err)
	}
	restarts := 0
	for _, row := range rows[1:] {
		if row[8] == "restart" {
			restarts++
		}
	}
	if restarts != 1 {
		t.Errorf("%d restart rows", restarts)
	}
	ifc, ok := files["poll/127.0.0.1/interfaces.csv"]
	if !ok || !bytes.HasPrefix(ifc, []byte("time,cycle,if_index,if_name,if_alias,oper,speed_mbps,in_octets,out_octets,in_bps,out_bps,")) {
		t.Errorf("interfaces.csv %q", ifc[:min(len(ifc), 200)])
	}
	if _, ok := files["poll/127.0.0.2/system.csv"]; !ok {
		t.Errorf("no v3 device system.csv in %v", keys(files))
	}

	// Delete: the target goes, its files stay.
	if code := r.do(t, "DELETE", "/api/poll/targets/"+t2.ID, nil, nil); code != 204 {
		t.Errorf("delete %d", code)
	}
	r.stop(t)
	filepath.WalkDir(dataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.HasSuffix(p, ".gz") {
			return nil
		}
		if n := filepath.Base(p); n == "snmp-users.json" || n == "snmp-users.dat" {
			return nil // the credentials store itself (0600, or DPAPI)
		}
		b, _ := os.ReadFile(p)
		for _, s := range []string{community, authPass, privPass} {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds a secret", p)
			}
		}
		return nil
	})
	if _, err := os.Stat(filepath.Join(dataDir, "logs", "127.0.0.2", "poll")); err != nil {
		t.Errorf("the deleted target's files: %v", err)
	}
}

// pollWait is waitFor with room for a loaded runner: a poll cycle is a few
// round trips, and the condition returns as soon as it holds.
func pollWait(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
