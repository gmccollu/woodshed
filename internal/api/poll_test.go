package api

import (
	"context"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/poller"
)

// The fake backend's poller: no targets. The poll routes are tested against
// a real server in internal/server (poll_test.go), with the UI's own bodies.

// fakePollTarget is docs/api.md's example target.
func fakePollTarget() PollTarget {
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	return PollTarget{ID: "pt_5c1e9a2b", Settings: poller.Settings{Address: "10.1.0.1", Port: 161, DeviceID: "10.1.0.1", Enabled: true,
		Version: "3", V3User: "monitor", IntervalS: 60, TimeoutMS: 2000, Retries: 1, Presets: []string{"system", "system-info", "interfaces"},
		Interfaces: poller.Interfaces{All: true}, MaxInterfaces: 64,
		Custom: []poller.Custom{{OID: "1.3.6.1.4.1.32473.1.2.0", Kind: "scalar", Label: "queue depth"}}},
		State: poller.State{Status: "ok", LastAttempt: &at, LastOK: &at, RTTms: 4, EngineID: "80001f8880a1b2c3d4", SysName: "edge-fw-01",
			HCCounters: true, HostResources: true, InterfacesPolled: 24, InterfacesTotal: 26}, Version: 3}
}

func (b *fakeBackend) PollTargets(context.Context) ([]PollTarget, error) {
	return []PollTarget{fakePollTarget()}, nil
}
func (b *fakeBackend) PollTarget(context.Context, string) (PollTarget, error) {
	return PollTarget{}, ErrNotFound
}
func (b *fakeBackend) CreatePollTarget(_ context.Context, in poller.Input) (PollTarget, error) {
	return PollTarget{}, ErrPollTargetLimit
}
func (b *fakeBackend) UpdatePollTarget(context.Context, string, poller.Input, int64) (PollTarget, error) {
	return PollTarget{}, ErrNotFound
}
func (b *fakeBackend) DeletePollTarget(context.Context, string) error { return ErrNotFound }
func (b *fakeBackend) TestPoll(context.Context, poller.Input, string) (poller.TestResult, error) {
	return poller.TestResult{}, &RetryAfterError{After: time.Second, Msg: "slow down"}
}
func (b *fakeBackend) PollSeries(_ context.Context, q poller.SeriesQuery) (poller.SeriesResult, error) {
	avg, mx := 81234567.0, 90123456.0
	return poller.SeriesResult{DeviceID: q.Device, BucketSeconds: 60, Source: "files",
		Series: []poller.Series{{Key: "in_bps", Label: "In (all interfaces)", Unit: "bit/s",
			Points: []poller.Point{{Start: q.From, Avg: &avg, Max: &mx, Count: 1}}}},
		Markers: []poller.Marker{{Time: "2026-11-15T10:04:00.410Z", Kind: "restart", Reboot: "1", Detail: "sysUpTime and hrSystemUptime reset"}}}, nil
}
func (b *fakeBackend) PollTimeline(context.Context, PollTimelineQuery) (poller.Timeline, error) {
	return poller.Timeline{Devices: []poller.TimelineDevice{}, Markers: []poller.Marker{}}, nil
}
func (b *fakeBackend) PollDevice(context.Context, string, time.Time, time.Time) (poller.Panel, error) {
	return poller.Panel{}, ErrNotFound
}
func (b *fakeBackend) PollState(context.Context) (poller.Summary, error) {
	at := time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)
	return poller.Summary{Targets: 12, Answering: 11, Failing: 1, LastCycle: &at,
		Hour: poller.HourTotals{Cycles: 720, Failures: map[string]int64{"timeout": 3}}}, nil
}

func TestPollRoutesErrors(t *testing.T) {
	srv := startServer(t, nil, UIConfig{})
	c := httpClient()
	for _, tc := range []struct {
		method, path, body string
		want               int
	}{
		{"GET", "/api/poll", "", 200},
		{"GET", "/api/poll/targets", "", 200},
		{"GET", "/api/poll/targets/pt_00000000", "", 404},
		{"GET", "/api/poll/series", "", 400},
		{"POST", "/api/poll/targets", `{"address":"10.1.0.1"}`, 409},
		{"POST", "/api/poll/targets", `{"address":"10.1.0.1","bogus":1}`, 400},
		{"POST", "/api/poll/test", `{"id":"pt_1"}`, 429},
		{"GET", "/api/poll/series?device=10.1.0.1&from=2026-11-15T10:00:00Z&to=2026-11-15T09:00:00Z", "", 400},
		{"GET", "/api/poll/series?device=10.1.0.1&bucket=7", "", 400},
		{"GET", "/api/poll/timeline?devices=10.1.0.1", "", 200},
		{"GET", "/api/poll/device/10.1.0.1", "", 404},
		{"DELETE", "/api/poll/targets/pt_1", "", 404},
	} {
		r := do(t, c, tc.method, srv.url(tc.path), tc.body)
		if r.code != tc.want {
			t.Errorf("%s %s: %d %s, want %d", tc.method, tc.path, r.code, r.body, tc.want)
		}
	}
}
