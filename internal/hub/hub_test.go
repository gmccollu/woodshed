package hub

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
)

type fakeClock struct{ ns atomic.Int64 }

func newClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.ns.Store(t.UnixNano())
	return c
}
func (c *fakeClock) Now() time.Time      { return time.Unix(0, c.ns.Load()).UTC() }
func (c *fakeClock) Add(d time.Duration) { c.ns.Add(int64(d)) }
func (c *fakeClock) Set(t time.Time)     { c.ns.Store(t.UnixNano()) }
func sev(n int) *int                     { return &n }
func ip(s string) netip.Addr             { return netip.MustParseAddr(s) }
func msg(from string, sev int, raw string) model.Message {
	return model.Message{Received: t0, Sender: ip(from), Severity: sev, Facility: 1, Raw: []byte(raw)}
}

var t0 = time.Date(2026, 11, 10, 20, 41, 7, 112_345_678, time.UTC)

var groups = map[string]string{"192.0.2.1": "HQ", "192.0.2.2": "HQ", "198.51.100.5": "Lab"}

func groupOf(id string) string { return groups[id] }

func drain(s *Subscription) (entries []Entry, notices []Notice) {
	for {
		select {
		case it, ok := <-s.C():
			if !ok {
				return
			}
			if it.Entry != nil {
				entries = append(entries, *it.Entry)
			} else {
				notices = append(notices, *it.Sampled)
			}
		default:
			return
		}
	}
}

func TestFilters(t *testing.T) {
	type tc struct {
		name string
		f    Filter
		want []string // raws that pass
	}
	in := []model.Message{
		msg("192.0.2.1", 3, "<11>Link DOWN on port 1"),
		msg("192.0.2.2", 6, "<14>user login ok"),
		msg("198.51.100.5", 7, "<15>debug noise"),
		msg("203.0.113.9", model.Unknown, "no pri: Link down"),
		msg("2001:db8::1", 4, "<12>Ünïcode WARNING"),
	}
	cases := []tc{
		{"all", Filter{}, []string{"<11>Link DOWN on port 1", "<14>user login ok", "<15>debug noise", "no pri: Link down", "<12>Ünïcode WARNING"}},
		{"devices", Filter{Devices: []string{"192.0.2.2", "2001_db8__1"}}, []string{"<14>user login ok", "<12>Ünïcode WARNING"}},
		{"group", Filter{Group: "HQ"}, []string{"<11>Link DOWN on port 1", "<14>user login ok"}},
		{"ungrouped", Filter{Ungrouped: true}, []string{"no pri: Link down", "<12>Ünïcode WARNING"}},
		{"min_severity 4, unknown passes", Filter{MinSeverity: sev(4)}, []string{"<11>Link DOWN on port 1", "no pri: Link down", "<12>Ünïcode WARNING"}},
		{"min_severity 0", Filter{MinSeverity: sev(0)}, []string{"no pri: Link down"}},
		{"q ascii fold", Filter{Q: "link down"}, []string{"<11>Link DOWN on port 1", "no pri: Link down"}},
		{"q non-ascii", Filter{Q: "ÜNÏCODE"}, []string{"<12>Ünïcode WARNING"}},
		{"combined", Filter{Group: "HQ", MinSeverity: sev(5), Q: "PORT"}, []string{"<11>Link DOWN on port 1"}},
		{"severities 3,7", Filter{Severities: SeveritySet(0).With(3).With(7)}, []string{"<11>Link DOWN on port 1", "<15>debug noise"}},
		{"severities unknown only", Filter{Severities: SeverityUnknownBit}, []string{"no pri: Link down"}},
		{"severities win over min_severity", Filter{Severities: SeveritySet(0).With(6), MinSeverity: sev(0)}, []string{"<14>user login ok"}},
		{"severities none", Filter{Severities: SeverityNone, MinSeverity: sev(7)}, nil},
		{"all severities", Filter{Severities: AllSeverities}, []string{"<11>Link DOWN on port 1", "<14>user login ok", "<15>debug noise", "no pri: Link down", "<12>Ünïcode WARNING"}},
	}
	for _, c := range cases {
		h := New(Options{GroupOf: groupOf})
		for _, m := range in {
			h.Publish(m)
		}
		s := h.Subscribe(c.f)
		var got []string
		for _, e := range s.Replay {
			got = append(got, string(e.Raw))
			if !c.f.Match(e, groupOf) {
				t.Errorf("%s: Match disagrees on %q", c.name, e.Raw)
			}
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s:\n got %q\nwant %q", c.name, got, c.want)
		}
		// Live delivery uses the same filter.
		for _, m := range in {
			h.Publish(m)
		}
		live, _ := drain(s)
		if len(live) != len(c.want) {
			t.Errorf("%s: live got %d, want %d", c.name, len(live), len(c.want))
		}
		s.Close()
	}
}

func TestParseFilter(t *testing.T) {
	f, err := ParseFilter(url.Values{"devices": {"192.0.2.1, 192.0.2.2,,"}, "min_severity": {"4"}, "q": {"Link"}, "group": {"HQ"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Devices) != 2 || f.Devices[1] != "192.0.2.2" || *f.MinSeverity != 4 || f.Q != "Link" || f.Group != "HQ" {
		t.Errorf("%+v", f)
	}
	f, _ = ParseFilter(url.Values{"ungrouped": {"true"}})
	if !f.Ungrouped || f.MinSeverity != nil {
		t.Errorf("%+v", f)
	}
	for _, bad := range []url.Values{
		{"min_severity": {"8"}}, {"min_severity": {"-1"}}, {"min_severity": {"warn"}},
		{"ungrouped": {"yes"}}, {"group": {"HQ"}, "ungrouped": {"true"}},
	} {
		if _, err := ParseFilter(bad); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestDefaultHeartbeatIs15s(t *testing.T) {
	// docs/api.md: the UI treats 45 s of silence as a dead stream.
	if DefaultHeartbeat != 15*time.Second || New(Options{}).opts.Heartbeat != 15*time.Second {
		t.Errorf("heartbeat %v", DefaultHeartbeat)
	}
}

func TestParseSeverities(t *testing.T) {
	f, err := ParseFilter(url.Values{"severities": {"0, 3,unknown,"}, "min_severity": {"7"}})
	if err != nil {
		t.Fatal(err)
	}
	if f.MinSeverity != nil || f.Severities != SeveritySet(0).With(0).With(3).With(-1) {
		t.Errorf("severities should win: %+v", f)
	}
	for sev, want := range map[int]bool{0: true, 1: false, 3: true, 7: false, -1: true} {
		if f.Severities.Has(sev) != want {
			t.Errorf("Has(%d) = %v", sev, !want)
		}
	}
	// An empty value means all, so min_severity applies.
	f, err = ParseFilter(url.Values{"severities": {""}, "min_severity": {"4"}})
	if err != nil || f.Severities != 0 || f.MinSeverity == nil || *f.MinSeverity != 4 {
		t.Errorf("empty severities: %+v %v", f, err)
	}
	if s, err := ParseSeverities("UNKNOWN,7"); err != nil || s != SeverityUnknownBit|1<<7 {
		t.Errorf("%b %v", s, err)
	}
	if s, err := ParseSeverities("none"); err != nil || s != SeverityNone || s.Has(0) || s.Has(-1) {
		t.Errorf("none: %b %v", s, err)
	}
	for _, bad := range []string{"8", "-1", "warn", "3,x", "03", "1.0", " 9 ", "none,3", "unknown,none"} {
		if _, err := ParseFilter(url.Values{"severities": {bad}}); err == nil {
			t.Errorf("severities=%q accepted", bad)
		}
	}
	// A bad min_severity is still refused when severities is given.
	if _, err := ParseFilter(url.Values{"severities": {"3"}, "min_severity": {"9"}}); err == nil {
		t.Error("bad min_severity accepted next to severities")
	}
}

func TestLiveSeveritiesBadRequest(t *testing.T) {
	h := New(Options{})
	defer h.Close()
	rec := httptest.NewRecorder()
	h.ServeSSE(rec, httptest.NewRequest("GET", "/api/live?severities=3,banana", nil))
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "banana") {
		t.Errorf("%d %s", rec.Code, rec.Body)
	}
}

func TestRingAndReplay(t *testing.T) {
	h := New(Options{})
	for i := 0; i < 6000; i++ {
		h.Publish(msg("192.0.2.1", 6, fmt.Sprintf("m%d", i)))
	}
	if h.n != 5000 || string(h.ring[h.head].Raw) != "m1000" {
		t.Fatalf("ring n=%d oldest=%q", h.n, h.ring[h.head].Raw)
	}
	s := h.Subscribe(Filter{})
	if len(s.Replay) != 200 || string(s.Replay[0].Raw) != "m5800" || string(s.Replay[199].Raw) != "m5999" {
		t.Errorf("replay %d [%q..%q]", len(s.Replay), s.Replay[0].Raw, s.Replay[len(s.Replay)-1].Raw)
	}
	// Replay finds matches anywhere in the ring, oldest first.
	s2 := h.Subscribe(Filter{Q: "m10"}) // m1000..m1099: the oldest part of the ring
	if len(s2.Replay) != 100 || string(s2.Replay[0].Raw) != "m1000" || string(s2.Replay[len(s2.Replay)-1].Raw) != "m1099" {
		t.Errorf("filtered replay %d last %q", len(s2.Replay), s2.Replay[len(s2.Replay)-1].Raw)
	}

	// The byte cap evicts too.
	hb := New(Options{RingBytes: 1000})
	for i := 0; i < 50; i++ {
		hb.Publish(msg("192.0.2.1", 6, strings.Repeat("x", 100)))
	}
	if hb.n != 10 || hb.bytes != 1000 {
		t.Errorf("byte cap: n=%d bytes=%d", hb.n, hb.bytes)
	}
	// A message bigger than the cap is still kept, alone.
	hb.Publish(msg("192.0.2.1", 6, strings.Repeat("y", 5000)))
	if hb.n != 1 {
		t.Errorf("oversize: n=%d", hb.n)
	}
}

// TestSampling5000 publishes 5,000 msg/s for 5 s (fake clock) to one subscriber
// that keeps up: it gets at most Rate messages per second, spread over each second,
// and a "sampled" notice once a second.
func TestSampling5000(t *testing.T) {
	clk := newClock(t0)
	h := New(Options{Clock: clk.Now, Buffer: 10000})
	s := h.Subscribe(Filter{})
	var perSec []int
	var notices []Notice
	var spread []int // index (0..4999) within each second of the delivered messages, second 3
	for sec := 0; sec < 5; sec++ {
		for i := 0; i < 5000; i++ {
			h.Publish(msg("192.0.2.1", 6, fmt.Sprintf("s%d-%d", sec, i)))
			clk.Add(200 * time.Microsecond)
		}
		e, n := drain(s)
		perSec = append(perSec, len(e))
		notices = append(notices, n...)
		if sec == 3 {
			for _, x := range e {
				var a, b int
				fmt.Sscanf(string(x.Raw), "s%d-%d", &a, &b)
				spread = append(spread, b)
			}
		}
	}
	for i, n := range perSec {
		if n > 50 || n < 45 {
			t.Errorf("second %d: %d messages delivered, want about 50", i, n)
		}
	}
	// A notice at each window boundary after the first (the 5th window hasn't ended).
	if len(notices) != 4 {
		t.Fatalf("notices %+v", notices)
	}
	for _, n := range notices {
		if n.Rate < 4900 || n.Rate > 5100 || n.Shown > 50 || n.Shown < 45 {
			t.Errorf("notice %+v", n)
		}
	}
	if len(spread) == 0 || spread[0] > 200 || spread[len(spread)-1] < 4500 {
		t.Errorf("sample isn't spread over the second: first %d, last %d", spread[0], spread[len(spread)-1])
	}
	// Below the rate, nothing is sampled and no notice is sent.
	for i := 0; i < 40; i++ {
		clk.Add(25 * time.Millisecond)
		h.Publish(msg("192.0.2.1", 6, "slow"))
	}
	clk.Add(2 * time.Second)
	for i := 0; i < 40; i++ {
		clk.Add(25 * time.Millisecond)
		h.Publish(msg("192.0.2.1", 6, "slow"))
	}
	e, n := drain(s)
	// The first window after the burst ends the burst's sampling with one notice.
	if len(n) != 1 {
		t.Errorf("notices after slowing down: %+v", n)
	}
	if len(e) < 70 {
		t.Errorf("slow traffic: got %d of 80", len(e))
	}
}

// TestSamplingRealTime: 5,000 msg/s published in real time for 2 s, a subscriber
// reading over SSE gets about 50/s, and ingest isn't slowed.
func TestSamplingRealTime(t *testing.T) {
	if testing.Short() {
		t.Skip("real-time test")
	}
	h := New(Options{})
	srv := httptest.NewServer(http.HandlerFunc(h.ServeSSE))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events := make(chan sseEvent, 10000)
	go readSSE(resp.Body, events)

	const rate, dur = 5000, 2 * time.Second
	start := time.Now()
	var maxPublish, elapsed time.Duration
	sent := 0
	for time.Since(start) < dur {
		// elapsed is when the sends caught up, not after the sleep below: a sleep the
		// OS stretches on a busy runner isn't time Publish took.
		elapsed = time.Since(start)
		due := int(elapsed.Seconds() * rate)
		for ; sent < due; sent++ {
			p := time.Now()
			h.Publish(msg("192.0.2.1", 6, fmt.Sprintf("rt %d", sent)))
			if d := time.Since(p); d > maxPublish {
				maxPublish = d
			}
		}
		time.Sleep(time.Millisecond)
	}
	// Read until the stream has been quiet for 500 ms (a fixed sleep and a
	// non-blocking drain could stop before a slow reader caught up).
	var msgs, sampled int
	var last, best Notice
loop:
	for {
		select {
		case ev := <-events:
			switch ev.name {
			case "message":
				msgs++
			case "sampled":
				sampled++
				json.Unmarshal([]byte(ev.data), &last)
				if last.Rate > best.Rate {
					best = last
				}
			}
		case <-time.After(500 * time.Millisecond):
			break loop
		}
	}
	achieved := float64(sent) / elapsed.Seconds()
	t.Logf("published %d in %v (%.0f msg/s, max Publish %v); delivered %d messages, %d sampled notices, last %+v",
		sent, elapsed.Round(time.Millisecond), achieved, maxPublish, msgs, sampled, last)
	if achieved < 0.95*rate {
		t.Errorf("ingest slowed to %.0f msg/s", achieved)
	}
	if msgs > 160 || msgs < 60 {
		t.Errorf("delivered %d messages over %v, want about 50/s", msgs, elapsed)
	}
	// The highest notice, not the last: a window the publisher was stalled in
	// (the runner, not the hub) reports a lower matching rate.
	if sampled < 1 || best.Rate < 3000 {
		t.Errorf("sampled notices %d, highest %+v, last %+v", sampled, best, last)
	}
}

func TestSlowSubscriberDrops(t *testing.T) {
	h := New(Options{Buffer: 8, Rate: 1 << 30})
	slow := h.Subscribe(Filter{})
	fast := h.Subscribe(Filter{})
	var wg sync.WaitGroup
	var got atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range fast.C() {
			got.Add(1)
		}
	}()
	var publishing time.Duration
	for i := 0; i < 1000; i++ {
		p := time.Now()
		h.Publish(msg("192.0.2.1", 6, "x"))
		publishing += time.Since(p)
		if i%8 == 7 {
			// Let the fast reader catch up before its 8-slot buffer refills: a fixed
			// sleep lost whole batches when the OS didn't run the reader for a while.
			want := int64(i + 1)
			deadline := time.Now().Add(10 * time.Second)
			for got.Load() < want && time.Now().Before(deadline) {
				time.Sleep(50 * time.Microsecond)
			}
		}
	}
	if publishing > 2*time.Second {
		t.Errorf("Publish blocked: 1000 took %v", publishing)
	}
	if n := slow.Dropped(); n != 1000-8 {
		t.Errorf("slow dropped %d, want %d", n, 1000-8)
	}
	if st := h.Stats(); st.Dropped < 1000-8 || st.Published != 1000 || st.Subscribers != 2 {
		t.Errorf("stats %+v", st)
	}
	fast.Close()
	wg.Wait()
	t.Logf("fast subscriber got %d of 1000", got.Load())
	if got.Load() != 1000 {
		t.Errorf("fast subscriber got only %d", got.Load())
	}
	slow.Close()
	slow.Close()
	if h.Stats().Subscribers != 0 {
		t.Error("subscribers left")
	}
}

func TestRate(t *testing.T) {
	clk := newClock(t0.Truncate(time.Second))
	h := New(Options{Clock: clk.Now})
	if r := h.Rate(); r != 0 {
		t.Errorf("initial rate %v", r)
	}
	for sec := 0; sec < 8; sec++ {
		for i := 0; i < 100; i++ {
			h.Publish(msg("192.0.2.1", 6, "x"))
			clk.Add(10 * time.Millisecond)
		}
		if sec == 1 {
			if r := h.Rate(); r != 100 {
				t.Errorf("after 2 s: %v", r)
			}
		}
	}
	if r := h.Rate(); r != 100 {
		t.Errorf("rate %v", r)
	}
	clk.Add(10 * time.Second)
	if r := h.Rate(); r != 0 {
		t.Errorf("idle rate %v", r)
	}
}

func TestEntryJSON(t *testing.T) {
	e := Entry{Received: t0, DeviceID: "2001_db8__1", Severity: model.Unknown, Raw: []byte("a \"q\"\nb\xff")}
	b, _ := json.Marshal(e)
	want := `{"received":"2026-11-10T20:41:07.112Z","device_id":"2001_db8__1","severity":null,"raw":"a \"q\"\nb` + "\ufffd" + `"}`
	if string(b) != want {
		t.Errorf("\n got %s\nwant %s", b, want)
	}
	e.Severity = 0
	b, _ = json.Marshal(e)
	if !strings.Contains(string(b), `"severity":0`) {
		t.Errorf("severity 0: %s", b)
	}
}

type sseEvent struct{ name, data string }

// readSSE parses an event stream: "event:"/"data:" fields, blank line ends an
// event, ":" lines are comments (reported as name ":").
func readSSE(r interface{ Read([]byte) (int, error) }, out chan<- sseEvent) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var ev sseEvent
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if ev.name != "" || ev.data != "" {
				out <- ev
			}
			ev = sseEvent{}
		case strings.HasPrefix(line, ":"):
			out <- sseEvent{name: ":", data: strings.TrimSpace(line[1:])}
		case strings.HasPrefix(line, "event: "):
			ev.name = line[len("event: "):]
		case strings.HasPrefix(line, "data: "):
			ev.data = line[len("data: "):]
		}
	}
	close(out)
}

func next(t *testing.T, ch <-chan sseEvent, skipComments bool) sseEvent {
	t.Helper()
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("stream ended")
			}
			if skipComments && ev.name == ":" {
				continue
			}
			return ev
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for an event")
		}
	}
}

func TestServeSSE(t *testing.T) {
	clk := newClock(t0)
	h := New(Options{GroupOf: groupOf, Clock: clk.Now, Heartbeat: 100 * time.Millisecond})
	for i := 0; i < 300; i++ {
		h.Publish(msg("192.0.2.1", 6, fmt.Sprintf("hq %d", i)))
		h.Publish(msg("203.0.113.9", model.Unknown, fmt.Sprintf("other %d", i)))
	}
	srv := httptest.NewServer(http.HandlerFunc(h.ServeSSE))
	defer srv.Close()

	// Bad query: 400 with a JSON error.
	resp, err := http.Get(srv.URL + "?min_severity=9")
	if err != nil {
		t.Fatal(err)
	}
	var e struct{ Error string }
	json.NewDecoder(resp.Body).Decode(&e)
	resp.Body.Close()
	if resp.StatusCode != 400 || !strings.Contains(e.Error, "min_severity") {
		t.Errorf("bad query: %d %+v", resp.StatusCode, e)
	}

	resp, err = http.Get(srv.URL + "?group=HQ&min_severity=6&q=HQ")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Errorf("headers %v", resp.Header)
	}
	events := make(chan sseEvent, 1000)
	go readSSE(resp.Body, events)

	// Replay: the last 200 HQ messages, oldest first.
	for i := 100; i < 300; i++ {
		ev := next(t, events, true)
		if ev.name != "message" {
			t.Fatalf("replay %d: event %q", i, ev.name)
		}
		var m struct {
			Received string `json:"received"`
			DeviceID string `json:"device_id"`
			Severity *int   `json:"severity"`
			Raw      string `json:"raw"`
		}
		if err := json.Unmarshal([]byte(ev.data), &m); err != nil {
			t.Fatal(err)
		}
		if m.Raw != fmt.Sprintf("hq %d", i) || m.DeviceID != "192.0.2.1" || m.Severity == nil || *m.Severity != 6 ||
			m.Received != "2026-11-10T20:41:07.112Z" {
			t.Fatalf("replay %d: %+v", i, m)
		}
	}
	// Live: an unknown-severity message in the group passes min_severity.
	groups["203.0.113.50"] = "HQ"
	defer delete(groups, "203.0.113.50")
	h.Publish(msg("203.0.113.50", model.Unknown, "HQ unknown sev"))
	h.Publish(msg("192.0.2.1", 7, "HQ debug, filtered out"))
	h.Publish(msg("192.0.2.2", 3, "HQ error"))
	ev := next(t, events, true)
	if ev.name != "message" || !strings.Contains(ev.data, `"severity":null`) || !strings.Contains(ev.data, `"raw":"HQ unknown sev"`) {
		t.Errorf("live 1: %+v", ev)
	}
	ev = next(t, events, true)
	if !strings.Contains(ev.data, `"raw":"HQ error"`) || !strings.Contains(ev.data, `"device_id":"192.0.2.2"`) {
		t.Errorf("live 2: %+v", ev)
	}
	// Heartbeat comment.
	if ev := next(t, events, false); ev.name != ":" || ev.data != "ping" {
		t.Errorf("want a heartbeat, got %+v", ev)
	}
	// Sampling notice: 200 matches in one second, then the window ends.
	for i := 0; i < 200; i++ {
		h.Publish(msg("192.0.2.1", 6, "HQ burst"))
		clk.Add(5 * time.Millisecond)
	}
	h.Publish(msg("192.0.2.1", 6, "HQ after"))
	var got Notice
	for got.Rate == 0 {
		ev := next(t, events, true)
		if ev.name == "sampled" {
			if err := json.Unmarshal([]byte(ev.data), &got); err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(ev.data, `{"rate":`) || !strings.Contains(ev.data, `,"shown":`) {
				t.Errorf("sampled data %s", ev.data)
			}
		}
	}
	if got.Shown != 50 || got.Rate < 190 || got.Rate > 205 {
		t.Errorf("notice %+v", got)
	}

	// Client disconnect unsubscribes.
	resp.Body.Close()
	deadline := time.Now().Add(5 * time.Second)
	for h.Stats().Subscribers != 0 && time.Now().Before(deadline) {
		h.Publish(msg("192.0.2.1", 6, "HQ keepalive"))
		time.Sleep(10 * time.Millisecond)
	}
	if n := h.Stats().Subscribers; n != 0 {
		t.Errorf("%d subscribers after disconnect", n)
	}
}

func TestCloseEndsStreams(t *testing.T) {
	h := New(Options{})
	srv := httptest.NewServer(http.HandlerFunc(h.ServeSSE))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	events := make(chan sseEvent, 10)
	go readSSE(resp.Body, events)
	next(t, events, false) // ": live"
	h.Close()
	h.Publish(msg("192.0.2.1", 6, "after close"))
	select {
	case _, ok := <-events:
		for ok {
			_, ok = <-events
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream didn't end after Close")
	}
	if s := h.Subscribe(Filter{}); s.Replay != nil {
		t.Error("subscribe after close")
	} else if _, ok := <-s.C(); ok {
		t.Error("channel open after close")
	}
}

func TestContainsFoldASCII(t *testing.T) {
	for _, c := range []struct {
		s, q string
		want bool
	}{{"Hello World", "world", true}, {"HELLO", "hello", true}, {"hel", "hello", false}, {"abc", "", true}, {"xAbAbC", "abc", true}, {"ÄBC", "bc", true}} {
		if got := containsFoldASCII([]byte(c.s), []byte(c.q)); got != c.want {
			t.Errorf("%q in %q: %v", c.q, c.s, got)
		}
	}
}

func BenchmarkPublishOneSubscriber(b *testing.B) {
	h := New(Options{})
	s := h.Subscribe(Filter{Q: "needle"})
	go func() {
		for range s.C() {
		}
	}()
	m := msg("192.0.2.1", 6, "<134>Nov 10 20:41:07 edge-fw-01 conn opened tcp 192.0.2.10:443 -> 198.51.100.7:51515")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		h.Publish(m)
	}
}

func TestHiddenDevicesOnlyWhenNamed(t *testing.T) {
	var mu sync.Mutex
	hidden := map[string]bool{"192.0.2.9": true}
	h := New(Options{HiddenOf: func(id string) bool {
		mu.Lock()
		defer mu.Unlock()
		return hidden[id]
	}})
	defer h.Close()
	h.Publish(msg("192.0.2.9", 6, "hidden one"))
	h.Publish(msg("192.0.2.1", 6, "visible one"))
	all := h.Subscribe(Filter{})
	named := h.Subscribe(Filter{Devices: []string{"192.0.2.9"}})
	grouped := h.Subscribe(Filter{Ungrouped: true, Q: "e"})
	defer all.Close()
	defer named.Close()
	defer grouped.Close()
	raws := func(es []Entry) string {
		var out []string
		for _, e := range es {
			out = append(out, string(e.Raw))
		}
		return strings.Join(out, "|")
	}
	if got := raws(all.Replay); got != "visible one" {
		t.Errorf("default replay %q", got)
	}
	if got := raws(grouped.Replay); got != "visible one" {
		t.Errorf("ungrouped replay %q", got)
	}
	if got := raws(named.Replay); got != "hidden one" {
		t.Errorf("named replay %q", got)
	}
	h.Publish(msg("192.0.2.9", 6, "hidden two"))
	// Un-hiding takes effect for open subscriptions.
	mu.Lock()
	delete(hidden, "192.0.2.9")
	mu.Unlock()
	h.Publish(msg("192.0.2.9", 6, "unhidden three"))
	time.Sleep(10 * time.Millisecond)
	for name, c := range map[string]struct {
		s    *Subscription
		want string
	}{
		"default": {all, "unhidden three"},
		"named":   {named, "hidden two|unhidden three"},
		"grouped": {grouped, "unhidden three"},
	} {
		got, _ := drain(c.s)
		if raws(got) != c.want {
			t.Errorf("%s live: %q, want %q", name, raws(got), c.want)
		}
	}
}
