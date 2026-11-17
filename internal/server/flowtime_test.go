package server

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/flow"
)

// Flow records whose times are far from when they arrived (SPEC §13.10
// decision 70), end to end: every record is stored as sent; GET /api/flows
// counts them per exporter with the largest offset; the flow_time banner needs
// flow.TimeBannerMin of them in the last hour; a search at their own time
// finds them, one around their arrival doesn't.
func TestFlowTimeOffsetsBanner(t *testing.T) {
	r, _, ix := flowServer(t, nil)
	ctx := context.Background()
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", ix))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	const wrap = time.Duration(1<<32) * time.Millisecond // the uptime wrap: 49.7 days
	seq := uint32(0)
	send := func(n int, off time.Duration) {
		t.Helper()
		now := time.Now()
		b := flow.NewBuilder(flow.IPFIX)
		// sourceIPv4Address, flowStartMilliseconds, flowEndMilliseconds, octetDeltaCount
		b.Template(256, []flow.TemplateField{{ID: 8, Length: 4}, {ID: 152, Length: 8}, {ID: 153, Length: 8}, {ID: 1, Length: 8}})
		end := now.Add(off).UnixMilli()
		for i := 0; i < n; i++ {
			b.Data(256, flow.Values{}.Bytes([]byte{10, 40, 0, byte(i)}).U64(uint64(end-1000)).U64(uint64(end)).U64(100))
		}
		if _, err := conn.Write(b.Message(flow.Header{ExportTime: uint32(now.Unix()), Seq: seq, Domain: 1})); err != nil {
			t.Fatal(err)
		}
		seq += uint32(n)
	}
	exporter := func(want func(api.FlowExporter) bool) api.FlowExporter {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			var st api.FlowState
			r.do(t, "GET", "/api/flows", nil, &st)
			if len(st.Exporters) == 1 && want(st.Exporters[0]) {
				return st.Exporters[0]
			}
			if time.Now().After(deadline) {
				t.Fatalf("exporters %+v", st.Exporters)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	banner := func(now time.Time) string {
		for _, b := range r.srv.be.flowBanners(ctx, r.srv.be.config(), now, "linux") {
			if b.Kind == "flow_time" {
				return b.Text
			}
		}
		return ""
	}
	send(5, -time.Second)            // normal
	send(3, -30*time.Hour)           // behind, under the banner's count
	send(flow.TimeBannerMin-1, wrap) // ahead, one short
	e := exporter(func(e api.FlowExporter) bool { return e.Counts24h.Records == int64(8+flow.TimeBannerMin-1) })
	if o := e.TimeOffsets1h; o.Ahead != flow.TimeBannerMin-1 || o.Behind != 3 || o.MaxAheadMS < wrap.Milliseconds()-60_000 ||
		o.MaxBehindMS < 30*3600_000 || e.TimeOffsets24h != o {
		t.Fatalf("offsets 1h %+v 24h %+v", o, e.TimeOffsets24h)
	}
	if b := banner(time.Now()); b != "" {
		t.Fatalf("a banner under the threshold: %q", b)
	}
	send(1, wrap)
	exporter(func(e api.FlowExporter) bool { return e.TimeOffsets1h.Ahead == flow.TimeBannerMin })
	want := "Flow records from 127.0.0.1 have times up to 49.7 days ahead of when they arrived: the exporter's clock or uptime is probably wrong."
	if b := banner(time.Now()); !strings.HasPrefix(b, want) {
		t.Fatalf("banner %q, want %q…", b, want)
	}
	if b := banner(time.Now().Add(61 * time.Minute)); b != "" {
		t.Fatalf("a banner an hour on: %q", b)
	}
	// Every record is stored: 5 around their arrival, 3 a day and more
	// back, 10 at their own time 49.7 days ahead.
	now := time.Now()
	win := func(from, to time.Time) string {
		return "from=" + url.QueryEscape(from.UTC().Format(time.RFC3339)) + "&to=" + url.QueryEscape(to.UTC().Format(time.RFC3339))
	}
	waitFlows(t, r, win(now.Add(-10*time.Minute), now.Add(10*time.Minute)), 5)
	waitFlows(t, r, win(now.Add(-31*time.Hour), now.Add(-29*time.Hour)), 3)
	waitFlows(t, r, win(now.Add(wrap-time.Hour), now.Add(wrap+time.Hour)), int64(flow.TimeBannerMin))
}

func TestFlowTimeText(t *testing.T) {
	n := int64(flow.TimeBannerMin)
	both := flow.TimeOffsets{Ahead: n, Behind: n, MaxAheadMs: 2 * 3600_000, MaxBehindMs: 30 * 3600_000}
	behind := flow.TimeOffsets{Ahead: 2, Behind: n + 5, MaxAheadMs: 2 * 3600_000, MaxBehindMs: 72 * 3600_000}
	for _, c := range []struct {
		offs []flowTimeOff
		want string
	}{
		{[]flowTimeOff{{"10.1.0.1", both}}, "Flow records from 10.1.0.1 have times up to 2.0 h ahead of, or up to 30 h behind, when they arrived: " +
			"the exporter's clock or uptime is probably wrong."},
		{[]flowTimeOff{{"10.1.0.1", behind}}, "Flow records from 10.1.0.1 have times up to 3.0 days behind when they arrived: the exporter's"},
		{[]flowTimeOff{{"10.2.0.1", behind}, {"10.1.0.1", both}}, "Flow records from 10.1.0.1 (up to 2.0 h ahead, up to 30 h behind), " +
			"10.2.0.1 (up to 3.0 days behind) have times far from when they arrived: the exporters' clocks or uptimes are probably wrong."},
	} {
		got := flowTimeText(c.offs)
		if !strings.HasPrefix(got, c.want) || !strings.HasSuffix(got, " They're kept as sent, at their own times.") {
			t.Errorf("got %q\nwant %q…", got, c.want)
		}
	}
	var many []flowTimeOff
	for i := range 7 {
		many = append(many, flowTimeOff{fmt.Sprintf("10.9.0.%d", i), both})
	}
	if got := flowTimeText(many); !strings.Contains(got, "10.9.0.4 (up to 2.0 h ahead, up to 30 h behind) and 2 more have times far") {
		t.Errorf("many: %q", got)
	}
}
