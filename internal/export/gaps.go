package export

import (
	"sort"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
)

// Gap is a period inside an export's range when Woodshed couldn't have
// received messages (or one protocol of them).
type Gap struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Kind   string    `json:"kind"`  // not_running, listener_down or listener_stopped
	Proto  string    `json:"proto"` // "udp", "tcp", "tls" or "snmp" for listener gaps, else ""
	Detail string    `json:"detail"`
}

// Gap kinds.
const (
	GapNotRunning      = "not_running"      // the service wasn't running
	GapListenerDown    = "listener_down"    // a listener failed to bind and stayed down
	GapListenerStopped = "listener_stopped" // a listener was stopped while the service ran (turned off in Settings)
)

// minGap drops blips shorter than this: a listener restart on a settings
// change stops and starts it within milliseconds.
const minGap = time.Second

// GapsNote is how gaps are derived; it goes into manifest.json.
const GapsNote = "Gaps come from Woodshed's own event log. not_running: from the service's stop event (or, after " +
	"a crash, the last message or event recorded before the next start; the start of such a gap is approximate) to the " +
	"next start event, and before the first start on record. listener_down: from a bind error to that listener's " +
	"next start. listener_stopped: from a listener stop while the service kept running (a settings change) to its next " +
	"start. Gaps shorter than 1 s are left out. A device that simply sent nothing is not a gap."

// EventClass is what an event means for gaps.
type EventClass int

// Event classes. They are read from an event's Kind and Source only, never its
// wording: the service records its start and stop with index.SourceService,
// each listener its start, stop and bind errors with index.ListenerSource.
const (
	EventOther EventClass = iota
	EventServiceStart
	EventServiceStop
	EventListenerStart
	EventListenerStop
	EventBindError
)

// ClassifyEvent returns what e means for gap detection, and the listener's
// protocol for listener events.
func ClassifyEvent(e index.Event) (EventClass, string) {
	proto := ""
	switch e.Source {
	case index.SourceListenerUDP:
		proto = "udp"
	case index.SourceListenerTCP:
		proto = "tcp"
	case index.SourceListenerTLS:
		proto = "tls"
	case index.SourceListenerSNMP:
		proto = "snmp"
	case index.SourceService:
		switch e.Kind {
		case index.KindStart:
			return EventServiceStart, ""
		case index.KindStop:
			return EventServiceStop, ""
		}
		return EventOther, ""
	default:
		return EventOther, ""
	}
	switch e.Kind {
	case index.KindStart:
		return EventListenerStart, proto
	case index.KindStop:
		return EventListenerStop, proto
	case index.KindBind:
		return EventBindError, proto
	}
	return EventOther, proto
}

// ComputeGaps derives the gaps inside [from, to) from every event up to to
// (oldest first; events before from set the state at from). lastMessage
// returns the newest received time of any stored line before t, to date a
// crash. now caps the end: the future isn't a gap.
func ComputeGaps(events []index.Event, from, to, now time.Time, lastMessage func(t time.Time) time.Time) []Gap {
	if now.Before(to) {
		to = now
	}
	var gaps []Gap
	add := func(g Gap) {
		if g.From.Before(from) {
			g.From = from
		}
		if g.To.After(to) {
			g.To = to
		}
		if g.To.Sub(g.From) >= minGap {
			gaps = append(gaps, g)
		}
	}
	type open struct {
		since  time.Time
		kind   string
		detail string
	}
	listeners := map[string]*open{}
	closeListeners := func(at time.Time) {
		for proto, o := range listeners {
			add(Gap{From: o.since, To: at, Kind: o.kind, Proto: proto, Detail: o.detail})
			delete(listeners, proto)
		}
	}
	running := false
	everStarted := false
	var stoppedAt, lastEvent time.Time
	for _, e := range events {
		if !e.Time.Before(to) {
			break
		}
		cls, proto := ClassifyEvent(e)
		switch cls {
		case EventServiceStart:
			switch {
			case !everStarted:
				add(Gap{From: from, To: e.Time, Kind: GapNotRunning, Detail: "before the first start on record"})
			case running:
				// Started again without a stop: the previous run ended abruptly.
				since := lastEvent
				if lm := lastMessage(e.Time); lm.After(since) {
					since = lm
				}
				closeListeners(since)
				add(Gap{From: since, To: e.Time, Kind: GapNotRunning,
					Detail: "Woodshed stopped without a clean shutdown (crash or power loss); the start of this gap is approximate"})
			default:
				add(Gap{From: stoppedAt, To: e.Time, Kind: GapNotRunning, Detail: "Woodshed wasn't running"})
			}
			running, everStarted = true, true
		case EventServiceStop:
			closeListeners(e.Time)
			running, stoppedAt = false, e.Time
		case EventListenerStart:
			if o := listeners[proto]; o != nil {
				add(Gap{From: o.since, To: e.Time, Kind: o.kind, Proto: proto, Detail: o.detail})
				delete(listeners, proto)
			}
		case EventListenerStop:
			if running && listeners[proto] == nil {
				listeners[proto] = &open{since: e.Time, kind: GapListenerStopped, detail: strings.ToUpper(proto) + " listener stopped"}
			}
		case EventBindError:
			if listeners[proto] == nil || listeners[proto].kind != GapListenerDown {
				if o := listeners[proto]; o != nil {
					add(Gap{From: o.since, To: e.Time, Kind: o.kind, Proto: proto, Detail: o.detail})
				}
				listeners[proto] = &open{since: e.Time, kind: GapListenerDown, detail: "listener down: " + e.Text}
			}
		}
		lastEvent = e.Time
	}
	switch {
	case !everStarted:
		add(Gap{From: from, To: to, Kind: GapNotRunning, Detail: "no start on record"})
	case !running:
		add(Gap{From: stoppedAt, To: to, Kind: GapNotRunning, Detail: "Woodshed wasn't running"})
	}
	closeListeners(to)
	sort.SliceStable(gaps, func(i, j int) bool { return gaps[i].From.Before(gaps[j].From) })
	return gaps
}
