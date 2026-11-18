package hub

import (
	"bufio"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
)

// timeLayout matches the log files' received time (RFC 3339 UTC, milliseconds).
const timeLayout = "2006-01-02T15:04:05.000Z"

// MarshalJSON gives the API shape of a live-tail line (docs/api.md):
// {"received", "device_id", "severity" (null when unknown), "raw"}, plus
// "truncated", "incomplete", "frame_arrived" and "frame_length" only when set
// (2.0). received has millisecond precision, like the log files. Bytes of raw
// that aren't valid UTF-8 become U+FFFD.
func (e Entry) MarshalJSON() ([]byte, error) {
	var sev *int
	if e.Severity != model.Unknown {
		s := e.Severity
		sev = &s
	}
	return json.Marshal(struct {
		Received     string `json:"received"`
		DeviceID     string `json:"device_id"`
		Severity     *int   `json:"severity"`
		Raw          string `json:"raw"`
		Truncated    bool   `json:"truncated,omitempty"`
		Incomplete   bool   `json:"incomplete,omitempty"`
		FrameArrived int64  `json:"frame_arrived,omitempty"`
		FrameLength  int64  `json:"frame_length,omitempty"`
	}{e.Received.UTC().Format(timeLayout), e.DeviceID, sev, string(e.Raw), e.Truncated, e.Incomplete, e.FrameArrived, e.FrameLength})
}

// maxBatch bounds how many queued items are written before a flush.
const maxBatch = 64

// ServeSSE serves GET /api/live as text/event-stream (docs/api.md). It replays up
// to the last 200 matching messages, then streams new ones as "message" events and
// sampling notices as "sampled" events, with a comment line as a heartbeat every
// 15 s. It returns when the client goes away or the hub closes. A bad query gets
// 400 with {"error": "..."}.
//
// It clears the connection's write deadline (http.Server.WriteTimeout would
// otherwise cut the stream).
func (h *Hub) ServeSSE(w http.ResponseWriter, r *http.Request) {
	f, err := ParseFilter(r.URL.Query())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{}) // not every writer supports it; nothing to do then
	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "no-cache")
	hd.Set("X-Accel-Buffering", "no") // tell reverse proxies not to buffer
	w.WriteHeader(http.StatusOK)

	sub := h.Subscribe(f)
	defer sub.Close()

	bw := bufio.NewWriterSize(w, 16<<10)
	flush := func() bool {
		if bw.Flush() != nil {
			return false
		}
		return rc.Flush() == nil
	}
	bw.WriteString(": live\n\n")
	for i := range sub.Replay {
		writeEvent(bw, "message", sub.Replay[i])
	}
	if !flush() {
		return
	}

	hb := time.NewTicker(h.opts.Heartbeat)
	defer hb.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			bw.WriteString(": ping\n\n")
			if !flush() {
				return
			}
		case it, ok := <-sub.C():
			if !ok {
				return
			}
			writeItem(bw, it)
			// Write what else is queued before flushing.
			for n := 1; n < maxBatch; n++ {
				select {
				case it, ok = <-sub.C():
					if !ok {
						flush()
						return
					}
					writeItem(bw, it)
					continue
				default:
				}
				break
			}
			if !flush() {
				return
			}
		}
	}
}

func writeItem(bw *bufio.Writer, it Item) {
	if it.Entry != nil {
		writeEvent(bw, "message", *it.Entry)
	} else if it.Sampled != nil {
		writeEvent(bw, "sampled", *it.Sampled)
	}
}

func writeEvent(bw *bufio.Writer, name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	bw.WriteString("event: ")
	bw.WriteString(name)
	bw.WriteString("\ndata: ")
	bw.Write(b) // JSON escapes newlines, so the data is always one line
	bw.WriteString("\n\n")
}
