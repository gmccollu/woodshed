package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/poller"
	"github.com/gmccollu/woodshed/internal/search"
)

// The SNMP poller's routes (SPEC §12, docs/api.md "Poll targets", "Poll data
// for graphs" and "Polling state"). A v1/v2c community is write-only: GET
// says only community_set, and nothing else ever returns it.

// PollBackend is what the poll routes need from the service.
type PollBackend interface {
	PollTargets(ctx context.Context) ([]PollTarget, error)
	PollTarget(ctx context.Context, id string) (PollTarget, error)
	// CreatePollTarget: a *poller.ValidationError for a bad body,
	// ErrPollTargetExists or ErrPollTargetLimit.
	CreatePollTarget(ctx context.Context, in poller.Input) (PollTarget, error)
	// UpdatePollTarget: as Create, ErrNotFound, and ErrPollTargetChanged when
	// ifVersion > 0 and the target moved on.
	UpdatePollTarget(ctx context.Context, id string, in poller.Input, ifVersion int64) (PollTarget, error)
	DeletePollTarget(ctx context.Context, id string) error
	// TestPoll runs a test poll of a body (not saved) or of a stored target
	// (id). A *RetryAfterError beyond the rate limit.
	TestPoll(ctx context.Context, in poller.Input, id string) (poller.TestResult, error)
	PollSeries(ctx context.Context, q poller.SeriesQuery) (poller.SeriesResult, error)
	PollTimeline(ctx context.Context, q PollTimelineQuery) (poller.Timeline, error)
	// PollDevice is the device panel (ErrNotFound for a device no target polls).
	PollDevice(ctx context.Context, deviceID string, from, to time.Time) (poller.Panel, error)
	PollState(ctx context.Context) (poller.Summary, error)
}

// Poll target errors.
var (
	ErrPollTargetExists  = errors.New("a poll target for that address and port already exists")
	ErrPollTargetLimit   = errors.New("the poll target limit is reached")
	ErrPollTargetChanged = errors.New("the poll target changed since you loaded it")
)

// PollTarget is one target as the API shows it.
type PollTarget struct {
	ID string `json:"id"`
	poller.Settings
	CommunitySet bool         `json:"community_set"`
	State        poller.State `json:"state"`
	// Version makes the ETag.
	Version int64 `json:"-"`
}

// ETag is the target's entity tag.
func (t PollTarget) ETag() string { return fmt.Sprintf(`"%s.%d"`, t.ID, t.Version) }

// PollTimelineQuery is GET /api/poll/timeline's selection.
type PollTimelineQuery struct {
	Devices   []string
	Group     string
	Ungrouped bool
	From, To  time.Time
	Bucket    time.Duration
}

func (t *PollTarget) normalize() {
	if t.Presets == nil {
		t.Presets = []string{}
	}
	if t.Pinned == nil {
		t.Pinned = []poller.IfRef{}
	}
	if t.Custom == nil {
		t.Custom = []poller.Custom{}
	}
}

// pollRange reads from, to and bucket: to defaults to now, from to a day
// before it; the bucket defaults from the range as for the summary.
func pollRange(v url.Values, now time.Time) (from, to time.Time, bucket time.Duration, err error) {
	if from, err = parseTimeParam(v, "from"); err != nil {
		return
	}
	if to, err = parseTimeParam(v, "to"); err != nil {
		return
	}
	if to.IsZero() {
		to = now.UTC()
	}
	if from.IsZero() {
		from = to.Add(-24 * time.Hour)
	}
	if !from.Before(to) {
		err = errors.New("from must be before to")
		return
	}
	bucket = search.DefaultBucket(to.Sub(from))
	if s := v.Get("bucket"); s != "" {
		n, perr := strconv.Atoi(s)
		if perr != nil || n < 1 {
			err = fmt.Errorf("bucket must be a number of seconds, not %q", s)
			return
		}
		bucket = time.Duration(n) * time.Second
	}
	if qerr := search.CheckBucket(bucket, from.UnixMilli(), to.UnixMilli()); qerr != nil {
		err = qerr
	}
	return
}

func (s *Server) pollError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *poller.ValidationError
	var se *poller.SeriesError
	var ra *RetryAfterError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "Some fields need fixing.", Errors: nonNilMap(ve.Errors)})
	case errors.As(err, &se):
		writeError(w, http.StatusBadRequest, se.Msg)
	case errors.Is(err, ErrPollTargetExists):
		writeJSON(w, http.StatusConflict, errorBody{Error: "That address and port are already polled.",
			Errors: map[string]string{"address": "is already polled on that port"}})
	case errors.Is(err, ErrPollTargetLimit):
		writeError(w, http.StatusConflict, "The polled-device limit is reached (poll.max_targets in Settings).")
	case errors.Is(err, ErrPollTargetChanged):
		writeError(w, http.StatusConflict, ErrPollTargetChanged.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "No poll target with that id.")
	case errors.As(err, &ra):
		secs := max(int((ra.After+time.Second-1)/time.Second), 1)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, ra.Msg)
	default:
		s.requestOrBackendError(w, r, err, "")
	}
}

// pollRoutes adds the poller's routes to mux.
func (s *Server) pollRoutes(mux *http.ServeMux) {
	b := s.backend
	mux.Handle("/api/poll", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		st, err := b.PollState(r.Context())
		if err != nil {
			s.pollError(w, r, err)
			return
		}
		if st.Hour.Failures == nil {
			st.Hour.Failures = map[string]int64{}
		}
		writeJSON(w, http.StatusOK, st)
	}})
	mux.Handle("/api/poll/targets", methods{
		http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
			ts, err := b.PollTargets(r.Context())
			if err != nil {
				s.pollError(w, r, err)
				return
			}
			ts = slices.Clone(nonNil(ts))
			for i := range ts {
				ts[i].normalize()
			}
			writeJSON(w, http.StatusOK, ts)
		},
		http.MethodPost: func(w http.ResponseWriter, r *http.Request) {
			var in poller.Input
			if !decodeJSON(w, r, &in) {
				return
			}
			t, err := b.CreatePollTarget(r.Context(), in)
			if err != nil {
				s.pollError(w, r, err)
				return
			}
			t.normalize()
			w.Header().Set("ETag", t.ETag())
			writeJSON(w, http.StatusCreated, t)
		},
	})
	mux.Handle("/api/poll/targets/{id}", methods{
		http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
			t, err := b.PollTarget(r.Context(), r.PathValue("id"))
			if err != nil {
				s.pollError(w, r, err)
				return
			}
			t.normalize()
			w.Header().Set("ETag", t.ETag())
			writeJSON(w, http.StatusOK, t)
		},
		http.MethodPut: func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var in poller.Input
			if !decodeJSON(w, r, &in) {
				return
			}
			var ifVersion int64
			if h := r.Header.Get("If-Match"); h != "" && strings.TrimSpace(h) != "*" {
				cur, err := b.PollTarget(r.Context(), id)
				if err != nil {
					s.pollError(w, r, err)
					return
				}
				if !etagMatches(h, cur.ETag()) {
					writeError(w, http.StatusConflict, ErrPollTargetChanged.Error())
					return
				}
				ifVersion = cur.Version
			}
			t, err := b.UpdatePollTarget(r.Context(), id, in, ifVersion)
			if err != nil {
				s.pollError(w, r, err)
				return
			}
			t.normalize()
			w.Header().Set("ETag", t.ETag())
			writeJSON(w, http.StatusOK, t)
		},
		http.MethodDelete: func(w http.ResponseWriter, r *http.Request) {
			if err := b.DeletePollTarget(r.Context(), r.PathValue("id")); err != nil {
				s.pollError(w, r, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		},
	})
	mux.Handle("/api/poll/test", methods{http.MethodPost: func(w http.ResponseWriter, r *http.Request) {
		var in poller.Input
		if !decodeJSON(w, r, &in) {
			return
		}
		id := ""
		if in.ID != nil {
			id = *in.ID
		}
		res, err := b.TestPoll(r.Context(), in, id)
		if err != nil {
			s.pollError(w, r, err)
			return
		}
		if res.Steps == nil {
			res.Steps = []poller.TestStep{}
		}
		writeJSON(w, http.StatusOK, res)
	}})
	mux.Handle("/api/poll/series", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		from, to, bucket, err := pollRange(v, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		dev := strings.TrimSpace(v.Get("device"))
		if dev == "" {
			writeError(w, http.StatusBadRequest, "device is required")
			return
		}
		keys := splitList(v.Get("series"))
		if len(keys) == 0 {
			keys = []string{"in_bps", "out_bps", "cpu"}
		}
		res, err := b.PollSeries(r.Context(), poller.SeriesQuery{Device: dev, From: from, To: to, Bucket: bucket, Keys: keys,
			Cursor: v.Get("cursor")})
		if err != nil {
			s.pollError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}})
	mux.Handle("/api/poll/timeline", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		from, to, bucket, err := pollRange(v, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ungrouped, err := parseBoolParam(v, "ungrouped")
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := b.PollTimeline(r.Context(), PollTimelineQuery{Devices: splitList(v.Get("devices")), Group: v.Get("group"),
			Ungrouped: ungrouped, From: from, To: to, Bucket: bucket})
		if err != nil {
			s.pollError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}})
	mux.Handle("/api/poll/device/{id}", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		from, to, _, err := pollRange(v, time.Now())
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		res, err := b.PollDevice(r.Context(), r.PathValue("id"), from, to)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				writeError(w, http.StatusNotFound, "No polled device with that id.")
				return
			}
			s.pollError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
	}})
}
