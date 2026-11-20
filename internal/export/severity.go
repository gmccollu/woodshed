package export

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
)

// The syslog severity filter in a bundle (SPEC §13.10 decision 86): the
// settings in effect for the device over the window, from the filter's events,
// and how many syslog messages it left out, so a bundle never hides that
// something wasn't stored.

// SeverityFilterSummary is a device's severity filter in a bundle's summary
// (manifest.json "severity_filter", README.txt's Filter line), for a bundle
// with syslog.
type SeverityFilterSummary struct {
	// Settings are the filter's settings over the window, oldest first, each
	// for its span (together they cover From to To of the bundle).
	Settings []SeveritySetting `json:"settings"`
	// NotStored counts the syslog messages the filter left out in the
	// window, NotStoredBySeverity by severity name (only the ones with any),
	// from the index's per-minute (past 24 hours, hourly) counts for the
	// buckets that start in the span From to To. Known is false when the
	// whole window is older than the counts kept (7 days); Partial when only
	// its end is kept (counted from From); ByHour when hourly buckets widened
	// the span to whole hours.
	NotStored           int64            `json:"not_stored"`
	NotStoredBySeverity map[string]int64 `json:"not_stored_by_severity"`
	From                time.Time        `json:"from"`
	To                  time.Time        `json:"to"`
	ByHour              bool             `json:"by_hour"`
	Partial             bool             `json:"partial"`
	Known               bool             `json:"known"`
}

// SeveritySetting is the filter in effect for a device from From to To:
// MinSeverity (emerg … debug; "debug" stores everything), "" when no event
// records it (older than the events kept, or a 2.1.0-rc1 event that doesn't
// say what it changed from); Own says it's the device's own setting rather
// than the default.
type SeveritySetting struct {
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	MinSeverity string    `json:"min_severity"`
	Own         bool      `json:"own"`
}

// sevHistory is what the index records of the filter's settings: each change
// (its severity_filter events), the oldest event kept (none before it are
// known), and the setting the last run recorded (what holds after the last
// change, or always when nothing changed).
type sevHistory struct {
	defaults   []sevChange
	devices    map[string][]sevChange
	horizon    time.Time
	rec        index.SeverityFilterState
	hasHorizon bool
}

type sevChange struct {
	at time.Time
	config.SeverityEvent
}

func loadSevHistory(ctx context.Context, idx *index.DB) (*sevHistory, error) {
	h := &sevHistory{devices: map[string][]sevChange{}}
	evs, err := idx.EventsOfKind(ctx, index.KindSeverityFilter)
	if err != nil {
		return nil, err
	}
	for _, e := range evs {
		c, ok := config.ParseSeverityEvent(e.Text)
		switch {
		case !ok:
		case c.Default && e.DeviceID == "":
			h.defaults = append(h.defaults, sevChange{e.Time, c})
		case !c.Default && e.DeviceID != "":
			h.devices[e.DeviceID] = append(h.devices[e.DeviceID], sevChange{e.Time, c})
		}
	}
	if h.horizon, h.hasHorizon, err = idx.FirstEventTime(ctx); err != nil {
		return nil, err
	}
	rec, ok, err := idx.RecordedSeverityFilter(ctx)
	if err != nil {
		return nil, err
	}
	if !ok {
		// No 2.1 run recorded one: what ran stored everything.
		rec = index.SeverityFilterState{Default: config.SeverityDebug}
	}
	h.rec = rec
	return h, nil
}

// at is the setting a list of changes gives at t: the last change at or
// before it, else what the first one changed from, else (no change kept)
// fallback; ok is false when no event records it.
func (h *sevHistory) at(cs []sevChange, t time.Time, fallback int) (level int, ok bool) {
	i := sort.Search(len(cs), func(i int) bool { return cs[i].at.After(t) }) - 1
	if i >= 0 {
		return cs[i].Level, true
	}
	kept := !h.hasHorizon || !t.Before(h.horizon)
	if len(cs) > 0 {
		return cs[0].Was, cs[0].WasKnown && kept
	}
	return fallback, kept
}

// setting is the device's setting at t (level -1: not recorded).
func (h *sevHistory) setting(deviceID, addr string, t time.Time) (level int, own bool) {
	fallback := -1
	if l, ok := h.rec.ByDevice[addr]; ok {
		fallback = l
	}
	dev, ok := h.at(h.devices[deviceID], t, fallback)
	if !ok {
		return -1, false
	}
	if dev >= 0 {
		return dev, true
	}
	def, ok := h.at(h.defaults, t, h.rec.Default)
	if !ok {
		return -1, false
	}
	return def, false
}

// settings are the device's settings from from to to, a span per setting.
func (h *sevHistory) settings(deviceID, addr string, from, to time.Time) []SeveritySetting {
	edges := []time.Time{from}
	add := func(t time.Time) {
		if t.After(from) && t.Before(to) {
			edges = append(edges, t)
		}
	}
	for _, c := range h.defaults {
		add(c.at)
	}
	for _, c := range h.devices[deviceID] {
		add(c.at)
	}
	if h.hasHorizon {
		add(h.horizon)
	}
	slices.SortFunc(edges, func(a, b time.Time) int { return a.Compare(b) })
	var out []SeveritySetting
	for i, t := range edges {
		end := to
		if i+1 < len(edges) {
			end = edges[i+1]
		}
		if !end.After(t) {
			continue
		}
		level, own := h.setting(deviceID, addr, t)
		s := SeveritySetting{From: t.UTC(), To: end.UTC(), Own: own}
		if level >= 0 {
			s.MinSeverity = config.SeverityName(level)
		}
		if n := len(out); n > 0 && out[n-1].MinSeverity == s.MinSeverity && out[n-1].Own == s.Own {
			out[n-1].To = s.To
			continue
		}
		out = append(out, s)
	}
	return out
}

// sevAddr is the config's key for a device's own setting: its row IP's
// address without the zone, else its ID's.
func sevAddr(deviceID, ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		var ok bool
		if a, ok = model.ParseDeviceID(deviceID); !ok {
			return ""
		}
	}
	return a.Unmap().WithZone("").String()
}

// severitySummary is a device's SeverityFilterSummary for the window.
func (b *builder) severitySummary(ctx context.Context, h *sevHistory, deviceID, ip string, info Info) (*SeverityFilterSummary, error) {
	w, err := b.idx.FilteredIn(ctx, deviceID, info.From, info.To, b.now().Add(-index.StatsRetention))
	if err != nil {
		return nil, err
	}
	s := &SeverityFilterSummary{Settings: h.settings(deviceID, sevAddr(deviceID, ip), info.From, info.To),
		NotStored: w.Total(), NotStoredBySeverity: map[string]int64{}, From: w.From, To: w.To,
		ByHour: w.ByHour, Partial: w.Partial, Known: !w.NotKept}
	for i, n := range w.SevCounts {
		if n > 0 {
			s.NotStoredBySeverity[datatype.SeverityNames[i]] = n
		}
	}
	return s, nil
}

// readme is the README's Filter line, or "" when there's nothing to say: the
// filter stored everything and left nothing out in the window.
func (s *SeverityFilterSummary) readme(tf timeFmt) string {
	if s == nil {
		return ""
	}
	filtering, allKnown := false, true
	for _, st := range s.Settings {
		filtering = filtering || (st.MinSeverity != "" && st.MinSeverity != "debug")
		allKnown = allKnown && st.MinSeverity != ""
	}
	if s.NotStored == 0 && !filtering && (s.Known || allKnown) {
		return ""
	}
	setting := settingWords(s.Settings, tf)
	if !s.Known {
		return join(setting, "counts of messages it left out aren't kept this far back (7 days)")
	}
	if s.NotStored == 0 {
		return join(setting, "nothing was left out in this window")
	}
	what := s.counts()
	msgs := "messages"
	if s.NotStored == 1 {
		msgs = "message"
	}
	span := "in this window"
	switch {
	case s.Partial:
		span = "since " + tf.edge(s.From) + " (counts are kept 7 days)"
	case s.ByHour:
		span = fmt.Sprintf("from %s to %s (counted by the hour)", tf.edge(s.From), tf.edge(s.To))
	}
	return join(setting, fmt.Sprintf("%s %s not stored %s", what, msgs, span))
}

// settingWords says the settings over the window: "storing warning and above
// (the default) until 20:49:00, then notice and above (this device's
// setting)"; "setting before 20:49:00 not recorded, then storing …".
func settingWords(ss []SeveritySetting, tf timeFmt) string {
	var parts []string
	storing := false
	for i, st := range ss {
		var w string
		if st.MinSeverity == "" {
			w = "setting not recorded"
			if i+1 < len(ss) {
				w = "setting before " + tf.edge(st.To) + " not recorded"
			}
		} else {
			level, _ := config.ParseSeverity(st.MinSeverity)
			w = config.SeverityPhrase(level)
			if !storing {
				w, storing = "storing "+w, true
			}
			if st.Own {
				w += " (this device's setting)"
			} else {
				w += " (the default)"
			}
			if i+1 < len(ss) {
				w += " until " + tf.edge(st.To)
			}
		}
		if i > 0 {
			w = "then " + w
		}
		parts = append(parts, w)
	}
	return strings.Join(parts, ", ")
}

func join(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}

// counts names the left-out messages by severity, least severe first:
// "12,345 debug and 2 info".
func (s *SeverityFilterSummary) counts() string {
	var parts []string
	for i := 7; i >= 0; i-- {
		if n := s.NotStoredBySeverity[datatype.SeverityNames[i]]; n > 0 {
			parts = append(parts, datatype.Thousands(n)+" "+datatype.SeverityNames[i])
		}
	}
	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
	}
	return strings.Join(parts, ", ")
}
