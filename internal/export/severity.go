package export

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
)

// The syslog severity filter in a bundle (SPEC §13.10 decision 86): what the
// device's filter keeps now, and how many syslog messages it left out in the
// window, so a bundle never hides that something wasn't stored.

// SeverityFilterSummary is a device's severity filter in a bundle's summary
// (manifest.json "severity_filter", README.txt's Filter line), for a bundle
// with syslog.
type SeverityFilterSummary struct {
	// MinSeverity is the filter in effect when the bundle was built (emerg …
	// debug; "debug" stores everything), "" when not known; Own says it's the
	// device's own setting rather than the default.
	MinSeverity string `json:"min_severity"`
	Own         bool   `json:"own"`
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

// severitySummary is a device's SeverityFilterSummary for the window.
func (b *builder) severitySummary(ctx context.Context, deviceID string, info Info) (*SeverityFilterSummary, error) {
	w, err := b.idx.FilteredIn(ctx, deviceID, info.From, info.To, b.now().Add(-index.StatsRetention))
	if err != nil {
		return nil, err
	}
	s := &SeverityFilterSummary{NotStored: w.Total(), NotStoredBySeverity: map[string]int64{}, From: w.From, To: w.To,
		ByHour: w.ByHour, Partial: w.Partial, Known: !w.NotKept}
	for i, n := range w.SevCounts {
		if n > 0 {
			s.NotStoredBySeverity[datatype.SeverityNames[i]] = n
		}
	}
	if b.severityFilter != nil {
		level, own := b.severityFilter(deviceID)
		if level >= 0 && level <= 7 {
			s.MinSeverity, s.Own = datatype.SeverityNames[level], own
		}
	}
	return s, nil
}

// readme is the README's Filter line, or "" when there's nothing to say: the
// filter stores everything and left nothing out in the window.
func (s *SeverityFilterSummary) readme(tf timeFmt) string {
	if s == nil || (s.NotStored == 0 && (s.MinSeverity == "" || s.MinSeverity == "debug")) {
		return ""
	}
	setting := ""
	switch {
	case s.MinSeverity == "debug":
		setting = "storing everything now"
	case s.MinSeverity != "":
		setting = "storing " + s.MinSeverity + " and above"
		if s.MinSeverity == "emerg" {
			setting = "storing emerg only"
		}
	}
	if setting != "" {
		if s.Own {
			setting += " (this device's setting)"
		} else {
			setting += " (the default)"
		}
	}
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
