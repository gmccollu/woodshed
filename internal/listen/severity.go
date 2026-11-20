package listen

import (
	"net/netip"
	"time"

	"github.com/gmccollu/woodshed/internal/syslog"
)

// The syslog severity filter (SPEC §13.10 decision 86): syslog messages less
// severe than a sender's minimum are left out at the listener, before they're
// copied, queued or parsed, and counted through Options.OnFiltered. Messages
// without a valid PRI are always kept. Traps and flows never pass here.

// SeverityFilter is which syslog messages to keep: severities 0 to Min (7,
// debug, keeps everything), or a sender's own minimum in ByDevice.
type SeverityFilter struct {
	Min      int
	ByDevice map[netip.Addr]int // keys unmapped, without a zone
}

// sevFilter is a SeverityFilter as the hot path reads it, immutable once
// stored (Server.sevf).
type sevFilter struct {
	min   int
	floor int // the lowest minimum of all: a severity at or below it is kept without a lookup
	by    map[netip.Addr]int
}

// SetSeverityFilter replaces the filter, from the next message on (open TCP
// connections included). A filter that keeps everything is removed, so the
// listeners don't even read the PRI.
func (s *Server) SetSeverityFilter(f SeverityFilter) {
	sf := &sevFilter{min: min(max(f.Min, 0), 7), by: map[netip.Addr]int{}}
	sf.floor = sf.min
	active := sf.min < 7
	for a, n := range f.ByDevice {
		n = min(max(n, 0), 7)
		sf.by[a.Unmap().WithZone("")] = n
		sf.floor = min(sf.floor, n)
		active = active || n < 7
	}
	if len(sf.by) == 0 {
		sf.by = nil
	}
	if !active {
		sf = nil
	}
	s.sevf.Store(sf)
}

// filteredOut applies the severity filter to one syslog message from from
// (unmapped): it reports whether the message is left out, and then counts it.
// A load and a nil check when no filter is set; otherwise the PRI is read in
// place, and the per-sender map is looked up only for a severity above the
// lowest minimum.
func (s *Server) filteredOut(raw []byte, from netip.Addr, now time.Time) bool {
	f := s.sevf.Load()
	if f == nil {
		return false
	}
	sev := syslog.Severity(raw)
	if sev <= f.floor { // model.Unknown (-1) too: always kept
		return false
	}
	keep := f.min
	if f.by != nil {
		k := from
		if k.Zone() != "" {
			k = k.WithZone("")
		}
		if n, ok := f.by[k]; ok {
			keep = n
		}
	}
	if sev <= keep {
		return false
	}
	s.filtered.Add(1)
	if s.opts.OnFiltered != nil {
		s.opts.OnFiltered(from, now, sev)
	}
	return true
}
