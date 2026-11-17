package flow

import "time"

// The flow-time check (SPEC §13.10 decision 70): a record whose flow time is
// far from when its datagram arrived is kept exactly as decoded, and counted
// per exporter, so a broken exporter clock or uptime, or a decoder bug of
// ours, shows instead of hiding the records at a time no search looks at.
const (
	// TimeAheadLimit: a record ends this much after it arrived. A flow can't
	// end after it was exported, so only a clock difference explains it, and
	// a header clock up to ClockSkewLimit off is accepted as is: anything
	// within it is left to that rule.
	TimeAheadLimit = time.Hour
	// TimeBehindLimit: a record ends this much before it arrived. An
	// exporter sends a flow within its inactive or active timeout of its
	// last packet (seconds to an hour), so a day can't be a normal export,
	// whatever the timeouts. The start isn't checked behind: a long-lived
	// connection can start days earlier.
	TimeBehindLimit = 24 * time.Hour
	// TimeBannerMin: the flow_time banner needs this many such records from
	// one exporter in the last hour. A stray record (a cache entry left over
	// from a clock step) isn't worth a banner; a broken clock or uptime
	// affects every record, so even a record a minute passes it.
	TimeBannerMin = 10
)

// TimeOffset reports how far a record's flow time is from its received
// time, past the limits: ahead is how much its end is after it arrived (more
// than TimeAheadLimit), behind how much its end is before (more than
// TimeBehindLimit), in ms; both 0 for a normal record. Records on received
// time (TimeReceived) are never off.
func TimeOffset(r *Record) (ahead, behind int64) {
	if r.TimeSource == TimeReceived {
		return 0, 0
	}
	switch d := r.End - r.Received; {
	case d > TimeAheadLimit.Milliseconds():
		return d, 0
	case -d > TimeBehindLimit.Milliseconds():
		return 0, -d
	}
	return 0, 0
}

// TimeOffsets counts records with times far from their arrival (TimeOffset)
// and the largest offset seen each way, in ms.
type TimeOffsets struct {
	Ahead       int64 `json:"ahead"`
	Behind      int64 `json:"behind"`
	MaxAheadMs  int64 `json:"max_ahead_ms"`
	MaxBehindMs int64 `json:"max_behind_ms"`
}

// Add counts one record's offsets (TimeOffset's results).
func (o *TimeOffsets) Add(ahead, behind int64) {
	if ahead > 0 {
		o.Ahead++
		o.MaxAheadMs = max(o.MaxAheadMs, ahead)
	}
	if behind > 0 {
		o.Behind++
		o.MaxBehindMs = max(o.MaxBehindMs, behind)
	}
}

func (o *TimeOffsets) merge(p TimeOffsets) {
	o.Ahead += p.Ahead
	o.Behind += p.Behind
	o.MaxAheadMs = max(o.MaxAheadMs, p.MaxAheadMs)
	o.MaxBehindMs = max(o.MaxBehindMs, p.MaxBehindMs)
}

// Any reports whether any record was off.
func (o TimeOffsets) Any() bool { return o.Ahead > 0 || o.Behind > 0 }

// offSlot is one time slot's offsets: an hour or 5 minutes.
type offSlot struct {
	at int64 // the slot's number (unix hour, or unix 5-minute)
	o  TimeOffsets
}

// offState is an exporter's offsets by hour for 24 hours and by 5 minutes
// for the last hour. It's allocated on the exporter's first off record, so a
// normal exporter pays a pointer.
type offState struct {
	hours [24]offSlot
	fives [12]offSlot
}

const fiveMinMs = 5 * 60 * 1000

func (s *offState) add(at int64, o TimeOffsets) {
	h, f := at/3600000, at/fiveMinMs
	if sl := &s.hours[h%24]; sl.at == h {
		sl.o.merge(o)
	} else {
		*sl = offSlot{at: h, o: o}
	}
	if sl := &s.fives[f%12]; sl.at == f {
		sl.o.merge(o)
	} else {
		*sl = offSlot{at: f, o: o}
	}
}

// sums are the last 24 hours' and the last hour's offsets at now (unix ms).
func (s *offState) sums(now int64) (day, hour TimeOffsets) {
	h, f := now/3600000, now/fiveMinMs
	for _, sl := range s.hours {
		if sl.at > h-24 && sl.at <= h {
			day.merge(sl.o)
		}
	}
	for _, sl := range s.fives {
		if sl.at > f-12 && sl.at <= f {
			hour.merge(sl.o)
		}
	}
	return day, hour
}

// countOff adds a datagram's offsets at its received time (unix ms).
func (e *exporter) countOff(at int64, o TimeOffsets) {
	e.cmu.Lock()
	if e.off == nil {
		e.off = &offState{}
	}
	e.off.add(at, o)
	e.cmu.Unlock()
}

// checkTime counts a record about to be emitted whose flow time is far from
// its arrival. The record isn't changed.
func (ds *decState) checkTime(r *Record) {
	if ds.c.fileMode {
		return
	}
	if a, b := TimeOffset(r); a > 0 || b > 0 {
		ds.off.Add(a, b)
	}
}
