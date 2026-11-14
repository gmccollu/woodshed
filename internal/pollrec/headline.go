package pollrec

import "time"

// Headline series (SPEC §12.3): the few per-device series poll_hourly keeps,
// computed per cycle from that cycle's sys and if records. The poller computes
// them as samples arrive; reindex computes them again from the files with the
// same code, so the two always agree.
const (
	SeriesInBps     = "in_bps"         // summed over interfaces
	SeriesOutBps    = "out_bps"        // summed over interfaces
	SeriesMaxIfIn   = "max_if_in_bps"  // the highest single interface
	SeriesMaxIfOut  = "max_if_out_bps" // the highest single interface
	SeriesErrorsD   = "errors_d"       // in + out error deltas, summed
	SeriesDiscardsD = "discards_d"     // in + out discard deltas, summed
	SeriesCPU       = "cpu"
	SeriesMemPct    = "mem_used_pct"
)

// HeadlineSeries lists them.
func HeadlineSeries() []string {
	return []string{SeriesInBps, SeriesOutBps, SeriesMaxIfIn, SeriesMaxIfOut, SeriesErrorsD, SeriesDiscardsD, SeriesCPU, SeriesMemPct}
}

// IsHeadline reports whether a series key is a headline series.
func IsHeadline(key string) bool {
	for _, s := range HeadlineSeries() {
		if s == key {
			return true
		}
	}
	return false
}

// Cycle accumulates one cycle's headline values.
type Cycle struct {
	Device string
	Cycle  uint64
	At     time.Time // the first record's received time
	vals   map[string]float64
}

// NewCycle starts a cycle's accumulator.
func NewCycle(device string, cycle uint64, at time.Time) *Cycle {
	return &Cycle{Device: device, Cycle: cycle, At: at, vals: map[string]float64{}}
}

func (c *Cycle) sum(key string, v float64) { c.vals[key] += v }

func (c *Cycle) max(key string, v float64) {
	if old, ok := c.vals[key]; !ok || v > old {
		c.vals[key] = v
	}
}

// Add takes one record of the cycle (other kinds are ignored).
func (c *Cycle) Add(r *Record) {
	switch r.Kind {
	case KindSys:
		if v, ok := r.Float("cpu"); ok {
			c.vals[SeriesCPU] = v
		}
		used, ok1 := r.Float("mem_used")
		total, ok2 := r.Float("mem_total")
		if ok1 && ok2 && total > 0 {
			c.vals[SeriesMemPct] = used * 100 / total
		}
	case KindIf:
		if v, ok := r.Float("in_bps"); ok {
			c.sum(SeriesInBps, v)
			c.max(SeriesMaxIfIn, v)
		}
		if v, ok := r.Float("out_bps"); ok {
			c.sum(SeriesOutBps, v)
			c.max(SeriesMaxIfOut, v)
		}
		for _, k := range []string{"in_err_d", "out_err_d"} {
			if v, ok := r.Float(k); ok {
				c.sum(SeriesErrorsD, v)
			}
		}
		for _, k := range []string{"in_disc_d", "out_disc_d"} {
			if v, ok := r.Float(k); ok {
				c.sum(SeriesDiscardsD, v)
			}
		}
	}
}

// Values are the cycle's headline values (only the measured ones).
func (c *Cycle) Values() map[string]float64 { return c.vals }

// Hourly is one headline series' aggregate over one hour.
type Hourly struct {
	Device string
	Series string
	Hour   time.Time // the hour's start, UTC
	Min    float64
	Max    float64
	Sum    float64
	Count  int64
}

// Rollup accumulates Hourly rows.
type Rollup struct {
	rows map[rollupKey]*Hourly
}

type rollupKey struct {
	device, series string
	hour           int64
}

// NewRollup starts an empty rollup.
func NewRollup() *Rollup { return &Rollup{rows: map[rollupKey]*Hourly{}} }

// AddCycle adds a cycle's values to the hour it started in.
func (ru *Rollup) AddCycle(c *Cycle) {
	hour := c.At.UTC().Truncate(time.Hour)
	for s, v := range c.vals {
		k := rollupKey{c.Device, s, hour.Unix()}
		h := ru.rows[k]
		if h == nil {
			h = &Hourly{Device: c.Device, Series: s, Hour: hour, Min: v, Max: v}
			ru.rows[k] = h
		}
		h.Min, h.Max = min(h.Min, v), max(h.Max, v)
		h.Sum += v
		h.Count++
	}
}

// Len is the number of rows held.
func (ru *Rollup) Len() int { return len(ru.rows) }

// Take returns the rows and empties the rollup.
func (ru *Rollup) Take() []Hourly {
	out := make([]Hourly, 0, len(ru.rows))
	for _, h := range ru.rows {
		out = append(out, *h)
	}
	clear(ru.rows)
	return out
}
