package search

import (
	"context"
	"sort"
	"time"
)

// Hit is one matching line from a Scanner.
type Hit struct {
	Received time.Time
	FileID   int64
	Day      string // the day of the file it's in (YYYY-MM-DD, UTC)
	Offset   int64
	Line     []byte // the stored line, without '\n'
	Escaped  []byte // the escaped raw message, within Line
}

// Scanner reads one device's matching lines oldest first (file order), with no
// time budget. The export builder uses it, so an export holds exactly what a
// search with the same filter shows.
type Scanner struct {
	r *run
	s *stream
}

// NewScanner prepares a scan of one device over f.
func (e *Engine) NewScanner(ctx context.Context, device string, f Filter) (*Scanner, error) {
	c, err := e.compile(f)
	if err != nil {
		return nil, err
	}
	r := &run{e: e, ctx: ctx, now: e.now(), m: c.m, ex: c.ex, dt: c.dt, tf: c.tf, need: 1, files: map[int64]struct{}{}, ringBytes: e.ringBytes}
	if r.fromMs, r.toMs, err = e.resolveRange(f); err != nil {
		return nil, err
	}
	files, err := e.filesByDevice(ctx, f.Type, []string{device}, r.fromMs, r.toMs)
	if err != nil {
		return nil, err
	}
	s := newStream(device, files[device])
	if c.none {
		s.done = true
	}
	return &Scanner{r: r, s: s}, nil
}

// Next returns the next matching line; ok is false at the end (check Err). The
// Hit's slices are valid until the next call.
func (sc *Scanner) Next() (Hit, bool) {
	for {
		if h := sc.s.head(); h != nil {
			x := sc.s.pop()
			return Hit{Received: time.UnixMilli(x.ms).UTC(), FileID: x.file.ID, Day: x.file.Day, Offset: x.off,
				Line: x.line, Escaped: x.esc}, true
		}
		if sc.s.done || sc.r.expired() {
			return Hit{}, false
		}
		sc.s.step(sc.r)
	}
}

// Err is the context's error if the scan stopped because of it.
func (sc *Scanner) Err() error { return sc.r.err }

// Scanned is the number of uncompressed bytes read so far.
func (sc *Scanner) Scanned() int64 { return sc.r.scanned }

// Files is the number of files read so far.
func (sc *Scanner) Files() int { return len(sc.r.files) }

// Close releases the open file.
func (sc *Scanner) Close() { sc.s.close() }

// EstimatePart is the upper bound for one device-day.
type EstimatePart struct {
	Device, Day  string
	Lines, Bytes int64
	Files        int
}

// Estimate is an upper bound on what a scan of devices over [from, to) reads,
// from the index alone (file rows and checkpoints), without opening any file.
// Bytes counts the stored lines, so it bounds an export's uncompressed output
// too (unescaping only shrinks a line).
type Estimate struct {
	Lines, Bytes int64
	Files        int
	Parts        []EstimatePart // by device, then day
}

// Estimate bounds a scan of devices over f's time range.
func (e *Engine) Estimate(ctx context.Context, devices []string, f Filter) (Estimate, error) {
	var est Estimate
	fromMs, toMs, err := e.resolveRange(f)
	if err != nil {
		return est, err
	}
	if _, _, none, err := typeFilter(f); err != nil || none {
		return est, err
	}
	files, err := e.filesByDevice(ctx, f.Type, devices, fromMs, toMs)
	if err != nil {
		return est, err
	}
	type dd struct{ dev, day string }
	parts := map[dd]*EstimatePart{}
	for dev, fs := range files {
		for _, fi := range fs {
			cps, err := e.idx.Checkpoints(ctx, fi.ID)
			if err != nil {
				return est, err
			}
			s, en := regionStart(cps, fromMs), regionEnd(cps, toMs)
			var sLine, eLine int64 = 0, fi.Lines
			eOff := max(fi.RawSize, s)
			for _, c := range cps {
				if c.Offset == s {
					sLine = c.Line
				}
				if en >= 0 && c.Offset == en {
					eLine, eOff = c.Line, c.Offset
				}
			}
			if eOff <= s && fi.LastReceived.UnixMilli() < fromMs {
				continue // only widened in for the index's lag; nothing in range
			}
			p := parts[dd{dev, fi.Day}]
			if p == nil {
				p = &EstimatePart{Device: dev, Day: fi.Day}
				parts[dd{dev, fi.Day}] = p
			}
			p.Lines += max(eLine-sLine, 0)
			p.Bytes += max(eOff-s, 0)
			p.Files++
		}
	}
	for _, p := range parts {
		est.Parts = append(est.Parts, *p)
		est.Lines += p.Lines
		est.Bytes += p.Bytes
		est.Files += p.Files
	}
	sort.Slice(est.Parts, func(i, j int) bool {
		a, b := est.Parts[i], est.Parts[j]
		return a.Device < b.Device || (a.Device == b.Device && a.Day < b.Day)
	})
	return est, nil
}

// CheckFilter validates f (its regular expressions and time range) without
// reading anything. It returns a *QueryError for a bad filter.
func (e *Engine) CheckFilter(f Filter) error {
	if _, err := e.compile(f); err != nil {
		return err
	}
	_, _, err := e.resolveRange(f)
	return err
}
