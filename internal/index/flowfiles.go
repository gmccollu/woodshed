package index

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gmccollu/woodshed/internal/flowseg"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Flow segments on disk (SPEC §13.2): logs/<device>/flows/*.wsf. The line
// listing (logfile.List) never sees them; this does, for Reindex, Reconcile
// and the store's recovery.

// FlowFile is a segment found on disk.
type FlowFile struct {
	DeviceID string
	Name     flowseg.Name
	Rel      string // '/'-separated, relative to the data dir
	Path     string
	Size     int64
}

// ListFlowFiles returns every segment under dataDir/logs, by device, then
// name.
func ListFlowFiles(dataDir string) ([]FlowFile, error) {
	root := filepath.Join(dataDir, logfile.LogsDir)
	devs, err := os.ReadDir(root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []FlowFile
	for _, dv := range devs {
		if !dv.IsDir() {
			continue
		}
		dir := filepath.Join(root, dv.Name(), logfile.FlowDir)
		ents, err := os.ReadDir(dir)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			if !e.Type().IsRegular() {
				continue
			}
			n, ok := flowseg.ParseName(e.Name())
			if !ok {
				continue
			}
			p := filepath.Join(dir, e.Name())
			info, err := e.Info()
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			out = append(out, FlowFile{DeviceID: dv.Name(), Name: n, Path: p, Size: info.Size(),
				Rel: logfile.LogsDir + "/" + dv.Name() + "/" + logfile.FlowDir + "/" + e.Name()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceID != out[j].DeviceID {
			return out[i].DeviceID < out[j].DeviceID
		}
		return out[i].Name.Less(out[j].Name)
	})
	return out, nil
}

// FlowRows are a segment's index rows: its files row, its flow_segments
// row and its flow_minute rows.
type FlowRows struct {
	File    File
	Segment FlowSegment
	Minutes []FlowMinute
}

// FlowRowsOf builds a segment's rows from its footer (or a writer's
// snapshot); closed says whether the segment is finished.
func FlowRowsOf(ff FlowFile, f *flowseg.Footer, size int64, closed bool) FlowRows {
	t := f.Totals
	fr := FlowRows{
		File: File{DeviceID: ff.DeviceID, Type: TypeFlow, Path: ff.Rel, Day: ff.Name.Day, Part: ff.Name.Hour*1000 + ff.Name.Part,
			FirstReceived: tm(f.MinReceived), LastReceived: tm(f.MaxReceived), Size: size, RawSize: size,
			Lines: t.Records + f.Raw, Compressed: closed},
		Segment: FlowSegment{Path: ff.Rel, DeviceID: ff.DeviceID, Start: f.MinStart, End: f.MaxEnd, Records: t.Records,
			Bytes: t.Bytes, Packets: t.Packets, BytesScaled: t.ScaledBytes, PacketsScaled: t.ScaledPackets,
			ScaledComplete: t.UnknownSampling == 0, Samplings: f.Samplings, Domains: f.Domains, Raw: f.Raw,
			NoTemplate: f.RawStatus[2], Malformed: f.RawStatus[3], Late: t.Status[1], Closed: closed},
	}
	fr.Minutes = FlowMinutesOf(ff.Rel, ff.DeviceID, f.Minutes)
	return fr
}

// FlowMinutesOf turns segment minutes into flow_minute rows.
func FlowMinutesOf(rel, deviceID string, ms []flowseg.Minute) []FlowMinute {
	out := make([]FlowMinute, 0, len(ms))
	for _, m := range ms {
		out = append(out, FlowMinute{Path: rel, DeviceID: deviceID, Minute: m.Minute, Records: m.Records, Bytes: m.Bytes,
			Packets: m.Packets, BytesScaled: m.ScaledBytes, PacketsScaled: m.ScaledPackets, Unknown: m.UnknownSampling > 0})
	}
	return out
}

// flowRebuilt is one segment's rows for rebuild.
type flowRebuilt struct {
	rows  FlowRows
	first time.Time
	last  time.Time
}

// ClosedFlow is a closed segment as the index has it: its files row and
// flow_segments row, both written when the segment closed (its footer on
// disk, the file's final size stat'ed after the writer closed it).
type ClosedFlow struct {
	Path     string // the files row's path
	DeviceID string
	Size     int64
	Records  int64
	// First and Last are the lowest and highest received times (the
	// footer's MinReceived and MaxReceived; zero when it had none).
	First, Last time.Time
	bytes       int64 // flow_segments.bytes (minutesMatch)
}

// Current reports whether ff on disk is still the segment these rows
// describe: same path, same device and same size. The rows say closed only
// once the footer is written and the writer has closed the file (the size is
// stat'ed after that), and a closed segment is never written again, so the
// rows and the segment's flow_minute rows already hold what its footer says
// and nothing needs reading. A segment a crash left open has no closed rows;
// one cut or replaced by hand almost always has another size; either is
// read, and so is one the store's recovery rewrote (Reconcile's recovered),
// whatever its size. A same-size change made outside Woodshed (a disk fault,
// an edit) isn't seen here, by design (no file is read for it): the segment is
// trusted until a query reads it, and `woodshed reindex` reads every footer
// (the user guide says so, under Rebuilding the index).
func (c ClosedFlow) Current(ff FlowFile) bool {
	return c.Path == ff.Rel && c.DeviceID == ff.DeviceID && c.Size == ff.Size && ff.Size > 0
}

// ClosedFlowSegments returns, by path, every flow segment whose files and
// flow_segments rows both say it closed.
func (d *DB) ClosedFlowSegments(ctx context.Context) (map[string]ClosedFlow, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT f.path, f.device_id, f.size, f.first_received, f.last_received, s.records, s.bytes
		FROM files f JOIN flow_segments s ON s.path = f.path
		WHERE f.type = ? AND f.compressed = 1 AND s.closed = 1`, TypeFlow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ClosedFlow{}
	for rows.Next() {
		var c ClosedFlow
		var first, last int64
		if err := rows.Scan(&c.Path, &c.DeviceID, &c.Size, &first, &last, &c.Records, &c.bytes); err != nil {
			return nil, err
		}
		c.First, c.Last = tm(first), tm(last)
		out[c.Path] = c
	}
	return out, rows.Err()
}

// FlowRowsVersion is the version of the rules that derive a segment's
// files, flow_segments and flow_minute rows from its footer (FlowRowsOf, and
// the store's rows as it writes). Bump it whenever they change: the first
// Reconcile under a different version (newer or older) reads every footer,
// and records its own in index_meta.
const FlowRowsVersion = 1

const metaFlowRowsVersion = "flow_rows_version"

// flowSegmentOrphans lists flow_segments paths without a files row.
func (d *DB) flowSegmentOrphans(ctx context.Context) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT path FROM flow_segments WHERE path NOT IN (SELECT path FROM files)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// minuteSums are a segment's flow_minute rows summed.
type minuteSums struct{ records, bytes float64 }

// flowMinuteSums sums flow_minute by path, from the covering index
// flow_minute_path_sums (no table rows are read).
func (d *DB) flowMinuteSums(ctx context.Context) (map[string]minuteSums, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT path, TOTAL(records), TOTAL(bytes) FROM flow_minute GROUP BY path`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]minuteSums{}
	for rows.Next() {
		var p string
		var m minuteSums
		if err := rows.Scan(&p, &m.records, &m.bytes); err != nil {
			return nil, err
		}
		out[p] = m
	}
	return out, rows.Err()
}

// exactSum bounds the values minuteSums compares: below it, TOTAL's float
// sums of the minutes are exact, and a footer's saturating sums haven't
// saturated.
const exactSum = 1 << 53

// minutesMatch reports whether a closed segment's flow_minute rows add up
// to its flow_segments row. Each record counts once, in its end minute, and
// its bytes are spread over its minutes with the remainder in the last one
// (flowseg's minute rule), so the sums equal the segment's records and bytes
// unless a value is too large to compare (then only what can be compared is).
func (c ClosedFlow) minutesMatch(m minuteSums) bool {
	if c.Records < exactSum && m.records != float64(c.Records) {
		return false
	}
	if c.bytes < exactSum && m.bytes != float64(c.bytes) {
		return false
	}
	return true
}

// FlowRowsStaleFile, in the data dir, says the flow rows may not match the
// segments in a way their sizes don't show: flow_minute is missing deltas
// the store queued but never applied (its queue overflowed while the index
// kept failing; the segments' own rows are whole, the latest one wins), or
// RedecodeFlows rewrote segments and the Reindex after it didn't finish. The
// next Reconcile (or Reindex) then reads every segment's footer and removes
// the file. Without it, Reconcile keeps a closed segment's rows without
// reading it (ClosedFlow.Current), so it can't see either.
const FlowRowsStaleFile = "index-flows.stale"

// MarkFlowRowsStale creates FlowRowsStaleFile in dataDir.
func MarkFlowRowsStale(dataDir string) error {
	f, err := os.OpenFile(filepath.Join(dataDir, FlowRowsStaleFile), os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func flowRowsStale(dataDir string) bool {
	_, err := os.Lstat(filepath.Join(dataDir, FlowRowsStaleFile))
	return err == nil
}

func clearFlowRowsStale(dataDir string) error {
	err := os.Remove(filepath.Join(dataDir, FlowRowsStaleFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// readFlowFiles reads the footers of the segments on disk, except those
// whose closed rows in known are still current (ClosedFlow.Current): they
// come back in kept, unread and uncounted. Reindex passes no known rows, so
// every segment is read. With fix set (Reindex: the server is stopped), a
// segment without a footer is recovered first; otherwise (Reconcile, after
// the store's own recovery) it's left out and counted.
func readFlowFiles(dataDir string, fix bool, known map[string]ClosedFlow, res *ReindexResult) (read []flowRebuilt, kept []ClosedFlow, err error) {
	files, err := ListFlowFiles(dataDir)
	if err != nil {
		return nil, nil, err
	}
	for _, ff := range files {
		if c, ok := known[ff.Rel]; ok && c.Current(ff) {
			kept = append(kept, c)
			continue
		}
		r, err := flowseg.Open(ff.Path)
		if errors.Is(err, flowseg.ErrNoFooter) && fix {
			rr, rerr := flowseg.Recover(ff.Path)
			if rerr != nil {
				res.Skipped = append(res.Skipped, ff.Rel)
				continue
			}
			res.FlowRecovered++
			res.TornBytes += rr.CutBytes
			r, err = flowseg.Open(ff.Path)
		}
		if err != nil {
			res.Skipped = append(res.Skipped, ff.Rel)
			continue
		}
		f := r.Footer()
		st, serr := os.Stat(ff.Path)
		size := ff.Size
		if serr == nil {
			size = st.Size()
		}
		rows := FlowRowsOf(ff, f, size, true)
		r.Close()
		res.Scanned++
		res.FlowRead++
		read = append(read, flowRebuilt{rows: rows, first: tm(f.MinReceived), last: tm(f.MaxReceived)})
	}
	return read, kept, nil
}
