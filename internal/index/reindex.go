package index

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// ReindexResult describes a Reindex or Reconcile run.
type ReindexResult struct {
	Files     []File   // every indexed file afterwards, by device and FirstReceived
	Scanned   int      // files read from disk (in full, from where the index left off, or a flow segment's footer)
	Removed   int      // rows dropped because their file is gone
	Devices   int      // devices with files on disk
	TornBytes int64    // bytes in partial last lines, not indexed
	BadLines  int64    // lines that didn't parse
	Skipped   []string // files not indexed (for example a .log.gz whose .log is still there)
	// PollRollups is the poll_hourly rows Reindex rebuilt.
	PollRollups int
	// FlowRecovered is the flow segments Reindex closed (no footer: a crash).
	FlowRecovered int
}

// Reindex rebuilds the files and checkpoints tables from the log files under dataDir,
// and each device's first seen, last heard and totals. Devices keep their name, group
// and hidden flag; first seen keeps the earlier of the old and rebuilt value, and the
// totals keep the larger, so files deleted by retention don't shrink a device's
// history. Stats, events and the storage history are left alone.
//
// The store must not be running on dataDir (use `woodshed reindex` with the service
// stopped). Files are only read, never changed.
//
// It also rebuilds the poll rollups (poll_hourly) from the poll files; the
// poll targets are user data and stay (SPEC §12.3).
func (d *DB) Reindex(ctx context.Context, dataDir string) (ReindexResult, error) {
	res, err := d.rebuild(ctx, dataDir, true, nil)
	if err != nil {
		return res, err
	}
	n, err := d.RebuildPollHourly(ctx, dataDir)
	res.PollRollups = n
	return res, err
}

// Reconcile brings the index in line with the files on disk cheaply: rows for files
// whose size still matches are kept, an uncompressed file that only grew is scanned
// from where its row ends, other changed or new files are scanned in full, and rows
// for missing files are dropped. A closed flow segment whose rows still match the
// file is kept without being opened; other flow segments are read from their
// footers. The store runs it at startup, after crash repair, and names the
// segments that repair recovered (their '/'-separated paths relative to
// dataDir, as FlowFile.Rel): they're read whatever their rows say.
func (d *DB) Reconcile(ctx context.Context, dataDir string, recovered ...string) (ReindexResult, error) {
	return d.rebuild(ctx, dataDir, false, recovered)
}

type rebuilt struct {
	f          File
	cps        []Checkpoint
	replaceCPs bool
	changed    bool
	sum        logfile.Summary
	scanned    bool
}

func (d *DB) rebuild(ctx context.Context, dataDir string, full bool, recovered []string) (ReindexResult, error) {
	var res ReindexResult
	entries, _, err := logfile.List(dataDir)
	if err != nil {
		return res, err
	}
	rows, err := d.Files(ctx, "")
	if err != nil {
		return res, err
	}
	existing := make(map[string]File, len(rows))
	for _, f := range rows {
		existing[f.Path] = f
	}
	onDisk := make(map[string]bool, len(entries))
	for _, e := range entries {
		onDisk[e.Rel] = true
	}
	// Flow segments (SPEC §13.2): Reindex rebuilds every row from its footer
	// (no records are read). Reconcile keeps a closed segment's rows when the
	// file still matches them (ClosedFlow.Current) without opening it, and
	// reads only new, changed, unclosed or just-recovered segments, or every
	// one while the rows are marked stale (FlowRowsStaleFile).
	rereadFlows := full || flowRowsStale(dataDir)
	var known map[string]ClosedFlow
	if !rereadFlows {
		if known, err = d.ClosedFlowSegments(ctx); err != nil {
			return res, err
		}
		for _, rel := range recovered {
			delete(known, rel)
		}
	}
	flows, keptFlows, err := readFlowFiles(dataDir, full, known, &res)
	if err != nil {
		return res, err
	}

	var out []rebuilt
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if e.Name.Compressed {
			plain := e.Name
			plain.Compressed = false
			if onDisk[logfile.RelPathType(e.Type, e.DeviceID, plain)] {
				// A compression that didn't finish deleting its original: the .log is
				// authoritative until the store verifies the .gz.
				res.Skipped = append(res.Skipped, e.Rel)
				continue
			}
		}
		base := File{DeviceID: e.DeviceID, Type: e.Type, Path: e.Rel, Day: e.Name.Day, Part: e.Name.Part,
			Size: e.Size, Compressed: e.Name.Compressed}
		row, ok := existing[e.Rel]
		if !full && ok && row.Size == e.Size && row.Compressed == e.Name.Compressed && fileType(row.Type) == fileType(e.Type) {
			out = append(out, rebuilt{f: row})
			continue
		}
		var r rebuilt
		done := false
		if !full && ok && !e.Name.Compressed && row.Size > 0 && row.Lines > 0 && e.Size > row.Size {
			r, done, err = resumeScan(ctx, d, e, base, row)
			if err != nil {
				return res, err
			}
		}
		if !done {
			sum, err := logfile.ScanFile(e.Path)
			if err != nil {
				return res, err
			}
			base.FirstReceived, base.LastReceived = sum.First, sum.Last
			base.Lines, base.RawSize = sum.Lines, sum.RawSize
			r = rebuilt{f: base, cps: sum.Checkpoints, replaceCPs: true, sum: sum}
		}
		r.changed, r.scanned = true, true
		res.Scanned++
		res.TornBytes += r.sum.TornBytes
		res.BadLines += r.sum.BadLines
		if r.f.Lines == 0 {
			res.Skipped = append(res.Skipped, e.Rel)
			continue
		}
		out = append(out, r)
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	st := &stmts{tx: tx, ctx: ctx}
	defer st.close()

	if full {
		for _, q := range []string{`DELETE FROM files`, `DELETE FROM flow_segments`, `DELETE FROM flow_minute`} {
			if _, err := st.exec(q); err != nil {
				return res, err
			}
		}
	} else {
		kept := make(map[string]bool, len(out)+len(flows)+len(keptFlows))
		for _, r := range out {
			kept[r.f.Path] = true
		}
		for _, fr := range flows {
			kept[fr.rows.File.Path] = true
		}
		for _, c := range keptFlows {
			kept[c.Path] = true
		}
		for _, f := range rows {
			if !kept[f.Path] {
				if _, err := st.exec(`DELETE FROM files WHERE id = ?`, f.ID); err != nil {
					return res, err
				}
				if fileType(f.Type) == TypeFlow {
					if err := st.deleteFlowRows(f.Path); err != nil {
						return res, err
					}
				}
				res.Removed++
			}
		}
	}
	for i := range flows {
		fr := &flows[i].rows
		if _, err := st.upsertFile(fr.File); err != nil {
			return res, err
		}
		if err := st.replaceFlowRows(&fr.Segment, fr.Minutes); err != nil {
			return res, err
		}
	}

	type devAgg struct {
		ip          string
		first, last time.Time
		msgs, bytes int64
	}
	devs := map[string]*devAgg{}
	var devOrder []string
	for i := range out {
		r := &out[i]
		if r.changed {
			id, err := st.upsertFile(r.f)
			if err != nil {
				return res, err
			}
			if r.replaceCPs && !full {
				if _, err := st.exec(`DELETE FROM checkpoints WHERE file_id = ?`, id); err != nil {
					return res, err
				}
			}
			if err := st.checkpoints(id, r.cps); err != nil {
				return res, err
			}
			r.f.ID = id
		}
		a := devs[r.f.DeviceID]
		if a == nil {
			a = &devAgg{}
			devs[r.f.DeviceID] = a
			devOrder = append(devOrder, r.f.DeviceID)
		}
		if a.ip == "" && r.sum.Sender.IsValid() {
			a.ip = r.sum.Sender.Unmap().String()
		}
		if !r.f.FirstReceived.IsZero() && (a.first.IsZero() || r.f.FirstReceived.Before(a.first)) {
			a.first = r.f.FirstReceived
		}
		if r.f.LastReceived.After(a.last) {
			a.last = r.f.LastReceived
		}
		if r.scanned && r.replaceCPs {
			a.msgs += r.sum.Lines - r.sum.BadLines
			a.bytes += r.sum.MsgBytes
		} else {
			a.msgs += r.f.Lines
		}
	}
	addFlow := func(id string, first, last time.Time, records int64) {
		a := devs[id]
		if a == nil {
			a = &devAgg{}
			devs[id] = a
			devOrder = append(devOrder, id)
		}
		if !first.IsZero() && (a.first.IsZero() || first.Before(a.first)) {
			a.first = first
		}
		if last.After(a.last) {
			a.last = last
		}
		a.msgs += records
	}
	for _, fr := range flows {
		addFlow(fr.rows.File.DeviceID, fr.first, fr.last, fr.rows.Segment.Records)
	}
	for _, c := range keptFlows {
		addFlow(c.DeviceID, c.First, c.Last, c.Records)
	}
	for _, id := range devOrder {
		a := devs[id]
		ip := a.ip
		if ip == "" {
			ip = ipFromDeviceID(id)
		}
		var q string
		if full {
			q = `INSERT INTO devices (id, ip, first_seen, last_heard, total_msgs, total_bytes) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen),
				last_heard = max(last_heard, excluded.last_heard),
				total_msgs = max(total_msgs, excluded.total_msgs), total_bytes = max(total_bytes, excluded.total_bytes)`
		} else {
			q = `INSERT INTO devices (id, ip, first_seen, last_heard, total_msgs, total_bytes) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET first_seen = min(first_seen, excluded.first_seen),
				last_heard = max(last_heard, excluded.last_heard)`
		}
		if _, err := st.exec(q, id, ip, ms(a.first), ms(a.last), a.msgs, a.bytes); err != nil {
			return res, err
		}
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}
	if rereadFlows {
		// Every footer is in flow_minute again.
		if err := clearFlowRowsStale(dataDir); err != nil {
			return res, err
		}
	}
	res.Devices = len(devOrder)
	res.Files, err = d.Files(ctx, "")
	return res, err
}

// resumeScan scans an uncompressed file that grew, from where its row ends. It
// reports false when the row can't be trusted as a prefix of the file.
func resumeScan(ctx context.Context, d *DB, e logfile.Entry, base File, row File) (rebuilt, bool, error) {
	last, ok, err := d.LastCheckpoint(ctx, row.ID)
	if err != nil || !ok || last.Offset >= row.Size {
		return rebuilt{}, false, err
	}
	f, err := logfile.OpenFile(e.Path)
	if err != nil {
		return rebuilt{}, false, err
	}
	defer f.Close()
	var b [1]byte
	if _, err := f.ReadAt(b[:], row.Size-1); err != nil || b[0] != '\n' {
		return rebuilt{}, false, nil
	}
	if _, err := f.Seek(row.Size, io.SeekStart); err != nil {
		return rebuilt{}, false, err
	}
	cpr := logfile.ResumeCheckpointer(last, row.LastReceived)
	sum, err := logfile.Scan(f, logfile.ScanOptions{Start: row.Size, StartLine: row.Lines, Checkpointer: &cpr})
	if err != nil {
		return rebuilt{}, false, err
	}
	base.FirstReceived, base.LastReceived = row.FirstReceived, row.LastReceived
	if !sum.First.IsZero() && (base.FirstReceived.IsZero() || sum.First.Before(base.FirstReceived)) {
		base.FirstReceived = sum.First
	}
	if sum.Last.After(base.LastReceived) {
		base.LastReceived = sum.Last
	}
	base.Lines, base.RawSize = sum.Lines, sum.RawSize
	return rebuilt{f: base, cps: sum.Checkpoints, sum: sum}, true, nil
}

// ipFromDeviceID reverses model.DeviceID where it can (IPv6 ':' became '_').
func ipFromDeviceID(id string) string {
	if a, err := netip.ParseAddr(id); err == nil {
		return a.String()
	}
	if a, err := netip.ParseAddr(strings.ReplaceAll(id, "_", ":")); err == nil {
		return a.String()
	}
	return id
}
