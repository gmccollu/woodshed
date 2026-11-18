package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// recover brings the data dir to a clean state at startup:
//
//  1. Temp files (a gzip in progress) are deleted.
//  2. A .log with a .log.gz of the same name is an interrupted compression: if the
//     gzip holds the same bytes the .log is deleted, otherwise the .log is moved to a
//     new part number (nothing is overwritten).
//  3. A torn last line (a partial write) in an uncompressed file is completed with a
//     newline if its timestamp and sender survived, and cut off otherwise.
//  4. The index is reconciled with the files (index.Reconcile).
//  5. Each device's latest "<day>.log" for today (or later) is parked: the device
//     appends to it on its next message. Every other uncompressed file is queued
//     for compression.
func (s *Store) recover(ctx context.Context) error {
	entries, temps, unknown, err := logfile.ListAll(s.dataDir)
	if err != nil {
		return err
	}
	// A folder inside a device folder that no data type claims is left alone
	// (SPEC §11.1), and said once per start.
	for _, u := range unknown {
		s.log.Info("store: ignoring a folder no data type claims", "folder", u)
	}
	var notes []string
	removed := 0
	for _, t := range temps {
		if os.Remove(t) == nil {
			removed++
		}
	}
	if removed > 0 {
		notes = append(notes, fmt.Sprintf("removed %d unfinished gzip files", removed))
	}

	byRel := make(map[string]logfile.Entry, len(entries))
	for _, e := range entries {
		byRel[e.Rel] = e
	}
	pairs, changed := 0, false
	for _, e := range entries {
		if e.Name.Compressed {
			continue
		}
		gz := e.Name
		gz.Compressed = true
		g, ok := byRel[logfile.RelPathType(e.Type, e.DeviceID, gz)]
		if !ok {
			continue
		}
		changed = true
		pairs++
		if same, err := sameContent(e.Path, g.Path); err == nil && same {
			if err := os.Remove(e.Path); err != nil {
				return err
			}
			continue
		}
		dir := filepath.Dir(e.Path)
		nn := logfile.Name{Day: e.Name.Day, Part: nextPart(dir, e.Name.Day)}
		if err := os.Rename(e.Path, filepath.Join(dir, nn.String())); err != nil {
			return err
		}
	}
	if pairs > 0 {
		notes = append(notes, fmt.Sprintf("finished %d interrupted compressions", pairs))
	}
	if changed {
		if entries, _, err = logfile.List(s.dataDir); err != nil {
			return err
		}
	}

	for _, e := range entries {
		if e.Name.Compressed {
			continue
		}
		kept, cut, err := repairTail(e.Path)
		if err != nil {
			return err
		}
		if kept > 0 {
			s.event(index.LevelWarn, index.KindRecover, e.DeviceID,
				fmt.Sprintf("%s ended in a partial line (%d bytes, likely an unclean stop); kept it as its own line", e.Rel, kept))
		}
		if cut > 0 {
			s.event(index.LevelWarn, index.KindRecover, e.DeviceID,
				fmt.Sprintf("%s ended in %d bytes of an unreadable partial line (likely an unclean stop); removed them", e.Rel, cut))
		}
	}

	// Flow segments a crash left open are closed before the index is
	// reconciled with the files (SPEC §13.2).
	recovered, err := s.recoverFlows(ctx)
	if err != nil {
		return err
	}
	res, err := s.idx.Reconcile(ctx, s.dataDir, recovered...)
	if err != nil {
		return err
	}
	if res.Scanned > 0 || res.Removed > 0 {
		notes = append(notes, fmt.Sprintf("index: re-read %d files, dropped %d rows for missing files", res.Scanned, res.Removed))
	}
	rows := make(map[string]index.File, len(res.Files))
	for _, f := range res.Files {
		rows[f.Path] = f
	}
	if entries, _, err = logfile.List(s.dataDir); err != nil {
		return err
	}
	today := logfile.DayOf(s.clock())
	// Each device's data type has its own active file (SPEC §11.1).
	type devType struct{ dev, typ string }
	var devOrder []devType
	byDev := map[devType][]logfile.Entry{}
	for _, e := range entries {
		k := devType{e.DeviceID, e.Type}
		if _, ok := byDev[k]; !ok {
			devOrder = append(devOrder, k)
		}
		byDev[k] = append(byDev[k], e)
	}
	queued := 0
	for _, k := range devOrder {
		dev, list := k.dev, byDev[k]
		var active *logfile.Entry
		for i := range list {
			n := list[i].Name
			if !n.Compressed && n.Part == 0 && n.Day >= today && (active == nil || n.Day > active.Name.Day) {
				active = &list[i]
			}
		}
		s.devMu.Lock()
		s.known[dev] = struct{}{} // has logs: exempt from the new-device rate
		s.devMu.Unlock()
		for _, e := range list {
			if active != nil && e.Rel == active.Rel {
				// Today's file: park it. The device gets in-memory state only when it
				// sends again, and then appends to this file.
				row, ok := rows[e.Rel]
				ce, err := s.parkFromDisk(ctx, e, row, ok)
				if err != nil {
					return err
				}
				if ce != nil {
					s.addClosed(ce)
				}
				continue
			}
			ce := &catEntry{deviceID: dev, typ: e.Type, name: e.Name, abs: e.Path, rel: e.Rel, size: e.Size}
			if !e.Name.Compressed {
				ce.rawSize = e.Size
				queued++
			}
			if row, ok := rows[e.Rel]; ok {
				ce.first, ce.last, ce.lines, ce.rawSize = row.FirstReceived, row.LastReceived, row.Lines, row.RawSize
			}
			if ce.last.IsZero() { // no readable lines: age it by its file name
				if t, err := logfile.DayStart(e.Name.Day); err == nil {
					ce.last = t.Add(24*time.Hour - time.Millisecond)
				}
			}
			s.addClosed(ce)
		}
	}
	if len(notes) > 0 {
		s.event(index.LevelWarn, index.KindRecover, "", "startup recovery: "+strings.Join(notes, "; "))
	}
	if queued > 0 {
		s.log.Info("store: closed files waiting for compression", "files", queued)
	}
	return nil
}

// parkFromDisk turns a device's file for today, found at startup, into a parked
// catalog entry: its state comes from the index row and newest checkpoint when the
// row matches the file, otherwise from a scan (and the row is rewritten).
func (s *Store) parkFromDisk(ctx context.Context, e logfile.Entry, row index.File, hasRow bool) (*catEntry, error) {
	ce := &catEntry{deviceID: e.DeviceID, typ: e.Type, name: e.Name, abs: e.Path, rel: e.Rel, size: e.Size, rawSize: e.Size, parked: true}
	if hasRow && row.Size == e.Size && row.Lines > 0 {
		last, ok, err := s.idx.LastCheckpoint(ctx, row.ID)
		if err != nil {
			return nil, err
		}
		if ok {
			ce.first, ce.last, ce.lines = row.FirstReceived, row.LastReceived, row.Lines
			ce.cp = logfile.ResumeCheckpointer(last, row.LastReceived)
			return ce, nil
		}
	}
	sum, err := logfile.ScanFile(e.Path)
	if err != nil {
		return nil, err
	}
	if sum.Lines == 0 && sum.RawSize == 0 {
		os.Remove(e.Path) // an empty file: nothing to keep
		return nil, nil
	}
	ce.size, ce.rawSize, ce.lines, ce.first, ce.last, ce.cp = sum.RawSize, sum.RawSize, sum.Lines, sum.First, sum.Last, sum.Checkpointer
	if sum.Lines > 0 {
		s.pushOps(index.FileOp{Kind: index.OpUpsert, File: ce.row(), Checkpoints: sum.Checkpoints, ResetCheckpoints: true})
	}
	return ce, nil
}

// repairTail fixes a file whose last line has no newline (a write torn by a crash or
// power loss). If the partial line still starts with a valid timestamp and sender it
// is kept and terminated, marked incomplete (the message itself may be cut short;
// tornEnd); otherwise the partial bytes are removed. It returns how many bytes of
// the partial line were kept or cut.
func repairTail(path string) (kept, cut int64, err error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, 0, err
		}
		return 0, 0, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() == 0 {
		return 0, 0, err
	}
	size := st.Size()
	var last [1]byte
	if _, err := f.ReadAt(last[:], size-1); err != nil {
		return 0, 0, err
	}
	if last[0] == '\n' {
		return 0, 0, nil
	}
	const chunk = 64 << 10
	buf := make([]byte, chunk)
	tailStart := int64(0)
	for pos := size; pos > 0; {
		start := max(0, pos-chunk)
		n, err := f.ReadAt(buf[:pos-start], start)
		if err != nil && err != io.EOF {
			return 0, 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			tailStart = start + int64(i) + 1
			break
		}
		pos = start
	}
	tailLen := size - tailStart
	if tailLen <= 1<<20 {
		tail := make([]byte, tailLen)
		if _, err := f.ReadAt(tail, tailStart); err != nil && err != io.EOF {
			return 0, 0, err
		}
		if _, perr := logfile.ParseLine(tail); perr == nil && bytes.IndexByte(tail, 0) < 0 {
			keep, end := tornEnd(tail)
			if _, err := f.WriteAt(end, tailStart+int64(keep)); err != nil {
				return 0, 0, err
			}
			if n := tailStart + int64(keep) + int64(len(end)); n < size {
				if err := f.Truncate(n); err != nil {
					return 0, 0, err
				}
			}
			return tailLen, 0, syncFile(f)
		}
	}
	if err := f.Truncate(tailStart); err != nil {
		return 0, 0, err
	}
	return 0, tailLen, syncFile(f)
}

// tornEnd is how a torn last line (no '\n') is finished: its first keep bytes
// stay, then end, the line's marker with incomplete set and a '\n'. A marker
// the tear cut into is replaced (a truncated flag it shows is kept, lengths
// aren't: they may be torn too), and a lone backslash the tear left at the end
// of the escaped message is dropped, so the line reads back as the message that
// was written, marked incomplete.
func tornEnd(tail []byte) (keep int, end []byte) {
	esc, f := logfile.SplitFlags(tail)
	keep = len(esc)
	n := 0
	for n < keep && tail[keep-1-n] == '\\' {
		n++
	}
	if n%2 == 1 {
		keep--
	}
	end = logfile.AppendFlags(nil, logfile.Flags{Truncated: f.Truncated, Incomplete: true})
	return keep, append(end, '\n')
}

// sameContent reports whether a plain file and a gzip hold the same bytes.
func sameContent(plain, gz string) (bool, error) {
	a, an, err := hashPlain(plain)
	if err != nil {
		return false, err
	}
	b, bn, err := hashGzip(gz)
	if err != nil {
		return false, nil // an unreadable gzip is not the same
	}
	return an == bn && bytes.Equal(a, b), nil
}
