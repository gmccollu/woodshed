package index

import (
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

// readFlowFiles reads every segment's footer. With fix set (Reindex: the
// server is stopped), a segment without one is recovered first; otherwise
// (Reconcile, after the store's own recovery) it's left out and counted.
func readFlowFiles(dataDir string, fix bool, res *ReindexResult) ([]flowRebuilt, error) {
	files, err := ListFlowFiles(dataDir)
	if err != nil {
		return nil, err
	}
	var out []flowRebuilt
	for _, ff := range files {
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
		out = append(out, flowRebuilt{rows: rows, first: tm(f.MinReceived), last: tm(f.MaxReceived)})
	}
	return out, nil
}
