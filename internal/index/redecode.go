package index

import (
	"errors"
	"fmt"
	"os"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowseg"
)

// RedecodeResult is what RedecodeFlows did.
type RedecodeResult struct {
	Segments  int // segments rewritten
	Decoded   int // raw sets decoded
	Records   int // records they gave
	StillRaw  int // raw sets left (no template in the segment, or malformed)
	Unreadable []string
}

// RedecodeFlows re-reads every segment's raw sets (SPEC §13.1.3, `woodshed
// reindex --flows-redecode`): a set kept for lack of its template is decoded
// with the segment's own template of that exporter port, domain and ID (the
// first one received after the set, else the latest), and the segment is
// rewritten with the records added (status late) and the rest still raw. The
// store must not be running; Reindex afterwards rebuilds the index rows.
func RedecodeFlows(dataDir, version string, rules []flow.IEKey) (RedecodeResult, error) {
	var res RedecodeResult
	files, err := ListFlowFiles(dataDir)
	if err != nil {
		return res, err
	}
	for _, ff := range files {
		n, recs, left, err := redecodeOne(ff, version, rules)
		if err != nil {
			res.Unreadable = append(res.Unreadable, ff.Rel+": "+err.Error())
			continue
		}
		if n > 0 {
			res.Segments++
			res.Decoded += n
			res.Records += recs
		}
		res.StillRaw += left
	}
	return res, nil
}

func redecodeOne(ff FlowFile, version string, rules []flow.IEKey) (decoded, records, left int, err error) {
	r, err := flowseg.Open(ff.Path)
	if errors.Is(err, flowseg.ErrNoFooter) {
		if _, err = flowseg.Recover(ff.Path); err == nil {
			r, err = flowseg.Open(ff.Path)
		}
	}
	if err != nil {
		return 0, 0, 0, err
	}
	closed := false
	defer func() {
		if !closed {
			r.Close()
		}
	}()
	f := r.Footer()
	if f.Raw == 0 {
		return 0, 0, 0, nil
	}
	tmpls := r.Templates()
	var raws []*flow.RawSet
	if err := r.Raw(func(rs *flow.RawSet) bool {
		c := *rs
		c.Data = append([]byte(nil), rs.Data...)
		c.Header = append([]byte(nil), rs.Header...)
		raws = append(raws, &c)
		return true
	}); err != nil {
		return 0, 0, 0, err
	}
	var extra []flow.Record
	var keep []*flow.RawSet
	for _, rs := range raws {
		t := templateFor(tmpls, rs)
		if rs.Status != flow.StatusNoTemplate || t == nil {
			keep = append(keep, rs)
			continue
		}
		recs, err := flow.DecodeRawSet(t, rs, flow.RedecodeOptions{RuleIDIEs: rules})
		if err != nil || len(recs) == 0 {
			keep = append(keep, rs)
			continue
		}
		for i := range recs {
			recs[i].Status = flow.StatusLate
		}
		extra = append(extra, recs...)
		decoded++
	}
	if decoded == 0 {
		return 0, 0, len(keep), nil
	}
	tmp := ff.Path + ".redecode.tmp"
	os.Remove(tmp)
	w, err := flowseg.Create(tmp, f.DeviceID, f.Hour, version)
	if err != nil {
		return 0, 0, 0, err
	}
	fail := func(e error) (int, int, int, error) {
		w.Close()
		os.Remove(tmp)
		return 0, 0, 0, e
	}
	var buf []flow.Record
	for i := 0; i < r.Blocks(); i++ {
		if buf, err = r.ReadBlock(i, flowseg.ColAll, buf); err != nil {
			return fail(fmt.Errorf("block %d: %w", i, err))
		}
		for j := range buf {
			if err := w.Append(&buf[j]); err != nil {
				return fail(err)
			}
		}
		if err := w.Flush(); err != nil {
			return fail(err)
		}
	}
	for i := range extra {
		if err := w.Append(&extra[i]); err != nil {
			return fail(err)
		}
	}
	for _, rs := range keep {
		if err := w.AppendRaw(rs); err != nil {
			return fail(err)
		}
	}
	for _, t := range tmpls {
		w.AddTemplate(t)
	}
	if m := r.Meta(); m != nil {
		w.SetMeta(m)
	}
	if _, err := w.Close(); err != nil {
		os.Remove(tmp)
		return 0, 0, 0, err
	}
	r.Close()
	closed = true
	if err := os.Rename(tmp, ff.Path); err != nil {
		os.Remove(tmp)
		return 0, 0, 0, err
	}
	return decoded, len(extra), len(keep), nil
}

// templateFor picks the segment's template for a raw set: the same version,
// exporter port, domain and ID, the first received after the set, else the
// latest.
func templateFor(ts []*flow.Template, rs *flow.RawSet) *flow.Template {
	var after, latest *flow.Template
	for _, t := range ts {
		if t.ID != rs.TemplateID || t.Domain != rs.Domain || t.ExporterPort != rs.ExporterPort || t.Version != rs.Version {
			continue
		}
		if t.Received >= rs.Received && (after == nil || t.Received < after.Received) {
			after = t
		}
		if latest == nil || t.Received > latest.Received {
			latest = t
		}
	}
	if after != nil {
		return after
	}
	return latest
}
