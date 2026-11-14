package search

import (
	"context"
	"errors"
	"sort"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// ContextPage is the /api/context response: lines around a hit, in file order.
type ContextPage struct {
	Lines    []Line
	HitIndex int
	AtStart  bool // no older stored line for the device
	AtEnd    bool // no newer stored line for the device
}

// Context returns up to before lines before the line ref names and up to after
// lines after it, from the same device in file order, crossing into the
// neighbouring part and day files. It returns ErrNotFound when the line's file
// is gone and a *QueryError for an invalid ref.
func (e *Engine) Context(ctx context.Context, ref string, before, after int) (ContextPage, error) {
	id, off, ms, err := decodeRef(ref)
	if err != nil {
		return ContextPage{}, err
	}
	before, after = min(max(before, 0), MaxContext), min(max(after, 0), MaxContext)
	row, err := e.idx.File(ctx, id)
	if errors.Is(err, index.ErrNotFound) {
		return ContextPage{}, ErrNotFound
	}
	if err != nil {
		return ContextPage{}, err
	}
	rows, err := e.idx.Files(ctx, row.DeviceID)
	if err != nil {
		return ContextPage{}, err
	}
	files := make([]*fileInfo, 0, len(rows))
	at := -1
	for _, r := range rows {
		if logfile.NormType(r.Type) != logfile.NormType(row.Type) {
			continue // context stays within the ref's data type (SPEC §11.1)
		}
		fi := &fileInfo{File: r}
		if r.ID == id {
			at = len(files)
		}
		files = append(files, fi)
	}
	if at < 0 {
		return ContextPage{}, ErrNotFound
	}
	sort.SliceStable(files, func(i, j int) bool { return files[i].key().less(files[j].key()) })
	for i, f := range files {
		if f.ID == id {
			at = i
		}
	}
	r := &run{e: e, ctx: ctx, m: &matcher{kind: matchAll}, fromMs: -1 << 62, toMs: 1 << 62, files: map[int64]struct{}{}}

	// The hit and the lines after it.
	o, err := e.open(ctx, files[at])
	if errors.Is(err, errGone) {
		return ContextPage{}, ErrNotFound
	}
	if err != nil {
		return ContextPage{}, err
	}
	defer o.Close()
	rd, err := o.reader(off)
	if err != nil {
		return ContextPage{}, &QueryError{Msg: "Invalid ref."}
	}
	fw := newFwd(rd, off, e.block)
	var hitLine hit
	var afterLines []hit
	haveHit := false
	exhausted := false
	for !exhausted && len(afterLines) < after+1 {
		buf, boff, err := fw.next()
		if err != nil || buf == nil {
			exhausted = err == nil
			break
		}
		for _, h := range r.lines(buf, boff, -1, files[at], nil) {
			if !haveHit {
				if h.off != off || h.ms != ms {
					return ContextPage{}, &QueryError{Msg: "Invalid ref."}
				}
				hitLine, haveHit = h, true
				continue
			}
			if len(afterLines) < after {
				afterLines = append(afterLines, h)
			} else {
				afterLines = append(afterLines, h) // one extra: proves there's more
				break
			}
		}
	}
	if !haveHit {
		return ContextPage{}, &QueryError{Msg: "Invalid ref."}
	}
	atEnd := false
	if len(afterLines) > after {
		afterLines = afterLines[:after]
	} else {
		// Continue into the following files.
		for i := at + 1; len(afterLines) <= after && i < len(files); i++ {
			afterLines = append(afterLines, e.firstLines(r, files[i], after+1-len(afterLines))...)
		}
		if len(afterLines) > after {
			afterLines = afterLines[:after]
		} else {
			atEnd = true
		}
	}

	// The lines before it: this file, then earlier ones.
	want := before + 1 // one extra: proves there's more
	beforeLines := e.lastLines(r, o, files[at], off, want)
	for i := at - 1; len(beforeLines) < want && i >= 0; i-- {
		var older []hit
		if po, err := e.open(ctx, files[i]); err == nil {
			older = e.lastLines(r, po, files[i], -1, want-len(beforeLines))
			po.Close()
		}
		beforeLines = append(older, beforeLines...)
	}
	atStart := len(beforeLines) < want
	if !atStart {
		beforeLines = beforeLines[1:]
	}

	page := ContextPage{HitIndex: len(beforeLines), AtStart: atStart, AtEnd: atEnd}
	for _, h := range beforeLines {
		page.Lines = append(page.Lines, e.line(row.DeviceID, h))
	}
	page.Lines = append(page.Lines, e.line(row.DeviceID, hitLine))
	for _, h := range afterLines {
		page.Lines = append(page.Lines, e.line(row.DeviceID, h))
	}
	return page, nil
}

// firstLines returns up to n lines from the start of a file.
func (e *Engine) firstLines(r *run, fi *fileInfo, n int) []hit {
	o, err := e.open(r.ctx, fi)
	if err != nil {
		return nil
	}
	defer o.Close()
	rd, err := o.reader(0)
	if err != nil {
		return nil
	}
	fw := newFwd(rd, 0, e.block)
	var out []hit
	for len(out) < n {
		buf, off, err := fw.next()
		if err != nil || buf == nil {
			break
		}
		out = r.lines(buf, off, -1, fi, out)
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// lastLines returns up to n lines ending before offset end (-1: the end of the
// file), oldest first.
func (e *Engine) lastLines(r *run, o *opened, fi *fileInfo, end int64, n int) []hit {
	if n <= 0 {
		return nil
	}
	if !o.file.Compressed {
		tail := false
		if end < 0 {
			size, err := o.size()
			if err != nil {
				return nil
			}
			end, tail = size, true
		}
		var out []hit
		for end > 0 && len(out) < n {
			buf, start, err := readBack(o.f, 0, end, e.block, tail)
			if err != nil || buf == nil {
				break
			}
			tail = false
			out = append(r.lines(buf, start, -1, fi, nil), out...)
			end = start
		}
		if len(out) > n {
			out = out[len(out)-n:]
		}
		return out
	}
	// Compressed: read forward from a checkpoint far enough back, keeping the
	// last n lines; step further back until there are n or the file starts.
	cps := fi.cps
	k := len(cps) // index of the first checkpoint at or after end
	if end >= 0 {
		k = sort.Search(len(cps), func(i int) bool { return cps[i].Offset >= end })
	}
	for back := 1; ; back *= 4 {
		startIdx := k - back
		var start int64
		if startIdx > 0 {
			start = cps[startIdx].Offset
		}
		rd, err := o.reader(start)
		if err != nil {
			return nil
		}
		fw := newFwd(rd, start, e.block)
		g := newRing(n, 1<<62)
		for {
			buf, off, err := fw.next()
			if err != nil || buf == nil || (end >= 0 && off >= end) {
				break
			}
			for _, h := range r.lines(buf, off, end, fi, nil) {
				g.push(h)
			}
		}
		kept, dropped := g.items()
		if dropped || len(kept) >= n || startIdx <= 0 {
			return append([]hit(nil), kept...)
		}
	}
}
