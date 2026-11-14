package search

import (
	"bytes"
	"compress/flate"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
)

const (
	cursorVersion = 1
	macLen        = 16
	bindLen       = 16
)

// binding hashes the parameters a cursor is tied to: everything but the cursor
// and the limit, with times as sent (zero when defaulted).
func (q *Query) binding() []byte {
	h := sha256.New()
	var b []byte
	str := func(s string) {
		b = binary.AppendUvarint(b[:0], uint64(len(s)))
		h.Write(b)
		h.Write([]byte(s))
	}
	num := func(v int64) {
		b = binary.AppendVarint(b[:0], v)
		h.Write(b)
	}
	flag := func(v bool) {
		if v {
			num(1)
		} else {
			num(0)
		}
	}
	str("woodshed-search-v1")
	str(q.Q)
	flag(q.Regex)
	flag(q.Case)
	num(int64(q.Severities))
	tm := func(t interface{ UnixNano() int64 }, zero bool) {
		if zero {
			num(0)
			return
		}
		num(t.UnixNano())
	}
	tm(q.From, q.From.IsZero())
	tm(q.To, q.To.IsZero())
	devs := sortedUnique(q.Devices)
	num(int64(len(devs)))
	for _, d := range devs {
		str(d)
	}
	str(q.Group)
	flag(q.Ungrouped)
	flag(q.Asc)
	str(q.Exclude)
	flag(q.Terms)
	num(int64(q.Facilities))
	for _, list := range [][]string{q.Apps, q.Hosts, q.ExcludeApps, q.ExcludeHosts, q.ExcludeDevices} {
		vs := sortedUnique(list)
		num(int64(len(vs)))
		for _, v := range vs {
			str(v)
		}
	}
	if t := q.Type; t != "" && t != TypeSyslog { // a syslog query binds as in 1.1
		str(t)
		if q.Trap != nil {
			str(q.Trap.Bind())
		}
	}
	return h.Sum(nil)[:bindLen]
}

type cursorStream struct {
	dev    string
	fileID int64 // 0: the stream hasn't started a file
	first  int64 // the file's FirstReceived (ms), to place it if it's gone
	pos    int64
	hint   int64
	// head: the stream's next matching line starts (asc) or ends (desc) at pos
	// and was received at headMs.
	head   bool
	headMs int64
}

type cursorState struct {
	fromMs, toMs int64
	streams      []cursorStream
}

// encodeCursor returns the cursor for the streams' positions, or "" when every
// stream is finished.
func (e *Engine) encodeCursor(bind []byte, r *run, streams []*stream) string {
	var cs []cursorStream
	for _, s := range streams {
		if h := s.head(); h != nil {
			pos := h.off
			if r.desc {
				pos = h.end
			}
			cs = append(cs, cursorStream{dev: s.dev, fileID: h.file.ID, first: h.file.FirstReceived.UnixMilli(), pos: pos,
				head: true, headMs: h.ms})
			continue
		}
		if s.pending {
			f := s.files[s.fi]
			cs = append(cs, cursorStream{dev: s.dev, fileID: f.ID, first: f.FirstReceived.UnixMilli(), pos: s.pos,
				head: true, headMs: s.pendingMs})
			continue
		}
		if !s.done && s.finished(r.desc) {
			s.nextFile(r.desc)
		}
		if s.done {
			continue
		}
		f := s.files[s.fi]
		cs = append(cs, cursorStream{dev: s.dev, fileID: f.ID, first: f.FirstReceived.UnixMilli(), pos: s.pos, hint: s.hint})
	}
	if len(cs) == 0 {
		return ""
	}
	var p []byte
	p = binary.AppendVarint(p, r.fromMs)
	p = binary.AppendVarint(p, r.toMs)
	p = binary.AppendUvarint(p, uint64(len(cs)))
	for _, c := range cs {
		p = binary.AppendUvarint(p, uint64(len(c.dev)))
		p = append(p, c.dev...)
		p = binary.AppendUvarint(p, uint64(c.fileID))
		p = binary.AppendVarint(p, c.first)
		p = binary.AppendVarint(p, c.pos)
		p = binary.AppendUvarint(p, uint64(c.hint))
		if c.head {
			p = append(p, 1)
			p = binary.AppendVarint(p, c.headMs)
		} else {
			p = append(p, 0)
		}
	}
	var z bytes.Buffer
	z.WriteByte(cursorVersion)
	z.Write(bind)
	fw, _ := flate.NewWriter(&z, flate.BestSpeed)
	fw.Write(p)
	fw.Close()
	mac := hmac.New(sha256.New, e.key)
	mac.Write(z.Bytes())
	out := mac.Sum(z.Bytes())[:z.Len()+macLen]
	return base64.RawURLEncoding.EncodeToString(out)
}

var (
	errCursorInvalid = &QueryError{Msg: "This cursor isn't valid (it was changed, or the server restarted since). Start the search again."}
	errCursorOther   = &QueryError{Msg: "The cursor belongs to a different search: keep every parameter except limit the same as on the first page."}
)

func (e *Engine) decodeCursor(s string, bind []byte) (*cursorState, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) < 1+bindLen+macLen {
		return nil, errCursorInvalid
	}
	body, sum := raw[:len(raw)-macLen], raw[len(raw)-macLen:]
	mac := hmac.New(sha256.New, e.key)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil)[:macLen], sum) || body[0] != cursorVersion {
		return nil, errCursorInvalid
	}
	if !bytes.Equal(body[1:1+bindLen], bind) {
		return nil, errCursorOther
	}
	p, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(body[1+bindLen:])), 64<<20))
	if err != nil {
		return nil, errCursorInvalid
	}
	d := decoder{b: p}
	c := &cursorState{fromMs: d.varint(), toMs: d.varint()}
	n := d.uvarint()
	if d.err != nil || n > uint64(len(p)) {
		return nil, errCursorInvalid
	}
	for i := uint64(0); i < n; i++ {
		var cs cursorStream
		cs.dev = d.str()
		cs.fileID = int64(d.uvarint())
		cs.first = d.varint()
		cs.pos = d.varint()
		cs.hint = int64(d.uvarint())
		if d.uvarint() == 1 {
			cs.head, cs.headMs = true, d.varint()
		}
		c.streams = append(c.streams, cs)
	}
	if d.err != nil || len(d.b) != 0 {
		return nil, errCursorInvalid
	}
	return c, nil
}

type decoder struct {
	b   []byte
	err error
}

var errShort = errors.New("short")

func (d *decoder) uvarint() uint64 {
	v, n := binary.Uvarint(d.b)
	if n <= 0 {
		d.err = errShort
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) varint() int64 {
	v, n := binary.Varint(d.b)
	if n <= 0 {
		d.err = errShort
		return 0
	}
	d.b = d.b[n:]
	return v
}

func (d *decoder) str() string {
	n := d.uvarint()
	if d.err != nil || n > uint64(len(d.b)) {
		d.err = errShort
		return ""
	}
	s := string(d.b[:n])
	d.b = d.b[n:]
	return s
}

// resume rebuilds a stream at a cursor position. A file that's gone (retention)
// is passed over: the stream continues with the next file in scan order.
func (c cursorStream) resume(files []*fileInfo, desc bool) *stream {
	s := newStream(c.dev, files)
	if s.done {
		return s
	}
	if c.fileID == 0 {
		if desc {
			s.fi = len(files) - 1
		}
		return s
	}
	for i, f := range files {
		if f.ID == c.fileID {
			s.fi, s.pos, s.hint = i, c.pos, c.hint
			if s.pos < -1 {
				s.pos = -1
			}
			s.pending, s.pendingMs = c.head && s.pos >= 0, c.headMs
			return s
		}
	}
	k := fileKey{c.first, c.fileID}
	if desc {
		s.fi = -1
		for i, f := range files {
			if f.key().less(k) {
				s.fi = i
			}
		}
	} else {
		s.fi = len(files)
		for i := len(files) - 1; i >= 0; i-- {
			if k.less(files[i].key()) {
				s.fi = i
			}
		}
	}
	if s.fi < 0 || s.fi >= len(files) {
		s.done = true
	}
	return s
}
