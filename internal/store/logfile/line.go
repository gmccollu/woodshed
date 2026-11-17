// Package logfile defines Woodshed's on-disk log format: the line format, the file
// names, the checkpoint rule and a streaming scanner. The store writes with it, and the
// index, search and export read with it, so every reader and writer agrees on one set
// of rules.
//
// A line is
//
//	<received UTC, RFC 3339 with ms> <sender IP> <escaped raw message>\n
//
// for example "2026-11-10T20:41:07.112Z 192.0.2.1 <134>Nov 10 20:41:07 host app: hi".
// CR, LF and backslash in the raw message are escaped as \r, \n and \\ so one message
// is always exactly one line. Every other byte (including NUL and invalid UTF-8) is
// written as received.
//
// A message that wasn't stored whole ends with a marker after a blank (2.0, see
// Flags): "... <13>short \#incomplete=9/50". The escaping above never writes a
// backslash after a blank followed by anything but \, n or r, so " \#" can't come
// from a message. A reader from before 2.0 shows the marker as part of the message.
package logfile

import (
	"bytes"
	"errors"
	"net/netip"
	"strconv"
	"time"
)

// TimeLen is the length of a formatted received time ("2006-01-02T15:04:05.000Z").
const TimeLen = 24

// ErrBadLine is returned by ParseLine for a line that doesn't start with a received
// time and a sender IP.
var ErrBadLine = errors.New("logfile: malformed line")

// AppendTime appends t in UTC as "2006-01-02T15:04:05.000Z" (millisecond precision,
// truncated, not rounded).
func AppendTime(dst []byte, t time.Time) []byte {
	t = t.UTC()
	year, month, day := t.Date()
	hour, min, sec := t.Clock()
	ms := t.Nanosecond() / 1e6
	if year < 0 || year > 9999 {
		// Out of the fixed-width range; fall back to the general formatter.
		return t.AppendFormat(dst, "2006-01-02T15:04:05.000Z07:00")
	}
	var b [TimeLen]byte
	b[0] = byte('0' + year/1000)
	b[1] = byte('0' + year/100%10)
	b[2] = byte('0' + year/10%10)
	b[3] = byte('0' + year%10)
	b[4] = '-'
	b[5] = byte('0' + int(month)/10)
	b[6] = byte('0' + int(month)%10)
	b[7] = '-'
	b[8] = byte('0' + day/10)
	b[9] = byte('0' + day%10)
	b[10] = 'T'
	b[11] = byte('0' + hour/10)
	b[12] = byte('0' + hour%10)
	b[13] = ':'
	b[14] = byte('0' + min/10)
	b[15] = byte('0' + min%10)
	b[16] = ':'
	b[17] = byte('0' + sec/10)
	b[18] = byte('0' + sec%10)
	b[19] = '.'
	b[20] = byte('0' + ms/100)
	b[21] = byte('0' + ms/10%10)
	b[22] = byte('0' + ms%10)
	b[23] = 'Z'
	return append(dst, b[:]...)
}

// ParseTime parses a received time written by AppendTime. Other RFC 3339 forms are
// accepted too (for hand-edited files); the result is always UTC.
func ParseTime(b []byte) (time.Time, error) {
	if len(b) == TimeLen && b[4] == '-' && b[7] == '-' && b[10] == 'T' && b[13] == ':' &&
		b[16] == ':' && b[19] == '.' && b[23] == 'Z' {
		n := func(i, w int) (int, bool) {
			v := 0
			for _, c := range b[i : i+w] {
				if c < '0' || c > '9' {
					return 0, false
				}
				v = v*10 + int(c-'0')
			}
			return v, true
		}
		year, ok1 := n(0, 4)
		month, ok2 := n(5, 2)
		day, ok3 := n(8, 2)
		hour, ok4 := n(11, 2)
		min, ok5 := n(14, 2)
		sec, ok6 := n(17, 2)
		ms, ok7 := n(20, 3)
		if ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && month >= 1 && month <= 12 &&
			day >= 1 && day <= 31 && hour < 24 && min < 60 && sec < 60 {
			t := time.Date(year, time.Month(month), day, hour, min, sec, ms*1e6, time.UTC)
			if t.Day() == day { // reject 2026-02-31 and friends
				return t, nil
			}
		}
		return time.Time{}, ErrBadLine
	}
	t, err := time.Parse(time.RFC3339Nano, string(b))
	if err != nil {
		return time.Time{}, ErrBadLine
	}
	return t.UTC(), nil
}

// AppendEscaped appends raw with CR, LF and backslash escaped as \r, \n and \\.
func AppendEscaped(dst, raw []byte) []byte {
	start := 0
	for i, c := range raw {
		var esc byte
		switch c {
		case '\n':
			esc = 'n'
		case '\r':
			esc = 'r'
		case '\\':
			esc = '\\'
		default:
			continue
		}
		dst = append(dst, raw[start:i]...)
		dst = append(dst, '\\', esc)
		start = i + 1
	}
	return append(dst, raw[start:]...)
}

// Unescape appends the original bytes of an escaped raw message to dst. It reverses
// AppendEscaped exactly. Any other backslash sequence, and a lone trailing backslash
// (for example in a line torn by a crash), is kept as is.
func Unescape(dst, esc []byte) []byte {
	for {
		i := bytes.IndexByte(esc, '\\')
		if i < 0 || i == len(esc)-1 {
			return append(dst, esc...)
		}
		dst = append(dst, esc[:i]...)
		switch esc[i+1] {
		case 'n':
			dst = append(dst, '\n')
		case 'r':
			dst = append(dst, '\r')
		case '\\':
			dst = append(dst, '\\')
		default:
			dst = append(dst, esc[i], esc[i+1])
		}
		esc = esc[i+2:]
	}
}

// AppendLine appends one complete line (with its trailing '\n') for a message.
// received is written in UTC with millisecond precision.
func AppendLine(dst []byte, received time.Time, sender netip.Addr, raw []byte) []byte {
	return AppendLineFlags(dst, received, sender, raw, Flags{})
}

// AppendLineFlags is AppendLine for a message with flags: the marker goes after
// the escaped message (nothing when f is zero).
func AppendLineFlags(dst []byte, received time.Time, sender netip.Addr, raw []byte, f Flags) []byte {
	dst = AppendTime(dst, received)
	dst = append(dst, ' ')
	dst = sender.Unmap().AppendTo(dst)
	dst = append(dst, ' ')
	dst = AppendEscaped(dst, raw)
	dst = AppendFlags(dst, f)
	return append(dst, '\n')
}

// Flags say how a stored message differs from what its sender sent (2.0). They're
// written as a marker at the end of the line: a blank, "\#" and the set flags,
// comma-separated, in this order:
//
//   - "truncated": cut at the max message size;
//   - "incomplete=A/L": an octet-counted TCP or TLS frame that ended before its
//     advertised length L, with A of its bytes arrived (A counts bytes past the
//     max size too);
//   - "incomplete": a line Woodshed cut by closing the connection itself (the
//     frame timeout, an eviction, shutdown), whose length isn't known.
//
// A reader ignores flags it doesn't know, so later versions can add some. Lengths
// that can't be right (A not below L, a torn number) are dropped and the flag
// kept; a torn flag name ("incompl") still counts as its flag.
type Flags struct {
	Truncated  bool
	Incomplete bool
	// Arrived and Length are an incomplete octet-counted frame's (0, 0: not known).
	Arrived, Length int64
}

// IsZero reports whether no flag is set (the message was stored whole).
func (f Flags) IsZero() bool { return !f.Truncated && !f.Incomplete }

const flagMark = "\\#"

// AppendFlags appends f's marker, " \#truncated,incomplete=9/50", or nothing
// when f is zero.
func AppendFlags(dst []byte, f Flags) []byte {
	if f.IsZero() {
		return dst
	}
	dst = append(dst, ' ')
	dst = append(dst, flagMark...)
	if f.Truncated {
		dst = append(dst, "truncated"...)
	}
	if f.Incomplete {
		if f.Truncated {
			dst = append(dst, ',')
		}
		dst = append(dst, "incomplete"...)
		if f.Length > 0 {
			dst = append(dst, '=')
			dst = strconv.AppendInt(dst, f.Arrived, 10)
			dst = append(dst, '/')
			dst = strconv.AppendInt(dst, f.Length, 10)
		}
	}
	return dst
}

// SplitFlags splits a line's escaped message into the message and its marker's
// flags. With no marker it returns esc and zero flags. A whole stored line works
// too: the marker is always last.
func SplitFlags(esc []byte) ([]byte, Flags) {
	sp := bytes.LastIndexByte(esc, ' ')
	if sp < 0 || !bytes.HasPrefix(esc[sp+1:], []byte(flagMark)) {
		return esc, Flags{}
	}
	var f Flags
	for item := range bytes.SplitSeq(esc[sp+1+len(flagMark):], []byte{','}) {
		name, val, _ := bytes.Cut(item, []byte{'='})
		switch {
		case flagName(name, "truncated"):
			f.Truncated = true
		case flagName(name, "incomplete"):
			f.Incomplete = true
			a, l, ok := bytes.Cut(val, []byte{'/'})
			if !ok || string(name) != "incomplete" {
				break
			}
			arrived, err1 := strconv.ParseInt(string(a), 10, 64)
			length, err2 := strconv.ParseInt(string(l), 10, 64)
			if err1 == nil && err2 == nil && arrived >= 0 && arrived < length {
				f.Arrived, f.Length = arrived, length
			}
		}
	}
	return esc[:sp], f
}

// flagName reports whether a marker item's name is flag, or the start of it: a
// line torn inside its marker (" \#incompl") keeps what the marker said. So a
// later flag's name must not be the start of an earlier one's.
func flagName(name []byte, flag string) bool {
	return len(name) > 0 && len(name) <= len(flag) && string(name) == flag[:len(name)]
}

// Line is one parsed line. Escaped aliases the input passed to ParseLine.
type Line struct {
	Received time.Time
	Sender   netip.Addr
	Escaped  []byte // the raw message, still escaped, without the marker
	Flags    Flags  // the marker's (2.0)
}

// Raw returns a newly allocated copy of the original raw message.
func (l Line) Raw() []byte { return Unescape(make([]byte, 0, len(l.Escaped)), l.Escaped) }

// ParseLine parses one line, with or without its trailing '\n'. A trailing "\r\n" is
// tolerated (a literal CR can never be part of a message, which is always escaped).
func ParseLine(line []byte) (Line, error) {
	if n := len(line); n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	sp := bytes.IndexByte(line, ' ')
	if sp < 0 {
		return Line{}, ErrBadLine
	}
	t, err := ParseTime(line[:sp])
	if err != nil {
		return Line{}, err
	}
	rest := line[sp+1:]
	var ipb, esc []byte
	if sp2 := bytes.IndexByte(rest, ' '); sp2 >= 0 {
		ipb, esc = rest[:sp2], rest[sp2+1:]
	} else {
		ipb = rest
	}
	ip, err := netip.ParseAddr(string(ipb))
	if err != nil {
		return Line{}, ErrBadLine
	}
	esc, f := SplitFlags(esc)
	return Line{Received: t, Sender: ip, Escaped: esc, Flags: f}, nil
}
