package search

import (
	"bytes"
	"regexp"
	"unicode/utf8"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Severity, Facility and PRI are the syslog type's (internal/datatype): the
// storage line has no severity, so search and export read it from the raw
// message.

// Severity returns the syslog severity (0-7) of a raw message from its PRI, or
// model.Unknown when it has no valid one (datatype.Severity).
func Severity(raw []byte) int { return datatype.Severity(raw) }

// Facility returns the syslog facility (0-23) of a raw message from its PRI,
// or model.Unknown when it has no valid one (datatype.Facility).
func Facility(raw []byte) int { return datatype.Facility(raw) }

// PRI returns the PRI value (0-191) of a raw message, or -1 when it has no
// valid one (datatype.PRI).
func PRI(raw []byte) int { return datatype.PRI(raw) }

// matcher matches q against a raw message (unescaped, without the stored
// prefix).
type matcher struct {
	kind   matchKind
	needle []byte // the needle; lower-cased for foldASCII and foldUnicode
	re     *regexp.Regexp

	// prefilter: the needle can be searched for in the escaped storage bytes
	// to find candidate lines (it has no byte that escaping changes). A
	// candidate still has to match its unescaped message.
	prefilter bool
	// first byte of the needle in both cases, for the fold prefilter.
	lo, up byte
	// pre is a regex's prefilter: a substring matcher for the literal every
	// match starts with; for terms, the longest term every match contains.
	pre *matcher
	// terms is a syntax=terms expression (matchTerms).
	terms *termNode
}

type matchKind int

const (
	matchAll         matchKind = iota // empty q
	matchExact                        // case=true substring
	matchFoldASCII                    // case-insensitive, ASCII needle
	matchFoldUnicode                  // case-insensitive, non-ASCII needle
	matchRegex
	matchTerms // syntax=terms with more than one term
)

// QueryError is a request the engine refuses (a 400 at the API): an invalid
// regular expression, cursor or ref, or an empty time range.
type QueryError struct{ Msg string }

func (e *QueryError) Error() string { return e.Msg }

func newMatcher(q string, isRegex, caseSensitive bool) (*matcher, error) {
	if q == "" {
		return &matcher{kind: matchAll}, nil
	}
	if isRegex {
		expr := q
		if !caseSensitive {
			expr = "(?i)" + q
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			// Report the error against what the user typed, not our "(?i)".
			if _, err2 := regexp.Compile(q); err2 != nil {
				err = err2
			}
			return nil, &QueryError{Msg: err.Error()}
		}
		m := &matcher{kind: matchRegex, re: re}
		// Every match begins with the expression's literal prefix (of the
		// case-sensitive form; with case=false, matched ignoring ASCII case), so
		// only lines holding it need the regex.
		if exact, err := regexp.Compile(q); err == nil {
			if prefix, _ := exact.LiteralPrefix(); prefix != "" && (caseSensitive || isASCII([]byte(prefix))) {
				if pre, _ := newMatcher(prefix, false, caseSensitive); pre.prefilter {
					m.pre, m.prefilter = pre, true
				}
			}
		}
		return m, nil
	}
	m := &matcher{needle: []byte(q)}
	switch {
	case caseSensitive:
		m.kind = matchExact
	case isASCII(m.needle):
		m.kind = matchFoldASCII
		m.needle = bytes.ToLower(m.needle)
		m.lo, m.up = m.needle[0], upperASCII(m.needle[0])
	default:
		m.kind = matchFoldUnicode
		m.needle = bytes.ToLower(m.needle)
	}
	if m.kind != matchFoldUnicode && bytes.IndexAny(m.needle, "\\\r\n") < 0 {
		m.prefilter = true
	}
	return m, nil
}

// match reports whether raw (an unescaped message) matches.
func (m *matcher) match(raw []byte) bool {
	switch m.kind {
	case matchAll:
		return true
	case matchExact:
		return bytes.Contains(raw, m.needle)
	case matchFoldASCII:
		return m.nextFold(raw, 0) >= 0
	case matchFoldUnicode:
		return bytes.Contains(bytes.ToLower(raw), m.needle)
	case matchTerms:
		return m.terms.match(raw)
	default:
		return m.re.Match(raw)
	}
}

// next returns the index of the next candidate at or after from in buf, or
// -1. Only valid when prefilter is set.
func (m *matcher) next(buf []byte, from int) int {
	if m.pre != nil {
		return m.pre.next(buf, from)
	}
	if m.kind == matchExact {
		if i := bytes.Index(buf[from:], m.needle); i >= 0 {
			return from + i
		}
		return -1
	}
	return m.nextFold(buf, from)
}

// nextFold finds the lower-case ASCII needle in s ignoring ASCII case, from
// from on. It jumps between occurrences of the first byte (either case) with
// IndexByte, which is vectorised.
func (m *matcher) nextFold(s []byte, from int) int {
	n := len(m.needle)
	i := from
	nextLo, nextUp := -2, -2 // -2: not looked up yet; -1: none left
	for i+n <= len(s) {
		if nextLo != -1 && nextLo < i {
			nextLo = indexFrom(s, m.lo, i)
		}
		if m.up != m.lo && nextUp != -1 && nextUp < i {
			nextUp = indexFrom(s, m.up, i)
		} else if m.up == m.lo {
			nextUp = -1
		}
		j := nextLo
		if j < 0 || (nextUp >= 0 && nextUp < j) {
			j = nextUp
		}
		if j < 0 || j+n > len(s) {
			return -1
		}
		if equalFoldASCII(s[j+1:j+n], m.needle[1:]) {
			return j
		}
		i = j + 1
	}
	return -1
}

func indexFrom(s []byte, c byte, from int) int {
	if from >= len(s) {
		return -1
	}
	if k := bytes.IndexByte(s[from:], c); k >= 0 {
		return from + k
	}
	return -1
}

// equalFoldASCII reports whether s equals the lower-case ASCII q, ignoring
// ASCII case in s.
func equalFoldASCII(s, q []byte) bool {
	for k := range q {
		c := s[k]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != q[k] {
			return false
		}
	}
	return true
}

func upperASCII(c byte) byte {
	if 'a' <= c && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// splitLine splits a stored line (without its '\n') into its received time in
// Unix milliseconds and the escaped raw message, without the line's marker
// (logfile.Flags). ok is false for a line that doesn't start with a received
// time, a blank, a sender and a blank.
func splitLine(line []byte) (ms int64, esc []byte, ok bool) {
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1] // tolerated, as in logfile.ParseLine
	}
	var rest []byte
	if len(line) > logfile.TimeLen+2 && line[logfile.TimeLen] == ' ' {
		ms, ok = parseMillis(line[:logfile.TimeLen])
		rest = line[logfile.TimeLen+1:]
	}
	if !ok {
		// A hand-edited file may use another RFC 3339 form.
		sp := bytes.IndexByte(line, ' ')
		if sp <= 0 {
			return 0, nil, false
		}
		t, err := logfile.ParseTime(line[:sp])
		if err != nil {
			return 0, nil, false
		}
		ms, rest = t.UnixMilli(), line[sp+1:]
	}
	sp := bytes.IndexByte(rest, ' ')
	if sp <= 0 {
		return 0, nil, false
	}
	esc, _ = logfile.SplitFlags(rest[sp+1:])
	return ms, esc, true
}

// parseMillis parses "2006-01-02T15:04:05.000Z" into Unix milliseconds without
// the time package (the hot path of every scan).
func parseMillis(b []byte) (int64, bool) {
	if len(b) != logfile.TimeLen || b[4] != '-' || b[7] != '-' || b[10] != 'T' || b[13] != ':' ||
		b[16] != ':' || b[19] != '.' || b[23] != 'Z' {
		return 0, false
	}
	num := func(s []byte) (int64, bool) {
		var v int64
		for _, c := range s {
			if c < '0' || c > '9' {
				return 0, false
			}
			v = v*10 + int64(c-'0')
		}
		return v, true
	}
	y, ok1 := num(b[0:4])
	mo, ok2 := num(b[5:7])
	d, ok3 := num(b[8:10])
	h, ok4 := num(b[11:13])
	mi, ok5 := num(b[14:16])
	s, ok6 := num(b[17:19])
	f, ok7 := num(b[20:23])
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 60 {
		return 0, false
	}
	return ((daysFromCivil(y, mo, d)*24+h)*60+mi)*60000 + s*1000 + f, true
}

// daysFromCivil is the number of days since 1970-01-01 of a proleptic
// Gregorian date (H. Hinnant's algorithm).
func daysFromCivil(y, m, d int64) int64 {
	if m <= 2 {
		y--
	}
	era := y / 400
	if y < 0 && y%400 != 0 {
		era--
	}
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return era*146097 + doe - 719468
}
