package syslog

import (
	"bytes"
	"io"
)

// DefaultMaxSize is the maximum message size (SPEC §3.1), used when
// NewStreamReader is given a size of zero or less.
const DefaultMaxSize = 64 << 10

const (
	readBufSize    = 32 << 10
	maxCountDigits = 10 // octet counts up to 9,999,999,999; longer runs are text
	maxEmptyReads  = 100
)

// StreamReader splits a syslog TCP stream into messages. Framing is detected
// per message (RFC 6587):
//
//   - Octet counting, "<len> <msg>", when the frame starts with a non-zero
//     digit, at most 10 digits, a space and then '<' (the PRI every octet-
//     counting sender emits). Once a connection has used octet counting, the
//     '<' check is dropped for its later frames.
//   - Otherwise newline framing: the message ends at LF or NUL; a CR right
//     before the terminator is dropped too, so CRLF works. A lone CR inside a
//     message is kept.
//
// Empty frames (blank lines, a stray LF after an octet-counted frame) are
// skipped. An octet-counted frame the stream ends in before its advertised
// length is kept, and Incomplete says so. A StreamReader is not safe for
// concurrent use.
type StreamReader struct {
	r          io.Reader
	buf        []byte
	start, end int   // unread bytes are buf[start:end]
	err        error // sticky error from r, returned once the buffer drains
	max        int
	msg        []byte
	octet      bool // this connection has sent an octet-counted frame

	// The last message's frame, when it was an octet-counted frame the stream
	// ended in: the bytes of it that arrived and its advertised length.
	short           bool
	arrived, length int64
}

// NewStreamReader returns a reader that yields messages of at most maxSize
// bytes from r (DefaultMaxSize if maxSize <= 0).
func NewStreamReader(r io.Reader, maxSize int) *StreamReader {
	if maxSize <= 0 {
		maxSize = DefaultMaxSize
	}
	return &StreamReader{r: r, buf: make([]byte, readBufSize), max: maxSize}
}

// Next returns the next message without its framing. A message longer than
// maxSize is cut to maxSize bytes and truncated is true; the rest of it is
// read and discarded so the next call starts on the next frame. The returned
// slice is valid only until the next call to Next.
//
// When the stream ends, any final unterminated message (or the part of an
// octet-counted frame that arrived) is returned first, with a nil error. After
// that Next returns io.EOF, or the reader's error if it failed. A reader that
// keeps returning no data and no error gets io.ErrNoProgress.
//
// An octet-counted frame the stream ended in, whatever the cause (EOF, a reset,
// a TLS close, a deadline), is returned with what arrived, and Incomplete
// reports it. Such a frame is the only message that can be empty: its header
// arrived and none of its bytes did, or, once the connection has used octet
// counting, a frame the stream ended in while its count ("50", "50 ") was
// arriving (Incomplete then gives a length of 0: the count isn't known).
func (s *StreamReader) Next() (msg []byte, truncated bool, err error) {
	s.short, s.arrived, s.length = false, 0, 0
	for {
		for s.start < s.end && isFrameJunk(s.buf[s.start]) {
			s.start++
		}
		if s.start < s.end {
			break
		}
		if !s.fill() {
			return nil, false, s.err
		}
	}
	n, hdr, ok, cut := s.octetHeader()
	if ok {
		s.octet = true
		return s.readCounted(n, hdr)
	}
	if cut {
		// On a connection already counting octets, the stream ended inside the
		// next frame's count: nothing of the message arrived. (A connection's
		// first frame stays ambiguous: "50" then EOF is a line.)
		s.start = s.end
		s.msg = s.msg[:0]
		s.short = true
		return s.msg, false, nil
	}
	return s.readLine()
}

// Incomplete reports whether the message the last Next returned is an
// octet-counted frame the stream ended in before its advertised length: arrived
// of its length bytes came (arrived counts bytes past the max size too, so a
// frame can be both truncated and incomplete). A length of 0 means the stream
// ended inside the count itself (the message is then empty). A newline-framed
// message is never incomplete here: RFC 6587 non-transparent framing can't tell
// a last line without its LF from a complete one (the caller may know more, such
// as a reset).
func (s *StreamReader) Incomplete() (arrived, length int64, ok bool) {
	return s.arrived, s.length, s.short
}

// Buffered returns how many bytes of messages not yet returned the reader already
// holds: what was read from the stream after the last message Next returned,
// not counting the LF, CR and NUL bytes Next skips before a message. A caller
// can tell from it whether the next message has already started arriving.
func (s *StreamReader) Buffered() int {
	i := s.start
	for i < s.end && isFrameJunk(s.buf[i]) {
		i++
	}
	return s.end - i
}

func isFrameJunk(c byte) bool { return c == '\n' || c == '\r' || c == 0 }

// fill reads more data into buf. It reports false when no byte was added
// because r is done or failed (s.err is then set).
func (s *StreamReader) fill() bool {
	if s.err != nil {
		return false
	}
	if s.start == s.end {
		s.start, s.end = 0, 0
	} else if s.end == len(s.buf) {
		s.compact()
	}
	for range maxEmptyReads {
		n, err := s.r.Read(s.buf[s.end:])
		if n < 0 || n > len(s.buf)-s.end {
			n = 0
			if err == nil {
				err = io.ErrShortBuffer
			}
		}
		s.end += n
		if err != nil {
			s.err = err
			return n > 0
		}
		if n > 0 {
			return true
		}
	}
	s.err = io.ErrNoProgress
	return false
}

func (s *StreamReader) compact() {
	n := copy(s.buf, s.buf[s.start:s.end])
	s.start, s.end = 0, n
}

// ensure tries to have n unread bytes buffered. It asks r only for what is
// missing, so it never waits for bytes past the n-th.
func (s *StreamReader) ensure(n int) bool {
	if len(s.buf)-s.start < n {
		s.compact()
	}
	for s.end-s.start < n {
		if !s.fill() {
			return false
		}
	}
	return true
}

// octetHeader checks for "<digits> " at the start of the unread data, peeking
// one byte at a time so an idle connection after a short line can't block it.
// cut reports that the connection already counts octets and the stream ended
// while only digits of a count had arrived.
func (s *StreamReader) octetHeader() (n int64, hdr int, ok, cut bool) {
	for i := 0; ; i++ {
		if !s.ensure(i + 1) {
			return 0, 0, false, s.octet && i > 0
		}
		c := s.buf[s.start+i]
		switch {
		case c >= '0' && c <= '9':
			if (i == 0 && c == '0') || i == maxCountDigits {
				return 0, 0, false, false
			}
			n = n*10 + int64(c-'0')
		case c == ' ' && i > 0:
			if s.octet {
				return n, i + 1, true, false
			}
			if s.ensure(i+2) && s.buf[s.start+i+1] == '<' {
				return n, i + 1, true, false
			}
			return 0, 0, false, false
		default:
			return 0, 0, false, false
		}
	}
}

// readCounted reads an n-byte frame whose header is hdr bytes long.
func (s *StreamReader) readCounted(n int64, hdr int) ([]byte, bool, error) {
	s.start += hdr
	s.msg = s.msg[:0]
	truncated := false
	length := n
	for n > 0 {
		if s.start == s.end && !s.fill() {
			// The stream ended mid-frame: return what arrived, flagged.
			s.short, s.arrived, s.length = true, length-n, length
			return s.msg, truncated, nil
		}
		take := s.end - s.start
		if int64(take) > n {
			take = int(n)
		}
		chunk := s.buf[s.start : s.start+take]
		if room := s.max - len(s.msg); len(chunk) > room {
			chunk, truncated = chunk[:room], true
		}
		s.msg = append(s.msg, chunk...)
		s.start += take
		n -= int64(take)
	}
	return s.msg, truncated, nil
}

// readLine reads up to the next LF or NUL.
func (s *StreamReader) readLine() ([]byte, bool, error) {
	s.msg = s.msg[:0]
	var total int64 // bytes in the line, terminator excluded
	lastCR := false
	for {
		data := s.buf[s.start:s.end]
		k := bytes.IndexByte(data, '\n')
		seg := data
		if k >= 0 {
			seg = data[:k]
		}
		if z := bytes.IndexByte(seg, 0); z >= 0 {
			k, seg = z, seg[:z]
		}
		if len(seg) > 0 {
			lastCR = seg[len(seg)-1] == '\r'
			total += int64(len(seg))
			if room := s.max - len(s.msg); room > 0 {
				s.msg = append(s.msg, seg[:min(room, len(seg))]...)
			}
		}
		if k >= 0 {
			s.start += k + 1
			return s.finishLine(total, lastCR)
		}
		s.start = s.end
		if !s.fill() {
			if total == 0 {
				return nil, false, s.err
			}
			return s.finishLine(total, lastCR)
		}
	}
}

// finishLine drops a CR that sat right before the terminator and works out
// whether the content (without that CR) was cut.
func (s *StreamReader) finishLine(total int64, lastCR bool) ([]byte, bool, error) {
	if lastCR {
		total--
		if len(s.msg) > int(total) {
			s.msg = s.msg[:total]
		}
	}
	return s.msg, total > int64(s.max), nil
}

// TrimDatagram strips trailing LF, CR and NUL bytes from a UDP datagram, which
// is always exactly one message. It returns a subslice of b.
func TrimDatagram(b []byte) []byte {
	n := len(b)
	for n > 0 && (b[n-1] == '\n' || b[n-1] == '\r' || b[n-1] == 0) {
		n--
	}
	return b[:n]
}
