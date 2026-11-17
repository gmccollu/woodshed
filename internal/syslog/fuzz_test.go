package syslog

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gmccollu/woodshed/internal/model"
)

func FuzzParse(f *testing.F) {
	for _, tc := range parseCases {
		f.Add([]byte(tc.raw), recv.Unix())
	}
	f.Add([]byte("<13>Jan  1 00:00:00 h a: x"), int64(0))
	f.Add([]byte("<13>Dec 31 23:59:59 h a: x"), time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	f.Fuzz(func(t *testing.T, raw []byte, recvUnix int64) {
		orig := bytes.Clone(raw)
		var received time.Time
		if recvUnix != 0 {
			// Keep the year in a sane range so time arithmetic can't overflow.
			received = time.Unix(recvUnix%(1<<36), 0).UTC()
		}
		m := model.Message{Received: received, Hostname: "stale", App: "stale", Facility: 99}
		Parse(raw, &m)
		if !bytes.Equal(raw, orig) {
			t.Fatalf("raw modified")
		}
		if (m.Facility == model.Unknown) != (m.Severity == model.Unknown) {
			t.Fatalf("facility %d and severity %d disagree on unknown", m.Facility, m.Severity)
		}
		if m.Facility != model.Unknown && (m.Facility < 0 || m.Facility > 23 || m.Severity < 0 || m.Severity > 7) {
			t.Fatalf("facility/severity out of range: %d/%d", m.Facility, m.Severity)
		}
		if !m.Timestamp.IsZero() && m.Timestamp.Location() != time.UTC {
			t.Fatalf("timestamp not UTC: %v", m.Timestamp)
		}
		for _, s := range []string{m.Hostname, m.App} {
			if s == "stale" && !bytes.Contains(raw, []byte("stale")) {
				t.Fatalf("field not reset")
			}
			if len(s) > maxHostLen || !utf8.ValidString(s) || !printable([]byte(s)) {
				t.Fatalf("bad field %q", s)
			}
			if s != "" && !bytes.Contains(raw, []byte(s)) {
				t.Fatalf("field %q not taken from raw", s)
			}
		}
		if len(m.App) > maxAppLen {
			t.Fatalf("app too long: %d", len(m.App))
		}
		// Deterministic.
		m2 := model.Message{Received: received}
		Parse(raw, &m2)
		if m2.Facility != m.Facility || m2.Severity != m.Severity || !m2.Timestamp.Equal(m.Timestamp) ||
			m2.Hostname != m.Hostname || m2.App != m.App {
			t.Fatalf("not deterministic")
		}
	})
}

// chunkReader returns at most n bytes per Read, to exercise every buffer
// boundary.
type chunkReader struct {
	b []byte
	n int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.b) == 0 {
		return 0, io.EOF
	}
	k := min(len(p), c.n, len(c.b))
	copy(p, c.b[:k])
	c.b = c.b[k:]
	return k, nil
}

func FuzzStreamReader(f *testing.F) {
	seeds := []string{
		"a\nb\n", "<13>a\r\n<13>b\r\n", "a\x00b", "11 <13>hello x17 <13>hello world!!",
		"6 <13>ab5 hello", "9999999999 <13>x", "123 apples\n", "05 <13>a\n", "\n\r\n\x00",
		"10 <13>abcdef3 <1>4 <1>a", "abcdef\r\nf\n", strings.Repeat("x", 300) + "\n",
		"50 <13>short", "6 <13>ab50 ", "50 <13>abcdefgh",
	}
	for _, s := range seeds {
		f.Add([]byte(s), uint16(5), uint8(1))
		f.Add([]byte(s), uint16(0), uint8(7))
	}
	f.Fuzz(func(t *testing.T, in []byte, maxSize uint16, chunk uint8) {
		max := int(maxSize % 512)
		limit := max
		if limit == 0 {
			limit = DefaultMaxSize
		}
		whole := drain(t, NewStreamReader(bytes.NewReader(in), max), len(in), limit)
		chunked := drain(t, NewStreamReader(&chunkReader{in, int(chunk%16) + 1}, max), len(in), limit)
		if len(whole) != len(chunked) {
			t.Fatalf("chunking changed the frame count: %d vs %d", len(whole), len(chunked))
		}
		total := 0
		for i := range whole {
			if whole[i] != chunked[i] {
				t.Fatalf("frame %d differs by chunking: %q vs %q", i, whole[i], chunked[i])
			}
			total += len(whole[i].msg)
		}
		if total > len(in) {
			t.Fatalf("output %d bytes from %d input bytes", total, len(in))
		}
		// Without digits there is no octet counting: frames are the
		// non-empty pieces between terminators, minus a CR before one.
		if bytes.IndexAny(in, "0123456789") < 0 {
			var want []frame
			for _, line := range bytes.FieldsFunc(in, func(r rune) bool { return r == '\n' || r == 0 }) {
				line = bytes.TrimLeft(line, "\r")
				line = bytes.TrimSuffix(line, []byte("\r"))
				if len(line) == 0 {
					continue
				}
				fr := frame{msg: string(line)}
				if len(line) > limit {
					fr = frame{msg: string(line[:limit]), truncated: true}
				}
				want = append(want, fr)
			}
			if len(want) != len(whole) {
				t.Fatalf("got %d frames, want %d", len(whole), len(want))
			}
			for i := range want {
				if want[i] != whole[i] {
					t.Fatalf("frame %d = %q, want %q", i, whole[i], want[i])
				}
			}
		}
	})
}

func drain(t *testing.T, sr *StreamReader, n, limit int) []frame {
	t.Helper()
	var out []frame
	for range n + 2 {
		msg, tr, err := sr.Next()
		if err != nil {
			if err != io.EOF {
				t.Fatalf("unexpected error %v", err)
			}
			return out
		}
		if len(msg) > limit {
			t.Fatalf("message of %d bytes exceeds max %d", len(msg), limit)
		}
		arrived, length, short := sr.Incomplete()
		if len(msg) == 0 && !tr && !short {
			t.Fatalf("empty untruncated message")
		}
		if short {
			// What arrived is short of the count, and the message is what arrived
			// up to the max (truncated exactly when that cut something).
			if arrived < 0 || arrived >= length || int64(len(msg)) != min(arrived, int64(limit)) ||
				tr != (arrived > int64(limit)) {
				t.Fatalf("incomplete %d/%d with a %d-byte message (truncated %v, max %d)", arrived, length, len(msg), tr, limit)
			}
		}
		out = append(out, frame{string(msg), tr, shortOf(sr)})
	}
	t.Fatalf("no EOF after %d calls", n+2)
	return nil
}

func FuzzTrimDatagram(f *testing.F) {
	f.Add([]byte("<13>a\r\n\x00"))
	f.Fuzz(func(t *testing.T, b []byte) {
		orig := bytes.Clone(b)
		got := TrimDatagram(b)
		if !bytes.Equal(b, orig) || !bytes.HasPrefix(orig, got) {
			t.Fatalf("TrimDatagram changed or reordered data")
		}
		if n := len(got); n > 0 && (got[n-1] == '\n' || got[n-1] == '\r' || got[n-1] == 0) {
			t.Fatalf("trailing terminator left: %q", got)
		}
		for _, c := range orig[len(got):] {
			if c != '\n' && c != '\r' && c != 0 {
				t.Fatalf("removed non-terminator byte %q", c)
			}
		}
	})
}
