package syslog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

type frame struct {
	msg       string
	truncated bool
	short     string // "arrived/length" when Incomplete reported the frame, else ""
}

// shortOf is Incomplete's report as frame.short.
func shortOf(sr *StreamReader) string {
	if arrived, length, ok := sr.Incomplete(); ok {
		return fmt.Sprintf("%d/%d", arrived, length)
	}
	return ""
}

// readAll drains a StreamReader, copying each message, and returns the frames
// and the final error. It fails the test if the reader doesn't terminate.
func readAll(t testing.TB, sr *StreamReader, limit int) ([]frame, error) {
	t.Helper()
	var out []frame
	for range limit {
		msg, tr, err := sr.Next()
		if err != nil {
			if msg != nil || tr {
				t.Fatalf("Next returned data with error %v", err)
			}
			if _, _, ok := sr.Incomplete(); ok {
				t.Fatalf("Incomplete set with error %v", err)
			}
			return out, err
		}
		out = append(out, frame{string(msg), tr, shortOf(sr)})
	}
	t.Fatalf("reader did not finish within %d calls", limit)
	return nil, nil
}

func (fr frame) String() string {
	s := fmt.Sprintf("%q", fr.msg)
	if fr.truncated {
		s += "(truncated)"
	}
	if fr.short != "" {
		s += "(incomplete " + fr.short + ")"
	}
	return s
}

func f(s string) frame  { return frame{msg: s} }
func ft(s string) frame { return frame{msg: s, truncated: true} }

// fi is a frame the stream ended in: short is "arrived/length".
func fi(s, short string) frame { return frame{msg: s, short: short} }

func TestStreamReader(t *testing.T) {
	long := strings.Repeat("x", 100)
	cases := []struct {
		name string
		in   string
		max  int
		want []frame
	}{
		{"LF", "a\nb\n", 0, []frame{f("a"), f("b")}},
		{"CRLF", "<13>a\r\n<13>b\r\n", 0, []frame{f("<13>a"), f("<13>b")}},
		{"NUL", "a\x00b\x00", 0, []frame{f("a"), f("b")}},
		{"NUL then LF", "a\x00\nb\n", 0, []frame{f("a"), f("b")}},
		{"blank lines skipped", "\n\n\r\na\n\n\nb\n\n", 0, []frame{f("a"), f("b")}},
		{"final message without terminator", "a\nb", 0, []frame{f("a"), f("b")}},
		{"final message ending in CR", "a\nb\r", 0, []frame{f("a"), f("b")}},
		{"lone CR kept", "a\rb\n", 0, []frame{f("a\rb")}},
		{"leading space kept", "  a \n", 0, []frame{f("  a ")}},
		{"empty stream", "", 0, nil},
		{"only terminators", "\n\r\n\x00", 0, nil},
		{"octet counting", "11 <13>hello x17 <13>hello world!!", 0,
			[]frame{f("<13>hello x"), f("<13>hello world!!")}},
		{"octet frame containing LF", "9 <13>a\nb c8 <13>defg", 0, []frame{f("<13>a\nb c"), f("<13>defg")}},
		{"octet then LF after each frame", "6 <13>ab\n6 <13>cd\n", 0, []frame{f("<13>ab"), f("<13>cd")}},
		{"octet then newline framing", "6 <13>ab<13>cd\n<13>ef\n", 0, []frame{f("<13>ab"), f("<13>cd"), f("<13>ef")}},
		{"digits without '<' are text", "123 apples\n2026-11-10T20:41:07Z h a: x\n", 0,
			[]frame{f("123 apples"), f("2026-11-10T20:41:07Z h a: x")}},
		{"after octet frames, '<' is not required", "6 <13>ab5 hello", 0, []frame{f("<13>ab"), f("hello")}},
		{"leading zero count is text", "05 <13>a\n", 0, []frame{f("05 <13>a")}},
		{"11-digit count is text", "12345678901 <13>a\n", 0, []frame{f("12345678901 <13>a")}},
		{"digits only at EOF", "12345", 0, []frame{f("12345")}},
		{"digits and space at EOF", "12 ", 0, []frame{f("12 ")}},
		{"octet frame cut by EOF", "50 <13>short", 0, []frame{fi("<13>short", "9/50")}},
		{"octet frame exactly its count at EOF", "9 <13>short", 0, []frame{f("<13>short")}},
		{"complete frames, then one cut by EOF", "6 <13>ab6 <13>cd50 <13>ef", 0,
			[]frame{f("<13>ab"), f("<13>cd"), fi("<13>ef", "6/50")}},
		{"later frame's header only at EOF", "6 <13>ab50 ", 0, []frame{f("<13>ab"), fi("", "0/50")}},
		{"later frame's count cut at EOF", "6 <13>ab50", 0, []frame{f("<13>ab"), fi("", "0/0")}},
		{"later frame's one-digit count cut at EOF", "6 <13>ab5", 0, []frame{f("<13>ab"), fi("", "0/0")}},
		{"later frame's header and '<' at EOF", "6 <13>ab50 <", 0, []frame{f("<13>ab"), fi("<", "1/50")}},
		{"first frame's digits at EOF stay a line", "50", 0, []frame{f("50")}},
		{"first frame's header and '<' at EOF", "50 <", 0, []frame{fi("<", "1/50")}},
		{"huge octet count at EOF", "9999999999 <13>x", 0, []frame{fi("<13>x", "5/9999999999")}},
		{"incomplete and over the max", "50 <13>abcdefgh", 5,
			[]frame{{msg: "<13>a", truncated: true, short: "12/50"}}},
		{"over the max, complete", "12 <13>abcdefgh", 5, []frame{ft("<13>a")}},
		{"unterminated last line is not incomplete", "<13>a\n<13>b", 0, []frame{f("<13>a"), f("<13>b")}},
		{"truncate LF", "abcdefgh\nij\n", 5, []frame{ft("abcde"), f("ij")}},
		{"truncate final unterminated", "abcdefgh", 5, []frame{ft("abcde")}},
		{"exactly max", "abcde\nf\n", 5, []frame{f("abcde"), f("f")}},
		{"exactly max with CRLF", "abcde\r\nf\n", 5, []frame{f("abcde"), f("f")}},
		{"one over max with CRLF", "abcdef\r\nf\n", 5, []frame{ft("abcde"), f("f")}},
		{"CRLF within max", "abcd\r\n", 5, []frame{f("abcd")}},
		{"truncate octet", "10 <13>abcdef3 <1>4 <1>a", 5, []frame{ft("<13>a"), f("<1>"), f("<1>a")}},
		{"octet exactly max", "5 <13>a5 <13>b", 5, []frame{f("<13>a"), f("<13>b")}},
		{"long line over buffer", long + "\nok\n", 64, []frame{ft(long[:64]), f("ok")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"whole", "onebyte", "halfbuf"} {
				var r io.Reader = strings.NewReader(tc.in)
				switch mode {
				case "onebyte":
					r = iotest.OneByteReader(r)
				case "halfbuf":
					r = iotest.HalfReader(r)
				}
				got, err := readAll(t, NewStreamReader(r, tc.max), len(tc.in)+2)
				if err != io.EOF {
					t.Fatalf("%s: final error %v, want io.EOF", mode, err)
				}
				if fmt.Sprint(got) != fmt.Sprint(tc.want) {
					t.Fatalf("%s: got %q, want %q", mode, got, tc.want)
				}
			}
		})
	}
}

// Messages larger than the internal buffer, at maxSize and beyond, across
// many reads.
func TestStreamReaderLarge(t *testing.T) {
	big := bytes.Repeat([]byte("y"), 200<<10)
	var in bytes.Buffer
	in.WriteString("<13>")
	in.Write(big)
	in.WriteString("\n<13>after\n")
	fmt.Fprintf(&in, "%d <13>", len(big)+4)
	in.Write(big)
	in.WriteString("<13>tail\n")
	got, err := readAll(t, NewStreamReader(iotest.HalfReader(&in), 0), 10)
	if err != io.EOF {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d frames, want 4", len(got))
	}
	for i, want := range []frame{ft(""), f("<13>after"), ft(""), f("<13>tail")} {
		if got[i].truncated != want.truncated {
			t.Errorf("frame %d truncated = %v", i, got[i].truncated)
		}
		if want.truncated {
			if len(got[i].msg) != DefaultMaxSize || !strings.HasPrefix(got[i].msg, "<13>yyy") {
				t.Errorf("frame %d: len %d prefix %q", i, len(got[i].msg), got[i].msg[:8])
			}
		} else if got[i].msg != want.msg {
			t.Errorf("frame %d = %q, want %q", i, got[i].msg, want.msg)
		}
	}
}

// A short line on an idle connection must be returned without waiting for
// more bytes (the octet-count detection peeks only as far as it needs).
func TestStreamReaderIdleConnection(t *testing.T) {
	for _, in := range []string{"42\n", "<13>hi\n", "7\n", "123 x\n"} {
		pr, pw := io.Pipe()
		go pw.Write([]byte(in))
		sr := NewStreamReader(pr, 0)
		done := make(chan frame, 1)
		go func() {
			msg, tr, _ := sr.Next()
			done <- frame{msg: string(msg), truncated: tr}
		}()
		select {
		case got := <-done:
			if want := strings.TrimSuffix(in, "\n"); got.msg != want {
				t.Errorf("%q: got %q", in, got.msg)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("%q: Next blocked on an idle connection", in)
		}
		pw.Close()
	}
}

// A huge declared length must not allocate a matching buffer.
func TestStreamReaderHugeCountNoAlloc(t *testing.T) {
	in := []byte("9999999999 <13>" + strings.Repeat("z", 1<<20))
	allocs := testing.AllocsPerRun(5, func() {
		sr := NewStreamReader(bytes.NewReader(in), 1024)
		msg, tr, err := sr.Next()
		if err != nil || !tr || len(msg) != 1024 {
			t.Fatalf("got len %d truncated %v err %v", len(msg), tr, err)
		}
	})
	if allocs > 10 {
		t.Fatalf("%.0f allocs reading a huge frame", allocs)
	}
}

func TestStreamReaderErrors(t *testing.T) {
	boom := errors.New("boom")
	sr := NewStreamReader(io.MultiReader(strings.NewReader("a\npartial"), iotest.ErrReader(boom)), 0)
	got, err := readAll(t, sr, 10)
	if err != boom || fmt.Sprint(got) != fmt.Sprint([]frame{f("a"), f("partial")}) {
		t.Fatalf("got %q, %v", got, err)
	}
	// The error is sticky.
	if _, _, err := sr.Next(); err != boom {
		t.Fatalf("second error %v", err)
	}

	// Data and an error from the same Read call.
	sr = NewStreamReader(iotest.DataErrReader(strings.NewReader("x\ny")), 0)
	got, err = readAll(t, sr, 10)
	if err != io.EOF || fmt.Sprint(got) != fmt.Sprint([]frame{f("x"), f("y")}) {
		t.Fatalf("DataErrReader: got %q, %v", got, err)
	}

	// A reader that never makes progress must not hang.
	sr = NewStreamReader(zeroReader{}, 0)
	if _, _, err := sr.Next(); err != io.ErrNoProgress {
		t.Fatalf("zero reader: %v", err)
	}

	// Timeouts surface as the reader's error after the data so far.
	sr = NewStreamReader(iotest.TimeoutReader(iotest.OneByteReader(strings.NewReader("ab"))), 0)
	if msg, _, err := sr.Next(); string(msg) != "a" || err != nil {
		t.Fatalf("timeout reader: first Next %q, %v", msg, err)
	}
	if _, _, err := sr.Next(); err != iotest.ErrTimeout {
		t.Fatalf("timeout reader: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read([]byte) (int, error) { return 0, nil }

func TestTrimDatagram(t *testing.T) {
	cases := map[string]string{
		"":                 "",
		"\n":               "",
		"\r\n\x00":         "",
		"<13>a":            "<13>a",
		"<13>a\n":          "<13>a",
		"<13>a\r\n":        "<13>a",
		"<13>a\x00":        "<13>a",
		"<13>a\n\x00\r\n":  "<13>a",
		"<13>a\nb":         "<13>a\nb",
		"\n<13>a":          "\n<13>a",
		"<13>a \t":         "<13>a \t",
		"<13>a\r\nb\r\n\n": "<13>a\r\nb",
	}
	for in, want := range cases {
		b := []byte(in)
		got := TrimDatagram(b)
		if string(got) != want {
			t.Errorf("TrimDatagram(%q) = %q, want %q", in, got, want)
		}
		if len(got) > 0 && &got[0] != &b[0] {
			t.Errorf("TrimDatagram(%q) copied", in)
		}
	}
}
