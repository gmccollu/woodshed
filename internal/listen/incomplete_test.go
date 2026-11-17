package listen

import (
	"crypto/tls"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/model"
)

// waitInFrame waits until a connection in s's pool has a message in progress: its
// bytes are in the server's reader, so a reset sent now can't discard them.
func waitInFrame(t *testing.T, s *Server) {
	t.Helper()
	waitFor(t, "a message in progress", func() bool {
		s.pool.mu.Lock()
		defer s.pool.mu.Unlock()
		for c := range s.pool.conns {
			if c.inFrame.Load() {
				return true
			}
		}
		return false
	})
}

type wantMsg struct {
	raw             string
	truncated, inc  bool
	arrived, length int64
}

func checkMsg(t *testing.T, what string, m model.Message, w wantMsg) {
	t.Helper()
	if string(m.Raw) != w.raw || m.Truncated != w.truncated || m.Incomplete != w.inc ||
		m.FrameArrived != w.arrived || m.FrameLength != w.length {
		t.Errorf("%s: %q truncated=%v incomplete=%v %d/%d; want %q truncated=%v incomplete=%v %d/%d", what,
			m.Raw, m.Truncated, m.Incomplete, m.FrameArrived, m.FrameLength, w.raw, w.truncated, w.inc, w.arrived, w.length)
	}
}

func frameOf(st Status, proto string) FrameStatus {
	for _, f := range st.Frames {
		if f.Listener == proto {
			return f
		}
	}
	return FrameStatus{Listener: "missing " + proto}
}

// Octet-counted frames that end short, over real TCP: the sender's FIN, a
// reset, a header with no bytes, and one over the max size too. A last line
// without its LF is complete, as RFC 6587 allows.
func TestTCPIncompleteFrames(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.MaxMessageBytes = 64
	s, c, _ := start(t, cfg, nil)
	addr := tcpAddr(t, s)
	dial := func() *net.TCPConn {
		t.Helper()
		cn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cn.Close() })
		return cn.(*net.TCPConn)
	}
	n := 0
	send := func(what, data string, reset bool, want ...wantMsg) {
		t.Helper()
		cn := dial()
		if _, err := cn.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
		if reset {
			waitInFrame(t, s)
			cn.SetLinger(0) // the close sends a reset
		}
		cn.Close()
		got := c.wait(t, n+len(want))
		if len(got) != n+len(want) {
			t.Fatalf("%s: %d messages, want %d", what, len(got)-n, len(want))
		}
		for i, w := range want {
			checkMsg(t, what, got[n+i], w)
		}
		n += len(want)
	}
	long := strings.Repeat("y", 100)

	send("complete", "9 <13>short", false, wantMsg{raw: "<13>short"})
	send("FIN mid-frame", "50 <13>short", false, wantMsg{raw: "<13>short", inc: true, arrived: 9, length: 50})
	send("reset mid-frame", "6 <13>ab40 <13>reset me", true,
		wantMsg{raw: "<13>ab"}, wantMsg{raw: "<13>reset me", inc: true, arrived: 12, length: 40})
	send("over the max and incomplete", "200 <13>"+long, false,
		wantMsg{raw: ("<13>" + long)[:64], truncated: true, inc: true, arrived: 104, length: 200})
	send("over the max, complete", "104 <13>"+long, false, wantMsg{raw: ("<13>" + long)[:64], truncated: true})
	send("last line without LF", "<13>one\n<13>no LF", false, wantMsg{raw: "<13>one"}, wantMsg{raw: "<13>no LF"})
	// Only the header of the second frame arrives: nothing to store, but counted.
	send("header only", "6 <13>ab50 ", false, wantMsg{raw: "<13>ab"})
	waitFor(t, "the header-only frame's count", func() bool { return s.Status().TCPIncompleteFrames == 4 })

	st := s.Status()
	if f := frameOf(st, "tcp"); f.Incomplete != 4 || f.FrameTimeouts != 0 || f.Port == 0 {
		t.Errorf("frames %+v", st.Frames)
	}
	// "Truncated" stays the max size's: the two frames over 64 bytes.
	if st.Truncated != 2 || st.Received != 9 || st.TCPFrameTimeouts != 0 {
		t.Errorf("status %+v", st)
	}
	if c.count() != 9 {
		t.Errorf("%d messages delivered, want 9", c.count())
	}
}

// Our own cuts of an octet-counted frame keep its lengths: the frame timeout,
// and shutdown.
func TestTCPIncompleteOurCut(t *testing.T) {
	cfg := loopback(0, 0)
	cfg.TCPFrameTimeout = config.Duration(300 * time.Millisecond)
	s, c, _ := start(t, cfg, nil)
	cn, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer cn.Close()
	cn.Write([]byte("50 <13>slow"))
	if !closedByServer(cn, 5*time.Second) {
		t.Fatal("the frame timeout didn't close the connection")
	}
	checkMsg(t, "frame timeout", c.wait(t, 1)[0], wantMsg{raw: "<13>slow", inc: true, arrived: 8, length: 50})
	waitFor(t, "the frame timeout's count", func() bool { return s.Status().TCPFrameTimeouts == 1 })
	if f := frameOf(s.Status(), "tcp"); f.Incomplete != 1 || f.FrameTimeouts != 1 {
		t.Errorf("frames %+v", f)
	}

	cn2, err := net.Dial("tcp", tcpAddr(t, s))
	if err != nil {
		t.Fatal(err)
	}
	defer cn2.Close()
	cn2.Write([]byte("40 <13>at shutdown"))
	waitInFrame(t, s)
	s.Close() // no sink call after Close returns
	got := c.wait(t, 2)
	checkMsg(t, "shutdown", got[1], wantMsg{raw: "<13>at shutdown", inc: true, arrived: 15, length: 40})
	if f := frameOf(s.Status(), "tcp"); f.Incomplete != 2 || f.FrameTimeouts != 1 {
		t.Errorf("frames %+v", f)
	}
}

// Over real TLS: a close_notify and a bare TCP close mid-frame both leave the
// frame incomplete, counted on the TLS listener.
func TestTLSIncompleteFrames(t *testing.T) {
	cfg := tlsConfig(false)
	s, c, pool := startTLS(t, cfg, nil)
	n := 0
	for _, tc := range []struct {
		what   string
		data   string
		notify bool
		want   wantMsg
	}{
		{"complete, close_notify", "9 <13>short", true, wantMsg{raw: "<13>short"}},
		{"close_notify mid-frame", "50 <13>short", true, wantMsg{raw: "<13>short", inc: true, arrived: 9, length: 50}},
		{"TCP close mid-frame", "60 <13>no notify", false, wantMsg{raw: "<13>no notify", inc: true, arrived: 13, length: 60}},
	} {
		raw, err := net.Dial("tcp", tlsAddr(t, s))
		if err != nil {
			t.Fatal(err)
		}
		cl := tls.Client(raw, client(pool))
		if _, err := cl.Write([]byte(tc.data)); err != nil {
			t.Fatal(err)
		}
		if tc.notify {
			cl.Close()
		} else {
			raw.Close()
		}
		n++
		checkMsg(t, tc.what, c.wait(t, n)[n-1], tc.want)
	}
	waitFor(t, "the TLS count", func() bool { return frameOf(s.Status(), "tls").Incomplete == 2 })
	st := s.Status()
	if len(st.Frames) != 1 || st.TCPIncompleteFrames != 2 || st.Truncated != 0 {
		t.Errorf("status %+v", st)
	}
}
