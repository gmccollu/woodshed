package syslog

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

// The public report: "50 <13>short" then EOF came back exactly like "9 <13>short",
// complete. Now the first is kept and flagged, the second isn't.
func TestStreamReaderIncompleteVsComplete(t *testing.T) {
	for _, tc := range []struct {
		in        string
		short     bool
		arr, want int64
	}{
		{"50 <13>short", true, 9, 50},
		{"9 <13>short", false, 0, 0},
	} {
		sr := NewStreamReader(strings.NewReader(tc.in), 0)
		msg, tr, err := sr.Next()
		if err != nil || string(msg) != "<13>short" || tr {
			t.Fatalf("%q: %q truncated=%v err=%v", tc.in, msg, tr, err)
		}
		arr, length, ok := sr.Incomplete()
		if ok != tc.short || arr != tc.arr || length != tc.want {
			t.Errorf("%q: Incomplete() = %d, %d, %v; want %d, %d, %v", tc.in, arr, length, ok, tc.arr, tc.want, tc.short)
		}
		if _, _, err := sr.Next(); err != io.EOF {
			t.Fatalf("%q: then %v, want io.EOF", tc.in, err)
		}
		if _, _, ok := sr.Incomplete(); ok {
			t.Errorf("%q: Incomplete still set after io.EOF", tc.in)
		}
	}
}

// Incomplete describes only the last message: the next Next clears it.
func TestStreamReaderIncompleteResets(t *testing.T) {
	pr, pw := io.Pipe()
	go func() {
		pw.Write([]byte("6 <13>ab"))
		pw.CloseWithError(syscall.ECONNRESET)
	}()
	sr := NewStreamReader(pr, 0)
	if msg, _, err := sr.Next(); string(msg) != "<13>ab" || err != nil {
		t.Fatalf("first: %q %v", msg, err)
	}
	if _, _, ok := sr.Incomplete(); ok {
		t.Fatal("a complete frame reported incomplete")
	}
	if _, _, err := sr.Next(); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("then %v", err)
	}
}

// A reset (any read error) mid-frame: what arrived is returned, incomplete,
// and the error comes next.
func TestStreamReaderResetMidFrame(t *testing.T) {
	for _, mode := range []string{"whole", "onebyte", "data+err"} {
		var r io.Reader = io.MultiReader(strings.NewReader("6 <13>ab40 <13>partial"), iotest.ErrReader(syscall.ECONNRESET))
		switch mode {
		case "onebyte":
			r = iotest.OneByteReader(r)
		case "data+err":
			r = &dataErrReader{data: []byte("6 <13>ab40 <13>partial"), err: syscall.ECONNRESET}
		}
		sr := NewStreamReader(r, 0)
		got, err := readAll(t, sr, 10)
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("%s: final error %v", mode, err)
		}
		want := []frame{f("<13>ab"), fi("<13>partial", "11/40")}
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("%s: got %v, want %v", mode, got, want)
		}
	}
}

// dataErrReader returns all its data together with err in one Read.
type dataErrReader struct {
	data []byte
	err  error
}

func (d *dataErrReader) Read(p []byte) (int, error) {
	if len(d.data) == 0 {
		return 0, d.err
	}
	n := copy(p, d.data)
	d.data = d.data[n:]
	if len(d.data) == 0 {
		return n, d.err
	}
	return n, nil
}

// A TLS sender that closes mid-frame: with close_notify (a clean TLS EOF) and
// without (the TCP connection just closes).
func TestStreamReaderTLSCloseMidFrame(t *testing.T) {
	cert := selfSigned(t)
	for _, notify := range []bool{true, false} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		sent := make(chan error, 1)
		go func() {
			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				sent <- err
				return
			}
			cli := tls.Client(raw, &tls.Config{InsecureSkipVerify: true})
			if _, err := cli.Write([]byte("8 <13>full50 <13>cut off")); err != nil {
				sent <- err
				return
			}
			if notify {
				sent <- cli.Close() // close_notify, then the TCP close
				return
			}
			sent <- raw.Close() // no close_notify
		}()
		sc, err := ln.Accept()
		ln.Close()
		if err != nil {
			t.Fatal(err)
		}
		srv := tls.Server(sc, &tls.Config{Certificates: []tls.Certificate{cert}})
		srv.SetReadDeadline(time.Now().Add(10 * time.Second))
		got, err := readAll(t, NewStreamReader(srv, 0), 10)
		if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("notify=%v: final error %v", notify, err)
		}
		want := []frame{f("<13>full"), fi("<13>cut off", "11/50")}
		if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
			t.Fatalf("notify=%v: got %v, want %v (final error %v)", notify, got, want, err)
		}
		if e := <-sent; e != nil {
			t.Fatalf("notify=%v: client: %v", notify, e)
		}
		srv.Close()
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
