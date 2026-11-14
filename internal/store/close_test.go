package store

import (
	"fmt"
	"math/rand"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// Close with the background workers running, syslog and trap streams open on
// several devices, closed files waiting for the closer pool and a compression
// in progress: it finishes promptly, abandoning the compression (redone at the
// next Open) and leaving every message on disk and in the index.
func TestCloseWithOpenStreamsAndCompression(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()
	clock := newClock(day0)
	opts := Options{DataDir: dir, Index: idx, Clock: clock.Now, Logger: quiet, PartBytes: 256 << 10,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }}
	s, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	inGzip := make(chan struct{}, 64)
	s.testHookGzip = func(string) {
		select {
		case inGzip <- struct{}{}:
		default:
		}
		time.Sleep(300 * time.Millisecond) // a slow (throttled) compression pass
	}
	r := rand.New(rand.NewSource(1))
	write := func(n int) int {
		total := 0
		for i := 0; i < n; i++ {
			for d := 1; d <= 8; d++ {
				m := model.Message{Received: clock.Now(), Sender: ip(d), Raw: []byte(fmt.Sprintf("<13>syslog %d %s", i, randText(r, 300)))}
				if err := s.Write(m); err != nil {
					t.Fatal(err)
				}
				m.Raw = []byte(fmt.Sprintf("v=2c pdu=trap id=%d status=ok vb=1.3.6.1.4.1.32473.1.1.1.0:str:\"%s\" raw=AA==", i, randText(r, 300)))
				if err := s.WriteType(logfile.TypeTrap, m); err != nil {
					t.Fatal(err)
				}
				total += 2
			}
		}
		return total
	}
	sent := write(2000) // several parts per device and type: closed files to fsync and gzip
	select {
	case <-inGzip:
	case <-time.After(20 * time.Second):
		t.Fatal("no compression started")
	}
	sent += write(50) // and fresh data in every open stream
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("Close took %v", took)
	if took > 3*time.Second {
		t.Fatalf("Close took %v", took)
	}
	// Everything written is in the files and the index; the next Open finishes
	// the abandoned compression.
	files, _ := idx.Files(bg, "")
	var lines int64
	types := map[string]int{}
	for _, f := range files {
		lines += f.Lines
		types[logfile.NormType(f.Type)]++
	}
	if lines != int64(sent) || types["syslog"] == 0 || types["trap"] == 0 {
		t.Fatalf("index: %d lines of %d, files by type %v", lines, sent, types)
	}
	s2, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	if _, temps, err := logfile.List(dir); err != nil || len(temps) != 0 {
		t.Fatalf("temps %v %v", temps, err)
	}
}

// compressEnv is a running (not Manual) store with closed files of both types
// waiting for the compressor.
func compressEnv(t *testing.T, hooks func(*Store)) (*Store, Options, string) {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { idx.Close() })
	clock := newClock(day0)
	opts := Options{DataDir: dir, Index: idx, Clock: clock.Now, Logger: quiet, PartBytes: 64 << 10,
		DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }}
	s, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	hooks(s)
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 600; i++ {
		m := model.Message{Received: clock.Now(), Sender: ip(1), Raw: []byte("<13>" + randText(r, 300))}
		if err := s.Write(m); err != nil {
			t.Fatal(err)
		}
		m.Raw = []byte("v=2c pdu=trap status=ok vb=1.3.6.1.4.1.32473.1.1.1.0:str:\"" + randText(r, 300) + "\" raw=AA==")
		if err := s.WriteType(logfile.TypeTrap, m); err != nil {
			t.Fatal(err)
		}
	}
	return s, opts, dir
}

// gzCount counts the compressed files and the temp files on disk.
func gzCount(t *testing.T, dir string) (gz, temps int) {
	t.Helper()
	ents, tmps, err := logfile.List(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.Name.Compressed {
			gz++
		}
	}
	return gz, len(tmps)
}

// The CI failure (TestTLSRenewRequestAtStart, macOS): Close waited for the
// compressor goroutine, whose OS thread had just been put in the background
// band and wasn't scheduled for seconds on a busy machine (its stack: in
// Setpriority from lowerThreadPriority). Close no longer depends on that thread.
func TestCloseDoesntWaitForAStarvedCompressor(t *testing.T) {
	release := make(chan struct{})
	stalled := make(chan struct{})
	s, opts, dir := compressEnv(t, func(s *Store) {
		s.testHookLowerPrio = func() { close(stalled); <-release } // a thread the OS doesn't run
	})
	select {
	case <-stalled:
	case <-time.After(20 * time.Second):
		t.Fatal("the compressor never had work")
	}
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > compressorStopWait+2*time.Second {
		t.Fatalf("Close took %v", took)
	}
	gzBefore, _ := gzCount(t, dir)
	// The thread runs again: it changes nothing, and exits.
	close(release)
	select {
	case <-s.compDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the compressor didn't exit")
	}
	if gz, temps := gzCount(t, dir); gz != gzBefore || temps != 0 {
		t.Fatalf("after Close: %d gz (was %d), %d temp files", gz, gzBefore, temps)
	}
	// The next Open compresses what's waiting.
	s2, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for gz, _ := gzCount(t, dir); gz == 0; gz, _ = gzCount(t, dir) {
		if time.Now().After(deadline) {
			t.Fatal("nothing compressed after reopening")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
}

// A compression caught by Close between its gzip and its commit never commits
// afterwards: the original stays, no .gz appears, and its temp file is removed.
func TestNoCompressionCommitsAfterClose(t *testing.T) {
	inGzip := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	s, _, dir := compressEnv(t, func(s *Store) {
		s.testHookGzip = func(string) {
			once.Do(func() { close(inGzip); <-release })
		}
	})
	select {
	case <-inGzip:
	case <-time.After(20 * time.Second):
		t.Fatal("no compression started")
	}
	gzBefore, _ := gzCount(t, dir)
	start := time.Now()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > compressorStopWait+2*time.Second {
		t.Fatalf("Close took %v", took)
	}
	close(release)
	select {
	case <-s.compDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the compressor didn't exit")
	}
	if gz, temps := gzCount(t, dir); gz != gzBefore || temps != 0 {
		t.Fatalf("after Close: %d gz (was %d), %d temp files", gz, gzBefore, temps)
	}
}
