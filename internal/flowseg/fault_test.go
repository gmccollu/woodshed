package flowseg

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// Fault injection for the writer (the cut-back promised on Writer): a failed
// write drops what it was writing (the open block, a raw chunk, a template
// chunk) and returns the error, the file is cut back to the last complete
// section, later writes land after good data, and Open, OpenLive and Recover
// all read exactly what was written successfully.

var errInjected = errors.New("injected write failure")

// faultMode is how an armed write fails.
type faultMode int

const (
	faultFail  faultMode = iota // nothing written, an error
	faultShort                  // half the bytes written, an error
)

// faultCfg arms a faultFile.
type faultCfg struct {
	magic     string // the section kind to fail: "WSB1", "WSR1", "WSC1", "WST1" (the tail)
	nth       int    // fail the nth such write (1-based)
	mode      faultMode
	truncFail bool // the Truncate right after the fault fails
	// The tail after the template table (the footer body's buffered writes,
	// its prefix, the trailer): fail the tailNth write, or with tailRead the
	// first read (a header copied from its block).
	tailNth  int
	tailRead bool
}

// faultFile is an *os.File whose nth write of a section kind fails once, and
// whose next Truncate after that can fail too (leaving the torn bytes).
type faultFile struct {
	*os.File
	faultCfg
	mu        sync.Mutex
	seen      int
	fired     bool
	truncNext bool
	inTail    bool // the template table has been written
	tailW     int  // writes since
}

func (f *faultFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	hit := false
	if f.inTail {
		f.tailW++
		if !f.fired && f.tailW == f.tailNth {
			hit, f.fired, f.truncNext = true, true, f.truncFail
		}
	} else if !f.fired && len(p) >= 4 && string(p[:4]) == f.magic {
		f.seen++
		if f.seen == f.nth {
			hit, f.fired, f.truncNext = true, true, f.truncFail
		}
	}
	if len(p) >= 4 && string(p[:4]) == "WST1" {
		f.inTail = true
	}
	f.mu.Unlock()
	if !hit {
		return f.File.WriteAt(p, off)
	}
	if f.mode == faultShort {
		n, err := f.File.WriteAt(p[:len(p)/2], off)
		if err != nil {
			return n, err
		}
		return n, errInjected
	}
	return 0, errInjected
}

func (f *faultFile) ReadAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	hit := f.inTail && f.tailRead && !f.fired
	if hit {
		f.fired, f.truncNext = true, f.truncFail
	}
	f.mu.Unlock()
	if hit {
		return 0, errInjected
	}
	return f.File.ReadAt(p, off)
}

func (f *faultFile) tailWrites() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tailW
}

func (f *faultFile) Truncate(size int64) error {
	f.mu.Lock()
	fail := f.truncNext
	f.truncNext = false
	f.mu.Unlock()
	if fail {
		return errInjected
	}
	return f.File.Truncate(size)
}

func (f *faultFile) didFire() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fired
}

// faultRecord is phase p's ith record: the sequence number travels in src_as.
func faultRecord(seq int, recv int64, tmpl *flow.Template) flow.Record {
	return flow.Record{Has: flow.HasSrc | flow.HasDst | flow.HasBytes | flow.HasPackets | flow.HasEnd | flow.HasStart | flow.HasSrcAS,
		Received: recv, End: recv - 500, Start: recv - 2000, Src: netip.AddrFrom4([4]byte{10, 0, byte(seq >> 8), byte(seq)}),
		Dst: netip.MustParseAddr("198.51.100.7"), Bytes: uint64(100 + seq), Packets: 1, Sampling: 1, SrcAS: uint32(seq),
		Template: tmpl, TemplateID: tmpl.ID, Version: flow.IPFIX, ExporterPort: 40000, Domain: 1}
}

// phaseTemplate is a template first used in phase p (so each phase's first
// flush writes a template chunk).
func phaseTemplate(p int) *flow.Template {
	return &flow.Template{Version: flow.IPFIX, ExporterPort: 40000, Domain: 1, ID: uint16(300 + p), Received: testHour.UnixMilli() + int64(p),
		Fields: []flow.TemplateField{{ID: 8, Length: 4}, {ID: 12, Length: 4}, {ID: 1, Length: 8}}}
}

const (
	faultPhases    = 6
	faultPerPhase  = 40
	faultFirstRecv = int64(1_000_000)
)

// faultRun is what a run wrote, as the writer reported it.
type faultRun struct {
	path        string
	wantSeqs    map[int]bool // records in blocks written successfully
	wantRaws    int
	minuteRecs  int64 // records TakeMinutes reported
	closeErr    error
	gotErrPhase int // the phase whose write failed (-1: none)
}

// runFaulted writes faultPhases phases (each: records, a raw set, then an
// explicit Flush, or with auto set the 1 s rule's flush inside the next
// phase's first Append), then Close, with the configured fault armed.
func runFaulted(t *testing.T, cfg faultCfg, auto bool, metaAtClose bool) (faultRun, *faultFile) {
	t.Helper()
	noSync(t)
	var ff *faultFile
	old := wrapFile
	wrapFile = func(f *os.File) segFile {
		ff = &faultFile{File: f, faultCfg: cfg}
		return ff
	}
	defer func() { wrapFile = old }()
	dir := t.TempDir()
	path := filepath.Join(dir, NameFor(testHour).String())
	w, err := Create(path, "10.1.0.1", testHour, "2.0.0-test")
	if err != nil {
		t.Fatal(err)
	}
	run := faultRun{path: path, wantSeqs: map[int]bool{}, gotErrPhase: -1}
	take := func() {
		for _, m := range w.TakeMinutes() {
			run.minuteRecs += m.Records
		}
	}
	pending := map[int]bool{} // records in the open block
	pendingRaw := 0
	seq := 0
	for p := 0; p < faultPhases; p++ {
		tmpl := phaseTemplate(p)
		recv := faultFirstRecv + int64(p)*1000
		for i := 0; i < faultPerPhase; i++ {
			r := faultRecord(seq, recv+int64(i), tmpl)
			before := ff.didFire()
			err := w.Append(&r)
			if err != nil {
				// The 1 s rule's flush failed: the open block is gone, and so is
				// this record.
				if !errors.Is(err, errInjected) || before {
					t.Fatalf("phase %d: Append: %v", p, err)
				}
				run.gotErrPhase = p
				pending = map[int]bool{}
				midReaders(t, w, run)
			} else {
				if auto && i == 0 && p > 0 {
					// The flush inside this Append wrote the previous block.
					for s := range pending {
						if s != seq {
							run.wantSeqs[s] = true
						}
					}
					pending = map[int]bool{}
				}
				pending[seq] = true
			}
			seq++
		}
		raw := flow.RawSet{Received: recv + 5, ExporterPort: 40000, Domain: 1, Version: flow.IPFIX, TemplateID: uint16(900 + p),
			Status: flow.StatusNoTemplate, Header: []byte{0, 10}, Data: []byte(fmt.Sprintf("raw %d", p))}
		if err := w.AppendRaw(&raw); err != nil {
			t.Fatalf("AppendRaw: %v", err)
		}
		pendingRaw++
		if auto && p < faultPhases-1 {
			continue
		}
		// An explicit flush: the block, then the raw sets.
		blockFired, rawFired := false, false
		beforeFired := ff.didFire()
		err := w.Flush()
		if err != nil {
			if !errors.Is(err, errInjected) || beforeFired {
				t.Fatalf("phase %d: Flush: %v", p, err)
			}
			run.gotErrPhase = p
			if ff.magic == "WSR1" {
				rawFired = true
			} else {
				blockFired = true
			}
		}
		if !blockFired {
			for s := range pending {
				run.wantSeqs[s] = true
			}
		}
		if !rawFired {
			run.wantRaws += pendingRaw
		}
		pending, pendingRaw = map[int]bool{}, 0
		take()
		if err != nil {
			// Right after the fault (torn bytes may still sit at the end when the
			// truncate failed), a live reader and a snapshot reader see exactly
			// the sections written so far.
			midReaders(t, w, run)
		}
	}
	if metaAtClose {
		w.SetMeta([]byte("meta at close"))
	}
	_, run.closeErr = w.Close()
	take()
	return run, ff
}

// readSeqs reads every record's sequence number and the raw set count.
func readSeqs(t *testing.T, r *Reader) (map[int]int, int) {
	t.Helper()
	seqs := map[int]int{}
	for i := 0; i < r.Blocks(); i++ {
		recs, err := r.ReadBlock(i, ColAll, nil)
		if err != nil {
			t.Fatalf("block %d: %v", i, err)
		}
		for _, rec := range recs {
			seqs[int(rec.SrcAS)]++
			if rec.Template == nil || rec.Template.ID != rec.TemplateID {
				t.Fatalf("record %d lost its template: %+v", rec.SrcAS, rec.Template)
			}
		}
	}
	raws := 0
	if err := r.Raw(func(*flow.RawSet) bool { raws++; return true }); err != nil {
		t.Fatal(err)
	}
	return seqs, raws
}

func checkSeqs(t *testing.T, what string, got map[int]int, want map[int]bool) {
	t.Helper()
	for s, n := range got {
		if n != 1 || !want[s] {
			t.Fatalf("%s: record %d read %d times (written successfully: %v)", what, s, n, want[s])
		}
	}
	if len(got) != len(want) {
		var missing []int
		for s := range want {
			if got[s] == 0 {
				missing = append(missing, s)
			}
		}
		sort.Ints(missing)
		t.Fatalf("%s: %d records, want %d; missing %v", what, len(got), len(want), missing)
	}
}

// checkRun reads the closed (or recovered) segment every way and compares it
// with what the writer reported as written.
func checkRun(t *testing.T, run faultRun) {
	t.Helper()
	before, err := os.ReadFile(run.path)
	if err != nil {
		t.Fatal(err)
	}
	live, err := OpenLive(run.path)
	if err != nil {
		t.Fatalf("OpenLive: %v", err)
	}
	ls, lr := readSeqs(t, live)
	live.Close()
	checkSeqs(t, "OpenLive", ls, run.wantSeqs)
	if after, _ := os.ReadFile(run.path); !bytes.Equal(before, after) {
		t.Fatal("OpenLive changed the file")
	}
	rr, err := Recover(run.path)
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if run.closeErr == nil && (!rr.Clean || rr.CutBytes != 0) {
		t.Fatalf("Recover of a cleanly closed segment changed it: %+v", rr)
	}
	r, err := Open(run.path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	opened, oraw := readSeqs(t, r)
	checkSeqs(t, "Open", opened, run.wantSeqs)
	if oraw != run.wantRaws || lr != run.wantRaws {
		t.Fatalf("raw sets: Open %d, OpenLive %d, want %d", oraw, lr, run.wantRaws)
	}
	f := r.Footer()
	var minuteRecs int64
	for _, m := range f.Minutes {
		minuteRecs += m.Records
	}
	if f.Totals.Records != int64(len(run.wantSeqs)) || minuteRecs != f.Totals.Records || f.Raw != int64(run.wantRaws) {
		t.Fatalf("footer: %d records (%d in minutes), %d raw; want %d, %d", f.Totals.Records, minuteRecs, f.Raw,
			len(run.wantSeqs), run.wantRaws)
	}
	if run.closeErr == nil && run.minuteRecs != f.Totals.Records {
		t.Fatalf("TakeMinutes reported %d records, the segment holds %d", run.minuteRecs, f.Totals.Records)
	}
	if run.minuteRecs > f.Totals.Records {
		t.Fatalf("TakeMinutes counted %d records, more than the %d stored", run.minuteRecs, f.Totals.Records)
	}
}

// Every section kind failing, whole or short, with the cut-back's truncate
// working or failing: the writer goes on, and every reader agrees on what
// was written.
func TestWriterFaults(t *testing.T) {
	for _, magic := range []string{"WSB1", "WSR1", "WSC1"} {
		for _, mode := range []faultMode{faultFail, faultShort} {
			for _, truncFail := range []bool{false, true} {
				for _, nth := range []int{1, 3, faultPhases} {
					for _, auto := range []bool{false, true} {
						name := fmt.Sprintf("%s/mode%d/truncfail=%v/nth%d/auto=%v", magic, mode, truncFail, nth, auto)
						t.Run(name, func(t *testing.T) {
							run, ff := runFaulted(t, faultCfg{magic: magic, nth: nth, mode: mode, truncFail: truncFail}, auto, false)
							if !ff.didFire() {
								if magic == "WSR1" && auto && nth > 1 {
									return // raw sets go out in one chunk at the end with auto flushes
								}
								t.Fatal("the fault never fired")
							}
							if run.gotErrPhase < 0 {
								t.Fatal("the fault fired but no call returned an error")
							}
							if run.closeErr != nil {
								t.Fatalf("Close after the fault: %v", run.closeErr)
							}
							checkRun(t, run)
						})
					}
				}
			}
		}
	}
}

// Close failing (its template chunk, or the tail: table, footer, trailer),
// whole, short or with the truncate failing: Close returns the error, and
// Recover finishes the segment with every block written before.
func TestWriterCloseFaults(t *testing.T) {
	for _, tc := range []struct {
		magic string
		meta  bool
	}{{"WST1", false}, {"WSC1", true}} {
		for _, mode := range []faultMode{faultFail, faultShort} {
			for _, truncFail := range []bool{false, true} {
				name := fmt.Sprintf("%s/mode%d/truncfail=%v", tc.magic, mode, truncFail)
				t.Run(name, func(t *testing.T) {
					// The template chunks of the phases come first: fail only the one at close.
					nth := 1
					if tc.magic == "WSC1" {
						nth = faultPhases + 1
					}
					run, ff := runFaulted(t, faultCfg{magic: tc.magic, nth: nth, mode: mode, truncFail: truncFail}, false, tc.meta)
					if !ff.didFire() || !errors.Is(run.closeErr, errInjected) {
						t.Fatalf("fired %v, Close: %v", ff.didFire(), run.closeErr)
					}
					if _, err := Open(run.path); !errors.Is(err, ErrNoFooter) {
						t.Fatalf("Open after a failed Close: %v, want ErrNoFooter", err)
					}
					checkRun(t, run)
				})
			}
		}
	}
}

// Close failing inside the streamed tail, at every write after the
// template table (each buffered piece of the footer body, its prefix, the
// trailer) and at a header's read, whole, short or with the truncate
// failing: Close returns the error, nothing opens as closed, and Recover
// finishes the segment with every block written before.
func TestWriterTailFaults(t *testing.T) {
	old := tailBufSize
	tailBufSize = 64 // many small writes, each header split over several
	defer func() { tailBufSize = old }()
	// An unarmed run counts the tail's writes.
	_, ff := runFaulted(t, faultCfg{tailNth: -1}, false, false)
	total := ff.tailWrites()
	if total < 10 {
		t.Fatalf("only %d writes after the table", total)
	}
	type tc struct {
		nth  int
		read bool
	}
	var cases []tc
	for n := 1; n <= total; n++ {
		cases = append(cases, tc{nth: n})
	}
	cases = append(cases, tc{read: true})
	for _, c := range cases {
		for _, mode := range []faultMode{faultFail, faultShort} {
			for _, truncFail := range []bool{false, true} {
				if c.read && mode == faultShort {
					continue
				}
				name := fmt.Sprintf("write%d of %d/read=%v/mode%d/truncfail=%v", c.nth, total, c.read, mode, truncFail)
				t.Run(name, func(t *testing.T) {
					run, ff := runFaulted(t, faultCfg{tailNth: c.nth, tailRead: c.read, mode: mode, truncFail: truncFail}, false, false)
					if !ff.didFire() || !errors.Is(run.closeErr, errInjected) {
						t.Fatalf("fired %v, Close: %v", ff.didFire(), run.closeErr)
					}
					if _, err := Open(run.path); !errors.Is(err, ErrNoFooter) {
						t.Fatalf("Open after a failed Close: %v, want ErrNoFooter", err)
					}
					checkRun(t, run)
				})
			}
		}
	}
}

// midReaders checks OpenLive and OpenSnapshot against what was written so far.
func midReaders(t *testing.T, w *Writer, run faultRun) {
	t.Helper()
	live, err := OpenLive(run.path)
	if err != nil {
		t.Fatalf("OpenLive mid-run: %v", err)
	}
	ls, lr := readSeqs(t, live)
	live.Close()
	checkSeqs(t, "OpenLive mid-run", ls, run.wantSeqs)
	snap, err := OpenSnapshot(run.path, w.Snapshot())
	if err != nil {
		t.Fatalf("OpenSnapshot mid-run: %v", err)
	}
	ss, sr := readSeqs(t, snap)
	snap.Close()
	checkSeqs(t, "OpenSnapshot mid-run", ss, run.wantSeqs)
	if lr != run.wantRaws || sr != run.wantRaws {
		t.Fatalf("mid-run raw sets: live %d, snapshot %d, want %d", lr, sr, run.wantRaws)
	}
}
