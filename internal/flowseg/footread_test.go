package flowseg

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
)

// A closed segment opens with its blocks' directory only: the index (Bloom
// filters, protocol and interface sets) loads per block from the footer's
// copy, the same as the writer's, and isn't kept, so an open segment holds
// a small part of its footer whatever the segment's size.
func TestFooterStreamedAndLight(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.wsf")
	hour := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	w, err := Create(path, "10.1.0.1", hour, "test")
	if err != nil {
		t.Fatal(err)
	}
	const n = 400_000
	r := flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort |
		flow.HasProto | flow.HasBytes | flow.HasInIf, Sampling: 1, Proto: 6}
	for i := 0; i < n; i++ {
		ms := hour.UnixMilli() + int64(i)/100 // full blocks (65,536 rows), the filters' size dominating
		r.Received, r.End, r.Start = ms, ms, ms-100
		// Every address distinct: the Bloom filters' worst case.
		r.Src = netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		r.Dst = netip.AddrFrom4([4]byte{172, byte(i >> 16), byte(i >> 8), byte(i)})
		r.SrcPort, r.DstPort, r.InIf, r.Bytes = uint16(i), uint16(i>>3), uint32(i%7), uint64(i)
		if err := w.Append(&r); err != nil {
			t.Fatal(err)
		}
	}
	closed, err := w.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	b, _ := os.ReadFile(path)
	footLen := int64(binary.LittleEndian.Uint32(b[len(b)-trailerLen:]))
	b = nil

	runtime.GC()
	runtime.GC() // sync.Pool's victims (the writer's compressors) go on the second
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	rd, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	runtime.GC()
	runtime.ReadMemStats(&m1)
	runtime.KeepAlive(w)
	kept := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	t.Logf("%d blocks, segment %d bytes, footer %d bytes; an open reader keeps %d", len(closed.Blocks), st.Size(), footLen, kept)
	if kept > footLen/20 || kept > int64(len(closed.Blocks))*1024+256<<10 {
		t.Fatalf("the open reader keeps %d bytes of a %d-byte footer (%d blocks)", kept, footLen, len(closed.Blocks))
	}
	f := rd.Footer()
	if len(f.Blocks) != len(closed.Blocks) || f.Totals != closed.Totals || !reflect.DeepEqual(f.Minutes, closed.Minutes) {
		t.Fatalf("footer differs: %d blocks %+v", len(f.Blocks), f.Totals)
	}
	sf, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sf.Close()
	for i := range f.Blocks {
		lb, cb := f.Blocks[i], closed.Blocks[i]
		// Close returns the footer as Open reads it: light, pointing at the
		// footer's copies.
		if lb.loaded || lb.keys.bits != nil || cb.loaded || cb.keys.bits != nil || cb.Minutes != nil ||
			!reflect.DeepEqual(lb, cb) {
			t.Fatalf("block %d: directory entry %+v, Close returned %+v", i, lb, cb)
		}
		got, err := rd.Block(i)
		if err != nil {
			t.Fatal(err)
		}
		want := ownHeader(t, sf, st.Size(), lb)
		if !reflect.DeepEqual(got.keys, want.keys) || got.protos != want.protos || !reflect.DeepEqual(got.inIfs, want.inIfs) ||
			!reflect.DeepEqual(got.Minutes, want.Minutes) || got.Totals != want.Totals || got.Rows != want.Rows {
			t.Fatalf("block %d: index differs from the block's own header", i)
		}
		if f.Blocks[i].loaded {
			t.Fatalf("block %d: the index was kept", i)
		}
	}
	// A flipped byte in a block's header copy fails the footer's CRC.
	b, _ = os.ReadFile(path)
	b[f.Blocks[1].hdrOff+3] ^= 0x40
	bad := filepath.Join(dir, "bad.wsf")
	os.WriteFile(bad, b, 0o600)
	if _, err := Open(bad); err == nil {
		t.Fatal("a corrupt footer opened")
	}
}

// ownHeader parses block bi's header from the block section itself (not the
// footer's copy).
func ownHeader(t *testing.T, f io.ReaderAt, size int64, bi BlockInfo) BlockInfo {
	t.Helper()
	magic, body, ok := readSection(f, bi.Offset, size, nil)
	if !ok || magic != magicBlock {
		t.Fatalf("block at %d doesn't read", bi.Offset)
	}
	d := &dec{b: body}
	hdr := d.next(int(d.limit(uint64(len(body)))))
	var own BlockInfo
	readHeader(&dec{b: hdr}, &own)
	if d.err != nil || !own.loaded {
		t.Fatalf("block at %d: its header doesn't parse", bi.Offset)
	}
	return own
}

// The streamed footer is byte for byte what the in-memory encoder wrote
// before (encodeFooterRef, kept as it was), whatever the buffer size: over
// many blocks with raw chunks, rebuilt independently by scanning the
// segment's own sections.
func TestStreamedFooterBytes(t *testing.T) {
	r := rand.New(rand.NewPCG(4, 4))
	recs := make([]flow.Record, 0, 3000)
	for i := 0; i < cap(recs); i++ {
		recs = append(recs, randRecord(r, testHour.UnixMilli()+int64(i)*7, i%3 == 0))
	}
	raws := make([]flow.RawSet, 0, 40)
	for i := 0; i < cap(raws); i++ {
		raws = append(raws, randRaw(r, testHour.UnixMilli()+int64(i)*50))
	}
	old := tailBufSize
	defer func() { tailBufSize = old }()
	for _, bs := range []int{1, 7, 97, 4096, old} {
		tailBufSize = bs
		path, closed := writeSegment(t, t.TempDir(), recs, raws, 50)
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		n := int64(binary.LittleEndian.Uint32(b[len(b)-trailerLen:]))
		bodyOff := int64(len(b)) - trailerLen - n
		body := b[bodyOff : bodyOff+n]
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		h, err := readHeaderAt(f, int64(len(b)))
		if err != nil {
			t.Fatal(err)
		}
		s := scan(f, int64(len(b)), h)
		f.Close()
		ref := s.footer()
		ref.tableOff = s.off
		hdrs := make([][]byte, len(ref.Blocks))
		for i, bi := range ref.Blocks {
			hdrs[i] = b[bi.hdrOff : bi.hdrOff+bi.hdrLen]
		}
		if want := encodeFooterRef(ref, hdrs); !bytes.Equal(body, want) {
			t.Fatalf("buffer %d: the footer body (%d bytes) differs from the reference (%d bytes)", bs, len(body), len(want))
		}
		if len(closed.Blocks) != len(ref.Blocks) || len(closed.Blocks) < 50 || len(closed.RawChunks) == 0 {
			t.Fatalf("%d blocks, %d raw chunks", len(closed.Blocks), len(closed.RawChunks))
		}
		for i, bi := range closed.Blocks {
			// Each entry points at its header's copy inside the footer body.
			if bi.hdrOff < bodyOff || bi.hdrOff+bi.hdrLen > bodyOff+n || !bytes.Equal(b[bi.hdrOff:bi.hdrOff+bi.hdrLen], hdrs[i]) {
				t.Fatalf("buffer %d: block %d's header copy at %d+%d", bs, i, bi.hdrOff, bi.hdrLen)
			}
		}
	}
}

// encodeFooterRef is the footer encoder as it was before the footer was
// streamed (the whole body in memory), kept as the format's reference.
func encodeFooterRef(f *Footer, hdrs [][]byte) []byte {
	b := putUvarint(nil, 1)
	b = putBytes(b, []byte(f.DeviceID))
	b = putVarint(b, f.Hour.UnixMilli())
	b = putBytes(b, []byte(f.WriterVersion))
	b = appendTotals(b, &f.Totals)
	b = putUvarint(b, uint64(f.Raw))
	for _, v := range f.RawStatus {
		b = putUvarint(b, uint64(v))
	}
	b = putVarint(b, f.MinReceived)
	b = putUvarint(b, uint64(f.MaxReceived-f.MinReceived))
	b = putVarint(b, f.MinStart)
	b = putUvarint(b, uint64(f.MaxEnd-f.MinStart))
	b = appendU32s(b, f.Samplings)
	b = appendU32s(b, f.Domains)
	b = appendMinutes(b, f.Minutes)
	b = putUvarint(b, uint64(f.tableOff))
	b = putUvarint(b, uint64(len(f.Blocks)))
	for i := range f.Blocks {
		bi := &f.Blocks[i]
		b = putUvarint(b, uint64(bi.Offset))
		b = putUvarint(b, uint64(bi.Length))
		b = putBytes(b, hdrs[i])
	}
	b = putUvarint(b, uint64(len(f.RawChunks)))
	for _, c := range f.RawChunks {
		b = putUvarint(b, uint64(c.Offset))
		b = putUvarint(b, uint64(c.Length))
		b = putUvarint(b, uint64(c.Count))
		b = putVarint(b, c.MinReceived)
		b = putUvarint(b, uint64(c.MaxReceived-c.MinReceived))
		for _, v := range c.Status {
			b = putUvarint(b, uint64(v))
		}
	}
	return b
}
