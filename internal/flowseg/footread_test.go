package flowseg

import (
	"encoding/binary"
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
	for i := range f.Blocks {
		lb := f.Blocks[i]
		if lb.loaded || lb.keys.bits != nil || lb.Rows != closed.Blocks[i].Rows || lb.MaxEnd != closed.Blocks[i].MaxEnd {
			t.Fatalf("block %d: directory entry %+v", i, lb)
		}
		got, err := rd.Block(i)
		if err != nil {
			t.Fatal(err)
		}
		want := closed.Blocks[i]
		if !reflect.DeepEqual(got.keys, want.keys) || got.protos != want.protos || !reflect.DeepEqual(got.inIfs, want.inIfs) ||
			!reflect.DeepEqual(got.Minutes, want.Minutes) || got.Totals != want.Totals {
			t.Fatalf("block %d: index differs from the writer's", i)
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
