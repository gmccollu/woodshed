package flowseg

import (
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/gmccollu/woodshed/internal/flow"
)

// The block index never rules out a block holding a match: for random
// records and random filters, whenever a full scan of a block finds a match,
// the index says "may".
func TestIndexNeverSkipsAMatch(t *testing.T) {
	r := rand.New(rand.NewPCG(1234, 5678))
	dir := t.TempDir()
	falsePos, absent := 0, 0
	for seg := 0; seg < 6; seg++ {
		os.MkdirAll(filepath.Join(dir, string(rune('a'+seg))), 0o700)
		var recs []flow.Record
		recv := testHour.UnixMilli()
		hosts := []int{5, 60, 300, 5000}[seg%4]
		for i := 0; i < 4000; i++ {
			rec := randRecord(r, recv, false)
			if rec.Is(flow.HasSrc) {
				rec.Src = randAddr(r, hosts)
			}
			if r.IntN(80) == 0 { // many interfaces in a few blocks: the Bloom form
				rec.Has |= flow.HasInIf
				rec.InIf = uint32(r.IntN(1000))
			}
			recs = append(recs, rec)
			if r.IntN(500) == 0 {
				recv += 1000
			}
		}
		path, _ := writeSegment(t, filepath.Join(dir, string(rune('a'+seg))), recs, nil, 300+r.IntN(900))
		rd, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		for bi := 0; bi < rd.Blocks(); bi++ {
			info, err := rd.Block(bi)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := rd.ReadBlock(bi, ColAll, nil)
			if err != nil {
				t.Fatal(err)
			}
			for q := 0; q < 300; q++ {
				f := randFilter(r, rows)
				match := false
				for i := range rows {
					if f.match(&rows[i]) {
						match = true
						break
					}
				}
				may := f.may(info)
				if match && !may {
					t.Fatalf("segment %d block %d: index skips a match for %+v", seg, bi, f)
				}
				if !match && f.kind == "addr" {
					absent++
					if may {
						falsePos++
					}
				}
			}
		}
		rd.Close()
	}
	if absent < 1000 {
		t.Fatalf("only %d absent-address probes", absent)
	}
	if rate := float64(falsePos) / float64(absent); rate > 0.03 {
		t.Fatalf("address false positives %.2f%% (%d of %d)", 100*rate, falsePos, absent)
	}
	t.Logf("address false positives: %d of %d", falsePos, absent)
}

type testFilter struct {
	kind string
	addr netip.Addr
	pfx  netip.Prefix
	port uint16
	val  uint32
}

func randFilter(r *rand.Rand, rows []flow.Record) testFilter {
	kinds := []string{"addr", "prefix", "port", "proto", "inif", "outif"}
	f := testFilter{kind: kinds[r.IntN(len(kinds))]}
	row := &rows[r.IntN(len(rows))]
	fromRow := r.IntN(2) == 0
	switch f.kind {
	case "addr", "prefix":
		a := randAddr(r, 6000)
		if fromRow {
			for _, c := range []netip.Addr{row.Src, row.Dst, row.PostNATSrc, row.PostNATDst} {
				if c.IsValid() {
					a = c
					break
				}
			}
		}
		f.addr = a
		bitsMax := 32
		if !a.Is4() {
			bitsMax = 128
		}
		f.pfx = netip.PrefixFrom(a, r.IntN(bitsMax+1)).Masked()
	case "port":
		f.port = uint16(r.IntN(65536))
		if fromRow {
			f.port = []uint16{row.SrcPort, row.DstPort, row.PostNATSrcPort, row.PostNATDstPort}[r.IntN(4)]
		}
	case "proto":
		f.val = uint32(r.IntN(256))
		if fromRow {
			f.val = uint32(row.Proto)
		}
	case "inif", "outif":
		f.val = uint32(r.IntN(1 << 20))
		if fromRow {
			f.val = []uint32{row.InIf, row.OutIf}[r.IntN(2)]
		}
	}
	return f
}

func (f testFilter) match(rec *flow.Record) bool {
	type av struct {
		bit uint64
		a   netip.Addr
	}
	addrs := []av{{flow.HasSrc, rec.Src}, {flow.HasDst, rec.Dst}, {flow.HasPostNATSrc, rec.PostNATSrc}, {flow.HasPostNATDst, rec.PostNATDst}}
	switch f.kind {
	case "addr":
		for _, x := range addrs {
			if rec.Has&x.bit != 0 && x.a == f.addr {
				return true
			}
		}
	case "prefix":
		for _, x := range addrs {
			if rec.Has&x.bit != 0 && f.pfx.Contains(x.a) {
				return true
			}
		}
	case "port":
		for _, x := range []struct {
			bit uint64
			p   uint16
		}{{flow.HasSrcPort, rec.SrcPort}, {flow.HasDstPort, rec.DstPort}, {flow.HasPostNATSrcPort, rec.PostNATSrcPort},
			{flow.HasPostNATDstPort, rec.PostNATDstPort}} {
			if rec.Has&x.bit != 0 && x.p == f.port {
				return true
			}
		}
	case "proto":
		return rec.Is(flow.HasProto) && uint32(rec.Proto) == f.val
	case "inif":
		return rec.Is(flow.HasInIf) && rec.InIf == f.val
	case "outif":
		return rec.Is(flow.HasOutIf) && rec.OutIf == f.val
	}
	return false
}

func (f testFilter) may(b *BlockInfo) bool {
	switch f.kind {
	case "addr":
		return b.MayHaveAddr(f.addr)
	case "prefix":
		return b.MayHavePrefix(f.pfx)
	case "port":
		return b.MayHavePort(f.port)
	case "proto":
		return b.HasProto(uint8(f.val))
	case "inif":
		return b.MayHaveInIf(f.val)
	case "outif":
		return b.MayHaveOutIf(f.val)
	}
	return true
}

// Prefixes shorter than the indexed /24 and /48 can't rule anything out; an
// IPv4-mapped prefix is read as IPv4.
func TestMayHavePrefixForms(t *testing.T) {
	recs := []flow.Record{{Has: flow.HasSrc, Src: netip.MustParseAddr("10.1.2.3"), Received: 1}}
	path, _ := writeSegment(t, t.TempDir(), recs, nil, 0)
	rd, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()
	b, _ := rd.Block(0)
	for s, want := range map[string]bool{
		"10.1.2.0/24": true, "10.1.3.0/24": false, "10.1.2.3/32": true, "10.1.2.4/32": false, "10.1.2.0/30": true,
		"10.1.2.4/30": true, // same /24: can't tell
		"10.0.0.0/8":  true, "::ffff:10.1.3.0/120": false, "::ffff:10.1.2.0/120": true, "2001:db8::/48": false,
		"2001:db8::/32": true,
	} {
		if got := b.MayHavePrefix(netip.MustParsePrefix(s)); got != want {
			t.Errorf("%s: %v", s, got)
		}
	}
	if b.MayHavePort(0) || b.AnyProto() || b.MayHaveInIf(0) {
		t.Error("absent columns must rule a block out")
	}
}
