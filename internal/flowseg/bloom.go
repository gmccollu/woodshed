package flowseg

import (
	"encoding/binary"
	"math/bits"
	"net/netip"
)

// The block index's Bloom filters (SPEC §13.2): over each record's addresses
// (source, destination and the post-NAT pair), their /24 (IPv4) or /48 (IPv6)
// prefixes, and its ports (source, destination and the post-NAT pair; one
// key space for every port column, so a "port" filter tests one key). Sized
// from the block's distinct keys at bloomBitsPerKey, about 1 % false positives
// with bloomK probes. The hash is fixed (not seeded per process): filters are
// stored on disk.

const (
	bloomBitsPerKey = 10
	bloomK          = 7
	maxBloomBytes   = 4 << 20 // a block's filter, as stored (a corrupt length beyond it is refused)
)

// Key tags, so an address, a prefix and a port never share a key.
const (
	tagAddr   = 1
	tagPfx4   = 2
	tagPfx6   = 3
	tagPort   = 4
	tagIfList = 5
)

func mix64(h uint64) uint64 {
	h ^= h >> 33
	h *= 0xff51afd7ed558ccd
	h ^= h >> 33
	h *= 0xc4ceb9fe1a85ec53
	h ^= h >> 33
	return h
}

// hashWords hashes a tag and two 64-bit words.
func hashWords(tag byte, a, b uint64) uint64 {
	h := mix64(uint64(tag)*0x9e3779b97f4a7c15 ^ a)
	h = mix64(h ^ bits.RotateLeft64(b, 31) ^ 0x2545f4914f6cdd1d)
	return h
}

func addrWords(a netip.Addr) (uint64, uint64) {
	b := a.Unmap().As16()
	return binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
}

func addrKey(a netip.Addr) uint64 {
	x, y := addrWords(a)
	return hashWords(tagAddr, x, y)
}

// prefixKey is the /24 or /48 key of an address.
func prefixKey(a netip.Addr) uint64 {
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return hashWords(tagPfx4, uint64(b[0])<<16|uint64(b[1])<<8|uint64(b[2]), 0)
	}
	b := a.As16()
	return hashWords(tagPfx6, uint64(binary.BigEndian.Uint64(b[:8])>>16), 0)
}

func portKey(p uint16) uint64 { return hashWords(tagPort, uint64(p), 0) }

func ifKey(i uint32) uint64 { return hashWords(tagIfList, uint64(i), 0) }

// bloom is a built filter: k probes over m bits.
type bloom struct {
	k    int
	bits []byte
}

func newBloom(n int) bloom {
	m := n * bloomBitsPerKey
	if m < 64 {
		m = 64
	}
	nb := (m + 7) / 8
	if nb > maxBloomBytes {
		nb = maxBloomBytes
	}
	return bloom{k: bloomK, bits: make([]byte, nb)}
}

func (f bloom) add(h uint64) {
	m := uint64(len(f.bits)) * 8
	h1, h2 := h, (h>>32)|1
	for i := 0; i < f.k; i++ {
		p := (h1 + uint64(i)*h2) % m
		f.bits[p>>3] |= 1 << (p & 7)
	}
}

func (f bloom) has(h uint64) bool {
	if len(f.bits) == 0 || f.k == 0 {
		return false
	}
	m := uint64(len(f.bits)) * 8
	h1, h2 := h, (h>>32)|1
	for i := 0; i < f.k; i++ {
		p := (h1 + uint64(i)*h2) % m
		if f.bits[p>>3]&(1<<(p&7)) == 0 {
			return false
		}
	}
	return true
}

func appendBloom(b []byte, f bloom) []byte {
	b = append(b, byte(f.k))
	return putBytes(b, f.bits)
}

func readBloom(d *dec) bloom {
	k := int(d.byte1())
	bs := d.bytes()
	if d.err == nil && (k == 0 && len(bs) != 0 || k > 32 || len(bs) > maxBloomBytes) {
		d.fail()
	}
	if d.err != nil {
		return bloom{}
	}
	return bloom{k: k, bits: bs}
}

// keySet collects a block's distinct key hashes before the filter is sized.
type keySet map[uint64]struct{}

func (s keySet) addAddr(a netip.Addr) {
	s[addrKey(a)] = struct{}{}
	s[prefixKey(a)] = struct{}{}
}

func (s keySet) bloom() bloom {
	f := newBloom(len(s))
	for h := range s {
		f.add(h)
	}
	return f
}
