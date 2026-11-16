package poller

import (
	"encoding/binary"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 15, 10, 0, 0, 0, time.UTC)

func TestCounterDelta(t *testing.T) {
	prev := sample{value: 100, at: t0, ok: true}
	at := t0.Add(60 * time.Second)
	cases := []struct {
		name        string
		prev        sample
		cur         uint64
		kind        counterKind
		bound       uint64
		fwd, disc   bool
		ok, wrapped bool
		delta       uint64
	}{
		{"up", prev, 700, counter64, 0, true, false, true, false, 600},
		{"no prev", sample{}, 700, counter64, 0, true, false, false, false, 0},
		{"c64 drop", prev, 50, counter64, 0, true, false, false, false, 0},
		{"c32 wrap, speed unknown", sample{value: wrap32 - 10, at: t0, ok: true}, 5, counter32, 0, true, false, true, true, 15},
		{"c32 wrap, plausible", sample{value: wrap32 - 10, at: t0, ok: true}, 5, counter32, 1000, true, false, true, true, 15},
		{"c32 wrap, implausible", sample{value: 2000, at: t0, ok: true}, 5, counter32, 1000, true, false, false, false, 0},
		{"c32 drop after restart", sample{value: wrap32 - 10, at: t0, ok: true}, 5, counter32, 0, false, false, false, false, 0},
		{"c32 drop with discontinuity", sample{value: wrap32 - 10, at: t0, ok: true}, 5, counter32, 0, true, true, false, false, 0},
		{"no time", sample{value: 1, at: at, ok: true}, 5, counter64, 0, true, false, false, false, 0},
	}
	for _, c := range cases {
		d := counterDelta(c.prev, c.cur, at, c.kind, c.bound, c.fwd, c.disc)
		if d.ok != c.ok || d.wrapped != c.wrapped || (c.ok && d.delta != c.delta) {
			t.Errorf("%s: %+v", c.name, d)
		}
	}
	// 1.1 x 1000 Mb/s over 60 s, in octets.
	if b := octetBound(1000, 60); b != 8250000000/1 && b != wrap32 {
		t.Errorf("octetBound %d", b)
	}
	if b := octetBound(100, 60); b != 825000000 {
		t.Errorf("octetBound 100 Mb/s: %d", b)
	}
	if octetBound(0, 60) != 0 {
		t.Error("unknown speed has a bound")
	}
}

func TestUptimeDropped(t *testing.T) {
	min := time.Minute
	cases := []struct {
		name      string
		prev, cur uint64
		el        time.Duration
		drop      bool
	}{
		{"forward", 1000, 7000, min, false},
		{"restart", 104518345, 1532, min, true},
		{"497-day wrap", wrap32 - 3000, 3000, min, false},
		{"wrap too far", wrap32 - 3000, 900000, min, true},
		{"small but not near the top", 300000000, 10, min, true},
	}
	for _, c := range cases {
		if got := uptimeDropped(c.prev, c.cur, c.el); got != c.drop {
			t.Errorf("%s: %v", c.name, got)
		}
	}
}

// FuzzRates feeds any sequence of counter values, uptimes and intervals
// through the rate rules (SPEC §12.8): a rate is never negative, a wrap is
// never above its plausibility bound, and every drop is explained by a wrap
// or a discontinuity.
func FuzzRates(f *testing.F) {
	seed := func(vals ...uint64) []byte {
		b := make([]byte, 0, 8*len(vals))
		for _, v := range vals {
			b = binary.BigEndian.AppendUint64(b, v)
		}
		return b
	}
	f.Add(seed(1, 100, 60, 2, 50, 60), true, uint64(1000))
	f.Add(seed(wrap32-5, 7, 60, 5, 1, 60), false, uint64(0))
	f.Add(seed(1<<63, 1, 0, 1<<64-1, 1<<64-1, 1), true, uint64(1))
	f.Fuzz(func(t *testing.T, data []byte, is64 bool, speed uint64) {
		kind := counter32
		if is64 {
			kind = counter64
		}
		speed %= 1 << 20 // Mb/s
		var prev sample
		var prevUp uint64
		at := t0
		for len(data) >= 24 {
			v := binary.BigEndian.Uint64(data)
			up := binary.BigEndian.Uint64(data[8:]) % wrap32
			step := time.Duration(binary.BigEndian.Uint64(data[16:])%3600) * time.Second
			data = data[24:]
			if kind == counter32 {
				v %= wrap32
			}
			at = at.Add(step)
			fwd := !prev.ok || !uptimeDropped(prevUp, up, step)
			var bound uint64
			if prev.ok {
				bound = octetBound(speed, at.Sub(prev.at).Seconds())
			}
			d := counterDelta(prev, v, at, kind, bound, fwd, false)
			if d.ok {
				if d.seconds <= 0 {
					t.Fatalf("a rate over %v s", d.seconds)
				}
				rate := float64(d.delta) / d.seconds
				if rate < 0 {
					t.Fatalf("negative rate %v", rate)
				}
				if v < prev.value {
					if kind == counter64 || !d.wrapped {
						t.Fatalf("a drop %d -> %d accepted without a wrap (%v)", prev.value, v, kind)
					}
					if bound > 0 && d.delta > bound {
						t.Fatalf("a wrap of %d over the bound %d", d.delta, bound)
					}
					if !fwd {
						t.Fatal("a wrap accepted across a restart")
					}
				} else if d.delta != v-prev.value {
					t.Fatalf("delta %d for %d -> %d", d.delta, prev.value, v)
				}
			} else if prev.ok && v >= prev.value && fwd && at.After(prev.at) {
				t.Fatalf("a rise %d -> %d over %v refused", prev.value, v, at.Sub(prev.at))
			}
			prev, prevUp = sample{value: v, at: at, ok: true}, up
		}
	})
}
