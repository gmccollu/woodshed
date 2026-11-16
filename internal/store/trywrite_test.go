package store

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
)

// TryWrite stores only what is a plain buffer append, and otherwise does
// nothing, so a UDP reader can call it without ever waiting on the disk.
func TestTryWrite(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.FlushBytes = 4096; o.PartBytes = 1 << 20 })
	a := ip(1)
	msg := func(s string) model.Message { return model.Message{Received: e.clock.Now(), Sender: a, Raw: []byte(s)} }
	try := func(s string) bool {
		t.Helper()
		ok, err := e.s.TryWrite(msg(s))
		if ok && err != nil {
			t.Fatalf("TryWrite(%q): %v", s, err)
		}
		return ok
	}
	if try("<13>new stream") {
		t.Fatal("a stream that isn't open yet was written (it needs admission and may stat its file)")
	}
	if u := e.s.Usage(); u.Written != 0 || u.Dropped != 0 || u.Devices != 0 {
		t.Fatalf("a refused TryWrite changed something: %+v", u)
	}
	e.write(a, "<13>one") // opens the stream and today's file
	if !try("<13>two") || !try("<13>three") {
		t.Fatal("a plain append was refused")
	}

	// The stream's lock is held (a flush or an fsync in progress): refused at once.
	v, _ := e.s.devices.Load(streamKey{a, 0})
	d := v.(*device)
	d.mu.Lock()
	done := make(chan bool)
	go func() { done <- try("<13>while locked") }()
	select {
	case ok := <-done:
		if ok {
			t.Error("written while the lock was held")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TryWrite waited for the lock")
	}
	d.mu.Unlock()

	// A line that would fill the buffer to FlushBytes needs a flush: refused,
	// and the buffer is as it was.
	d.mu.Lock()
	before := len(d.buf)
	d.mu.Unlock()
	if try("<13>" + strings.Repeat("x", 5000)) {
		t.Error("a line needing a flush was written")
	}
	d.mu.Lock()
	if len(d.buf) != before {
		t.Errorf("buffer %d bytes, was %d", len(d.buf), before)
	}
	d.mu.Unlock()

	// A new day needs a rotation: refused.
	e.clock.Add(24 * time.Hour)
	if try("<13>tomorrow") {
		t.Error("a new day's line was written")
	}
	e.clock.Add(-24 * time.Hour)

	// Paused: dropped and counted, as Write does, without the disk.
	e.s.paused.Store(true)
	if ok, err := e.s.TryWrite(msg("<13>paused")); !ok || !errors.Is(err, ErrPaused) {
		t.Errorf("paused: %v %v", ok, err)
	}
	e.s.paused.Store(false)
	if r := e.s.DropsByReason24h(); r.Paused != 1 {
		t.Errorf("drops %+v", r)
	}

	if err := e.s.Flush(); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range readLines(t, e.dir, model.DeviceID(a)) {
		got = append(got, string(l.Raw()))
	}
	if strings.Join(got, ",") != "<13>one,<13>two,<13>three" {
		t.Errorf("lines %q", got)
	}
	if u := e.s.Usage(); u.Written != 3 {
		t.Errorf("written %d", u.Written)
	}
}

// A line that would start a new part is refused (the rotation renames files).
func TestTryWriteSizeRotation(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.PartBytes = 300 })
	a := ip(2)
	e.write(a, "<13>"+strings.Repeat("a", 200))
	if ok, _ := e.s.TryWrite(model.Message{Received: e.clock.Now(), Sender: a, Raw: []byte("<13>" + strings.Repeat("b", 200))}); ok {
		t.Error("a line past part_bytes was written")
	}
}

// TryWriteType refuses an unknown type as WriteType does.
func TestTryWriteType(t *testing.T) {
	e := newEnv(t, nil)
	if ok, err := e.s.TryWriteType("nope", model.Message{Received: e.clock.Now(), Sender: ip(3), Raw: []byte("x")}); !ok || !errors.Is(err, ErrUnknownType) {
		t.Errorf("%v %v", ok, err)
	}
}
