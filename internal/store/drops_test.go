package store

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
)

// UDP queue drops count for the sender's device, in dropped_24h's stats, by
// reason, and as one event a minute however many devices they're from.
func TestDropQueued(t *testing.T) {
	e := newEnv(t, nil)
	a, b := ip(1), ip(2)
	e.write(a, "<13>stored")
	e.s.DropQueued(a, e.clock.Now(), 5)
	e.s.DropQueued(b, e.clock.Now(), 3)            // a sender with nothing stored yet gets a device
	e.s.DropQueued(netip.Addr{}, e.clock.Now(), 2) // past the listener's per-sender table
	e.s.DropQueued(a, e.clock.Now(), 0)            // nothing
	if u := e.s.Usage(); u.Dropped != 10 || u.Written != 0 {
		t.Fatalf("usage %+v", u)
	}
	e.clock.Add(2 * time.Minute)
	e.maintain()
	per, _ := e.idx.DeviceCounts(bg, day0.Add(-time.Hour), day0.Add(time.Hour))
	if per["192.0.2.1"].Dropped != 5 || per["192.0.2.1"].Msgs != 1 || per["192.0.2.2"].Dropped != 3 || per[index.RefusedDeviceID].Dropped != 2 {
		t.Fatalf("per device %+v", per)
	}
	if _, dropped, _ := e.idx.DropCounts(bg, e.clock.Now().Add(-24*time.Hour)); dropped != 10 {
		t.Fatalf("dropped_24h %d", dropped)
	}
	if r := e.s.DropsByReason24h(); r != (DropReasons{QueueFull: 10}) {
		t.Fatalf("by reason %+v", r)
	}
	evs := eventsOf(t, e.idx, index.KindDrop)
	if len(evs) != 1 || evs[0].DeviceID != "" || evs[0].Level != index.LevelWarn ||
		!strings.Contains(evs[0].Text, "dropped 10 UDP messages from 2 devices: the UDP receive queue was full") {
		t.Fatalf("events %+v", evs)
	}
	// One device: the event names it.
	e.s.DropQueued(b, e.clock.Now(), 4)
	e.clock.Add(2 * time.Minute)
	e.maintain()
	evs = eventsOf(t, e.idx, index.KindDrop)
	if len(evs) != 2 || evs[1].DeviceID != "192.0.2.2" || !strings.Contains(evs[1].Text, "dropped 4 UDP messages from 1 device:") {
		t.Fatalf("events %+v", evs)
	}
	// 24 hours later they've aged out of the reason counts.
	e.clock.Add(25 * time.Hour)
	if r := e.s.DropsByReason24h(); r != (DropReasons{}) {
		t.Fatalf("by reason a day later %+v", r)
	}
}

// Every kind of drop lands in its reason.
func TestDropsByReason(t *testing.T) {
	e := newEnv(t, func(o *Options) { o.MaxDevices = 1; o.NewDeviceBurst = 1 })
	e.write(ip(1), "<13>one")
	if err := e.s.Write(model.Message{Received: e.clock.Now(), Sender: ip(2), Raw: []byte("refused")}); err == nil {
		t.Fatal("second device admitted")
	}
	// A failed write drops the buffered lines (the other one is already in
	// the buffer).
	e.write(ip(1), "<13>two")
	v, _ := e.s.devices.Load(ip(1))
	d := v.(*device)
	d.mu.Lock()
	d.failBufferLocked(errors.New("disk on fire"))
	d.mu.Unlock()
	e.s.paused.Store(true)
	e.s.Write(model.Message{Received: e.clock.Now(), Sender: ip(1), Raw: []byte("paused")})
	e.s.DropQueued(ip(1), e.clock.Now(), 1)
	if r := e.s.DropsByReason24h(); r != (DropReasons{Paused: 1, WriteError: 2, Refused: 1, QueueFull: 1}) {
		t.Fatalf("by reason %+v", r)
	}
	if u := e.s.Usage(); u.Dropped != 5 {
		t.Fatalf("usage %+v", u)
	}
}
