package server

import (
	"context"
	"fmt"
	"github.com/gmccollu/woodshed/internal/model"
	"net/netip"
	"slices"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
)

var zeroTime time.Time

// blocker answers "is this device blocked?" from the blocklist in effect.
type blocker struct{ prefixes []netip.Prefix }

func (b *backend) blocker() blocker {
	ps, _ := b.config().Listeners.BlockPrefixes() // validated when saved
	return blocker{prefixes: ps}
}

func (k blocker) empty() bool { return len(k.prefixes) == 0 }

// deviceIP is a device ID's address when the ID alone can say
// (model.ParseDeviceID: not for a zoned ID, which is lossy).
func deviceIP(id string) (netip.Addr, bool) { return model.ParseDeviceID(id) }

// deviceAddr is a device's address from its row's IP column, which keeps an
// IPv6 zone ("fe80::1%5"), and from the ID only when the row has none.
func deviceAddr(id, ip string) (netip.Addr, bool) {
	if ip != "" {
		if a, err := netip.ParseAddr(ip); err == nil {
			return a.Unmap(), true
		}
	}
	return deviceIP(id)
}

// blocked: the device with this ID (and row IP, "" when not at hand) is on
// the blocklist; the listener compares without the zone, so this does too.
func (k blocker) blocked(id string) bool { return k.blockedAt(id, "") }

func (k blocker) blockedAt(id, ip string) bool {
	if k.empty() {
		return false
	}
	a, ok := deviceAddr(id, ip)
	if !ok {
		return false
	}
	a = a.WithZone("")
	for _, p := range k.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// mark sets Blocked and the "blocked" status on the devices the blocklist covers.
func (k blocker) mark(ds []api.Device) {
	if k.empty() {
		return
	}
	for i := range ds {
		if k.blockedAt(ds[i].ID, ds[i].IP) {
			ds[i].Blocked, ds[i].Status = true, statusBlocked
		}
	}
}

// blockedIDs are the devices (of all IDs) the blocklist covers.
func (k blocker) blockedIDs(ids []string) []string {
	out := []string{}
	if k.empty() {
		return out
	}
	for _, id := range ids {
		if k.blocked(id) {
			out = append(out, id)
		}
	}
	return out
}

// setBlocked adds or removes the device's exact address on the blocklist,
// saves the config and applies it to the listeners. It returns the entry that
// still covers the device after an unblock ("" if none).
func (b *backend) setBlocked(ctx context.Context, d index.Device, block bool) (string, error) {
	ip, ok := deviceAddr(d.ID, d.IP)
	if !ok {
		return "", fmt.Errorf("device %q has no address", d.ID)
	}
	b.saveMu.Lock()
	defer b.saveMu.Unlock()
	cur := b.config()
	next := cur.Clone()
	next.Listeners.Blocklist = slices.Clone(cur.Listeners.Blocklist)
	changed := false
	if block {
		changed = next.Listeners.Block(ip)
	} else {
		changed = next.Listeners.Unblock(ip) > 0
	}
	if changed {
		if err := config.Save(b.cfgPath, next); err != nil {
			return "", fmt.Errorf("save the config: %w", err)
		}
		b.cfgMu.Lock()
		b.cfg = next.Clone()
		b.cfgMu.Unlock()
		if ln := b.ln.Load(); ln != nil {
			if err := ln.Reconfigure(next.Listeners); err != nil {
				return "", fmt.Errorf("apply the blocklist: %w", err)
			}
		}
		verb := "blocked"
		if !block {
			verb = "unblocked"
		}
		b.deviceEvent(d.ID, fmt.Sprintf("%s %s by the admin", verb, ip))
	}
	if by, still := next.Listeners.BlockedBy(ip); !block && still {
		return by, nil
	}
	return "", nil
}

// deviceEvent records a device event (index.KindDevice).
func (b *backend) deviceEvent(id, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.idx.AddEvent(ctx, index.Event{Level: index.LevelInfo, Kind: index.KindDevice, DeviceID: id, Text: text}); err != nil {
		b.log.Warn("couldn't record a device event", "err", err, "text", text)
	}
}

// blockedCounts are the non-hidden blocked devices by the status they'd have,
// to take out of /api/stats' online, quiet and offline counts.
func (b *backend) blockedCounts(ctx context.Context, k blocker, onlineSince, quietSince int64) (on, quiet, off int, err error) {
	if k.empty() {
		return 0, 0, 0, nil
	}
	ids, err := b.idx.DeviceIDs(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	bl := k.blockedIDs(ids)
	for len(bl) > 0 {
		n := min(len(bl), 1000)
		ds, err := b.idx.DevicesByID(ctx, bl[:n], zeroTime, zeroTime)
		if err != nil {
			return 0, 0, 0, err
		}
		for _, d := range ds {
			if d.Hidden {
				continue
			}
			switch lh := d.LastHeard.UnixMilli(); {
			case !d.LastHeard.IsZero() && lh >= onlineSince:
				on++
			case !d.LastHeard.IsZero() && lh >= quietSince:
				quiet++
			default:
				off++
			}
		}
		bl = bl[n:]
	}
	return on, quiet, off, nil
}
