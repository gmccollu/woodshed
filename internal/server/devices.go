package server

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
)

// QueryDevices pages the device list in SQL (index.QueryDevices, security
// review N15: the list used to be built whole for every request). sort=rate
// orders by the index's per-minute stats from the start of the previous whole
// minute (the window msgs_per_min uses); the rate shown is the live one where
// the device has sent since start.
func (b *backend) QueryDevices(ctx context.Context, q api.DeviceQuery) (api.DevicePage, error) {
	now := b.now()
	minute := now.UTC().Truncate(time.Minute)
	k := b.blocker()
	var active map[string][]string
	if !q.ActiveFrom.IsZero() {
		var err error
		if active, err = b.search.Active(ctx, datatype.Names(), q.ActiveFrom, q.ActiveTo); err != nil {
			return api.DevicePage{}, err
		}
	}
	if (q.Sort == "" || q.Sort == "rate") && q.Q == "" {
		page, err := b.devicesByLiveRate(ctx, q, now, k, active)
		k.mark(page.Devices)
		b.markTLS(page.Devices)
		b.markTypes(ctx, page.Devices)
		return page, err
	}
	iq := index.DeviceQuery{
		Limit: q.Limit, Offset: q.Offset, Sort: index.DeviceSort(q.Sort), Q: q.Q, Group: q.Group, Ungrouped: q.Ungrouped,
		Hidden: index.HiddenFilter(q.Hidden), RateFrom: minute.Add(-time.Minute),
	}
	if q.Blocked == "only" || (q.Blocked == "exclude" && !k.empty()) {
		ids, err := b.idx.DeviceIDs(ctx)
		if err != nil {
			return api.DevicePage{}, err
		}
		if bl := k.blockedIDs(ids); q.Blocked == "only" {
			iq.OnlyIDs = bl
		} else {
			iq.NotIDs = bl
		}
	}
	if active != nil {
		var keep map[string]bool
		if iq.OnlyIDs != nil {
			keep = make(map[string]bool, len(iq.OnlyIDs))
			for _, id := range iq.OnlyIDs {
				keep[id] = true
			}
		}
		only := []string{} // not nil: no active device is an empty page
		for id := range active {
			if keep == nil || keep[id] {
				only = append(only, id)
			}
		}
		slices.Sort(only)
		iq.OnlyIDs = only
	}
	page, err := b.idx.QueryDevices(ctx, iq)
	if err != nil {
		return api.DevicePage{}, err
	}
	// The index already summed each page device's messages over the rate
	// window (RecentMsgs); live numbers only for the page's devices.
	rates := rates{from: minute.Add(-time.Minute), counts: make(map[string]index.Counts, len(page.Devices))}
	ids := make([]string, len(page.Devices))
	for i, d := range page.Devices {
		rates.counts[d.ID] = index.Counts{Msgs: d.RecentMsgs}
		ids[i] = d.ID
	}
	quiet := b.config().Quiet
	live := b.live.subset(ids, now)
	out := api.DevicePage{Total: page.Total, Devices: make([]api.Device, 0, len(page.Devices))}
	for _, d := range page.Devices {
		if d.ID == index.RefusedDeviceID {
			continue
		}
		out.Devices = append(out.Devices, withLive(d, live, rates, now, quiet))
	}
	k.mark(out.Devices)
	b.markTLS(out.Devices)
	b.markTypes(ctx, out.Devices)
	return out, nil
}

// Groups serves GET /api/groups from the index.
func (b *backend) Groups(ctx context.Context) ([]api.Group, error) {
	gs, err := b.idx.Groups(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]api.Group, len(gs))
	for i, g := range gs {
		out[i] = api.Group{Name: g.Name, Devices: g.Devices}
	}
	return out, nil
}

// devicesByLiveRate serves sort=rate (the dashboard's busiest devices) without
// summing every device's stats in SQL, which took seconds on a small VM at
// 10,000 devices: it orders the device IDs by the live rate (the msgs_per_min
// shown) and filters by the group and hidden caches the live tail keeps, then
// reads only the page's rows. A search (q) needs names, so it goes through
// QueryDevices.
func (b *backend) devicesByLiveRate(ctx context.Context, q api.DeviceQuery, now time.Time, k blocker, active map[string][]string) (api.DevicePage, error) {
	ids, err := b.idx.DeviceIDs(ctx)
	if err != nil {
		return api.DevicePage{}, err
	}
	groups, hidden := *b.groups.Load(), *b.hidden.Load()
	live := b.live.snapshot(now)
	match := ids[:0]
	for _, id := range ids {
		g, h := groups[id], hidden[id]
		switch {
		case id == index.RefusedDeviceID:
		case q.Hidden == "only" && !h, q.Hidden == "exclude" && h:
		case q.Group != "" && g != q.Group, q.Ungrouped && g != "":
		case q.Blocked == "only" && !k.blocked(id), q.Blocked == "exclude" && k.blocked(id):
		case active != nil && len(active[id]) == 0:
		default:
			match = append(match, id)
		}
	}
	slices.SortStableFunc(match, func(a, c string) int { // ids are sorted, so ties stay by ID
		return cmp.Compare(live[c].MsgsPerMin, live[a].MsgsPerMin)
	})
	out := api.DevicePage{Total: len(match), Devices: []api.Device{}}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if q.Offset >= len(match) {
		return out, nil
	}
	pageIDs := match[q.Offset:min(q.Offset+limit, len(match))]
	minute := now.UTC().Truncate(time.Minute)
	ds, err := b.idx.DevicesByID(ctx, pageIDs, minute.Add(-time.Minute), time.Time{})
	if err != nil {
		return api.DevicePage{}, err
	}
	rs := rates{from: minute.Add(-time.Minute), counts: make(map[string]index.Counts, len(ds))}
	for _, d := range ds {
		rs.counts[d.ID] = index.Counts{Msgs: d.RecentMsgs}
	}
	quiet := b.config().Quiet
	for _, d := range ds {
		out.Devices = append(out.Devices, withLive(d, live, rs, now, quiet))
	}
	return out, nil
}
