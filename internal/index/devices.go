package index

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// DeviceSort orders a device page (docs/api.md: GET /api/devices). Directions are
// fixed: rate busiest first, name A–Z (unnamed devices by IP), last_heard and
// first_seen newest first. Ties break by ID.
type DeviceSort string

// Device sort orders.
const (
	SortRate      DeviceSort = "rate"
	SortName      DeviceSort = "name"
	SortLastHeard DeviceSort = "last_heard"
	SortFirstSeen DeviceSort = "first_seen"
)

// HiddenFilter selects hidden devices in a page.
type HiddenFilter string

// Hidden filters.
const (
	HiddenInclude HiddenFilter = "include"
	HiddenOnly    HiddenFilter = "only"
	HiddenExclude HiddenFilter = "exclude"
)

// DeviceQuery is one page of the device list. Zero values: Limit 200 (capped at
// 1,000), Offset 0, SortRate, HiddenInclude.
type DeviceQuery struct {
	Limit, Offset int
	Sort          DeviceSort
	// Q matches the ID, IP or name as a case-insensitive substring (ASCII case
	// folding, as SQLite's lower()).
	Q         string
	Group     string // only this group
	Ungrouped bool   // only devices without a group (ignored if Group is set)
	Hidden    HiddenFilter
	// OnlyIDs, if set, limits the page to these devices; NotIDs leaves these
	// out (for filters the index can't compute, such as the blocklist's CIDRs).
	OnlyIDs, NotIDs []string
	// RateFrom and RateTo bound the stats summed into Device.RecentMsgs, which
	// SortRate orders by. The API uses the last full minute for msgs_per_min.
	RateFrom, RateTo time.Time
}

// DevicePage is a page of devices and the total matching the filters.
type DevicePage struct {
	Devices []Device
	Total   int
}

// GroupCount is a group and its number of non-hidden devices.
type GroupCount struct {
	Name    string
	Devices int
}

// QueryDevices returns a page of devices, filtered, sorted and paged in SQL.
func (d *DB) QueryDevices(ctx context.Context, q DeviceQuery) (DevicePage, error) {
	if q.Limit <= 0 {
		q.Limit = 200
	}
	q.Limit = min(q.Limit, 1000)
	q.Offset = max(q.Offset, 0)
	where := []string{"1=1"}
	var args []any
	if q.Q != "" {
		where = append(where, `(instr(lower(d.id), lower(?)) > 0 OR instr(lower(d.ip), lower(?)) > 0 OR instr(lower(d.name), lower(?)) > 0)`)
		args = append(args, q.Q, q.Q, q.Q)
	}
	switch {
	case q.Group != "":
		where = append(where, `d.grp = ?`)
		args = append(args, q.Group)
	case q.Ungrouped:
		where = append(where, `d.grp = ''`)
	}
	if q.OnlyIDs != nil {
		if len(q.OnlyIDs) == 0 {
			return DevicePage{}, nil
		}
		in, a := inList(q.OnlyIDs)
		where = append(where, `d.id IN `+in)
		args = append(args, a...)
	}
	if len(q.NotIDs) > 0 {
		in, a := inList(q.NotIDs)
		where = append(where, `d.id NOT IN `+in)
		args = append(args, a...)
	}
	switch q.Hidden {
	case HiddenOnly:
		where = append(where, `d.hidden = 1`)
	case HiddenExclude:
		where = append(where, `d.hidden = 0`)
	case "", HiddenInclude:
	default:
		return DevicePage{}, fmt.Errorf("index: unknown hidden filter %q", q.Hidden)
	}
	w := strings.Join(where, " AND ")
	var page DevicePage
	if err := d.db.QueryRowContext(ctx, `SELECT count(*) FROM devices d WHERE `+w, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	var order string
	switch q.Sort {
	case "", SortRate:
		order = `rate DESC, d.id`
	case SortName:
		order = `CASE WHEN d.name = '' THEN d.ip ELSE d.name END COLLATE NOCASE, d.id`
	case SortLastHeard:
		order = `d.last_heard DESC, d.id`
	case SortFirstSeen:
		order = `d.first_seen DESC, d.id`
	default:
		return page, fmt.Errorf("index: unknown device sort %q", q.Sort)
	}
	rateFrom, rateTo := ms(q.RateFrom.Truncate(time.Minute)), int64(1<<62-1)
	if !q.RateTo.IsZero() {
		rateTo = ms(q.RateTo)
	}
	// Pick the page's IDs first, from cheap columns (indexes serve the time and
	// name orders), then read the costly columns (bytes on disk, the rate) for
	// those rows only. Computing them for every device before sorting made a
	// page of 30 cost all 10,000 (review N15, slow machines).
	var inner string
	inArgs := args
	if q.Sort == "" || q.Sort == SortRate {
		inner = `SELECT d.id FROM devices d
			LEFT JOIN (SELECT device_id, sum(msgs) AS rate FROM (
				SELECT device_id, msgs FROM stats WHERE minute >= ? AND minute < ?
				UNION ALL SELECT device_id, msgs FROM type_stats WHERE minute >= ? AND minute < ?) GROUP BY device_id) r
			ON r.device_id = d.id WHERE ` + w + ` ORDER BY COALESCE(r.rate, 0) DESC, d.id LIMIT ? OFFSET ?`
		inArgs = append([]any{rateFrom, rateTo, rateFrom, rateTo}, args...)
	} else {
		inner = `SELECT d.id FROM devices d WHERE ` + w + ` ORDER BY ` + order + ` LIMIT ? OFFSET ?`
	}
	inArgs = append(append([]any{}, inArgs...), q.Limit, q.Offset)
	idRows, err := d.db.QueryContext(ctx, inner, inArgs...)
	if err != nil {
		return page, err
	}
	var ids []string
	for idRows.Next() {
		var id string
		if err := idRows.Scan(&id); err != nil {
			idRows.Close()
			return page, err
		}
		ids = append(ids, id)
	}
	idRows.Close()
	if err := idRows.Err(); err != nil || len(ids) == 0 {
		return page, err
	}
	page.Devices, err = d.DevicesByID(ctx, ids, q.RateFrom, q.RateTo)
	return page, err
}

// Groups returns every group with its number of non-hidden devices, sorted by name.
// Ungrouped devices aren't listed; a group whose devices are all hidden is listed
// with 0.
func (d *DB) Groups(ctx context.Context) ([]GroupCount, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT grp, sum(hidden = 0) FROM devices WHERE grp != '' GROUP BY grp ORDER BY grp`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupCount
	for rows.Next() {
		var g GroupCount
		if err := rows.Scan(&g.Name, &g.Devices); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// PruneDevices deletes devices that have no files left, no name, no group and aren't
// hidden, and weren't heard since heardBefore, and returns their IDs (so the store
// can remove their empty folders). Named, grouped or hidden devices are always kept:
// each is a choice the user made.
func (d *DB) PruneDevices(ctx context.Context, heardBefore time.Time) ([]string, error) {
	rows, err := d.db.QueryContext(ctx, `DELETE FROM devices WHERE name = '' AND grp = '' AND hidden = 0 AND last_heard < ?
		AND NOT EXISTS (SELECT 1 FROM files f WHERE f.device_id = devices.id) RETURNING id`, ms(heardBefore))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
