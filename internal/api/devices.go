package api

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"
)

// Device list paging (docs/api.md, GET /api/devices).
const (
	defaultDeviceLimit = 200
	maxDeviceLimit     = 1000
)

// DeviceQuery is GET /api/devices' query.
type DeviceQuery struct {
	Limit, Offset int
	Sort          string // rate (busiest first), name, last_heard (newest first), first_seen (newest first)
	Q             string // case-insensitive substring of id, IP or name
	Group         string
	Ungrouped     bool
	Hidden        string // include, only, exclude
	Blocked       string // include, only, exclude
	// ActiveFrom and ActiveTo (both or neither) keep only the devices with a
	// stored record of any type received in [ActiveFrom, ActiveTo) (1.2, the
	// incident bundle's preview).
	ActiveFrom, ActiveTo time.Time
}

// DevicePage is the body of GET /api/devices.
type DevicePage struct {
	Devices []Device `json:"devices"`
	Total   int      `json:"total"` // devices matching the filters, before paging
}

// ParseDeviceQuery reads GET /api/devices' query string.
func ParseDeviceQuery(v url.Values) (DeviceQuery, error) {
	q := DeviceQuery{Limit: defaultDeviceLimit, Sort: "rate", Hidden: "include", Blocked: "include", Q: v.Get("q"), Group: v.Get("group")}
	for _, p := range []struct {
		name string
		dst  *int
		min  int
	}{{"limit", &q.Limit, 1}, {"offset", &q.Offset, 0}} {
		if s := v.Get(p.name); s != "" {
			n, err := strconv.Atoi(s)
			if err != nil || n < p.min {
				return q, fmt.Errorf("%s must be an integer of at least %d, not %q", p.name, p.min, s)
			}
			*p.dst = n
		}
	}
	q.Limit = min(q.Limit, maxDeviceLimit)
	if s := v.Get("sort"); s != "" {
		switch s {
		case "rate", "name", "last_heard", "first_seen":
			q.Sort = s
		default:
			return q, fmt.Errorf("sort must be rate, name, last_heard or first_seen, not %q", s)
		}
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{{"hidden", &q.Hidden}, {"blocked", &q.Blocked}} {
		if s := v.Get(f.name); s != "" {
			switch s {
			case "include", "only", "exclude":
				*f.dst = s
			default:
				return q, fmt.Errorf("%s must be include, only or exclude, not %q", f.name, s)
			}
		}
	}
	var err error
	if q.Ungrouped, err = parseBoolParam(v, "ungrouped"); err != nil {
		return q, err
	}
	if q.Group != "" && q.Ungrouped {
		return q, fmt.Errorf("group and ungrouped=true are alternatives; send one")
	}
	if q.ActiveFrom, err = parseTimeParam(v, "active_from"); err != nil {
		return q, err
	}
	if q.ActiveTo, err = parseTimeParam(v, "active_to"); err != nil {
		return q, err
	}
	switch {
	case q.ActiveFrom.IsZero() != q.ActiveTo.IsZero():
		return q, fmt.Errorf("active_from and active_to go together; send both or neither")
	case !q.ActiveFrom.IsZero() && !q.ActiveFrom.Before(q.ActiveTo):
		return q, fmt.Errorf("active_from must be before active_to")
	}
	return q, nil
}

func (s *Server) getDevices(w http.ResponseWriter, r *http.Request) {
	q, err := ParseDeviceQuery(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	page, err := s.backend.QueryDevices(r.Context(), q)
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	page.Devices = nonNil(page.Devices)
	for i := range page.Devices {
		page.Devices[i].normalize()
	}
	writeJSON(w, http.StatusOK, page)
}

// Group is one entry of GET /api/groups.
type Group struct {
	Name    string `json:"name"`
	Devices int    `json:"devices"` // non-hidden devices in the group
}

func (s *Server) getGroups(w http.ResponseWriter, r *http.Request) {
	gs, err := s.backend.Groups(r.Context())
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	// A group whose devices are all hidden isn't listed.
	gs = slices.DeleteFunc(slices.Clone(gs), func(g Group) bool { return g.Devices == 0 })
	writeJSON(w, http.StatusOK, nonNil(gs))
}
