package poller

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// Limits (SPEC §12.1, §12.10 #9; docs/api.md "Poll targets").
const (
	MaxCustom      = 32
	DefaultMaxRows = 128
	MaxMaxRows     = 1024
	MaxPinned      = 1024
	MaxIfList      = 1024
	MaxLabel       = 64
	DefaultPort    = 161
)

// IfRef is an interface named in a target: an ifName or an ifIndex.
type IfRef struct {
	Name  string
	Index int
}

func (r IfRef) String() string {
	if r.Name != "" {
		return r.Name
	}
	return strconv.Itoa(r.Index)
}

// MarshalJSON writes a name as a string and an index as a number.
func (r IfRef) MarshalJSON() ([]byte, error) {
	if r.Name != "" {
		return json.Marshal(r.Name)
	}
	return json.Marshal(r.Index)
}

// UnmarshalJSON reads a string (a name, or digits: an index) or a number.
func (r *IfRef) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*r = IfRef{Index: n}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return errors.New("an interface is an ifName (a string) or an ifIndex (a number)")
	}
	*r = IfRef{Name: s}
	return nil
}

// Interfaces is a target's interface selection: all (up to the cap), or a
// list.
type Interfaces struct {
	All  bool
	List []IfRef
}

// MarshalJSON writes "all" or the list.
func (i Interfaces) MarshalJSON() ([]byte, error) {
	if i.All {
		return []byte(`"all"`), nil
	}
	l := i.List
	if l == nil {
		l = []IfRef{}
	}
	return json.Marshal(l)
}

// UnmarshalJSON reads "all" or a list.
func (i *Interfaces) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s != "all" {
			return errors.New(`interfaces is "all" or a list of ifNames and indexes`)
		}
		*i = Interfaces{All: true}
		return nil
	}
	var l []IfRef
	if err := json.Unmarshal(b, &l); err != nil {
		return errors.New(`interfaces is "all" or a list of ifNames and indexes`)
	}
	*i = Interfaces{List: l}
	return nil
}

// Custom is one custom OID: a scalar (one Get) or a walk.
type Custom struct {
	OID     string `json:"oid"`
	Kind    string `json:"kind"` // "scalar" or "walk"
	Label   string `json:"label"`
	MaxRows int    `json:"max_rows"`
}

// Custom kinds.
const (
	CustomScalar = "scalar"
	CustomWalk   = "walk"
)

// Settings are what a target is configured with (docs/api.md): the stored
// part, without the community.
type Settings struct {
	Address       string     `json:"address"`
	Port          int        `json:"port"`
	DeviceID      string     `json:"device_id"`
	Enabled       bool       `json:"enabled"`
	Version       string     `json:"version"` // "1", "2c", "3"
	V3User        string     `json:"v3_user"`
	IntervalS     int        `json:"interval_s"`
	TimeoutMS     int        `json:"timeout_ms"`
	Retries       int        `json:"retries"`
	Presets       []string   `json:"presets"`
	Interfaces    Interfaces `json:"interfaces"`
	MaxInterfaces int        `json:"max_interfaces"`
	Pinned        []IfRef    `json:"pinned"`
	Custom        []Custom   `json:"custom"`
}

// Input is a POST or PUT body: Settings with every field optional, plus the
// write-only community.
type Input struct {
	Address       *string     `json:"address"`
	Port          *int        `json:"port"`
	DeviceID      *string     `json:"device_id"`
	Enabled       *bool       `json:"enabled"`
	Version       *string     `json:"version"`
	Community     *string     `json:"community"`
	V3User        *string     `json:"v3_user"`
	IntervalS     *int        `json:"interval_s"`
	TimeoutMS     *int        `json:"timeout_ms"`
	Retries       *int        `json:"retries"`
	Presets       []string    `json:"presets"`
	Interfaces    *Interfaces `json:"interfaces"`
	MaxInterfaces *int        `json:"max_interfaces"`
	Pinned        []IfRef     `json:"pinned"`
	Custom        []Custom    `json:"custom"`
}

// ValidationError is a 400 with errors by field (docs/api.md).
type ValidationError struct {
	Errors map[string]string
}

func (e *ValidationError) Error() string {
	keys := make([]string, 0, len(e.Errors))
	for k := range e.Errors {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(k + ": " + e.Errors[k])
	}
	return b.String()
}

// Resolve turns a body into Settings: fields left out take the target's
// current settings (cur, for a PUT) or else the Settings defaults (def, SPEC
// §12.1). It validates everything but whether the v3 user exists (hasUser).
// For v1 and v2c, communityStored says whether a community is already stored;
// the returned community is the new one (nil: keep the stored one).
func Resolve(in Input, cur *Settings, def config.Poll, communityStored bool, hasUser func(string) bool) (Settings, []byte, error) {
	errs := map[string]string{}
	var s Settings
	if cur != nil {
		s = *cur
		s.Presets = slices.Clone(cur.Presets)
		s.Pinned = slices.Clone(cur.Pinned)
		s.Custom = slices.Clone(cur.Custom)
	} else {
		s = Settings{Port: DefaultPort, Enabled: true, Version: "2c", IntervalS: def.IntervalS, TimeoutMS: def.TimeoutMS,
			Retries: def.Retries, Presets: slices.Clone(def.Presets), Interfaces: Interfaces{All: true},
			MaxInterfaces: def.MaxInterfaces, Pinned: []IfRef{}, Custom: []Custom{}}
	}
	if in.Address != nil {
		s.Address = strings.TrimSpace(*in.Address)
	}
	addr, err := netip.ParseAddr(s.Address)
	switch {
	case s.Address == "":
		errs["address"] = "is required"
	case err != nil:
		errs["address"] = "must be an IP address (names aren't looked up)"
	case addr.Zone() != "":
		errs["address"] = "can't have a zone"
	case addr.IsUnspecified() || addr.IsMulticast():
		errs["address"] = "must be one device's address"
	default:
		s.Address = addr.Unmap().String()
	}
	if in.Port != nil {
		s.Port = *in.Port
	}
	if s.Port < 1 || s.Port > 65535 {
		errs["port"] = "must be between 1 and 65535"
	}
	// device_id defaults to the address; on a PUT that changes the address, a
	// device ID that was the old address's default follows the new one.
	switch {
	case in.DeviceID != nil:
		s.DeviceID = strings.TrimSpace(*in.DeviceID)
	case cur == nil:
		s.DeviceID = ""
	case in.Address != nil:
		if old, err := netip.ParseAddr(cur.Address); err == nil && cur.DeviceID == model.DeviceID(old) {
			s.DeviceID = ""
		}
	}
	if s.DeviceID == "" {
		if errs["address"] == "" {
			s.DeviceID = model.DeviceID(addr)
		}
	} else if a, err := parseDeviceID(s.DeviceID); err != nil {
		errs["device_id"] = "must be a device ID (an IP address)"
	} else {
		s.DeviceID = model.DeviceID(a)
	}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if in.Version != nil {
		s.Version = *in.Version
	}
	var community []byte
	switch s.Version {
	case "1", "2c":
		if in.Community != nil {
			if *in.Community == "" {
				errs["community"] = "can't be empty for SNMPv" + s.Version
			} else if len(*in.Community) > 255 {
				errs["community"] = "is at most 255 bytes"
			} else {
				community = []byte(*in.Community)
			}
		} else if !communityStored {
			errs["community"] = "is required for SNMPv" + s.Version
		}
		s.V3User = ""
	case "3":
		if in.V3User != nil {
			s.V3User = strings.TrimSpace(*in.V3User)
		}
		if s.V3User == "" {
			errs["v3_user"] = "is required for SNMPv3"
		} else if hasUser != nil && !hasUser(s.V3User) {
			errs["v3_user"] = fmt.Sprintf("no v3 user %q (add it under Settings → SNMP traps)", s.V3User)
		}
		if in.Community != nil && *in.Community != "" {
			errs["community"] = "SNMPv3 uses a user, not a community"
		}
	default:
		errs["version"] = `must be "1", "2c" or "3"`
	}
	if in.IntervalS != nil {
		s.IntervalS = *in.IntervalS
	}
	if s.IntervalS < config.MinPollIntervalS || s.IntervalS > config.MaxPollIntervalS {
		errs["interval_s"] = fmt.Sprintf("must be between %d and %d", config.MinPollIntervalS, config.MaxPollIntervalS)
	}
	if in.TimeoutMS != nil {
		s.TimeoutMS = *in.TimeoutMS
	}
	if s.TimeoutMS < config.MinPollTimeoutMS || s.TimeoutMS > config.MaxPollTimeoutMS {
		errs["timeout_ms"] = fmt.Sprintf("must be between %d and %d", config.MinPollTimeoutMS, config.MaxPollTimeoutMS)
	}
	if in.Retries != nil {
		s.Retries = *in.Retries
	}
	if s.Retries < config.MinPollRetries || s.Retries > config.MaxPollRetries {
		errs["retries"] = fmt.Sprintf("must be between %d and %d", config.MinPollRetries, config.MaxPollRetries)
	}
	if in.Presets != nil {
		s.Presets = in.Presets
	}
	seen := map[string]bool{}
	for i, p := range s.Presets {
		if !slices.Contains(config.PollPresets(), p) {
			errs[fmt.Sprintf("presets[%d]", i)] = "must be system, system-info or interfaces"
		} else if seen[p] {
			errs[fmt.Sprintf("presets[%d]", i)] = "is listed twice"
		}
		seen[p] = true
	}
	if in.Interfaces != nil {
		s.Interfaces = *in.Interfaces
	}
	if !s.Interfaces.All {
		if len(s.Interfaces.List) == 0 {
			errs["interfaces"] = `is "all" or a non-empty list`
		}
		if len(s.Interfaces.List) > MaxIfList {
			errs["interfaces"] = fmt.Sprintf("lists at most %d interfaces", MaxIfList)
		}
		checkRefs(errs, "interfaces", s.Interfaces.List)
	}
	if in.MaxInterfaces != nil {
		s.MaxInterfaces = *in.MaxInterfaces
	}
	if s.MaxInterfaces < config.MinPollMaxInterfaces || s.MaxInterfaces > config.MaxPollMaxInterfaces {
		errs["max_interfaces"] = fmt.Sprintf("must be between %d and %d", config.MinPollMaxInterfaces, config.MaxPollMaxInterfaces)
	}
	if in.Pinned != nil {
		s.Pinned = in.Pinned
	}
	if len(s.Pinned) > MaxPinned {
		errs["pinned"] = fmt.Sprintf("lists at most %d interfaces", MaxPinned)
	}
	checkRefs(errs, "pinned", s.Pinned)
	if in.Custom != nil {
		s.Custom = in.Custom
	}
	if len(s.Custom) > MaxCustom {
		errs["custom"] = fmt.Sprintf("has at most %d entries", MaxCustom)
	}
	for i := range s.Custom {
		c := &s.Custom[i]
		key := fmt.Sprintf("custom[%d]", i)
		o, err := snmp.ParseOID(strings.TrimSpace(c.OID))
		if err != nil || len(o) < 2 || o[0] > 2 {
			errs[key+".oid"] = "must be a numeric OID (1.3.6.1.…)"
		} else {
			c.OID = o.String()
		}
		switch c.Kind {
		case "", CustomScalar:
			c.Kind, c.MaxRows = CustomScalar, 0
		case CustomWalk:
			if c.MaxRows == 0 {
				c.MaxRows = DefaultMaxRows
			}
			if c.MaxRows < 1 || c.MaxRows > MaxMaxRows {
				errs[key+".max_rows"] = fmt.Sprintf("must be between 1 and %d", MaxMaxRows)
			}
		default:
			errs[key+".kind"] = `must be "scalar" or "walk"`
		}
		c.Label = strings.TrimSpace(c.Label)
		if len(c.Label) > MaxLabel {
			errs[key+".label"] = fmt.Sprintf("is at most %d bytes", MaxLabel)
		}
	}
	if s.Presets == nil {
		s.Presets = []string{}
	}
	if s.Pinned == nil {
		s.Pinned = []IfRef{}
	}
	if s.Custom == nil {
		s.Custom = []Custom{}
	}
	if len(errs) > 0 {
		return s, nil, &ValidationError{Errors: errs}
	}
	return s, community, nil
}

func checkRefs(errs map[string]string, key string, refs []IfRef) {
	for i, r := range refs {
		if r.Name == "" && r.Index < 1 {
			errs[fmt.Sprintf("%s[%d]", key, i)] = "must be an ifName or an ifIndex of at least 1"
		}
		if len(r.Name) > 255 {
			errs[fmt.Sprintf("%s[%d]", key, i)] = "is at most 255 bytes"
		}
	}
}

// parseDeviceID reads a device ID: an IP address, with '_' for IPv6's ':'
// (model.DeviceID).
func parseDeviceID(id string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(id); err == nil {
		return a.Unmap(), nil
	}
	return netip.ParseAddr(strings.ReplaceAll(id, "_", ":"))
}

// DeviceAddr is the address a device ID names (the store's sender for its
// poll lines).
func DeviceAddr(id string) (netip.Addr, error) { return parseDeviceID(id) }

// version is the snmp version of a target's "1", "2c" or "3".
func (s *Settings) version() snmp.Version {
	switch s.Version {
	case "1":
		return snmp.V1
	case "3":
		return snmp.V3
	}
	return snmp.V2c
}

func (s *Settings) has(preset string) bool { return slices.Contains(s.Presets, preset) }
