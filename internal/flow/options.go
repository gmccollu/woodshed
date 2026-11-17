package flow

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Options data kept raw (SPEC §13.1.2): an options record with any field
// the collector doesn't interpret (sampling, interface names, the system
// init time) is kept whole, per exporter and scope (port, domain, version),
// keyed by its template and its scope values, with the latest versions by
// received time, so nothing an exporter sends is lost. Interpreted-only
// records (an interface name, a sampler) aren't duplicated here.

const (
	// maxRawOptBytes is the raw options' share of maxMetaBytes, so they can't
	// crowd out interface names and samplers.
	maxRawOptBytes = 2 << 20
	// maxOptVersions is how many versions of one key are kept.
	maxOptVersions = 4
	// maxOptKeys bounds the keys of one scope.
	maxOptKeys = 1024
)

// OptionsValue is one field of a kept options record.
type OptionsValue struct {
	PEN   uint32 `json:"pen"`
	ID    uint16 `json:"id"`
	Scope bool   `json:"scope,omitempty"`
	Value []byte `json:"-"`
}

// MarshalJSON writes the value as hex.
func (v OptionsValue) MarshalJSON() ([]byte, error) {
	type alias struct {
		PEN   uint32 `json:"pen"`
		ID    uint16 `json:"id"`
		Name  string `json:"name,omitempty"`
		Scope bool   `json:"scope,omitempty"`
		Hex   string `json:"hex"`
	}
	return json.Marshal(alias{v.PEN, v.ID, IEName(v.PEN, v.ID), v.Scope, hex.EncodeToString(v.Value)})
}

// OptionsData is one kept options record.
type OptionsData struct {
	Domain     uint32         `json:"domain"`
	Port       uint16         `json:"port"`
	Version    uint8          `json:"version"`
	TemplateID uint16         `json:"template_id"`
	Received   time.Time      `json:"received"`  // when this version first came
	Refreshed  time.Time      `json:"refreshed"` // the latest identical copy
	Fields     []OptionsValue `json:"fields"`
}

func (o *OptionsData) size() int {
	n := 96
	for _, f := range o.Fields {
		n += 16 + len(f.Value)
	}
	return n
}

func sameValues(a, b []OptionsValue) bool {
	return slices.EqualFunc(a, b, func(x, y OptionsValue) bool {
		return x.PEN == y.PEN && x.ID == y.ID && x.Scope == y.Scope && string(x.Value) == string(y.Value)
	})
}

// interpretedOption reports whether an options field is a scope field or one
// the collector reads into metadata.
func interpretedOption(f TemplateField, scope bool) bool {
	if scope {
		return true // scope fields are the record's key, kept with it either way
	}
	if f.PEN != 0 {
		return false
	}
	switch f.ID {
	case ieInIf, ieOutIf, ieIfName, ieIfDesc, ieSamplerID, ieSelectorID, ieSamplingInterval, ieSamplerRandomInterval,
		ieSamplingPacketInterval, ieSamplingPacketSpace, ieSamplingSize, ieSamplingPopulation, ieSamplingProbability,
		ieSysInitMs:
		return true
	}
	return false
}

// keepOptions stores an options record raw when it holds any field the
// collector doesn't interpret. Decode's goroutine only; it takes c.mu.
func (c *Collector) keepOptions(e *exporter, d *domainState, t *Template, vals []fieldVal, at int64) {
	raw := false
	for _, x := range vals {
		if !interpretedOption(x.f, x.scope) {
			raw = true
			break
		}
	}
	if !raw {
		return
	}
	var key strings.Builder
	key.WriteString(strconv.Itoa(int(t.ID)))
	fields := make([]OptionsValue, len(vals))
	for i, x := range vals {
		fields[i] = OptionsValue{PEN: x.f.PEN, ID: x.f.ID, Scope: x.scope, Value: slices.Clone(x.v)}
		if x.scope {
			key.WriteByte('/')
			key.WriteString(hex.EncodeToString(x.v))
		}
	}
	k := key.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if d.opts == nil {
		d.opts = map[string][]*OptionsData{}
	}
	hist := d.opts[k]
	if n := len(hist); n > 0 && sameValues(hist[n-1].Fields, fields) {
		hist[n-1].Refreshed = time.UnixMilli(at).UTC()
		return
	}
	if hist == nil && len(d.opts) >= maxOptKeys {
		return
	}
	od := &OptionsData{Domain: d.key.domain, Port: d.key.port, Version: t.Version, TemplateID: t.ID,
		Received: time.UnixMilli(at).UTC(), Refreshed: time.UnixMilli(at).UTC(), Fields: fields}
	sz := od.size()
	for len(hist) >= maxOptVersions || (len(hist) > 0 && c.rawOptBytes+sz > maxRawOptBytes) {
		old := hist[0].size()
		hist = hist[1:]
		c.rawOptBytes -= old
		e.rawOpt -= old
	}
	if c.rawOptBytes+sz > maxRawOptBytes {
		if len(hist) == 0 {
			delete(d.opts, k)
		} else {
			d.opts[k] = hist
		}
		return
	}
	d.opts[k] = append(hist, od)
	c.rawOptBytes += sz
	e.rawOpt += sz
	e.metaVer.Add(1)
}

// Options returns the options records kept raw for an exporter (every
// scope, oldest version first). Safe from any goroutine.
func (c *Collector) Options(addr netip.Addr) []OptionsData {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e := c.exporters[addr.Unmap()]
	if e == nil {
		return nil
	}
	var out []OptionsData
	for _, d := range e.domains {
		for _, hist := range d.opts {
			for _, od := range hist {
				out = append(out, *od)
			}
		}
	}
	slices.SortFunc(out, func(a, b OptionsData) int {
		if a.Domain != b.Domain {
			return int(int64(a.Domain) - int64(b.Domain))
		}
		if a.TemplateID != b.TemplateID {
			return int(a.TemplateID) - int(b.TemplateID)
		}
		return a.Received.Compare(b.Received)
	})
	return out
}

// metaBlob is Metadata's JSON: per scope its sampling, samplers and system
// init time, the interface names, and the options records kept raw.
type metaBlob struct {
	Exporter string        `json:"exporter"`
	Scopes   []metaScope   `json:"scopes"`
	IfNames  []metaIfName  `json:"if_names,omitempty"`
	Options  []OptionsData `json:"options,omitempty"`
}

type metaScope struct {
	Port      uint16            `json:"port"`
	Domain    uint32            `json:"domain"`
	Version   uint8             `json:"version"`
	Sampling  uint32            `json:"sampling,omitempty"`
	Samplers  map[uint32]uint32 `json:"samplers,omitempty"`
	SysInitMs int64             `json:"sys_init_ms,omitempty"`
}

type metaIfName struct {
	Domain  uint32 `json:"domain"`
	IfIndex uint32 `json:"if_index"`
	Name    string `json:"name"`
}

// Metadata is an exporter's metadata as one JSON blob, for a segment's
// template table (flowseg.Writer.SetMeta): per scope its sampling, samplers
// and system init time, the interface names, and the options records kept
// raw. The version rises with every change, so a caller can pass the blob
// only when it changed. Safe from any goroutine.
func (c *Collector) Metadata(addr netip.Addr) (blob []byte, version uint64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e := c.exporters[addr.Unmap()]
	if e == nil {
		return nil, 0
	}
	var m metaBlob
	m.Exporter = e.addr.String()
	for _, d := range e.domains {
		m.Scopes = append(m.Scopes, metaScope{Port: d.key.port, Domain: d.key.domain, Version: d.key.version, Sampling: d.sampling,
			Samplers: d.samplers, SysInitMs: d.sysInitMs})
		for _, hist := range d.opts {
			for _, od := range hist {
				m.Options = append(m.Options, *od)
			}
		}
	}
	slices.SortFunc(m.Scopes, func(a, b metaScope) int {
		if a.Domain != b.Domain {
			return int(int64(a.Domain) - int64(b.Domain))
		}
		return int(a.Port) - int(b.Port)
	})
	slices.SortFunc(m.Options, func(a, b OptionsData) int { return a.Received.Compare(b.Received) })
	for k, n := range e.ifNames {
		m.IfNames = append(m.IfNames, metaIfName{Domain: uint32(k >> 32), IfIndex: uint32(k), Name: n})
	}
	slices.SortFunc(m.IfNames, func(a, b metaIfName) int {
		if a.Domain != b.Domain {
			return int(int64(a.Domain) - int64(b.Domain))
		}
		return int(int64(a.IfIndex) - int64(b.IfIndex))
	})
	b, _ := json.Marshal(m)
	return b, e.metaVer.Load()
}
