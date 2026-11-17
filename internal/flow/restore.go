package flow

import (
	"encoding/json"
	"net/netip"
	"slices"
)

// The collector at start (SPEC §13.10 decision 83): what an exporter's stored
// data says about it, so a restart doesn't zero its last 24 hours or make its
// next records wait for a template the exporter sent before the restart.

// RestoreBucket is one stored bucket of an exporter's counts: At is its start
// (unix ms), an hour or 5 minutes long.
type RestoreBucket struct {
	At     int64
	Counts Counts
	Off    TimeOffsets
}

// Restored is an exporter's state from its stored data.
type Restored struct {
	Addr      netip.Addr
	LastHeard int64 // unix ms
	// Hours are the last 24 hours' counts by hour; Fives the last hour's
	// times off arrival by 5 minutes (the flow_time banner's window).
	Hours []RestoreBucket
	Fives []RestoreBucket
	// Templates and Meta are the newest segment's template table and
	// metadata blob (Metadata's format). TemplatesAt is when that segment
	// last stored something: the templates were in use then, and time out
	// from it as if refreshed then.
	Templates   []*Template
	TemplatesAt int64
	Meta        []byte
}

// Restore loads exporters' stored state into a collector that hasn't
// decoded anything yet (call it before the first Decode, from Decode's
// goroutine). Counts land in the 24-hour rings (not in the since-start
// counts); templates and metadata only fill what's empty, so anything the
// exporter has already sent wins, and a template it sends again replaces
// the restored one as usual. Exporters are restored least recently heard
// first, so the exporter cap keeps the most recent.
func (c *Collector) Restore(rs []Restored) {
	rs = slices.Clone(rs)
	slices.SortStableFunc(rs, func(a, b Restored) int {
		switch {
		case a.LastHeard < b.LastHeard:
			return -1
		case a.LastHeard > b.LastHeard:
			return 1
		}
		return 0
	})
	for i := range rs {
		r := &rs[i]
		if !r.Addr.IsValid() {
			continue
		}
		e := c.exporterFor(r.Addr.Unmap(), r.LastHeard)
		c.restoreCounts(e, r)
		c.restoreTemplates(e, r)
		c.restoreMeta(e, r.Meta)
	}
}

func (c *Collector) restoreCounts(e *exporter, r *Restored) {
	e.cmu.Lock()
	defer e.cmu.Unlock()
	for _, b := range r.Hours {
		h := b.At / 3600000
		slot := &e.hours[h%24]
		if slot.hour != h {
			*slot = hourCounts{hour: h}
		}
		slot.c.add(b.Counts)
		if b.Off.Any() {
			if e.off == nil {
				e.off = &offState{}
			}
			if sl := &e.off.hours[h%24]; sl.at == h {
				sl.o.merge(b.Off)
			} else {
				*sl = offSlot{at: h, o: b.Off}
			}
		}
	}
	for _, b := range r.Fives {
		if !b.Off.Any() {
			continue
		}
		if e.off == nil {
			e.off = &offState{}
		}
		f := b.At / fiveMinMs
		if sl := &e.off.fives[f%12]; sl.at == f {
			sl.o.merge(b.Off)
		} else {
			*sl = offSlot{at: f, o: b.Off}
		}
	}
}

func (c *Collector) restoreTemplates(e *exporter, r *Restored) {
	ts := slices.Clone(r.Templates)
	// The table can hold several definitions of one ID: the newest wins.
	slices.SortStableFunc(ts, func(a, b *Template) int {
		switch {
		case a.Received < b.Received:
			return -1
		case a.Received > b.Received:
			return 1
		}
		return 0
	})
	for _, t := range ts {
		if t == nil || (t.Version != V9 && t.Version != IPFIX) {
			continue
		}
		d := c.domainFor(e, tkey{port: t.ExporterPort, domain: t.Domain, version: t.Version})
		if te := d.templates[t.ID]; te != nil && te.refreshed > r.TemplatesAt {
			continue // already sent again since
		}
		cp := *t
		cp.Fields = slices.Clone(t.Fields)
		c.addTemplate(e, d, &cp, r.TemplatesAt)
		if t.Received > 0 {
			// "Last template" is when a definition last arrived, not the
			// restore's refresh time (the newest comes last).
			c.mu.Lock()
			d.lastTemplate = t.Received
			c.mu.Unlock()
		}
	}
}

// restoreMeta fills the sampling, samplers, system init times and interface
// names a metadata blob holds, where the collector has none yet. Options
// records kept raw aren't restored: the segments keep them, and the next
// options data refreshes them.
func (c *Collector) restoreMeta(e *exporter, blob []byte) {
	if len(blob) == 0 {
		return
	}
	var m metaBlob
	if json.Unmarshal(blob, &m) != nil {
		return
	}
	for _, sc := range m.Scopes {
		if sc.Version != V5 && sc.Version != V9 && sc.Version != IPFIX {
			continue
		}
		d := c.domainFor(e, tkey{port: sc.Port, domain: sc.Domain, version: sc.Version})
		c.mu.Lock()
		if d.sampling == 0 && sc.Sampling != 0 {
			d.sampling = sc.Sampling
			e.metaVer.Add(1)
		}
		if d.sysInitMs == 0 && sc.SysInitMs != 0 {
			d.sysInitMs = sc.SysInitMs
			e.metaVer.Add(1)
		}
		for id, rate := range sc.Samplers {
			if d.samplers == nil {
				d.samplers = map[uint32]uint32{}
			}
			if _, ok := d.samplers[id]; !ok && len(d.samplers) < maxSamplers && rate != 0 {
				d.samplers[id] = rate
				e.metaVer.Add(1)
			}
		}
		c.mu.Unlock()
	}
	for _, n := range m.IfNames {
		if _, ok := e.ifNames[uint64(n.Domain)<<32|uint64(n.IfIndex)]; !ok {
			c.setIfName(e, n.Domain, n.IfIndex, n.Name)
		}
	}
}
