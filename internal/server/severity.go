package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
	"github.com/gmccollu/woodshed/internal/model"
)

// The syslog severity filter (SPEC §13.10 decision 86): the config holds the
// default (syslog.min_severity) and each device's own setting
// (syslog.min_severity_by_device, set by PATCH /api/devices like blocked);
// the listeners apply it; the store counts what it leaves out.

// severityFilterOf is the listeners' filter for a config.
func severityFilterOf(c config.Syslog) listen.SeverityFilter {
	return listen.SeverityFilter{Min: c.Level(), ByDevice: c.DeviceLevels()}
}

// applySeverityFilter hands the config's filter to the running listeners.
func (b *backend) applySeverityFilter(c config.Syslog) {
	if ln := b.ln.Load(); ln != nil {
		ln.SetSeverityFilter(severityFilterOf(c))
	}
}

// deviceSeverity is the minimum severity in effect for a device (its ID and
// row IP), and whether it's the device's own (for bundles).
func (b *backend) deviceSeverity(id, rowIP string) (level int, own bool) {
	cfg := b.config()
	ip, ok := deviceAddr(id, rowIP)
	if !ok {
		return cfg.Syslog.Level(), false
	}
	return cfg.Syslog.DeviceLevel(ip)
}

// setDeviceSeverity sets the device's own minimum severity (a severity name or
// number, or config.SeverityDefault to follow the default), saves the config,
// applies it to the listeners from the next message and records an event.
func (b *backend) setDeviceSeverity(d index.Device, v string) error {
	ip, ok := deviceAddr(d.ID, d.IP)
	if !ok {
		return &api.RequestError{Msg: fmt.Sprintf("device %q has no address, so it can't have its own severity filter", d.ID)}
	}
	level := -1
	if v != config.SeverityDefault {
		n, ok := config.ParseSeverity(v)
		if !ok {
			return &api.RequestError{Msg: "min_severity must be \"default\" or a severity"}
		}
		level = n
	}
	b.saveMu.Lock()
	defer b.saveMu.Unlock()
	cur := b.config()
	next := cur.Clone()
	if !next.Syslog.SetDevice(ip, level) {
		return nil
	}
	if err := config.Save(b.cfgPath, next); err != nil {
		return fmt.Errorf("save the config: %w", err)
	}
	b.cfgMu.Lock()
	b.cfg = next.Clone()
	b.cfgMu.Unlock()
	b.applySeverityFilter(next.Syslog)
	b.recordSeverityFilter(next.Syslog)
	who := ip.String()
	if d.Name != "" {
		who += " (" + d.Name + ")"
	}
	text := fmt.Sprintf("severity filter for %s set to %s", who, filterPhrase(level))
	if level < 0 {
		text = fmt.Sprintf("severity filter for %s set to the default (%s)", who, filterPhrase(next.Syslog.Level()))
	}
	b.severityEvent(d.ID, text)
	return nil
}

// filterPhrase is what a level stores, for events: "info and above", "everything".
func filterPhrase(level int) string {
	if level == config.SeverityDebug {
		return "store everything"
	}
	return config.SeverityPhrase(level)
}

// defaultSeverityChanged records a change of syslog.min_severity (a settings
// save) and applies it.
func (b *backend) defaultSeverityChanged(cur, next config.Syslog) {
	if cur.Level() == next.Level() {
		return
	}
	b.applySeverityFilter(next)
	b.recordSeverityFilter(next)
	text := fmt.Sprintf("default severity filter set to %s (was %s)", filterPhrase(next.Level()), config.SeverityPhrase(cur.Level()))
	switch n := len(next.DeviceLevels()); n {
	case 0:
	case 1:
		text += "; 1 device keeps its own setting"
	default:
		text += fmt.Sprintf("; %d devices keep their own setting", n)
	}
	b.severityEvent("", text)
}

func (b *backend) severityEvent(id, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.idx.AddEvent(ctx, index.Event{Level: index.LevelInfo, Kind: index.KindSeverityFilter, DeviceID: id, Text: text}); err != nil {
		b.log.Warn("couldn't record a severity filter event", "err", err, "text", text)
	}
}

// sevMap is counts by severity name, only the ones with any.
func sevMap(c index.SevCounts) map[string]int64 {
	out := map[string]int64{}
	for i, n := range c {
		if n > 0 {
			out[config.SeverityNames[i]] = n
		}
	}
	return out
}

// markSeverity fills the devices' severity filter fields: the setting from
// the config, the last 24 hours' counts from the store's running totals
// (memory, never the index).
func (b *backend) markSeverity(_ context.Context, ds []api.Device) error {
	if len(ds) == 0 {
		return nil
	}
	cfg := b.config()
	ids := make([]string, len(ds))
	for i, d := range ds {
		ids[i] = d.ID
	}
	counts := b.store.Filtered24h(ids)
	for i := range ds {
		d := &ds[i]
		level, own := cfg.Syslog.Level(), false
		if ip, ok := deviceAddr(d.ID, d.IP); ok {
			level, own = cfg.Syslog.DeviceLevel(ip)
		}
		d.MinSeverity = config.SeverityDefault
		if own {
			d.MinSeverity = config.SeverityName(level)
		}
		d.MinSeverityEffective = config.SeverityName(level)
		c := counts[d.ID]
		d.Filtered24h, d.FilteredBySeverity24h = c.Total(), sevMap(c)
	}
	return nil
}

// severityStats is /api/stats severity_filter, and the run-state file's
// (written every second): from the store's running totals, never the index.
func (b *backend) severityStats(context.Context) (api.SeverityFilterStats, error) {
	cfg := b.config()
	st := api.SeverityFilterStats{MinSeverity: config.SeverityName(cfg.Syslog.Level()), DeviceOverrides: len(cfg.Syslog.DeviceLevels())}
	by := b.store.Filtered24h(nil)
	var tot index.SevCounts
	for id, c := range by {
		tot.Add(c)
		if id != index.RefusedDeviceID {
			st.Devices24h++
		}
	}
	st.Filtered24h, st.BySeverity24h = tot.Total(), sevMap(tot)
	return st, nil
}

// filterState is the config's filter as the index records it.
func filterState(c config.Syslog) index.SeverityFilterState {
	st := index.SeverityFilterState{Default: c.Level(), ByDevice: map[string]int{}}
	for a, l := range c.DeviceLevels() {
		st.ByDevice[a.String()] = l
	}
	return st
}

// recordSeverityFilter records the filter the server now runs with, for the
// next start's comparison (severityChangedWhileStopped).
func (b *backend) recordSeverityFilter(c config.Syslog) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.idx.RecordSeverityFilter(ctx, filterState(c)); err != nil {
		b.log.Warn("couldn't record the severity filter", "err", err)
	}
}

// severityChangedWhileStopped compares the filter this start runs with to the
// one the last run recorded and records an event for each difference (the
// CLI and hand edits of the config change it while Woodshed is stopped), then
// records the new one. An index that never recorded one (2.0, or a new
// index) compares with no filter, which is what ran before.
func (b *backend) severityChangedWhileStopped(c config.Syslog) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	prev, ok, err := b.idx.RecordedSeverityFilter(ctx)
	if err != nil {
		b.log.Warn("couldn't read the recorded severity filter", "err", err)
		return
	}
	if !ok {
		prev = index.SeverityFilterState{Default: config.SeverityDebug, ByDevice: map[string]int{}}
	}
	cur := filterState(c)
	const why = " (changed while Woodshed was stopped)"
	// The newest event already says it: a live change whose record didn't
	// get saved (RecordSeverityFilter failed), not one made while stopped.
	said := func(id string, ok func(text string) bool) bool {
		e, found, err := b.idx.LatestEvent(ctx, index.KindSeverityFilter, id)
		return err == nil && found && ok(e.Text)
	}
	if cur.Default != prev.Default && !said("", func(t string) bool {
		p := "default severity filter set to " + filterPhrase(cur.Default)
		return strings.HasPrefix(t, p+" ") || strings.HasPrefix(t, p+",")
	}) {
		b.severityEvent("", fmt.Sprintf("default severity filter set to %s, was %s%s", filterPhrase(cur.Default), config.SeverityPhrase(prev.Default), why))
	}
	addrs := map[string]bool{}
	for a := range cur.ByDevice {
		addrs[a] = true
	}
	for a := range prev.ByDevice {
		addrs[a] = true
	}
	sorted := make([]string, 0, len(addrs))
	for a := range addrs {
		sorted = append(sorted, a)
	}
	slices.Sort(sorted)
	for _, a := range sorted {
		now, has := cur.ByDevice[a]
		was, had := prev.ByDevice[a]
		if has == had && now == was {
			continue
		}
		ip, err := netip.ParseAddr(a)
		if err != nil {
			continue
		}
		id := model.DeviceID(ip)
		if said(id, func(t string) bool {
			if !has {
				return strings.Contains(t, " set to the default")
			}
			return strings.Contains(t, " set to "+filterPhrase(now)) && !strings.Contains(t, " set to the default")
		}) {
			continue
		}
		who := a
		if d, err := b.idx.Device(ctx, id); err == nil && d.Name != "" {
			who += " (" + d.Name + ")"
		}
		text := fmt.Sprintf("severity filter for %s set to %s%s", who, filterPhrase(now), why)
		if !has {
			text = fmt.Sprintf("severity filter for %s set to the default, %s%s", who, filterPhrase(cur.Default), why)
		}
		b.severityEvent(id, text)
	}
	if !ok || cur.Default != prev.Default || len(sorted) > 0 {
		if err := b.idx.RecordSeverityFilter(ctx, cur); err != nil {
			b.log.Warn("couldn't record the severity filter", "err", err)
		}
	}
}
