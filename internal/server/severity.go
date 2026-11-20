package server

import (
	"context"
	"fmt"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/listen"
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

// deviceSeverity is the minimum severity in effect for a device ID, and
// whether it's the device's own (for bundles).
func (b *backend) deviceSeverity(id string) (level int, own bool) {
	cfg := b.config()
	ip, ok := deviceIP(id)
	if !ok {
		return cfg.Syslog.Level(), false
	}
	return cfg.Syslog.DeviceLevel(ip)
}

// setDeviceSeverity sets the device's own minimum severity (a severity name or
// number, or config.SeverityDefault to follow the default), saves the config,
// applies it to the listeners from the next message and records an event.
func (b *backend) setDeviceSeverity(d index.Device, v string) error {
	ip, ok := deviceIP(d.ID)
	if !ok {
		return fmt.Errorf("device %q has no address", d.ID)
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
// the config, the last 24 hours' counts from the index (one query for the
// page, through the partial index: devices with none cost nothing).
func (b *backend) markSeverity(ctx context.Context, ds []api.Device) error {
	if len(ds) == 0 {
		return nil
	}
	cfg := b.config()
	ids := make([]string, len(ds))
	for i, d := range ds {
		ids[i] = d.ID
	}
	counts, err := b.idx.FilteredCounts(ctx, ids, b.now().Add(-24*time.Hour), time.Time{})
	if err != nil {
		return err
	}
	for i := range ds {
		d := &ds[i]
		level, own := cfg.Syslog.Level(), false
		if ip, ok := deviceIP(d.ID); ok {
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

// severityStats is /api/stats severity_filter.
func (b *backend) severityStats(ctx context.Context) (api.SeverityFilterStats, error) {
	cfg := b.config()
	st := api.SeverityFilterStats{MinSeverity: config.SeverityName(cfg.Syslog.Level()), DeviceOverrides: len(cfg.Syslog.DeviceLevels())}
	by, err := b.idx.FilteredCounts(ctx, nil, b.now().Add(-24*time.Hour), time.Time{})
	if err != nil {
		return st, err
	}
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
