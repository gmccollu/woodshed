package datatype

import (
	"strings"

	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/syslog"
)

// FieldMatcher matches the program/tag and hostname that syslog.Parse reads
// from a message's header (model.Message.App and Hostname). It holds no state,
// so the runs of one request can share it; each run brings its own Message.
type FieldMatcher struct {
	apps, exApps   []appPattern
	hosts, exHosts []string // lower-cased
}

// appPattern is one app value: lower-cased, without a leading '%', and with a
// trailing '*' turned into prefix.
type appPattern struct {
	s      string
	prefix bool
}

func appPatterns(apps []string) []appPattern {
	var out []appPattern
	for _, a := range apps {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		p := appPattern{}
		if strings.HasSuffix(a, "*") {
			p.prefix = true
			a = strings.TrimRight(a, "*")
		}
		p.s = strings.ToLower(TrimPct(a))
		out = append(out, p)
	}
	return out
}

func hostPatterns(hosts []string) []string {
	var out []string
	for _, h := range hosts {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, strings.ToLower(h))
		}
	}
	return out
}

// NewFieldMatcher returns nil when every list is empty.
func NewFieldMatcher(apps, hosts, exApps, exHosts []string) *FieldMatcher {
	fm := FieldMatcher{apps: appPatterns(apps), hosts: hostPatterns(hosts), exApps: appPatterns(exApps), exHosts: hostPatterns(exHosts)}
	if len(fm.apps) == 0 && len(fm.hosts) == 0 && len(fm.exApps) == 0 && len(fm.exHosts) == 0 {
		return nil
	}
	return &fm
}

// trimPct drops one leading '%': syslog.Parse keeps it in App for a
// "%FAC-N-MNEMONIC" tag, and people type the tag either way.
func TrimPct(s string) string { return strings.TrimPrefix(s, "%") }

func hostIn(host string, hosts []string) bool {
	for _, h := range hosts {
		if strings.EqualFold(host, h) {
			return true
		}
	}
	return false
}

// appIn reports whether app (without its '%') matches one of ps.
func appIn(app string, ps []appPattern) bool {
	for _, p := range ps {
		if p.prefix {
			if len(app) >= len(p.s) && strings.EqualFold(app[:len(p.s)], p.s) {
				return true
			}
		} else if strings.EqualFold(app, p.s) {
			return true
		}
	}
	return false
}

// Match parses raw into msg (the caller's scratch Message) and reports whether
// its app and host pass.
func (fm *FieldMatcher) Match(raw []byte, msg *model.Message) bool {
	syslog.Parse(raw, msg)
	if len(fm.hosts) > 0 && !hostIn(msg.Hostname, fm.hosts) {
		return false
	}
	if len(fm.exHosts) > 0 && msg.Hostname != "" && hostIn(msg.Hostname, fm.exHosts) {
		return false
	}
	app := TrimPct(msg.App)
	if len(fm.apps) > 0 && (app == "" || !appIn(app, fm.apps)) {
		return false
	}
	if len(fm.exApps) > 0 && app != "" && appIn(app, fm.exApps) {
		return false
	}
	return true
}

// Fields returns the program/tag and hostname of a raw message, as the app and
// host filters see them (App keeps a "%" tag's '%').
func Fields(raw []byte) (app, host string) {
	var m model.Message
	syslog.Parse(raw, &m)
	return m.App, m.Hostname
}
