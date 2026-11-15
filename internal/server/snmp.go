package server

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/config"
	"github.com/gmccollu/woodshed/internal/fwrule"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
	"github.com/gmccollu/woodshed/internal/trap"
)

// The SNMP trap receiver's service side (SPEC §11.2): the receiver, its
// settings, banners, run-state part and the API's SNMP routes.

// snmpSide holds the receiver and the cached firewall state.
type snmpSide struct {
	rcv *trap.Receiver

	fwCheck func(port int) string // nil off Windows
	fwMu    sync.Mutex
	fwState string
	fwPort  int
	fwAt    time.Time
}

func trapSettings(l config.SNMPListener) trap.Settings {
	return trap.Settings{AnswerInforms: l.AnswerInforms, StrictTime: l.V3StrictTime, EngineID: l.EngineID, MIBDir: l.MIBDir}
}

// openSNMP opens the receiver (its engine, credentials and MIBs) whether or not
// the listener is on: Settings manages the users either way.
func (b *backend) openSNMP(cfg config.Config) error {
	r, err := trap.Open(trap.Options{
		DataDir:  cfg.Storage.DataDir,
		Write:    b.trapWrite,
		TryWrite: b.trapTryWrite,
		Admit:    func(a netip.Addr) error { return b.store.AdmitType(logfile.TypeTrap, a) },
		Event: func(level, text string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = b.idx.AddEvent(ctx, index.Event{Level: index.Level(level), Kind: index.KindError, Text: "SNMP: " + text})
		},
		Logger: b.log,
	}, trapSettings(cfg.Listeners.SNMP))
	if err != nil {
		return err
	}
	b.snmp = &snmpSide{rcv: r}
	if runtime.GOOS == "windows" {
		b.snmp.fwCheck = func(port int) string { return fwrule.SNMPWindowsState(fwrule.Exec, port) }
	}
	return nil
}

// trapWrite stores one trap record: the device is heard (online) like a
// syslog sender, but the live tail stays syslog-only (SPEC §11.1).
func (b *backend) trapWrite(m model.Message) error {
	if b.firstMsg.Load() == 0 {
		b.firstMsg.CompareAndSwap(0, m.Received.UnixMilli())
	}
	b.live.add(m.Sender, m.Received)
	return b.store.WriteType(logfile.TypeTrap, m)
}

// trapTryWrite is trapWrite that never waits on the store (store.TryWriteType),
// for the SNMP reader's fast path; false means it did nothing.
func (b *backend) trapTryWrite(m model.Message) (bool, error) {
	ok, err := b.store.TryWriteType(logfile.TypeTrap, m)
	if !ok {
		return false, nil
	}
	if b.firstMsg.Load() == 0 {
		b.firstMsg.CompareAndSwap(0, m.Received.UnixMilli())
	}
	b.live.add(m.Sender, m.Received)
	return true, err
}

// trapQueueDrop counts the SNMP listener's queue drops for the senders' trap
// streams.
func (b *backend) trapQueueDrop(from netip.Addr, at time.Time, n int64) {
	b.store.DropQueuedType(logfile.TypeTrap, from, at, n)
}

func (t *snmpSide) firewall(port int, now time.Time) string {
	if t.fwCheck == nil {
		return fwrule.StateUnknown
	}
	t.fwMu.Lock()
	defer t.fwMu.Unlock()
	if t.fwState == "" || t.fwPort != port || now.Sub(t.fwAt) >= fwRecheck || now.Before(t.fwAt) {
		t.fwState, t.fwPort, t.fwAt = t.fwCheck(port), port, now
	}
	return t.fwState
}

// snmpFirewall is the firewall part of /api/snmp: only the installed service
// has the rule (as for TLS).
func (b *backend) snmpFirewall(l config.SNMPListener) api.SNMPFirewall {
	fw := api.SNMPFirewall{State: fwrule.StateUnknown}
	if b.isService {
		fw.State = b.snmp.firewall(l.Port, b.now())
	}
	switch fw.State {
	case fwrule.StateMissing, fwrule.StateDisabled, fwrule.StateWrongPort:
		fw.Command = "woodshed snmp on"
	}
	return fw
}

func (b *backend) SNMP(ctx context.Context) (api.SNMPState, error) {
	cfg := b.config()
	r := b.snmp.rcv
	return api.SNMPState{Enabled: cfg.Listeners.SNMP.Enabled, Port: cfg.Listeners.SNMP.Port, Engine: r.Engine(),
		Counts24h: r.Counts(), MIBs: r.MIBs(), Firewall: b.snmpFirewall(cfg.Listeners.SNMP)}, nil
}

func (b *backend) ReloadMIBs(ctx context.Context) (api.SNMPMIBs, error) {
	return b.snmp.rcv.ReloadMIBs(), nil
}

func (b *backend) SNMPFailures(ctx context.Context) ([]api.SNMPFailure, error) {
	return b.snmp.rcv.Failures(), nil
}

func (b *backend) SNMPUsers(ctx context.Context) ([]api.SNMPUser, error) {
	return b.snmp.rcv.Users(), nil
}

func (b *backend) CreateSNMPUser(ctx context.Context, in api.SNMPUserInput) (api.SNMPUser, error) {
	u, err := b.snmp.rcv.PutUser(in, "")
	if err == nil {
		b.snmpEvent(fmt.Sprintf("SNMP v3 user %q added (%s)", u.Name, u.Level))
	}
	return u, err
}

func (b *backend) UpdateSNMPUser(ctx context.Context, name string, in api.SNMPUserInput) (api.SNMPUser, error) {
	u, err := b.snmp.rcv.PutUser(in, name)
	if err == nil {
		b.snmpEvent(fmt.Sprintf("SNMP v3 user %q changed (%s)", u.Name, u.Level))
	}
	return u, err
}

func (b *backend) DeleteSNMPUser(ctx context.Context, name string) error {
	err := b.snmp.rcv.DeleteUser(name)
	if err == nil {
		b.snmpEvent(fmt.Sprintf("SNMP v3 user %q deleted", name))
	}
	return err
}

// snmpEvent records a change to the SNMP credentials: a user's name and level
// only, never a secret.
func (b *backend) snmpEvent(text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = b.idx.AddEvent(ctx, index.Event{Level: index.LevelInfo, Kind: index.KindAuth, Text: text})
}

// snmpBanners are snmp_firewall (the installed service on Windows), and
// snmp_credentials and snmp_mibs (docs/api.md "Banners (1.2)").
func (b *backend) snmpBanners(cfg config.Config, now time.Time) []api.Banner {
	l := cfg.Listeners.SNMP
	var out []api.Banner
	if l.Enabled && b.isService && runtime.GOOS == "windows" {
		if text := snmpFirewallText(b.snmp.firewall(l.Port, now), l.Port); text != "" {
			out = append(out, api.Banner{Kind: "snmp_firewall", Level: api.LevelWarn, Text: text})
		}
	}
	if n := b.snmp.rcv.UnreadableUsers(); n > 0 {
		text := fmt.Sprintf("%d SNMP v3 users can't be read on this machine (the data folder was moved from another machine "+
			"or account). Enter their passphrases again in Settings → SNMP traps.", n)
		if n == 1 {
			text = "1 SNMP v3 user can't be read on this machine (the data folder was moved from another machine or account). " +
				"Enter its passphrases again in Settings → SNMP traps."
		}
		out = append(out, api.Banner{Kind: "snmp_credentials", Level: api.LevelWarn, Text: text})
	}
	if m := b.snmp.rcv.MIBs(); len(m.Errors) > 0 {
		text := fmt.Sprintf("%d files in the MIB folder didn't load; their names are missing. Settings → SNMP traps lists them.", len(m.Errors))
		if len(m.Errors) == 1 {
			text = "1 file in the MIB folder didn't load; its names are missing. Settings → SNMP traps lists it."
		}
		out = append(out, api.Banner{Kind: "snmp_mibs", Level: api.LevelInfo, Text: text})
	}
	return out
}

func snmpFirewallText(state string, port int) string {
	const fix = " In an administrator prompt, run: woodshed snmp on"
	switch state {
	case fwrule.StateDisabled:
		return fmt.Sprintf("The Windows firewall rule %q is turned off, so devices can't send SNMP traps to UDP port %d.", fwrule.SNMPRuleName, port) + fix
	case fwrule.StateMissing:
		return fmt.Sprintf("There's no Windows firewall rule for SNMP traps, so devices can't reach UDP port %d.", port) + fix
	case fwrule.StateWrongPort:
		return fmt.Sprintf("The Windows firewall rule %q allows another port, not %d, so devices can't send SNMP traps.", fwrule.SNMPRuleName, port) + fix
	}
	return ""
}

// runStateSNMP is the run-state file's snmp part (omitted while the listener is
// off, no user is set and no trap was received).
func (b *backend) runStateSNMP(cfg config.Config) *RunStateSNMP {
	if b.snmp == nil {
		return nil
	}
	l := cfg.Listeners.SNMP
	r := b.snmp.rcv
	users := r.Users()
	if !l.Enabled && len(users) == 0 && r.LastTrap().IsZero() {
		return nil
	}
	c, e, m := r.Counts(), r.Engine(), r.MIBs()
	rs := &RunStateSNMP{Enabled: l.Enabled, Port: l.Port, AnswerInforms: l.AnswerInforms, EngineID: e.ID, EngineBoots: e.Boots,
		Received24h: c.Received, InformsAnswered24h: c.InformsAnswered, RateLimited24h: c.RepliesRateLimited,
		TimeResyncs24h: c.TimeResyncs, ByStatus24h: c.ByStatus, Users: len(users), UnreadableUsers: r.UnreadableUsers(),
		MIBNames: m.Names, MIBErrors: len(m.Errors)}
	for i, f := range r.Failures() {
		if i == 5 {
			break
		}
		rs.Failures = append(rs.Failures, RunStateSNMPFailure{IP: f.IP, Count24h: f.Count24h, Status: f.Status, Detail: f.Detail,
			LastSeen: f.LastSeen.Truncate(time.Minute)})
	}
	return rs
}

// apiSettings is the settings object with the communities as hash prefixes
// (they're kept in the credentials file, never in the config).
func (b *backend) apiSettings(c config.Config) (api.Settings, error) {
	st, err := toAPISettings(c)
	if err != nil {
		return st, err
	}
	if st.Listeners.SNMP != nil && b.snmp != nil {
		st.Listeners.SNMP.Communities = b.snmp.rcv.Communities()
	}
	return st, nil
}

// saveCommunities applies a settings save's community list (hash prefixes keep
// the stored communities, plain strings add new ones).
func (b *backend) saveCommunities(in []string) error {
	err := b.snmp.rcv.SetCommunities(in)
	var ve *api.ValidationError
	if errors.As(err, &ve) {
		return ve
	}
	return err
}

// snmpChanged reports whether the SNMP listener's socket settings changed.
func snmpChanged(a, b config.SNMPListener) bool {
	return a.Enabled != b.Enabled || a.Addr != b.Addr || a.Port != b.Port
}
