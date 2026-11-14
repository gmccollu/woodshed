// Package config is Woodshed's configuration: the TOML file (woodshed.toml) and the
// object behind /api/settings (docs/api.md). The JSON shape of Config is exactly
// the settings object; a few tuning knobs exist only in the file (json:"-").
//
// Load reads the file, creating it with defaults when it's missing; Save writes it
// atomically; Validate checks a Config and returns per-field errors keyed by dotted
// JSON paths ("listeners.udp.port", "listeners.allowlist[2]").
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/gmccollu/woodshed/internal/atomicfile"
)

// FileName is the config file's base name.
const FileName = "woodshed.toml"

// Defaults (SPEC §2, §3.1, §3.4, §4, §5).
const (
	DefaultListenAddr          = "0.0.0.0" // wildcard; Go binds it dual-stack (IPv4 and IPv6)
	DefaultSyslogPort          = 514
	DefaultUIPort              = 8514
	DefaultUDPRcvbufBytes      = 32 << 20
	DefaultMaxMessageBytes     = 64 << 10
	DefaultRetentionDays       = 30
	DefaultRetentionBytes      = 20 << 30
	DefaultPartBytes           = 100 << 20
	DefaultQuietAfterSeconds   = 300
	DefaultOfflineAfterSeconds = 3600
)

// Limits checked by Validate.
const (
	MinRetentionBytes  = 1 << 30
	MinPartBytes       = 1 << 20
	MaxPartBytes       = 1 << 30
	MinMaxMessageBytes = 2048     // RFC 5424 §6.1: receivers should accept 2048 octets
	MaxMaxMessageBytes = 16 << 20 // TCP only; a UDP datagram can't exceed 64 KiB anyway
	MaxUDPRcvbufBytes  = 1 << 30
)

// Config is the whole configuration. Its JSON form is the /api/settings object.
type Config struct {
	Listeners Listeners `toml:"listeners" json:"listeners"`
	Storage   Storage   `toml:"storage" json:"storage"`
	UI        UI        `toml:"ui" json:"ui"`
	Quiet     Quiet     `toml:"quiet" json:"quiet"`
	Updates   Updates   `toml:"updates" json:"updates"`
}

// Listeners configures the syslog listeners and the sender allowlist.
type Listeners struct {
	UDP Listener `toml:"udp" json:"udp" comment:"Syslog over UDP. addr 0.0.0.0 (or ::) listens on every interface, IPv4 and IPv6."`
	TCP Listener `toml:"tcp" json:"tcp" comment:"Syslog over TCP (octet-counted or newline-framed, detected per message)."`
	// TLS is syslog over TLS (tls.go), off by default.
	TLS TLSListener `toml:"tls" json:"tls" comment:"Syslog over TLS (RFC 5425), TCP 6514 by default. Off until you turn it on."`
	// Allowlist holds IPs or CIDRs; empty accepts every sender.
	Allowlist []string `toml:"allowlist" json:"allowlist" comment:"Accept messages only from these IPs or CIDRs, e.g. [\"192.0.2.0/24\", \"2001:db8::1\"]. Empty accepts everyone."`
	// Blocklist holds IPs or CIDRs whose messages are refused; it wins over the
	// allowlist (blocklist.go).
	Blocklist []string `toml:"blocklist" json:"blocklist" comment:"Refuse messages from these IPs or CIDRs, even if the allowlist accepts them."`
	// New-sender limits (devicelimits.go).
	MaxDevices          int `toml:"max_devices" json:"max_devices" comment:"At most this many senders active (heard in the last 10 minutes) at once; more are refused and counted as dropped."`
	NewDeviceBurst      int `toml:"new_device_burst" json:"new_device_burst" comment:"New senders (no logs yet) allowed in a burst,"`
	NewDevicesPerMinute int `toml:"new_devices_per_minute" json:"new_devices_per_minute" comment:"then this many a minute."`

	// File-only tuning (not part of /api/settings). Zero means the default.
	UDPRcvbufBytes  int `toml:"udp_rcvbuf_bytes" json:"-" comment:"UDP socket receive buffer to request, in bytes. The OS may grant less; the About page shows what it granted."`
	MaxMessageBytes int `toml:"max_message_bytes" json:"-" comment:"Longer messages are truncated (and counted), never dropped."`
	// TCP abuse limits (tcplimits.go).
	TCPMaxConnsPerSource int      `toml:"tcp_max_conns_per_source" json:"-" comment:"Open TCP connections allowed per sender address."`
	TCPMaxConnsPerPrefix int      `toml:"tcp_max_conns_per_prefix" json:"-" comment:"Open TCP connections allowed per IPv6 /64 (all its addresses together)."`
	TCPFrameTimeout      Duration `toml:"tcp_frame_timeout" json:"-" comment:"Once a TCP message starts, all of it must arrive within this (e.g. 60s); then the connection is closed and the part kept, marked truncated."`
	TCPIdleTimeout       Duration `toml:"tcp_idle_timeout" json:"-" comment:"Close a TCP connection that sends no complete message for this long (1m to 168h). Keep it long: some senders notice a closed connection only when a later write fails, and lose messages until they reconnect."`
	// UDP receive queue limits (udpqueue.go), per UDP socket.
	UDPQueueMessages int   `toml:"udp_queue_messages" json:"-" comment:"Each UDP listener queues at most this many messages (1,000 to 2,000,000) while writing to disk catches up; more are dropped and counted."`
	UDPQueueBytes    int64 `toml:"udp_queue_bytes" json:"-" comment:"and at most this many bytes of them (1 MiB to 1 GiB), whichever fills first."`
}

// Listener is one syslog listener.
type Listener struct {
	Enabled bool   `toml:"enabled" json:"enabled"`
	Addr    string `toml:"addr" json:"addr"`
	Port    int    `toml:"port" json:"port"`
}

// Storage configures the data directory and retention.
type Storage struct {
	// DataDir is read-only through the API (v1).
	DataDir        string `toml:"data_dir" json:"data_dir" comment:"Logs and index.db live here. Change it only with the service stopped (move the folder too)."`
	RetentionDays  int    `toml:"retention_days" json:"retention_days" comment:"Delete rotated logs older than this many days."`
	RetentionBytes int64  `toml:"retention_bytes" json:"retention_bytes" comment:"Delete the oldest rotated logs while all logs take more than this (bytes, at least 1 GiB)."`
	PartBytes      int64  `toml:"part_bytes" json:"part_bytes" comment:"Close a device's active file at this size (bytes, 1 MiB to 1 GiB)."`
}

// UI configures the web UI.
type UI struct {
	LANMode bool `toml:"lan_mode" json:"lan_mode" comment:"false: the UI listens on 127.0.0.1 only. true: on every interface, over HTTPS, with a password."`
	Port    int  `toml:"port" json:"port"`
	// CertFile and KeyFile are a user certificate for LAN mode (PEM); both empty
	// means the self-signed one generated on this machine.
	CertFile string `toml:"cert_file" json:"cert_file" comment:"LAN mode HTTPS certificate and key (PEM files, absolute paths). Leave both empty for the self-signed certificate."`
	KeyFile  string `toml:"key_file" json:"key_file"`
	// RequireLoginLocal makes localhost mode use the password and sessions too
	// (once a password is set), so other users of this machine can't use the UI.
	RequireLoginLocal bool `toml:"require_login_local" json:"require_login_local" comment:"true: the UI asks for the password on localhost too (needs a password)."`
	// ExtraHostnames are added to the self-signed certificate (DNS names or IPs).
	ExtraHostnames []string `toml:"extra_hostnames" json:"extra_hostnames" comment:"Extra names or IP addresses for the self-signed LAN mode certificate (e.g. a DNS alias)."`
	// TrustedHosts are extra Host header values the UI accepts (reverse proxies).
	TrustedHosts []string `toml:"trusted_hosts" json:"trusted_hosts" comment:"Extra Host values the UI accepts, host or host:port (e.g. a reverse proxy's public name)."`
}

// Quiet sets the device status thresholds (online, quiet, offline).
type Quiet struct {
	QuietAfterSeconds   int `toml:"quiet_after_seconds" json:"quiet_after_seconds" comment:"A device is quiet (amber) after this many seconds without a message,"`
	OfflineAfterSeconds int `toml:"offline_after_seconds" json:"offline_after_seconds" comment:"and offline (red) after this many."`
}

// Update check settings (SPEC §10.2).
const (
	UpdateCheckAsk = "ask" // the default: the UI asks once
	UpdateCheckOn  = "on"
	UpdateCheckOff = "off"
)

// Updates configures the opt-in update check (SPEC §10.2).
type Updates struct {
	Check string `toml:"check" json:"check" comment:"Check for new Woodshed versions once a day: \"ask\" (the default: ask once in the UI), \"on\" or \"off\". It fetches one public file and sends nothing about this server."`
}

// ValidUpdateCheck reports whether v is a value updates.check accepts.
func ValidUpdateCheck(v string) bool {
	return v == UpdateCheckAsk || v == UpdateCheckOn || v == UpdateCheckOff
}

// Default returns the default configuration for this OS.
func Default() Config {
	return Config{
		Listeners: Listeners{
			UDP:             Listener{Enabled: true, Addr: DefaultListenAddr, Port: DefaultSyslogPort},
			TCP:             Listener{Enabled: true, Addr: DefaultListenAddr, Port: DefaultSyslogPort},
			TLS:             TLSListener{Addr: DefaultListenAddr, Port: DefaultTLSPort},
			Allowlist:       []string{},
			Blocklist:       []string{},
			UDPRcvbufBytes:  DefaultUDPRcvbufBytes,
			MaxMessageBytes: DefaultMaxMessageBytes,

			TCPMaxConnsPerSource: DefaultTCPMaxConnsPerSource,
			TCPFrameTimeout:      DefaultTCPFrameTimeout,
			TCPIdleTimeout:       DefaultTCPIdleTimeout,
			TCPMaxConnsPerPrefix: DefaultTCPMaxConnsPerPrefix,

			MaxDevices:          DefaultMaxDevices,
			NewDeviceBurst:      DefaultNewDeviceBurst,
			NewDevicesPerMinute: DefaultNewDevicesPerMinute,

			UDPQueueMessages: DefaultUDPQueueMessages,
			UDPQueueBytes:    DefaultUDPQueueBytes,
		},
		Storage: Storage{
			DataDir:        DefaultDataDir(),
			RetentionDays:  DefaultRetentionDays,
			RetentionBytes: DefaultRetentionBytes,
			PartBytes:      DefaultPartBytes,
		},
		UI:      UI{Port: DefaultUIPort, ExtraHostnames: []string{}, TrustedHosts: []string{}},
		Quiet:   Quiet{QuietAfterSeconds: DefaultQuietAfterSeconds, OfflineAfterSeconds: DefaultOfflineAfterSeconds},
		Updates: Updates{Check: UpdateCheckAsk},
	}
}

// Clone returns a deep copy (the allowlist is not shared).
func (c Config) Clone() Config {
	c.Listeners.Allowlist = append([]string{}, c.Listeners.Allowlist...)
	c.Listeners.Blocklist = append([]string{}, c.Listeners.Blocklist...)
	c.UI.ExtraHostnames = append([]string{}, c.UI.ExtraHostnames...)
	c.UI.TrustedHosts = append([]string{}, c.UI.TrustedHosts...)
	return c
}

// Normalize fills what a decoded Config may lack: a nil allowlist becomes empty
// (so it serializes as [] rather than null), allowlist entries are trimmed, and zero
// file-only fields (UDPRcvbufBytes, MaxMessageBytes) take their defaults. It
// doesn't touch anything Validate checks otherwise.
func (c *Config) Normalize() {
	al := make([]string, 0, len(c.Listeners.Allowlist))
	for _, s := range c.Listeners.Allowlist {
		al = append(al, strings.TrimSpace(s))
	}
	c.Listeners.Allowlist = al
	c.Listeners.Blocklist = trimList(c.Listeners.Blocklist)
	c.UI.ExtraHostnames = normalizeHosts(c.UI.ExtraHostnames)
	c.UI.TrustedHosts = normalizeHosts(c.UI.TrustedHosts)
	if c.Listeners.UDPRcvbufBytes == 0 {
		c.Listeners.UDPRcvbufBytes = DefaultUDPRcvbufBytes
	}
	if c.Listeners.MaxMessageBytes == 0 {
		c.Listeners.MaxMessageBytes = DefaultMaxMessageBytes
	}
	normalizeTCPLimits(&c.Listeners)
	normalizeDeviceLimits(&c.Listeners)
	normalizeUDPQueue(&c.Listeners)
}

// Prefixes parses the allowlist: an IP becomes a single-address prefix and IPv4-mapped
// IPv6 addresses are unmapped. Validate first; Prefixes fails on the first bad entry.
func (l Listeners) Prefixes() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(l.Allowlist))
	for _, s := range l.Allowlist {
		p, err := parseAllow(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
		}
		if p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q: zones aren't allowed in a CIDR", s)
		}
		if p.Addr().Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not an IP address or CIDR", s)
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Load reads the config at path. If the file doesn't exist it's created with
// Default() (directory mode 0750, file 0640). Keys missing from the file take their
// defaults; unknown keys are ignored (a newer version's file still loads). Load
// doesn't validate: call Validate.
func Load(path string) (Config, error) {
	c, _, err := LoadOrCreate(path, Default())
	return c, err
}

// Read reads the config at path like Load, but never creates it: a missing or
// unreadable file is an error (errors.Is fs.ErrNotExist or fs.ErrPermission).
// For looking at another Woodshed's config.
func Read(path string) (Config, error) {
	b, err := atomicfile.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	return decode(path, b, Default())
}

// LoadOrCreate is Load with explicit defaults, and reports whether it created the file.
func LoadOrCreate(path string, def Config) (Config, bool, error) {
	b, err := atomicfile.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		c := def.Clone()
		c.Normalize()
		if err := Save(path, c); err != nil {
			return Config{}, false, err
		}
		return c, true, nil
	}
	if err != nil {
		return Config{}, false, fmt.Errorf("config: %w", err)
	}
	c, err := decode(path, b, def)
	return c, false, err
}

// decode parses a config file's content over def.
func decode(path string, b []byte, def Config) (Config, error) {
	c := def.Clone()
	c.Listeners.Allowlist = nil // a file without the key gets [] from Normalize
	c.Listeners.Blocklist = nil
	if err := toml.Unmarshal(b, &c); err != nil {
		var de *toml.DecodeError
		if errors.As(err, &de) {
			row, col := de.Position()
			return Config{}, fmt.Errorf("config: %s:%d:%d: %s", path, row, col, de.Error())
		}
		return Config{}, fmt.Errorf("config: %s: %w", path, err)
	}
	c.Normalize()
	return c, nil
}

const header = `# Woodshed configuration. The service reads it at start; the web UI's Settings page
# edits it too (and rewrites this file, without your comments).
# Sizes are in bytes. See SPEC.md for what each setting does.

`

// Marshal returns the TOML form of c, with a header and a comment on each setting.
func Marshal(c Config) ([]byte, error) {
	c = c.Clone()
	c.Normalize()
	b, err := toml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return append([]byte(header), b...), nil
}

// Save writes c to path atomically: a temp file in the same directory, fsynced,
// then renamed over path. The directory is created with mode 0750 and the file
// gets 0640.
func Save(path string, c Config) error {
	b, err := Marshal(c)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	f, err := os.CreateTemp(dir, "."+FileName+"-*.tmp")
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if runtime.GOOS != "windows" {
		if err := f.Chmod(0o640); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	if _, err := f.Write(b); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := atomicfile.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	ok = true
	syncDir(dir)
	return nil
}

// syncDir fsyncs a directory so a rename survives a crash. Best effort; Windows
// can't fsync a directory.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
