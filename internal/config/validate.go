package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// Errors maps a dotted JSON path ("listeners.udp.port", "listeners.allowlist[2]")
// to a human-readable message, as in the 400 body of PUT /api/settings.
type Errors map[string]string

// Error joins the messages in key order.
func (e Errors) Error() string {
	keys := make([]string, 0, len(e))
	for k := range e {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + e[k]
	}
	return "config: " + strings.Join(parts, "; ")
}

// Err returns e as an error, or nil when it's empty (so a nil map never ends up in
// a non-nil error interface).
func (e Errors) Err() error {
	if len(e) == 0 {
		return nil
	}
	return e
}

// Validate checks c. prev is the configuration in effect (nil at startup); with it,
// a changed storage.data_dir is an error, because the data dir is read-only in v1.
// It returns nil when c is valid.
func (c Config) Validate(prev *Config) Errors {
	return c.validate(runtime.GOOS, prev)
}

func (c Config) validate(goos string, prev *Config) Errors {
	e := Errors{}
	l := c.Listeners
	checkListener(e, goos, "listeners.udp", l.UDP)
	checkListener(e, goos, "listeners.tcp", l.TCP)
	checkTLSListener(e, goos, l)
	checkBlocklist(e, l)
	for i, s := range l.Allowlist {
		if _, err := parseAllow(s); err != nil {
			e[fmt.Sprintf("listeners.allowlist[%d]", i)] = "must be an IP address or a CIDR (e.g. 192.0.2.0/24)"
		}
	}
	if l.UDPRcvbufBytes < 0 || l.UDPRcvbufBytes > MaxUDPRcvbufBytes {
		e["listeners.udp_rcvbuf_bytes"] = fmt.Sprintf("must be between 0 (default) and %d", MaxUDPRcvbufBytes)
	}
	if l.MaxMessageBytes != 0 && (l.MaxMessageBytes < MinMaxMessageBytes || l.MaxMessageBytes > MaxMaxMessageBytes) {
		e["listeners.max_message_bytes"] = fmt.Sprintf("must be between %d and %d", MinMaxMessageBytes, MaxMaxMessageBytes)
	}
	checkTCPLimits(e, l)
	checkDeviceLimits(e, l)
	checkUDPQueue(e, l)

	s := c.Storage
	switch {
	case strings.TrimSpace(s.DataDir) == "":
		e["storage.data_dir"] = "is required"
	case prev != nil && filepath.Clean(s.DataDir) != filepath.Clean(prev.Storage.DataDir):
		e["storage.data_dir"] = "can't be changed here: stop the service, move the folder and edit data_dir in the config file"
	case !isAbs(s.DataDir):
		e["storage.data_dir"] = "must be an absolute path"
	}
	if s.RetentionDays < 1 {
		e["storage.retention_days"] = "must be at least 1"
	}
	if s.RetentionBytes < MinRetentionBytes {
		e["storage.retention_bytes"] = "must be at least 1 GiB (1073741824)"
	}
	if s.PartBytes < MinPartBytes || s.PartBytes > MaxPartBytes {
		e["storage.part_bytes"] = "must be between 1 MiB (1048576) and 1 GiB (1073741824)"
	}

	switch p := c.UI.Port; {
	case p < 1 || p > 65535:
		e["ui.port"] = "must be between 1 and 65535"
	case p == l.UDP.Port || p == l.TCP.Port || p == l.TLS.Port:
		e["ui.port"] = "can't be the same as a syslog listener port"
	}

	checkCertPair(e, c.UI)
	checkUIHosts(e, c.UI)

	q := c.Quiet
	if q.QuietAfterSeconds < 1 {
		e["quiet.quiet_after_seconds"] = "must be at least 1"
	} else if q.QuietAfterSeconds >= q.OfflineAfterSeconds {
		e["quiet.quiet_after_seconds"] = "must be less than offline_after_seconds"
	}
	if q.OfflineAfterSeconds < 1 {
		e["quiet.offline_after_seconds"] = "must be at least 1"
	}
	if !ValidUpdateCheck(c.Updates.Check) {
		e["updates.check"] = `must be "ask", "on" or "off"`
	}
	if len(e) == 0 {
		return nil
	}
	return e
}

// checkCertPair: ui.cert_file and ui.key_file are both empty, or both absolute
// paths to existing files.
func checkCertPair(e Errors, ui UI) {
	checkFilePair(e, "ui", ui.CertFile, ui.KeyFile, "the self-signed certificate")
}

// checkFilePair checks a <prefix>.cert_file / <prefix>.key_file pair: both
// empty (empty names what that means), or both absolute paths to readable
// files.
func checkFilePair(e Errors, prefix, certPath, keyPath, empty string) {
	cert, key := strings.TrimSpace(certPath), strings.TrimSpace(keyPath)
	if cert == "" && key == "" {
		return
	}
	// One message for every way a file can be wrong: the check runs as the
	// service account, and saying "not found" versus "permission denied" would
	// tell a UI user which files exist where they can't look.
	check := func(k, p, other, what string) {
		switch {
		case p == "":
			e[k] = "is required when " + other + " is set (or leave both empty for " + empty + ")"
		case !isAbs(p):
			e[k] = "must be an absolute path"
		default:
			if fi, err := os.Stat(p); err != nil || !fi.Mode().IsRegular() {
				e[k] = "is not a readable " + what + " file"
			} else if f, err := os.Open(p); err != nil {
				e[k] = "is not a readable " + what + " file"
			} else {
				f.Close()
			}
		}
	}
	check(prefix+".cert_file", cert, "key_file", "certificate")
	check(prefix+".key_file", key, "cert_file", "key")
}

func checkListener(e Errors, goos, key string, ln Listener) {
	if ln.Port < 1 || ln.Port > 65535 {
		e[key+".port"] = "must be between 1 and 65535"
	}
	a, err := netip.ParseAddr(strings.TrimSpace(ln.Addr))
	if err != nil {
		e[key+".addr"] = "must be an IP address (0.0.0.0 or :: listens on every interface)"
		return
	}
	// SPEC §3.1/§5: on macOS a non-root process can bind a port below 1024 only on
	// the wildcard address.
	if goos == "darwin" && ln.Enabled && ln.Port >= 1 && ln.Port < 1024 && !a.IsUnspecified() {
		e[key+".addr"] = fmt.Sprintf("on macOS, port %d can only be bound on every interface (0.0.0.0 or ::); "+
			"use the sender allowlist to restrict who can send, or pick a port of 1024 or above", ln.Port)
	}
}
