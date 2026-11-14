package main

import (
	"regexp"
	"strings"
	"testing"
)

// No command takes a secret on its command line (SPEC §11.2.6, §11.6), where
// every local user would see it in the process list: a flag about a
// passphrase, a password or a community names a file instead.
func TestNoSecretOnTheCommandLine(t *testing.T) {
	flagRE := regexp.MustCompile(`(?m)^\s+-([a-z0-9-]+)`)
	for _, cmd := range []string{"run", "install", "status", "reindex", "search", "set-password", "lan-mode", "tls", "snmp",
		"update-check", "reset-password", "send", "bench", "portable"} {
		_, out, errOut := runCLI(cmd, "--help")
		ms := flagRE.FindAllStringSubmatch(out+errOut, -1)
		if cmd == "send" && !strings.Contains(out+errOut, "-auth-pass-file") || len(ms) == 0 && cmd != "portable" {
			t.Errorf("woodshed %s --help: no flags read (%d)", cmd, len(ms))
		}
		for _, m := range ms {
			name := m[1]
			secret := strings.Contains(name, "pass") || strings.Contains(name, "community") || strings.Contains(name, "secret")
			if secret && !strings.HasSuffix(name, "-file") {
				t.Errorf("woodshed %s --%s takes a secret on the command line", cmd, name)
			}
		}
	}
}
