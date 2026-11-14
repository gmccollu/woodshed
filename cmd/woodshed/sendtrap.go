package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/loadgen"
	"github.com/gmccollu/woodshed/internal/snmp"
)

// The environment variables `woodshed send --proto trap` reads secrets from
// when no file is given (SPEC §11.6): never from a command line.
const (
	envSNMPCommunity = "WOODSHED_SNMP_COMMUNITY"
	envSNMPAuthPass  = "WOODSHED_SNMP_AUTH_PASS"
	envSNMPPrivPass  = "WOODSHED_SNMP_PRIV_PASS"
)

// trapFlags are `woodshed send`'s flags for --proto trap.
type trapFlags struct {
	version, communityFile, user, auth, priv, keyExt, authPassFile, privPassFile, trapOID, engineID *string
	inform                                                                                          *bool
	varbinds                                                                                        *int
	timeout                                                                                         *time.Duration
}

var trapFlagNames = map[string]bool{
	"snmp-version": true, "inform": true, "community-file": true, "user": true, "auth": true, "priv": true,
	"key-ext": true, "auth-pass-file": true, "priv-pass-file": true, "trap-oid": true, "varbinds": true,
	"engine-id": true, "timeout": true,
}

func addTrapFlags(fs *cmdFlags) *trapFlags {
	return &trapFlags{
		version:       fs.String("snmp-version", "2c", "trap: SNMP `version`: 1, 2c or 3"),
		inform:        fs.Bool("inform", false, "trap: send informs and wait for each Response (2c, 3); reports round trips and timeouts"),
		communityFile: fs.String("community-file", "", "trap: read the v1/v2c community from this `file` (else $"+envSNMPCommunity+", else \"public\")"),
		user:          fs.String("user", "", "trap: the SNMPv3 user `name`"),
		auth:          fs.String("auth", "none", "trap: v3 authentication `protocol`: none, md5, sha, sha-224, sha-256, sha-384 or sha-512"),
		priv:          fs.String("priv", "none", "trap: v3 privacy `protocol`: none, des, aes-128, aes-192 or aes-256"),
		keyExt:        fs.String("key-ext", "draft", "trap: AES-192/256 key extension `method`: draft or alt"),
		authPassFile:  fs.String("auth-pass-file", "", "trap: read the v3 authentication passphrase from this `file` (else $"+envSNMPAuthPass+")"),
		privPassFile:  fs.String("priv-pass-file", "", "trap: read the v3 privacy passphrase from this `file` (else $"+envSNMPPrivPass+")"),
		trapOID:       fs.String("trap-oid", loadgen.DefaultTrapOID.String(), "trap: the snmpTrapOID, numeric or a built-in `name` such as linkDown"),
		varbinds:      fs.Int("varbinds", 1, "trap: varbinds per trap after the header, the sequence one first (`number`)"),
		engineID:      fs.String("engine-id", "", "trap: v3 engine ID in `hex`: the sender's for traps (default random), the receiver's for informs (default: discovered)"),
		timeout:       fs.Duration("timeout", loadgen.DefaultInformTimeout, "trap: how long an inform waits for its Response (a `duration`)"),
	}
}

// readSNMPSecret reads a secret from file (one line; a trailing CR/LF is dropped)
// or else from the environment variable env. It returns nil when neither is set.
func readSNMPSecret(file, env string) ([]byte, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		b = bytes.TrimRight(b, "\r\n")
		if len(b) == 0 {
			return nil, fmt.Errorf("%s is empty", file)
		}
		return b, nil
	}
	if v, ok := os.LookupEnv(env); ok && v != "" {
		return []byte(v), nil
	}
	return nil, nil
}

// trapOptions turns the flags into loadgen's options; errors are usage errors.
func (f *trapFlags) options() (loadgen.TrapOptions, error) {
	t := loadgen.TrapOptions{Version: strings.ToLower(*f.version), Inform: *f.inform, User: *f.user, Varbinds: *f.varbinds, Timeout: *f.timeout}
	switch t.Version {
	case "1", "2c", "3":
	case "2":
		t.Version = "2c"
	default:
		return t, fmt.Errorf("--snmp-version must be 1, 2c or 3, not %q", *f.version)
	}
	var err error
	if t.Auth, err = snmp.ParseAuthProtocol(*f.auth); err != nil {
		return t, errors.New(strings.TrimPrefix(err.Error(), "snmp: "))
	}
	if t.Priv, err = snmp.ParsePrivProtocol(*f.priv); err != nil {
		return t, errors.New(strings.TrimPrefix(err.Error(), "snmp: "))
	}
	if t.KeyExt, err = snmp.ParseKeyExt(*f.keyExt); err != nil {
		return t, errors.New(strings.TrimPrefix(err.Error(), "snmp: "))
	}
	if t.TrapOID, err = snmp.ParseOID(*f.trapOID); err != nil {
		if t.TrapOID, err = snmp.BuiltinMIBs().Lookup(*f.trapOID); err != nil {
			return t, fmt.Errorf("--trap-oid %q is neither a numeric OID nor a built-in name", *f.trapOID)
		}
	}
	if *f.varbinds < 1 || *f.varbinds > 1000 {
		return t, errors.New("--varbinds must be 1 to 1000")
	}
	if *f.engineID != "" {
		if t.EngineID, err = snmp.ParseEngineID(*f.engineID); err != nil {
			return t, fmt.Errorf("--engine-id: %s", strings.TrimPrefix(err.Error(), "snmp: "))
		}
	}
	if t.Version != "3" {
		if *f.user != "" || t.Auth != snmp.AuthNone || t.Priv != snmp.PrivNone || *f.engineID != "" || *f.authPassFile != "" || *f.privPassFile != "" {
			return t, errors.New("--user, --auth, --priv, --engine-id and the passphrase files are for --snmp-version 3")
		}
		if t.Community, err = readSNMPSecret(*f.communityFile, envSNMPCommunity); err != nil {
			return t, fmt.Errorf("--community-file: %v", err)
		}
		return t, nil
	}
	if *f.communityFile != "" {
		return t, errors.New("--community-file is for --snmp-version 1 and 2c")
	}
	if t.User == "" {
		return t, errors.New("--snmp-version 3 needs --user")
	}
	if t.Priv != snmp.PrivNone && t.Auth == snmp.AuthNone {
		return t, errors.New("--priv needs --auth")
	}
	if t.Auth != snmp.AuthNone {
		if t.AuthPass, err = readSNMPSecret(*f.authPassFile, envSNMPAuthPass); err != nil {
			return t, fmt.Errorf("--auth-pass-file: %v", err)
		}
		if t.AuthPass == nil {
			return t, fmt.Errorf("--auth needs a passphrase: --auth-pass-file FILE or $%s", envSNMPAuthPass)
		}
	}
	if t.Priv != snmp.PrivNone {
		if t.PrivPass, err = readSNMPSecret(*f.privPassFile, envSNMPPrivPass); err != nil {
			return t, fmt.Errorf("--priv-pass-file: %v", err)
		}
		if t.PrivPass == nil {
			return t, fmt.Errorf("--priv needs a passphrase: --priv-pass-file FILE or $%s", envSNMPPrivPass)
		}
	}
	return t, nil
}

// checkTrapFlags refuses the trap flags with another protocol, and the
// syslog-only flags with --proto trap.
func checkTrapFlags(fs *cmdFlags, proto string) error {
	var bad []string
	fs.Visit(func(f *flag.Flag) {
		trapOnly := trapFlagNames[f.Name]
		syslogOnly := f.Name == "framing" || f.Name == "size" || f.Name == "hostname"
		if (proto == "trap" && syslogOnly) || (proto != "trap" && trapOnly) {
			bad = append(bad, "--"+f.Name)
		}
	})
	if len(bad) == 0 {
		return nil
	}
	if proto == "trap" {
		return fmt.Errorf("%s: not for --proto trap", strings.Join(bad, ", "))
	}
	return fmt.Errorf("%s: only for --proto trap", strings.Join(bad, ", "))
}

// sendTrapResult prints a trap run's result and returns the exit code.
func sendTrapResult(stdout, stderr io.Writer, o loadgen.SendOptions, res loadgen.SendResult, err error) int {
	kind := "trap"
	if o.Trap.Inform {
		kind = "inform"
	}
	plural := "s"
	if res.Sent == 1 {
		plural = ""
	}
	if res.Sent > 0 || err == nil {
		fmt.Fprintf(stdout, "Sent %d %s%s (%s) to %s in %v (%.0f/s), run %s.\n",
			res.Sent, kind, plural, o.Trap.Describe(), o.Addr, res.Elapsed.Round(time.Millisecond), res.Rate, res.RunID)
	}
	code := 0
	if st := res.Informs; st != nil {
		fmt.Fprintf(stdout, "%d answered, %d timed out", st.Answered, st.TimedOut)
		if st.Resent > 0 {
			fmt.Fprintf(stdout, ", %d sent again after a Report", st.Resent)
		}
		if len(st.RTTs) > 0 {
			fmt.Fprintf(stdout, "; round trip p50 %v, p99 %v, max %v", st.Percentile(50).Round(10*time.Microsecond),
				st.Percentile(99).Round(10*time.Microsecond), st.Percentile(100).Round(10*time.Microsecond))
		}
		fmt.Fprintln(stdout, ".")
		if st.TimedOut > 0 {
			code = 1
		}
	}
	if res.Sent > 0 {
		fmt.Fprintf(stdout, "Find them by searching for %q.\n", loadgen.SeqTag(res.RunID))
	}
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "woodshed send: interrupted")
			return 1
		}
		return fail(stderr, "send", err)
	}
	if !o.Trap.Inform {
		fmt.Fprintln(stdout, "(Traps have no delivery confirmation: check the receiver to see that they arrived.)")
	}
	return code
}
