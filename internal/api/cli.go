package api

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
)

// The helpers below let the woodshed CLI (set-password, lan-mode, status) work
// on the same files, in the same formats, as the server.

// CheckNewPassword returns why pw can't be a UI password, or "" if it can (the
// rule PUT /api/password applies).
func CheckNewPassword(pw string) string { return checkNewPassword(pw) }

// HashPassword returns the Argon2id PHC string the server stores in
// PasswordFile for pw.
func HashPassword(pw string) (string, error) { return hashPassword(pw, defaultArgon) }

// PasswordSet reports whether dataDir holds a UI password hash.
func PasswordSet(dataDir string) (bool, error) {
	h, err := readHash(dataDir)
	return h != "", err
}

// StableAddrs are the addresses the self-signed certificate covers, without
// loopback: where other machines reach the UI in LAN mode.
func StableAddrs() ([]netip.Addr, error) {
	id, err := localIdentity()
	if err != nil {
		return nil, err
	}
	return id.stableAddrs(), nil
}

// stableAddrs is id's addresses without loopback (StableAddrs, and
// /api/status's ui_addrs).
func (id hostIdentity) stableAddrs() []netip.Addr {
	var out []netip.Addr
	for _, ip := range id.IPs {
		if !ip.IsLoopback() {
			out = append(out, ip)
		}
	}
	return out
}

// CertFingerprintPEM is the SHA-256 of the first certificate in a PEM file's
// content, as /api/status shows it (AB:CD:…).
func CertFingerprintPEM(b []byte) (string, error) {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return "", errors.New("no certificate in the file")
		}
		if blk.Type == "CERTIFICATE" {
			if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
				return "", err
			}
			return certFingerprint(blk.Bytes), nil
		}
	}
}
