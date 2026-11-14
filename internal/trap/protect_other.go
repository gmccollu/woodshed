//go:build !windows

package trap

// Off Windows the credentials file is protected by its mode (0600, owned by
// the service account, in the 0750 data folder; SPEC §11.2.6): macOS's
// Keychain needs cgo and a login keychain a daemon doesn't have, and Linux
// has no key store for system services. The blob is stored as it is.

func protect(plain []byte) ([]byte, error) { return append([]byte{}, plain...), nil }

func unprotect(blob []byte) ([]byte, error) { return append([]byte{}, blob...), nil }
