// Package model holds the types shared between Woodshed's packages.
package model

import (
	"net/netip"
	"strings"
	"time"
)

// Unknown marks a Facility or Severity that could not be parsed (no valid PRI).
const Unknown = -1

// Message is one received syslog message. Raw is always the bytes exactly as received
// (after framing, before any parsing); everything else is best-effort metadata.
type Message struct {
	Received  time.Time  // when Woodshed received it, UTC
	Sender    netip.Addr // source IP of the packet or connection
	Raw       []byte     // exact bytes as received (no trailing newline)
	Truncated bool       // Raw was cut at the max message size

	// Incomplete: the message's frame ended before all of it arrived (2.0). An
	// octet-counted TCP or TLS frame shorter than its count, whatever closed the
	// connection (FrameArrived of FrameLength bytes came), or a line Woodshed cut
	// by closing the connection itself (lengths 0: not known). Raw is what arrived.
	Incomplete                bool
	FrameArrived, FrameLength int64

	// Parsed metadata (zero values when absent).
	Facility  int       // 0-23, or Unknown if no PRI
	Severity  int       // 0-7, or Unknown if no PRI
	Timestamp time.Time // the device's own timestamp as a UTC instant, if parseable. Zone-less device times are
	// read as UTC wall-clock time (the real zone can't be known), so the UI labels this "device time".
	Hostname string
	App      string
}

// DeviceID returns the directory-safe device ID for a sender: the IP as text,
// with ':' replaced by '_' so IPv6 addresses are valid Windows file names.
func DeviceID(a netip.Addr) string {
	s := a.Unmap().String()
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ':' || s[i] == '%' {
			out[i] = '_'
		} else {
			out[i] = s[i]
		}
	}
	return string(out)
}

// ParseDeviceID is the address a device ID stands for, the inverse of
// DeviceID: ':' and an IPv6 zone's '%' are both written '_' there
// (fe80::1%en0 is "fe80__1_en0"), so a zoned ID is tried with each '_' from
// the right as the zone's, and only a parse that builds the same ID counts.
// ok is false for an ID that isn't an address (index.RefusedDeviceID).
func ParseDeviceID(id string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(strings.ReplaceAll(id, "_", ":")); err == nil {
		return a.Unmap(), true
	}
	for i := len(id) - 1; i > 0; i-- {
		if id[i] != '_' {
			continue
		}
		a, err := netip.ParseAddr(strings.ReplaceAll(id[:i], "_", ":") + "%" + id[i+1:])
		if err == nil && DeviceID(a) == id {
			return a, true
		}
	}
	return netip.Addr{}, false
}
