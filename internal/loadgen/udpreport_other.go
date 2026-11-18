//go:build !windows

package loadgen

import "net"

// reportRefusals: elsewhere a connected UDP socket reports ICMP port
// unreachable (ECONNREFUSED) already.
func reportRefusals(net.Conn) {}
