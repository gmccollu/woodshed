package trap

import (
	"net/netip"
	"time"

	"github.com/gmccollu/woodshed/internal/listen"
)

// packet is a datagram from src without a socket (replies fail quietly).
func packet(raw []byte, at time.Time) *listen.TrapPacket {
	return &listen.TrapPacket{Raw: raw, From: netip.AddrPortFrom(src, 50000), Received: at}
}
