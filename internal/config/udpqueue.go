package config

import "fmt"

// UDP receive queue limits (SPEC §11.5, file-only, see Listeners): each UDP
// socket's queue between its reader and the store holds at most this many
// messages and bytes, whichever fills first.
const (
	DefaultUDPQueueMessages = 100000 // 10 s at the 10,000 msg/s target
	DefaultUDPQueueBytes    = 64 << 20

	MinUDPQueueMessages = 1000
	MaxUDPQueueMessages = 2000000
	MinUDPQueueBytes    = 1 << 20
	MaxUDPQueueBytes    = 1 << 30
)

// normalizeUDPQueue gives zero queue limits their defaults (a 1.1 file has
// neither key).
func normalizeUDPQueue(l *Listeners) {
	if l.UDPQueueMessages == 0 {
		l.UDPQueueMessages = DefaultUDPQueueMessages
	}
	if l.UDPQueueBytes == 0 {
		l.UDPQueueBytes = DefaultUDPQueueBytes
	}
}

func checkUDPQueue(e Errors, l Listeners) {
	if n := l.UDPQueueMessages; n != 0 && (n < MinUDPQueueMessages || n > MaxUDPQueueMessages) {
		e["listeners.udp_queue_messages"] = fmt.Sprintf("must be between %d and %d", MinUDPQueueMessages, MaxUDPQueueMessages)
	}
	if n := l.UDPQueueBytes; n != 0 && (n < MinUDPQueueBytes || n > MaxUDPQueueBytes) {
		e["listeners.udp_queue_bytes"] = fmt.Sprintf("must be between %d (1 MiB) and %d (1 GiB)", MinUDPQueueBytes, MaxUDPQueueBytes)
	}
}
