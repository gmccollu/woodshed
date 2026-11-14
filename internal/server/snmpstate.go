package server

import "time"

// RunStateSNMP is the SNMP trap receiver's part of the run-state file, for
// `woodshed snmp status` and `woodshed status` (omitted while the listener was
// never turned on and has no engine file).
type RunStateSNMP struct {
	Enabled       bool   `json:"enabled"`
	Port          int    `json:"port"`
	AnswerInforms bool   `json:"answer_informs"`
	EngineID      string `json:"engine_id,omitempty"` // hex
	EngineBoots   int64  `json:"engine_boots,omitempty"`
	Error         string `json:"error,omitempty"` // why the listener or its engine couldn't start
	// The last 24 hours.
	Received24h        int64            `json:"received_24h"`
	InformsAnswered24h int64            `json:"informs_answered_24h"`
	RateLimited24h     int64            `json:"replies_rate_limited_24h"`
	TimeResyncs24h     int64            `json:"time_resyncs_24h"`
	ByStatus24h        map[string]int64 `json:"by_status_24h,omitempty"`
	Users              int              `json:"users"`
	UnreadableUsers    int              `json:"unreadable_users,omitempty"`
	MIBNames           int              `json:"mib_names"`
	MIBErrors          int              `json:"mib_errors,omitempty"`
	// Failures are the 5 senders failing most in the last 24 hours.
	Failures []RunStateSNMPFailure `json:"failures,omitempty"`
}

// RunStateSNMPFailure is one failing sender.
type RunStateSNMPFailure struct {
	IP       string    `json:"ip"`
	Count24h int64     `json:"count_24h"`
	Status   string    `json:"status"`
	Detail   string    `json:"detail"`
	LastSeen time.Time `json:"last_seen"`
}
