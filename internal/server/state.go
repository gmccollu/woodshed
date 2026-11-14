package server

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/atomicfile"
)

// StateFileName is the run-state file a running server keeps in its data dir
// for `woodshed status`. It matters when the API can't answer, for example when
// the UI port is taken by another program: status then reads the UI error here.
const StateFileName = "woodshed.state.json"

// RunState is the content of the run-state file (docs/api.md, "Run-state
// file"). The server rewrites it within a second of any change.
type RunState struct {
	PID       int        `json:"pid"`
	Version   string     `json:"version"`
	StartedAt time.Time  `json:"started_at"`
	Config    string     `json:"config"`
	DataDir   string     `json:"data_dir"`
	UI        RunStateUI `json:"ui"`

	// The syslog listeners and the banners, exactly as /api/status has them
	// (so `woodshed status` can show them when the API needs a login).
	// Listeners is empty before the listeners start; Banners is sorted errors
	// first, like /api/status.
	Listeners               []api.Listener `json:"listeners"`
	UDPRcvbufBytes          int64          `json:"udp_rcvbuf_bytes"`
	UDPRcvbufRequestedBytes int64          `json:"udp_rcvbuf_requested_bytes"`
	Banners                 []api.Banner   `json:"banners"`
	// TLS is the TLS syslog listener: its certificate fingerprints and expiry,
	// and the senders failing most (omitted while it was never turned on).
	TLS *RunStateTLS `json:"tls,omitempty"`
	// SNMP is the SNMP trap receiver (snmpstate.go).
	SNMP *RunStateSNMP `json:"snmp,omitempty"`
}

// RunStateUI is the UI server's state.
type RunStateUI struct {
	Listening bool   `json:"listening"`
	URL       string `json:"url"`
	LANMode   bool   `json:"lan_mode"`
	Error     string `json:"error,omitempty"`
	// CertFingerprint is the SHA-256 of the LAN-mode certificate (AB:CD:…).
	CertFingerprint string `json:"cert_fingerprint,omitempty"`
}

func writeState(dataDir string, rs RunState) error {
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, StateFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o640); err != nil {
		return err
	}
	return atomicfile.Rename(tmp, path)
}

func removeState(dataDir string) {
	_ = os.Remove(filepath.Join(dataDir, StateFileName))
}

// ReadState reads the run-state file in dataDir. The file only means something
// while DataDirInUse reports true: a crashed server leaves it behind.
func ReadState(dataDir string) (RunState, error) {
	var rs RunState
	b, err := atomicfile.ReadFile(filepath.Join(dataDir, StateFileName))
	if err != nil {
		return rs, err
	}
	if err := json.Unmarshal(b, &rs); err != nil {
		return rs, errors.New("run-state file is malformed: " + err.Error())
	}
	return rs, nil
}
