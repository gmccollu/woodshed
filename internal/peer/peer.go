// Package peer finds another Woodshed on this machine: the installed service,
// or another running copy. It needs no privileges, so an ordinary user's copy
// can tell that the ports it can't bind are probably held by the service (whose
// sockets lsof and /proc don't show to other users).
//
// The service is found through the service manager (launchd, systemd, the
// Windows SCM), which any user may query; other copies through run-state files
// (woodshed.state.json) the caller names, when they're readable.
package peer

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/atomicfile"
)

// Kind is what kind of Woodshed a peer is (docs/api.md, holder_kind).
type Kind string

// Peer kinds.
const (
	KindService Kind = "woodshed_service" // the installed service
	KindCopy    Kind = "woodshed"         // another running copy (woodshed run, portable)
)

// Info describes a running peer.
type Info struct {
	Kind  Kind
	PID   int    // 0 if unknown
	UIURL string // "" if unknown
	// UIKnown is set when a run-state file said whether the peer's UI is
	// listening; UIListening and UIError are what it said.
	UIKnown     bool
	UIListening bool
	UIError     string
	// Config is the config file the peer runs with, and Listeners its syslog
	// listeners, from its run-state file ("" and nil when that wasn't readable,
	// or before its listeners started).
	Config    string
	Listeners []Listener
}

// Listener is one of a peer's enabled syslog listeners.
type Listener struct {
	Proto string `json:"proto"` // "udp" or "tcp"
	Port  int    `json:"port"`
}

// Options configures Find. Zero fields take the real thing.
type Options struct {
	// StateFiles are run-state files to read for peers (and the service's UI
	// address); unreadable ones are skipped.
	StateFiles []string
	// SelfPID is this process (never reported as a peer).
	SelfPID int

	run   func(ctx context.Context, name string, args ...string) ([]byte, error)
	query func(ctx context.Context, o *Options) (running bool, pid int) // the OS's service query
	alive func(pid int) bool
}

// Find returns the peer Woodshed, if one is running: the service first, else a
// copy named by a run-state file whose process is alive.
func Find(ctx context.Context, o Options) (Info, bool) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if o.run == nil {
		o.run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).Output()
		}
	}
	if o.query == nil {
		o.query = serviceQuery
	}
	if o.alive == nil {
		o.alive = processAlive
	}
	states := readStates(o.StateFiles)
	if running, pid := o.query(ctx, &o); running && pid != o.SelfPID {
		info := Info{Kind: KindService, PID: pid}
		for _, st := range states {
			if pid == 0 || st.PID == pid {
				info.PID, info.UIURL = st.PID, st.UI.URL
				info.UIKnown, info.UIListening, info.UIError = true, st.UI.Listening, st.UI.Error
				info.Config, info.Listeners = st.Config, st.Listeners
				break
			}
		}
		return info, true
	}
	for _, st := range states {
		if st.PID > 0 && st.PID != o.SelfPID && o.alive(st.PID) {
			return Info{Kind: KindCopy, PID: st.PID, UIURL: st.UI.URL, UIKnown: true, UIListening: st.UI.Listening, UIError: st.UI.Error,
				Config: st.Config, Listeners: st.Listeners}, true
		}
	}
	return Info{}, false
}

// runState is the part of server.RunState read here (the server package
// imports this one).
type runState struct {
	PID    int    `json:"pid"`
	Config string `json:"config"`
	UI     struct {
		Listening bool   `json:"listening"`
		URL       string `json:"url"`
		Error     string `json:"error"`
	} `json:"ui"`
	Listeners []Listener `json:"listeners"`
}

func readStates(paths []string) []runState {
	var out []runState
	for _, p := range paths {
		b, err := atomicfile.ReadFile(p)
		if err != nil || len(b) > 1<<20 {
			continue
		}
		var st runState
		if json.Unmarshal(b, &st) == nil && st.PID > 0 {
			out = append(out, st)
		}
	}
	return out
}

// parseLaunchctl reads `launchctl print system/<label>`: "state = running" and
// "pid = N" at the service's top level.
func parseLaunchctl(out []byte) (running bool, pid int) {
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		// Top-level keys are indented by one tab; nested blocks by more.
		if !strings.HasPrefix(line, "\t") || strings.HasPrefix(line, "\t\t") {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), " = ")
		if !ok {
			continue
		}
		switch k {
		case "state":
			running = v == "running"
		case "pid":
			pid, _ = strconv.Atoi(v)
		}
	}
	return running, pid
}

// parseSystemctl reads `systemctl show <unit> -p MainPID,ActiveState`.
func parseSystemctl(out []byte) (running bool, pid int) {
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveState":
			running = v == "active" || v == "reloading"
		case "MainPID":
			pid, _ = strconv.Atoi(v)
		}
	}
	return running, pid
}

// ProcessAlive reports whether a process with this PID exists (another
// user's included).
func ProcessAlive(pid int) bool { return pid > 0 && processAlive(pid) }
