package snmp

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/gmccollu/woodshed/internal/atomicfile"
)

// EngineFile is the name of the engine state file in the data folder.
const EngineFile = "snmp-engine.json"

type engineState struct {
	EngineID    string `json:"engine_id"`
	EngineBoots int64  `json:"engine_boots"`
}

// LoadEngine reads the engine state at path (creating it with a new engine ID
// the first time), adds one to engineBoots, writes it back atomically and
// returns the engine, with snmpEngineTime counting from start (SPEC §11.2.3).
// override, when set, is the engine ID to use instead of the stored one (the
// stored one is kept for when the override is removed); boots count either way.
func LoadEngine(path string, override []byte, start time.Time) (*Engine, error) {
	var st engineState
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &st); err != nil {
			return nil, fmt.Errorf("snmp: %s: %w", path, err)
		}
		if _, err := ParseEngineID(st.EngineID); err != nil {
			return nil, fmt.Errorf("snmp: %s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		st.EngineID = hex.EncodeToString(NewEngineID())
	default:
		return nil, fmt.Errorf("snmp: %w", err)
	}
	if st.EngineBoots < maxBoots {
		st.EngineBoots++
	}
	if st.EngineBoots < 1 {
		st.EngineBoots = 1
	}
	out, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicfile.WriteFile(path, append(out, '\n'), 0o600); err != nil {
		return nil, fmt.Errorf("snmp: writing %s: %w", path, err)
	}
	id, _ := ParseEngineID(st.EngineID)
	if override != nil {
		id = append([]byte(nil), override...)
	}
	return &Engine{ID: id, Boots: st.EngineBoots, Start: start}, nil
}
