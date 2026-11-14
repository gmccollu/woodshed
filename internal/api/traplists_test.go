package api

import (
	"encoding/json"
	"testing"
)

// Trap filters in JSON bodies take strings, or numbers for the numeric ones.
func TestTrapListsNumbers(t *testing.T) {
	var tl TrapLists
	if err := json.Unmarshal([]byte(`{"generic": [0, 6], "specific": ["17"], "pdus": ["inform"]}`), &tl); err != nil {
		t.Fatal(err)
	}
	f, err := tl.Filter()
	if err != nil || f == nil || len(f.Generic) != 2 || f.Generic[1] != "6" || f.Specific[0] != "17" || f.PDUs[0] != "inform" {
		t.Fatalf("%+v %v", f, err)
	}
	if err := json.Unmarshal([]byte(`{"generic": [true]}`), &tl); err == nil {
		t.Fatal("a boolean value")
	}
}
