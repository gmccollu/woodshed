package loadgen

import (
	"context"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/snmp"
)

// woodshed bench --proto trap: the whole trap pipeline (SNMP listener, queue,
// receiver, store) with every trap on disk exactly once, and every inform
// answered.
func TestBenchTrap(t *testing.T) {
	for _, to := range []TrapOptions{
		{Version: "2c", Varbinds: 10},
		{Version: "1"},
		{Version: "3", Inform: true, Auth: snmp.AuthSHA256, Priv: snmp.PrivAES128},
		{Version: "3", Auth: snmp.AuthSHA512, Priv: snmp.PrivAES256, KeyExt: snmp.KeyExtAlt},
	} {
		res, err := Bench(context.Background(), BenchOptions{Proto: "trap", Rate: 500, Duration: 400 * time.Millisecond, Trap: to,
			Settle: 2 * time.Second})
		if err != nil {
			t.Fatalf("%s: %v", to.Describe(), err)
		}
		if !res.OK() || res.Received != res.Sent || res.Sent < 150 {
			t.Fatalf("%s: %s", to.Describe(), res)
		}
		if to.Inform && (res.Informs == nil || res.Informs.Answered != int(res.Sent)) {
			t.Fatalf("%s: informs %+v", to.Describe(), res.Informs)
		}
	}
}
