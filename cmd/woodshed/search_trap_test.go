package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/snmp"
	"github.com/gmccollu/woodshed/internal/store"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// woodshed search --type trap (SPEC §11.4, §11.2.5): a data folder with syslog
// and traps; the trap search reads only the traps, with the trap filters, and
// its JSON is the API's trap shape.
func TestSearchTraps(t *testing.T) {
	f := newSearchFixture(t)
	idx, err := index.Open(filepath.Join(f.dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	at := fxNow.Add(-2 * time.Hour)
	st, err := store.Open(store.Options{DataDir: f.dir, Index: idx, Manual: true, Clock: func() time.Time { return at },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		trap := "1.3.6.1.6.3.1.1.5.3"
		if i%2 == 1 {
			trap = "1.3.6.1.6.3.1.1.5.4"
		}
		o, _ := snmp.ParseOID(trap)
		seq, _ := snmp.ParseOID("1.3.6.1.4.1.32473.1.1.1.0")
		raw := snmp.EncodeCommunity(snmp.V2c, []byte("public"), snmp.EncodePDU(&snmp.PDU{Type: snmp.PDUTrap, RequestID: int64(i), Varbinds: []snmp.Varbind{
			{OID: snmp.OIDSysUpTime, Value: snmp.Value{Kind: snmp.KindTimeTicks, Uint: 5}},
			{OID: snmp.OIDSnmpTrapOID, Value: snmp.Value{Kind: snmp.KindOID, OID: o}},
			{OID: seq, Value: snmp.Value{Kind: snmp.KindOctetString, Bytes: []byte(fmt.Sprintf("seq=run:%d", i))}},
		}}))
		rec := snmp.FormatRecord(nil, snmp.Decode(raw, nil, at), snmp.RecordOptions{Names: snmp.BuiltinMIBs()})
		if err := st.WriteType(logfile.TypeTrap, model.Message{Received: at.Add(time.Duration(i) * time.Second), Sender: fxDevs[0], Raw: rec}); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	idx.Close()

	code, out, errOut := runSearch(t, f.dir, "--type", "trap", "--field", "trap_oid=linkDown", "--last", "24h")
	if code != 0 || strings.Count(out, "\n") != 5 || strings.Contains(out, "<") || !strings.Contains(out, "trap=1.3.6.1.6.3.1.1.5.3(linkDown)") {
		t.Fatalf("text: %d %q %s", code, out, errOut)
	}
	code, out, _ = runSearch(t, f.dir, "--type", "trap", "--json", "--last", "24h", "seq=run:3\"")
	if code != 0 || strings.Count(out, "\n") != 1 {
		t.Fatalf("json: %d %q", code, out)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(out), &obj); err != nil {
		t.Fatal(err)
	}
	fields, _ := obj["fields"].(map[string]any)
	if obj["type"] != "trap" || fields["trap_name"] != "linkUp" || obj["device_name"] == nil || obj["severity"] != nil {
		t.Fatalf("json object %v", obj)
	}
	// q never matches base64, and the syslog search is untouched by traps.
	if code, out, _ := runSearch(t, f.dir, "--type", "trap", "--count", "--last", "24h", "MIG"); code != 1 || out != "0\n" {
		t.Fatalf("base64 %d %q", code, out)
	}
	if code, out, _ := runSearch(t, f.dir, "--count", "--last", "24h", "linkDown"); code == 0 && strings.TrimSpace(out) != "0" {
		code2, out2, _ := runSearch(t, f.dir, "--count", "--last", "24h", "trap=1.3.6")
		if code2 != 1 || out2 != "0\n" {
			t.Fatalf("syslog search found traps: %q / %q", out, out2)
		}
	}
}
