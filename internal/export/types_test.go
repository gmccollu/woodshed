package export

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// An export of traps puts them in traps/<device>/<day>.log, says so in the
// manifest and README, and an export of several types takes no filters.
func TestExportTypes(t *testing.T) {
	e := newEnv(t, 20)
	at := e.day0.Add(36 * time.Hour)
	for i := 0; i < 10; i++ {
		rec := fmt.Sprintf("v=2c pdu=trap id=%d cred=#efa1f375 status=ok trap=1.3.6.1.6.3.1.1.5.%d vb=1.3.6.1.4.1.32473.1.1.1.0:str:\"seq=run:%d\" raw=MAA=", i, 3+i%2, i)
		if err := e.st.WriteType(logfile.TypeTrap, model.Message{Received: at.Add(time.Duration(i) * time.Second), Sender: devA, Raw: []byte(rec)}); err != nil {
			t.Fatal(err)
		}
	}
	e.st.Flush()
	m := e.manager()
	from, to := e.day0, e.day0.Add(48*time.Hour)

	tf, _ := datatype.ParseTrapFilter(func(p string) string {
		if p == "trap_oid" {
			return "linkDown"
		}
		return ""
	})
	in, err := m.Create(bg, Request{AllDevices: true, From: from, To: to, Filters: Filters{Types: []string{"trap"}, Trap: tf}})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, m, in.ID, Ready)
	files, _ := readZip(t, m, in.ID)
	day := logfile.DayOf(at)
	got := string(files["traps/192.0.2.1/"+day+".log"])
	if strings.Count(got, "\n") != 5 || !strings.Contains(got, "trap=1.3.6.1.6.3.1.1.5.3") || strings.Contains(got, "5.4") {
		t.Fatalf("trap file %q (files %v)", got, keys(files))
	}
	for name := range files {
		if strings.HasPrefix(name, "logs/") {
			t.Fatalf("syslog in a trap export: %s", name)
		}
	}
	var man Manifest
	json.Unmarshal(files["manifest.json"], &man)
	if man.Kind != "export" || len(man.Types) != 1 || man.Types[0] != "trap" || man.Folders["traps"] != "trap" || man.Request.Filters.Type != "trap" {
		t.Fatalf("manifest %+v", man)
	}
	if !strings.Contains(string(files["README.txt"]), "traps/<device>") || !strings.Contains(string(files["README.txt"]), "SHA-256") {
		t.Fatalf("README %s", files["README.txt"])
	}

	// Both types, no filters: syslog in logs/ as in 1.1, traps in traps/.
	in, err = m.Create(bg, Request{Devices: []string{"192.0.2.1"}, From: from, To: to, Filters: Filters{Types: []string{"syslog", "trap"}}})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, m, in.ID, Ready)
	files, _ = readZip(t, m, in.ID)
	if strings.Count(string(files["traps/192.0.2.1/"+day+".log"]), "\n") != 10 || len(files["logs/192.0.2.1/"+day+".log"]) == 0 {
		t.Fatalf("both types: %v", keys(files))
	}
	if _, err := m.Create(bg, Request{AllDevices: true, From: from, To: to, Filters: Filters{Q: "x", Types: []string{"syslog", "trap"}}}); err == nil ||
		!strings.Contains(err.Error(), "Filters apply to one data type") {
		t.Fatalf("filters with two types: %v", err)
	}

	// A 1.1 request (no types) builds the 1.1 zip: syslog only, no README traps part.
	in, err = m.Create(bg, Request{AllDevices: true, From: from, To: to})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, m, in.ID, Ready)
	files, _ = readZip(t, m, in.ID)
	for name := range files {
		if strings.HasPrefix(name, "traps/") {
			t.Fatalf("traps in a 1.1 export: %s", name)
		}
	}
	if strings.Contains(string(files["README.txt"]), "traps/") {
		t.Fatal("README of a syslog export mentions traps")
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
