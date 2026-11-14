package snmp

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestEngineIDs(t *testing.T) {
	a, b := NewEngineID(), NewEngineID()
	if len(a) != 13 || !bytes.Equal(a[:5], []byte{0x80, 0, 0, 0, 5}) || bytes.Equal(a, b) {
		t.Errorf("NewEngineID: %x %x", a, b)
	}
	for _, s := range []string{"80000000050102030405060708", "0x8000000005aabbccdd", "80:00:00:00:05"} {
		if _, err := ParseEngineID(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"", "8000", "zz000000000000", "00" + string(bytes.Repeat([]byte("00"), 32))} {
		if _, err := ParseEngineID(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	e := &Engine{Boots: 1, Start: t0}
	if e.Time(t0.Add(90*time.Second)) != 90 || e.Time(t0.Add(-time.Hour)) != 0 || e.Time(t0.Add(100*365*24*time.Hour)) != 1<<31-1 {
		t.Error("Engine.Time")
	}
}

func TestLoadEngine(t *testing.T) {
	path := filepath.Join(t.TempDir(), EngineFile)
	e1, err := LoadEngine(path, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	if e1.Boots != 1 || len(e1.ID) != 13 {
		t.Fatalf("first start: %+v", e1)
	}
	e2, err := LoadEngine(path, nil, t0)
	if err != nil {
		t.Fatal(err)
	}
	if e2.Boots != 2 || !bytes.Equal(e2.ID, e1.ID) {
		t.Errorf("second start: %+v", e2)
	}
	over := mustHex(t, "8000000005ffffffffffffffff")
	e3, err := LoadEngine(path, over, t0)
	if err != nil {
		t.Fatal(err)
	}
	if e3.Boots != 3 || !bytes.Equal(e3.ID, over) {
		t.Errorf("override: %+v", e3)
	}
	if e4, _ := LoadEngine(path, nil, t0); !bytes.Equal(e4.ID, e1.ID) {
		t.Error("the override replaced the stored ID")
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", fi.Mode())
		}
	}
	if err := os.WriteFile(path, []byte(`{"engine_id":"zz"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEngine(path, nil, t0); err == nil {
		t.Error("a bad engine file accepted")
	}
	if err := os.WriteFile(path, []byte(`{"engine_id":"80000000050102030405060708","engine_boots":2147483647}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if e, err := LoadEngine(path, nil, t0); err != nil || e.Boots != 1<<31-1 {
		t.Errorf("latched boots: %+v %v", e, err)
	}
}
