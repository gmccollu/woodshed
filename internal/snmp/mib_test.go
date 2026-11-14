package snmp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltinMIBs(t *testing.T) {
	s := BuiltinMIBs()
	for oid, want := range map[string]string{
		"1.3.6.1.6.3.1.1.5.1":      "coldStart",
		"1.3.6.1.6.3.1.1.5.2":      "warmStart",
		"1.3.6.1.6.3.1.1.5.3":      "linkDown",
		"1.3.6.1.6.3.1.1.5.4":      "linkUp",
		"1.3.6.1.6.3.1.1.5.5":      "authenticationFailure",
		"1.3.6.1.2.1.1.3.0":        "sysUpTime.0",
		"1.3.6.1.6.3.1.1.4.1.0":    "snmpTrapOID.0",
		"1.3.6.1.6.3.1.1.4.3.0":    "snmpTrapEnterprise.0",
		"1.3.6.1.2.1.2.2.1.8.3":    "ifOperStatus.3",
		"1.3.6.1.2.1.31.1.1.1.1.7": "ifName.7",
		"1.3.6.1.2.1.31.1.1.1.18.7": "ifAlias.7",
		"1.3.6.1.4.1":              "enterprises",
		"1.3.6.1.4.1.32473.1":      "", // under a plain subtree node: no name
		"1.3.6.1.6.3.15.1.1.4.0":   "usmStatsUnknownEngineIDs.0",
		"1.3.6.1.6.3.18.1.3.0":     "snmpTrapAddress.0",
		"2.5":                      "",
	} {
		o, _ := ParseOID(oid)
		if got := s.Name(o); got != want {
			t.Errorf("Name(%s) = %q, want %q", oid, got, want)
		}
	}
	for _, tc := range []struct {
		oid  string
		v    int64
		want string
	}{
		{"1.3.6.1.2.1.2.2.1.8.3", 2, "down"},
		{"1.3.6.1.2.1.2.2.1.8.3", 7, "lowerLayerDown"},
		{"1.3.6.1.2.1.2.2.1.8.3", 99, ""},
		{"1.3.6.1.2.1.2.2.1.7.1", 1, "up"},
		{"1.3.6.1.2.1.31.1.1.1.16.1", 1, "true"}, // ifPromiscuousMode, through SNMPv2-TC's TruthValue
		{"1.3.6.1.2.1.2.2.1.1.1", 1, ""},
	} {
		o, _ := ParseOID(tc.oid)
		if got := s.EnumName(o, tc.v); got != tc.want {
			t.Errorf("EnumName(%s, %d) = %q, want %q", tc.oid, tc.v, got, tc.want)
		}
	}
	for name, want := range map[string]string{"linkDown": "1.3.6.1.6.3.1.1.5.3", "IF-MIB::linkUp": "1.3.6.1.6.3.1.1.5.4", "coldStart": "1.3.6.1.6.3.1.1.5.1", "ifOperStatus": "1.3.6.1.2.1.2.2.1.8"} {
		o, err := s.Lookup(name)
		if err != nil || o.String() != want {
			t.Errorf("Lookup(%s) = %s, %v", name, o, err)
		}
	}
	if _, err := s.Lookup("noSuchTrap"); err == nil {
		t.Error("unknown name found")
	}
	if _, err := s.Lookup("IF-MIB::coldStart"); err == nil {
		t.Error("coldStart found in IF-MIB")
	}
	if !s.IsNotification(oidLinkDown) || s.IsNotification(OIDSysUpTime) {
		t.Error("IsNotification")
	}
	if s.Len() < 80 {
		t.Errorf("only %d built-in names", s.Len())
	}
}

const exampleMIBs = `
EXAMPLE-SMI DEFINITIONS ::= BEGIN
IMPORTS enterprises, MODULE-IDENTITY FROM SNMPv2-SMI;
example MODULE-IDENTITY
    LAST-UPDATED "202611140000Z"
    ORGANIZATION "Example"
    CONTACT-INFO "nobody -- not a comment inside a string"
    DESCRIPTION  "The documentation enterprise (RFC 5612)."
    ::= { enterprises 32473 }
exampleProducts OBJECT IDENTIFIER ::= { example 1 }
Status ::= TEXTUAL-CONVENTION
    STATUS current
    DESCRIPTION "A status."
    SYNTAX INTEGER { ok(1), warning(2), failed(3), unknown(-1) }
END
`

const exampleTraps = `
EXAMPLE-TRAP-MIB DEFINITIONS ::= BEGIN
IMPORTS
    NOTIFICATION-TYPE, OBJECT-TYPE, Integer32 FROM SNMPv2-SMI
    example, exampleProducts, Status FROM EXAMPLE-SMI
    DisplayString FROM SNMPv2-TC
    ifIndex FROM IF-MIB
    something FROM NOT-LOADED-MIB;

-- a comment ends at the next pair -- -- and this one at the line's end: exampleObjects OBJECT IDENTIFIER ::= { example 99 }
--------------------------------------------
exampleObjects OBJECT IDENTIFIER ::= { example 2 }
exampleNotifs  OBJECT IDENTIFIER ::= { example 0 }

exampleTable OBJECT-TYPE
    SYNTAX     SEQUENCE OF ExampleEntry
    MAX-ACCESS not-accessible
    STATUS     current
    DESCRIPTION "A table; ::= inside a string doesn't end anything."
    ::= { exampleObjects 1 }
exampleEntry OBJECT-TYPE
    SYNTAX     ExampleEntry
    MAX-ACCESS not-accessible
    STATUS     current
    DESCRIPTION "."
    INDEX      { exampleIndex }
    ::= { exampleTable 1 }
ExampleEntry ::= SEQUENCE { exampleIndex Integer32, exampleState Status, exampleName DisplayString }
exampleIndex OBJECT-TYPE SYNTAX Integer32 (1..65535) MAX-ACCESS not-accessible STATUS current DESCRIPTION "." ::= { exampleEntry 1 }
exampleState OBJECT-TYPE SYNTAX Status MAX-ACCESS read-only STATUS current DESCRIPTION "." ::= { exampleEntry 2 }
exampleName  OBJECT-TYPE SYNTAX DisplayString (SIZE (0..64)) MAX-ACCESS read-only STATUS current DESCRIPTION "." ::= { exampleEntry 3 }
exampleMode  OBJECT-TYPE
    SYNTAX     INTEGER { off(0), on(1), auto(2) }
    MAX-ACCESS read-write
    STATUS     current
    DESCRIPTION "."
    DEFVAL     { auto }
    ::= { exampleObjects 2 }

exampleStateChange NOTIFICATION-TYPE
    OBJECTS { exampleState, exampleName }
    STATUS  current
    DESCRIPTION "The state changed."
    ::= { exampleNotifs 1 }

exampleGroups OBJECT IDENTIFIER ::= { example 3 }
exampleGroup OBJECT-GROUP OBJECTS { exampleState } STATUS current DESCRIPTION "." ::= { exampleGroups 1 }
END

EXAMPLE-V1-MIB DEFINITIONS ::= BEGIN
IMPORTS TRAP-TYPE FROM RFC-1215 exampleProducts FROM EXAMPLE-SMI;
exampleBoxDown TRAP-TYPE
    ENTERPRISE exampleProducts
    VARIABLES  { ifIndex }
    DESCRIPTION "A v1 trap."
    ::= 7
deep OBJECT IDENTIFIER ::= { iso org(3) dod(6) internet(1) private(4) enterprises(1) 32473 77 }
END
`

func TestMIBFiles(t *testing.T) {
	s, rep := LoadMIBFiles([]MIBFile{
		{"traps.mib", []byte(exampleTraps)},
		{"smi.my", []byte(exampleMIBs)},
		{"broken.mib", []byte("BROKEN-MIB DEFINITIONS ::= BEGIN\nfoo OBJECT IDENTIFIER ::= { example 5 }\nbar OBJECT-TYPE\n DESCRIPTION \"never closed\n::= { foo 1 }\nEND\n")},
		{"no-end.mib", []byte("NOEND-MIB DEFINITIONS ::= BEGIN\nfoo OBJECT IDENTIFIER ::= { example 5 }\n")},
		{"not-a-mib.txt", []byte("just some notes\n")},
	})
	if rep.Files != 5 || rep.Modules != 3 {
		t.Errorf("files %d modules %d", rep.Files, rep.Modules)
	}
	errs := map[string]MIBError{}
	for _, e := range rep.Errors {
		errs[e.File] = e
	}
	if e := errs["broken.mib"]; e.Line != 4 || !strings.Contains(e.Msg, "unterminated string") {
		t.Errorf("broken.mib: %+v", e)
	}
	if e := errs["no-end.mib"]; !strings.Contains(e.Msg, "missing END") {
		t.Errorf("no-end.mib: %+v", e)
	}
	if e := errs["not-a-mib.txt"]; !strings.Contains(e.Msg, "no MIB module") {
		t.Errorf("not-a-mib.txt: %+v", e)
	}
	if len(rep.Errors) != 3 {
		t.Errorf("errors: %+v", rep.Errors)
	}
	warned := false
	for _, w := range rep.Warnings {
		if strings.Contains(w.Msg, "NOT-LOADED-MIB") && w.File == "traps.mib" && w.Line > 0 {
			warned = true
		}
		if strings.Contains(w.Msg, "SNMPv2-TC") || strings.Contains(w.Msg, "RFC-1215") || strings.Contains(w.Msg, "SNMPv2-SMI") {
			t.Errorf("warning for a standard module: %+v", w)
		}
	}
	if !warned {
		t.Errorf("no warning for the missing import: %+v", rep.Warnings)
	}
	for oid, want := range map[string]string{
		"1.3.6.1.4.1.32473":           "example",
		"1.3.6.1.4.1.32473.1":         "exampleProducts",
		"1.3.6.1.4.1.32473.0.1":       "exampleStateChange",
		"1.3.6.1.4.1.32473.2.1.1.2.5": "exampleState.5",
		"1.3.6.1.4.1.32473.2.2.0":     "exampleMode.0",
		"1.3.6.1.4.1.32473.1.0.7":     "exampleBoxDown",
		"1.3.6.1.4.1.32473.3.1":       "exampleGroup",
		"1.3.6.1.4.1.32473.77":        "deep",
		"1.3.6.1.4.1.32473.99":        "",
		"1.3.6.1.2.1.2.2.1.8.3":       "ifOperStatus.3", // the built-in set is still there
	} {
		o, _ := ParseOID(oid)
		if got := s.Name(o); got != want {
			t.Errorf("Name(%s) = %q, want %q", oid, got, want)
		}
	}
	for _, tc := range []struct {
		oid  string
		v    int64
		want string
	}{
		{"1.3.6.1.4.1.32473.2.1.1.2.5", 3, "failed"},  // a TC imported from another file
		{"1.3.6.1.4.1.32473.2.1.1.2.5", -1, "unknown"}, // a negative enumeration
		{"1.3.6.1.4.1.32473.2.2.0", 2, "auto"},
		{"1.3.6.1.4.1.32473.2.1.1.3.5", 1, ""},
	} {
		o, _ := ParseOID(tc.oid)
		if got := s.EnumName(o, tc.v); got != tc.want {
			t.Errorf("EnumName(%s, %d) = %q, want %q", tc.oid, tc.v, got, tc.want)
		}
	}
	o, _ := ParseOID("1.3.6.1.4.1.32473.0.1")
	if !s.IsNotification(o) {
		t.Error("exampleStateChange isn't a notification")
	}
	if o, err := s.Lookup("EXAMPLE-V1-MIB::exampleBoxDown"); err != nil || o.String() != "1.3.6.1.4.1.32473.1.0.7" {
		t.Errorf("Lookup: %s %v", o, err)
	}
	// The built-in set itself isn't changed by a load.
	if BuiltinMIBs().Name(o) != "" {
		t.Error("the built-in set learned a loaded name")
	}
}

// TestMIBOverride: a file holding a built-in module replaces it.
func TestMIBOverride(t *testing.T) {
	s, rep := LoadMIBFiles([]MIBFile{{"if.mib", []byte(`IF-MIB DEFINITIONS ::= BEGIN
IMPORTS mib-2 FROM SNMPv2-SMI;
interfaces OBJECT IDENTIFIER ::= { mib-2 2 }
ifTable OBJECT-TYPE SYNTAX SEQUENCE OF IfEntry ::= { interfaces 2 }
ifEntry OBJECT-TYPE SYNTAX IfEntry ::= { ifTable 1 }
ifOperStatus OBJECT-TYPE SYNTAX INTEGER { up(1), down(2), renamedState(9) } ::= { ifEntry 8 }
END`)}})
	if len(rep.Errors) != 0 {
		t.Fatal(rep.Errors)
	}
	o, _ := ParseOID("1.3.6.1.2.1.2.2.1.8.1")
	if s.EnumName(o, 9) != "renamedState" {
		t.Error("the file's IF-MIB isn't used")
	}
	if o, _ := ParseOID("1.3.6.1.2.1.2.2.1.7.1"); s.Name(o) != "ifEntry.7.1" {
		t.Errorf("the built-in IF-MIB is still used: %q", s.Name(o))
	}
	if o, _ := ParseOID("1.3.6.1.6.3.1.1.5.1"); s.Name(o) != "coldStart" {
		t.Error("other built-in modules went too")
	}
}

func TestMIBDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.MIB", exampleMIBs)
	write("b.txt", exampleTraps)
	write("c.json", "{}")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	write("sub/d.mib", "garbage")
	s, rep := LoadMIBDir(dir)
	if rep.Files != 2 || len(rep.Errors) != 0 {
		t.Errorf("files %d errors %+v", rep.Files, rep.Errors)
	}
	if o, _ := ParseOID("1.3.6.1.4.1.32473.0.1"); s.Name(o) != "exampleStateChange" {
		t.Error("not loaded")
	}
	// A missing folder gives the built-in set and no error.
	s, rep = LoadMIBDir(filepath.Join(dir, "none"))
	if len(rep.Errors) != 0 || s.Name(oidLinkDown) != "linkDown" {
		t.Errorf("missing folder: %+v", rep.Errors)
	}
}

func TestMIBLimits(t *testing.T) {
	var b strings.Builder
	b.WriteString("BIG-MIB DEFINITIONS ::= BEGIN\n")
	for i := 0; i < 50; i++ {
		b.WriteString("n")
		b.WriteString(strings.Repeat("x", i%5))
		b.WriteString(itoaTest(i))
		b.WriteString(" OBJECT IDENTIFIER ::= { enterprises 32473 ")
		b.WriteString(itoaTest(i))
		b.WriteString(" }\n")
	}
	b.WriteString("END\n")
	n := 0
	if _, err := parseMIBFile([]byte(b.String()), &n, 20); err == nil || !strings.Contains(err.Error(), "more than 20 names") {
		t.Errorf("name limit: %v", err)
	}
	if _, err := parseMIBFile([]byte("X DEFINITIONS ::= BEGIN\n"+strings.Repeat("a", maxIdentLen+1)+" OBJECT IDENTIFIER ::= { iso 1 }\nEND"), &n, MaxMIBNames); err == nil {
		t.Error("an over-long identifier accepted")
	}
	// Cycles and unresolvable parents are warnings, not loops.
	_, rep := LoadMIBFiles([]MIBFile{{"cycle.mib", []byte("CYC DEFINITIONS ::= BEGIN\na OBJECT IDENTIFIER ::= { b 1 }\nb OBJECT IDENTIFIER ::= { a 1 }\nc OBJECT IDENTIFIER ::= { nowhere 1 }\nEND")}})
	if len(rep.Warnings) != 3 || len(rep.Errors) != 0 {
		t.Errorf("cycle: %+v %+v", rep.Warnings, rep.Errors)
	}
}

func itoaTest(i int) string {
	if i < 10 {
		return string(rune('0' + i))
	}
	return itoaTest(i/10) + string(rune('0'+i%10))
}
