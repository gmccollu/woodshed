package snmp

import (
	_ "embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// MIB folder limits (SPEC §11.2.4).
const (
	MaxMIBFiles = 2000
	MaxMIBBytes = 64 << 20
	MaxMIBNames = 1000000
)

// MIBError is a problem in a MIB file: an error skips the file, a warning (a
// missing import, an unresolvable parent) doesn't.
type MIBError struct {
	File string
	Line int
	Msg  string
}

func (e *MIBError) Error() string {
	switch {
	case e.File != "" && e.Line > 0:
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	case e.File != "":
		return e.File + ": " + e.Msg
	}
	return e.Msg
}

// MIBReport says what a load read.
type MIBReport struct {
	Files    int // files read (not counting the built-in set)
	Modules  int // modules loaded from them
	Names    int // named OIDs in the set, built-in ones included
	Errors   []MIBError
	Warnings []MIBError
}

// MIBSet names OIDs and integer values. The zero value names nothing; use
// BuiltinMIBs or LoadMIBDir. It's read-only once built, so safe for concurrent use.
type MIBSet struct {
	root   mnode
	byName map[string][]nameEntry
	mods   map[string]*mibModule
	count  int
}

type mnode struct {
	children map[uint32]*mnode
	oid      OID
	name     string
	module   string
	kind     defKind
	enum     map[int64]string
}

//go:embed builtin.mib
var builtinMIB []byte

var (
	builtinOnce sync.Once
	builtinMods []*mibModule
	builtinSet  *MIBSet
)

func loadBuiltin() {
	n := 0
	mods, err := parseMIBFile(builtinMIB, &n, MaxMIBNames)
	if err != nil {
		panic("snmp: the built-in MIB set doesn't parse: " + err.Error())
	}
	for _, m := range mods {
		m.builtin = true
		m.file = "(built-in)"
	}
	builtinMods = mods
	builtinSet, _ = buildMIBSet(nil, MIBReport{})
}

// BuiltinMIBs returns the built-in set: the standard notifications (coldStart,
// warmStart, linkDown, linkUp, authenticationFailure, egpNeighborLoss),
// sysUpTime, snmpTrapOID, snmpTrapEnterprise, the system group and the IF-MIB
// interface columns.
func BuiltinMIBs() *MIBSet {
	builtinOnce.Do(loadBuiltin)
	return builtinSet
}

// MIBFile is one file's name and contents, for LoadMIBFiles.
type MIBFile struct {
	Name string
	Data []byte
}

// LoadMIBDir reads the MIB files (*.mib, *.my, *.txt, any case) in dir, not its
// subfolders, in name order, plus the built-in set. A file that doesn't parse is
// skipped and listed in the report's errors; the rest still load. A missing dir
// is an error in the report and gives the built-in set.
func LoadMIBDir(dir string) (*MIBSet, MIBReport) {
	var rep MIBReport
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s, r := LoadMIBFiles(nil)
			return s, r
		}
		rep.Errors = append(rep.Errors, MIBError{File: dir, Msg: err.Error()})
		s, r := LoadMIBFiles(nil)
		r.Errors = append(rep.Errors, r.Errors...)
		return s, r
	}
	var files []MIBFile
	total := 0
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".mib", ".my", ".txt":
		default:
			continue
		}
		if len(files) >= MaxMIBFiles {
			rep.Errors = append(rep.Errors, MIBError{File: e.Name(), Msg: fmt.Sprintf("more than %d MIB files; the rest aren't read", MaxMIBFiles)})
			break
		}
		info, err := e.Info()
		if err != nil {
			rep.Errors = append(rep.Errors, MIBError{File: e.Name(), Msg: err.Error()})
			continue
		}
		if total+int(info.Size()) > MaxMIBBytes {
			rep.Errors = append(rep.Errors, MIBError{File: e.Name(), Msg: fmt.Sprintf("the MIB files pass %d MiB; the rest aren't read", MaxMIBBytes>>20)})
			break
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			rep.Errors = append(rep.Errors, MIBError{File: e.Name(), Msg: err.Error()})
			continue
		}
		total += len(b)
		files = append(files, MIBFile{Name: e.Name(), Data: b})
	}
	s, r := LoadMIBFiles(files)
	r.Errors = append(rep.Errors, r.Errors...)
	return s, r
}

// LoadMIBFiles builds a set from files plus the built-in set. A module in files
// replaces the built-in module of the same name.
func LoadMIBFiles(files []MIBFile) (*MIBSet, MIBReport) {
	builtinOnce.Do(loadBuiltin)
	var rep MIBReport
	var mods []*mibModule
	names := 0
	for _, f := range files {
		ms, err := parseMIBFile(f.Data, &names, MaxMIBNames)
		rep.Files++
		if err != nil {
			me := MIBError{File: f.Name, Msg: err.Error()}
			var pe *MIBError
			if errors.As(err, &pe) {
				me.Line, me.Msg = pe.Line, pe.Msg
			}
			rep.Errors = append(rep.Errors, me)
			if names > MaxMIBNames {
				break
			}
			continue
		}
		for _, m := range ms {
			m.file = f.Name
		}
		mods = append(mods, ms...)
	}
	return buildMIBSet(mods, rep)
}

// buildMIBSet resolves the modules (user ones, then the built-in ones they
// don't replace) into a set.
func buildMIBSet(user []*mibModule, rep MIBReport) (*MIBSet, MIBReport) {
	s := &MIBSet{byName: map[string][]nameEntry{}, mods: map[string]*mibModule{}}
	var all []*mibModule
	for _, m := range user {
		if old, ok := s.mods[m.name]; ok {
			rep.Warnings = append(rep.Warnings, MIBError{File: m.file, Line: m.line, Msg: fmt.Sprintf("module %s is also in %s; that one is used", m.name, old.file)})
			continue
		}
		s.mods[m.name] = m
		all = append(all, m)
		rep.Modules++
	}
	for _, m := range builtinMods {
		if _, ok := s.mods[m.name]; !ok {
			s.mods[m.name] = m
			all = append(all, m)
		}
	}
	// Global name index (lenient fallback when an import is missing).
	global := map[string]*mibModule{}
	for _, m := range all {
		for _, d := range m.order {
			if _, ok := global[d.name]; !ok {
				global[d.name] = m
			}
		}
	}
	for _, m := range user {
		if s.mods[m.name] != m {
			continue
		}
		mods := make([]string, 0, len(m.importMods))
		for name := range m.importMods {
			mods = append(mods, name)
		}
		sort.Strings(mods)
		for _, name := range mods {
			if _, ok := s.mods[name]; !ok && !macroOnlyModules[name] {
				rep.Warnings = append(rep.Warnings, MIBError{File: m.file, Line: m.importMods[name], Msg: fmt.Sprintf("module %s imports from %s, which isn't loaded", m.name, name)})
			}
		}
	}
	r := &resolver{set: s, global: global, memo: map[*mibDef]*resolveState{}}
	// Built-in modules first, so their names win for the standard OIDs.
	order := append(append([]*mibModule(nil), all[len(all)-countBuiltin(all):]...), all[:len(all)-countBuiltin(all)]...)
	for _, m := range order {
		for _, d := range m.order {
			oid, ok := r.resolve(m, d, 0)
			if !ok {
				if !m.builtin {
					rep.Warnings = append(rep.Warnings, MIBError{File: m.file, Line: d.line, Msg: fmt.Sprintf("%s: can't resolve %s's parent %q", m.name, d.name, d.parent)})
				}
				continue
			}
			s.add(m, d, oid, r.enumFor(m, d))
		}
	}
	rep.Names = s.count
	return s, rep
}

func countBuiltin(all []*mibModule) int {
	n := 0
	for _, m := range all {
		if m.builtin {
			n++
		}
	}
	return n
}

// macroOnlyModules define only macros and types: importing from them needs no file.
var macroOnlyModules = map[string]bool{
	"SNMPv2-CONF": true, "SNMPv2-TC": true, "RFC-1212": true, "RFC-1215": true,
}

var rootOIDs = map[string]OID{
	"iso": {1}, "ccitt": {0}, "itu-t": {0}, "joint-iso-ccitt": {2}, "joint-iso-itu-t": {2},
}

type resolver struct {
	set    *MIBSet
	global map[string]*mibModule
	memo   map[*mibDef]*resolveState
}

// find looks a name up from module m: its own definitions, then the module it
// imports the name from, then any module that defines it.
func (r *resolver) find(m *mibModule, name string) (*mibModule, *mibDef) {
	if d, ok := m.defs[name]; ok {
		return m, d
	}
	if from, ok := m.imports[name]; ok {
		if im := r.set.mods[from]; im != nil {
			if d, ok := im.defs[name]; ok {
				return im, d
			}
		}
	}
	if gm := r.global[name]; gm != nil {
		return gm, gm.defs[name]
	}
	return nil, nil
}

func (r *resolver) resolve(m *mibModule, d *mibDef, depth int) (OID, bool) {
	if st, ok := r.memo[d]; ok {
		return st.oid, st.oid != nil && !st.resolving
	}
	if depth > 64 {
		return nil, false
	}
	st := &resolveState{resolving: true}
	r.memo[d] = st
	defer func() { st.resolving = false }()
	var base OID
	switch {
	case d.parent == "":
	case rootOIDs[d.parent] != nil && m.defs[d.parent] == nil:
		base = rootOIDs[d.parent]
	default:
		pm, pd := r.find(m, d.parent)
		if pd == nil {
			if root := rootOIDs[d.parent]; root != nil {
				base = root
				break
			}
			return nil, false
		}
		var ok bool
		if base, ok = r.resolve(pm, pd, depth+1); !ok {
			return nil, false
		}
	}
	oid := make(OID, 0, len(base)+len(d.subs))
	oid = append(append(oid, base...), d.subs...)
	if len(oid) == 0 || len(oid) > MaxOIDLen {
		return nil, false
	}
	st.oid = oid
	return oid, true
}

// resolveState is one definition's resolution, kept per build (the built-in
// modules are shared between sets, so nothing is stored on them).
type resolveState struct {
	oid       OID
	resolving bool
}

// enumFor is d's enumeration: its own, or its syntax type's (through
// TEXTUAL-CONVENTIONs, across modules).
func (r *resolver) enumFor(m *mibModule, d *mibDef) map[int64]string {
	if d.enum != nil {
		return d.enum
	}
	ref, mod := d.tcRef, m
	for i := 0; ref != "" && i < 16; i++ {
		t, tm := r.findType(mod, ref)
		if t == nil {
			return nil
		}
		if t.enum != nil {
			return t.enum
		}
		ref, mod = t.ref, tm
	}
	return nil
}

func (r *resolver) findType(m *mibModule, name string) (*mibType, *mibModule) {
	if t, ok := m.types[name]; ok {
		return t, m
	}
	if from, ok := m.imports[name]; ok {
		if im := r.set.mods[from]; im != nil {
			if t, ok := im.types[name]; ok {
				return t, im
			}
		}
	}
	for _, om := range r.set.mods {
		if t, ok := om.types[name]; ok {
			return t, om
		}
	}
	return nil, nil
}

func (s *MIBSet) add(m *mibModule, d *mibDef, oid OID, enum map[int64]string) {
	n := &s.root
	for _, sub := range oid {
		c := n.children[sub]
		if c == nil {
			if n.children == nil {
				n.children = map[uint32]*mnode{}
			}
			c = &mnode{}
			n.children[sub] = c
		}
		n = c
	}
	switch {
	case n.name == "":
		s.count++
		n.oid, n.name, n.module, n.kind = oid, d.name, m.name, d.kind
	case n.kind == defOID && d.kind != defOID:
		// An object or notification names the node better than a plain
		// OBJECT IDENTIFIER assignment of it.
		n.name, n.module, n.kind = d.name, m.name, d.kind
	}
	if n.enum == nil && enum != nil {
		n.enum = enum
	}
	s.byName[d.name] = append(s.byName[d.name], nameEntry{module: m.name, oid: n.oid})
}

type nameEntry struct {
	module string
	oid    OID
}

// deepest returns the deepest named node on o's path, and how many
// sub-identifiers it covers.
func (s *MIBSet) deepest(o OID) (*mnode, int) {
	if s == nil {
		return nil, 0
	}
	var best *mnode
	depth := 0
	n := &s.root
	for i, sub := range o {
		c := n.children[sub]
		if c == nil {
			break
		}
		n = c
		if n.name != "" {
			best, depth = n, i+1
		}
	}
	return best, depth
}

// Name returns o's name: the name of o itself, or of the object or notification
// it's an instance of plus the index ("ifOperStatus.3", "sysUpTime.0"). An OID
// under a plain subtree node (enterprises.99999.1) gets no name: it would say
// nothing the number doesn't.
func (s *MIBSet) Name(o OID) string {
	n, depth := s.deepest(o)
	if n == nil {
		return ""
	}
	if depth == len(o) {
		return n.name
	}
	if n.kind == defOID {
		return ""
	}
	b := []byte(n.name)
	for _, sub := range o[depth:] {
		b = append(b, '.')
		b = strconv.AppendUint(b, uint64(sub), 10)
	}
	return string(b)
}

// EnumName returns the named value v of the object o belongs to, or "".
func (s *MIBSet) EnumName(o OID, v int64) string {
	n, _ := s.deepest(o)
	if n == nil || n.enum == nil {
		return ""
	}
	return n.enum[v]
}

// IsNotification reports whether o is a NOTIFICATION-TYPE or TRAP-TYPE.
func (s *MIBSet) IsNotification(o OID) bool {
	n, depth := s.deepest(o)
	return n != nil && depth == len(o) && n.kind == defNotification
}

// Len is the number of named OIDs.
func (s *MIBSet) Len() int {
	if s == nil {
		return 0
	}
	return s.count
}

// ErrUnknownName is returned by Lookup for a name no module defines.
var ErrUnknownName = errors.New("snmp: unknown MIB name")

// Lookup returns the OID of a MIB name, "linkDown" or "IF-MIB::linkDown". A
// bare name defined with different OIDs in several modules is ambiguous (an
// error naming them).
func (s *MIBSet) Lookup(name string) (OID, error) {
	if s == nil {
		return nil, ErrUnknownName
	}
	mod := ""
	if i := strings.Index(name, "::"); i >= 0 {
		mod, name = name[:i], name[i+2:]
	}
	var found []nameEntry
	for _, n := range s.byName[name] {
		if mod == "" || n.module == mod {
			found = append(found, n)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%w %q", ErrUnknownName, name)
	}
	for _, n := range found[1:] {
		if !n.oid.Equal(found[0].oid) {
			var ms []string
			for _, f := range found {
				ms = append(ms, f.module+"::"+name)
			}
			return nil, fmt.Errorf("snmp: %q is ambiguous (%s); name the module", name, strings.Join(ms, ", "))
		}
	}
	return append(OID(nil), found[0].oid...), nil
}
