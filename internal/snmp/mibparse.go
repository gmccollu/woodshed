package snmp

import (
	"fmt"
	"strconv"
)

// The MIB reader takes only what naming needs (SPEC §11.2.4): OBJECT IDENTIFIER
// assignments, the OID-assigning macros (OBJECT-TYPE, NOTIFICATION-TYPE,
// TRAP-TYPE, MODULE-IDENTITY, OBJECT-IDENTITY and the conformance macros of the
// same shape), IMPORTS, and INTEGER enumerations, including those of
// TEXTUAL-CONVENTIONs and plain type assignments. Everything else is skipped
// token by token. It isn't a MIB compiler.

// maxIdentLen bounds an identifier (SMIv2 asks for at most 64; names go into
// records, so a longer one is refused).
const maxIdentLen = 128

type mtokKind uint8

const (
	mEOF mtokKind = iota
	mIdent
	mNumber
	mString
	mPunct
	mOther
)

type mtok struct {
	kind mtokKind
	text string
	line int
}

func (t mtok) is(s string) bool { return (t.kind == mIdent || t.kind == mPunct) && t.text == s }

// mlexer turns MIB text into tokens, with a small lookahead.
type mlexer struct {
	b    []byte
	i    int
	line int
	buf  []mtok
	err  error
}

func newMLexer(b []byte) *mlexer { return &mlexer{b: b, line: 1} }

func (l *mlexer) next() mtok {
	if len(l.buf) > 0 {
		t := l.buf[0]
		l.buf = l.buf[1:]
		return t
	}
	return l.scan()
}

func (l *mlexer) peek(n int) mtok {
	for len(l.buf) <= n {
		l.buf = append(l.buf, l.scan())
	}
	return l.buf[n]
}

func (l *mlexer) fail(line int, format string, args ...any) mtok {
	if l.err == nil {
		l.err = &MIBError{Line: line, Msg: fmt.Sprintf(format, args...)}
	}
	l.i = len(l.b)
	return mtok{kind: mEOF, line: line}
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool  { return '0' <= c && c <= '9' }

func (l *mlexer) scan() mtok {
	b := l.b
	for l.i < len(b) {
		c := b[l.i]
		switch {
		case c == '\n':
			l.line++
			l.i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			l.i++
		case c == '-' && l.i+1 < len(b) && b[l.i+1] == '-':
			// A comment runs to the end of the line or the next "--".
			l.i += 2
			for l.i < len(b) && b[l.i] != '\n' {
				if b[l.i] == '-' && l.i+1 < len(b) && b[l.i+1] == '-' {
					l.i += 2
					break
				}
				l.i++
			}
		case c == '"':
			line := l.line
			l.i++
			for l.i < len(b) && b[l.i] != '"' {
				if b[l.i] == '\n' {
					l.line++
				}
				l.i++
			}
			if l.i >= len(b) {
				return l.fail(line, "unterminated string")
			}
			l.i++
			return mtok{kind: mString, line: line}
		case c == '\'':
			line := l.line
			l.i++
			for l.i < len(b) && b[l.i] != '\'' {
				if b[l.i] == '\n' {
					l.line++
				}
				l.i++
			}
			if l.i >= len(b) {
				return l.fail(line, "unterminated quoted value")
			}
			l.i++
			if l.i < len(b) && isLetter(b[l.i]) {
				l.i++ // 'ff'H, '0101'B
			}
			return mtok{kind: mOther, line: line}
		case isLetter(c):
			s := l.i
			for l.i < len(b) && (isLetter(b[l.i]) || isDigit(b[l.i]) || b[l.i] == '_' ||
				(b[l.i] == '-' && !(l.i+1 < len(b) && b[l.i+1] == '-'))) {
				l.i++
			}
			if l.i-s > maxIdentLen {
				return l.fail(l.line, "identifier longer than %d characters", maxIdentLen)
			}
			return mtok{kind: mIdent, text: string(b[s:l.i]), line: l.line}
		case isDigit(c):
			s := l.i
			for l.i < len(b) && isDigit(b[l.i]) {
				l.i++
			}
			if l.i-s > 20 {
				return l.fail(l.line, "number too long")
			}
			return mtok{kind: mNumber, text: string(b[s:l.i]), line: l.line}
		case c == ':' && l.i+2 < len(b) && b[l.i+1] == ':' && b[l.i+2] == '=':
			l.i += 3
			return mtok{kind: mPunct, text: "::=", line: l.line}
		case c == '.' && l.i+1 < len(b) && b[l.i+1] == '.':
			l.i += 2
			if l.i < len(b) && b[l.i] == '.' {
				l.i++
				return mtok{kind: mPunct, text: "...", line: l.line}
			}
			return mtok{kind: mPunct, text: "..", line: l.line}
		default:
			l.i++
			if c < 0x80 {
				return mtok{kind: mPunct, text: string(rune(c)), line: l.line}
			}
			return mtok{kind: mOther, line: l.line}
		}
	}
	return mtok{kind: mEOF, line: l.line}
}

// --- the parse result ---

type defKind uint8

const (
	defOID defKind = iota
	defObject
	defNotification
)

// mibDef is one OID assignment: parent name (or "" for an absolute OID) and the
// sub-identifiers under it.
type mibDef struct {
	name   string
	parent string
	subs   []uint32
	line   int
	kind   defKind
	enum   map[int64]string
	tcRef  string // SYNTAX names a type whose enumeration applies
}

// mibType is a TEXTUAL-CONVENTION or type assignment: an enumeration, or another
// type it refines.
type mibType struct {
	enum map[int64]string
	ref  string
}

type mibModule struct {
	name       string
	file       string
	line       int
	imports    map[string]string // symbol → module
	importMods map[string]int    // module → line of the IMPORTS
	defs       map[string]*mibDef
	order      []*mibDef
	types      map[string]*mibType
	builtin    bool
}

// parseMIBFile parses one file's modules. names counts definitions and
// enumeration entries against the set's limit.
func parseMIBFile(data []byte, names *int, maxNames int) ([]*mibModule, error) {
	p := &mparser{l: newMLexer(data), names: names, maxNames: maxNames}
	var mods []*mibModule
	for {
		mod := p.module()
		if p.err() != nil {
			return nil, p.err()
		}
		if mod == nil {
			break
		}
		mods = append(mods, mod)
	}
	if len(mods) == 0 {
		return nil, &MIBError{Line: 1, Msg: "no MIB module (no \"<name> DEFINITIONS ::= BEGIN\")"}
	}
	return mods, nil
}

type mparser struct {
	l        *mlexer
	perr     error
	names    *int
	maxNames int
}

func (p *mparser) err() error {
	if p.perr != nil {
		return p.perr
	}
	return p.l.err
}

func (p *mparser) fail(line int, format string, args ...any) {
	if p.perr == nil && p.l.err == nil {
		p.perr = &MIBError{Line: line, Msg: fmt.Sprintf(format, args...)}
	}
	p.l.i = len(p.l.b)
	p.l.buf = nil
}

func (p *mparser) count(n int) bool {
	*p.names += n
	if *p.names > p.maxNames {
		p.fail(p.l.line, "more than %d names in the MIB set", p.maxNames)
		return false
	}
	return true
}

// module finds and parses the next module, or returns nil at the end.
func (p *mparser) module() *mibModule {
	l := p.l
	for {
		t := l.next()
		if t.kind == mEOF {
			return nil
		}
		if t.kind == mIdent && l.peek(0).is("DEFINITIONS") {
			l.next()
			// [IMPLICIT|EXPLICIT|AUTOMATIC TAGS] ::= BEGIN
			for i := 0; ; i++ {
				u := l.next()
				if u.is("BEGIN") {
					break
				}
				if u.kind == mEOF || i > 8 {
					p.fail(t.line, "module %s: no BEGIN after DEFINITIONS", t.text)
					return nil
				}
			}
			mod := &mibModule{
				name: t.text, line: t.line, imports: map[string]string{}, importMods: map[string]int{},
				defs: map[string]*mibDef{}, types: map[string]*mibType{},
			}
			p.body(mod)
			if p.err() != nil {
				return nil
			}
			return mod
		}
	}
}

// isMacroName reports whether t names a macro invocation: an upper-case word
// with a hyphen (OBJECT-TYPE, NOTIFICATION-TYPE, a vendor's own macro, …).
func isMacroName(t mtok) bool {
	if t.kind != mIdent || len(t.text) < 3 {
		return false
	}
	hy := false
	for i := 0; i < len(t.text); i++ {
		c := t.text[i]
		switch {
		case 'A' <= c && c <= 'Z', isDigit(c):
		case c == '-':
			hy = true
		default:
			return false
		}
	}
	return hy
}

func (p *mparser) body(mod *mibModule) {
	l := p.l
	for p.err() == nil {
		t := l.next()
		switch {
		case t.kind == mEOF:
			p.fail(t.line, "module %s: missing END", mod.name)
			return
		case t.is("END"):
			return
		case t.is("IMPORTS"):
			p.imports(mod, t.line)
		case t.is("EXPORTS"):
			p.skipTo(";")
		case t.is("{") || t.is("(") || t.is("["):
			p.skipGroup(t)
		case t.kind == mIdent:
			n := l.peek(0)
			switch {
			case n.is("MACRO"):
				// A macro definition (in the SMI modules): skip its body.
				for u := l.next(); !u.is("END"); u = l.next() {
					if u.kind == mEOF {
						p.fail(t.line, "macro %s: missing END", t.text)
						return
					}
				}
			case n.is("OBJECT") && l.peek(1).is("IDENTIFIER"):
				l.next()
				l.next()
				if !l.next().is("::=") {
					p.fail(t.line, "%s OBJECT IDENTIFIER: want ::=", t.text)
					return
				}
				p.oidValue(mod, t, defOID)
			case n.is("::="):
				l.next()
				p.typeAssignment(mod, t)
			case isMacroName(n) && !isMacroName(t):
				l.next()
				p.macro(mod, t, n.text)
			}
		}
	}
}

func (p *mparser) imports(mod *mibModule, line int) {
	l := p.l
	var syms []string
	for {
		t := l.next()
		switch {
		case t.kind == mEOF:
			p.fail(line, "IMPORTS without a closing ;")
			return
		case t.is(";"):
			return
		case t.is("FROM"):
			m := l.next()
			if m.kind != mIdent {
				p.fail(t.line, "IMPORTS: FROM without a module name")
				return
			}
			for _, s := range syms {
				mod.imports[s] = m.text
			}
			if _, ok := mod.importMods[m.text]; !ok {
				mod.importMods[m.text] = m.line
			}
			syms = syms[:0]
		case t.kind == mIdent:
			syms = append(syms, t.text)
		}
	}
}

func (p *mparser) skipTo(s string) {
	for t := p.l.next(); !t.is(s) && t.kind != mEOF; t = p.l.next() {
	}
}

// skipGroup skips a balanced (), {} or [] group whose opening token is open.
func (p *mparser) skipGroup(open mtok) {
	depth := 1
	for depth > 0 {
		t := p.l.next()
		switch {
		case t.kind == mEOF:
			p.fail(open.line, "unbalanced %s", open.text)
			return
		case t.is("{") || t.is("(") || t.is("["):
			depth++
		case t.is("}") || t.is(")") || t.is("]"):
			depth--
		}
	}
}

// oidValue parses "{ parent n name(n) … }" and adds the definitions.
func (p *mparser) oidValue(mod *mibModule, name mtok, kind defKind) *mibDef {
	l := p.l
	open := l.next()
	if !open.is("{") {
		p.fail(name.line, "%s: want an OID value in braces", name.text)
		return nil
	}
	d := &mibDef{name: name.text, line: name.line, kind: kind}
	first := true
	for {
		t := l.next()
		switch {
		case t.is("}"):
			if first {
				p.fail(name.line, "%s: empty OID value", name.text)
				return nil
			}
			return p.addDef(mod, d)
		case t.kind == mNumber:
			v, err := strconv.ParseUint(t.text, 10, 32)
			if err != nil {
				p.fail(t.line, "%s: sub-identifier %s out of range", name.text, t.text)
				return nil
			}
			d.subs = append(d.subs, uint32(v))
		case t.kind == mIdent:
			if l.peek(0).is("(") {
				l.next()
				nt := l.next()
				if nt.kind != mNumber || !l.next().is(")") {
					p.fail(t.line, "%s: want %s(<number>)", name.text, t.text)
					return nil
				}
				v, err := strconv.ParseUint(nt.text, 10, 32)
				if err != nil {
					p.fail(t.line, "%s: sub-identifier %s out of range", name.text, nt.text)
					return nil
				}
				if first {
					// "iso(1)": a root by number.
					d.subs = append(d.subs, uint32(v))
				} else {
					d.subs = append(d.subs, uint32(v))
					// An intermediate name: define it as the path so far.
					p.addDef(mod, &mibDef{name: t.text, parent: d.parent, subs: append([]uint32(nil), d.subs...), line: t.line})
				}
			} else if first {
				d.parent = t.text
			} else {
				p.fail(t.line, "%s: %s in the middle of an OID value needs a number", name.text, t.text)
				return nil
			}
		default:
			p.fail(t.line, "%s: unexpected token in an OID value", name.text)
			return nil
		}
		first = false
		if len(d.subs) > MaxOIDLen {
			p.fail(name.line, "%s: OID value too long", name.text)
			return nil
		}
	}
}

func (p *mparser) addDef(mod *mibModule, d *mibDef) *mibDef {
	if !p.count(1 + len(d.enum)) {
		return nil
	}
	if old, ok := mod.defs[d.name]; ok {
		// A second definition of the same name in a module: the first wins, but an
		// object's syntax fills in a plain OID assignment.
		if old.kind == defOID && d.kind != defOID {
			*old = *d
		}
		return old
	}
	mod.defs[d.name] = d
	mod.order = append(mod.order, d)
	return d
}

// macro parses "<name> <MACRO> clauses ::= value".
func (p *mparser) macro(mod *mibModule, name mtok, macro string) {
	l := p.l
	kind := defOID
	switch macro {
	case "OBJECT-TYPE":
		kind = defObject
	case "NOTIFICATION-TYPE", "TRAP-TYPE":
		kind = defNotification
	}
	var enum map[int64]string
	var tcRef, enterprise string
clauses:
	for {
		t := l.next()
		switch {
		case t.kind == mEOF || t.is("END"):
			p.fail(name.line, "%s %s: missing ::=", name.text, macro)
			return
		case t.is("::="):
			break clauses
		case t.is("SYNTAX"):
			enum, tcRef = p.syntax()
		case t.is("ENTERPRISE"):
			if e := l.next(); e.kind == mIdent {
				enterprise = e.text
			}
		case t.is("{") || t.is("(") || t.is("["):
			p.skipGroup(t)
		}
		if p.err() != nil {
			return
		}
	}
	if macro == "TRAP-TYPE" {
		// "::= n" under ENTERPRISE: enterprise.0.n (RFC 3584 §3).
		t := l.next()
		v, err := strconv.ParseUint(t.text, 10, 32)
		if t.kind != mNumber || err != nil || enterprise == "" {
			p.fail(name.line, "%s TRAP-TYPE: want ENTERPRISE and \"::= <number>\"", name.text)
			return
		}
		p.addDef(mod, &mibDef{name: name.text, parent: enterprise, subs: []uint32{0, uint32(v)}, line: name.line, kind: kind})
		return
	}
	if !l.peek(0).is("{") {
		// A value form this reader doesn't take; skip it.
		return
	}
	if d := p.oidValue(mod, name, kind); d != nil {
		if enum != nil {
			p.count(len(enum))
		}
		d.enum, d.tcRef = enum, tcRef
	}
}

// syntax reads a SYNTAX clause: INTEGER { … } gives an enumeration; a type name
// gives a reference (and its own { … } refinement, if any, an enumeration).
func (p *mparser) syntax() (map[int64]string, string) {
	l := p.l
	t := l.next()
	var ref string
	switch {
	case t.is("INTEGER") || t.is("Integer32"):
	case t.is("BITS"):
		if l.peek(0).is("{") {
			p.skipGroup(l.next())
		}
		return nil, ""
	case t.is("OCTET") || t.is("OBJECT") || t.is("SEQUENCE"):
		l.next() // STRING, IDENTIFIER, OF
		return nil, ""
	case t.kind == mIdent:
		ref = t.text
	default:
		return nil, ""
	}
	var enum map[int64]string
	if l.peek(0).is("{") {
		enum = p.enumList(l.next())
	}
	for l.peek(0).is("(") {
		p.skipGroup(l.next())
	}
	return enum, ref
}

// enumList parses "{ name(n), name(-n), … }" after its opening brace.
func (p *mparser) enumList(open mtok) map[int64]string {
	l := p.l
	enum := map[int64]string{}
	for {
		t := l.next()
		switch {
		case t.is("}"):
			return enum
		case t.is(","):
		case t.kind == mIdent && l.peek(0).is("("):
			l.next()
			neg := false
			nt := l.next()
			if nt.is("-") {
				neg, nt = true, l.next()
			}
			if nt.kind != mNumber || !l.next().is(")") {
				p.fail(t.line, "enumeration %s: want %s(<number>)", t.text, t.text)
				return nil
			}
			v, err := strconv.ParseInt(nt.text, 10, 64)
			if err != nil {
				p.fail(t.line, "enumeration %s: number out of range", t.text)
				return nil
			}
			if neg {
				v = -v
			}
			if _, ok := enum[v]; !ok {
				enum[v] = t.text
			}
		case t.kind == mEOF:
			p.fail(open.line, "unterminated enumeration")
			return nil
		default:
			// A range or anything else inside: skip it (balanced).
			if t.is("{") || t.is("(") || t.is("[") {
				p.skipGroup(t)
			}
		}
	}
}

// typeAssignment parses "<Name> ::= …": a TEXTUAL-CONVENTION or INTEGER with an
// enumeration is kept; anything else is left for the body loop to skip.
func (p *mparser) typeAssignment(mod *mibModule, name mtok) {
	l := p.l
	t := l.peek(0)
	switch {
	case t.is("TEXTUAL-CONVENTION"):
		l.next()
		for {
			u := l.next()
			if u.is("SYNTAX") {
				enum, ref := p.syntax()
				p.count(len(enum))
				mod.types[name.text] = &mibType{enum: enum, ref: ref}
				return
			}
			if u.kind == mEOF || u.is("::=") || u.is("END") {
				p.fail(name.line, "%s TEXTUAL-CONVENTION: no SYNTAX", name.text)
				return
			}
			if u.is("{") || u.is("(") || u.is("[") {
				p.skipGroup(u)
			}
		}
	case t.is("INTEGER") || t.is("Integer32"):
		l.next()
		if l.peek(0).is("{") {
			enum := p.enumList(l.next())
			p.count(len(enum))
			mod.types[name.text] = &mibType{enum: enum}
		}
	case t.is("[") || t.is("SEQUENCE") || t.is("CHOICE"):
		// [APPLICATION n] IMPLICIT …, SEQUENCE { … }, CHOICE { … }: skip.
		l.next()
		if t.is("[") {
			p.skipGroup(t)
		} else if l.peek(0).is("{") {
			p.skipGroup(l.next())
		}
	}
}
