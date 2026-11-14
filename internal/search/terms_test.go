package search

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

// show prints a parsed query: terms quoted, & for AND, | for OR, ! for NOT.
func show(n *termNode) string {
	if n == nil {
		return "<all>"
	}
	switch n.op {
	case opTerm:
		return `"` + n.text + `"`
	case opNot:
		return "!" + show(n.kids[0])
	}
	sep := " & "
	if n.op == opOr {
		sep = " | "
	}
	parts := make([]string, len(n.kids))
	for i, k := range n.kids {
		parts[i] = show(k)
	}
	return "(" + strings.Join(parts, sep) + ")"
}

func TestTermsGrammar(t *testing.T) {
	t.Parallel()
	cases := []struct{ q, want string }{
		{``, `<all>`},
		{`   `, `<all>`},
		{`deny`, `"deny"`},
		{`deny tcp`, `("deny" & "tcp")`},
		{`deny AND tcp`, `("deny" & "tcp")`},
		{`a OR b c`, `("a" | ("b" & "c"))`},
		{`a b OR c`, `(("a" & "b") | "c")`},
		{`a OR b OR c`, `("a" | "b" | "c")`},
		{`NOT a b`, `(!"a" & "b")`},
		{`NOT NOT a`, `!!"a"`},
		{`a NOT b`, `("a" & !"b")`},
		{`NOT (a OR b)`, `!("a" | "b")`},
		{`(a OR b) c`, `(("a" | "b") & "c")`},
		{`a(b)c`, `("a" & "b" & "c")`},
		{`"deny tcp"`, `"deny tcp"`},
		{`"AND"`, `"AND"`},
		{`and or not`, `("and" & "or" & "not")`},
		{`user="bob"`, `"user="bob""`},
		{`"(pid 312)"`, `"(pid 312)"`},
		{`"a\"b" "c\\d" "e\f"`, `("a"b" & "c\d" & "e\f")`},
		{`"a"b`, `("a" & "b")`},
		{"x\ty z", `("x" & "y" & "z")`},
		{`((((((((a))))))))`, `"a"`},
	}
	for _, c := range cases {
		e, err := parseTerms(c.q, false)
		if err != nil {
			t.Errorf("%q: %v", c.q, err)
			continue
		}
		if got := show(e); got != c.want {
			t.Errorf("%q: %s, want %s", c.q, got, c.want)
		}
	}
}

func TestTermsErrors(t *testing.T) {
	t.Parallel()
	many := strings.Repeat("a ", 40)
	cases := []struct{ q, want string }{
		{`deny "tcp`, `Unclosed quote starting at character 6.`},
		{`"abc\"`, `Unclosed quote starting at character 1.`},
		{`é "x`, `Unclosed quote starting at character 3.`}, // characters, not bytes
		{`a b c d e f g ) x`, `Unmatched ")" at character 15.`},
		{`)`, `Unmatched ")" at character 1.`},
		{`a (b`, `Missing ")" for the "(" at character 3.`},
		{`((a)`, `Missing ")" for the "(" at character 1.`},
		{`deny tcp OR`, `"OR" at character 10 needs a term on both sides.`},
		{`OR a`, `"OR" at character 1 needs a term on both sides.`},
		{`a OR OR b`, `"OR" at character 3 needs a term on both sides.`},
		{`(OR a)`, `"OR" at character 2 needs a term on both sides.`},
		{`a AND`, `"AND" at character 3 needs a term on both sides.`},
		{`AND a`, `"AND" at character 1 needs a term on both sides.`},
		{`a AND OR b`, `"AND" at character 3 needs a term on both sides.`},
		{`a NOT`, `"NOT" at character 3 needs a term after it.`},
		{`NOT`, `"NOT" at character 1 needs a term after it.`},
		{`(NOT) a`, `"NOT" at character 2 needs a term after it.`},
		{`a "" b`, `Empty phrase at character 3.`},
		{`a () b`, `Empty parentheses at character 3.`},
		{`a ( ) b`, `Empty parentheses at character 3.`},
		{many, `Too many terms (40); the limit is 32.`},
		{`(((((((((a)))))))))`, `Parentheses nested deeper than 8.`},
		{strings.Repeat("x", 4097), `The query is longer than 4 KiB.`},
	}
	for _, c := range cases {
		_, err := parseTerms(c.q, false)
		var qe *QueryError
		if !errors.As(err, &qe) || qe.Msg != c.want {
			t.Errorf("%.40q: %v, want %q", c.q, err, c.want)
		}
	}
	// 32 terms is fine; 4 KiB is fine.
	if _, err := parseTerms(strings.Repeat("a ", 32), false); err != nil {
		t.Error(err)
	}
	if _, err := parseTerms(strings.Repeat("x", 4096), false); err != nil {
		t.Error(err)
	}
}

func TestTermsMatch(t *testing.T) {
	t.Parallel()
	line := []byte(`<134>Nov 10 web-01 sshd[312]: Deny TCP from 10.0.0.1 user="bob" (pid 312) NOT FOUND`)
	cases := []struct {
		q    string
		cs   bool
		want bool
	}{
		{`deny tcp`, false, true},
		{`"deny tcp"`, false, true},
		{`"tcp deny"`, false, false},
		{`deny NOT 10.0.0.1`, false, false},
		{`deny NOT 10.0.0.2`, false, true},
		{`NOT 10.0.0.2`, false, true},
		{`allow OR deny`, false, true},
		{`allow OR (deny udp)`, false, false},
		{`"NOT FOUND"`, false, true},
		{`"(pid 312)"`, false, true},
		{`user="bob"`, false, true},
		{`Deny TCP`, true, true},
		{`deny`, true, false},
		{`"Deny tcp"`, true, false},
		{`not`, false, true}, // an ordinary word: matches "NOT FOUND"
		{``, false, true},
	}
	for _, c := range cases {
		m, err := newTermsMatcher(c.q, c.cs)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		if got := m.match(line); got != c.want {
			t.Errorf("%q (case %v): %v, want %v", c.q, c.cs, got, c.want)
		}
	}
	// "deny tcp" in terms mode as a phrase equals text mode's q.
	tm, _ := newTermsMatcher(`"deny tcp"`, false)
	xm, _ := newMatcher(`deny tcp`, false, false)
	if tm.kind != xm.kind || string(tm.needle) != string(xm.needle) {
		t.Errorf("phrase matcher %+v, text %+v", tm, xm)
	}
	// The prefilter is the longest positive term on the top-level AND chain.
	m, _ := newTermsMatcher(`ab NOT longestterm abcdef (x OR yyyyyyyyy)`, false)
	if !m.prefilter || m.pre == nil || string(m.pre.needle) != "abcdef" {
		t.Errorf("prefilter %v %+v", m.prefilter, m.pre)
	}
	if m, _ := newTermsMatcher(`a OR bbbb`, false); m.prefilter {
		t.Error("no term is required by an OR")
	}
	if m, _ := newTermsMatcher(`NOT a`, false); m.prefilter {
		t.Error("NOT alone has no prefilter")
	}
	if got := TermsPositive(`deny NOT 10.0.0.1 "a b" NOT (x OR y) (z OR w)`); strings.Join(got, "|") != "deny|a b|z|w" {
		t.Errorf("positive terms %q", got)
	}
}

func TestTermsWithRegexRefused(t *testing.T) {
	t.Parallel()
	e := &Engine{}
	if _, err := e.compile(Filter{Q: "a", Terms: true, Regex: true}); err == nil || err.Error() != ErrTermsWithRegex {
		t.Fatalf("%v", err)
	}
	if _, err := e.compile(Filter{Exclude: `"x`, Terms: true}); err == nil || err.Error() != "exclude: Unclosed quote starting at character 1." {
		t.Fatalf("%v", err)
	}
}

func FuzzTerms(f *testing.F) {
	for _, s := range []string{`a OR b c`, `NOT (a OR "b c")`, `"x\"y\\z"`, `(((a)))`, `a ) (`, `"`, `é "à`, `AND OR NOT`} {
		f.Add(s, "some line with a and b c and x\"y\\z")
	}
	f.Fuzz(func(t *testing.T, q, line string) {
		e, err := parseTerms(q, false)
		if err != nil {
			var qe *QueryError
			if !errors.As(err, &qe) {
				t.Fatalf("%q: error %T %v", q, err, err)
			}
			// Every position names a character of the query (or one past it).
			if i := strings.Index(qe.Msg, "character "); i >= 0 {
				var n int
				for _, c := range qe.Msg[i+len("character "):] {
					if c < '0' || c > '9' {
						break
					}
					n = n*10 + int(c-'0')
				}
				if n < 1 || n > utf8.RuneCountInString(q)+1 {
					t.Fatalf("%q: position %d out of range: %s", q, n, qe.Msg)
				}
			}
			return
		}
		m, err := newTermsMatcher(q, false)
		if err != nil {
			t.Fatalf("%q parsed, then %v", q, err)
		}
		// The compiled matcher agrees with the plain tree.
		want := e == nil || e.match([]byte(line))
		if got := m.match([]byte(line)); got != want {
			t.Fatalf("%q on %q: matcher %v, tree %v", q, line, got, want)
		}
	})
}
