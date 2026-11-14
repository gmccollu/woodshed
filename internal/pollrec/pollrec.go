// Package pollrec is the poll record line (SPEC §12.3): what the poller
// writes in logs/<device>/poll/, and what the poll data type, the index's
// rollup rebuild, export and the bundle read back. A record is "kind=K
// cycle=N" and then the kind's keys in a fixed order (Keys), each "key=value":
// a bare token, or a double-quoted string with ", \ and control characters
// escaped. Raw counters are always written; rate keys only when there's a
// valid previous sample; disc=1 marks a discontinuity.
//
// It has no dependencies on the poller, so readers don't pull in the network
// side.
package pollrec

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Record kinds.
const (
	KindSys     = "sys"
	KindIf      = "if"
	KindOID     = "oid"
	KindStatus  = "status"
	KindRestart = "restart"
	KindInfo    = "info"
)

// Kinds lists every kind, in the schema's order.
func Kinds() []string { return []string{KindSys, KindIf, KindOID, KindStatus, KindRestart, KindInfo} }

// Statuses are kind=status's status values, and "ok" (the field's domain,
// docs/api.md).
func Statuses() []string {
	return []string{"ok", "timeout", "unreachable", "auth_failed", "unknown_user", "unknown_engine", "not_in_time",
		"decrypt_failed", "error", "overrun"}
}

// OperNames are ifOperStatus's values (RFC 2863), 1-based.
var OperNames = []string{"up", "down", "testing", "unknown", "dormant", "notPresent", "lowerLayerDown"}

// OperName names an ifOperStatus value ("unknown" for anything else).
func OperName(v int64) string {
	if v >= 1 && int(v) <= len(OperNames) {
		return OperNames[v-1]
	}
	return "unknown"
}

// Keys are each kind's keys after kind and cycle, in the order they're
// written. A record writes the ones it has, in this order; readers ignore
// keys they don't know, so later versions can add some at the end.
var Keys = map[string][]string{
	KindSys: {"uptime", "hr_uptime", "cpu", "mem_used", "mem_total", "rtt_ms"},
	KindIf: {"if", "name", "oper", "oper_was", "speed_mbps", "bits",
		"in_octets", "out_octets", "in_bps", "out_bps",
		"in_err", "out_err", "in_err_d", "out_err_d",
		"in_disc", "out_disc", "in_disc_d", "out_disc_d",
		"in_ucast", "out_ucast", "in_mcast", "out_mcast", "in_bcast", "out_bcast",
		"in_ucast_pps", "out_ucast_pps", "in_mcast_pps", "out_mcast_pps", "in_bcast_pps", "out_bcast_pps",
		"disc", "wraps"},
	KindOID:     {"oid", "row", "label", "type", "value", "rate", "disc", "capped"},
	KindStatus:  {"status", "detail", "cred"},
	KindRestart: {"reboot", "uptime", "prev_uptime", "hr_uptime", "prev_hr_uptime", "boots", "prev_boots", "source"},
	KindInfo: {"sys_name", "sys_descr", "sys_oid", "hc", "hr", "ifs_total", "ifs_polled",
		"if", "name", "descr", "alias", "speed_mbps"},
}

// quotedKeys are always written quoted (free text).
var quotedKeys = map[string]bool{"name": true, "label": true, "detail": true, "sys_name": true, "sys_descr": true,
	"descr": true, "alias": true}

// KV is one key and its value.
type KV struct {
	Key, Value string
}

// Record is one poll record: its kind, cycle and the rest of its keys.
type Record struct {
	Kind   string
	Cycle  uint64
	Fields []KV
}

// Get returns a key's value ("" and false when absent).
func (r *Record) Get(key string) (string, bool) {
	for _, f := range r.Fields {
		if f.Key == key {
			return f.Value, true
		}
	}
	return "", false
}

// Value returns a key's value, or "".
func (r *Record) Value(key string) string {
	v, _ := r.Get(key)
	return v
}

// Uint returns a key's value as an unsigned integer.
func (r *Record) Uint(key string) (uint64, bool) {
	v, ok := r.Get(key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(v, 10, 64)
	return n, err == nil
}

// Float returns a key's value as a number.
func (r *Record) Float(key string) (float64, bool) {
	v, ok := r.Get(key)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseFloat(v, 64)
	return n, err == nil && !math.IsNaN(n) && !math.IsInf(n, 0)
}

// Set adds or replaces a key.
func (r *Record) Set(key, value string) {
	for i := range r.Fields {
		if r.Fields[i].Key == key {
			r.Fields[i].Value = value
			return
		}
	}
	r.Fields = append(r.Fields, KV{key, value})
}

// Builder writes a record's keys in Keys order.
type Builder struct {
	r Record
}

// New starts a record.
func New(kind string, cycle uint64) *Builder { return &Builder{r: Record{Kind: kind, Cycle: cycle}} }

// Str sets a key.
func (b *Builder) Str(key, v string) *Builder { b.r.Set(key, v); return b }

// Uint sets a key to an unsigned integer.
func (b *Builder) Uint(key string, v uint64) *Builder { return b.Str(key, strconv.FormatUint(v, 10)) }

// Int sets a key to an integer.
func (b *Builder) Int(key string, v int64) *Builder { return b.Str(key, strconv.FormatInt(v, 10)) }

// Float sets a key to a number: an integer when it's whole, else at most 2
// decimals (rates).
func (b *Builder) Float(key string, v float64) *Builder { return b.Str(key, FormatFloat(v)) }

// Record returns the record, its keys sorted into Keys order.
func (b *Builder) Record() Record {
	order := Keys[b.r.Kind]
	pos := func(k string) int {
		for i, o := range order {
			if o == k {
				return i
			}
		}
		return len(order)
	}
	f := b.r.Fields
	// Insertion sort (a few dozen keys): stable, keeps unknown keys last.
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && pos(f[j].Key) < pos(f[j-1].Key); j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
	return b.r
}

// FormatFloat writes a rate: whole numbers as integers, others with at most
// two decimals, never in exponent form.
func FormatFloat(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return "0"
	}
	if v == math.Trunc(v) && math.Abs(v) < 1e18 {
		return strconv.FormatInt(int64(v), 10)
	}
	s := strconv.FormatFloat(v, 'f', 2, 64)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "-0" {
		return "0"
	}
	return s
}

// Append appends the record's line (without the envelope) to dst.
func Append(dst []byte, r Record) []byte {
	dst = append(dst, "kind="...)
	dst = appendValue(dst, r.Kind, false)
	dst = append(dst, " cycle="...)
	dst = strconv.AppendUint(dst, r.Cycle, 10)
	for _, f := range r.Fields {
		if !validKey(f.Key) || f.Key == "kind" || f.Key == "cycle" {
			continue
		}
		dst = append(dst, ' ')
		dst = append(dst, f.Key...)
		dst = append(dst, '=')
		dst = appendValue(dst, f.Value, quotedKeys[f.Key])
	}
	return dst
}

// Format is Append to a new slice.
func Format(r Record) []byte { return Append(nil, r) }

func validKey(k string) bool {
	if k == "" || len(k) > 64 {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

// bare reports whether v can be written without quotes.
func bare(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if c <= ' ' || c == '"' || c == '\\' || c == '=' || c >= 0x7f {
			return false
		}
	}
	return true
}

func appendValue(dst []byte, v string, quote bool) []byte {
	if !quote && bare(v) {
		return append(dst, v...)
	}
	dst = append(dst, '"')
	for i := 0; i < len(v); {
		c := v[i]
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < ' ' || c == 0x7f {
				dst = append(dst, fmt.Sprintf("\\x%02x", c)...)
			} else if c >= 0x80 {
				r, n := utf8.DecodeRuneInString(v[i:])
				if r == utf8.RuneError && n == 1 {
					dst = append(dst, fmt.Sprintf("\\x%02x", c)...)
				} else {
					dst = append(dst, v[i:i+n]...)
				}
				i += n
				continue
			} else {
				dst = append(dst, c)
			}
		}
		i++
	}
	return append(dst, '"')
}

// ErrNotPoll is Parse's error for a line that isn't a poll record.
var ErrNotPoll = errors.New("pollrec: not a poll record")

// MaxFields bounds a record's keys (a parse of anything longer stops).
const MaxFields = 256

// Parse reads a record (without the envelope). Unknown keys are kept.
func Parse(line []byte) (Record, error) {
	var r Record
	p := parser{b: line}
	first := true
	for {
		p.skipSpaces()
		if p.done() {
			break
		}
		k, err := p.key()
		if err != nil {
			return r, err
		}
		v, err := p.value()
		if err != nil {
			return r, err
		}
		switch {
		case first:
			if k != "kind" || v == "" {
				return r, ErrNotPoll
			}
			r.Kind = v
			first = false
		case k == "cycle" && r.Cycle == 0:
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return r, fmt.Errorf("pollrec: cycle %q isn't a number", v)
			}
			r.Cycle = n
		default:
			if len(r.Fields) >= MaxFields {
				return r, fmt.Errorf("pollrec: more than %d keys", MaxFields)
			}
			r.Fields = append(r.Fields, KV{k, v})
		}
	}
	if first {
		return r, ErrNotPoll
	}
	return r, nil
}

// KindOf reads only a record's kind (cheap, for filters).
func KindOf(line []byte) string {
	if len(line) < 6 || string(line[:5]) != "kind=" {
		return ""
	}
	i := 5
	for i < len(line) && line[i] != ' ' {
		i++
	}
	return string(line[5:i])
}

type parser struct {
	b []byte
	i int
}

func (p *parser) done() bool { return p.i >= len(p.b) }

func (p *parser) skipSpaces() {
	for p.i < len(p.b) && p.b[p.i] == ' ' {
		p.i++
	}
}

func (p *parser) key() (string, error) {
	start := p.i
	for p.i < len(p.b) && p.b[p.i] != '=' && p.b[p.i] != ' ' {
		p.i++
	}
	if p.i >= len(p.b) || p.b[p.i] != '=' || p.i == start {
		return "", fmt.Errorf("pollrec: a key without a value at byte %d", start)
	}
	k := string(p.b[start:p.i])
	p.i++
	return k, nil
}

func (p *parser) value() (string, error) {
	if p.i < len(p.b) && p.b[p.i] == '"' {
		p.i++
		var sb strings.Builder
		for p.i < len(p.b) {
			c := p.b[p.i]
			switch c {
			case '"':
				p.i++
				return sb.String(), nil
			case '\\':
				if p.i+1 >= len(p.b) {
					return "", errors.New("pollrec: an unfinished escape")
				}
				e := p.b[p.i+1]
				p.i += 2
				switch e {
				case 'n':
					sb.WriteByte('\n')
				case 'r':
					sb.WriteByte('\r')
				case 't':
					sb.WriteByte('\t')
				case 'x':
					if p.i+2 > len(p.b) {
						return "", errors.New("pollrec: an unfinished \\x escape")
					}
					n, err := strconv.ParseUint(string(p.b[p.i:p.i+2]), 16, 8)
					if err != nil {
						return "", errors.New("pollrec: a bad \\x escape")
					}
					sb.WriteByte(byte(n))
					p.i += 2
				default:
					sb.WriteByte(e)
				}
			default:
				sb.WriteByte(c)
				p.i++
			}
		}
		return "", errors.New("pollrec: an unterminated string")
	}
	start := p.i
	for p.i < len(p.b) && p.b[p.i] != ' ' {
		p.i++
	}
	return string(p.b[start:p.i]), nil
}

// IfName is an if or info record's interface as the schema's if field shows
// it: its name, or its index when it has none.
func IfName(r *Record) string {
	if n := r.Value("name"); n != "" {
		return n
	}
	return r.Value("if")
}

// Text is the part of a record q matches: the whole record (it holds no
// base64 or secrets).
func Text(line []byte) []byte { return line }
