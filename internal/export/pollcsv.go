package export

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"sort"
	"strconv"
	"time"

	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/pollrec"
	"github.com/gmccollu/woodshed/internal/search"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// The poll type in a zip (SPEC §12.6): not the stored lines but three CSV
// files per device, poll/<device>/system.csv, interfaces.csv and oids.csv,
// with a header row, UTF-8, RFC 4180 quoting (CRLF line ends) and RFC 3339
// UTC times. An empty cell is "not measured" (no previous sample, a
// discontinuity, not supported), never zero. A file is written only when it
// has rows.

// The CSV columns (SPEC §12.6).
var (
	SystemCSVColumns = []string{"time", "cycle", "uptime_s", "hr_uptime_s", "cpu_pct", "mem_used_bytes", "mem_total_bytes", "rtt_ms",
		"status", "detail"}
	InterfacesCSVColumns = []string{"time", "cycle", "if_index", "if_name", "if_alias", "oper", "speed_mbps", "in_octets", "out_octets",
		"in_bps", "out_bps", "in_errors", "out_errors", "in_errors_delta", "out_errors_delta", "in_discards", "out_discards",
		"in_discards_delta", "out_discards_delta", "discontinuity"}
	OIDsCSVColumns = []string{"time", "cycle", "oid", "label", "row", "type", "value", "rate"}
)

// csvTime is a row's time: RFC 3339, UTC, milliseconds.
func csvTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ticksSeconds turns TimeTicks (1/100 s) into seconds: "1045123.45".
func ticksSeconds(v string) string {
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return ""
	}
	if n%100 == 0 {
		return strconv.FormatUint(n/100, 10)
	}
	s := strconv.FormatUint(n/100, 10) + "." + strconv.FormatUint(100+n%100, 10)[1:]
	if s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	return s
}

// aliasAt is an interface's ifAlias from an info line.
type aliasAt struct {
	t     time.Time
	alias string
}

// aliases are the interfaces' ifAlias over time, by ifIndex.
type aliases map[string][]aliasAt

// at is the interface's alias from its latest info line at or before t, or
// from its first one in the window when none came before.
func (a aliases) at(idx string, t time.Time) string {
	l := a[idx]
	if len(l) == 0 {
		return ""
	}
	i := sort.Search(len(l), func(i int) bool { return l[i].t.After(t) })
	if i == 0 {
		return l[0].alias
	}
	return l[i-1].alias
}

func systemRow(r *pollrec.Record, t time.Time) []string {
	row := []string{csvTime(t), strconv.FormatUint(r.Cycle, 10), "", "", "", "", "", "", "", ""}
	switch r.Kind {
	case pollrec.KindSys:
		row[2], row[3] = ticksSeconds(r.Value("uptime")), ticksSeconds(r.Value("hr_uptime"))
		row[4], row[5], row[6], row[7] = r.Value("cpu"), r.Value("mem_used"), r.Value("mem_total"), r.Value("rtt_ms")
		row[8] = "ok"
	case pollrec.KindStatus:
		row[8], row[9] = r.Value("status"), r.Value("detail")
	case pollrec.KindRestart:
		row[2], row[3] = ticksSeconds(r.Value("uptime")), ticksSeconds(r.Value("hr_uptime"))
		row[8], row[9] = "restart", datatype.RestartDetail(r)
	default:
		return nil
	}
	return row
}

func interfaceRow(al aliases) func(r *pollrec.Record, t time.Time) []string {
	return func(r *pollrec.Record, t time.Time) []string {
		if r.Kind != pollrec.KindIf {
			return nil
		}
		idx := r.Value("if")
		disc := ""
		if r.Value("disc") == "1" {
			disc = "1"
		}
		return []string{csvTime(t), strconv.FormatUint(r.Cycle, 10), idx, r.Value("name"), al.at(idx, t), r.Value("oper"),
			r.Value("speed_mbps"), r.Value("in_octets"), r.Value("out_octets"), r.Value("in_bps"), r.Value("out_bps"),
			r.Value("in_err"), r.Value("out_err"), r.Value("in_err_d"), r.Value("out_err_d"),
			r.Value("in_disc"), r.Value("out_disc"), r.Value("in_disc_d"), r.Value("out_disc_d"), disc}
	}
}

func oidRow(r *pollrec.Record, t time.Time) []string {
	if r.Kind != pollrec.KindOID {
		return nil
	}
	return []string{csvTime(t), strconv.FormatUint(r.Cycle, 10), r.Value("oid"), r.Value("label"), r.Value("row"), r.Value("type"),
		r.Value("value"), r.Value("rate")}
}

// pollPass is one CSV file of one device: the device's poll lines of some
// kinds, through the request's filter, one row each.
type pollPass struct {
	file    string
	columns []string
	kinds   []string
	row     func(r *pollrec.Record, t time.Time) []string
}

// writePoll writes a device's poll CSVs. ts (a bundle's) counts every record
// that became a row. It returns the bytes scanned.
func (b *builder) writePoll(ctx context.Context, zw *zipWriter, dev string, flt search.Filter, ts *typeCount, res *buildResult,
	files *[]ManifestFile, progress func(scanned int64)) (int64, error) {
	var scanned int64
	// The aliases come from every info line in the range, whatever the filter.
	al := aliases{}
	info, _ := (*datatype.PollFilter)(nil).WithKinds(pollrec.KindInfo)
	err := b.scanPoll(ctx, dev, search.Filter{From: flt.From, To: flt.To, Type: datatype.Poll, Poll: info}, &scanned,
		func(r *pollrec.Record, t time.Time, _ []byte) error {
			if idx := r.Value("if"); idx != "" {
				al[idx] = append(al[idx], aliasAt{t, r.Value("alias")})
			}
			return nil
		})
	if err != nil {
		return scanned, err
	}
	for _, l := range al {
		sort.SliceStable(l, func(i, j int) bool { return l[i].t.Before(l[j].t) })
	}
	passes := []pollPass{
		{"system.csv", SystemCSVColumns, []string{pollrec.KindSys, pollrec.KindStatus, pollrec.KindRestart}, systemRow},
		{"interfaces.csv", InterfacesCSVColumns, []string{pollrec.KindIf}, interfaceRow(al)},
		{"oids.csv", OIDsCSVColumns, []string{pollrec.KindOID}, oidRow},
	}
	var buf bytes.Buffer
	cw := csv.NewWriter(&buf)
	cw.UseCRLF = true
	for _, p := range passes {
		pf, ok := flt.Poll.WithKinds(p.kinds...)
		if !ok {
			continue
		}
		f := flt
		f.Type, f.Poll = datatype.Poll, pf
		var out *fileOut
		emit := func(rec []string) error {
			buf.Reset()
			if err := cw.Write(rec); err != nil {
				return err
			}
			cw.Flush()
			if _, err := zw.Write(buf.Bytes()); err != nil {
				return err
			}
			out.sum.Write(buf.Bytes())
			out.mf.Bytes += int64(buf.Len())
			return nil
		}
		err := b.scanPoll(ctx, dev, f, &scanned, func(r *pollrec.Record, t time.Time, rec []byte) error {
			row := p.row(r, t)
			if row == nil {
				return nil
			}
			if out == nil {
				name := FolderOf(datatype.Poll) + "/" + dev + "/" + p.file
				if err := zw.create(name, -1); err != nil {
					return err
				}
				out = &fileOut{mf: ManifestFile{Path: name, DeviceID: dev, First: t}, sum: sha256.New()}
				if err := emit(p.columns); err != nil {
					return err
				}
			}
			if err := emit(row); err != nil {
				return err
			}
			out.mf.Lines++
			out.mf.Last = t
			res.lines++
			if ts != nil {
				ts.add(rec, t)
			}
			if out.mf.Lines%4096 == 0 {
				progress(scanned)
			}
			return nil
		})
		if out != nil {
			out.mf.SHA256 = hex.EncodeToString(out.sum.Sum(nil))
			*files = append(*files, out.mf)
		}
		if err != nil {
			return scanned, err
		}
	}
	return scanned, nil
}

// scanPoll calls fn with each of a device's poll records that pass flt,
// oldest first. Records that don't parse are skipped.
func (b *builder) scanPoll(ctx context.Context, dev string, flt search.Filter, scanned *int64,
	fn func(r *pollrec.Record, t time.Time, rec []byte) error) error {
	sc, err := b.eng.NewScanner(ctx, dev, flt)
	if err != nil {
		return err
	}
	defer sc.Close()
	var rec []byte
	n := 0
	for {
		h, more := sc.Next()
		if !more {
			break
		}
		rec = logfile.Unescape(rec[:0], h.Escaped)
		if r, err := pollrec.Parse(rec); err == nil {
			if err := fn(&r, h.Received, rec); err != nil {
				return err
			}
		}
		if n++; n%4096 == 0 && ctx.Err() != nil {
			break
		}
	}
	*scanned += sc.Scanned()
	if err := sc.Err(); err != nil {
		return err
	}
	return ctx.Err()
}
