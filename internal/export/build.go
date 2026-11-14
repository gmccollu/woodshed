package export

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strings"
	"time"

	"github.com/gmccollu/woodshed/internal/atomicfile"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

type buildResult struct {
	lines, size int64
	files       int
}

// Manifest is manifest.json.
type Manifest struct {
	Format          string         `json:"format"` // "woodshed-export/1"
	WoodshedVersion string         `json:"woodshed_version"`
	ExportedAt      time.Time      `json:"exported_at"`
	ID              string         `json:"id"`
	Request         ManifestReq    `json:"request"`
	Files           []ManifestFile `json:"files"`
	Lines           int64          `json:"lines"`
	Gaps            []Gap          `json:"gaps"`
	GapsNote        string         `json:"gaps_note"`
	EventsFile      string         `json:"events_file"`
	Events          int            `json:"events"`
	// 1.2: the kind ("export"), the data types and which zip folder holds
	// each (docs/api.md).
	Kind    string            `json:"kind"`
	Types   []string          `json:"types"`
	Folders map[string]string `json:"folders"`
}

// ManifestReq echoes the request.
type ManifestReq struct {
	From    time.Time        `json:"from"`
	To      time.Time        `json:"to"`
	Devices []ManifestDevice `json:"devices"`
	Filters ManifestFilters  `json:"filters"`
}

// ManifestDevice is one exported device.
type ManifestDevice struct {
	ID    string `json:"id"`
	IP    string `json:"ip"`
	Name  string `json:"name"`
	Group string `json:"group"`
}

// ManifestFilters are the request's filters in API form.
type ManifestFilters struct {
	Devices    []string `json:"devices"` // as named in the request
	Group      string   `json:"group"`
	Ungrouped  bool     `json:"ungrouped"`
	Severities []any    `json:"severities"` // [] = all; ["none"] = nothing
	Q          string   `json:"q"`
	Regex      bool     `json:"regex"`
	Case       bool     `json:"case"`
	App        []string `json:"app"`     // program/tag values; [] = all
	Host       []string `json:"host"`    // header hostnames; [] = all
	Exclude    string   `json:"exclude"` // "" = nothing excluded
	// 1.1 (docs/api.md): the data type, the q/exclude syntax, facilities and the
	// exclude forms of devices, app and host.
	Type           string   `json:"type"`            // "syslog"
	Syntax         string   `json:"syntax"`          // "text" | "terms"
	Facilities     []any    `json:"facilities"`      // [] = all; ["none"] = nothing
	ExcludeDevices []string `json:"exclude_devices"` // [] = none excluded
	ExcludeApp     []string `json:"exclude_app"`
	ExcludeHost    []string `json:"exclude_host"`
}

// ManifestFile is one log file in the zip.
type ManifestFile struct {
	Path     string    `json:"path"`
	DeviceID string    `json:"device_id"`
	Day      string    `json:"day"`
	Lines    int64     `json:"lines"` // messages
	Bytes    int64     `json:"bytes"`
	SHA256   string    `json:"sha256"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

// SeverityList renders a severity set as the API's list: [] for all, ["none"],
// or the severities with "unknown".
func SeverityList(s hub.SeveritySet) []any {
	out := []any{}
	if s == hub.SeverityNone {
		return append(out, "none")
	}
	if s == 0 {
		return out
	}
	for i := 0; i < 8; i++ {
		if s.Has(i) {
			out = append(out, i)
		}
	}
	if s.Has(-1) {
		out = append(out, "unknown")
	}
	return out
}

// fileOut is the log file being written, with its checksum and counts.
type fileOut struct {
	mf  ManifestFile
	sum hash.Hash
}

func (m *Manager) build(ctx context.Context, e *entry) (buildResult, error) {
	m.mu.Lock()
	info := e.info
	m.mu.Unlock()
	req := Request{Devices: info.Named, From: info.From, To: info.To, Filters: info.Filters}
	types := req.TypesOrSyslog()

	type hk struct{ typ, dev, day string }
	hint := map[hk]int64{}
	var total int64
	for _, t := range types {
		est, err := m.eng.Estimate(ctx, info.Devices, req.typeFilter(t))
		if err != nil {
			return buildResult{}, err
		}
		for _, p := range est.Parts {
			hint[hk{t, p.Device, p.Day}] = p.Bytes
		}
		total += est.Bytes
	}
	total = max(total, 1)

	tmp := m.tmpPath(info.ID)
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o640)
	if err != nil {
		return buildResult{}, err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(tmp)
		}
	}()
	exportedAt := m.now().UTC()
	zw := newZipWriter(f, m.opts.zip64Limit, exportedAt, m.opts.Level)

	var res buildResult
	var files []ManifestFile
	var cur *fileOut
	finish := func() {
		if cur != nil {
			cur.mf.SHA256 = hex.EncodeToString(cur.sum.Sum(nil))
			files = append(files, cur.mf)
			cur = nil
		}
	}
	var done int64
	var line []byte
	for _, typ := range types {
		flt := req.typeFilter(typ)
		folder := FolderOf(typ)
		for _, dev := range info.Devices {
			sc, err := m.eng.NewScanner(ctx, dev, flt)
			if err != nil {
				return res, err
			}
			n := 0
			for {
				h, more := sc.Next()
				if !more {
					break
				}
				if cur == nil || cur.mf.Day != h.Day {
					finish()
					name := folder + "/" + dev + "/" + h.Day + ".log"
					size := int64(-1)
					if b, ok := hint[hk{typ, dev, h.Day}]; ok {
						size = b + 64<<10 // lines the index hadn't seen yet
					}
					if err := zw.create(name, size); err != nil {
						sc.Close()
						return res, err
					}
					cur = &fileOut{mf: ManifestFile{Path: name, DeviceID: dev, Day: h.Day, First: h.Received}, sum: sha256.New()}
				}
				if m.opts.testHookLine != nil {
					m.opts.testHookLine()
				}
				// The line as stored: "<received> <sender> <message>", with CR, LF and
				// backslash in the message escaped, so every message is one line.
				line = append(append(line[:0], h.Line...), '\n')
				if _, err := zw.Write(line); err != nil {
					sc.Close()
					return res, err
				}
				cur.sum.Write(line)
				cur.mf.Lines++
				cur.mf.Bytes += int64(len(line))
				cur.mf.Last = h.Received
				res.lines++
				if n++; n%4096 == 0 {
					m.setProgress(e, 0.97*float64(done+sc.Scanned())/float64(total))
					if ctx.Err() != nil {
						break
					}
				}
			}
			done += sc.Scanned()
			sc.Close()
			if err := sc.Err(); err != nil {
				return res, err
			}
			if err := ctx.Err(); err != nil {
				return res, err
			}
			finish()
		}
	}
	finish()

	// The service's own events in the range, and the gaps they show.
	evs, err := m.idx.Events(ctx, time.Time{}, info.To, 0)
	if err != nil {
		return res, err
	}
	var inRange []index.Event
	for _, ev := range evs {
		if !ev.Time.Before(info.From) {
			inRange = append(inRange, ev)
		}
	}
	allFiles, err := m.idx.Files(ctx, "")
	if err != nil {
		return res, err
	}
	lastMessage := func(t time.Time) time.Time {
		var last time.Time
		for _, fl := range allFiles {
			if fl.LastReceived.Before(t) && fl.LastReceived.After(last) {
				last = fl.LastReceived
			}
		}
		return last
	}
	gaps := ComputeGaps(evs, info.From, info.To, exportedAt, lastMessage)

	if err := zw.create("woodshed-events.log", -1); err != nil {
		return res, err
	}
	var eb []byte
	for _, ev := range inRange {
		eb = eb[:0]
		eb = logfile.AppendTime(eb, ev.Time)
		eb = fmt.Appendf(eb, " %s %s", ev.Level, ev.Kind)
		if ev.DeviceID != "" {
			eb = append(eb, ' ')
			eb = append(eb, ev.DeviceID...)
		}
		eb = append(eb, ' ')
		eb = logfile.AppendEscaped(eb, []byte(ev.Text))
		eb = append(eb, '\n')
		if _, err := zw.Write(eb); err != nil {
			return res, err
		}
	}

	if err := zw.create("README.txt", -1); err != nil {
		return res, err
	}
	if _, err := zw.Write([]byte(readme(info))); err != nil {
		return res, err
	}

	devs := make([]ManifestDevice, 0, len(info.Devices))
	for _, id := range info.Devices {
		d, err := m.idx.Device(ctx, id)
		if err != nil {
			d = index.Device{ID: id}
		}
		devs = append(devs, ManifestDevice{ID: d.ID, IP: d.IP, Name: d.Name, Group: d.Group})
	}
	man := Manifest{
		Format: "woodshed-export/1", WoodshedVersion: m.opts.Version, ExportedAt: exportedAt, ID: info.ID,
		Request: ManifestReq{From: info.From, To: info.To, Devices: devs, Filters: ManifestFilters{
			Devices: nonNil(info.Named), Group: info.Filters.Group, Ungrouped: info.Filters.Ungrouped, Severities: SeverityList(info.Filters.Severities),
			Q: info.Filters.Q, Regex: info.Filters.Regex, Case: info.Filters.Case,
			App: nonNil(info.Filters.Apps), Host: nonNil(info.Filters.Hosts), Exclude: info.Filters.Exclude,
			Type: "syslog", Syntax: syntaxName(info.Filters.Terms), Facilities: info.Filters.Facilities.List(),
			ExcludeDevices: nonNil(info.Filters.ExcludeDevices), ExcludeApp: nonNil(info.Filters.ExcludeApps),
			ExcludeHost: nonNil(info.Filters.ExcludeHosts)}},
		Files: nonNil(files), Lines: res.lines, Gaps: nonNil(gaps), GapsNote: GapsNote,
		EventsFile: "woodshed-events.log", Events: len(inRange),
		Kind: "export", Types: types, Folders: map[string]string{},
	}
	for _, t := range types {
		man.Folders[FolderOf(t)] = t
	}
	if len(types) == 1 && types[0] != datatype.Syslog {
		man.Request.Filters.Type = types[0]
	}
	mb, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return res, err
	}
	if err := zw.create("manifest.json", -1); err != nil {
		return res, err
	}
	if _, err := zw.Write(append(mb, '\n')); err != nil {
		return res, err
	}
	if err := zw.close(); err != nil {
		return res, err
	}
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if err := f.Sync(); err != nil {
		return res, err
	}
	st, err := f.Stat()
	if err != nil {
		return res, err
	}
	if err := f.Close(); err != nil {
		return res, err
	}
	if err := atomicfile.Rename(tmp, m.zipPath(info.ID)); err != nil {
		return res, err
	}
	ok = true
	res.size, res.files = st.Size(), len(files)
	return res, nil
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func syntaxName(terms bool) string {
	if terms {
		return "terms"
	}
	return "text"
}

func readme(info Info) string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Woodshed export %s\n", info.ID)
	fmt.Fprintf(&b, "Range: %s to %s (UTC, received time; the end is exclusive)\n",
		info.From.Format(time.RFC3339), info.To.Format(time.RFC3339))
	if fl := filterLines(info.Filters); len(fl) > 0 {
		b.WriteString("Filters (only lines that pass every one are included):\n")
		for _, l := range fl {
			b.WriteString("    " + l + "\n")
		}
	} else {
		b.WriteString("Filters: none (every line in the range)\n")
	}
	b.WriteString("\n")
	b.WriteString(strings.TrimLeft(`
logs/<device>/<YYYY-MM-DD>.log
    The messages Woodshed received from each device on that day (UTC), oldest
    first, one message per line, exactly as Woodshed stores them:
        <received time, UTC> <sender IP> <message>
    In <message>, a carriage return is written \r, a line feed \n and a
    backslash \\, so a message never spans lines; every other byte is as
    received. To get the messages back with their own line breaks:
        perl -pe 's/\\(\\|r|n)/$1 eq "r" ? "\r" : $1 eq "n" ? "\n" : "\\"/ge' <file>
    <device> is the sender's IP address (":" written as "_" for IPv6).

`+trapReadme(info)+`manifest.json
    What was exported: the request (devices with their names and groups, the
    range and any filters), each log file's line count and SHA-256, and "gaps":
    periods in the range when Woodshed wasn't running or a listener was down,
    so "the device sent nothing" can be told apart from "Woodshed wasn't
    listening". "gaps_note" says how the gaps are worked out.

woodshed-events.log
    Woodshed's own events in the range: starts and stops, listener bind errors,
    file rotations and deletions, dropped messages, paused writes.

To check a file: sha256sum logs/<device>/<day>.log (or on Windows:
certutil -hashfile <file> SHA256) and compare with manifest.json.
`, "\n"))
	return b.String()
}

// filterLines describes an export's line filters for README.txt, one per line
// (the device selection is in manifest.json).
func filterLines(f Filters) []string {
	var out []string
	how := func() string {
		var bits []string
		if f.Regex {
			bits = append(bits, "regular expression")
		}
		if f.Terms {
			bits = append(bits, "boolean terms")
		}
		if f.Case {
			bits = append(bits, "case-sensitive")
		} else {
			bits = append(bits, "any case")
		}
		return " (" + strings.Join(bits, ", ") + ")"
	}
	if f.Severities != 0 {
		var sev []string
		for _, v := range SeverityList(f.Severities) {
			sev = append(sev, fmt.Sprint(v))
		}
		out = append(out, "Severities: "+strings.Join(sev, ", "))
	}
	if f.Facilities != 0 {
		var fac []string
		for _, v := range f.Facilities.List() {
			fac = append(fac, fmt.Sprint(v))
		}
		out = append(out, "Facilities: "+strings.Join(fac, ", "))
	}
	if f.Q != "" {
		out = append(out, fmt.Sprintf("Text: %q%s", f.Q, how()))
	}
	if len(f.Apps) > 0 {
		out = append(out, "Program/tag: "+strings.Join(f.Apps, ", "))
	}
	if len(f.ExcludeApps) > 0 {
		out = append(out, "Program/tag left out: "+strings.Join(f.ExcludeApps, ", "))
	}
	if len(f.Hosts) > 0 {
		out = append(out, "Host: "+strings.Join(f.Hosts, ", "))
	}
	if len(f.ExcludeHosts) > 0 {
		out = append(out, "Host left out: "+strings.Join(f.ExcludeHosts, ", "))
	}
	if len(f.ExcludeDevices) > 0 {
		out = append(out, "Devices left out: "+strings.Join(f.ExcludeDevices, ", "))
	}
	if f.Exclude != "" {
		out = append(out, fmt.Sprintf("Exclude: %q%s", f.Exclude, how()))
	}
	return out
}

// trapReadme is README.txt's part about the traps folder, for a zip with
// traps (docs/api.md: communities are a hash prefix, and masked in raw=).
func trapReadme(info Info) string {
	has := false
	for _, t := range info.Filters.TypesOrSyslog() {
		has = has || t == datatype.Trap
	}
	if !has {
		return ""
	}
	return `traps/<device>/<YYYY-MM-DD>.log
    The SNMP traps and informs Woodshed received from each device on that day
    (UTC), in the same envelope as the logs: <received time> <sender IP>
    <record>. A record is the decoded trap: v=, pdu=, cred=, status=, the
    trap OID, one vb= per varbind (OIDs numeric, with names known when it was
    received), and raw= last, the whole datagram in base64. A v1/v2c community
    is never stored: cred= is "#" and the first 8 hex digits of its SHA-256,
    and in raw= the community's bytes are replaced by as many "*" bytes (the
    lengths are unchanged, so the datagram still decodes). A v3 message is
    kept exactly; its secrets are never in the packet.

`
}
