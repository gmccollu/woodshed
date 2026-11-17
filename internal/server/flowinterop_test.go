package server

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
)

// The flow interop test (SPEC §13.8, the CI job "flow-interop", Linux):
// softflowd replays a small synthetic pcap (made here: no real traffic) to a
// real server as flow v5, v9 and IPFIX, and the stored records are
// compared with the pcap's flows computed here; pmacct's nfprobe is a second
// IPFIX exporter when it's installed; and the flows.ipfix an export writes is
// read back by our decoder and by tshark, and both agree with the CSV.
//
// It runs only with WOODSHED_FLOW_INTEROP=1 (softflowd and tshark on PATH);
// WOODSHED_FLOW_INTEROP_REQUIRE=pmacct makes a missing pmacctd a failure.

type tuple struct {
	src, dst     netip.Addr
	sport, dport uint16
	proto        uint8
}

type pcapFlow struct {
	tuple
	packets, bytes uint64
}

func (k tuple) String() string {
	return fmt.Sprintf("%s > %s proto %d", netip.AddrPortFrom(k.src, k.sport), netip.AddrPortFrom(k.dst, k.dport), k.proto)
}

func (f *pcapFlow) String() string {
	if f == nil {
		return "nothing"
	}
	return fmt.Sprintf("%d packets, %d bytes", f.packets, f.bytes)
}

// writePcap writes an Ethernet pcap of n one-direction flows, each with a
// few packets, and returns the flows as a flow exporter should count them
// (IP bytes).
func writePcap(t *testing.T, path string, start time.Time) []pcapFlow {
	t.Helper()
	var b bytes.Buffer
	le := binary.LittleEndian
	hdr := make([]byte, 24)
	le.PutUint32(hdr[0:], 0xa1b2c3d4)
	le.PutUint16(hdr[4:], 2)
	le.PutUint16(hdr[6:], 4)
	le.PutUint32(hdr[16:], 65535)
	le.PutUint32(hdr[20:], 1) // Ethernet
	b.Write(hdr)
	var flows []pcapFlow
	at := start
	for i := 0; i < 12; i++ {
		f := pcapFlow{tuple: tuple{src: netip.AddrFrom4([4]byte{10, 10, 0, byte(i + 1)}), dst: netip.AddrFrom4([4]byte{192, 0, 2, byte(i%3 + 1)}),
			sport: uint16(40000 + i), dport: []uint16{443, 53, 22}[i%3], proto: []uint8{6, 17, 6}[i%3]}}
		for k := 0; k < 3+i; k++ {
			payload := 100 + 10*i
			l4 := 8
			if f.proto == 6 {
				l4 = 20
			}
			ipLen := 20 + l4 + payload
			pkt := make([]byte, 14+ipLen)
			copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 1})
			copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 2})
			pkt[12], pkt[13] = 0x08, 0x00
			ip := pkt[14:]
			ip[0] = 0x45
			binary.BigEndian.PutUint16(ip[2:], uint16(ipLen))
			binary.BigEndian.PutUint16(ip[4:], uint16(i*100+k))
			ip[8], ip[9] = 64, f.proto
			s4, d4 := f.src.As4(), f.dst.As4()
			copy(ip[12:16], s4[:])
			copy(ip[16:20], d4[:])
			var sum uint32
			for j := 0; j < 20; j += 2 {
				sum += uint32(binary.BigEndian.Uint16(ip[j:]))
			}
			for sum > 0xffff {
				sum = sum&0xffff + sum>>16
			}
			binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
			l := ip[20:]
			binary.BigEndian.PutUint16(l[0:], f.sport)
			binary.BigEndian.PutUint16(l[2:], f.dport)
			if f.proto == 6 {
				binary.BigEndian.PutUint32(l[4:], uint32(1000+k))
				l[12] = 5 << 4
				l[13] = 0x18 // PSH ACK
				binary.BigEndian.PutUint16(l[14:], 65535)
			} else {
				binary.BigEndian.PutUint16(l[4:], uint16(8+payload))
			}
			rec := make([]byte, 16)
			le.PutUint32(rec[0:], uint32(at.Unix()))
			le.PutUint32(rec[4:], uint32(at.Nanosecond()/1000))
			le.PutUint32(rec[8:], uint32(len(pkt)))
			le.PutUint32(rec[12:], uint32(len(pkt)))
			b.Write(rec)
			b.Write(pkt)
			f.packets++
			f.bytes += uint64(ipLen)
			at = at.Add(10 * time.Millisecond)
		}
		flows = append(flows, f)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return flows
}

// storedByVersion reads every stored record through the engine, by version.
func storedByVersion(t *testing.T, r *running) map[uint8]map[tuple]*pcapFlow {
	t.Helper()
	out := map[uint8]map[tuple]*pcapFlow{}
	q := flowquery.Query{From: time.Now().Add(-48 * time.Hour), To: time.Now().Add(time.Hour)}
	err := r.srv.be.flows.eng.Each(context.Background(), q, func(_ string, rec *flow.Record) error {
		m := out[rec.Version]
		if m == nil {
			m = map[tuple]*pcapFlow{}
			out[rec.Version] = m
		}
		k := tuple{rec.Src, rec.Dst, rec.SrcPort, rec.DstPort, rec.Proto}
		f := m[k]
		if f == nil {
			f = &pcapFlow{tuple: k}
			m[k] = f
		}
		f.packets += rec.SumPackets()
		f.bytes += rec.SumBytes()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFlowInterop(t *testing.T) {
	if os.Getenv("WOODSHED_FLOW_INTEROP") != "1" {
		t.Skip("set WOODSHED_FLOW_INTEROP=1 (with softflowd and tshark installed) to run")
	}
	softflowd, err := exec.LookPath("softflowd")
	if err != nil {
		t.Fatal("softflowd isn't on PATH")
	}
	r, nf, ix := flowServer(t, nil)
	dir := t.TempDir()
	pcap := filepath.Join(dir, "synthetic.pcap")
	// Packet times in the recent past, so the records are inside any window.
	want := writePcap(t, pcap, time.Now().Add(-10*time.Minute).Truncate(time.Second))
	var total uint64
	for _, f := range want {
		total += f.packets
	}

	for _, v := range []struct {
		arg  string
		ver  uint8
		port int
	}{{"5", flow.V5, nf}, {"9", flow.V9, nf}, {"10", flow.IPFIX, ix}} {
		out, err := exec.Command(softflowd, "-r", pcap, "-n", fmt.Sprintf("127.0.0.1:%d", v.port), "-v", v.arg, "-d").CombinedOutput()
		if err != nil {
			t.Fatalf("softflowd -v %s: %v\n%s", v.arg, err, out)
		}
		var got map[tuple]*pcapFlow
		deadline := time.Now().Add(30 * time.Second)
		for {
			r.srv.be.store.Flush()
			got = storedByVersion(t, r)[v.ver]
			var n uint64
			for _, f := range got {
				n += f.packets
			}
			if n >= total || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		bad := false
		for _, f := range want {
			g := got[f.tuple]
			if g == nil || g.packets != f.packets || g.bytes != f.bytes {
				t.Errorf("v%s %v: stored %+v, the pcap has %d packets, %d bytes", v.arg, f.tuple, g, f.packets, f.bytes)
				bad = true
			}
		}
		if len(got) != len(want) {
			t.Errorf("v%s: %d flows stored, the pcap has %d", v.arg, len(got), len(want))
			bad = true
		}
		if bad {
			arg := v.arg
			flowDiag(t, r, netip.MustParseAddr("127.0.0.1"), func(dst string) *exec.Cmd {
				return exec.Command(softflowd, "-r", pcap, "-n", dst, "-v", arg, "-d")
			})
		}
	}

	// pmacct's nfprobe: IPFIX with options data, when it's installed.
	if pm, err := exec.LookPath("pmacctd"); err == nil {
		conf := filepath.Join(dir, "pmacctd.conf")
		os.WriteFile(conf, []byte(fmt.Sprintf("daemonize: false\npcap_savefile: %s\npcap_savefile_wait: false\n"+
			"aggregate: src_host, dst_host, src_port, dst_port, proto\nplugins: nfprobe\nnfprobe_receiver: 127.0.0.1:%d\n"+
			"nfprobe_version: 10\nnfprobe_timeouts: expint=1:general=1:maxlife=1\nsampling_rate: 1\n", pcap, ix)), 0o600)
		before := storedByVersion(t, r)[flow.IPFIX]
		var n0 uint64
		for _, f := range before {
			n0 += f.packets
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := exec.CommandContext(ctx, pm, "-f", conf).CombinedOutput()
		cancel()
		if err != nil && ctx.Err() == nil {
			t.Logf("pmacctd: %v\n%s", err, out)
		}
		deadline := time.Now().Add(30 * time.Second)
		var n uint64
		for time.Now().Before(deadline) {
			r.srv.be.store.Flush()
			n = 0
			for _, f := range storedByVersion(t, r)[flow.IPFIX] {
				n += f.packets
			}
			if n >= n0+total {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		if n != n0+total {
			t.Errorf("pmacct nfprobe: %d packets stored, want %d more than the %d before", n, total, n0)
			flowDiag(t, r, netip.MustParseAddr("127.0.0.1"), nil)
		}
	} else if strings.Contains(os.Getenv("WOODSHED_FLOW_INTEROP_REQUIRE"), "pmacct") {
		t.Fatal("pmacctd isn't on PATH")
	} else {
		t.Log("pmacctd isn't installed: skipped the second exporter")
	}

	// An export's flows.ipfix: our decoder, tshark and the CSV agree.
	from, to := time.Now().Add(-2*time.Hour).UTC(), time.Now().Add(time.Minute).UTC()
	var created struct{ ID string }
	if code := r.do(t, "POST", "/api/exports", map[string]any{"devices": []string{"127.0.0.1"}, "from": from.Format(time.RFC3339),
		"to": to.Format(time.RFC3339), "types": []string{"flow"}}, &created); code != 202 {
		t.Fatalf("export: %d", code)
	}
	var info struct{ State, Error string }
	deadline := time.Now().Add(60 * time.Second)
	for info.State != "ready" && info.State != "failed" && time.Now().Before(deadline) {
		r.do(t, "GET", "/api/exports/"+created.ID, nil, &info)
		time.Sleep(100 * time.Millisecond)
	}
	if info.State != "ready" {
		t.Fatalf("export %+v", info)
	}
	_, _, zb := r.doRaw(t, "GET", "/api/exports/"+created.ID+"/download", nil)
	zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{}
	for _, f := range zr.File {
		rc, _ := f.Open()
		files[f.Name], _ = io.ReadAll(rc)
		rc.Close()
	}
	ipfixPath := filepath.Join(dir, "flows.ipfix")
	os.WriteFile(ipfixPath, files["flows/127.0.0.1/flows.ipfix"], 0o600)
	key := func(src, dst, sp, dp, proto string) string {
		return strings.Join([]string{src, dst, sp, dp, proto}, " ")
	}
	count := func(m map[string]int, k string) { m[k]++ }
	fromCSV := map[string]int{}
	cr := csv.NewReader(bytes.NewReader(files["flows/127.0.0.1/flows.csv"]))
	rows, err := cr.ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("flows.csv: %v (%d rows)", err, len(rows))
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	for _, row := range rows[1:] {
		count(fromCSV, key(row[col["src"]], row[col["dst"]], row[col["src_port"]], row[col["dst_port"]], row[col["proto"]]))
	}
	fromOurs := map[string]int{}
	if err := flow.ReadFile(bytes.NewReader(files["flows/127.0.0.1/flows.ipfix"]), flow.FileReadOptions{}, func(rec *flow.Record) {
		count(fromOurs, key(rec.Src.String(), rec.Dst.String(), strconv.Itoa(int(rec.SrcPort)), strconv.Itoa(int(rec.DstPort)),
			strconv.Itoa(int(rec.Proto))))
	}); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(sortedCounts(fromOurs)) != fmt.Sprint(sortedCounts(fromCSV)) {
		t.Errorf("our reader and the CSV disagree:\n ours %v\n csv  %v", sortedCounts(fromOurs), sortedCounts(fromCSV))
	}
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Fatal("tshark isn't on PATH")
	}
	out, err := exec.Command(tshark, "-r", ipfixPath, "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=;",
		"-e", "cflow.srcaddr", "-e", "cflow.dstaddr", "-e", "cflow.srcport", "-e", "cflow.dstport", "-e", "cflow.protocol").CombinedOutput()
	if err != nil {
		t.Fatalf("tshark: %v\n%s", err, out)
	}
	fromTshark := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) != 5 || cols[0] == "" {
			continue // a frame of templates or options only
		}
		parts := make([][]string, 5)
		for i := range cols {
			parts[i] = strings.Split(cols[i], ";")
		}
		for j := range parts[0] {
			if j >= len(parts[4]) {
				break
			}
			count(fromTshark, key(parts[0][j], parts[1][j], parts[2][j], parts[3][j], parts[4][j]))
		}
	}
	if fmt.Sprint(sortedCounts(fromTshark)) != fmt.Sprint(sortedCounts(fromCSV)) {
		t.Errorf("tshark and the CSV disagree:\n tshark %v\n csv    %v", sortedCounts(fromTshark), sortedCounts(fromCSV))
	}
}

func sortedCounts(m map[string]int) []string {
	var out []string
	for k, v := range m {
		out = append(out, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(out)
	return out
}

// The synthetic pcap is well formed: tcpdump (when it's installed; reading a
// file needs no privileges) reads every packet with the right addresses.
func TestSyntheticPcap(t *testing.T) {
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("tcpdump isn't installed")
	}
	path := filepath.Join(t.TempDir(), "synthetic.pcap")
	flows := writePcap(t, path, time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC))
	out, err := exec.Command(tcpdump, "-nn", "-r", path).CombinedOutput()
	if err != nil {
		t.Fatalf("tcpdump: %v\n%s", err, out)
	}
	var n uint64
	for _, f := range flows {
		n += f.packets
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	got := uint64(0)
	for _, l := range lines {
		if strings.Contains(l, " IP 10.10.0.") {
			got++
		}
	}
	if got != n || !strings.Contains(string(out), "10.10.0.1.40000 > 192.0.2.1.443") || strings.Contains(string(out), "bad cksum") {
		t.Fatalf("tcpdump read %d of %d packets:\n%s", got, n, out)
	}
}

// flowDiag logs what a flow test needs when an exporter's flows didn't arrive
// as expected: the collector's counts, domains and templates for the
// exporter; every record stored for it at any time, by version (a time
// decoded wrong lands outside the test's window); and, when capture isn't
// nil, the datagrams of a second run sent to a socket of the test's own
// (capture gets its host:port), the first in hex with its sets listed.
func flowDiag(t *testing.T, r *running, exporter netip.Addr, capture func(dst string) *exec.Cmd) {
	t.Helper()
	now := time.Now()
	coll := r.srv.be.flows.coll
	for _, st := range coll.Stats(now) {
		if st.Addr == exporter.Unmap() {
			t.Logf("collector, exporter %v: counts %+v; domains %+v; pending %d bytes; options kept raw %d; time source %s, clock skew %d ms",
				st.Addr, st.Counts, st.Domains, st.PendingBytes, st.OptionsRaw, st.TimeSource, st.ClockSkewMs)
		}
	}
	for _, ti := range coll.Templates(exporter) {
		var fs []string
		for _, f := range ti.Fields {
			fs = append(fs, fmt.Sprintf("%s(%d)/%d", f.Name, f.ID, f.Length))
		}
		t.Logf("template v%d domain %d port %d id %d options=%v: %s", ti.Version, ti.Domain, ti.Port, ti.ID, ti.Options, strings.Join(fs, " "))
	}
	r.srv.be.store.Flush()
	type seen struct {
		n          int
		first, max int64
		min        int64
	}
	byVer := map[uint8]*seen{}
	q := flowquery.Query{From: now.Add(-400 * 24 * time.Hour), To: now.Add(400 * 24 * time.Hour)}
	err := r.srv.be.flows.eng.Each(context.Background(), q, func(_ string, rec *flow.Record) error {
		s := byVer[rec.Version]
		if s == nil {
			s = &seen{min: rec.Start, max: rec.Start}
			byVer[rec.Version] = s
		}
		s.n++
		s.min, s.max = min(s.min, rec.Start), max(s.max, rec.Start)
		return nil
	})
	if err != nil {
		t.Logf("stored records: %v", err)
	}
	if len(byVer) == 0 {
		t.Logf("stored records: none at any time")
	}
	for v, s := range byVer {
		t.Logf("stored records v%d: %d, starts %s to %s (now %s)", v, s.n, time.UnixMilli(s.min).UTC().Format(time.RFC3339),
			time.UnixMilli(s.max).UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
	}
	if capture == nil {
		return
	}
	host := "127.0.0.1"
	if exporter.Is6() && !exporter.Is4In6() {
		host = "::1"
	}
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Logf("capture: %v", err)
		return
	}
	defer pc.Close()
	cmd := capture(pc.LocalAddr().String())
	out := &bytes.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Logf("capture: %v", err)
		return
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
		if out.Len() > 0 {
			t.Logf("capture run's output:\n%s", out.Bytes())
		}
	}()
	buf := make([]byte, 65536)
	var lens []int
	for len(lens) < 50 {
		pc.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		if len(lens) == 0 {
			t.Logf("first datagram (%d bytes), sets %s:\n%s", n, flowSets(buf[:n]), hex.Dump(buf[:min(n, 1500)]))
		}
		lens = append(lens, n)
	}
	t.Logf("capture: %d datagrams, lengths %v", len(lens), lens)
}

// flowSets lists a v9 or IPFIX message's header and sets, for flowDiag.
func flowSets(b []byte) string {
	if len(b) < 4 {
		return "(short)"
	}
	be := binary.BigEndian
	v, off := be.Uint16(b), 0
	var hdr string
	switch {
	case v == 9 && len(b) >= 20:
		hdr, off = fmt.Sprintf("v9 count %d uptime %d export %d seq %d source %d", be.Uint16(b[2:]), be.Uint32(b[4:]), be.Uint32(b[8:]),
			be.Uint32(b[12:]), be.Uint32(b[16:])), 20
	case v == 10 && len(b) >= 16:
		hdr, off = fmt.Sprintf("IPFIX length %d export %d seq %d domain %d", be.Uint16(b[2:]), be.Uint32(b[4:]), be.Uint32(b[8:]),
			be.Uint32(b[12:])), 16
	default:
		return fmt.Sprintf("version %d", v)
	}
	var sets []string
	for b = b[off:]; len(b) >= 4; {
		id, l := be.Uint16(b), int(be.Uint16(b[2:]))
		sets = append(sets, fmt.Sprintf("%d/%d", id, l))
		if l < 4 || l > len(b) {
			sets = append(sets, fmt.Sprintf("(bad length, %d left)", len(b)))
			break
		}
		b = b[l:]
	}
	return hdr + "; id/length " + strings.Join(sets, " ")
}
