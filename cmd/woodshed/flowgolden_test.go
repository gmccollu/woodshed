package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/flowquery"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/store"
)

// The flow listing's bytes didn't change when it got faster (SPEC §13.6):
// `woodshed search --type flow` (CSV rows, --json, --count, both orders,
// filters, --limit) and the bundle's flows.csv over a fixed store, as
// SHA-256s of what the listing gave before (Search's pages, encoding/json
// and encoding/csv; 2.0 at 28436d8), and /api/search's flow pages the same. Records overlap in flow time across
// blocks, segments and exporters, and carry every kind of column, extras and
// cells that need CSV quoting.

// writeGoldenFlows stores 3 exporters' 6,000 records each, received 10 ms
// apart from 08:59:30 (so across an hour's segments), each ending up to 5 s
// before it was received.
func writeGoldenFlows(t *testing.T, dir string) {
	t.Helper()
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 10, 8, 59, 30, 0, time.UTC)
	now := at
	st, err := store.Open(store.Options{DataDir: dir, Index: idx, Manual: true, Clock: func() time.Time { return now },
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), DiskUsage: func(string) (uint64, uint64, error) { return 1 << 40, 1 << 41, nil }})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewPCG(20, 26))
	addr := func() netip.Addr {
		if rng.IntN(5) == 0 {
			return netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 15: byte(rng.IntN(256))})
		}
		return netip.AddrFrom4([4]byte{10, 20, byte(rng.IntN(4)), byte(rng.IntN(256))})
	}
	names := []string{"Gi0/1", "outside", "dmz,1", `in"side`, " lead", "ünï"}
	exps := []netip.Addr{netip.MustParseAddr("192.0.2.71"), netip.MustParseAddr("192.0.2.72"), netip.MustParseAddr("2001:db8::73")}
	for i := 0; i < 6000; i++ {
		now = at.Add(time.Duration(i) * 10 * time.Millisecond)
		for d, exp := range exps {
			ms := now.UnixMilli()
			end := ms - rng.Int64N(5000)
			r := &flow.Record{Has: flow.HasStart | flow.HasEnd | flow.HasSrc | flow.HasDst | flow.HasSrcPort | flow.HasDstPort | flow.HasProto |
				flow.HasBytes | flow.HasPackets, Received: ms, Start: end - rng.Int64N(60000), End: end, Src: addr(), Dst: addr(),
				SrcPort: uint16(1024 + rng.IntN(60000)), DstPort: []uint16{443, 53, 22, 80}[rng.IntN(4)], Proto: []uint8{6, 17, 1}[rng.IntN(3)],
				Bytes: uint64(rng.IntN(1 << 30)), Packets: uint64(1 + rng.IntN(1000)), Sampling: []uint32{1, 0, 1000}[d], Domain: uint32(d + 1),
				Version: flow.IPFIX, TemplateID: 256}
			if rng.IntN(2) == 0 {
				r.Has |= flow.HasTCPFlags | flow.HasInIf | flow.HasOutIf | flow.HasInIfName | flow.HasOutIfName
				r.TCPFlags, r.InIf, r.OutIf = uint16(rng.IntN(512)), uint32(rng.IntN(9)), uint32(rng.IntN(9))
				r.InIfName, r.OutIfName = names[rng.IntN(len(names))], names[rng.IntN(len(names))]
			}
			if rng.IntN(4) == 0 {
				r.Has |= flow.HasFwEvent | flow.HasNatEvent | flow.HasPostNATSrc | flow.HasPostNATSrcPort | flow.HasRuleID | flow.HasEventTime
				r.FwEvent, r.NatEvent, r.PostNATSrc, r.PostNATSrcPort = uint8(1+rng.IntN(5)), uint8(rng.IntN(20)), addr(), uint16(rng.IntN(65536))
				r.RuleID, r.EventTime = names[rng.IntN(len(names))], end
				if rng.IntN(3) == 0 {
					r.Has &^= flow.HasEnd | flow.HasStart // an event: its time only
				}
			}
			if rng.IntN(6) == 0 {
				r.Has |= flow.HasSrcAS | flow.HasDstAS | flow.HasNextHop | flow.HasToS | flow.HasInitiatorBytes | flow.HasResponderBytes
				r.SrcAS, r.DstAS, r.NextHop, r.ToS = uint32(rng.IntN(70000)), uint32(rng.IntN(70000)), addr(), uint8(rng.IntN(256))
				r.InitiatorBytes, r.ResponderBytes = uint64(rng.IntN(1<<20)), uint64(rng.IntN(1<<20))
				r.Extras = []flow.Extra{{PEN: 9, ID: uint16(rng.IntN(40)), Value: []byte{byte(i), byte(d), 7}}}
			}
			if err := st.WriteFlows(exp, store.FlowBatch{Received: now, Records: []*flow.Record{r}}); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	idx.Close()
}

// goldenFlowListings are the cases' SHA-256s (and line counts) before.
var goldenFlowListings = map[string]string{
	"api-pages-137-asc-false":             "ebbf90cd7b68fa2f2a816ff441a44b97c8ff9fb2715a0ed94056f8d31fc34627 132",
	"api-pages-500-asc-false":             "828278ecc8a034443fed73a2384618d969ac47596cb18bbe9ec36824000365c4 37",
	"api-pages-5000-asc-true":             "5930aa2a3508b1bcfdf7f8989e58558b0900ad7e25a98a6da42053ea8fd4bdbf 4",
	"bundle flows/192.0.2.71/flows.csv":   "2ab0104ffc7f5822c2676882e2e471536e0e188a5b250a44f0f77e3ca162e37c 6001",
	"bundle flows/192.0.2.72/flows.csv":   "d8605e88639223bc0920924d5231cf6f6d48ad09c2df089344ac2c7d559cda7d 6001",
	"bundle flows/2001_db8__73/flows.csv": "10129f61ad43096aedb9e9342278898f771d025d8bc935bb6783bd6be7cc8147 6001",
	"count":                               "0eca2fe3afb4bddd95a5bd335ab7ba061f41f14c792e94a0064e99bb218016fd 1",
	"csv":                                 "455466da4d30a2470cc86e9cb5cc94b983c4fe54d58781385c6eeb3af6b1dfe0 18001",
	"csv-desc":                            "a1ac41f9e188c5d6d2bcc6a538618c15b59fb46090fd3010b0db8683624a5c0b 18001",
	"csv-filtered":                        "df9ac3d2de2e8da9d3f80e6d8df9fd694fa57c7eb981350523b3112d45dbfc0c 1807",
	"csv-one-device":                      "e458b673f4ae2cde1b13e18a8ebd93ce130489d912e04bf20c4db1d9538c9ad7 6001",
	"json":                                "aa3fc8d3d1b00adb60e43fe60e7cf2f052a8a7f59b72287fa3ec3c2e994be6aa 18000",
	"json-desc":                           "237bafb3d5aeff7f021de1c6341deeee5a67131738279fc42b574e088ad703ca 18000",
	"json-filtered":                       "8e63487db7048291ffe23b325cd3c5f61d097a1540f9864655904e4eed43234d 2365",
	"json-limit":                          "041468ea01fc1012ee717d4c5d75fa17b1df9616e0b69b197829659640e1f571 7777",
	"json-window":                         "4ae19b27324265d6846b911191230d5637398a81db2a5794675b9453b50233aa 8519",
}

func TestFlowListingGolden(t *testing.T) {
	dir := t.TempDir()
	writeGoldenFlows(t, dir)
	cases := map[string][]string{
		"csv":            {},
		"csv-desc":       {"--order", "desc"},
		"json":           {"--json"},
		"json-desc":      {"--json", "--order", "desc"},
		"count":          {"--count"},
		"json-filtered":  {"--json", "--src", "10.20.1.0/24", "--proto", "tcp,udp"},
		"csv-filtered":   {"--order", "desc", "--field", "fw_event=denied,created"},
		"json-limit":     {"--json", "--limit", "7777", "--order", "desc"},
		"json-window":    {"--json", "--from", "2026-11-10T08:59:58Z", "--to", "2026-11-10T09:00:20Z"},
		"csv-one-device": {"--devices", "2001:db8::73", "--order", "desc"},
	}
	got := map[string]string{}
	for name, args := range cases {
		base := []string{"--type", "flow", "--last", "24h"}
		if strings.HasSuffix(name, "window") {
			base = base[:2]
		}
		code, out, errOut := runSearch(t, dir, append(base, args...)...)
		if code != 0 {
			t.Fatalf("%s: exit %d: %s", name, code, errOut)
		}
		got[name] = fmt.Sprintf("%x %d", sha256.Sum256([]byte(out)), strings.Count(out, "\n"))
	}
	// /api/search's pages, encoded as the server does (elapsed_ms left 0).
	idx, err := index.Open(filepath.Join(dir, index.FileName))
	if err != nil {
		t.Fatal(err)
	}
	fe := flowEngine(dir, idx, nil, nil)
	for _, pc := range []struct {
		limit int
		asc   bool
	}{{500, false}, {5000, true}, {137, false}} {
		q := flowquery.Query{From: fxNow.Add(-24 * time.Hour), To: fxNow}
		sum, n, cursor := sha256.New(), 0, ""
		for {
			res, err := fe.Search(context.Background(), q, pc.limit, pc.asc, cursor, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			page := api.SearchPage{NextCursor: res.Cursor, Partial: res.Partial}
			for i := range res.Hits {
				h := &res.Hits[i]
				rec := h.Record
				page.Results = append(page.Results, api.SearchLine{Received: time.UnixMilli(rec.Received).UTC(), DeviceID: h.DeviceID,
					Type: datatype.Flow, Ref: h.Ref(), Flow: &rec})
			}
			b, err := json.Marshal(page)
			if err != nil {
				t.Fatal(err)
			}
			sum.Write(b)
			n++
			if res.Cursor == "" {
				break
			}
			cursor = res.Cursor
		}
		got[fmt.Sprintf("api-pages-%d-asc-%v", pc.limit, pc.asc)] = fmt.Sprintf("%x %d", sum.Sum(nil), n)
	}
	idx.Close()
	zipPath := filepath.Join(t.TempDir(), "flows.zip")
	searchNow = func() time.Time { return fxNow }
	bundleHostname = func() (string, error) { return "golden", nil }
	t.Cleanup(func() { searchNow, bundleHostname = time.Now, os.Hostname })
	if code, _, errOut := runCLI("bundle", "--data", dir, "--at", "2026-11-10T09:00:00Z", "--before", "1h", "--after", "1h",
		"--types", "flow", "--flow-formats", "csv", "--out", zipPath); code != 0 {
		t.Fatalf("bundle: exit %d: %s", code, errOut)
	}
	files, _ := readZipFile(t, zipPath)
	for name, b := range files {
		if strings.HasSuffix(name, "flows.csv") {
			got["bundle "+name] = fmt.Sprintf("%x %d", sha256.Sum256(b), strings.Count(string(b), "\n"))
		}
	}
	var keys []string
	for k := range got {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if os.Getenv("WOODSHED_PRINT_GOLDEN") != "" {
		for _, k := range keys {
			fmt.Printf("\t%q: %q,\n", k, got[k])
		}
		return
	}
	if len(got) != len(goldenFlowListings) {
		t.Fatalf("%d cases, %d golden", len(got), len(goldenFlowListings))
	}
	for _, k := range keys {
		if got[k] != goldenFlowListings[k] {
			t.Errorf("%s: %s, before %s", k, got[k], goldenFlowListings[k])
		}
	}
}
