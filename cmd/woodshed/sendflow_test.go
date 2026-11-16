package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/flow"
	"github.com/gmccollu/woodshed/internal/loadgen"
)

func TestFlowSendProto(t *testing.T) {
	for args, want := range map[string]string{
		"--proto ipfix --count 3": "ipfix", "--proto=Flow-V9": "flow-v9", "-proto flow-v5": "flow-v5",
		"--proto udp": "", "--count 3": "", "-- --proto ipfix": "",
	} {
		if got := flowSendProto(strings.Fields(args)); got != want {
			t.Errorf("%q: %q, want %q", args, got, want)
		}
	}
}

// TestSendFlowCommand sends with `woodshed send --proto flow-v9 --events` to
// the test's own socket, and checks the log against what arrived.
func TestSendFlowCommand(t *testing.T) {
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.LocalAddr().(*net.UDPAddr).Port
	logPath := filepath.Join(t.TempDir(), "sent.ndjson")
	const n = 150
	type pkt struct {
		b    []byte
		from netip.AddrPort
	}
	got := make(chan pkt, 256)
	go func() {
		buf := make([]byte, 65536)
		for {
			k, from, err := ln.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			got <- pkt{append([]byte(nil), buf[:k]...), from}
		}
	}()
	var out, errb bytes.Buffer
	code := cmdSend([]string{"--proto", "flow-v9", "--port", strconv.Itoa(port), "--count", strconv.Itoa(n), "--events",
		"--rate", "3000", "--run", "0badcafe", "--log", logPath}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "Sent 150 FLOW-V9 records") || !strings.Contains(out.String(), "run 0badcafe") {
		t.Errorf("output %q", out.String())
	}
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	logged := map[uint64]flowLogLine{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var l flowLogLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		logged[l.Seq] = l
	}
	if len(logged) != n {
		t.Fatalf("%d log lines", len(logged))
	}
	c := flow.NewCollector(flow.Options{RuleIDIEs: []flow.IEKey{loadgen.RuleIE(loadgen.ProtoFlowV9)}})
	seen := 0
	for seen < n {
		select {
		case p := <-got:
			c.Decode(flow.Packet{Data: p.b, From: p.from, Received: time.Now()}, func(r *flow.Record) {
				run, seq, ok := loadgen.FlowSeq(r)
				l, in := logged[seq]
				if !ok || run != "0badcafe" || !in || l.Src != r.Src.String() || l.FwEvent != flow.FwEventName(r.FwEvent) ||
					l.RuleID != r.RuleID || l.SumBytes != r.SumBytes() {
					t.Fatalf("record %d doesn't match its log line %+v: %+v", seq, l, r)
				}
				seen++
			}, func(rs *flow.RawSet) { t.Fatalf("raw %+v", rs) })
		case <-time.After(10 * time.Second):
			t.Fatalf("%d of %d arrived", seen, n)
		}
	}
	// Usage errors exit 2.
	if code := cmdSend([]string{"--proto", "flow-v5", "--events"}, &out, &errb); code != 2 {
		t.Errorf("--events with v5: exit %d", code)
	}
}
