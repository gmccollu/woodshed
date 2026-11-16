package flow

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Options records with fields the collector doesn't interpret are kept raw
// (SPEC §13.1.2), versioned by received time; interpreted-only ones aren't
// duplicated; Metadata carries everything and its version moves on change.
func TestOptionsKeptRaw(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	// Scope observationDomainId; the exporter's address (not interpreted) and
	// the system init time (interpreted).
	b.OptionsTemplate(300, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieExporterV4, Length: 4}, {ID: ieSysInitMs, Length: 8}})
	// An interface name only: interpreted, not kept raw.
	b.OptionsTemplate(301, 1, []TemplateField{{ID: ieInIf, Length: 4}, {ID: ieIfName, Length: 4}})
	// An enterprise-specific options field.
	b.OptionsTemplate(302, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {PEN: 32473, ID: 9, Length: 2}})
	b.Data(300, Values{}.U32(1).Addr(ip("192.0.2.77")).U64(uint64(t0.UnixMilli())))
	b.Data(301, Values{}.U32(3).Bytes([]byte("eth3")))
	b.Data(302, Values{}.U32(1).U16(0xbeef))
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Domain: 1}), exp1, t0)
	_, v0 := c.Metadata(exp1.Addr())
	opts := c.Options(exp1.Addr())
	if len(opts) != 2 || opts[0].TemplateID != 300 || opts[1].TemplateID != 302 {
		t.Fatalf("kept %+v", opts)
	}
	if f := opts[0].Fields; len(f) != 3 || !f[0].Scope || !bytes.Equal(f[1].Value, []byte{192, 0, 2, 77}) {
		t.Fatalf("fields %+v", f)
	}
	if st := stats(t, c, exp1.Addr()); st.OptionsRaw != 2 {
		t.Fatalf("stats options_raw %d", st.OptionsRaw)
	}
	// The same values again only refresh; a change is a new version.
	b.Data(300, Values{}.U32(1).Addr(ip("192.0.2.77")).U64(uint64(t0.UnixMilli())))
	s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 4, Domain: 1}), exp1, t0.Add(time.Minute))
	if opts = c.Options(exp1.Addr()); len(opts) != 2 || !opts[0].Refreshed.Equal(t0.Add(time.Minute)) || !opts[0].Received.Equal(t0) {
		t.Fatalf("refresh %+v", opts[0])
	}
	if _, v := c.Metadata(exp1.Addr()); v != v0 {
		t.Fatalf("a refresh changed the version: %d -> %d", v0, v)
	}
	for i := 0; i < maxOptVersions+2; i++ {
		b.Data(300, Values{}.U32(1).Addr(ip("192.0.2.77")).U64(uint64(t0.UnixMilli()+int64(i)+1)))
		s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: uint32(5 + i), Domain: 1}), exp1, t0.Add(time.Duration(2+i)*time.Minute))
	}
	n300 := 0
	for _, o := range c.Options(exp1.Addr()) {
		if o.TemplateID == 300 {
			n300++
		}
	}
	if n300 != maxOptVersions {
		t.Fatalf("%d versions kept, want %d", n300, maxOptVersions)
	}
	blob, v1 := c.Metadata(exp1.Addr())
	if v1 == v0 {
		t.Fatal("the version didn't move on a change")
	}
	var m map[string]any
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"if_names":[{"domain":1,"if_index":3,"name":"eth3"}]`, `"name":"exporterIPv4Address"`, `"hex":"c000024d"`,
		`"pen":32473`, `"sys_init_ms":`} {
		if !strings.Contains(string(blob), want) {
			t.Errorf("metadata lacks %s:\n%s", want, blob)
		}
	}
	if blob, v := c.Metadata(exp2.Addr()); blob != nil || v != 0 {
		t.Fatal("an unknown exporter has metadata")
	}
}

// The raw options' share stays bounded.
func TestOptionsRawBounded(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	b.OptionsTemplate(300, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {PEN: 32473, ID: 9, Length: Varlen}})
	big := bytes.Repeat([]byte{7}, 3000) // 1,024 keys of this are over the 2 MiB share
	for i := 0; i < 1500; i++ {
		b.Data(300, Values{}.U32(uint32(i)).Var(big))
		s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: uint32(i), Domain: 1}), exp1, t0)
	}
	if c.rawOptBytes > maxRawOptBytes || c.rawOptBytes < maxRawOptBytes-4000 || c.metaBytes > maxMetaBytes {
		t.Fatalf("raw %d meta %d", c.rawOptBytes, c.metaBytes)
	}
	if n := len(c.Options(exp1.Addr())); n == 0 || n > maxOptKeys {
		t.Fatalf("%d kept", n)
	}
}

// PendingOldest is the oldest data still waiting for its template.
func TestPendingOldest(t *testing.T) {
	c := NewCollector(Options{TemplateTimeout: time.Hour})
	var s sink
	data := func(tid uint16, seq uint32) []byte {
		b := NewBuilder(IPFIX)
		b.Data(tid, Values{}.U32(1))
		return b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: seq, Domain: 1})
	}
	if len(c.Stats(t0)) != 0 {
		t.Fatal("stats before any datagram")
	}
	s.decode(c, data(400, 0), exp1, t0)
	s.decode(c, data(401, 1), exp1, t0.Add(5*time.Minute))
	if st := stats(t, c, exp1.Addr()); !st.PendingOldest.Equal(t0) || st.PendingBytes == 0 {
		t.Fatalf("oldest %v bytes %d", st.PendingOldest, st.PendingBytes)
	}
	// Template 400 arrives: its data decodes; the oldest is now 401's.
	tb := NewBuilder(IPFIX)
	tb.Template(400, []TemplateField{{ID: 1, Length: 4}})
	s.decode(c, tb.Message(Header{ExportTime: uint32(t0.Unix()), Seq: 2, Domain: 1}), exp1, t0.Add(6*time.Minute))
	if st := stats(t, c, exp1.Addr()); !st.PendingOldest.Equal(t0.Add(5 * time.Minute)) {
		t.Fatalf("after 400's template: %v", st.PendingOldest)
	}
	// The wait runs out: nothing pending, zero.
	c.SetOptions(time.Minute, nil)
	c.Expire(t0.Add(7*time.Minute), func(*RawSet) {})
	if st := stats(t, c, exp1.Addr()); !st.PendingOldest.IsZero() || st.PendingBytes != 0 {
		t.Fatalf("after expiry: %v %d", st.PendingOldest, st.PendingBytes)
	}
}

// Options, Metadata and Stats are safe beside Decode and Expire (-race).
func TestOptionsConcurrent(t *testing.T) {
	c := NewCollector(Options{TemplateTimeout: time.Minute})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var s sink
		for i := 0; i < 300; i++ {
			b := NewBuilder(IPFIX)
			b.OptionsTemplate(300, 1, []TemplateField{{ID: ieObsDomainID, Length: 4}, {ID: ieExporterV4, Length: 4}})
			b.OptionsTemplate(301, 1, []TemplateField{{ID: ieInIf, Length: 4}, {ID: ieIfName, Length: 4}})
			b.Data(300, Values{}.U32(uint32(i%7)).Addr(ip("192.0.2.77")))
			b.Data(301, Values{}.U32(uint32(i%5)).Bytes([]byte("eth0")))
			b.Data(999, Values{}.U32(1)) // waits for a template
			s.decode(c, b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: uint32(i), Domain: 1}), exp1, t0.Add(time.Duration(i)*time.Second))
			c.Expire(t0.Add(time.Duration(i)*time.Second), func(*RawSet) {})
		}
	}()
	for {
		select {
		case <-done:
			if len(c.Options(exp1.Addr())) == 0 {
				t.Fatal("nothing kept")
			}
			return
		default:
			c.Stats(t0)
			c.Options(exp1.Addr())
			c.Metadata(exp1.Addr())
		}
	}
}
