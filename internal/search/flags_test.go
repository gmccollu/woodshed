package search

import (
	"testing"
	"time"

	"github.com/gmccollu/woodshed/internal/model"
	"github.com/gmccollu/woodshed/internal/store/logfile"
)

// A stored line's marker (2.0) reaches the result as Flags, isn't part of Raw,
// and isn't matched by text queries.
func TestSearchFlags(t *testing.T) {
	f := newWritableFixture(t, 1, 10)
	a := f.devs[0]
	at := f.day0.Add(25 * time.Hour) // after the fixture's own lines
	for i, m := range []model.Message{
		{Raw: []byte("<13>marked short"), Incomplete: true, FrameArrived: 16, FrameLength: 50},
		{Raw: []byte("<13>marked whole")},
		{Raw: []byte("<13>marked cut"), Truncated: true},
	} {
		m.Sender, m.Received = a, at.Add(time.Duration(i)*time.Millisecond)
		if err := f.st.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	f.flush()
	q := Query{Filter: Filter{Q: "marked", From: at, To: at.Add(time.Second)}, Asc: true}
	got, _ := f.all(q)
	want := []struct {
		raw string
		fl  logfile.Flags
	}{
		{"<13>marked short", logfile.Flags{Incomplete: true, Arrived: 16, Length: 50}},
		{"<13>marked whole", logfile.Flags{}},
		{"<13>marked cut", logfile.Flags{Truncated: true}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d results, want %d", len(got), len(want))
	}
	for i, w := range want {
		if string(got[i].Raw) != w.raw || got[i].Flags != w.fl || got[i].Severity != 5 {
			t.Errorf("%d: %q %+v sev %d, want %q %+v", i, got[i].Raw, got[i].Flags, got[i].Severity, w.raw, w.fl)
		}
	}
	for _, text := range []string{"incomplete", `\#`, "truncated", "50"} {
		q.Q = text
		if got, _ := f.all(q); len(got) != 0 {
			t.Errorf("%q matched the marker: %q", text, got[0].Raw)
		}
	}
	q.Q, q.Regex = `short$`, true
	if got, _ := f.all(q); len(got) != 1 {
		t.Errorf("an anchored regex sees the marker: %d results", len(got))
	}
}
