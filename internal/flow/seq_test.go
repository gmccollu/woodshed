package flow

import (
	"testing"
	"time"
)

// seqStream numbers messages with the given data and options record counts
// under a convention, from first.
func seqStream(timing, opts int, first uint32, data, optRecs []uint32) []seqMsg {
	out := make([]seqMsg, len(data))
	n := first
	for i := range data {
		m := seqMsg{data: data[i], opts: optRecs[i], known: true}
		if timing == seqAfter {
			n += m.count(opts)
			m.seq = n
		} else {
			m.seq = n
			n += m.count(opts)
		}
		out[i] = m
	}
	return out
}

// seqRun feeds messages to a learning state, a second apart, and returns
// the gaps, the records they stand for and the duplicates.
func seqRun(s *seqState, msgs []seqMsg) (gaps, lost, dups int64) {
	for i, m := range msgs {
		gap, dup := s.checkMsg(m, t0.Add(time.Duration(i)*time.Second).UnixMilli())
		switch {
		case dup:
			dups++
		case gap > 0:
			gaps++
			lost += gap
		}
	}
	return
}

// Varying message sizes (so the conventions differ) with an options record
// every fifth message.
func seqCounts(n int) (data, opts []uint32) {
	for i := range n {
		data = append(data, uint32(18+(i*7)%6))
		o := uint32(0)
		if i%5 == 0 {
			o = 1
		}
		opts = append(opts, o)
	}
	return
}

// Each convention is learned from the stream, and a gap is counted only
// for a real loss (lab, 2.0.0-rc1: an exporter numbering messages after
// their own records got a false gap per multi-message export).
func TestSeqConventions(t *testing.T) {
	data, opts := seqCounts(40)
	for _, c := range []struct {
		name         string
		timing, opts int
		mode         string
	}{
		{"rfc, options counted", seqRFC, seqOptsCounted, "rfc"},
		{"rfc, options not counted", seqRFC, seqOptsNot, "rfc"},
		{"after, options counted", seqAfter, seqOptsCounted, "after"},
		{"after, options not counted", seqAfter, seqOptsNot, "after"},
	} {
		msgs := seqStream(c.timing, c.opts, 0, data, opts)
		learner := func() *seqState { return &seqState{learn: true} }

		// No loss: no gap, and the convention is learned.
		s := learner()
		if gaps, _, dups := seqRun(s, msgs); gaps != 0 || dups != 0 {
			t.Errorf("%s: %d gaps, %d duplicates with no loss", c.name, gaps, dups)
		}
		if s.mode() != c.mode || s.opts != c.opts {
			t.Errorf("%s: learned %q options %d", c.name, s.mode(), s.opts)
		}

		// A message dropped after the convention is decided: one gap, its records.
		s = learner()
		lostMsg := msgs[20]
		drop := append(append([]seqMsg{}, msgs[:20]...), msgs[21:]...)
		if gaps, lost, _ := seqRun(s, drop); gaps != 1 || lost != int64(lostMsg.count(c.opts)) {
			t.Errorf("%s: dropped one: %d gaps, %d lost, want 1, %d", c.name, gaps, lost, lostMsg.count(c.opts))
		}
		// And one dropped while it's still learning (the third message).
		s = learner()
		drop = append(append([]seqMsg{}, msgs[:2]...), msgs[3:]...)
		if gaps, lost, _ := seqRun(s, drop); gaps != 1 || lost < int64(msgs[2].data)-6 {
			t.Errorf("%s: dropped while learning: %d gaps, %d lost", c.name, gaps, lost)
		}
		if s.mode() != c.mode {
			t.Errorf("%s: dropped while learning, learned %q", c.name, s.mode())
		}

		// Two messages swapped: the early one is a gap of the late one's
		// records (as before), the late one is ignored, and nothing after.
		s = learner()
		swap := append([]seqMsg{}, msgs...)
		swap[25], swap[26] = swap[26], swap[25]
		if gaps, lost, _ := seqRun(s, swap); gaps != 1 || lost != int64(msgs[25].count(c.opts)) || s.mode() != c.mode {
			t.Errorf("%s: swapped: %d gaps, %d lost, mode %q", c.name, gaps, lost, s.mode())
		}

		// An exporter restart: the numbers start again (from 0, under 100,000
		// back), no gap, and later losses still count.
		s = learner()
		again := seqStream(c.timing, c.opts, 0, data[:15], opts[:15])
		restart := append(append(append([]seqMsg{}, msgs[:30]...), again[:8]...), again[9:]...)
		if gaps, lost, _ := seqRun(s, restart); gaps != 1 || lost != int64(again[8].count(c.opts)) || s.mode() != c.mode {
			t.Errorf("%s: restart then a loss: %d gaps, %d lost (want 1, %d), mode %q", c.name, gaps, lost,
				again[8].count(c.opts), s.mode())
		}
	}
}

// v5 and v9 don't learn: a message numbered "after" is a gap there, as
// before; and a restart to low numbers resyncs after a few messages.
func TestSeqFixed(t *testing.T) {
	data, opts := seqCounts(20)
	for i := range opts {
		opts[i] = 0
	}
	s := &seqState{}
	if gaps, _, _ := seqRun(s, seqStream(seqRFC, seqOptsCounted, 1000, data, opts)); gaps != 0 || s.mode() != "" {
		t.Errorf("rfc: %d gaps, mode %q", gaps, s.mode())
	}
	s = &seqState{}
	if gaps, _, _ := seqRun(s, seqStream(seqAfter, seqOptsCounted, 1000, data, opts)); gaps == 0 {
		t.Error("v5/v9 learned a convention")
	}
	s = &seqState{}
	msgs := append(seqStream(seqRFC, seqOptsCounted, 50000, data, opts), seqStream(seqRFC, seqOptsCounted, 0, data, opts)...)
	if gaps, _, _ := seqRun(s, msgs); gaps != 0 {
		t.Errorf("restart to low numbers: %d gaps", gaps)
	}
}

// A message with no records (templates only) carries the next one's number:
// not a duplicate.
func TestSeqEmptyMessage(t *testing.T) {
	s := &seqState{learn: true}
	msgs := []seqMsg{{seq: 0, data: 20, known: true}, {seq: 20, known: true}, {seq: 20, data: 21, known: true}, {seq: 41, data: 20, known: true}}
	if gaps, _, dups := seqRun(s, msgs); gaps != 0 || dups != 0 {
		t.Errorf("%d gaps, %d duplicates", gaps, dups)
	}
}

// The lab's capture, rebuilt (2.0.0-rc1): an IPFIX exporter numbers each
// message after counting its own data records, not its options records:
// 21 data + 1 options carried 21, then 22, 21 and 20 data records carried
// 43, 64 and 84. That's no loss; the RFC check called 64 reordered and 84 a
// gap of 19. Then a real loss still counts, and /api/flows shows the mode.
func TestSeqAfterCapture(t *testing.T) {
	c := NewCollector(Options{})
	var s sink
	b := NewBuilder(IPFIX)
	rec := func(i int) []byte { return Values{}.Addr(ip("10.0.0.1")).U32(uint32(i)) }
	fields := []TemplateField{{ID: ieSrcV4, Length: 4}, {ID: ieOctetDelta, Length: 4}}
	msg := func(seq uint32, n int, first bool) []byte {
		if first {
			b.OptionsTemplate(300, 1, []TemplateField{{ID: ieInIf, Length: 4}, {ID: ieIfName, Length: Varlen}})
			b.Data(300, Values{}.U32(1).Var([]byte("eth0")))
			b.Template(256, fields)
		}
		for i := range n {
			b.Data(256, rec(i))
		}
		return b.Message(Header{ExportTime: uint32(t0.Unix()), Seq: seq, Domain: 0})
	}
	at := t0
	send := func(seq uint32, n int, first bool) {
		at = at.Add(time.Second)
		s.decode(c, msg(seq, n, first), exp1, at)
	}
	send(21, 21, true)
	send(43, 22, false)
	send(64, 21, false)
	send(84, 20, false)
	st := stats(t, c, exp1.Addr())
	if st.Counts.SequenceGaps != 0 || st.Counts.Duplicates != 0 || st.Counts.Records != 84 {
		t.Fatalf("capture: %+v", st.Counts)
	}
	send(107, 23, false) // the third telling message: decided
	if st = stats(t, c, exp1.Addr()); len(st.Domains) != 1 || st.Domains[0].SeqMode != "after" || st.Counts.SequenceGaps != 0 {
		t.Fatalf("decided: %+v %+v", st.Domains, st.Counts)
	}
	// A message of 19 records lost, then 22: one gap of 19.
	send(148, 22, false)
	if st = stats(t, c, exp1.Addr()); st.Counts.SequenceGaps != 1 || st.Counts.LostEstimate != 19 {
		t.Fatalf("loss: %+v", st.Counts)
	}
}
