package search

import (
	"testing"
	"time"
)

// BenchmarkSearch pages through the big fixture (60,000 visible lines in plain and
// compressed files over two days) with typical queries, so a change to the
// per-line checks shows up as ns/op. Run it with -benchtime=Nx for stable
// numbers; building the fixture takes a few seconds and isn't timed.
func BenchmarkSearch(b *testing.B) {
	f := sharedFixture(b, bigShape)
	all := Filter{From: f.day0, To: f.day0.Add(48 * time.Hour)}
	with := func(fn func(q *Query)) Query {
		q := Query{Filter: all, Limit: MaxLimit}
		fn(&q)
		return q
	}
	cases := []struct {
		name string
		q    Query
		full bool // page through everything; otherwise the first page only
	}{
		{"browse_first_page", Query{Filter: all, Limit: DefaultLimit}, false},
		{"browse_all", with(func(q *Query) {}), true},
		{"text_all", with(func(q *Query) { q.Q = "seq=00" }), true},
		{"text_rare", with(func(q *Query) { q.Q = "seq=0012" }), true},
		{"regex_all", with(func(q *Query) { q.Q = `seq=\d+5$`; q.Regex = true }), true},
		{"severity_all", with(func(q *Query) { q.Severities = sevs(3, 4) }), true},
		{"app_all", with(func(q *Query) { q.Apps = []string{"%FW-*"} }), true},
		{"host_all", with(func(q *Query) { q.Hosts = []string{"web-01"} }), true},
		{"exclude_all", with(func(q *Query) { q.Exclude = "conn opened" }), true},
		{"text_app_all", with(func(q *Query) { q.Q = "seq=00"; q.Apps = []string{"sshd"} }), true},
	}
	// Summaries (the field panel and histogram), each to the end of the range.
	sums := []struct {
		name string
		q    SummaryQuery
	}{
		{"summary_all", SummaryQuery{Filter: all}},
		{"summary_text", SummaryQuery{Filter: Filter{From: all.From, To: all.To, Q: "seq=00"}}},
		{"summary_app", SummaryQuery{Filter: Filter{From: all.From, To: all.To, Apps: []string{"%FW-*"}}}},
		{"histogram_index", SummaryQuery{Filter: all, Fields: []string{}}},
		{"histogram_scan", SummaryQuery{Filter: Filter{From: all.From, To: all.To, Q: "seq=00"}, Fields: []string{}}},
	}
	for _, c := range sums {
		b.Run(c.name, func(b *testing.B) {
			var n int64
			for b.Loop() {
				q := c.q
				for {
					s, err := f.eng.Summary(bg, q)
					if err != nil {
						b.Fatal(err)
					}
					n = s.Matched
					if s.NextCursor == "" {
						break
					}
					q.Cursor = s.NextCursor
				}
			}
			b.ReportMetric(float64(n), "matched")
		})
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			var n int
			for b.Loop() {
				if c.full {
					res, _ := f.all(c.q)
					n = len(res)
					continue
				}
				p, err := f.eng.Search(bg, c.q)
				if err != nil {
					b.Fatal(err)
				}
				n = len(p.Results)
			}
			b.ReportMetric(float64(n), "results")
		})
	}
}
