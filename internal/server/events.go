package server

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/datatype"
	"github.com/gmccollu/woodshed/internal/index"
	"github.com/gmccollu/woodshed/internal/search"
)

// Events v2: the schema, summaries and saved searches (docs/api.md), on top
// of internal/search and the index.

func (b *backend) SearchSchema(ctx context.Context) ([]api.SearchType, error) {
	var out []api.SearchType
	for _, t := range search.Schema() {
		at := api.SearchType{Type: t.Type, Label: t.Label, Default: t.Default}
		for _, f := range t.Fields {
			af := api.SearchField{Key: f.Key, Label: f.Label, Param: f.Param, ExcludeParam: f.ExcludeParam}
			for _, d := range f.Domain {
				af.Domain = append(af.Domain, api.DomainValue{Value: d.Value, Label: d.Label})
			}
			at.Fields = append(at.Fields, af)
		}
		out = append(out, at)
	}
	return out, nil
}

func (b *backend) Summary(ctx context.Context, r api.SummaryRequest) (api.SummaryPage, error) {
	if r.Type == datatype.Flow {
		return b.flowSummary(ctx, r)
	}
	q := search.SummaryQuery{
		Filter:  searchFilter(r.SearchRequest),
		Devices: r.Devices, Group: r.Group, Ungrouped: r.Ungrouped, ExcludeDevices: r.ExcludeDevices,
		Fields: r.Fields, Top: r.Top, NoHistogram: !r.Histogram, Bucket: time.Duration(r.Bucket) * time.Second,
		Budget: time.Duration(r.BudgetMS) * time.Millisecond, Cursor: r.Cursor,
	}
	s, err := b.search.Summary(ctx, q)
	if err != nil {
		return api.SummaryPage{}, requestError(err)
	}
	typ := r.Type
	if typ == "" {
		typ = search.TypeSyslog
	}
	out := api.SummaryPage{Type: typ, From: s.From, To: s.To, Matched: s.Matched, CountedFrom: s.CountedFrom,
		NextCursor: s.NextCursor, Partial: s.Partial, ScannedBytes: s.ScannedBytes, ScannedFiles: s.ScannedFiles,
		ElapsedMS: s.Elapsed.Milliseconds()}
	if h := s.Histogram; h != nil {
		ah := &api.SummaryHistogram{BucketSeconds: h.BucketSeconds, Source: h.Source}
		for _, bk := range h.Buckets {
			ah.Buckets = append(ah.Buckets, api.SummaryBucket{Start: bk.Start, Count: bk.Count, Approx: bk.Approx})
		}
		out.Histogram = ah
	}
	for _, f := range s.Fields {
		af := api.SummaryField{Key: f.Key, Label: f.Label, Other: f.Other, None: f.None, Distinct: f.Distinct, DistinctCapped: f.DistinctCapped}
		for _, v := range f.Values {
			af.Values = append(af.Values, api.SummaryValue{Value: v.Value, Label: v.Label, Count: v.Count, Filterable: v.Filterable})
		}
		out.Fields = append(out.Fields, af)
	}
	return out, nil
}

// savedFromIndex turns a stored row into the API form, with missing_devices
// and missing_group worked out against the devices now.
func (b *backend) savedFromIndex(row index.SavedSearch, devs []index.Device) (api.SavedSearch, error) {
	out := api.SavedSearch{ID: row.ID, Name: row.Name, Type: row.Type, Created: row.Created, Updated: row.Updated, Version: row.Version}
	if err := json.Unmarshal([]byte(row.Query), &out.Query); err != nil {
		return api.SavedSearch{}, err
	}
	known := map[string]bool{}
	inGroup := false
	for _, d := range devs {
		known[d.ID] = true
		if out.Query.Group != "" && d.Group == out.Query.Group && !d.Hidden {
			inGroup = true
		}
	}
	for _, id := range out.Query.Devices {
		if !known[id] {
			out.MissingDevices = append(out.MissingDevices, id)
		}
	}
	out.MissingGroup = out.Query.Group != "" && !inGroup
	return out, nil
}

func (b *backend) savedRows(ctx context.Context) ([]index.Device, error) {
	return b.idx.ListDevices(ctx)
}

func (b *backend) SavedSearches(ctx context.Context, typ string) ([]api.SavedSearch, error) {
	rows, err := b.idx.SavedSearches(ctx, typ)
	if err != nil {
		return nil, err
	}
	devs, err := b.savedRows(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]api.SavedSearch, 0, len(rows))
	for _, row := range rows {
		s, err := b.savedFromIndex(row, devs)
		if err != nil {
			b.log.Warn("server: skipping an unreadable saved search", "id", row.ID, "err", err)
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

func (b *backend) SavedSearch(ctx context.Context, id string) (api.SavedSearch, error) {
	row, err := b.idx.SavedSearch(ctx, id)
	if errors.Is(err, index.ErrNotFound) {
		return api.SavedSearch{}, api.ErrNotFound
	}
	if err != nil {
		return api.SavedSearch{}, err
	}
	devs, err := b.savedRows(ctx)
	if err != nil {
		return api.SavedSearch{}, err
	}
	return b.savedFromIndex(row, devs)
}

// checkSaved validates a saved query like /api/search: the text and exclude
// (regular expression or terms) each against its own key.
func (b *backend) checkSaved(in api.SavedSearchInput) error {
	f := searchFilter(in.Query.FilterOf(in.Type))
	errs := map[string]string{}
	if err := b.search.CheckFilter(search.Filter{Q: f.Q, Regex: f.Regex, Terms: f.Terms, Case: f.Case, From: f.From, To: f.To}); err != nil {
		var qe *search.QueryError
		if !errors.As(err, &qe) {
			return err
		}
		errs["query.q"] = qe.Msg
	}
	if f.Exclude != "" {
		if err := b.search.CheckFilter(search.Filter{Exclude: f.Exclude, Regex: f.Regex, Terms: f.Terms, Case: f.Case}); err != nil {
			var qe *search.QueryError
			if !errors.As(err, &qe) {
				return err
			}
			if m, ok := cutPrefix(qe.Msg, "exclude: "); ok {
				errs["query.exclude"] = m
			} else {
				errs["query.exclude"] = qe.Msg
			}
		}
	}
	if len(errs) > 0 {
		return &api.ValidationError{Fields: errs}
	}
	return nil
}

func cutPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return s, false
}

func savedErr(err error, name string) error {
	switch {
	case errors.Is(err, index.ErrSavedLimit):
		return api.ErrSavedSearchLimit
	case errors.Is(err, index.ErrNameTaken):
		return &api.NameTakenError{Name: name}
	case errors.Is(err, index.ErrSavedChanged):
		return api.ErrSavedSearchChanged
	case errors.Is(err, index.ErrNotFound):
		return api.ErrNotFound
	}
	return err
}

func (b *backend) storeSaved(ctx context.Context, in api.SavedSearchInput, save func(index.SavedSearch) (index.SavedSearch, error)) (api.SavedSearch, error) {
	if err := b.checkSaved(in); err != nil {
		return api.SavedSearch{}, err
	}
	q, err := json.Marshal(in.Query)
	if err != nil {
		return api.SavedSearch{}, err
	}
	row, err := save(index.SavedSearch{Name: in.Name, Type: in.Type, Query: string(q)})
	if err != nil {
		return api.SavedSearch{}, savedErr(err, in.Name)
	}
	devs, err := b.savedRows(ctx)
	if err != nil {
		return api.SavedSearch{}, err
	}
	return b.savedFromIndex(row, devs)
}

func (b *backend) CreateSavedSearch(ctx context.Context, in api.SavedSearchInput) (api.SavedSearch, error) {
	return b.storeSaved(ctx, in, func(s index.SavedSearch) (index.SavedSearch, error) {
		return b.idx.CreateSavedSearch(ctx, s, b.now())
	})
}

func (b *backend) UpdateSavedSearch(ctx context.Context, id string, in api.SavedSearchInput, ifVersion int64) (api.SavedSearch, error) {
	return b.storeSaved(ctx, in, func(s index.SavedSearch) (index.SavedSearch, error) {
		s.ID = id
		return b.idx.UpdateSavedSearch(ctx, s, ifVersion, b.now())
	})
}

func (b *backend) DeleteSavedSearch(ctx context.Context, id string) error {
	return savedErr(b.idx.DeleteSavedSearch(ctx, id), "")
}
