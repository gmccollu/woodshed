package server

import (
	"context"
	"errors"
	"time"

	"github.com/gmccollu/woodshed/internal/api"
	"github.com/gmccollu/woodshed/internal/export"
	"github.com/gmccollu/woodshed/internal/hub"
	"github.com/gmccollu/woodshed/internal/search"
)

// Search, context and exports: the api.Backend methods on top of
// internal/search and internal/export.

func toSeveritySet(s api.Severities) hub.SeveritySet {
	if s.None {
		return hub.SeverityNone
	}
	var set hub.SeveritySet
	for _, v := range s.Values {
		set = set.With(v)
	}
	if set == hub.AllSeverities {
		return 0
	}
	return set
}

func fromSeveritySet(set hub.SeveritySet) api.Severities {
	switch set {
	case 0:
		return api.Severities{}
	case hub.SeverityNone:
		return api.Severities{None: true}
	}
	var s api.Severities
	for i := 0; i < 8; i++ {
		if set.Has(i) {
			s.Values = append(s.Values, i)
		}
	}
	if set.Has(api.Unknown) {
		s.Values = append(s.Values, api.Unknown)
	}
	return s
}

// requestError turns the engines' "bad request" errors into the api's.
func requestError(err error) error {
	var qe *search.QueryError
	var re *export.RequestError
	switch {
	case errors.As(err, &qe):
		return &api.RequestError{Msg: qe.Msg}
	case errors.As(err, &re):
		return &api.RequestError{Msg: re.Msg}
	case errors.Is(err, search.ErrNotFound), errors.Is(err, export.ErrNotFound):
		return api.ErrNotFound
	case errors.Is(err, export.ErrNotReady):
		return api.ErrNotReady
	}
	return err
}

func toAPILines(ls []search.Line) []api.SearchLine {
	out := make([]api.SearchLine, len(ls))
	for i, l := range ls {
		out[i] = api.SearchLine{Received: l.Received, DeviceID: l.DeviceID, Severity: l.Severity, Raw: l.Raw, Ref: l.Ref, App: l.App, Host: l.Host}
	}
	return out
}

func toFacilitySet(f api.Facilities) search.FacilitySet {
	if f.None {
		return search.FacilityNone
	}
	var set search.FacilitySet
	for _, v := range f.Values {
		set = set.With(v)
	}
	return set.Normalize()
}

func fromFacilitySet(set search.FacilitySet) api.Facilities {
	switch set {
	case 0:
		return api.Facilities{}
	case search.FacilityNone:
		return api.Facilities{None: true}
	}
	var f api.Facilities
	for i := 0; i < 24; i++ {
		if set.Has(i) {
			f.Values = append(f.Values, i)
		}
	}
	if set.Has(api.Unknown) {
		f.Values = append(f.Values, api.Unknown)
	}
	return f
}

// searchFilter is the engine filter of a request.
func searchFilter(r api.SearchRequest) search.Filter {
	return search.Filter{Q: r.Q, Regex: r.Regex, Terms: r.Terms, Case: r.Case, Severities: toSeveritySet(r.Severities),
		Facilities: toFacilitySet(r.Facilities), From: r.From, To: r.To, Apps: r.App, Hosts: r.Host, ExcludeApps: r.ExcludeApp,
		ExcludeHosts: r.ExcludeHost, Exclude: r.Exclude}
}

// SearchQuery is the engine query of a /api/search request. `woodshed search`
// builds its query through it too, so the command line and the API mean the
// same thing by every filter (SPEC §11.4).
func SearchQuery(r api.SearchRequest) search.Query {
	return search.Query{
		Filter:  searchFilter(r),
		Devices: r.Devices, Group: r.Group, Ungrouped: r.Ungrouped, ExcludeDevices: r.ExcludeDevices, Asc: r.Asc, Limit: r.Limit,
		Cursor: r.Cursor,
	}
}

func (b *backend) Search(ctx context.Context, r api.SearchRequest) (api.SearchPage, error) {
	p, err := b.search.Search(ctx, SearchQuery(r))
	if err != nil {
		return api.SearchPage{}, requestError(err)
	}
	return api.SearchPage{Results: toAPILines(p.Results), NextCursor: p.NextCursor, ScannedBytes: p.ScannedBytes,
		ScannedFiles: p.ScannedFiles, ElapsedMS: p.Elapsed.Milliseconds(), Partial: p.Partial}, nil
}

func (b *backend) Context(ctx context.Context, ref string, before, after int) (api.ContextPage, error) {
	p, err := b.search.Context(ctx, ref, before, after)
	if err != nil {
		return api.ContextPage{}, requestError(err)
	}
	return api.ContextPage{Lines: toAPILines(p.Lines), HitIndex: p.HitIndex, AtStart: p.AtStart, AtEnd: p.AtEnd}, nil
}

func toExportRequest(r api.ExportRequest) export.Request {
	return export.Request{AllDevices: r.AllDevices, Devices: r.Devices, From: r.From, To: r.To, Filters: export.Filters{
		Group: r.Group, Ungrouped: r.Ungrouped, Severities: toSeveritySet(r.Severities), Q: r.Q, Regex: r.Regex, Case: r.Case,
		Apps: r.App, Hosts: r.Host, Exclude: r.Exclude, Terms: r.Terms, Facilities: toFacilitySet(r.Facilities),
		ExcludeDevices: r.ExcludeDevices, ExcludeApps: r.ExcludeApp, ExcludeHosts: r.ExcludeHost}}
}

func toAPIExport(e export.Info) api.ExportInfo {
	return api.ExportInfo{
		ID: e.ID, Created: e.Created, Devices: e.Devices, From: e.From, To: e.To, State: string(e.State),
		Progress: e.Progress, Lines: e.Lines, SizeBytes: e.SizeBytes, Error: e.Error, ReadyAt: e.ReadyAt, ExpiresAt: e.ExpiresAt,
		Filters: api.ExportFilters{Group: e.Filters.Group, Ungrouped: e.Filters.Ungrouped,
			Severities: fromSeveritySet(e.Filters.Severities), Q: e.Filters.Q, Regex: e.Filters.Regex, Case: e.Filters.Case,
			App: e.Filters.Apps, Host: e.Filters.Hosts, Exclude: e.Filters.Exclude,
			Type: "syslog", Syntax: map[bool]string{false: "text", true: "terms"}[e.Filters.Terms],
			Facilities: fromFacilitySet(e.Filters.Facilities), ExcludeDevices: e.Filters.ExcludeDevices,
			ExcludeApp: e.Filters.ExcludeApps, ExcludeHost: e.Filters.ExcludeHosts},
	}
}

func (b *backend) CreateExport(ctx context.Context, r api.ExportRequest) (api.ExportInfo, error) {
	e, err := b.exports.Create(ctx, toExportRequest(r))
	if err != nil {
		return api.ExportInfo{}, requestError(err)
	}
	return toAPIExport(e), nil
}

func (b *backend) EstimateExport(ctx context.Context, r api.ExportRequest) (api.ExportEstimate, error) {
	est, err := b.exports.Estimate(ctx, toExportRequest(r))
	if err != nil {
		return api.ExportEstimate{}, requestError(err)
	}
	return api.ExportEstimate{Lines: est.Lines, Bytes: est.Bytes, Files: est.Files}, nil
}

func (b *backend) Exports(ctx context.Context) ([]api.ExportInfo, error) {
	es := b.exports.List()
	out := make([]api.ExportInfo, len(es))
	for i, e := range es {
		out[i] = toAPIExport(e)
	}
	return out, nil
}

func (b *backend) Export(ctx context.Context, id string) (api.ExportInfo, error) {
	e, err := b.exports.Get(id)
	if err != nil {
		return api.ExportInfo{}, requestError(err)
	}
	return toAPIExport(e), nil
}

func (b *backend) OpenExport(ctx context.Context, id string) (api.ExportDownload, error) {
	f, info, err := b.exports.Download(id)
	if err != nil {
		return api.ExportDownload{}, requestError(err)
	}
	mod := time.Time{}
	if info.ReadyAt != nil {
		mod = *info.ReadyAt
	}
	return api.ExportDownload{File: f, ModTime: mod}, nil
}

func (b *backend) DeleteExport(ctx context.Context, id string) error {
	return requestError(b.exports.Delete(id))
}
