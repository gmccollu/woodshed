// Package api is Woodshed's HTTP layer: the REST API in docs/api.md, the embedded
// web UI, and the UI's security (localhost mode, LAN mode with a password and
// HTTPS).
//
// The handlers talk to the rest of the service only through the Backend
// interface, so this package doesn't depend on the listeners, the live hub or
// the config file (it uses the config package only for the host-name syntax of
// ui.extra_hostnames and ui.trusted_hosts). All JSON shapes below follow
// docs/api.md field for field.
package api

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Backend is everything the handlers need from the running service. Each method
// names the route it serves. Methods may be called concurrently.
type Backend interface {
	// Status serves GET /api/status.
	Status(ctx context.Context) (Status, error)

	// StorageEstimate serves GET /api/storage/estimate: the retention estimate for
	// a cap the user is typing in Settings. A cap the setting wouldn't accept is a
	// *RequestError.
	StorageEstimate(ctx context.Context, retentionBytes int64) (StorageEstimate, error)
	// Stats serves GET /api/stats.
	Stats(ctx context.Context) (Stats, error)

	// Rejected serves GET /api/rejected: senders refused by the allowlist.
	Rejected(ctx context.Context) ([]RejectedSender, error)

	// Devices returns every device, hidden ones included (for in-process
	// callers; the API pages through QueryDevices).
	Devices(ctx context.Context) ([]Device, error)

	// QueryDevices serves GET /api/devices: one page, filtered and sorted as q
	// says (docs/api.md), with the total matching.
	QueryDevices(ctx context.Context, q DeviceQuery) (DevicePage, error)

	// Groups serves GET /api/groups: every group with its number of
	// non-hidden devices, sorted by name (groups with none may be included;
	// this package leaves them out).
	Groups(ctx context.Context) ([]Group, error)

	// UpdateDevice serves PATCH /api/devices/{id}. Nil fields in p are left
	// alone. It returns the updated device, or an error wrapping ErrNotFound for
	// an unknown id.
	UpdateDevice(ctx context.Context, id string, p DevicePatch) (Device, error)

	// Settings serves GET /api/settings.
	Settings(ctx context.Context) (Settings, error)

	// SaveSettings serves PUT /api/settings. It validates the whole object and,
	// if it's valid, saves and applies it and returns the saved object. If it
	// isn't, it returns a *ValidationError (and saves nothing); its Fields go
	// to the client unchanged as {"errors": {...}}. A change to UI is applied by
	// this package, not the backend: it restarts the HTTP server after the
	// response is sent. A non-empty ifMatch is the ETag (SettingsETag) the
	// client loaded: if the settings in effect have another one, it saves nothing
	// and returns ErrSettingsChanged (checked under the same lock as the save).
	SaveSettings(ctx context.Context, s Settings, ifMatch string) (Settings, error)

	// RetryListeners serves POST /api/listeners/retry: rebind any syslog
	// listener that failed to bind. The client re-reads /api/status afterwards,
	// so a bind that fails again is not an error here.
	RetryListeners(ctx context.Context) error

	// StorageHistory serves GET /api/storage/history, newest first.
	StorageHistory(ctx context.Context) ([]StorageEntry, error)

	// LiveHandler serves GET /api/live (text/event-stream). This package
	// authenticates the request and adds the security headers, then hands it
	// over unchanged, query string included. The handler must return when
	// r.Context() is done: that is how a UI restart ends open streams.
	LiveHandler() http.Handler

	// Search serves GET /api/search: one page. The request is already parsed
	// and checked; what only the backend can check (the regular expression,
	// the cursor, the resolved range) comes back as a *RequestError.
	Search(ctx context.Context, r SearchRequest) (SearchPage, error)

	// SearchSchema serves GET /api/search/schema: the data types and their
	// field-panel fields.
	SearchSchema(ctx context.Context) ([]SearchType, error)

	// Summary serves GET /api/search/summary: one response of a field-panel
	// and histogram summary. What only the backend can check (the query, the
	// bucket, the cursor, an expired summary) is a *RequestError.
	Summary(ctx context.Context, r SummaryRequest) (SummaryPage, error)

	// SavedSearches serves GET /api/saved-searches: every saved search of a
	// type, sorted by name ignoring case, with MissingDevices and MissingGroup
	// worked out now.
	SavedSearches(ctx context.Context, typ string) ([]SavedSearch, error)
	// SavedSearch serves GET /api/saved-searches/{id}: ErrNotFound for an
	// unknown id.
	SavedSearch(ctx context.Context, id string) (SavedSearch, error)
	// CreateSavedSearch serves POST /api/saved-searches. A query /api/search
	// would refuse is a *ValidationError ("query.q", "query.exclude"); a name in
	// use a *NameTakenError; one too many ErrSavedSearchLimit.
	CreateSavedSearch(ctx context.Context, in SavedSearchInput) (SavedSearch, error)
	// UpdateSavedSearch serves PUT /api/saved-searches/{id}. With ifVersion >
	// 0 it saves only if the saved search is still at that Version
	// (ErrSavedSearchChanged). Errors otherwise as for CreateSavedSearch, and
	// ErrNotFound.
	UpdateSavedSearch(ctx context.Context, id string, in SavedSearchInput, ifVersion int64) (SavedSearch, error)
	// DeleteSavedSearch serves DELETE /api/saved-searches/{id}: ErrNotFound
	// for an unknown id.
	DeleteSavedSearch(ctx context.Context, id string) error

	// Context serves GET /api/context: before and after are 0-500. An invalid
	// ref is a *RequestError, a ref whose file is gone ErrNotFound.
	Context(ctx context.Context, ref string, before, after int) (ContextPage, error)

	// CreateExport serves POST /api/exports: it queues an export and returns
	// its entry. A selection with no devices, or a bad regular expression, is a
	// *RequestError.
	CreateExport(ctx context.Context, r ExportRequest) (ExportInfo, error)

	// EstimateExport serves POST /api/exports/estimate: an upper bound from the
	// index alone. Errors as for CreateExport.
	EstimateExport(ctx context.Context, r ExportRequest) (ExportEstimate, error)

	// Exports serves GET /api/exports, newest first.
	Exports(ctx context.Context) ([]ExportInfo, error)

	// Export serves GET /api/exports/{id}: ErrNotFound for an unknown id.
	Export(ctx context.Context, id string) (ExportInfo, error)

	// OpenExport opens a ready export's zip for GET /api/exports/{id}/download:
	// ErrNotFound for an unknown or expired one, ErrNotReady for one that isn't
	// ready. The caller closes the file.
	OpenExport(ctx context.Context, id string) (ExportDownload, error)

	// DeleteExport serves DELETE /api/exports/{id}: it cancels a queued or
	// building export, or deletes a ready one. ErrNotFound for an unknown id.
	DeleteExport(ctx context.Context, id string) error

	// Updates serves GET /api/updates: the update check's state (SPEC §10.2).
	Updates(ctx context.Context) (UpdateInfo, error)

	// SetUpdateCheck serves PUT /api/updates: it writes updates.check ("on" or
	// "off", checked by this package) to the config like a settings save, and
	// returns the new state.
	SetUpdateCheck(ctx context.Context, check string) (UpdateInfo, error)

	// CheckUpdatesNow serves POST /api/updates/check: ErrUpdateCheckOff unless
	// updates.check is "on" (or the build can't check), a *RetryAfterError
	// within a minute of the last one.
	CheckUpdatesNow(ctx context.Context) error

	// DismissUpdate serves POST /api/updates/dismiss: it hides the
	// update_available banner for version, for everyone. A version that isn't
	// one is a *RequestError.
	DismissUpdate(ctx context.Context, version string) error

	// RecordEvent adds one of the HTTP layer's own events to the service event
	// log (the one exported as woodshed-events.log): UI start and bind errors,
	// mode changes, password changes, certificate generation and login
	// lockouts. Errors are logged and otherwise ignored.
	RecordEvent(ctx context.Context, e Event) error

	// The TLS syslog listener (tls.go).
	TLSBackend
}

// ErrNotFound is returned (possibly wrapped) by UpdateDevice, Context and the
// export methods for an unknown id.
var ErrNotFound = errors.New("not found")

// ValidationError is returned by SaveSettings for an invalid object. Fields maps
// a dotted JSON path ("listeners.udp.port", "listeners.allowlist[2]") to a
// human-readable message.
type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string { return "invalid settings" }

// Event is one of the HTTP layer's own events (see Backend.RecordEvent).
type Event struct {
	Level string // "info", "warn" or "error"
	Kind  string // EventKindUI or EventKindAuth
	Text  string
}

// Event kinds and levels used by this package.
const (
	EventKindUI   = "ui"   // the UI server started, failed to bind, changed mode, generated a certificate
	EventKindAuth = "auth" // password set or changed, login lockout

	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// ---- GET /api/status ----

// Status is the body of GET /api/status.
type Status struct {
	Version                 string     `json:"version"`
	Build                   string     `json:"build"`
	OS                      string     `json:"os"`
	DataDir                 string     `json:"data_dir"`
	StartedAt               time.Time  `json:"started_at"`
	FirstMessageAt          *time.Time `json:"first_message_at"` // nil until the first message is received
	UDPRcvbufBytes          int64      `json:"udp_rcvbuf_bytes"`
	UDPRcvbufRequestedBytes int64      `json:"udp_rcvbuf_requested_bytes"`
	ReleasesURL             string     `json:"releases_url"`
	KernelDropsVisible      bool       `json:"kernel_drops_visible"`
	Listeners               []Listener `json:"listeners"`
	HostIPs                 []string   `json:"host_ips"`
	Banners                 []Banner   `json:"banners"`
	// UICertFingerprint is the SHA-256 of the UI's certificate in LAN mode
	// ("AB:CD:…"), "" in localhost mode. Filled by this package.
	UICertFingerprint string `json:"ui_cert_fingerprint"`
}

// Listener is one syslog listener's state.
type Listener struct {
	Proto  string `json:"proto"` // "udp", "tcp" or "tls"
	Addr   string `json:"addr"`
	Port   int    `json:"port"`
	OK     bool   `json:"ok"`
	Error  string `json:"error"`
	Holder string `json:"holder,omitempty"` // the process holding the port, when the OS tells us
	// Another Woodshed holding (probably) the port: "woodshed_service" or
	// "woodshed", its PID and UI address, when known (docs/api.md).
	HolderKind  string `json:"holder_kind,omitempty"`
	HolderPID   int    `json:"holder_pid,omitempty"`
	HolderUIURL string `json:"holder_ui_url,omitempty"`
}

// Banner is a message the UI shows at the top of every page.
type Banner struct {
	Kind   string `json:"kind"`          // listener_bind, writes_paused, low_disk, … (docs/api.md)
	Level  string `json:"level"`         // error, warn, info
	Text   string `json:"text"`          //
	Action string `json:"action"`        // "", "retry_listeners", "update_choice" or "update_dismiss"
	URL    string `json:"url,omitempty"` // a link for the banner (update_available: the release page)
}

// ---- GET /api/stats ----

// Stats is the body of GET /api/stats.
type Stats struct {
	MsgsPerSec       float64      `json:"msgs_per_sec"`
	Sparkline        []float64    `json:"sparkline"` // msgs/s averaged per minute, oldest first, last 60 minutes
	Devices          DeviceCounts `json:"devices"`
	Disk             Disk         `json:"disk"`
	Dropped24h       int64        `json:"dropped_24h"`
	KernelDropped24h *int64       `json:"kernel_dropped_24h"` // nil where the OS doesn't expose it
	Truncated24h     int64        `json:"truncated_24h"`
	Rejected24h      int64        `json:"rejected_24h"`
	// DroppedByReason splits the drops (SPEC §11.5); counted since the server
	// started, so across a restart it can sum to less than Dropped24h.
	DroppedByReason DroppedByReason `json:"dropped_by_reason"`
	UDPQueue        []UDPQueue      `json:"udp_queue"` // one per enabled UDP listener
}

// DroppedByReason is /api/stats dropped_by_reason (last 24 hours).
type DroppedByReason struct {
	Paused     int64 `json:"paused"`      // the low-disk guard had paused writing
	WriteError int64 `json:"write_error"` // a write to the log file failed
	Refused    int64 `json:"refused"`     // new senders over the device limits
	QueueFull  int64 `json:"queue_full"`  // a UDP listener's queue was full
}

// UDPQueue is one UDP listener's receive queue (/api/stats udp_queue).
type UDPQueue struct {
	Listener         string `json:"listener"` // "udp" (syslog), later "snmp"
	Port             int    `json:"port"`
	CapacityMessages int    `json:"capacity_messages"`
	CapacityBytes    int64  `json:"capacity_bytes"`
	Depth            int    `json:"depth"`
	HighWater24h     int    `json:"high_water_24h"`
	Dropped24h       int64  `json:"dropped_24h"`
	HighWaterByHour  []int  `json:"high_water_by_hour"` // oldest first, the last 24 hours (fewer just after start)
}

// DeviceCounts counts non-hidden devices by status.
type DeviceCounts struct {
	Total   int `json:"total"`
	Online  int `json:"online"`
	Quiet   int `json:"quiet"`
	Offline int `json:"offline"`
}

// Disk is the storage summary on the dashboard.
type Disk struct {
	UsedBytes int64 `json:"used_bytes"`
	CapBytes  int64 `json:"cap_bytes"`
	FreeBytes int64 `json:"free_bytes"`
	DaysKept  int   `json:"days_kept"`

	// The retention estimate (nil when unknown: under 1 h of data).
	BytesPerDay      *int64   `json:"bytes_per_day"`     // on-disk bytes a day at the last 24 h's rate
	CompressionRatio *float64 `json:"compression_ratio"` // measured on gzipped files, 8 until there are any
	EstimatedDays    *float64 `json:"estimated_days"`    // cap_bytes / bytes_per_day (nil at a zero rate)
	LimitedBy        *string  `json:"limited_by"`        // "cap" or "age"
}

// StorageEstimate is the body of GET /api/storage/estimate.
type StorageEstimate struct {
	EstimatedDays    *float64 `json:"estimated_days"`
	BytesPerDay      *int64   `json:"bytes_per_day"`
	CompressionRatio *float64 `json:"compression_ratio"`
}

// ---- GET /api/rejected ----

// RejectedSender is a refused sender.
type RejectedSender struct {
	IP       string    `json:"ip"`
	Count24h int64     `json:"count_24h"`
	LastSeen time.Time `json:"last_seen"`
	Reason   string    `json:"reason"` // the latest refusal's reason: "allowlist" or "per_source"
}

// ---- /api/devices ----

// Device is one sender.
type Device struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Name      string    `json:"name"`
	Group     string    `json:"group"`
	Hidden    bool      `json:"hidden"`
	FirstSeen time.Time `json:"first_seen"`
	LastHeard time.Time `json:"last_heard"`
	Status    string    `json:"status"` // online, quiet, offline, blocked
	Blocked   bool      `json:"blocked"`
	// BlockedBy is set on a PATCH that unblocked the device's own address while
	// a broader blocklist entry still covers it.
	BlockedBy   string `json:"blocked_by,omitempty"`
	MsgsPerMin  int64  `json:"msgs_per_min"`
	TotalMsgs   int64  `json:"total_msgs"`
	BytesOnDisk int64  `json:"bytes_on_disk"`
	// TLS is the device's TLS counts, nil until it has tried TLS (since start).
	TLS *DeviceTLS `json:"tls"`
}

// DevicePatch is the body of PATCH /api/devices/{id}; nil fields are left alone.
type DevicePatch struct {
	Name    *string `json:"name,omitempty"`
	Group   *string `json:"group,omitempty"`
	Hidden  *bool   `json:"hidden,omitempty"`
	Blocked *bool   `json:"blocked,omitempty"` // add or remove the device's exact address on listeners.blocklist
}

// ---- /api/settings ----

// Settings is the body of GET and PUT /api/settings.
type Settings struct {
	Listeners ListenersSettings `json:"listeners"`
	Storage   StorageSettings   `json:"storage"`
	UI        UISettings        `json:"ui"`
	Quiet     QuietSettings     `json:"quiet"`
	// Updates is always in GET. A PUT without it (a 1.0 client or script)
	// leaves updates.check as it is.
	Updates *UpdatesSettings `json:"updates,omitempty"`
}

// UpdatesSettings holds the update check setting.
type UpdatesSettings struct {
	Check string `json:"check"` // "ask", "on" or "off"
}

// ListenersSettings holds the syslog listener settings.
type ListenersSettings struct {
	UDP       ListenerSettings    `json:"udp"`
	TCP       ListenerSettings    `json:"tcp"`
	TLS       TLSListenerSettings `json:"tls"`
	Allowlist []string            `json:"allowlist"`
	Blocklist []string            `json:"blocklist"`
	// New-sender limits (the device_limit banner).
	MaxDevices          int `json:"max_devices"`
	NewDeviceBurst      int `json:"new_device_burst"`
	NewDevicesPerMinute int `json:"new_devices_per_minute"`
}

// ListenerSettings is one syslog listener's settings.
type ListenerSettings struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
}

// TLSListenerSettings is the TLS syslog listener's settings (SPEC §10.3.1).
type TLSListenerSettings struct {
	Enabled        bool   `json:"enabled"`
	Addr           string `json:"addr"`
	Port           int    `json:"port"`
	AllowLegacyTLS bool   `json:"allow_legacy_tls"`
	CertFile       string `json:"cert_file"` // empty: Woodshed's own CA and certificate
	KeyFile        string `json:"key_file"`
}

// StorageSettings holds the storage settings. DataDir is read-only in v1.
type StorageSettings struct {
	DataDir        string `json:"data_dir"`
	RetentionDays  int    `json:"retention_days"`
	RetentionBytes int64  `json:"retention_bytes"`
	PartBytes      int64  `json:"part_bytes"`
}

// UISettings holds the web UI settings.
type UISettings struct {
	LANMode           bool     `json:"lan_mode"`
	Port              int      `json:"port"`
	CertFile          string   `json:"cert_file"` // empty: use the self-signed certificate
	KeyFile           string   `json:"key_file"`
	RequireLoginLocal bool     `json:"require_login_local"` // localhost mode asks for the password too
	ExtraHostnames    []string `json:"extra_hostnames"`     // added to the self-signed certificate
	TrustedHosts      []string `json:"trusted_hosts"`       // extra Host values accepted (reverse proxies)
}

// QuietSettings holds the device status thresholds.
type QuietSettings struct {
	QuietAfterSeconds   int `json:"quiet_after_seconds"`
	OfflineAfterSeconds int `json:"offline_after_seconds"`
}

// ---- /api/updates ----

// UpdateInfo is the body of GET /api/updates (and of PUT's answer).
type UpdateInfo struct {
	Check            string         `json:"check"`     // "ask", "on" or "off"
	Available        bool           `json:"available"` // false in a build that can't check
	URL              string         `json:"url"`       // the releases file
	Current          string         `json:"current"`
	LastCheck        *time.Time     `json:"last_check"`  // nil until the first check
	LastResult       string         `json:"last_result"` // "", "ok" or "error"
	LastError        string         `json:"last_error"`
	LastErrorKind    string         `json:"last_error_kind"`
	NextCheck        *time.Time     `json:"next_check"` // nil unless check is "on"
	Latest           *LatestRelease `json:"latest"`     // nil until a check succeeds, and after turning it off
	UpdateAvailable  bool           `json:"update_available"`
	DismissedVersion string         `json:"dismissed_version"`
}

// LatestRelease is the newest release this build would offer.
type LatestRelease struct {
	Version    string `json:"version"`
	Prerelease bool   `json:"prerelease"`
	URL        string `json:"url"` // the release page
}

func (u *UpdateInfo) normalize() {
	if u.LastCheck != nil {
		t := u.LastCheck.UTC()
		u.LastCheck = &t
	}
	if u.NextCheck != nil {
		t := u.NextCheck.UTC()
		u.NextCheck = &t
	}
}

// ErrUpdateCheckOff is CheckUpdatesNow's answer while updates.check isn't
// "on", or in a build that can't check (409).
var ErrUpdateCheckOff = errors.New("the update check is off")

// RetryAfterError is a 429 with a Retry-After header.
type RetryAfterError struct {
	After time.Duration
	Msg   string
}

func (e *RetryAfterError) Error() string { return e.Msg }

// ---- GET /api/storage/history ----

// StorageEntry is one deleted file.
type StorageEntry struct {
	Time     time.Time `json:"time"`
	File     string    `json:"file"`
	DeviceID string    `json:"device_id"`
	Bytes    int64     `json:"bytes"`
	Reason   string    `json:"reason"` // age, cap, low_disk
}

// ---- normalization: UTC times, [] rather than null ----

func (s *Status) normalize() {
	s.StartedAt = s.StartedAt.UTC()
	if s.FirstMessageAt != nil {
		t := s.FirstMessageAt.UTC()
		s.FirstMessageAt = &t
	}
	s.Listeners = nonNil(s.Listeners)
	s.HostIPs = nonNil(s.HostIPs)
	s.Banners = nonNil(s.Banners)
	SortBanners(s.Banners)
}

// SortBanners puts banners in priority order: errors, then warnings, then
// anything else; stable within a level.
func SortBanners(bs []Banner) {
	slices.SortStableFunc(bs, func(a, b Banner) int { return bannerRank(a.Level) - bannerRank(b.Level) })
}

func bannerRank(level string) int {
	switch level {
	case LevelError:
		return 0
	case LevelWarn:
		return 1
	}
	return 2
}

// MaxRejected caps GET /api/rejected.
const MaxRejected = 200

// normalizeRejected sorts by count_24h descending (most recent first on a tie),
// keeps at most MaxRejected and makes times UTC.
func normalizeRejected(rs []RejectedSender) []RejectedSender {
	rs = slices.Clone(nonNil(rs))
	slices.SortStableFunc(rs, func(a, b RejectedSender) int {
		if a.Count24h != b.Count24h {
			return cmp.Compare(b.Count24h, a.Count24h)
		}
		return b.LastSeen.Compare(a.LastSeen)
	})
	if len(rs) > MaxRejected {
		rs = rs[:MaxRejected]
	}
	for i := range rs {
		rs[i].LastSeen = rs[i].LastSeen.UTC()
	}
	return rs
}

func (s *Stats) normalize() { s.Sparkline = nonNil(s.Sparkline) }

func (d *Device) normalize() {
	d.FirstSeen = d.FirstSeen.UTC()
	d.LastHeard = d.LastHeard.UTC()
	if t := d.TLS; t != nil {
		if t.LastConnected != nil {
			lc := t.LastConnected.UTC()
			t.LastConnected = &lc
		}
		if t.LastFailure != nil {
			t.LastFailure.Time = t.LastFailure.Time.UTC()
		}
	}
}

func (s *Settings) normalize() {
	s.Listeners.Allowlist = nonNil(s.Listeners.Allowlist)
	s.Listeners.Blocklist = nonNil(s.Listeners.Blocklist)
	s.UI.ExtraHostnames = nonNil(s.UI.ExtraHostnames)
	s.UI.TrustedHosts = nonNil(s.UI.TrustedHosts)
}

// ErrSettingsChanged is SaveSettings's answer to a stale If-Match.
var ErrSettingsChanged = errors.New("settings changed since you loaded them")

// SettingsETag is the strong ETag of a settings object as GET /api/settings
// sends it: a hash of its normalized JSON.
func SettingsETag(st Settings) string {
	st.normalize()
	b, err := json.Marshal(st)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// etagMatches reports whether an If-Match header value names etag ("*", or one
// of a comma-separated list; a weak W/ tag compares by its value).
func etagMatches(header, etag string) bool {
	for _, t := range strings.Split(header, ",") {
		t = strings.TrimPrefix(strings.TrimSpace(t), "W/")
		if t == "*" || t == etag {
			return true
		}
	}
	return false
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
