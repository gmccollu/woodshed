package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gmccollu/woodshed/internal/config"
)

// maxBody caps JSON request bodies.
const maxBody = 1 << 20

// maxLabel caps a device name or group, in characters.
const maxLabel = 128

// writeJSON writes v with the given status. API responses are never cached.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status = http.StatusInternalServerError
		b = []byte(`{"error":"internal error: could not encode the response"}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n"))
}

// errorBody is the body of every non-2xx response. Errors is set only for
// field-level validation errors.
type errorBody struct {
	Error  string            `json:"error"`
	Errors map[string]string `json:"errors,omitempty"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorBody{Error: msg})
}

// backendError reports a Backend failure as a 500 without leaking internals
// beyond the error text the backend chose.
func (s *Server) backendError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("api: backend error", "method", r.Method, "path", r.URL.Path, "err", err)
	writeError(w, http.StatusInternalServerError, "internal error: "+err.Error())
}

// decodeJSON reads a JSON object body into v, refusing unknown fields, trailing
// data and oversized bodies. It writes the error response itself and returns
// false on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeJSONLimit(w, r, v, maxBody)
}

// decodeJSONLimit is decodeJSON with its own body size limit.
func decodeJSONLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	ct := r.Header.Get("Content-Type")
	if ct != "" && !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "The request body must be JSON (Content-Type: application/json).")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		switch {
		case errors.As(err, &mbe):
			writeError(w, http.StatusRequestEntityTooLarge, "The request body is too large.")
		case errors.Is(err, io.EOF):
			writeError(w, http.StatusBadRequest, "The request body is empty.")
		default:
			writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		}
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "Invalid JSON: unexpected data after the object.")
		return false
	}
	if _, err := dec.Token(); err != io.EOF {
		writeError(w, http.StatusBadRequest, "Invalid JSON: unexpected data after the object.")
		return false
	}
	return true
}

// methods dispatches on the request method and answers others with 405.
type methods map[string]http.HandlerFunc

func (m methods) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h, ok := m[r.Method]; ok {
		h(w, r)
		return
	}
	allow := make([]string, 0, len(m))
	for _, k := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if _, ok := m[k]; ok {
			allow = append(allow, k)
		}
	}
	w.Header().Set("Allow", strings.Join(allow, ", "))
	writeError(w, http.StatusMethodNotAllowed, fmt.Sprintf("%s is not allowed on %s.", r.Method, r.URL.Path))
}

// apiRoutes returns the /api/ and /healthz routes. Auth and the other checks are
// middleware around it (see Server.handler).
func (s *Server) apiRoutes() *http.ServeMux {
	mux := http.NewServeMux()
	b := s.backend

	mux.Handle("/healthz", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}})

	// Status and stats.
	mux.Handle("/api/status", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		st, err := b.Status(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		st.UICertFingerprint = s.State().CertFingerprint
		st.UIAddrs = s.uiAddrs()
		st.normalize()
		writeJSON(w, http.StatusOK, st)
	}})
	mux.Handle("/api/listeners/retry", methods{http.MethodPost: func(w http.ResponseWriter, r *http.Request) {
		if err := b.RetryListeners(r.Context()); err != nil {
			s.backendError(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}})
	mux.Handle("/api/stats", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		st, err := b.Stats(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		st.normalize()
		writeJSON(w, http.StatusOK, st)
	}})
	mux.Handle("/api/rejected", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		rs, err := b.Rejected(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, normalizeRejected(rs))
	}})

	// Devices.
	mux.Handle("/api/devices", methods{http.MethodGet: s.getDevices})
	mux.Handle("/api/groups", methods{http.MethodGet: s.getGroups})
	mux.Handle("/api/devices/{id}", methods{http.MethodPatch: s.patchDevice})

	// Live tail.
	live := b.LiveHandler()
	mux.Handle("/api/live", methods{http.MethodGet: live.ServeHTTP})

	// Search and exports.
	mux.Handle("/api/search", methods{http.MethodGet: s.getSearch})
	mux.Handle("/api/search/schema", methods{http.MethodGet: s.getSchema})
	mux.Handle("/api/search/summary", methods{http.MethodGet: s.getSummary})
	mux.Handle("/api/saved-searches", methods{http.MethodGet: s.listSaved, http.MethodPost: s.createSaved})
	mux.Handle("/api/saved-searches/{id}", methods{http.MethodGet: s.getSaved, http.MethodPut: s.putSaved, http.MethodDelete: s.deleteSaved})
	mux.Handle("/api/context", methods{http.MethodGet: s.getContext})
	mux.Handle("/api/exports", methods{http.MethodGet: s.listExports, http.MethodPost: s.postExport})
	mux.Handle("/api/exports/estimate", methods{http.MethodPost: s.postEstimate})
	mux.Handle("/api/exports/{id}", methods{http.MethodGet: s.getExport, http.MethodDelete: s.deleteExport})
	mux.Handle("/api/exports/{id}/download", methods{http.MethodGet: s.downloadExport})
	mux.Handle("/api/exports/{id}/ticket", methods{http.MethodPost: s.postTicket})

	// Settings.
	mux.Handle("/api/settings", methods{
		http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
			st, err := b.Settings(r.Context())
			if err != nil {
				s.backendError(w, r, err)
				return
			}
			st.normalize()
			w.Header().Set("ETag", SettingsETag(st))
			writeJSON(w, http.StatusOK, st)
		},
		http.MethodPut: s.putSettings,
	})
	mux.Handle("/api/storage/estimate", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("retention_bytes")
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "retention_bytes must be an integer number of bytes")
			return
		}
		est, err := b.StorageEstimate(r.Context(), n)
		if err != nil {
			s.requestOrBackendError(w, r, err, "")
			return
		}
		writeJSON(w, http.StatusOK, est)
	}})
	mux.Handle("/api/storage/history", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		es, err := b.StorageHistory(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		es = nonNil(es)
		for i := range es {
			es[i].Time = es[i].Time.UTC()
		}
		writeJSON(w, http.StatusOK, es)
	}})

	// The update check.
	mux.Handle("/api/updates", methods{http.MethodGet: s.getUpdates, http.MethodPut: s.putUpdates})
	mux.Handle("/api/updates/check", methods{http.MethodPost: s.postUpdateCheck})
	mux.Handle("/api/updates/dismiss", methods{http.MethodPost: s.postUpdateDismiss})

	// Auth.
	mux.Handle("/api/session", methods{http.MethodGet: s.getSession})
	mux.Handle("/api/login", methods{http.MethodPost: s.login})
	mux.Handle("/api/logout", methods{http.MethodPost: s.logout})
	mux.Handle("/api/password", methods{http.MethodPut: s.putPassword})

	// The TLS syslog listener.
	s.tlsRoutes(mux)

	// Anything else under /api/.
	notFound := func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "No such API route: "+r.URL.Path)
	}
	s.snmpRoutes(mux)
	s.pollRoutes(mux)
	s.setupRoutes(mux)
	s.flowRoutes(mux)
	mux.HandleFunc("/api/", notFound)
	mux.HandleFunc("/api", notFound)
	return mux
}

func (s *Server) patchDevice(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var p DevicePatch
	if !decodeJSON(w, r, &p) {
		return
	}
	for field, v := range map[string]*string{"name": p.Name, "group": p.Group} {
		if v == nil {
			continue
		}
		if msg := checkLabel(*v); msg != "" {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: field + ": " + msg, Errors: map[string]string{field: msg}})
			return
		}
	}
	if v := p.MinSeverity; v != nil {
		if strings.EqualFold(strings.TrimSpace(*v), config.SeverityDefault) {
			*v = config.SeverityDefault // "Default" too, as the CLI takes it
		}
		if _, ok := config.ParseSeverity(*v); !ok && *v != config.SeverityDefault {
			msg := `Must be "default" or a severity: emerg, alert, crit, err, warning, notice, info or debug (or 0 to 7).`
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "min_severity: " + msg, Errors: map[string]string{"min_severity": msg}})
			return
		}
	}
	d, err := s.backend.UpdateDevice(r.Context(), id, p)
	if errors.Is(err, ErrNotFound) {
		writeError(w, http.StatusNotFound, fmt.Sprintf("No device with id %q.", id))
		return
	}
	var re *RequestError
	if errors.As(err, &re) {
		// A device the change can't apply to (min_severity on an ID without an address).
		body := errorBody{Error: re.Msg}
		if p.MinSeverity != nil {
			body.Errors = map[string]string{"min_severity": re.Msg}
		}
		writeJSON(w, http.StatusBadRequest, body)
		return
	}
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	d.normalize()
	writeJSON(w, http.StatusOK, d)
}

// checkLabel validates a device name or group and returns a message, or "".
func checkLabel(v string) string {
	if !utf8.ValidString(v) {
		return "Must be valid UTF-8."
	}
	if utf8.RuneCountInString(v) > maxLabel {
		return fmt.Sprintf("At most %d characters.", maxLabel)
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return "Must not contain control characters."
		}
	}
	return ""
}

func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var in Settings
	if !decodeJSON(w, r, &in) {
		return
	}
	if u := in.Updates; u != nil && u.Check != "ask" && u.Check != "on" && u.Check != "off" {
		writeJSON(w, http.StatusBadRequest, errorBody{
			Error:  "Some settings need fixing.",
			Errors: map[string]string{"updates.check": `Must be "ask", "on" or "off".`},
		})
		return
	}
	// LAN mode needs a password first (SPEC §5). The backend can't know: the
	// password lives in this package.
	if in.UI.LANMode && !s.auth.passwordSet() {
		writeJSON(w, http.StatusBadRequest, errorBody{
			Error:  "Some settings need fixing.",
			Errors: map[string]string{"ui.lan_mode": "Set a password before turning on LAN mode."},
		})
		return
	}
	if in.UI.RequireLoginLocal && !s.auth.passwordSet() {
		writeJSON(w, http.StatusBadRequest, errorBody{
			Error:  "Some settings need fixing.",
			Errors: map[string]string{"ui.require_login_local": "Set a password before requiring it on localhost."},
		})
		return
	}
	// If-Match: the ETag from GET. The backend compares it under its save lock,
	// so a concurrent change (another tab, a device blocked) can't slip between.
	// "*" or no header saves whatever is in effect (scripts).
	ifMatch := ""
	if h := r.Header.Get("If-Match"); h != "" {
		cur, err := s.backend.Settings(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		cur.normalize()
		etag := SettingsETag(cur)
		if !etagMatches(h, etag) {
			writeError(w, http.StatusConflict, ErrSettingsChanged.Error())
			return
		}
		ifMatch = etag
	}
	saved, err := s.backend.SaveSettings(r.Context(), in, ifMatch)
	if errors.Is(err, ErrSettingsChanged) {
		writeError(w, http.StatusConflict, ErrSettingsChanged.Error())
		return
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		writeJSON(w, http.StatusBadRequest, errorBody{Error: "Some settings need fixing.", Errors: nonNilMap(ve.Fields)})
		return
	}
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	saved.normalize()

	// require_login_local and the host lists apply at once, without a restart.
	s.mu.Lock()
	s.want.RequireLoginLocal = saved.UI.RequireLoginLocal
	s.want.ExtraHostnames, s.want.TrustedHosts = saved.UI.ExtraHostnames, saved.UI.TrustedHosts
	s.mu.Unlock()
	s.requireLocal.Store(saved.UI.RequireLoginLocal)
	s.setHosts(saved.UI.ExtraHostnames, saved.UI.TrustedHosts)

	// A mode, port or certificate change restarts the UI server after this
	// response (the restart waits for this request to finish before it closes
	// the listener); the response says so.
	cur := s.currentUI()
	restart := saved.UI.LANMode != cur.LANMode || saved.UI.Port != cur.Port ||
		saved.UI.CertFile != cur.CertFile || saved.UI.KeyFile != cur.KeyFile
	w.Header().Set("ETag", SettingsETag(saved))
	writeJSON(w, http.StatusOK, settingsResponse{Settings: saved, Restarting: restart})
	if restart {
		next := cur
		next.LANMode, next.Port = saved.UI.LANMode, saved.UI.Port
		next.CertFile, next.KeyFile = saved.UI.CertFile, saved.UI.KeyFile
		s.log.Info("api: UI settings changed; restarting the UI server", "lan_mode", next.LANMode, "port", next.Port)
		s.Reconfigure(next)
	}
}

func (s *Server) getUpdates(w http.ResponseWriter, r *http.Request) {
	u, err := s.backend.Updates(r.Context())
	if err != nil {
		s.backendError(w, r, err)
		return
	}
	u.normalize()
	writeJSON(w, http.StatusOK, u)
}

// putUpdates is the banner's Turn on / No thanks and the Settings switch:
// "on" or "off" only ("ask" is for Settings).
func (s *Server) putUpdates(w http.ResponseWriter, r *http.Request) {
	var in UpdatesSettings
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Check != "on" && in.Check != "off" {
		writeJSON(w, http.StatusBadRequest, errorBody{
			Error:  `check must be "on" or "off".`,
			Errors: map[string]string{"check": `Must be "on" or "off".`},
		})
		return
	}
	u, err := s.backend.SetUpdateCheck(r.Context(), in.Check)
	if err != nil {
		s.requestOrBackendError(w, r, err, "")
		return
	}
	u.normalize()
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) postUpdateCheck(w http.ResponseWriter, r *http.Request) {
	err := s.backend.CheckUpdatesNow(r.Context())
	var ra *RetryAfterError
	switch {
	case err == nil:
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusAccepted)
	case errors.Is(err, ErrUpdateCheckOff):
		writeError(w, http.StatusConflict, "The update check is off. Turn it on first.")
	case errors.As(err, &ra):
		secs := max(int((ra.After+time.Second-1)/time.Second), 1)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		writeError(w, http.StatusTooManyRequests, ra.Msg)
	default:
		s.backendError(w, r, err)
	}
}

func (s *Server) postUpdateDismiss(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Version string `json:"version"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.backend.DismissUpdate(r.Context(), in.Version); err != nil {
		s.requestOrBackendError(w, r, err, "")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// settingsResponse is the PUT /api/settings body: the saved settings, plus
// "restarting": true when the UI server restarts after the response.
type settingsResponse struct {
	Settings
	Restarting bool `json:"restarting,omitempty"`
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// recoverer turns a handler panic into a 500 with a JSON body.
func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				log.Error("api: handler panic", "method", r.Method, "path", r.URL.Path, "panic", v)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
