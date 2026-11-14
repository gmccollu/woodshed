package api

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"
	"time"
)

// The SNMP trap receiver's routes (SPEC §11.2, docs/api.md "SNMP trap
// listener", "SNMP state" and "SNMP v3 users"): its state, the MIB reload, the
// failing senders and the v3 users. Secrets never leave through any of them:
// a user's passphrases are write-only (auth_set / priv_set), and communities
// appear only as hash prefixes in /api/settings.

// SNMPBackend is what the SNMP routes need from the service.
type SNMPBackend interface {
	// SNMP serves GET /api/snmp.
	SNMP(ctx context.Context) (SNMPState, error)
	// ReloadMIBs serves POST /api/snmp/mibs/reload: it reads the MIB folder
	// again and returns what it loaded.
	ReloadMIBs(ctx context.Context) (SNMPMIBs, error)
	// SNMPFailures serves GET /api/snmp/failures.
	SNMPFailures(ctx context.Context) ([]SNMPFailure, error)
	// SNMPUsers serves GET /api/snmp/users, in name order.
	SNMPUsers(ctx context.Context) ([]SNMPUser, error)
	// CreateSNMPUser serves POST /api/snmp/users: a *ValidationError for a bad
	// body, ErrSNMPUserExists for a name in use.
	CreateSNMPUser(ctx context.Context, in SNMPUserInput) (SNMPUser, error)
	// UpdateSNMPUser serves PUT /api/snmp/users/{name}: errors as for
	// CreateSNMPUser, and ErrNotFound.
	UpdateSNMPUser(ctx context.Context, name string, in SNMPUserInput) (SNMPUser, error)
	// DeleteSNMPUser serves DELETE /api/snmp/users/{name}: ErrNotFound for an
	// unknown name.
	DeleteSNMPUser(ctx context.Context, name string) error
}

// ErrSNMPUserExists is CreateSNMPUser's error for a name in use (409).
var ErrSNMPUserExists = errors.New("an SNMP v3 user with that name already exists")

// SNMPState is the body of GET /api/snmp.
type SNMPState struct {
	Enabled   bool         `json:"enabled"`
	Port      int          `json:"port"`
	Engine    SNMPEngine   `json:"engine"`
	Counts24h SNMPCounts   `json:"counts_24h"`
	MIBs      SNMPMIBs     `json:"mibs"`
	Firewall  SNMPFirewall `json:"firewall"`
}

// SNMPEngine is Woodshed's own v3 engine (authoritative for informs).
type SNMPEngine struct {
	ID    string `json:"id"`    // hex
	Boots int64  `json:"boots"` // engineBoots
	Time  int64  `json:"time"`  // engineTime, seconds since the start
}

// SNMPCounts are the last 24 hours' counts.
type SNMPCounts struct {
	Received           int64            `json:"received"`
	InformsAnswered    int64            `json:"informs_answered"`
	RepliesRateLimited int64            `json:"replies_rate_limited"`
	DiscoveryReports   int64            `json:"discovery_reports"`
	TimeResyncs        int64            `json:"time_resyncs"`
	ByStatus           map[string]int64 `json:"by_status"` // only statuses with a count
}

// SNMPMIBs is the MIB folder's state.
type SNMPMIBs struct {
	Dir      string         `json:"dir"`
	Files    int            `json:"files"`
	Names    int            `json:"names"`
	LoadedAt time.Time      `json:"loaded_at"`
	Errors   []SNMPMIBError `json:"errors"`
	Warnings []SNMPMIBError `json:"warnings"`
}

// SNMPMIBError is a MIB file that didn't load (or a warning about one).
type SNMPMIBError struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

// SNMPFirewall is what Woodshed can see of the OS firewall for the SNMP port
// (as for TLS: always "unknown" off Windows).
type SNMPFirewall struct {
	State   string `json:"state"`   // ok, missing, disabled, wrong_port, unknown
	Command string `json:"command"` // what to run as an administrator ("" except on Windows)
}

// SNMPFailure is one sender whose v3 traps failed, or whose packets were
// malformed, in the last 24 hours (GET /api/snmp/failures).
type SNMPFailure struct {
	IP       string    `json:"ip"`
	Count24h int64     `json:"count_24h"`
	LastSeen time.Time `json:"last_seen"`
	Status   string    `json:"status"` // the latest failure's status
	Detail   string    `json:"detail"` // the user, engine or decoding error; never key material
	DeviceID string    `json:"device_id"`
	// TimeResyncs24h counts the sender's v3 clock relearns (SPEC §11.8 #28).
	TimeResyncs24h int64 `json:"time_resyncs_24h"`
}

// SNMPUser is one v3 user, without its secrets (GET /api/snmp/users).
type SNMPUser struct {
	Name      string   `json:"name"`
	Level     string   `json:"level"` // noAuthNoPriv, authNoPriv, authPriv
	Auth      string   `json:"auth"`  // none, md5, sha, sha-224, sha-256, sha-384, sha-512
	Priv      string   `json:"priv"`  // none, des, aes-128, aes-192, aes-256
	KeyExt    string   `json:"key_ext"`
	EngineIDs []string `json:"engine_ids"`
	AuthSet   bool     `json:"auth_set"`
	PrivSet   bool     `json:"priv_set"`
	Stored    string   `json:"stored"`   // "passphrase" or "localized"
	Readable  bool     `json:"readable"` // false: the credentials file can't be decrypted here
	// Weak lists the protocols Settings labels weak (md5, sha, des).
	Weak []string `json:"weak"`
}

// SNMPUserInput is the body of POST /api/snmp/users and PUT /api/snmp/users/{name}.
type SNMPUserInput struct {
	Name      string   `json:"name"`
	Auth      string   `json:"auth"`
	AuthPass  string   `json:"auth_pass"`
	Priv      string   `json:"priv"`
	PrivPass  string   `json:"priv_pass"`
	KeyExt    string   `json:"key_ext"`
	EngineIDs []string `json:"engine_ids"`
}

// MaxSNMPFailures caps GET /api/snmp/failures.
const MaxSNMPFailures = 200

func (st *SNMPState) normalize() {
	if st.Counts24h.ByStatus == nil {
		st.Counts24h.ByStatus = map[string]int64{}
	}
	st.MIBs.normalize()
	if st.Firewall.State == "" {
		st.Firewall.State = "unknown"
	}
}

func (m *SNMPMIBs) normalize() {
	m.Errors, m.Warnings = nonNil(m.Errors), nonNil(m.Warnings)
	if !m.LoadedAt.IsZero() {
		m.LoadedAt = m.LoadedAt.UTC()
	}
}

func normalizeSNMPFailures(fs []SNMPFailure) []SNMPFailure {
	fs = slices.Clone(nonNil(fs))
	slices.SortStableFunc(fs, func(a, b SNMPFailure) int {
		if a.Count24h != b.Count24h {
			return cmp.Compare(b.Count24h, a.Count24h)
		}
		return b.LastSeen.Compare(a.LastSeen)
	})
	if len(fs) > MaxSNMPFailures {
		fs = fs[:MaxSNMPFailures]
	}
	for i := range fs {
		fs[i].LastSeen = fs[i].LastSeen.UTC()
	}
	return fs
}

func normalizeSNMPUser(u *SNMPUser) {
	u.EngineIDs, u.Weak = nonNil(u.EngineIDs), nonNil(u.Weak)
}

// snmpRoutes adds the SNMP routes to mux.
func (s *Server) snmpRoutes(mux *http.ServeMux) {
	b := s.backend
	mux.Handle("/api/snmp", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		st, err := b.SNMP(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		st.normalize()
		writeJSON(w, http.StatusOK, st)
	}})
	mux.Handle("/api/snmp/mibs/reload", methods{http.MethodPost: func(w http.ResponseWriter, r *http.Request) {
		m, err := b.ReloadMIBs(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		m.normalize()
		writeJSON(w, http.StatusOK, m)
	}})
	mux.Handle("/api/snmp/failures", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		fs, err := b.SNMPFailures(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, normalizeSNMPFailures(fs))
	}})
	userErr := func(w http.ResponseWriter, r *http.Request, err error) {
		var ve *ValidationError
		switch {
		case errors.As(err, &ve):
			writeJSON(w, http.StatusBadRequest, errorBody{Error: "Some fields need fixing.", Errors: nonNilMap(ve.Fields)})
		case errors.Is(err, ErrSNMPUserExists):
			writeError(w, http.StatusConflict, "A v3 user with that name already exists.")
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "No v3 user with that name.")
		default:
			s.backendError(w, r, err)
		}
	}
	mux.Handle("/api/snmp/users", methods{
		http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
			us, err := b.SNMPUsers(r.Context())
			if err != nil {
				s.backendError(w, r, err)
				return
			}
			us = slices.Clone(nonNil(us))
			for i := range us {
				normalizeSNMPUser(&us[i])
			}
			writeJSON(w, http.StatusOK, us)
		},
		http.MethodPost: func(w http.ResponseWriter, r *http.Request) {
			var in SNMPUserInput
			if !decodeJSON(w, r, &in) {
				return
			}
			u, err := b.CreateSNMPUser(r.Context(), in)
			if err != nil {
				userErr(w, r, err)
				return
			}
			normalizeSNMPUser(&u)
			writeJSON(w, http.StatusCreated, u)
		},
	})
	mux.Handle("/api/snmp/users/{name}", methods{
		http.MethodPut: func(w http.ResponseWriter, r *http.Request) {
			var in SNMPUserInput
			if !decodeJSON(w, r, &in) {
				return
			}
			u, err := b.UpdateSNMPUser(r.Context(), r.PathValue("name"), in)
			if err != nil {
				userErr(w, r, err)
				return
			}
			normalizeSNMPUser(&u)
			writeJSON(w, http.StatusOK, u)
		},
		http.MethodDelete: func(w http.ResponseWriter, r *http.Request) {
			if err := b.DeleteSNMPUser(r.Context(), r.PathValue("name")); err != nil {
				userErr(w, r, err)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		},
	})
}
