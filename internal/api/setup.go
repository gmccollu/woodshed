package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gmccollu/woodshed/internal/setuphelper"
)

// The device setup helper's routes (SPEC §13.5, docs/api.md "Setup helper"):
// the families, and one snippet filled from this server's settings. They read
// the settings, status and TLS state through the Backend and change nothing.
// No stored secret reaches a snippet: setuphelper.Server has no field for one.

// SetupServer describes this Woodshed for the setup helper from its settings,
// its status (the machine's addresses) and its TLS state (the certificate's
// names). The CLI builds the same from the config file.
func SetupServer(set Settings, st Status, tls TLSState) setuphelper.Server {
	l := func(e bool, addr string, port int) setuphelper.Listener {
		return setuphelper.Listener{Enabled: e, Addr: addr, Port: port}
	}
	srv := setuphelper.Server{
		HostIPs:   st.HostIPs,
		UDP:       l(set.Listeners.UDP.Enabled, set.Listeners.UDP.Addr, set.Listeners.UDP.Port),
		TCP:       l(set.Listeners.TCP.Enabled, set.Listeners.TCP.Addr, set.Listeners.TCP.Port),
		TLS:       l(set.Listeners.TLS.Enabled, set.Listeners.TLS.Addr, set.Listeners.TLS.Port),
		TLSSource: tls.Source,
	}
	if sn := set.Listeners.SNMP; sn != nil {
		srv.Trap = l(sn.Enabled, sn.Addr, sn.Port)
	} else {
		srv.Trap = l(false, "", 162)
	}
	if tls.Cert != nil {
		srv.TLSNames = tls.Cert.DNSNames
		srv.Names = append(srv.Names, tls.Cert.DNSNames...)
	} else {
		srv.TLSSource = ""
	}
	if tls.CA != nil {
		srv.CASHA256 = tls.CA.SHA256
	}
	srv.Names = append(srv.Names, set.UI.ExtraHostnames...)
	return srv
}

func (s *Server) setupServer(ctx context.Context) (setuphelper.Server, error) {
	b := s.backend
	set, err := b.Settings(ctx)
	if err != nil {
		return setuphelper.Server{}, err
	}
	st, err := b.Status(ctx)
	if err != nil {
		return setuphelper.Server{}, err
	}
	tls, err := b.TLS(ctx)
	if err != nil {
		return setuphelper.Server{}, err
	}
	return SetupServer(set, st, tls), nil
}

// setupRoutes adds the setup helper's routes to mux.
func (s *Server) setupRoutes(mux *http.ServeMux) {
	mux.Handle("/api/setup/families", methods{http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, setuphelper.Families())
	}})
	snippet := func(w http.ResponseWriter, r *http.Request, req setuphelper.Request) {
		srv, err := s.setupServer(r.Context())
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		sn, err := setuphelper.Generate(srv, req)
		var bad *setuphelper.Error
		if errors.As(err, &bad) {
			writeJSON(w, http.StatusBadRequest, errorBody{Error: bad.Error(), Errors: map[string]string{bad.Field: bad.Msg}})
			return
		}
		if err != nil {
			s.backendError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, sn)
	}
	mux.Handle("/api/setup/snippet", methods{
		http.MethodPost: func(w http.ResponseWriter, r *http.Request) {
			var req setuphelper.Request
			if !decodeJSON(w, r, &req) {
				return
			}
			snippet(w, r, req)
		},
		// The same fields as query parameters, for curl and scripts.
		http.MethodGet: func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			req := setuphelper.Request{Family: q.Get("family"), What: q.Get("what"), Transport: q.Get("transport"), Address: q.Get("address"),
				SourceInterface: q.Get("source_interface"), Interface: q.Get("interface"), Severity: q.Get("severity"),
				Facility: q.Get("facility"), V3User: q.Get("v3_user"), Auth: q.Get("auth"), Priv: q.Get("priv")}
			if req.What == "" {
				req.What = q.Get("type")
			}
			if v := q.Get("agent_port"); v != "" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || n > 65535 {
					writeJSON(w, http.StatusBadRequest, errorBody{Error: "agent_port: must be 1 to 65535",
						Errors: map[string]string{"agent_port": "must be 1 to 65535"}})
					return
				}
				req.AgentPort = n
			}
			snippet(w, r, req)
		},
	})
}
