// Package facade is the front-facing Open Terminal protocol surface: API-key
// auth, Open WebUI contract endpoints (config/templates), and pass-through
// proxying of everything else to the per-chat actor.
//
// Contract notes (from Open WebUI source):
//   - GET /api/config is public and must not wake an actor; the features map
//     gates every other endpoint the frontend probes.
//   - GET /api/v1/terminals/templates must answer 404 with JSON detail so
//     Open WebUI keeps plain-terminal mode.
//   - The reverse-proxy path must remain untouched-hader-faithful: WS
//     upgrades (agent + terminal) are spliced by httputil.ReverseProxy and
//     close codes must pass through verbatim, so the proxied ResponseWriter
//     is never wrapped.
package facade

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/egress"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/pool"
)

// Server fronts the actors.
type Server struct {
	cfg     *config.Config
	pl      *pool.Pool
	log     *slog.Logger
	egress  *egress.Manager // nil unless the egress approval flow is enabled
	backend backend.Backend // for the console's actor maintenance panel
	specs   *specCache      // cached terminal /openapi.json per template
}

// New builds the facade server.
func New(cfg *config.Config, pl *pool.Pool, log *slog.Logger) *Server {
	return &Server{cfg: cfg, pl: pl, log: log, specs: newSpecCache(filepath.Dir(cfg.StateDB))}
}

// SetEgress attaches the approval manager (nil-able); call before Handler.
func (s *Server) SetEgress(m *egress.Manager) { s.egress = m }

// SetBackend attaches the actor backend for console maintenance.
func (s *Server) SetBackend(b backend.Backend) { s.backend = b }

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public, contract-critical endpoints (never auth or wake an actor).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"features": s.cfg.Features})
	})
	// Keep plain-terminal mode (the orchestrator surface is out of scope for v1).
	mux.HandleFunc("GET /api/v1/terminals/templates", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusNotFound, detail{"Not found"})
	})

	// Open WebUI fetches the tool spec from GET /openapi.json for plain
	// terminal connections WITHOUT the bearer key (only headers it already
	// sends, e.g. X-User-Id); open-terminal serves its docs/public paths
	// unauthenticated, so these pass through with no auth check either.
	// Spec + doc pages are served from the template cache first — no actor is
	// needed to serve static content, so keyless polls stopped spinning up the
	// adhoc sandbox.
	for _, p := range []string{"GET /openapi.json", "GET /docs", "GET /redoc"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			s.serveSpec(w, r)
		})
	}

	mux.HandleFunc("/", s.route)
	s.RegisterEgress(mux)
	return mux
}

type detail struct {
	Detail string `json:"detail"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// route authenticates, resolves the chat identity, and proxies to the actor.
func (s *Server) route(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r.Header.Get("Authorization"))
	if !s.cfg.KeyMatches(token) {
		// Match open-terminal's 401 body shape.
		writeJSON(w, http.StatusUnauthorized, detail{"Invalid API key"})
		return
	}
	s.routeNoAuth(w, r)
}

// routeNoAuth resolves the chat identity and proxies to the actor without the
// bearer check (docs/specs paths, which Open WebUI calls keyless).
func (s *Server) routeNoAuth(w http.ResponseWriter, r *http.Request) {
	key := model.NewRouteKey(r.Header.Get("X-User-Id"), r.Header.Get("X-Session-Id"))

	ready, inflight, err := s.pl.Acquire(r.Context(), key)
	if err != nil {
		s.log.Warn("acquire failed", "key", key.LogString(), "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusBadGateway, detail{"actor not ready: " + err.Error()})
		return
	}
	defer inflight.Done()

	s.log.Debug("proxied request", "key", key.LogString(), "method", r.Method,
		"path", r.URL.Path, "actor", ready.Handle.Name)
	s.proxyFor(ready).ServeHTTP(w, r)
}

// bearerToken extracts the token from an `Authorization: Bearer <token>` header.
func bearerToken(h string) string {
	const prefix = "Bearer "
	if len(h) > len(prefix) && h[:len(prefix)] == prefix {
		return h[len(prefix):]
	}
	return ""
}
