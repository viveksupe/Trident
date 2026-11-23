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
	"strings"
	"sync"

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

	// transports caches one *http.Transport per actor name and dialers the
	// LATEST dialer the pool handed out for that actor (a per-request
	// Transport leaked idle tunnel connections + close goroutines for up to
	// five minutes each).
	transports sync.Map // actor name -> *http.Transport
	dialers    sync.Map // actor name -> backend.Dialer
}

// New builds the facade server.
func New(cfg *config.Config, pl *pool.Pool, log *slog.Logger) *Server {
	return &Server{cfg: cfg, pl: pl, log: log, specs: newSpecCache(filepath.Dir(cfg.StateDB))}
}

// SetEgress attaches the approval manager (nil-able); call before Handler.
func (s *Server) SetEgress(m *egress.Manager) { s.egress = m }

// SetBackend attaches the actor backend for console maintenance.
func (s *Server) SetBackend(b backend.Backend) { s.backend = b }

// Handler returns the root http.Handler: the human/LAN surface (Open WebUI
// protocol + console). The actor-facing TLS callback listener uses Handler()
// never — see CallbackHandler: actors can reach the callback listener by
// design, so it must expose only the egress callback endpoints.
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
	//
	// Registered WITHOUT a method prefix so every method reaches serveSpec
	// and non-GET/HEAD is answered 405 there: with a "GET /..." pattern the
	// mux lets method-mismatched requests fall through to the authenticated
	// "/" proxy instead (net/http never 405s while another pattern matches).
	// HEAD still matches these patterns, and serveSpec serves it from cache
	// (the server strips the body itself).
	for _, p := range []string{"/openapi.json", "/docs", "/redoc"} {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			s.serveSpec(w, r)
		})
	}

	mux.HandleFunc("/", s.route)
	s.RegisterEgress(mux)
	return mux
}

// CallbackHandler serves ONLY the actor-facing egress callback endpoints.
// Actors reach this listener through the tls-passthrough callback rule, so
// everything else (console pages, console APIs, the `/` proxy and its
// X-User-Id/X-Session-Id identity routing) must never be reachable here — an
// agent that landed on those endpoints could self-approve egress or reach
// other users' actors.
func (s *Server) CallbackHandler() http.Handler {
	mux := http.NewServeMux()
	if s.egress != nil { // only when the egress flow is on does the listener run
		s.RegisterEgressActor(mux)
	}
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

	// Distinct actor key: translate the credentials the actor receives
	// (front-side API key in → actor key out) on both channels actors
	// authenticate over — HTTP Authorization headers, and the first frame of
	// terminal/agent WebSocket upgrades.
	if s.cfg.KeyRewriteNeeded() {
		if isWebSocketUpgrade(r) {
			if s.spliceWS(w, r, ready) {
				return // splice owns the connection for its lifetime
			}
			// Fall through to the plain proxy (it will fail the upgrade with
			// the translated header only; auth frames would not rewrite).
		}
	}

	s.log.Debug("proxied request", "key", key.LogString(), "method", r.Method,
		"path", r.URL.Path, "actor", ready.Handle.Name)
	s.proxyFor(ready).ServeHTTP(w, r)
}

// bearerToken extracts the token from an `Authorization: Bearer <token>`
// header (scheme case-insensitive per RFC 7235).
func bearerToken(h string) string {
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}
