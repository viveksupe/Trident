// Template spec cache: Open WebUI polls GET /openapi.json often (keyless), and
// each poll otherwise spins up the keyless adhoc actor — a whole sandbox that
// serves a static JSON document. The facade serves the spec itself, captured
// the first time it flows through and persisted per ActorTemplate.
package facade

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/viveksupe/Trident/internal/model"
)

type specCache struct {
	dir string
}

func newSpecCache(dir string) *specCache { return &specCache{dir: dir} }

// specFetchKey is the FIXED internal identity for cache-miss fetches: a
// keyless client's X-User-Id / X-Session-Id headers must never choose which
// actor gets created or woken by a spec poll (any caller could otherwise
// create sandboxes for arbitrary identities).
var specFetchKey = model.NewRouteKey("_trident-spec-fetch", "spec-cache")

// file returns the cache file for one path of one ActorTemplate ref
// ("ns/name"). Each path caches separately: an HTML /docs response must never
// overwrite the JSON spec (the shared file used to serve /docs as JSON and
// let HTML clobber the spec).
func (c *specCache) file(templateRef, path string) string {
	if strings.Contains(templateRef, "..") {
		return ""
	}
	name := strings.ReplaceAll(templateRef, "/", "-")
	switch path {
	case "/openapi.json":
		name += "-openapi.json"
	case "/docs", "/redoc":
		name += "-docs.html"
	default:
		return ""
	}
	return filepath.Join(c.dir, name)
}

func (c *specCache) load(templateRef, path string) ([]byte, bool) {
	f := c.file(templateRef, path)
	if f == "" {
		return nil, false
	}
	b, err := os.ReadFile(f)
	if err != nil || len(b) == 0 {
		return nil, false
	}
	switch path {
	case "/openapi.json":
		// A spec must be a JSON object; anything else (an error page, HTML)
		// is not cacheable content.
		if !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
			return nil, false
		}
	case "/docs", "/redoc":
		if !bytes.Contains(b, []byte("<")) {
			return nil, false
		}
	}
	return b, true
}

func (c *specCache) save(templateRef, path string, body []byte) {
	f := c.file(templateRef, path)
	if f == "" || len(body) == 0 || len(body) > 4<<20 {
		return
	}
	// Validate BEFORE persisting: only 200s with the right content shape are
	// cached (checked by the caller for the status; shape here).
	switch path {
	case "/openapi.json":
		if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
			return
		}
	case "/docs", "/redoc":
		if !bytes.Contains(body, []byte("<")) {
			return
		}
	}
	// os.CreateTemp: concurrent misses on the shared "<file>.tmp" name used
	// to race and lose each other's writes.
	tmp, err := os.CreateTemp(c.dir, ".spec-*")
	if err != nil {
		return
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return
	}
	if err := os.Rename(tmp.Name(), f); err != nil {
		_ = os.Remove(tmp.Name())
	}
}

// serveSpec answers the keyless spec/doc paths (/openapi.json, /docs,
// /redoc). GET and HEAD only: HEAD is served exactly like GET — net/http
// discards the response body for HEAD at the server layer — so a cheap
// probe still hits the cache. Every cache miss proxies under the FIXED
// internal specFetchKey; nothing here ever routes through routeNoAuth, so
// neither the request method nor the caller's X-User-Id/X-Session-Id can
// choose which identity's actor gets created or woken. (HEAD used to fall
// into routeNoAuth — Go's mux matches HEAD on GET patterns — which handed
// keyless callers keyless Acquire under arbitrary identities; any other
// method now gets a plain 405.)
func (s *Server) serveSpec(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, detail{"method not allowed"})
		return
	}
	switch r.URL.Path {
	case "/openapi.json", "/docs", "/redoc":
	default:
		// Defensive: only the three spec paths are registered to serveSpec.
		// If that ever widens, a stray path must degrade to a 404 — never
		// to a keyless actor proxy under the caller's headers.
		writeJSON(w, http.StatusNotFound, detail{"Not found"})
		return
	}
	if body, ok := s.specs.load(s.cfg.TemplateRef, r.URL.Path); ok {
		ct := "application/json"
		if r.URL.Path != "/openapi.json" {
			ct = "text/html; charset=utf-8"
		}
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body) // HEAD: the server strips the body itself
		return
	}
	// Cache miss — for GET and HEAD alike — always under specFetchKey.
	buf := &bytes.Buffer{}
	sw := &specRecorder{ResponseWriter: w, buf: buf}
	s.routeAs(r, sw, specFetchKey)
	if sw.code == http.StatusOK {
		// save() skips an empty body (a HEAD miss records nothing), so a
		// HEAD can never poison the cache with a bodiless response.
		s.specs.save(s.cfg.TemplateRef, r.URL.Path, buf.Bytes())
	}
}

// routeAs proxies to the actor for a FIXED route key (spec fetches: the
// caller's X-User-Id / X-Session-Id must not pick the identity).
func (s *Server) routeAs(r *http.Request, w http.ResponseWriter, key model.RouteKey) {
	ready, inflight, err := s.pl.Acquire(r.Context(), key)
	if err != nil {
		s.log.Warn("acquire failed", "key", key.LogString(), "path", r.URL.Path, "err", err)
		code, d := acquireStatus(err)
		writeJSON(w, code, d)
		return
	}
	defer inflight.Done()
	s.log.Debug("proxied request", "key", key.LogString(), "method", r.Method,
		"path", r.URL.Path, "actor", ready.Handle.Name)
	s.proxyFor(ready).ServeHTTP(w, r)
}

// specRecorder tees the proxied response body so a 200 can be cached.
type specRecorder struct {
	http.ResponseWriter
	buf  *bytes.Buffer
	code int
}

func (s *specRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *specRecorder) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	s.buf.Write(b)
	return s.ResponseWriter.Write(b)
}
