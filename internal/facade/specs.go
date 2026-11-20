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
)

type specCache struct {
	dir string
}

func newSpecCache(dir string) *specCache { return &specCache{dir: dir} }

// path returns the cache file for an ActorTemplate ref ("ns/name").
func (c *specCache) file(templateRef string) string {
	name := strings.ReplaceAll(templateRef, "/", "-") + "-openapi.json"
	if strings.Contains(name, "..") || !strings.HasPrefix(name, "open-terminal-") {
		// Namespace always prefixes the name; the prefix check keeps the
		// namespace from being a path traversal while allowing real names.
		if strings.Contains(templateRef, "..") {
			return ""
		}
	}
	return filepath.Join(c.dir, name)
}

func (c *specCache) load(templateRef string) ([]byte, bool) {
	f := c.file(templateRef)
	if f == "" {
		return nil, false
	}
	b, err := os.ReadFile(f)
	if err != nil || len(b) == 0 || !bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) {
		return nil, false
	}
	return b, true
}

func (c *specCache) save(templateRef string, body []byte) {
	f := c.file(templateRef)
	if f == "" || len(body) == 0 {
		return
	}
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, f)
}

// serveSpec answers keyless /openapi.json from the cache; on a miss it proxies
// to the actor as usual and records the body for next time. Returns true when
// the request was handled here.
func (s *Server) serveSpec(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet || r.URL.Path != "/openapi.json" {
		return false
	}
	if body, ok := s.specs.load(s.cfg.TemplateRef); ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return true
	}
	buf := &bytes.Buffer{}
	sw := &specRecorder{ResponseWriter: w, buf: buf}
	s.routeNoAuth(sw, r)
	if sw.code == http.StatusOK {
		s.specs.save(s.cfg.TemplateRef, buf.Bytes())
	}
	return true
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
