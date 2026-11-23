package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/facade"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/pool"
)

// fakeBackend implements backend.Backend over an in-process HTTP target,
// standing in for an actor.
type fakeBackend struct {
	mu       sync.Mutex
	targets  map[string]*httptest.Server // actor name -> target server
	created  []string
	failNext atomic.Bool
}

func newFakeBackend() *fakeBackend { return &fakeBackend{targets: map[string]*httptest.Server{}} }

func (f *fakeBackend) targetServer(handler http.HandlerFunc) *httptest.Server {
	s := httptest.NewServer(handler)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.targets["srv"] = s
	return s
}

func (f *fakeBackend) EnsureReady(ctx context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	f.mu.Lock()
	f.created = append(f.created, key.LogString())
	f.mu.Unlock()
	u, err := url.Parse(f.targetServerDefault().URL)
	if err != nil {
		return nil, nil, err
	}
	addr := strings.TrimPrefix(u.Host, "127.0.0.1:")
	return &backend.Handle{Key: key, Name: "fake-" + key.ActorName("ot-"), CreatedAt: time.Now()},
		backend.TCPDialer{Addr: "127.0.0.1:" + addr}, nil
}

var srvOnce sync.Once
var srvDefault *httptest.Server
var srvOwner *fakeBackend

func (f *fakeBackend) targetServerDefault() *httptest.Server {
	srvOnce.Do(func() {
		srvDefault = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Actor-Path", r.URL.Path)
			w.Header().Add("X-Forwarded-User", "")
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, `{"path":%q,"method":%q}`, r.URL.Path, r.Method)
		}))
	})
	return srvDefault
}

func (f *fakeBackend) Get(ctx context.Context, key model.RouteKey) (*backend.Handle, error) {
	return &backend.Handle{Key: key, Name: "fake-" + key.ActorName("ot-")}, nil
}
func (f *fakeBackend) Suspend(ctx context.Context, h *backend.Handle) error { return nil }
func (f *fakeBackend) Delete(ctx context.Context, h *backend.Handle) error  { return nil }
func (f *fakeBackend) ListReady(ctx context.Context) ([]backend.Handle, error) {
	return nil, nil
}

func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		APIKey: "test-key", ActorAPIKey: "test-key", Features: config.DefaultFeatures(),
		// Isolated dir: the spec cache persists per template next to the DB.
		StateDB: filepath.Join(t.TempDir(), "sessions.db"),
	}
}

func newFacade(t *testing.T) (*fakeBackend, *httptest.Server) {
	t.Helper()
	backendImpl := newFakeBackend()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(backendImpl, nil, log, time.Minute, time.Hour, time.Hour)
	pl.AllowSuspend = false
	s := facade.New(newTestConfig(t), pl, log)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return backendImpl, srv
}

func do(t *testing.T, srv *httptest.Server, method, path, key string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(body)
}

func TestFacadeAuthRequired(t *testing.T) {
	_, srv := newFacade(t)
	resp, body := do(t, srv, http.MethodGet, "/files/cwd", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 without key, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Invalid API key") {
		t.Fatalf("body %s lacks open-terminal error shape", body)
	}
}

func TestFacadeConfigIsPublicAndUnproxied(t *testing.T) {
	_, srv := newFacade(t)
	resp, body := do(t, srv, http.MethodGet, "/api/config", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("/api/config must be public, got %d", resp.StatusCode)
	}
	var parsed struct {
		Features map[string]bool `json:"features"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("features not JSON: %s", body)
	}
	if !parsed.Features["terminal"] || !parsed.Features["agents"] {
		t.Fatalf("features missing core flags: %v", parsed.Features)
	}
	if parsed.Features["browser"] || parsed.Features["desktop"] {
		t.Fatalf("browser/desktop must be off in v1: %v", parsed.Features)
	}
}

func TestFacadeTemplatesIs404JSON(t *testing.T) {
	_, srv := newFacade(t)
	resp, body := do(t, srv, http.MethodGet, "/api/v1/terminals/templates", "", nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("templates must 404, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "\"detail\"") {
		t.Fatalf("404 must be JSON detail shape: %s", body)
	}
}

func TestFacadeHealthz(t *testing.T) {
	_, srv := newFacade(t)
	resp, _ := do(t, srv, http.MethodGet, "/healthz", "", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("healthz: %d", resp.StatusCode)
	}
}

func TestFacadeProxiesToActorAndRoutesByChat(t *testing.T) {
	backendImpl, srv := newFacade(t)
	hdr := map[string]string{"X-User-Id": "user-1", "X-Session-Id": "chat-1"}
	resp, body := do(t, srv, http.MethodGet, "/files/list?directory=.", "test-key", hdr)
	if resp.StatusCode != 200 {
		t.Fatalf("proxy failed: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"/files/list"`) {
		t.Fatalf("actor did not see the path: %s", body)
	}
	// Same chat twice must hit the singleflight/created list once.
	_, _ = do(t, srv, http.MethodGet, "/files/cwd", "test-key", hdr)
	created := len(backendImpl.created)
	if created != 1 {
		t.Fatalf("route chats must map to one actor; creates=%d", created)
	}
}

func TestFacadeOpenAPIIsKeylessAndProxied(t *testing.T) {
	backendImpl, srv := newFacade(t)
	// Open WebUI fetches specs with no Authorization header at all.
	resp, body := do(t, srv, http.MethodGet, "/openapi.json", "", map[string]string{"X-User-Id": "u1"})
	if resp.StatusCode != 200 {
		t.Fatalf("keyless /openapi.json must proxy without auth, got %d (%s)", resp.StatusCode, body)
	}
	if !strings.Contains(body, `"path":"/openapi.json"`) {
		t.Fatalf("actor did not serve the path: %s", body)
	}
	if len(backendImpl.created) != 1 {
		t.Fatalf("expected one actor create for the adhoc route, got %d", len(backendImpl.created))
	}
}

func TestFacadeBadKeyVariants(t *testing.T) {
	_, srv := newFacade(t)
	resp, _ := do(t, srv, http.MethodGet, "/execute", "wrong-key", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong key must 401, got %d", resp.StatusCode)
	}
}

// newFacadeCapped mirrors newFacade on a pool with actor-creation caps (R3).
func newFacadeCapped(t *testing.T, maxActors, maxActorsPerUser int) *httptest.Server {
	t.Helper()
	backendImpl := newFakeBackend()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(backendImpl, nil, log, time.Minute, time.Hour, time.Hour)
	pl.AllowSuspend = false
	pl.MaxActors = maxActors
	pl.MaxActorsPerUser = maxActorsPerUser
	s := facade.New(newTestConfig(t), pl, log)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

// TestFacadeActorCapServes429 covers the R3 route-level contract: creates
// admit up to the cap, the next new header pair gets 429 with a STATIC
// detail (no caps, counts or identities leak), sessions at the cap keep
// working, and the per-user cap isolates one user's flood from everyone
// else.
func TestFacadeActorCapServes429(t *testing.T) {
	t.Run("global cap", func(t *testing.T) {
		srv := newFacadeCapped(t, 1, 0)
		u1c1 := map[string]string{"X-User-Id": "u1", "X-Session-Id": "c1"}

		resp, _ := do(t, srv, http.MethodGet, "/probe", "test-key", u1c1)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("first create: status = %d, want 200", resp.StatusCode)
		}
		resp, body := do(t, srv, http.MethodGet, "/probe", "test-key",
			map[string]string{"X-User-Id": "u1", "X-Session-Id": "c2"})
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("create past cap: status = %d body = %s, want 429", resp.StatusCode, body)
		}
		if !strings.Contains(body, `"detail":"actor capacity reached"`) {
			t.Fatalf("429 body must carry the static detail, got %s", body)
		}
		for _, leak := range []string{"TRI_MAX_ACTORS", "would exceed", `"u1"`} {
			if strings.Contains(body, leak) {
				t.Fatalf("429 detail leaks internals (%q): %s", leak, body)
			}
		}
		// The session at the cap keeps serving.
		resp, _ = do(t, srv, http.MethodGet, "/probe", "test-key", u1c1)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("session at the cap must keep working, status = %d", resp.StatusCode)
		}
	})

	t.Run("per-user cap isolates users", func(t *testing.T) {
		srv := newFacadeCapped(t, 10, 1) // headroom: only the per-user cap fires
		resp, _ := do(t, srv, http.MethodGet, "/probe", "test-key",
			map[string]string{"X-User-Id": "user-a", "X-Session-Id": "c1"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("user A first create: status = %d, want 200", resp.StatusCode)
		}
		resp, body := do(t, srv, http.MethodGet, "/probe", "test-key",
			map[string]string{"X-User-Id": "user-a", "X-Session-Id": "c2"})
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("user A past per-user cap: status = %d body = %s, want 429", resp.StatusCode, body)
		}
		// User A's cap must not block user B.
		resp, _ = do(t, srv, http.MethodGet, "/probe", "test-key",
			map[string]string{"X-User-Id": "user-b", "X-Session-Id": "c1"})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("user B must be unaffected by user A's cap, status = %d", resp.StatusCode)
		}
	})
}
