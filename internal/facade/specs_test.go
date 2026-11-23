package facade

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/pool"
)

// specFakeBackend is an in-process actor target that records the identity of
// every EnsureReady it receives, so tests can assert WHICH route key a
// request woke — the whole point of the fixed specFetchKey.
type specFakeBackend struct {
	mu      sync.Mutex
	created []string
	target  *httptest.Server
}

func newSpecFakeBackend() *specFakeBackend {
	f := &specFakeBackend{}
	f.target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"path":%q,"method":%q}`, r.URL.Path, r.Method)
	}))
	return f
}

func (f *specFakeBackend) EnsureReady(_ context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	f.mu.Lock()
	f.created = append(f.created, key.LogString())
	f.mu.Unlock()
	u, err := url.Parse(f.target.URL)
	if err != nil {
		return nil, nil, err
	}
	return &backend.Handle{Key: key, Name: "fake-" + key.ActorName("ot-"), CreatedAt: time.Now()},
		backend.TCPDialer{Addr: u.Host}, nil
}

func (f *specFakeBackend) Get(context.Context, model.RouteKey) (*backend.Handle, error) {
	return nil, nil
}
func (f *specFakeBackend) Suspend(context.Context, *backend.Handle) error { return nil }
func (f *specFakeBackend) Delete(context.Context, *backend.Handle) error  { return nil }
func (f *specFakeBackend) ListReady(context.Context) ([]backend.Handle, error) {
	return nil, nil
}

func (f *specFakeBackend) creates() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.created))
	copy(out, f.created)
	return out
}

func (f *specFakeBackend) Close() { f.target.Close() }

// assertCreated fails when the backend saw any identity other than want.
func assertCreated(t *testing.T, f *specFakeBackend, want ...string) {
	t.Helper()
	got := f.creates()
	if len(got) != len(want) {
		t.Fatalf("backend woke %v, want exactly %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("backend woke %v, want exactly %v", got, want)
		}
	}
}

func newSpecTestConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		APIKey: "front-key", ActorAPIKey: "front-key",
		TemplateRef: "ots-webui/open-terminal",
		// Isolated dir: the spec cache persists per template next to the DB.
		StateDB:  filepath.Join(t.TempDir(), "sessions.db"),
		Features: config.DefaultFeatures(),
	}
}

type specFixture struct {
	backend *specFakeBackend
	srv     *httptest.Server
	server  *Server
}

func newSpecFixture(t *testing.T) *specFixture {
	t.Helper()
	fb := newSpecFakeBackend()
	t.Cleanup(fb.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(fb, nil, log, time.Minute, time.Hour, time.Hour)
	pl.AllowSuspend = false
	s := New(newSpecTestConfig(t), pl, log)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &specFixture{backend: fb, srv: srv, server: s}
}

func specDo(t *testing.T, srv *httptest.Server, method, path string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(b)
}

// victimHeaders are a hostile caller's identity spoofing on a keyless path.
func victimHeaders() map[string]string {
	return map[string]string{"X-User-Id": "victim-user", "X-Session-Id": "victim-chat"}
}

// TestSpecHEADFetchesOnlyFixedIdentity pins finding S2: a keyless HEAD on a
// spec path must fetch under the FIXED specFetchKey — never under the
// caller's X-User-Id/X-Session-Id (HEAD used to fall into routeNoAuth,
// letting any caller create or wake actors for arbitrary identities).
func TestSpecHEADFetchesOnlyFixedIdentity(t *testing.T) {
	fx := newSpecFixture(t)

	resp, body := specDo(t, fx.srv, http.MethodHead, "/openapi.json", victimHeaders())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless HEAD /openapi.json: got %d (%s)", resp.StatusCode, body)
	}
	if body != "" {
		t.Fatalf("HEAD response must carry no body, got %q", body)
	}
	// The ONLY identity ever woken is the fixed internal spec identity.
	assertCreated(t, fx.backend, specFetchKey.LogString())

	// A follow-up GET (same cold cache, same spoofed headers) reuses the
	// same fixed identity: still exactly one EnsureReady, no victim actor.
	resp, body = specDo(t, fx.srv, http.MethodGet, "/openapi.json", victimHeaders())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("keyless GET /openapi.json: got %d (%s)", resp.StatusCode, body)
	}
	assertCreated(t, fx.backend, specFetchKey.LogString())
}

// TestSpecHEADServedFromCache pins that HEAD hits the cache like GET: with
// the actor target gone (and pooled conns drained), a HEAD that went to the
// proxy would 502 — a cache hit still answers 200 without any new actor
// activity.
func TestSpecHEADServedFromCache(t *testing.T) {
	fx := newSpecFixture(t)

	resp, body := specDo(t, fx.srv, http.MethodGet, "/openapi.json", victimHeaders())
	if resp.StatusCode != http.StatusOK || body == "" {
		t.Fatalf("cache-warming GET: %d (%s)", resp.StatusCode, body)
	}
	assertCreated(t, fx.backend, specFetchKey.LogString())

	// Kill every path to the actor: drain pooled transport conns (we are in
	// package facade, the transports map is ours) and close the target.
	fx.server.transports.Range(func(_, v any) bool {
		if tr, ok := v.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
		return true
	})
	fx.backend.target.Close()

	resp, body = specDo(t, fx.srv, http.MethodHead, "/openapi.json", victimHeaders())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEAD must be served from cache, got %d (%s)", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("cached HEAD Content-Type = %q, want application/json", ct)
	}
	if body != "" {
		t.Fatalf("HEAD response must carry no body, got %q", body)
	}
	assertCreated(t, fx.backend, specFetchKey.LogString()) // nothing new was woken
}

// TestSpecPathOtherMethods405 pins that only GET and HEAD are accepted on
// spec paths. The patterns are registered method-agnostically so the 405 is
// reachable end to end (a "GET /..." pattern would let POST fall through to
// the authenticated "/" proxy instead).
func TestSpecPathOtherMethods405(t *testing.T) {
	fx := newSpecFixture(t)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/openapi.json"},
		{http.MethodPut, "/docs"},
		{http.MethodDelete, "/redoc"},
	} {
		resp, body := specDo(t, fx.srv, tc.method, tc.path, victimHeaders())
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("%s %s: got %d (%s), want 405", tc.method, tc.path, resp.StatusCode, body)
		}
		if allow := resp.Header.Get("Allow"); allow != "GET, HEAD" {
			t.Fatalf("%s %s: Allow = %q, want \"GET, HEAD\"", tc.method, tc.path, allow)
		}
	}
	// Not one of those probes may have touched the pool.
	assertCreated(t, fx.backend)
}

// TestSpecServeDefensivePathNeverProxies pins the defensive arm inside
// serveSpec: a path it was not meant to serve must 404 rather than degrade
// into a keyless actor proxy under the caller's headers.
func TestSpecServeDefensivePathNeverProxies(t *testing.T) {
	fx := newSpecFixture(t)

	req := httptest.NewRequest(http.MethodGet, "/not-a-spec-path", nil)
	for k, v := range victimHeaders() {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	fx.server.serveSpec(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("stray path: got %d, want 404", rec.Code)
	}
	assertCreated(t, fx.backend) // no acquire happened at all
}
