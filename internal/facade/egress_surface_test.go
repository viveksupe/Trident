package facade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/egress"
	"github.com/viveksupe/Trident/internal/pool"
)

type egressFixture struct {
	main *httptest.Server // Listener() equivalent: s.Handler()
	cbk  *httptest.Server // TLS callback listener equivalent: s.CallbackHandler()
	mgr  *egress.Manager
	srv  *Server
	fb   *specFakeBackend
}

// newEgressFixture wires a Server with a live egress flow and BOTH
// listeners, mirroring cmd/trident/main.go: fs.Handler() serves the public
// mux, fs.CallbackHandler() serves the callback TLS listener.
func newEgressFixture(t *testing.T) *egressFixture {
	t.Helper()
	cfg := newSpecTestConfig(t)
	cfg.ConsoleToken = "human-console-secret"
	cfg.EgressCallback = "trident-callback.ns.svc:8443"
	fb := newSpecFakeBackend()
	t.Cleanup(fb.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(fb, nil, log, time.Minute, time.Hour, time.Hour)
	pl.AllowSuspend = false
	st, err := egress.Open(filepath.Join(t.TempDir(), "egress.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	mgr := egress.New(st, nil, func(_ context.Context, actor string) (string, bool, error) {
		return "ots-webui", strings.HasPrefix(actor, "ot-"), nil
	}, log)
	s := New(cfg, pl, log)
	s.SetEgress(mgr)
	main := httptest.NewServer(s.Handler())
	t.Cleanup(main.Close)
	cbk := httptest.NewServer(s.CallbackHandler())
	t.Cleanup(cbk.Close)
	return &egressFixture{main: main, cbk: cbk, mgr: mgr, srv: s, fb: fb}
}

func egressDo(t *testing.T, srv *httptest.Server, method, urlPath, body string) (*http.Response, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+urlPath, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// Never follow redirects: the console compat route answers 301 and the
	// test asserts the status itself.
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp, string(b)
}

func wantStatus(t *testing.T, resp *http.Response, body string, want int, what string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s: got %d (%s), want %d", what, resp.StatusCode, strings.TrimSpace(body), want)
	}
}

// TestEgressSplitRegistration pins finding S5: the main (public) listener
// serves the human console and NEVER the actor-facing callback endpoints,
// while the callback listener serves the actor endpoints and never the
// console or the front-side proxy (Handler's doc: CallbackHandler must be
// built from Handler() never, or X-User-Id identity routing becomes
// reachable from the cluster side of the callback rule).
func TestEgressSplitRegistration(t *testing.T) {
	fx := newEgressFixture(t)

	// --- Public listener: console yes, actor routes NO. ---
	// Actor routes must fall through to the authenticated "/" proxy.
	resp, body := egressDo(t, fx.main, http.MethodGet, "/_tri/egress/helper.sh", "")
	wantStatus(t, resp, body, http.StatusUnauthorized, "main helper.sh (actor route must be absent)")
	if !strings.Contains(body, "Invalid API key") {
		t.Fatalf("main helper.sh must hit the front auth, got %q", body)
	}
	if strings.Contains(body, "tri-egress-request") {
		t.Fatalf("actor helper leaked onto the public listener: %q", body)
	}

	resp, body = egressDo(t, fx.main, http.MethodPost, "/_tri/egress/request",
		`{"actor":"ot-ucaller-c1","host":"example.com","reason":"r"}`)
	wantStatus(t, resp, body, http.StatusUnauthorized, "main POST /_tri/egress/request (must be absent)")
	if strings.Contains(body, "too many") || strings.Contains(body, "claim") {
		t.Fatalf("egress submit handler ran on the public listener: %q", body)
	}
	if r, _ := fx.mgr.GetRequest(1); r != nil {
		t.Fatalf("public POST must not file an egress request, got %+v", r)
	}

	resp, body = egressDo(t, fx.main, http.MethodGet, "/_tri/egress/request/1?actor=x", "")
	wantStatus(t, resp, body, http.StatusUnauthorized, "main request status (must be absent)")
	if strings.Contains(body, "actor claim") {
		t.Fatalf("status handler ran on the public listener: %q", body)
	}

	// Console IS on the public listener: page, compat redirect, API (401
	// without the console bearer).
	resp, body = egressDo(t, fx.main, http.MethodGet, "/_trident/console/egress", "")
	wantStatus(t, resp, body, http.StatusOK, "main console page")
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("console page Content-Type = %q", ct)
	}
	resp, body = egressDo(t, fx.main, http.MethodGet, "/_tri/console/egress", "")
	wantStatus(t, resp, body, http.StatusFound, "main console compat redirect")
	resp, body = egressDo(t, fx.main, http.MethodGet, "/_trident/console/egress/api/state", "")
	wantStatus(t, resp, body, http.StatusUnauthorized, "main console API without bearer")

	// --- Callback listener: actor routes yes, console/proxy NO. ---
	resp, body = egressDo(t, fx.cbk, http.MethodGet, "/_tri/egress/helper.sh", "")
	wantStatus(t, resp, body, http.StatusOK, "callback helper.sh")
	if !strings.Contains(body, "tri-egress-request") {
		t.Fatalf("callback helper.sh content: %q", body)
	}
	// Missing claim is 400 there — proves the status handler lives here.
	resp, body = egressDo(t, fx.cbk, http.MethodGet, "/_tri/egress/request/1", "")
	wantStatus(t, resp, body, http.StatusBadRequest, "callback status without claim")

	// Console is absent: no console routes, and no catch-all either.
	for _, p := range []string{
		"/_trident/console/egress",
		"/_trident/console/egress/api/state",
		"/_tri/console/egress",
		// Front-side surfaces must never appear on the actor listener:
		// X-User-Id identity routing would be reachable from inside the
		// cluster's pre-approved callback rule.
		"/",
		"/openapi.json",
		"/api/config",
	} {
		resp, body = egressDo(t, fx.cbk, http.MethodGet, p, "")
		wantStatus(t, resp, body, http.StatusNotFound, "callback listener must not serve "+p)
	}

	// None of these probes may have woken any actor.
	assertCreated(t, fx.fb)
}

// TestEgressStatusRequiresActorClaim pins that the optional ?actor= claim on
// GET /_tri/egress/request/{id} is now mandatory and verified: request ids
// are sequential int64s, so an absent claim would let anyone enumerate
// statuses, and a wrong claim must read as 404 (not 403/400) so the check
// itself cannot confirm that an id exists.
func TestEgressStatusRequiresActorClaim(t *testing.T) {
	fx := newEgressFixture(t)

	resp, body := egressDo(t, fx.cbk, http.MethodPost, "/_tri/egress/request",
		`{"actor":"ot-ucaller-c1","host":"example.com","reason":"why"}`)
	wantStatus(t, resp, body, http.StatusOK, "file request")
	var filed struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &filed); err != nil || filed.ID == 0 {
		t.Fatalf("filed request id: %q (%v)", body, err)
	}
	statusPath := "/_tri/egress/request/" + strconv.FormatInt(filed.ID, 10)

	// Missing claim -> 400, actionable and mandatory.
	resp, body = egressDo(t, fx.cbk, http.MethodGet, statusPath, "")
	wantStatus(t, resp, body, http.StatusBadRequest, "status without actor claim")
	if !strings.Contains(body, "actor claim is required") {
		t.Fatalf("missing claim error: %q", body)
	}

	// Wrong claim -> 404, phrased exactly like a nonexistent id so the
	// response cannot be used as an existence oracle.
	resp, wrongClaim := egressDo(t, fx.cbk, http.MethodGet, statusPath+"?actor=ot-uintruder-c1", "")
	wantStatus(t, resp, wrongClaim, http.StatusNotFound, "status with wrong claim")
	resp, missingID := egressDo(t, fx.cbk, http.MethodGet,
		"/_tri/egress/request/999999?actor=ot-uintruder-c1", "")
	wantStatus(t, resp, missingID, http.StatusNotFound, "status with nonexistent id")
	if wrongClaim != missingID {
		t.Fatalf("mismatch and missing must be indistinguishable: %q vs %q", wrongClaim, missingID)
	}

	// Right claim -> 200 with the request.
	resp, body = egressDo(t, fx.cbk, http.MethodGet, statusPath+"?actor=ot-ucaller-c1", "")
	wantStatus(t, resp, body, http.StatusOK, "status with owning claim")
	if !strings.Contains(body, "example.com") {
		t.Fatalf("owning claim response: %q", body)
	}
}

// TestEgressGlobalPendingCap pins the bounded global queue: once
// MaxPendingGlobal requests are pending, a NEW ask is refused with the
// sentinel error (429 on the wire), while dedup still answers re-asks of an
// already-filed (actor, host) — the cap sits after dedup on purpose.
func TestEgressGlobalPendingCap(t *testing.T) {
	fx := newEgressFixture(t)

	ctx := context.Background()
	for i := 0; i < egress.MaxPendingGlobal; i++ {
		actor := fmt.Sprintf("ot-u%04d-c1", i)
		host := fmt.Sprintf("h%d.example.com", i)
		req, err := fx.mgr.Submit(ctx, actor, host, "")
		if err != nil {
			t.Fatalf("pending %d/%d must file: %v", i, egress.MaxPendingGlobal, err)
		}
		if i == 0 && req == nil {
			t.Fatal("first submit must return the request")
		}
	}

	// Beyond the cap: sentinel error from the manager…
	_, err := fx.mgr.Submit(ctx, "ot-unew-c1", "overflow.example.com", "")
	if !errors.Is(err, egress.ErrTooManyPending) {
		t.Fatalf("513th submit: got %v, want ErrTooManyPending", err)
	}
	// …and HTTP 429 (not 400) from the callback endpoint.
	resp, body := egressDo(t, fx.cbk, http.MethodPost, "/_tri/egress/request",
		`{"actor":"ot-unew-c1","host":"overflow2.example.com","reason":""}`)
	wantStatus(t, resp, body, http.StatusTooManyRequests, "submit beyond global cap")
	if !strings.Contains(body, "too many pending") {
		t.Fatalf("429 body: %q", body)
	}

	// Dedup still answers at cap: the first (actor, host) re-ask returns
	// its existing id with 200, no new row.
	resp, body = egressDo(t, fx.cbk, http.MethodPost, "/_tri/egress/request",
		`{"actor":"ot-u0000-c1","host":"h0.example.com","reason":""}`)
	wantStatus(t, resp, body, http.StatusOK, "dedup re-ask at cap")
	var dup struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &dup); err != nil || dup.ID == 0 {
		t.Fatalf("dedup id: %q (%v)", body, err)
	}
	first, ferr := fx.mgr.GetRequest(1)
	if ferr != nil || first == nil {
		t.Fatalf("first request must exist: %v", ferr)
	}
	if dup.ID != first.ID {
		t.Fatalf("dedup at cap returned id %d, want the existing %d", dup.ID, first.ID)
	}
}

// TestEgressFlowOffRegistersNoRoutes pins the guards left behind after
// RegisterEgress was split: with no egress flow configured (the main.go
// default), neither listener serves any egress/console route.
func TestEgressFlowOffRegistersNoRoutes(t *testing.T) {
	fb := newSpecFakeBackend()
	t.Cleanup(fb.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(fb, nil, log, time.Minute, time.Hour, time.Hour)
	pl.AllowSuspend = false
	s := New(newSpecTestConfig(t), pl, log) // no EgressCallback, no SetEgress
	main := httptest.NewServer(s.Handler())
	t.Cleanup(main.Close)
	cbk := httptest.NewServer(s.CallbackHandler())
	t.Cleanup(cbk.Close)

	resp, body := egressDo(t, main, http.MethodGet, "/_trident/console/egress", "")
	wantStatus(t, resp, body, http.StatusUnauthorized, "console page with flow off falls to front auth")
	resp, body = egressDo(t, cbk, http.MethodGet, "/_tri/egress/helper.sh", "")
	wantStatus(t, resp, body, http.StatusNotFound, "callback helper with flow off")
	resp, body = egressDo(t, cbk, http.MethodGet, "/_trident/console/egress", "")
	wantStatus(t, resp, body, http.StatusNotFound, "callback console with flow off")
}
