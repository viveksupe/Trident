package test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/egress"
)

// fakeChecker passes only known actors.
func fakeChecker(known map[string]string) egress.ActorChecker {
	return func(_ context.Context, actor string) (string, bool, error) {
		ate, ok := known[actor]
		return ate, ok, nil
	}
}

func TestEgressFlowStoreAndManager(t *testing.T) {
	st, err := egress.Open(filepath.Join(t.TempDir(), "egress.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	m := egress.New(st, nil, fakeChecker(map[string]string{
		"ot-uabc-c123": "ots-webui",
	}), log)

	// Unknown actor claims are rejected.
	if _, err := m.Submit(context.Background(), "ot-unknown-xyz", "example.com", ""); err == nil {
		t.Fatal("unknown actor must be rejected")
	}
	// Invalid hostnames rejected.
	if _, err := m.Submit(context.Background(), "ot-uabc-c123", "bad host/name", ""); err == nil {
		t.Fatal("invalid host rejected")
	}
	// Valid submit lands pending, dedups per (actor, host).
	r1, err := m.Submit(context.Background(), "ot-uabc-c123", "Example.COM.", "agent wants it")
	if err != nil {
		t.Fatal(err)
	}
	if r1.Host != "example.com" {
		t.Fatalf("host normalization: %q", r1.Host)
	}
	if r2, err := m.Submit(context.Background(), "ot-uabc-c123", "example.com", ""); err != nil || r2.ID != r1.ID {
		t.Fatalf("submit must dedup; %v %v", r2, err)
	}
	pending, _ := st.Pending()
	if len(pending) != 1 {
		t.Fatalf("want 1 pending, got %d", len(pending))
	}
	// DecideApproved atomically marks approval + grant + expiry; a negative
	// TTL produces an already-expired grant the same way a lapsed one does.
	if _, _, err := st.DecideApproved(r1.ID, -time.Minute); err != nil {
		t.Fatal(err)
	}
	live, err := st.Live()
	if err != nil || len(live) != 1 {
		t.Fatalf("live grants: %v %v", live, err)
	}
	if live[0].Expires.IsZero() {
		t.Fatal("DecideApproved did not persist the expiry")
	}
	// Double-decide is refused.
	if _, err := st.Decide(r1.ID, egress.StatusDenied); err == nil {
		t.Fatal("already-decided request must refuse a second decision")
	}
	// Deny a second request creates no grant.
	r2, err := m.Submit(context.Background(), "ot-uabc-c123", "other.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Deny(r2.ID); err != nil {
		t.Fatal(err)
	}
	if live, _ = st.Live(); len(live) != 1 {
		t.Fatalf("denied request must not create a grant; live=%d", len(live))
	}
	if _, err := m.Snapshot(); err != nil {
		t.Fatal(err)
	}
}

// newConfigFor loads the env-driven config for a test.
func newConfigFor(t *testing.T) (*config.Config, error) {
	t.Helper()
	cfg, err := config.Load()
	return cfg, err
}

func TestConsoleTokenDistinct(t *testing.T) {
	t.Setenv("TRI_API_KEY", "agent-facing-key")
	t.Setenv("TRI_ACTOR_API_KEY", "actor-side-key")
	t.Setenv("TRI_BACKEND", "substrate")
	t.Setenv("TRI_EGRESS_CALLBACK", "trident-callback.ot-workerpool.svc:8080")
	// Same console token as API key must be refused at startup.
	t.Setenv("TRI_CONSOLE_TOKEN", "agent-facing-key")
	if _, err := newConfigFor(t); err == nil {
		t.Fatal("console token equal to the agent key must fail validation")
	}
	t.Setenv("TRI_CONSOLE_TOKEN", "human-only-secret")
	if _, err := newConfigFor(t); err != nil {
		t.Fatalf("distinct console token must validate: %v", err)
	}
}

// The actor key must differ from the front key when the egress flow is on:
// agents hold the front key and reach the callback listener.
func TestActorKeyDistinct(t *testing.T) {
	t.Setenv("TRI_API_KEY", "agent-facing-key")
	t.Setenv("TRI_BACKEND", "substrate")
	t.Setenv("TRI_EGRESS_CALLBACK", "trident-callback.ot-workerpool.svc:8443")
	t.Setenv("TRI_CONSOLE_TOKEN", "human-only-secret")
	if _, err := newConfigFor(t); err == nil {
		t.Fatal("actor key equal to the front key must fail validation")
	}
	t.Setenv("TRI_ACTOR_API_KEY", "actor-side-key")
	if _, err := newConfigFor(t); err != nil {
		t.Fatalf("distinct actor key must validate: %v", err)
	}
}
