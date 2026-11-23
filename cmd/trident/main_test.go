package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/sessionmap"
)

// partialListBackend fails ListReady exactly the way ListActors refuses a
// non-provable listing. Every other Backend method is unreachable on
// purpose: reconcile must stop, not fall through to something else.
type partialListBackend struct {
	backend.Backend
	err   error
	calls int
}

func (b *partialListBackend) ListReady(context.Context) ([]backend.Handle, error) {
	b.calls++
	return nil, b.err
}

// recordingPurger captures egress bookkeeping purges.
type recordingPurger struct{ purged []string }

func (p *recordingPurger) PurgeActor(_ context.Context, actor string) error {
	p.purged = append(p.purged, actor)
	return nil
}

// TestReconcileRefusesPruneOnPartialListing (S9): when the backend cannot
// prove it saw every actor, reconcileOnRestart must prune no session rows
// and purge no egress bookkeeping — a truncated listing would otherwise
// unsupervise live actors and orphan their sessions.
func TestReconcileRefusesPruneOnPartialListing(t *testing.T) {
	store, err := sessionmap.Open(filepath.Join(t.TempDir(), "sessions.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer func() { _ = store.Close() }()

	key := model.NewRouteKey("user-1", "chat-1")
	if err := store.Put(sessionmap.Entry{
		UserID:    key.UserID,
		ChatID:    key.ChatID,
		ActorName: "tri-alive-actor",
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("put entry: %v", err)
	}

	be := &partialListBackend{err: errors.New(
		"list actors in test: empty page carries a continuation token; refusing a possibly-partial listing")}
	purger := &recordingPurger{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	if err := reconcileOnRestart(context.Background(), log, be, store, purger, nil); err == nil {
		t.Fatal("reconcile must refuse an unprovable listing")
	}
	if be.calls != 1 {
		t.Fatalf("ListReady calls = %d, want exactly 1", be.calls)
	}
	all, aerr := store.All()
	if aerr != nil {
		t.Fatalf("store.All: %v", aerr)
	}
	if len(all) != 1 {
		t.Fatalf("session rows pruned on a partial listing: %d of 1 remain", len(all))
	}
	if len(purger.purged) != 0 {
		t.Fatalf("egress bookkeeping purged on a partial listing: %v", purger.purged)
	}
}
