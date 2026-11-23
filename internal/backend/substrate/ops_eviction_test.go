package substrate

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/model"
)

// opHas reports whether the op table currently holds name (test helper —
// reads the table under its mutex, like production callers do indirectly).
func opHas(b *Backend, name string) bool {
	b.ops.mu.Lock()
	defer b.ops.mu.Unlock()
	_, ok := b.ops.entries[name]
	return ok
}

// TestOpRecordEvictedOnDelete covers the terminal-eviction half of finding
// R3: a completed Delete drops the actor's op record AND its strike chain —
// no per-actor bytes survive the actor.
func TestOpRecordEvictedOnDelete(t *testing.T) {
	f := &fakeControl{}
	l := newPolicyLifecycle(f)
	b := newTestBackend(f, l)
	ctx := context.Background()

	key := model.NewRouteKey("user-1", "chat-del")
	name := key.ActorName(b.prefix)

	if _, _, err := b.EnsureReady(ctx, key); err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if got := b.ops.size(); got != 1 {
		t.Fatalf("op records after EnsureReady = %d, want 1", got)
	}
	// Seed a strike chain to prove terminal delete removes ALL bookkeeping.
	b.selfHealStrikes.Store(name, 2)

	if err := b.Delete(ctx, &backend.Handle{Name: name}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if f.deleteActorCalls != 1 {
		t.Fatalf("DeleteActor calls = %d, want 1", f.deleteActorCalls)
	}
	if got := b.ops.size(); got != 0 {
		t.Fatalf("op records after Delete = %d, want 0", got)
	}
	if opHas(b, name) {
		t.Fatal("deleted actor's op record survived")
	}
	if _, ok := b.selfHealStrikes.Load(name); ok {
		t.Fatal("strike chain survived terminal delete")
	}
}

// TestOpCacheBoundedUnderChurn is the insert-only regression test for
// finding R3: 1000 create/complete actor cycles must leave zero records —
// the old sync.Map accumulated one mutex per cycle (1000 entries here).
func TestOpCacheBoundedUnderChurn(t *testing.T) {
	f := &fakeControl{}
	l := newPolicyLifecycle(f)
	b := newTestBackend(f, l)
	ctx := context.Background()

	for i := 0; i < 1000; i++ {
		key := model.NewRouteKey("user-1", fmt.Sprintf("chat-%d", i))
		if _, _, err := b.EnsureReady(ctx, key); err != nil {
			t.Fatalf("cycle %d EnsureReady: %v", i, err)
		}
		if n := b.ops.size(); n != 1 {
			t.Fatalf("cycle %d: op records while actor live = %d, want 1", i, n)
		}
		if err := b.Delete(ctx, &backend.Handle{Name: key.ActorName(b.prefix)}); err != nil {
			t.Fatalf("cycle %d Delete: %v", i, err)
		}
		if n := b.ops.size(); n != 0 {
			t.Fatalf("cycle %d: op records after Delete = %d, want 0 (insert-only regression)", i, n)
		}
	}
}

// TestOpCacheCapEvictsOldestRecord covers the safety-cap half of finding
// R3: TRI_OPS_CACHE_MAX bounds the table even when nothing is deleted,
// evicting oldest records first; evicted records are re-created on next use.
func TestOpCacheCapEvictsOldestRecord(t *testing.T) {
	b := &Backend{opCacheMax: 8}

	for i := 0; i < 50; i++ {
		unlock := b.lockOp(fmt.Sprintf("actor-%03d", i))
		unlock()
	}
	if n := b.ops.size(); n != 8 {
		t.Fatalf("op table size = %d, want cap 8", n)
	}
	if opHas(b, "actor-000") {
		t.Fatal("oldest record should have been evicted at the cap")
	}
	if !opHas(b, "actor-049") {
		t.Fatal("newest record missing after cap eviction")
	}

	// Tradeoff: an evicted record is re-created on next use — locking the
	// oldest actor again works and re-serializes as before.
	unlock := b.lockOp("actor-000")
	if !opHas(b, "actor-000") {
		t.Fatal("re-locking an evicted actor should recreate its record")
	}
	unlock()

	// Unconfigured Backend falls back to the default bound instead of
	// growing without limit.
	var zero Backend
	u := zero.lockOp("fallback")
	u()
	if n := zero.ops.size(); n != 1 {
		t.Fatalf("zero-value Backend op records = %d, want 1", n)
	}
}

// TestEnsureReadyAfterEvictionNoStaleOp: after a terminal eviction, the
// next EnsureReady must succeed with fresh bookkeeping — no stale-record
// misuse (the lock verify/retry loop) and no dependence on the old record.
func TestEnsureReadyAfterEvictionNoStaleOp(t *testing.T) {
	f := &fakeControl{}
	l := newPolicyLifecycle(f)
	b := newTestBackend(f, l)
	ctx := context.Background()

	key := model.NewRouteKey("user-1", "chat-re")
	name := key.ActorName(b.prefix)

	if _, _, err := b.EnsureReady(ctx, key); err != nil {
		t.Fatalf("first EnsureReady: %v", err)
	}
	if err := b.Delete(ctx, &backend.Handle{Name: name}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if n := b.ops.size(); n != 0 {
		t.Fatalf("op records after Delete = %d, want 0", n)
	}

	// Re-ensure after eviction: the actor is recreated and the op record
	// re-created with it — identical behavior to a fresh backend.
	h, d, err := b.EnsureReady(ctx, key)
	if err != nil {
		t.Fatalf("EnsureReady after eviction: %v", err)
	}
	if h == nil || d == nil {
		t.Fatal("EnsureReady after eviction returned nil handle/dialer")
	}
	if n := b.ops.size(); n != 1 {
		t.Fatalf("op records after re-ensure = %d, want 1", n)
	}
	if _, _, err := b.EnsureReady(ctx, key); err != nil {
		t.Fatalf("second EnsureReady (record reuse): %v", err)
	}
}

// TestConcurrentEnsureDeleteRace drives interleaved EnsureReady and Delete
// for one actor name through the eviction path; the race detector must stay
// clean and the record count must stay bounded (at most one per name).
// This also exercises lockOp's verify/retry: a waiter that fetched a record
// evicted by a concurrent delete must re-serialize, never run in parallel
// on the stale mutex.
func TestConcurrentEnsureDeleteRace(t *testing.T) {
	f := &fakeControl{}
	l := newPolicyLifecycle(f)
	b := newTestBackend(f, l)
	ctx := context.Background()

	key := model.NewRouteKey("user-1", "chat-race")
	name := key.ActorName(b.prefix)

	var wg sync.WaitGroup
	const iters = 16
	for i := 0; i < iters; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _, _ = b.EnsureReady(ctx, key)
		}()
		go func() {
			defer wg.Done()
			_ = b.Delete(ctx, &backend.Handle{Name: name})
		}()
	}
	wg.Wait()

	if n := b.ops.size(); n > 1 {
		t.Fatalf("op records after concurrent ensure+delete = %d, want <= 1", n)
	}
}
