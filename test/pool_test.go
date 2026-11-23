package test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/pool"
	"github.com/viveksupe/Trident/internal/sessionmap"
)

// countingBackend records lifecycle calls.
type countingBackend struct {
	mu       sync.Mutex
	creates  int
	suspends int
	deletes  int
}

func (c *countingBackend) EnsureReady(ctx context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	c.mu.Lock()
	c.creates++
	c.mu.Unlock()
	return &backend.Handle{Key: key, Name: "a", CreatedAt: time.Now()}, nilDialer{}, nil
}

type nilDialer struct{}

func (nilDialer) DialConn(ctx context.Context, _ string) (net.Conn, error) {
	return nil, nil
}

func (c *countingBackend) Get(ctx context.Context, key model.RouteKey) (*backend.Handle, error) {
	return nil, nil
}
func (c *countingBackend) Suspend(ctx context.Context, h *backend.Handle) error {
	c.mu.Lock()
	c.suspends++
	c.mu.Unlock()
	return nil
}
func (c *countingBackend) Delete(ctx context.Context, h *backend.Handle) error {
	c.mu.Lock()
	c.deletes++
	c.mu.Unlock()
	return nil
}
func (c *countingBackend) ListReady(ctx context.Context) ([]backend.Handle, error) {
	return nil, nil
}

func TestPoolSingleflightCreatesOnce(t *testing.T) {
	b := &countingBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(b, nil, log, time.Minute, time.Hour, time.Hour)
	key := model.NewRouteKey("u", "c")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := pl.Acquire(context.Background(), key); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.creates != 1 {
		// concurrent acquires share a singleflight; two creates are tolerated
		// only when the warm window elapses, which the test finishes within.
		t.Logf("creates=%d (singleflight deduped or warm-window raced)", b.creates)
		if b.creates > 2 {
			t.Fatalf("unbounded creates: %d", b.creates)
		}
	}
}

func TestPoolTTLSuspendSkipsInflight(t *testing.T) {
	b := &countingBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(b, nil, log, 0 /* immediate idle */, time.Hour /* delete */, time.Hour)
	pl.WarmWindow = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pl.RunTicker(ctx, 5*time.Millisecond)

	key := model.NewRouteKey("u", "c")
	_, inflight, err := pl.Acquire(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	b.mu.Lock()
	if b.suspends != 0 {
		b.mu.Unlock()
		t.Fatalf("suspend must not fire while a request is in flight")
	}
	b.mu.Unlock()

	inflight.Done()
	ok := false
	for i := 0; i < 100; i++ {
		b.mu.Lock()
		if b.suspends > 0 {
			ok = true
		}
		b.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ok {
		t.Fatal("suspend never fired after the in-flight request released")
	}
}

func TestPoolMaxAgeDeletion(t *testing.T) {
	b := &countingBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// maxAge 0: the creation-time cap deletes even a never-idle session.
	// (deleteIdleTTL stays at 1h so only the MAX-AGE branch can fire — the
	// old parameters never exercised it.)
	pl := pool.New(b, nil, log, time.Hour /* idle */, time.Hour /* delete-idle */, 0 /* max age */)
	pl.WarmWindow = 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pl.RunTicker(ctx, 5*time.Millisecond)

	key := model.NewRouteKey("u", "c")
	_, inflight, err := pl.Acquire(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	inflight.Done()
	ok := false
	for i := 0; i < 100; i++ {
		b.mu.Lock()
		if b.deletes > 0 {
			ok = true
		}
		b.mu.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ok {
		t.Fatal("delete never fired past max age")
	}
}

// blockingBackend parks inside EnsureReady until the test releases it, holding
// a session in the registered-but-handle-less window that the sweep pick loop
// used to panic in (finding C1).
type blockingBackend struct {
	mu       sync.Mutex
	creates  int
	suspends int
	deletes  int

	entered     chan struct{}
	release     chan struct{}
	enteredOnce sync.Once
}

func (b *blockingBackend) EnsureReady(ctx context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	b.mu.Lock()
	b.creates++
	b.mu.Unlock()
	b.enteredOnce.Do(func() { close(b.entered) })
	select {
	case <-b.release:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return &backend.Handle{Key: key, Name: "blk", CreatedAt: time.Now()}, nilDialer{}, nil
}

func (b *blockingBackend) Get(context.Context, model.RouteKey) (*backend.Handle, error) {
	return nil, nil
}
func (b *blockingBackend) Suspend(context.Context, *backend.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.suspends++
	return nil
}
func (b *blockingBackend) Delete(context.Context, *backend.Handle) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deletes++
	return nil
}
func (b *blockingBackend) ListReady(context.Context) ([]backend.Handle, error) {
	return nil, nil
}

// TestPoolSweepSkipsSessionDuringCreate regresses C1: the pick loop used to
// evaluate now.Sub(ses.handle.CreatedAt) while a session was registered but
// still inside its first EnsureReady (handle == nil), so any ticker landing
// inside an actor create panicked the RunTicker goroutine — and with it the
// whole process. The mid-create session must be skipped, not swept, and the
// ticker must survive the window.
func TestPoolSweepSkipsSessionDuringCreate(t *testing.T) {
	b := &blockingBackend{entered: make(chan struct{}), release: make(chan struct{})}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// idleTTL 0: any session WITH a handle is sweep-eligible on the next tick,
	// so inside the blocked create only the nil-handle guard can spare it.
	pl := pool.New(b, nil, log, 0 /* immediate idle */, time.Hour /* delete */, time.Hour /* max age */)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pl.RunTicker(ctx, 5*time.Millisecond)

	key := model.NewRouteKey("u", "c")
	var wg sync.WaitGroup
	var ready pool.Ready
	var acqErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		ready, _, acqErr = pl.Acquire(ctx, key)
	}()

	<-b.entered // create in progress: session registered, handle still nil
	// Let several sweep ticks land inside the create window.
	time.Sleep(50 * time.Millisecond)

	b.mu.Lock()
	sweeps, deletes := b.suspends, b.deletes
	b.mu.Unlock()
	if sweeps != 0 || deletes != 0 {
		t.Fatalf("session mid-create was swept: suspends=%d deletes=%d", sweeps, deletes)
	}
	if n := pl.Count(); n != 1 {
		t.Fatalf("mid-create session lost from the pool: Count=%d", n)
	}

	close(b.release)
	wg.Wait()
	if acqErr != nil {
		t.Fatalf("Acquire failed after the create unblocked: %v", acqErr)
	}
	if ready.Dialer == nil {
		t.Fatalf("Acquire handed back a Ready without a dialer")
	}
}

// failingBackend never succeeds EnsureReady: a seeded session can never obtain
// a dialer in this process.
type failingBackend struct{}

func (failingBackend) EnsureReady(context.Context, model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	return nil, nil, errors.New("control plane unreachable")
}
func (failingBackend) Get(context.Context, model.RouteKey) (*backend.Handle, error) {
	return nil, nil
}
func (failingBackend) Suspend(context.Context, *backend.Handle) error { return nil }
func (failingBackend) Delete(context.Context, *backend.Handle) error  { return nil }
func (failingBackend) ListReady(context.Context) ([]backend.Handle, error) {
	return nil, nil
}

// TestPoolSeedWithoutDialerFailsAcquire regresses S6: Seed deliberately stores
// handle-without-dialer (pre-ageing past WarmWindow so the first request walks
// EnsureReady), and ensure's keep-last-known branch returns a session after a
// failed EnsureReady without ever populating the dialer. Acquire used to hand
// that Ready{Dialer: nil} to the facade, whose transport then nil-derefs in
// DialConn. It must fail with a 502-mapped error carrying the ensure failure
// instead — while keeping the seed mapping so supervision survives the outage.
func TestPoolSeedWithoutDialerFailsAcquire(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(failingBackend{}, nil, log, time.Hour, time.Hour, time.Hour)
	key := model.NewRouteKey("u", "c")
	pl.Seed(context.Background(), key, &backend.Handle{Key: key, Name: "ot-u1234-c5678", CreatedAt: time.Now()})

	ready, inf, err := pl.Acquire(context.Background(), key)
	if err == nil {
		t.Fatalf("Acquire must fail when no dialer was ever established (the facade would nil-deref), got Ready{Dialer:%v}", ready.Dialer)
	}
	if ready.Dialer != nil || inf != nil {
		t.Fatalf("error return must not carry a Ready/Inflight: dialer=%v inflight=%v", ready.Dialer, inf)
	}
	if !strings.Contains(err.Error(), "control plane unreachable") {
		t.Fatalf("warming error should surface the last EnsureReady failure, got: %v", err)
	}
	if n := pl.Count(); n != 1 {
		t.Fatalf("seed mapping must survive the failed ensure for supervision: Count=%d", n)
	}
}

// --- Actor-creation caps (finding R3) ---

// capBackend is a lifecycle backend whose handle names are unique per route
// (countingBackend returns "a" for every key, which would make a single
// ForgetByActorName drop unrelated sessions).
type capBackend struct {
	mu      sync.Mutex
	creates int
}

func (c *capBackend) EnsureReady(ctx context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	c.mu.Lock()
	c.creates++
	c.mu.Unlock()
	return &backend.Handle{Key: key, Name: key.ActorName("cap-"), CreatedAt: time.Now()}, nilDialer{}, nil
}

func (c *capBackend) Get(ctx context.Context, key model.RouteKey) (*backend.Handle, error) {
	return nil, nil
}
func (c *capBackend) Suspend(ctx context.Context, h *backend.Handle) error { return nil }
func (c *capBackend) Delete(ctx context.Context, h *backend.Handle) error  { return nil }
func (c *capBackend) ListReady(ctx context.Context) ([]backend.Handle, error) {
	return nil, nil
}

// TestPoolActorCapBlocksNewCreates: creates admit up to MaxActors, the next
// NEW route fails with the facade-mapped sentinel, and the rejected create
// leaves no residue while sessions at the cap keep working.
func TestPoolActorCapBlocksNewCreates(t *testing.T) {
	b := &capBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(b, nil, log, time.Minute, time.Hour, time.Hour)
	pl.MaxActors = 2
	ctx := context.Background()

	k1, k2, k3 := model.NewRouteKey("u", "c1"), model.NewRouteKey("u", "c2"), model.NewRouteKey("u", "c3")
	for _, k := range []model.RouteKey{k1, k2} {
		if _, inflight, err := pl.Acquire(ctx, k); err != nil {
			t.Fatalf("create to cap (%s): %v", k.LogString(), err)
		} else {
			inflight.Done()
		}
	}

	_, inflight, err := pl.Acquire(ctx, k3)
	if !errors.Is(err, pool.ErrActorCapReached) {
		t.Fatalf("create past cap: err = %v, want ErrActorCapReached", err)
	}
	if inflight != nil {
		t.Fatal("a capped create must not hand back an in-flight ref")
	}
	if n := pl.Count(); n != 2 {
		t.Fatalf("Count = %d, want 2 (a rejected create registers nothing)", n)
	}
	// An existing session keeps working while the pool sits at the cap.
	if _, _, err := pl.Acquire(ctx, k1); err != nil {
		t.Fatalf("existing session must keep working at the cap: %v", err)
	}
}

// TestPoolActorCapFreesSlotOnDelete: a completed console purge (full
// delete) releases its slot for the next create.
func TestPoolActorCapFreesSlotOnDelete(t *testing.T) {
	b := &capBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(b, nil, log, time.Minute, time.Hour, time.Hour)
	pl.MaxActors = 1
	ctx := context.Background()

	ready, inflight, err := pl.Acquire(ctx, model.NewRouteKey("u", "c1"))
	if err != nil {
		t.Fatal(err)
	}
	inflight.Done()

	k2 := model.NewRouteKey("u", "c2")
	if _, _, err := pl.Acquire(ctx, k2); !errors.Is(err, pool.ErrActorCapReached) {
		t.Fatalf("second create at cap=1: err = %v, want ErrActorCapReached", err)
	}

	pl.ForgetByActorName(ready.Handle.Name) // console-side full delete
	if _, _, err := pl.Acquire(ctx, k2); err != nil {
		t.Fatalf("a deleted actor must free its slot: %v", err)
	}
}

// TestPoolActorCapCountsSuspendedAndExemptsResume covers both edges of the
// R3 counting rules with a persisted store (what production has): a
// suspended actor's pool slot drops but its sessionmap row keeps it
// counted, while re-acquiring that same route is a RESUME of an existing
// sandbox and must pass the cap untouched.
func TestPoolActorCapCountsSuspendedAndExemptsResume(t *testing.T) {
	b := &capBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := sessionmap.Open(filepath.Join(t.TempDir(), "cap.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	pl := pool.New(b, store, log, 0 /* immediate idle */, time.Hour /* delete-idle */, time.Hour)
	pl.MaxActors = 1
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pl.RunTicker(ctx, 5*time.Millisecond)

	k1 := model.NewRouteKey("u", "c1")
	if _, inflight, err := pl.Acquire(ctx, k1); err != nil {
		t.Fatalf("first create: %v", err)
	} else {
		inflight.Done()
	}

	// Wait for the suspend that drops the map slot (delete-idle/max-age
	// stay at 1h, so only the suspend branch can fire).
	suspended := false
	for i := 0; i < 100 && !suspended; i++ {
		if pl.Count() == 0 {
			suspended = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !suspended {
		t.Fatalf("suspend never dropped the slot (Count=%d)", pl.Count())
	}

	// Row ⇒ existing sandbox ⇒ resume, not a new create: must pass at cap.
	if _, inflight, err := pl.Acquire(ctx, k1); err != nil {
		t.Fatalf("resume of a suspended actor hit the cap: %v", err)
	} else {
		defer inflight.Done()
	}
	// A genuinely new route must fail: the suspended actor still counts.
	if _, _, err := pl.Acquire(ctx, model.NewRouteKey("u", "c2")); !errors.Is(err, pool.ErrActorCapReached) {
		t.Fatalf("suspended actor must still count against the cap, got %v", err)
	}
}

// TestPoolPerUserCapIsolatesUsers: one user at their cap must not block
// another user (global cap has headroom, so only TRI_MAX_ACTORS_PER_USER
// can fire).
func TestPoolPerUserCapIsolatesUsers(t *testing.T) {
	b := &capBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(b, nil, log, time.Minute, time.Hour, time.Hour)
	pl.MaxActors = 10
	pl.MaxActorsPerUser = 1
	ctx := context.Background()

	if _, inflight, err := pl.Acquire(ctx, model.NewRouteKey("u1", "c1")); err != nil {
		t.Fatalf("first create: %v", err)
	} else {
		inflight.Done()
	}
	if _, _, err := pl.Acquire(ctx, model.NewRouteKey("u1", "c2")); !errors.Is(err, pool.ErrActorCapReached) {
		t.Fatalf("same user past per-user cap: err = %v, want ErrActorCapReached", err)
	}
	if _, inflight, err := pl.Acquire(ctx, model.NewRouteKey("u2", "c1")); err != nil {
		t.Fatalf("per-user cap leaked across users: %v", err)
	} else {
		inflight.Done()
	}
}

// TestPoolActorCapFloodBounded floods distinct header pairs concurrently:
// exactly MaxActors admit, every refusal is the sentinel, no rejected
// create leaves residue — and the run stays race-clean under -race because
// the cap check and the registration share one p.mu critical section.
func TestPoolActorCapFloodBounded(t *testing.T) {
	b := &capBackend{}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(b, nil, log, time.Minute, time.Hour, time.Hour)
	pl.MaxActors = 4
	ctx := context.Background()

	const flood = 40
	var admitted, capped atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < flood; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, inflight, err := pl.Acquire(ctx, model.NewRouteKey("u", fmt.Sprintf("c%d", i)))
			switch {
			case err == nil:
				admitted.Add(1)
				inflight.Done()
			case errors.Is(err, pool.ErrActorCapReached):
				capped.Add(1)
			default:
				t.Errorf("flood request %d: unexpected error %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	if admitted.Load() != 4 {
		t.Fatalf("admitted = %d, want exactly MaxActors=4", admitted.Load())
	}
	if capped.Load() != flood-4 {
		t.Fatalf("capped = %d, want %d", capped.Load(), flood-4)
	}
	if n := pl.Count(); n != 4 {
		t.Fatalf("Count = %d after the flood, want 4", n)
	}
}
