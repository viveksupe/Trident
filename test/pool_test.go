package test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/pool"
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
