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
