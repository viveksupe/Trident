package facade

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/pool"
)

// countingDialer hands out connections whose Close is counted, so tests can
// tell exactly when an evicted transport lets go of a socket — and that it
// only ever lets go of IDLE ones.
type countingDialer struct {
	addr   string
	mu     sync.Mutex
	dials  int
	closes int
}

func (d *countingDialer) DialConn(ctx context.Context, network string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dials++
	d.mu.Unlock()
	return &countingConn{Conn: c, d: d}, nil
}

func (d *countingDialer) counts() (dials, closes int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials, d.closes
}

type countingConn struct {
	net.Conn
	d *countingDialer
}

func (d *countingDialer) counts2() (int, int) { return d.dials, d.closes }

func (c *countingConn) Close() error {
	c.d.mu.Lock()
	c.d.closes++
	c.d.mu.Unlock()
	return c.Conn.Close()
}

// waitCloses polls until the dialer has recorded exactly want closes. The
// transport retires a connection on its readLoop goroutine (put-idle runs
// concurrently with the request that completed), so the count settles a
// moment after the request/eviction that caused it; a value that overshoots
// want fails at the deadline with the observed count.
func waitCloses(t *testing.T, d *countingDialer, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, c := d.counts()
		if c == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("conn closes = %d, want %d", c, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// evictFixture wires a Server whose actor target counts its connections, so
// proxyFor can be exercised (and evicted) without a pool/backend.
type evictFixture struct {
	s      *Server
	target *httptest.Server
	dial   *countingDialer
	name   string
}

func newEvictFixture(t *testing.T, handler http.HandlerFunc) *evictFixture {
	t.Helper()
	target := httptest.NewServer(handler)
	t.Cleanup(target.Close)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(nil, nil, log, time.Minute, time.Hour, time.Hour)
	s := New(newSpecTestConfig(t), pl, log)
	u, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	f := &evictFixture{s: s, target: target, dial: &countingDialer{addr: u.Host}, name: "ot-ur3-c1"}
	// Populate the caches once, as if the actor had already served traffic;
	// every later proxyFor LoadOrStores this same transport.
	s.proxyFor(f.ready())
	return f
}

func (f *evictFixture) ready() pool.Ready {
	return pool.Ready{
		Handle: backend.Handle{Name: f.name, CreatedAt: time.Now()},
		Dialer: f.dial,
	}
}

// get runs one proxied GET through the actor cache, exactly as route does.
// (Call from the test goroutine only — it Fatal's through t.)
func (f *evictFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://lan.example"+path, nil)
	rec := httptest.NewRecorder()
	f.s.proxyFor(f.ready()).ServeHTTP(rec, req)
	return rec
}

// TestEvictActorRemovesCachesAndClosesIdleConns: after eviction both maps
// are empty and the transport's idle keep-alive connection has been closed
// (before eviction the completed request's conn is still open — proves the
// close came from eviction, not IdleConnTimeout).
func TestEvictActorRemovesCachesAndClosesIdleConns(t *testing.T) {
	f := newEvictFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "pong")
	})

	rec := f.get(t, "/ok")
	if rec.Code != http.StatusOK || rec.Body.String() != "pong" {
		t.Fatalf("proxied GET: %d %q", rec.Code, rec.Body.String())
	}
	if _, ok := f.s.transports.Load(f.name); !ok {
		t.Fatal("transport not cached before eviction")
	}
	if _, ok := f.s.dialers.Load(f.name); !ok {
		t.Fatal("dialer not cached before eviction")
	}
	if dials, closes := f.dial.counts(); dials != 1 || closes != 0 {
		t.Fatalf("before eviction: dials=%d closes=%d, want 1/0 (conn idle, not yet closed)", dials, closes)
	}

	f.s.evictActor(f.name)

	if _, ok := f.s.transports.Load(f.name); ok {
		t.Fatal("transport survived eviction")
	}
	if _, ok := f.s.dialers.Load(f.name); ok {
		t.Fatal("dialer survived eviction")
	}
	// The idle conn is closed by the eviction call path
	// (CloseIdleConnections, immediate, or the readLoop retiring it a
	// moment later) — bounded poll instead of a sleep.
	waitCloses(t, f.dial, 1)
}

// TestEvictActorLeavesInFlightRequestsRunning pins the eviction contract
// from BOTH sides in one deterministic sequence: a slow request holds the
// first connection ACTIVE while a second request completes and leaves its
// connection IDLE. Eviction must close the idle one (closes -> 1) and leave
// the active one alone — the in-flight request still finishes 200. Duplicate
// evicts on the now-empty caches are no-ops (no panic, no extra closes).
func TestEvictActorLeavesInFlightRequestsRunning(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	// Unblock the target handler on any exit path (including a Fatal
	// mid-test), so httptest cleanup never waits on the active conn.
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	f := newEvictFixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			close(started)
			<-release
			_, _ = io.WriteString(w, "slow-done")
			return
		}
		_, _ = io.WriteString(w, "pong")
	})

	// In-flight first: its conn is active (never idle) from the start.
	slowDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodGet, "http://lan.example/slow", nil)
		rec := httptest.NewRecorder()
		f.s.proxyFor(f.ready()).ServeHTTP(rec, req)
		slowDone <- rec
	}()
	<-started // handler entered => request conn dialed and active

	// A completed request against the SAME transport leaves one idle conn
	// (the idle pool was empty while /slow was active, so this is a fresh,
	// now-idle connection — dial 2).
	if rec := f.get(t, "/ok"); rec.Code != http.StatusOK {
		t.Fatalf("concurrent GET while slow in flight: %d", rec.Code)
	}
	if dials, closes := f.dial.counts(); dials != 2 || closes != 0 {
		t.Fatalf("pre-eviction: dials=%d closes=%d, want 2/0", dials, closes)
	}

	f.s.evictActor(f.name)

	if _, ok := f.s.transports.Load(f.name); ok {
		t.Fatal("transport survived eviction")
	}
	// Only the idle conn closed; the active /slow conn is untouched (it
	// cannot be closed while in flight — net/http documents that
	// CloseIdleConnections does not interrupt connections in use).
	waitCloses(t, f.dial, 1)

	close(release)
	rec := <-slowDone
	if rec.Code != http.StatusOK || rec.Body.String() != "slow-done" {
		t.Fatalf("in-flight request broken by eviction: %d %q", rec.Code, rec.Body.String())
	}
	// After eviction the transport is retired (net/http sets
	// t.closeIdle, so tryPutIdleConn answers errCloseIdle): when the
	// in-flight response COMPLETES its conn closes instead of pooling.
	// Eviction therefore neither severs the live request nor leaks its
	// socket — the evicted transport ends up holding no conns at all.
	waitCloses(t, f.dial, 2)

	// Duplicate evicts: entries already gone — safe no-ops.
	f.s.evictActor(f.name)
	f.s.evictActor(f.name)
	if _, closes := f.dial.counts(); closes != 2 {
		t.Fatalf("duplicate evict changed conn closes: %d, want 2", closes)
	}
}

// TestEvictActorConcurrentWithProxying hammers eviction against live
// proxying from multiple goroutines; the race detector must stay quiet and
// the caches must be cleanly evictable at the end.
func TestEvictActorConcurrentWithProxying(t *testing.T) {
	f := newEvictFixture(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "pong")
	})

	var wgProxy sync.WaitGroup
	for i := 0; i < 4; i++ {
		wgProxy.Add(1)
		go func() {
			defer wgProxy.Done()
			for j := 0; j < 25; j++ {
				req := httptest.NewRequest(http.MethodGet, "http://lan.example/ok", nil)
				rec := httptest.NewRecorder()
				f.s.proxyFor(f.ready()).ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Errorf("concurrent proxied GET: %d", rec.Code)
					return
				}
			}
		}()
	}

	stop := make(chan struct{})
	var wgEvict sync.WaitGroup
	for i := 0; i < 4; i++ {
		wgEvict.Add(1)
		go func() {
			defer wgEvict.Done()
			for {
				select {
				case <-stop:
					return
				default:
					f.s.evictActor(f.name)
				}
			}
		}()
	}

	wgProxy.Wait()
	close(stop)
	wgEvict.Wait()

	// Whatever raced last, one final evict leaves both caches empty.
	f.s.evictActor(f.name)
	if _, ok := f.s.transports.Load(f.name); ok {
		t.Fatal("transport survived final eviction")
	}
	if _, ok := f.s.dialers.Load(f.name); ok {
		t.Fatal("dialer survived final eviction")
	}
}

// TestNewComposesPoolOnActorDeleted: New subscribes to the pool's delete
// path via OnActorDeleted (the fake callback stands in for the pool sweep)
// WITHOUT clobbering a hook already registered — main.go wires the egress
// purge before facade.New and both must run.
func TestNewComposesPoolOnActorDeleted(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := newSpecTestConfig(t)

	pl := pool.New(nil, nil, log, time.Minute, time.Hour, time.Hour)
	var prevFired atomic.Int32
	pl.OnActorDeleted = func(string) { prevFired.Add(1) } // main.go's egress purge

	s := New(cfg, pl, log)
	if pl.OnActorDeleted == nil {
		t.Fatal("New must subscribe to the pool delete path")
	}
	s.dialers.Store("ot-ur3-hook", backend.TCPDialer{Addr: "127.0.0.1:1"})
	s.transports.Store("ot-ur3-hook", &http.Transport{})

	pl.OnActorDeleted("ot-ur3-hook") // what the pool sweep fires after a delete

	if prevFired.Load() != 1 {
		t.Fatalf("pre-existing OnActorDeleted must still run, fired %d times", prevFired.Load())
	}
	if _, ok := s.transports.Load("ot-ur3-hook"); ok {
		t.Fatal("composed hook must evict the transport")
	}
	if _, ok := s.dialers.Load("ot-ur3-hook"); ok {
		t.Fatal("composed hook must evict the dialer")
	}

	// With no prior hook (egress flow off in main.go) New still subscribes,
	// and firing it for an unknown actor is a harmless no-op.
	pl2 := pool.New(nil, nil, log, time.Minute, time.Hour, time.Hour)
	_ = New(cfg, pl2, log)
	if pl2.OnActorDeleted == nil {
		t.Fatal("New must subscribe even without a pre-existing hook")
	}
	pl2.OnActorDeleted("never-seen-actor")
}

// TestConsoleActorDeleteEvictsProxyCaches covers the explicit-purge path:
// the console delete action goes through pool.ForgetByActorName, which fires
// no OnActorDeleted hook, so actorsDelete must evict the proxy caches itself.
func TestConsoleActorDeleteEvictsProxyCaches(t *testing.T) {
	fx := newEgressFixture(t)
	fx.srv.SetBackend(fx.fb)

	name := "ot-ur3-purge-c1"
	fx.srv.dialers.Store(name, backend.TCPDialer{Addr: "127.0.0.1:1"})
	fx.srv.transports.Store(name, &http.Transport{})

	req, err := http.NewRequest(http.MethodPost, fx.main.URL+"/_trident/console/actors/api/actor",
		strings.NewReader(`{"name":"`+name+`","action":"delete"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+fx.srv.cfg.ConsoleToken)
	resp, err := fx.main.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	wantStatus(t, resp, string(b), http.StatusOK, "console actor delete")

	if _, ok := fx.srv.transports.Load(name); ok {
		t.Fatal("console purge must evict the transport cache")
	}
	if _, ok := fx.srv.dialers.Load(name); ok {
		t.Fatal("console purge must evict the dialer cache")
	}
}
