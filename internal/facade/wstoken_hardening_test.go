package facade

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/pool"
)

// newTestServer builds the minimal Server the splice paths need (KeyRewriteNeeded
// is active because the front and actor keys differ).
func newTestServer() *Server {
	return &Server{
		cfg: &config.Config{APIKey: "front-side-key", ActorAPIKey: "actor-side-key"},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// TestSpliceReturnsAfterSilentClientDeath pins finding C4: whichever splice
// direction ends first must close BOTH connections and spliceWS must wait for
// both directions, so routeNoAuth's `defer inflight.Done()` (server.go) always
// runs. Before the fix, an unclean client disconnect left the actor→client
// copy blocked on a silent actor forever: spliceWS never returned and the pool
// session kept inflight > 0 (never suspended, never swept).
func TestSpliceReturnsAfterSilentClientDeath(t *testing.T) {
	s := newTestServer()

	// Silent actor: completes the upgrade, then never writes another byte
	// while keeping the connection open — the stall that used to pin the
	// session for the lifetime of the idle actor.
	upgrader := websocket.Upgrader{}
	actor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, _, _ = ws.ReadMessage() // blocks until the facade closes the conn
	}))
	defer actor.Close()

	ready := pool.Ready{
		Handle: backend.Handle{Name: "silent-actor"},
		Dialer: testDialer{addr: actor.Listener.Addr().String()},
	}

	handled := make(chan bool, 1)
	released := make(chan struct{})
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Same shape as routeNoAuth: the inflight refcount is released only
		// when spliceWS returns.
		defer close(released)
		handled <- s.spliceWS(w, r, ready)
	}))
	defer front.Close()

	wsURL := "ws" + front.URL[len("http"):]
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	// Unclean client death: drop the TCP connection with no close frame and
	// no further traffic.
	if err := conn.UnderlyingConn().Close(); err != nil {
		t.Fatalf("client close: %v", err)
	}

	select {
	case ok := <-handled:
		if !ok {
			t.Fatal("spliceWS reported the connection unhandled after a completed upgrade")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("spliceWS did not return after silent client death — the inflight refcount would never be released")
	}
	select {
	case <-released:
	case <-time.After(time.Second):
		t.Fatal("inflight release (defer close) never ran")
	}
}
