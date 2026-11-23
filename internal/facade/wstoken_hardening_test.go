package facade

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

// rawUpgrade performs the client half of a WebSocket upgrade over raw TCP
// (so tests can send arbitrary frame bytes afterwards) and returns the
// connection with the response headers consumed.
func rawUpgrade(t *testing.T, frontURL string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	u, err := url.Parse(frontURL)
	if err != nil {
		t.Fatalf("parse front url: %v", err)
	}
	c, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatalf("dial front: %v", err)
	}
	if _, err := fmt.Fprintf(c, "GET /ws HTTP/1.1\r\nHost: %s\r\n"+
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", u.Host); err != nil {
		t.Fatalf("write upgrade request: %v", err)
	}
	br := bufio.NewReader(c)
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		c.Close()
		t.Fatalf("read upgrade response: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	return c, br, resp
}

// newRawActor completes any upgrade with a fixed 101, then reports every byte
// it receives on the spliced connection (its read ends when the facade closes
// the connection).
func newRawActor(t *testing.T) (*httptest.Server, <-chan []byte) {
	t.Helper()
	got := make(chan []byte, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Error("actor: ResponseWriter is not a Hijacker")
			return
		}
		c, brw, err := hj.Hijack()
		if err != nil {
			t.Errorf("actor: hijack: %v", err)
			return
		}
		defer c.Close()
		// The upgrade request headers were already parsed by net/http before
		// the handler ran — nothing to drain; answer the handshake at once.
		_, _ = io.WriteString(c, "HTTP/1.1 101 Switching Protocols\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, brw)
		got <- buf.Bytes()
	}))
	return srv, got
}

// spliceFront runs the splice branch of routeNoAuth (server.go) and reports
// what spliceWS returned.
func spliceFront(s *Server, ready pool.Ready, handled chan<- bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handled <- s.spliceWS(w, r, ready)
	}))
}

// TestSpliceHugeDeclaredFrame (finding C2): the frame length field is a
// client-controlled 64-bit value consumed inside a goroutine net/http does
// not recover — make([]byte, ln) on a hostile length would OOM or panic the
// whole process (the old comment claimed a nonexistent 2-3 KiB control
// budget). The scan must cap buffered bytes at maxScanPayload, enforce
// RFC 6455's control-frame and reserved-bit rules, and replay oversized
// frames raw without ever buffering their payload.
func TestSpliceHugeDeclaredFrame(t *testing.T) {
	// Valid-but-huge 64-bit length: 2^63-1, reserved MSB clear.
	hugeLen := []byte{0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	// Invalid: reserved MSB set (RFC 6455 forbids it) — decodes to
	// int64(-1), the exact input that used to panic make([]byte, ln) with
	// "makeslice: len out of range" and kill the process.
	badLen := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

	// assertDropped runs a splice against the raw fake actor, sends frame
	// right after the handshake, and requires the splice to drop the
	// connection: client-side EOF, actor side released, spliceWS returning.
	// A panic or hang fails the test (and used to take the process down).
	assertDropped := func(t *testing.T, frame []byte) {
		t.Helper()
		s := newTestServer()
		actor, actorBytes := newRawActor(t)
		defer actor.Close()
		ready := pool.Ready{
			Handle: backend.Handle{Name: "raw-actor"},
			Dialer: testDialer{addr: actor.Listener.Addr().String()},
		}
		handled := make(chan bool, 1)
		front := spliceFront(s, ready, handled)
		defer front.Close()

		c, br, resp := rawUpgrade(t, front.URL)
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade: got %d", resp.StatusCode)
		}
		defer c.Close()

		if _, err := c.Write(frame); err != nil {
			t.Fatalf("write crafted frame: %v", err)
		}

		// The splice must drop the connection — not allocate from the
		// declared length, not panic.
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := br.Read(make([]byte, 1)); err != io.EOF {
			t.Fatalf("client read after violation: err = %v, want EOF (connection dropped)", err)
		}
		select {
		case <-actorBytes:
		case <-time.After(3 * time.Second):
			t.Fatal("actor side of the splice was never released")
		}
		select {
		case ok := <-handled:
			if !ok {
				t.Fatal("spliceWS reported the connection unhandled after a completed upgrade")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("spliceWS did not return after the protocol violation")
		}
	}

	t.Run("control frame over 125 bytes drops the connection", func(t *testing.T) {
		// FIN + ping, 64-bit length form declaring 2^63-1 payload bytes:
		// RFC 6455 allows control frames at most 125 payload bytes.
		assertDropped(t, append([]byte{0x89, 0x7f}, hugeLen...))
	})

	t.Run("reserved length bit drops the connection", func(t *testing.T) {
		// 0xff...ff decodes to int64(-1), slipping past every upper-bound
		// check straight into make([]byte, ln).
		assertDropped(t, append([]byte{0x81, 0x7f}, badLen...))
	})

	t.Run("oversized data frame replays raw", func(t *testing.T) {
		s := newTestServer()
		actor, actorBytes := newRawActor(t)
		defer actor.Close()
		ready := pool.Ready{
			Handle: backend.Handle{Name: "raw-actor"},
			Dialer: testDialer{addr: actor.Listener.Addr().String()},
		}
		handled := make(chan bool, 1)
		front := spliceFront(s, ready, handled)
		defer front.Close()

		c, _, resp := rawUpgrade(t, front.URL)
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("upgrade: got %d", resp.StatusCode)
		}

		// FIN + text, masked, 64-bit length declaring 2^63-1 bytes while
		// only 80 payload bytes actually follow (truncated hostile frame,
		// or the start of a legitimately huge one — either must stream).
		payload := bytes.Repeat([]byte("big-paste!"), 8)
		var frame bytes.Buffer
		frame.WriteByte(0x81)
		frame.WriteByte(0x80 | 0x7f)
		frame.Write(hugeLen)
		frame.Write([]byte{0x11, 0x22, 0x33, 0x44}) // mask key
		frame.Write(payload)
		if _, err := c.Write(frame.Bytes()); err != nil {
			t.Fatalf("write crafted frame: %v", err)
		}
		// Client FIN: the raw splice finishes, teardown releases both sides.
		if err := c.Close(); err != nil {
			t.Fatalf("client close: %v", err)
		}

		// The actor must see the wire bytes verbatim: replayed header plus
		// streamed payload — the declared 2^63-1 was never allocated.
		select {
		case got := <-actorBytes:
			if !bytes.Equal(got, frame.Bytes()) {
				t.Fatalf("replay mismatch: got %d bytes, want %d (byte-exact)", len(got), frame.Len())
			}
		case <-time.After(3 * time.Second):
			t.Fatal("actor side never saw the replayed frame — splice did not tear down")
		}
		select {
		case ok := <-handled:
			if !ok {
				t.Fatal("spliceWS reported the connection unhandled after a completed upgrade")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("spliceWS did not return after the oversized frame")
		}
	})
}
