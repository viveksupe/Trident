package facade

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/pool"
)

// Frame codec: a masked client frame must survive writeMaskedFrame →
// readWSFrame byte-for-byte (header byte preserved, payload unmasked).
func TestWSFrameCodecRoundTrip(t *testing.T) {
	for _, payload := range [][]byte{
		[]byte(`{"type":"auth","token":"front-key","cursor":0}`),
		bytes.Repeat([]byte("x"), 125),
		bytes.Repeat([]byte("y"), 60000),  // 16-bit extended length
		bytes.Repeat([]byte("z"), 200000),  // 64-bit extended length
	} {
		var buf bytes.Buffer
		head := byte(0x81) // FIN + text
		if err := writeMaskedFrame(&buf, head, payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		f, err := readWSFrame(bufio.NewReader(&buf))
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if f.head != head {
			t.Fatalf("head byte changed: %x", f.head)
		}
		if !bytes.Equal(f.payload, payload) {
			t.Fatalf("payload mismatch: %d vs %d bytes", len(f.payload), len(payload))
		}
	}
}

func TestAuthFrameRewrite(t *testing.T) {
	in := []byte(`{"type":"auth","token":"front-key","cursor":12,"other":true}`)
	if !isAuthFrame(in) {
		t.Fatal("auth frame not detected")
	}
	out, ok := rewriteAuthToken(in, "actor-secret")
	if !ok {
		t.Fatal("rewrite failed")
	}
	var f wsAuthFrame
	if err := json.Unmarshal(out, &f); err != nil {
		t.Fatal(err)
	}
	if f.Token != "actor-secret" {
		t.Fatalf("token not rewritten: %q", f.Token)
	}
	// Non-auth frames pass through untouched.
	plain := []byte(`{"type":"input","sequence":1,"data":"hi"}`)
	if isAuthFrame(plain) {
		t.Fatal("input frame misdetected as auth")
	}
}

// testDialer dials a fixed address (the fake actor).
type testDialer struct{ addr string }

func (d testDialer) DialConn(ctx context.Context, _ string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.addr)
}

// Full splice regression (C2): the actor must receive the ACTOR key in the
// first auth frame while the client presents the front-side key, and every
// later frame must arrive unmodified in both directions.
func TestSpliceWSRewritesFirstAuthFrame(t *testing.T) {
	const (
		frontKey = "front-side-key"
		actorKey = "actor-side-key"
		echoText = "dense-output-after-auth"
	)
	gotToken := make(chan string, 1)
	gotAfter := make(chan string, 1)

	upgrader := websocket.Upgrader{}
	actor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The actor insists on its own key, on the header too.
		if r.Header.Get("Authorization") != "Bearer "+actorKey {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, auth, err := ws.ReadMessage()
		if err != nil {
			return
		}
		var af struct {
			Type  string `json:"type"`
			Token string `json:"token"`
		}
		_ = json.Unmarshal(auth, &af)
		gotToken <- af.Token
		// Server-pushed frame before the client's next message: must reach
		// the client through the splice (actor → client direction).
		_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"output","sequence":0}`))
		// Return after the first data frame so this handler exits and the
		// actor-side connection closes — the splice goroutines then wind
		// down and the httptest servers can Close without deadlocking.
		_, msg, err := ws.ReadMessage()
		if err != nil {
			return
		}
		gotAfter <- string(msg)
	}))
	defer actor.Close()

	cfg := &config.Config{APIKey: frontKey, ActorAPIKey: actorKey}
	s := &Server{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	dial := testDialer{addr: actor.Listener.Addr().String()}

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			t.Error("upgrade not detected")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if ok := s.spliceWS(w, r, pool.Ready{
			Handle: backend.Handle{Name: "test-actor"},
			Dialer: dial,
		}); !ok {
			t.Error("splice failed")
		}
	}))
	defer front.Close()

	wsURL := "ws" + front.URL[len("http"):]
	h := http.Header{}
	h.Set("Authorization", "Bearer "+frontKey)
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, h)
	if err != nil {
		t.Fatalf("dial: %v (resp %v)", err, resp)
	}
	defer conn.Close()

	// Client presents the FRONT key in the auth frame, then a data frame.
	_ = conn.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"auth","token":"`+frontKey+`","cursor":0}`))
	_ = conn.WriteMessage(websocket.TextMessage,
		[]byte(`{"type":"input","sequence":1,"data":"`+echoText+`"}`))

	// Read the actor's pushed output frame client-side (splice direction 2).
	sawOutput := make(chan struct{}, 1)
	go func() {
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
			select {
			case sawOutput <- struct{}{}:
			default:
			}
		}
	}()

	select {
	case tok := <-gotToken:
		if tok != actorKey {
			t.Fatalf("actor saw token %q, want the actor key", tok)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("auth frame never reached the actor")
	}
	select {
	case <-sawOutput:
	case <-time.After(5 * time.Second):
		t.Fatal("actor's pushed output frame never reached the client")
	}
	select {
	case msg := <-gotAfter:
		if !strings.Contains(msg, echoText) {
			t.Fatalf("input frame mangled: %q", msg)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("input frame never reached the actor")
	}
}
