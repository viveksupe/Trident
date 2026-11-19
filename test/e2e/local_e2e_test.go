// Package e2e validates the full Open WebUI-visible protocol surface through
// the shim against a real open-terminal actor container (docker backend).
// Skipped unless docker and the actor image are available:
//
//	TRI_DOCKER_IMAGE=ot-actor:dev go test ./test/e2e/ -v
package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/viveksupe/Trident/internal/backend/fakedocker"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/facade"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/pool"
	"github.com/viveksupe/Trident/internal/sessionmap"
)

var (
	apiKey   = "e2e-test-key"
	chatHdrs = map[string]string{
		"X-User-Id":    "e2e-user",
		"X-Session-Id": "e2e-chat",
	}
)

// startShim boots the facade against a docker actor.
func startShim(t *testing.T) *httptest.Server {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}
	image := os.Getenv("TRI_DOCKER_IMAGE")
	if image == "" {
		image = "ot-actor:dev"
	}
	if _, err := exec.Command("docker", "image", "inspect", image).Output(); err != nil {
		t.Skipf("actor image %s not built", image)
	}

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0", APIKey: apiKey, ActorAPIKey: apiKey,
		Backend: "docker", StateDB: t.TempDir() + "/sessions.db",
		ActorPrefix: "e2e-ot-", ActorPort: 8000,
		IdleTTL: time.Hour, MaxAge: time.Hour,
		Features: config.DefaultFeatures(), EgressHosts: config.DefaultEgressHosts(),
	}
	store, err := sessionmap.Open(cfg.StateDB)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Route the backend's containers into a per-test prefix so parallel runs
	// don't collide; clean them up when the test ends.
	backendImpl := fakedocker.New("e2e-ot-", image, "8000", cfg.ActorAPIKey, nil)
	pl := pool.New(backendImpl, store, slog.New(slog.NewTextHandler(io.Discard, nil)), time.Hour, time.Hour, time.Hour)
	pl.AllowSuspend = false
	servers := httptest.NewServer(facade.New(cfg, pl, newLogger()).Handler())
	t.Cleanup(servers.Close)
	t.Cleanup(func() {
		name := "e2e-ot-" + model.Hash8(chatHdrs["X-User-Id"]) + "c" + model.Hash8(chatHdrs["X-Session-Id"])
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})
	return servers
}

func newLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func call(t *testing.T, base, method, path string, hdrs map[string]string, body io.Reader) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		t.Fatal(err)
	}
	hdrs2 := map[string]string{"Authorization": "Bearer " + apiKey}
	for k, v := range chatHdrs {
		hdrs2[k] = v
	}
	for k, v := range hdrs {
		hdrs2[k] = v
	}
	for k, v := range hdrs2 {
		req.Header.Set(k, v)
	}
	resp, err := baseHTTP().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	b := &bytes.Buffer{}
	b.Write(buf)
	return resp, b.String()
}

var client = &http.Client{Timeout: 300 * time.Second}

func baseHTTP() *http.Client { return client }

func TestFullProtocolAgainstActor(t *testing.T) {
	srv := startShim(t)
	base := srv.URL

	// 1. Contract endpoints.
	if resp, body := call(t, base, http.MethodGet, "/api/config", nil, nil); resp.StatusCode != 200 {
		t.Fatalf("/api/config %d %s", resp.StatusCode, body)
	} else {
		var cfgResp struct {
			Features map[string]bool `json:"features"`
		}
		if err := json.Unmarshal([]byte(body), &cfgResp); err != nil || !cfgResp.Features["terminal"] || !cfgResp.Features["agents"] {
			t.Fatalf("bad features: %s", body)
		}
	}
	if resp, _ := call(t, base, http.MethodGet, "/api/v1/terminals/templates", nil, nil); resp.StatusCode != 404 {
		t.Fatalf("templates must 404, got %d", resp.StatusCode)
	}
	if resp, body := call(t, base, http.MethodGet, "/files/cwd", map[string]string{"Authorization": "Bearer wrong"}, nil); resp.StatusCode != 401 || !strings.Contains(body, "Invalid API key") {
		t.Fatalf("bad-key behavior: %d %s", resp.StatusCode, body)
	}

	// 2. Files: cwd, write, read, list.
	resp, body := call(t, base, http.MethodPost, "/files/cwd", map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"path":"/home/user"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("POST /files/cwd %d %s", resp.StatusCode, body)
	}
	resp, body = call(t, base, http.MethodPost, "/files/write", map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"path":"e2e-shim.txt","content":"from the shim"}`))
	if resp.StatusCode != 200 {
		t.Fatalf("write %d %s", resp.StatusCode, body)
	}
	if resp, body = call(t, base, http.MethodGet, "/files/read?path=e2e-shim.txt", nil, nil); resp.StatusCode != 200 || !strings.Contains(body, "from the shim") {
		t.Fatalf("read %d %s", resp.StatusCode, body)
	}
	if resp, body = call(t, base, http.MethodGet, "/files/list?directory=.", nil, nil); resp.StatusCode != 200 || !strings.Contains(body, "e2e-shim.txt") {
		t.Fatalf("list %d %s", resp.StatusCode, body)
	}

	// 3. Execute a command (streamed log-response shape).
	resp, body = call(t, base, http.MethodPost, "/execute?wait=30", map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"command":"echo through-the-shim && printf 'second-line'"}`))
	if resp.StatusCode != 200 || !strings.Contains(body, "through-the-shim") {
		t.Fatalf("/execute %d %s", resp.StatusCode, body)
	}
	var logResp struct {
		Status   string `json:"status"`
		ExitCode *int   `json:"exit_code"`
		Output   []struct {
			Type string `json:"type"`
			Data string `json:"data"`
		} `json:"output"`
	}
	_ = json.Unmarshal([]byte(body), &logResp)
	if logResp.Status != "done" || logResp.ExitCode == nil || *logResp.ExitCode != 0 {
		t.Fatalf("execute shape: %s", body)
	}

	// 4. Agent discovery (protocol contract, no LLM key needed).
	resp, body = call(t, base, http.MethodGet, "/agents", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("/agents %d %s", resp.StatusCode, body)
	}
	var disc struct {
		ProtocolVersion int `json:"protocol_version"`
		Agents          []struct {
			ID        string `json:"id"`
			Available bool   `json:"available"`
		} `json:"agents"`
	}
	if err := json.Unmarshal([]byte(body), &disc); err != nil {
		t.Fatalf("/agents not JSON: %s", body)
	}
	if disc.ProtocolVersion != 1 {
		t.Fatalf("protocol_version must be 1: %s", body)
	}
	if len(disc.Agents) == 0 {
		t.Fatalf("/agents has no entries: %s", body)
	}

	// 5. Agent session lifecycle for an unavailable provider must return
	// open_terminal's JSON error shape through the proxy (i.e. proxy fidelity).
	if resp, body = call(t, base, http.MethodPost, "/agents/does-not-exist/sessions",
		map[string]string{"Content-Type": "application/json"},
		strings.NewReader(`{"request_id":"r1","cwd":"/home/user"}`)); resp.StatusCode >= 200 && resp.StatusCode < 300 {
		// Unexpected success would mean the shim invented behavior; leave to
		// whatever open_terminal replies, but it must be a JSON body.
		if !strings.HasPrefix(strings.TrimSpace(body), "{") {
			t.Fatalf("agent session create: non-JSON body %s", body)
		}
	} else if !strings.Contains(body, "detail") {
		t.Fatalf("agent error shape: %d %s", resp.StatusCode, body)
	}

	// 6. File upload (multipart) → {path}.
	fb := &bytes.Buffer{}
	mw := multipart.NewWriter(fb)
	fw, err := mw.CreateFormFile("file", "upload-e2e.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("uploaded via the shim"))
	_ = mw.Close()
	resp, body = call(t, base, http.MethodPost, "/files/upload?directory=/home/user",
		map[string]string{"Content-Type": mw.FormDataContentType()}, fb)
	if resp.StatusCode != 200 || !strings.Contains(body, "upload-e2e.txt") {
		t.Fatalf("upload %d %s", resp.StatusCode, body)
	}

	// 7. Interactive terminal WS: create a session first (the WS attaches to
	// an existing PTY session), auth in the first frame, then a binary write
	// must make the PTY echo (validates the WS splice through the proxy).
	resp, body = call(t, base, http.MethodPost, "/api/terminals", nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("POST /api/terminals %d %s", resp.StatusCode, body)
	}
	var createdTerm struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &createdTerm); err != nil || createdTerm.ID == "" {
		t.Fatalf("terminal session create shape: %s", body)
	}
	dialHeaders := http.Header{}
	for k, v := range chatHdrs {
		dialHeaders.Set(k, v)
	}
	dialHeaders.Set("Authorization", "Bearer "+apiKey)
	wsURL := "ws" + strings.TrimPrefix(base, "http") + "/api/terminals/" + createdTerm.ID
	dialer := websocket.Dialer{HandshakeTimeout: 60 * time.Second}
	ws, respW, err := dialer.Dial(wsURL, dialHeaders)
	if err != nil {
		t.Fatalf("terminal WS dial failed: %v (resp %v)", err, statusOf(respW))
	}
	defer ws.Close()
	auth, _ := json.Marshal(map[string]any{"type": "auth", "token": apiKey})
	if err := ws.WriteMessage(websocket.TextMessage, auth); err != nil {
		t.Fatalf("auth frame: %v", err)
	}
	// The server acks with a shell + process info; read up to 10s for output.
	if err := ws.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_ = ws.WriteMessage(websocket.BinaryMessage, []byte("echo ws-through-shim\n"))
	gotOutput := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage && strings.Contains(string(data), `"type":"output"`) {
			continue // resume-mode metadata
		}
		if bytes.Contains(data, []byte("ws-through-shim")) {
			gotOutput = true
			break
		}
	}
	if !gotOutput {
		t.Fatalf("terminal WS produced no echoed output")
	}
}

func statusOf(resp *http.Response) string {
	if resp == nil {
		return "<nil>"
	}
	return resp.Status
}
