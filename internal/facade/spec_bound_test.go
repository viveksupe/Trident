package facade

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/pool"
)

// TestSpecRecorderCapsCapture: the capture buffer can never exceed
// specCaptureLimit, while the client still receives every byte.
func TestSpecRecorderCapsCapture(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &specRecorder{ResponseWriter: rec, buf: &bytes.Buffer{}}
	chunk := make([]byte, specCaptureLimit/4) // 1 MiB

	for i := 0; i < 4; i++ {
		n, err := sr.Write(chunk)
		if n != len(chunk) || err != nil {
			t.Fatalf("chunk %d: n=%d err=%v", i, n, err)
		}
		if sr.overflowed {
			t.Fatalf("overflow flagged at exactly the cap boundary (write %d)", i+1)
		}
		if sr.buf.Len() > specCaptureLimit {
			t.Fatalf("buffer %d exceeds cap %d", sr.buf.Len(), specCaptureLimit)
		}
	}

	// One more chunk crosses the ceiling: capture stops, delivery does not.
	n, err := sr.Write(chunk)
	if n != len(chunk) || err != nil {
		t.Fatalf("overflowing write: n=%d err=%v", n, err)
	}
	if !sr.overflowed {
		t.Fatal("write past the cap must flag overflow")
	}
	if sr.buf.Len() > specCaptureLimit {
		t.Fatalf("buffer %d exceeds cap %d after overflow", sr.buf.Len(), specCaptureLimit)
	}

	// Further bytes stay out of the buffer but still reach the client.
	if n, err := sr.Write([]byte("tail")); n != 4 || err != nil {
		t.Fatalf("post-overflow write: n=%d err=%v", n, err)
	}
	if sr.buf.Len() > specCaptureLimit {
		t.Fatalf("buffer %d exceeds cap %d", sr.buf.Len(), specCaptureLimit)
	}
	if want := 4*len(chunk) + len(chunk) + 4; rec.Body.Len() != want {
		t.Fatalf("client received %d bytes, want %d (capture cap must not truncate delivery)", rec.Body.Len(), want)
	}
	if sr.code != http.StatusOK {
		t.Fatalf("code = %d, want 200", sr.code)
	}

	// A single oversized write overflows immediately without buffering it.
	sr2 := &specRecorder{ResponseWriter: httptest.NewRecorder(), buf: &bytes.Buffer{}}
	giant := make([]byte, specCaptureLimit+1)
	if n, err := sr2.Write(giant); n != len(giant) || err != nil {
		t.Fatalf("giant write: n=%d err=%v", n, err)
	}
	if !sr2.overflowed || sr2.buf.Len() != 0 {
		t.Fatalf("giant write: overflowed=%v buf=%d, want true/0", sr2.overflowed, sr2.buf.Len())
	}
}

// TestServeSpecOverflowNeverCaches drives serveSpec end to end against an
// actor that answers the spec path with a >4 MiB body: the client gets the
// full body, the capture is bounded (see TestSpecRecorderCapsCapture), the
// cache file is never created — and a previously cached valid spec keeps
// being served untouched (it short-circuits to the hit path, so the
// oversized capture never even runs).
func TestServeSpecOverflowNeverCaches(t *testing.T) {
	prefix, suffix := `{"spec":"`, `"}`
	total := len(prefix) + specCaptureLimit + len(suffix)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, prefix)
		_, _ = io.WriteString(w, string(bytes.Repeat([]byte("x"), specCaptureLimit)))
		_, _ = io.WriteString(w, suffix)
	}))
	fb := &specFakeBackend{target: target}
	t.Cleanup(fb.Close)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pl := pool.New(fb, nil, log, time.Minute, time.Hour, time.Hour)
	pl.AllowSuspend = false
	cfg := newSpecTestConfig(t)
	s := New(cfg, pl, log)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	// Cold cache: full oversized body delivered, nothing persisted.
	status, body := boundsDo(t, srv, "/openapi.json")
	if status != http.StatusOK || len(body) != total {
		t.Fatalf("oversized spec GET: status=%d len=%d, want 200/%d", status, len(body), total)
	}
	cacheFile := s.specs.file(cfg.TemplateRef, "/openapi.json")
	if cacheFile == "" {
		t.Fatal("cache file path empty")
	}
	if _, err := os.Stat(cacheFile); !os.IsNotExist(err) {
		t.Fatalf("oversized capture must not create a cache file, stat err=%v", err)
	}
	assertCreated(t, fb, specFetchKey.LogString())

	// A previously cached valid spec wins: served from cache, actor never
	// contacted, oversized content never captured.
	seeded := []byte(`{"seeded":true}`)
	if err := os.WriteFile(cacheFile, seeded, 0o600); err != nil {
		t.Fatal(err)
	}
	status, body = boundsDo(t, srv, "/openapi.json")
	if status != http.StatusOK || body != string(seeded) {
		t.Fatalf("cached spec: status=%d len=%d, want 200/%d (seeded)", status, len(body), len(seeded))
	}
	assertCreated(t, fb, specFetchKey.LogString()) // still only the cold-miss acquire
	if got, err := os.ReadFile(cacheFile); err != nil || !bytes.Equal(got, seeded) {
		t.Fatalf("cached spec modified: %q err=%v", got, err)
	}
}

// boundsDo performs a keyless GET and reads the WHOLE body (specDo's 1 MiB
// LimitReader is too small for the oversized-spec tests).
func boundsDo(t *testing.T, srv *httptest.Server, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// zdbg, when set by a debug test, records Close stack traces.
var zdbg func(string)
