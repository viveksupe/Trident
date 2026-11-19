package facade

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/viveksupe/Trident/internal/pool"
)

// proxyFor builds one ReverseProxy per Acquire result. Its Transport dials the
// actor through the backend's tunnel dialer, keeps FlushInterval at -1 so
// streaming bodies (agent WS replay, /execute tails, file streams) arrive
// unbuffered, and imposes no extra timeouts beyond the underlying conn (the
// substrate CONNECT tunnels carry no route timeout; long Open WebUI requests
// stay bounded by its client). The proxied ResponseWriter is never wrapped, so
// WebSocket upgrades splice natively and close codes pass through verbatim.
func (s *Server) proxyFor(ready pool.Ready) *httputil.ReverseProxy {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return ready.Dialer.DialConn(ctx, network)
		},
		// HTTP/1.1 only: the actor speaks plain HTTP/1.1; upgrades (WS) ride
		// on the 101-switch splicing of httputil.ReverseProxy.
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     5 * time.Minute,
	}

	return &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Point the clone at a symbolic host; the Transport dials the actor.
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "actor"
			// Preserve the original Host so the actor sees the client's host.
			pr.Out.Host = pr.In.Host
		},
		// Errors become open_terminal-shaped JSON; Open WebUI surfaces the
		// "detail" string in chat/terminal errors.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSON(w, http.StatusBadGateway, detail{"actor connection failed: " + err.Error()})
		},
	}
}
