package facade

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/pool"
)

// proxyFor returns a ReverseProxy for one Acquire result. Its Transport is
// cached per actor (transports), and its dial hook always resolves the LATEST
// dialer the pool handed out for that actor (dialers), so tunnel idle
// connections are reused across requests without ever dialing a stale peer.
// FlushInterval stays at -1 so streaming bodies (agent WS replay, /execute
// tails, file streams) arrive unbuffered, and no extra timeouts are imposed
// (the substrate CONNECT tunnels carry no route timeout; long Open WebUI
// requests stay bounded by its client). The proxied ResponseWriter is never
// wrapped, so WebSocket upgrades splice natively and close codes pass
// through verbatim.
func (s *Server) proxyFor(ready pool.Ready) *httputil.ReverseProxy {
	name := ready.Handle.Name
	s.dialers.Store(name, ready.Dialer)

	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if v, ok := s.dialers.Load(name); ok {
				if d, ok := v.(backend.Dialer); ok {
					return d.DialConn(ctx, network)
				}
			}
			return ready.Dialer.DialConn(ctx, network)
		},
		// HTTP/1.1 only: the actor speaks plain HTTP/1.1; upgrades (WS) ride
		// on the 101-switch splicing of httputil.ReverseProxy.
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     5 * time.Minute,
	}
	actual, _ := s.transports.LoadOrStore(name, tr)
	transport := actual.(*http.Transport)

	return &httputil.ReverseProxy{
		Transport: transport,
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Point the clone at a symbolic host; the Transport dials the actor.
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "actor"
			// Preserve the original Host so the actor sees the client's host.
			pr.Out.Host = pr.In.Host
			// Distinct actor key: the client presents the front-side key;
			// the actor expects its own.
			if s.cfg.KeyRewriteNeeded() {
				pr.Out.Header.Set("Authorization", "Bearer "+s.cfg.ActorAPIKey)
			}
		},
		// Errors become open_terminal-shaped JSON; Open WebUI surfaces the
		// "detail" string in chat/terminal errors.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			writeJSON(w, http.StatusBadGateway, detail{"actor connection failed: " + err.Error()})
		},
	}
}
