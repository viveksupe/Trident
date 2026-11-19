// Data-plane dialer: CONNECT tunnels to actors through atenet-router.
// Adapted from agent-substrate/substrate internal/ateclient/router.go
// (Apache-2.0, Copyright 2026 The Agent Substrate Authors).
//
// The tunnel carries a route timeout of 0 on the router side (its lifetime is
// bounded by idle timeout, drain and the peers), which is why the shim routes
// every data-plane byte — including long agent WebSockets — through CONNECT
// rather than the envoy :443 ingress path.
package substrate

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// TargetActorHeader identifies the actor selected for ingress routing as
// "<atespace>/<actor>" (internal/atenet headers contract).
const TargetActorHeader = "ate-target-actor"

const (
	// routerConnectTLSPort is atenet-router's CONNECT-TLS Service port.
	routerConnectTLSPort = 8444
	// routerCertTimeout bounds the initial wait for the podidentity signer.
	routerCertTimeout = 2 * time.Minute
	// routerCertRefreshTimeout bounds a refresh attempt made during a
	// handshake while a cached certificate is still valid.
	routerCertRefreshTimeout = 15 * time.Second
	// routerCertRequester names this client on its PodCertificateRequests.
	routerCertRequester = "trident"
)

// RouterDialer opens CONNECT tunnels to actors through atenet-router.
type RouterDialer struct {
	cfg       *rest.Config
	clientset kubernetes.Interface
	tlsConfig *tls.Config
	dial      func(ctx context.Context) (net.Conn, error)
	stopOnEnd func()
}

// NewRouterDialer returns a dialer that reaches atenet-router's CONNECT-TLS
// listener — direct over the cluster Service when in-cluster, through a
// port-forward when running outside. It verifies the router's servicedns
// serving certificate and presents a podidentity certificate for the ingress
// client ServiceAccount (routeSA), which the router allows by default.
//
// The certificate is requested before NewRouterDialer returns, so a caller
// without RBAC to create PodCertificateRequests fails here. It is refreshed
// once half its lifetime has passed.
func NewRouterDialer(ctx context.Context, cfg *rest.Config, systemNamespace, routerService, routeSA string) (*RouterDialer, error) {
	clientset, err := kubeClientset(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}

	routerHost := serviceDNSName(routerService, systemNamespace)
	tlsCfg, err := serverTLSConfig(ctx, clientset, routerHost)
	if err != nil {
		return nil, err
	}
	certs := &routerClientCerts{clientset: clientset, namespace: systemNamespace, sa: routeSA}
	if _, err := certs.get(ctx); err != nil {
		return nil, err
	}
	tlsCfg.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return certs.get(info.Context())
	}

	d := &RouterDialer{cfg: cfg, clientset: clientset, tlsConfig: tlsCfg}
	if inCluster() {
		// The Service VIP is the fast path: no per-connection port-forward.
		// The router exposes its CONNECT-TLS listener as port 8444 on the
		// Service (connect-tls), next to the default envoy ingress on 443.
		d.dial = func(ctx context.Context) (net.Conn, error) {
			var nd net.Dialer
			nd.Timeout = 15 * time.Second
			return nd.DialContext(ctx, "tcp", routerHost+":8444")
		}
		return d, nil
	}
	// Outside the cluster each tunnel gets its own port-forward: client-go
	// tears down a whole port-forward when any one stream errors, and this
	// also picks a ready router pod again after one goes away.
	d.dial = func(ctx context.Context) (net.Conn, error) {
		localPort, stop, err := servicePortForward(ctx, d.cfg, d.clientset, systemNamespace, routerService, routerConnectTLSPort)
		if err != nil {
			return nil, err
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", localPort))
		if err != nil {
			stop()
			return nil, err
		}
		return &stopOnClose{Conn: conn, stop: stop}, nil
	}
	return d, nil
}

// DialActor opens a CONNECT tunnel through atenet-router to port on
// "<atespace>/<name>".
func (d *RouterDialer) DialActor(ctx context.Context, atespace, name string, port int) (net.Conn, error) {
	rawConn, err := d.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting to router's CONNECT listener: %w", err)
	}
	conn, err := connectActor(ctx, rawConn, d.tlsConfig, atespace, name, port, http.Header{
		TargetActorHeader: []string{atespace + "/" + name},
	})
	if err != nil {
		_ = rawConn.Close()
		return nil, err
	}
	return conn, nil
}

// stopOnClose closes its stop callback alongside the underlying connection.
type stopOnClose struct {
	net.Conn
	stop     func()
	stopOnce sync.Once
}

func (s *stopOnClose) Close() error {
	err := s.Conn.Close()
	s.stopOnce.Do(s.stop)
	return err
}

func connectActor(ctx context.Context, rawConn net.Conn, tlsCfg *tls.Config, atespace, name string, port int, header http.Header) (*forwardedConn, error) {
	tlsConn := tls.Client(rawConn, tlsCfg.Clone())
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("TLS handshake with router's CONNECT listener: %w", err)
	}

	stopOnCancel := context.AfterFunc(ctx, func() { _ = tlsConn.Close() })
	defer stopOnCancel()

	destination := net.JoinHostPort(name, strconv.Itoa(port))
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Host: destination},
		Host:   destination,
		Header: header,
	}
	if err := req.Write(tlsConn); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("writing CONNECT request: %w", err)
	}

	reader := bufio.NewReader(tlsConn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("reading CONNECT response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		_ = resp.Body.Close()
		_ = tlsConn.Close()
		message := strings.TrimSpace(string(body))
		if message == "" {
			message = resp.Status
		}
		return nil, fmt.Errorf("router rejected CONNECT to %s with %s: %s", destination, resp.Status, message)
	}
	if !stopOnCancel() {
		_ = tlsConn.Close()
		return nil, ctx.Err()
	}

	return &forwardedConn{Conn: tlsConn, reader: reader}, nil
}

// routerClientCerts holds the current router client certificate. Adapted from
// internal/ateclient/router.go.
type routerClientCerts struct {
	clientset kubernetes.Interface
	namespace string
	sa        string

	mu             sync.Mutex
	cert           *tls.Certificate
	refreshAt      time.Time
	warnedFallback bool
}

func (c *routerClientCerts) get(ctx context.Context) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.cert != nil && now.Before(c.refreshAt) {
		return c.cert, nil
	}
	timeout := routerCertTimeout
	if c.cert != nil && now.Before(c.cert.Leaf.NotAfter) {
		timeout = routerCertRefreshTimeout
	}
	cert, err := requestPodIdentityCertificate(ctx, c.clientset, routerCertRequester, c.namespace, c.sa, timeout)
	if err != nil {
		now = time.Now()
		if c.cert != nil && now.Before(c.cert.Leaf.NotAfter) {
			if !c.warnedFallback {
				c.warnedFallback = true
				fmt.Fprintf(os.Stderr, "Warning: failed to refresh router client certificate (%v); using cached certificate until %s\n",
					err, c.cert.Leaf.NotAfter.Format(time.RFC3339))
			}
			backoff := now.Add(time.Minute)
			if c.cert.Leaf.NotAfter.Before(backoff) {
				backoff = c.cert.Leaf.NotAfter
			}
			c.refreshAt = backoff
			return c.cert, nil
		}
		return nil, fmt.Errorf("requesting a router client certificate for %s/%s: %w", c.namespace, c.sa, err)
	}
	c.cert = &cert
	c.refreshAt = cert.Leaf.NotBefore.Add(cert.Leaf.NotAfter.Sub(cert.Leaf.NotBefore) / 2)
	c.warnedFallback = false
	return c.cert, nil
}

// forwardedConn recovers bytes http.ReadResponse buffered past the header
// boundary.
type forwardedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *forwardedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *forwardedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
