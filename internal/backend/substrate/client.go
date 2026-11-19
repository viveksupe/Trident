// Control-plane gRPC client. Adapted from agent-substrate/substrate
// internal/ateclient/builder.go (Apache-2.0, Copyright 2026 The Agent
// Substrate Authors); OTel tracing and the metrics clientset are dropped.
package substrate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/viveksupe/Trident/third_party/ateapi"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // gcp/oidc/oauth exec plugin support
	"k8s.io/client-go/rest"
)

// roundRobinServiceConfig spreads RPCs over every ateapi replica (headless
// Service) instead of pinning one connection. internal/ateapiauth dials with
// the same policy.
const roundRobinServiceConfig = `{"loadBalancingConfig": [{"round_robin":{}}]}`

// servingCertSignerName and liveBundleSelector mirror the ClusterTrustBundle
// projected-volume sources in-cluster clients mount to verify substrate
// Service serving certificates.
const (
	servingCertSignerName = "servicedns.podcert.ate.dev/identity"
	liveBundleSelector    = "podcert.ate.dev/canarying=live"
)

// APIClient wraps the ateapi ControlClient and owns its transport.
type APIClient struct {
	ateapi.ControlClient
	conn   *grpc.ClientConn
	cancel func() // stops an out-of-cluster port-forward, if any
}

// Close tears down the connection and any port-forward.
func (c *APIClient) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	if c.cancel != nil {
		c.cancel()
	}
}

// NewAPIClient connects to the ate api Service. An empty endpoint dials
// api.<namespace>.svc:443 in-cluster, or port-forwards when running outside
// the cluster. cfg comes from kubeConfig(); it is passed separately so tests
// and the dialer can share one kubeconfig load.
func NewAPIClient(ctx context.Context, cfg *rest.Config, endpoint, tokenFile, apiService, clientSA, systemNamespace string) (*APIClient, error) {
	clientset, err := kubeClientset(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s client: %w", err)
	}
	apiHost := serviceDNSName(apiService, systemNamespace)

	// Verify the server before the bearer token rides along below.
	tlsCfg, err := serverTLSConfig(ctx, clientset, apiHost)
	if err != nil {
		return nil, err
	}

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	opts = append(opts, grpc.WithDefaultServiceConfig(roundRobinServiceConfig))

	tokenOpt, err := bearerTokenDialOption(ctx, clientset, tokenFile, clientSA, systemNamespace, apiHost)
	if err != nil {
		return nil, err
	}
	opts = append(opts, tokenOpt)

	var cancel func()
	target := endpoint
	if target == "" {
		if inCluster() {
			target = apiHost + ":443"
		} else {
			localPort, stop, err := servicePortForward(ctx, cfg, clientset, systemNamespace, apiService, 443)
			if err != nil {
				return nil, err
			}
			cancel = stop
			target = fmt.Sprintf("127.0.0.1:%d", localPort)
		}
	}
	conn, err := grpc.NewClient(target, opts...)
	if err != nil {
		if cancel != nil {
			cancel()
		}
		return nil, fmt.Errorf("dial ateapi at %s: %w", target, err)
	}
	return &APIClient{ControlClient: ateapi.NewControlClient(conn), conn: conn, cancel: cancel}, nil
}

// serverTLSConfig verifies a Service's servicedns serving certificate for
// serverName via live ClusterTrustBundles. Adapted from
// internal/ateclient/builder.go's serverTLSConfig.
func serverTLSConfig(ctx context.Context, clientset kubernetes.Interface, serverName string) (*tls.Config, error) {
	bundles, err := newTrustBundleClient(clientset)
	if err != nil {
		return nil, fmt.Errorf("discover ClusterTrustBundle API: %w", err)
	}
	items, err := bundles.list(ctx)
	if err != nil {
		return nil, fmt.Errorf("list ClusterTrustBundles: %w", err)
	}

	roots := x509.NewCertPool()
	found := false
	for _, item := range items {
		if item.signerName != servingCertSignerName {
			continue
		}
		if !roots.AppendCertsFromPEM([]byte(item.trustBundle)) {
			return nil, fmt.Errorf("ClusterTrustBundle %s contains no valid certificates", item.name)
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("no live ClusterTrustBundle found for signer %q", servingCertSignerName)
	}

	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    roots,
		ServerName: serverName,
	}, nil
}

// bearerTokenDialOption attaches a token from tokenFile when set, else mints a
// clientSA ServiceAccount token with audience apiHost.
//
// The minted token authenticates as the ServiceAccount principal, not as
// whoever runs the client (same semantics as internal/ateclient).
func bearerTokenDialOption(ctx context.Context, clientset kubernetes.Interface, tokenFile, clientSA, systemNamespace, apiHost string) (grpc.DialOption, error) {
	if tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read token file: %w", err)
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			return nil, fmt.Errorf("token file %q is empty", tokenFile)
		}
		return grpc.WithPerRPCCredentials(staticToken(token)), nil
	}
	expirationSeconds := int64(3600)
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			Audiences:         []string{apiHost},
			ExpirationSeconds: &expirationSeconds,
		},
	}
	token, err := clientset.CoreV1().ServiceAccounts(systemNamespace).CreateToken(ctx, clientSA, tokenRequest, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("request ateapi bearer token for SA %s/%s: %w", systemNamespace, clientSA, err)
	}
	if token.Status.Token == "" {
		return nil, fmt.Errorf("ateapi bearer token response was empty")
	}
	return grpc.WithPerRPCCredentials(staticToken(token.Status.Token)), nil
}

// staticToken is a bearer-token gRPC credential.
type staticToken string

func (c staticToken) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	if c == "" {
		return nil, fmt.Errorf("bearer token is empty")
	}
	return map[string]string{"authorization": "Bearer " + string(c)}, nil
}
func (c staticToken) RequireTransportSecurity() bool { return true }
