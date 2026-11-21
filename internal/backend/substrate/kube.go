// Package substrate speaks to an Agent Substrate install: the ate gRPC
// control plane (actor lifecycle) and the atenet CONNECT data plane.
//
// Adapted from agent-substrate/substrate internal packages (Apache-2.0,
// Copyright 2026 The Agent Substrate Authors); internal/ is not importable
// outside its module, so the pieces this shim needs live here with their
// license headers preserved.
package substrate

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// kubeConfig builds a client-go config: in the cluster use the pod's
// projected identity; outside the cluster use the kubeconfig (path + context).
func kubeConfig(kubeconfigPath, k8sContext string) (*rest.Config, error) {
	var cfg *rest.Config
	var err error
	if inCluster() {
		cfg, err = rest.InClusterConfig()
	} else {
		cfg, err = loadKubeConfig(kubeconfigPath, k8sContext)
	}
	if err != nil {
		return nil, err
	}
	// Older clusters use the deprecated beta ClusterTrustBundle and
	// PodCertificateRequest APIs; suppress their fallback warnings.
	cfg.WarningHandlerWithContext = &rest.NoWarnings{}
	return cfg, nil
}

// loadKubeConfig loads from an explicit path (or the default chain).
func loadKubeConfig(kubeconfigPath, k8sContext string) (*rest.Config, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath
	configOverrides := &clientcmd.ConfigOverrides{CurrentContext: k8sContext}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
}

// inCluster reports whether this process runs inside a pod (service account
// projected or KUBERNETES_SERVICE_HOST set).
func inCluster() bool {
	if _, err := os.Stat(filepath.Join("/var/run/secrets/kubernetes.io/serviceaccount", "token")); err == nil {
		return true
	}
	return os.Getenv("KUBERNETES_SERVICE_HOST") != ""
}

func kubeClientset(cfg *rest.Config) (*kubernetes.Clientset, error) {
	return kubernetes.NewForConfig(cfg)
}

// kubeConfigForEnv resolves the kubeconfig from the KUBECONFIG env (used by
// diagnostic helpers and the log observer).
func kubeConfigForEnv() (*rest.Config, error) { return kubeConfig(os.Getenv("KUBECONFIG"), "") }

// serviceDNSName renders "<service>.<namespace>.svc" — the name checked on
// serving certs and the audience of minted tokens.
func serviceDNSName(service, namespace string) string {
	return fmt.Sprintf("%s.%s.svc", service, namespace)
}
