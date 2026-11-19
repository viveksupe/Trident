// ClusterTrustBundle trust-bundle discovery. Adapted from
// agent-substrate/substrate internal/clustertrustbundle/client.go (Apache-2.0,
// Copyright 2026 The Agent Substrate Authors); only List is retained (the
// shim never writes trust bundles), and informers are dropped.
package substrate

import (
	"context"
	"fmt"

	certsv1 "k8s.io/api/certificates/v1"
	certsv1beta1 "k8s.io/api/certificates/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
)

// trustBundle is everything serverTLSConfig needs from a ClusterTrustBundle.
type trustBundle struct {
	name        string
	signerName  string
	trustBundle string
}

// trustBundleClient prefers certificates.k8s.io v1 and falls back to v1beta1
// only when discovery reports v1 absent (the deprecated beta API on older
// clusters).
type trustBundleClient struct {
	clientset kubernetes.Interface
	v1        bool
}

// Discover reports whether the cluster serves a ClusterTrustBundle API and
// which version to use.
func DiscoverClusterTrustBundles(d discoveryInterface) (schema.GroupVersion, error) {
	for _, gv := range []schema.GroupVersion{certsv1.SchemeGroupVersion, certsv1beta1.SchemeGroupVersion} {
		resources, err := d.ServerResourcesForGroupVersion(gv.String())
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return schema.GroupVersion{}, fmt.Errorf("discover ClusterTrustBundle %s: %w", gv.Version, err)
		}
		for _, resource := range resources.APIResources {
			if resource.Name == "clustertrustbundles" {
				return gv, nil
			}
		}
	}
	return schema.GroupVersion{}, fmt.Errorf("neither v1 nor v1beta1 ClusterTrustBundle is served")
}

// discoveryInterface is the subset of client-go's DiscoveryInterface used here.
type discoveryInterface interface {
	ServerResourcesForGroupVersion(groupVersion string) (*metav1.APIResourceList, error)
}

func newTrustBundleClient(clientset kubernetes.Interface) (*trustBundleClient, error) {
	gv, err := DiscoverClusterTrustBundles(clientset.Discovery())
	if err != nil {
		return nil, err
	}
	return &trustBundleClient{clientset: clientset, v1: gv == certsv1.SchemeGroupVersion}, nil
}

func (c *trustBundleClient) list(ctx context.Context) ([]trustBundle, error) {
	if c.v1 {
		list, err := c.clientset.CertificatesV1().ClusterTrustBundles().List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, err
		}
		return toBundles(len(list.Items), func(i int) (string, certsv1.ClusterTrustBundleSpec) {
			return list.Items[i].Name, list.Items[i].Spec
		}), nil
	}
	list, err := c.clientset.CertificatesV1beta1().ClusterTrustBundles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return toBundles(len(list.Items), func(i int) (string, certsv1.ClusterTrustBundleSpec) {
		return list.Items[i].Name, certsv1.ClusterTrustBundleSpec(list.Items[i].Spec)
	}), nil
}

func toBundles(n int, at func(int) (string, certsv1.ClusterTrustBundleSpec)) []trustBundle {
	out := make([]trustBundle, 0, n)
	for i := 0; i < n; i++ {
		name, spec := at(i)
		out = append(out, trustBundle{name: name, signerName: spec.SignerName, trustBundle: spec.TrustBundle})
	}
	return out
}
