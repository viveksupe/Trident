// Kube client access for shim-side observers (egress gateway log ingestion).
package substrate

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
)

// NewKubeClient builds a clientset from the same kubeconfig chain the
// control-plane client uses (env KUBECONFIG, in-cluster projected identity).
func NewKubeClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	kcfg, err := kubeConfig(kubeconfigPath, "")
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(kcfg)
}

// LogOptionsFor returns the log options for a since-seconds window.
func LogOptionsFor(sinceSeconds int64) *corev1.PodLogOptions {
	return &corev1.PodLogOptions{SinceSeconds: &sinceSeconds}
}
