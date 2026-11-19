// Observer ingests the substrate egress gateway's deny logs and turns each
// blocked connection into a pending approval: the human sees what agents
// tried to reach without anyone running the helper.
package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// DenyLog mirrors the gateway's deny JSON lines.
type DenyLog struct {
	Actor   string `json:"actor"`
	Chain   string `json:"chain"`
	Dest    string `json:"destination"`
	SNI     string `json:"sni"`
	Leg     string `json:"leg"`
	Details string `json:"details"`
}

// Observer polls atenet-egress pod logs and files pending requests for
// denied connections originating from shim-managed actors.
type Observer struct {
	mgr       *Manager
	checker   ActorChecker
	clientset *kubernetes.Clientset
	ns        string
	filter    string
	cooldown  time.Duration
	log       *slog.Logger

	mu   sync.Mutex
	seen map[string]time.Time
}

// NewObserver constructs the observer. checker filters foreign/unknown
// actors out of the gateway's logs.
func NewObserver(mgr *Manager, checker ActorChecker, clientset *kubernetes.Clientset, ns, filter string, log *slog.Logger) *Observer {
	return &Observer{
		mgr: mgr, checker: checker, clientset: clientset, ns: ns, filter: filter,
		cooldown: 15 * time.Minute,
		log:      log, seen: map[string]time.Time{},
	}
}

// Tick reads the recent deny lines from every matching pod and submits the
// unknown ones as pending requests.
func (o *Observer) Tick(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	pods, err := o.clientset.CoreV1().Pods(o.ns).List(ctx, metav1.ListOptions{LabelSelector: o.filter})
	if err != nil {
		o.log.Debug("observer pod list failed", "err", err)
		return
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, c := range pod.Spec.Containers {
			// Deny telemetry lines live in the envoy container.
			if c.Name != "envoy" {
				continue
			}
			f, err := o.clientset.CoreV1().Pods(o.ns).GetLogs(pod.Name, &corev1.PodLogOptions{
				Container:    c.Name,
				SinceSeconds: int64Ptr(90),
			}).Stream(ctx)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 16*1024), 256*1024)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if !strings.HasPrefix(line, "{") {
					continue
				}
				var d DenyLog
				if json.Unmarshal([]byte(line), &d) != nil || d.Chain != "denied" {
					continue
				}
				o.handle(ctx, d)
			}
			_ = f.Close()
		}
	}
}

func (o *Observer) handle(ctx context.Context, d DenyLog) {
	// actor spiffe: .../worker-for-actor/<atespace>/<name>
	parts := strings.Split(d.Actor, "/")
	if len(parts) < 2 {
		return
	}
	atespace, actor := parts[len(parts)-2], parts[len(parts)-1]
	if !strings.HasPrefix(actor, o.mgr.ActorPrefix) {
		return
	}
	if ok, err := o.check(ctx, atespace, actor); err != nil || !ok {
		return
	}
	ip := destIP(d.Dest)
	if ip == "" {
		return
	}
	host := d.SNI
	if host == "" {
		host = ptrHost(ip) // reverse lookup; may be empty
	}

	key := actor + "|" + host + "|" + ip
	o.mu.Lock()
	if until, ok := o.seen[key]; ok && time.Now().Before(until) {
		o.mu.Unlock()
		return
	}
	o.seen[key] = time.Now().Add(o.cooldown)
	o.mu.Unlock()

	reason := fmt.Sprintf("blocked egress to %s (observed in gateway logs)", d.Dest)
	if _, err := o.mgr.SubmitObserved(ctx, atespace, actor, host, ip, reason); err != nil {
		o.log.Debug("observer submit skipped", "actor", actor, "host", host, "err", err)
		return
	}
	o.log.Info("observed blocked egress", "actor", actor, "ip", ip, "host", host)
}

// SubmitObserved records a gateway-observed deny as a pending request. The
// host may be empty (no SNI, no PTR) — the console then asks the human for
// the allowlist name before opening it.
func (m *Manager) SubmitObserved(ctx context.Context, atespace, actor, host, ip, reason string) (*Request, error) {
	if host != "" {
		host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
		if existing, err := m.store.PendingFor(actor, host); err == nil && len(existing) > 0 {
			return &existing[0], nil
		}
	}
	r := &Request{Atespace: atespace, ActorName: actor, Host: host, Reason: reason, Status: StatusPending}
	if err := m.store.InsertRequest(r); err != nil {
		return nil, err
	}
	return r, nil
}

// SetRequestHost lets the human correct an observed request's allowlist
// hostname before approving (blocked connections carry an IP, not a name).
func (m *Manager) SetRequestHost(id int64, host string) error {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" || strings.Contains(host, "/") || strings.Contains(host, " ") {
		return fmt.Errorf("invalid hostname %q", host)
	}
	return m.store.SetHost(id, host)
}

// ApproveHost approves a request with a human-provided (or corrected)
// hostname override.
func (m *Manager) ApproveHost(ctx context.Context, id int64, ttl time.Duration, hostOverride string) error {
	if hostOverride != "" {
		if err := m.SetRequestHost(id, hostOverride); err != nil {
			return err
		}
	}
	return m.Approve(ctx, id, ttl)
}

func (o *Observer) check(ctx context.Context, atespace, actor string) (bool, error) {
	ok := strings.HasPrefix(actor, o.mgr.ActorPrefix)
	atespaceOk, exists, err := o.mgr.checkerFor()(ctx, actor)
	if err != nil {
		return false, err
	}
	return ok && exists && atespaceOk == atespace, nil
}

func destIP(dest string) string {
	if i := strings.LastIndex(dest, ":"); i >= 0 {
		return strings.Trim(dest[:i], "[]")
	}
	return dest
}

// ptrHost reverse-resolves an IP; empty on failure (no PTR records exist).
func ptrHost(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func int64Ptr(n int64) *int64 { return &n }


