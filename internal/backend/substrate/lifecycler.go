// Actor lifecycle over the ate gRPC control plane. Adapted from
// agent-substrate/substrate cmd/ate-setup/internal/steps/substrate.go
// (Apache-2.0, Copyright 2026 The Agent Substrate Authors).
package substrate

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"

	"github.com/viveksupe/Trident/third_party/ateapi"
)

// SingletonName is the egress policy's fixed name ("default").
const SingletonName = "default"

// objectRef builds the wire reference for an actor.
func objectRef(atespace, name string) *ateapi.ObjectRef {
	return &ateapi.ObjectRef{Atespace: atespace, Name: name}
}

// EnsureAtespace creates the atespace if it does not already exist. The store
// enforces that an ActorTemplate's atespace exists at create time.
func EnsureAtespace(ctx context.Context, client *APIClient, atespace string) error {
	_, err := client.CreateAtespace(ctx, &ateapi.CreateAtespaceRequest{
		Atespace: &ateapi.Atespace{
			Metadata: &ateapi.ResourceMetadata{Name: atespace},
		},
	})
	if status.Code(err) == codes.AlreadyExists {
		return nil
	}
	return err
}

// ActorTemplateFromManifest parses a single protojson-shaped YAML or JSON
// document into an ActorTemplate (strict: unknown fields are an error, so
// typos don't silently drop configuration).
func ActorTemplateFromManifest(manifest []byte) (*ateapi.ActorTemplate, error) {
	jsonData, err := yaml.YAMLToJSON(manifest)
	if err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}
	if string(jsonData) == "null" {
		return nil, fmt.Errorf("manifest is empty")
	}
	template := &ateapi.ActorTemplate{}
	if err := protojson.Unmarshal(jsonData, template); err != nil {
		return nil, err
	}
	return template, nil
}

// CreateActorTemplate creates the template through the ate API; an existing
// template is left in place (ActorTemplates are immutable — no update RPC).
func CreateActorTemplate(ctx context.Context, client *APIClient, template *ateapi.ActorTemplate) error {
	ref := template.GetMetadata()
	_, err := client.CreateActorTemplate(ctx, &ateapi.CreateActorTemplateRequest{ActorTemplate: template})
	if status.Code(err) == codes.AlreadyExists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating actor template %s/%s: %w", ref.GetAtespace(), ref.GetName(), err)
	}
	return nil
}

// createActor creates an actor from the template; an existing actor is left
// in place (idempotent restarts).
func createActor(ctx context.Context, client *APIClient, atespace, name, templateAtespace, templateName string) error {
	_, err := client.CreateActor(ctx, &ateapi.CreateActorRequest{
		Actor: &ateapi.Actor{
			Metadata: &ateapi.ResourceMetadata{
				Atespace: atespace,
				Name:     name,
			},
			ActorTemplate: &ateapi.ObjectRef{Atespace: templateAtespace, Name: templateName},
		},
	})
	if status.Code(err) == codes.AlreadyExists {
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating actor %s/%s: %w", atespace, name, err)
	}
	return nil
}

// ruleHasHostname reports whether host appears in hostnames.
func ruleHasHostname(hostnames []string, host string) bool {
	for _, h := range hostnames {
		if h == host {
			return true
		}
	}
	return false
}

// dropHostname removes one hostname from a list.
func dropHostname(hostnames []string, host string) []string {
	out := make([]string, 0, len(hostnames))
	for _, h := range hostnames {
		if h != host {
			out = append(out, h)
		}
	}
	return out
}

// tlsRule is one hostname's tls-passthrough rule. TLS-passthrough is
// required for the callback: the in-sandbox DNS only resolves hosts whose
// policy holds a TLS rule, and the shim terminates TLS itself (-k on the
// actor side against the self-signed cert).
func tlsRule(host string, ports []int32) *ateapi.EgressRule {
	return &ateapi.EgressRule{
		TlsPassthrough: &ateapi.TlsPassthroughRule{
			Hostnames: []string{host},
			Ports:     &ateapi.Ports{Numbers: append([]int32(nil), ports...)},
		},
	}
}

// callbackPort resolves the configured callback port, defaulting to the
// historical 8443. S8: l.CallbackPort is authoritative — the old code
// re-parsed a port out of the host-only CallbackHost and always yielded
// 8443, silently dead-ending the approval flow on any other port.
func callbackPort(configured string) int32 {
	if n, err := strconv.ParseInt(configured, 10, 32); err == nil && n >= 1 && n <= 65535 {
		return int32(n)
	}
	return 8443
}

// callbackRule allows the shim's callback listener on the configured port only.
func callbackRule(host, port string) *ateapi.EgressRule {
	return tlsRule(host, []int32{callbackPort(port)})
}

// desiredEgressRules collapses the shim's configuration into the rule set
// every actor's policy must contain: one tls-passthrough rule per
// TRI_EGRESS_HOSTS entry (443 only — they are TLS services) plus the callback
// rule on the CONFIGURED CallbackPort (S8: never re-parsed from the host-only
// CallbackHost string, which always yielded 8443). When the callback host
// also appears in the base list its ports merge into one rule, so the ensure
// reaches a fixed point instead of flip-flopping between two rules.
func (l *Lifecycle) desiredEgressRules() []*ateapi.EgressRule {
	type hostPorts struct {
		host  string
		ports []int32
	}
	var order []hostPorts
	add := func(host string, port int32) {
		for i := range order {
			if order[i].host != host {
				continue
			}
			for _, p := range order[i].ports {
				if p == port {
					return
				}
			}
			order[i].ports = append(order[i].ports, port)
			return
		}
		order = append(order, hostPorts{host: host, ports: []int32{port}})
	}
	// The in-sandbox DNS resolver only serves hosts with TLS rules, so the
	// callback rides tls-passthrough; the shim terminates TLS on its callback
	// port with a self-signed cert (agents use -k).
	for _, h := range l.EgressHosts {
		add(h, 443)
	}
	if l.CallbackHost != "" {
		add(l.CallbackHost, callbackPort(l.CallbackPort))
	}
	rules := make([]*ateapi.EgressRule, 0, len(order))
	for _, hp := range order {
		rules = append(rules, tlsRule(hp.host, hp.ports))
	}
	return rules
}

// desiredCallbackRules is the callback-only slice EnsureCallbackRule repairs
// against (diagnostics and legacy-rule migration entry point).
func (l *Lifecycle) desiredCallbackRules() []*ateapi.EgressRule {
	if l.CallbackHost == "" {
		return nil
	}
	return []*ateapi.EgressRule{callbackRule(l.CallbackHost, l.CallbackPort)}
}

// EnsureEgressPolicy is the idempotent ensure that replaces fire-once policy
// creation (S8): read the policy, compare against the desired rule set, and
// patch only on drift. EnsureReady calls it on every pass, so a failed create
// or a TRI_EGRESS_HOSTS change heals on the next request instead of stranding
// the actor deny-by-default forever.
func (l *Lifecycle) EnsureEgressPolicy(ctx context.Context, atespace, name string) error {
	return l.ensureEgressRules(ctx, atespace, name, l.desiredEgressRules())
}

// ensureEgressRules creates the policy when it is missing (the repair path
// for actors stranded by a failed fire-once create) or patches it when any
// desired rule is unsatisfied. The policy is left completely untouched when
// everything already matches — no update storms on hot EnsureReady passes.
func (l *Lifecycle) ensureEgressRules(ctx context.Context, atespace, name string, desired []*ateapi.EgressRule) error {
	if len(desired) == 0 {
		return nil
	}
	pol, err := l.GetEgressPolicy(ctx, atespace, name)
	if err != nil {
		return err
	}
	if pol == nil {
		return l.createEgressPolicy(ctx, atespace, name, desired)
	}
	merged, drift := l.mergeEgressRules(pol.Rules, desired)
	if !drift {
		return nil
	}
	pol.Rules = merged
	return l.UpdateEgressPolicy(ctx, atespace, name, pol)
}

// createEgressPolicy creates the actor's singleton policy with rules.
func (l *Lifecycle) createEgressPolicy(ctx context.Context, atespace, name string, rules []*ateapi.EgressRule) error {
	_, err := l.client.CreateActorEgressPolicy(ctx, &ateapi.CreateActorEgressPolicyRequest{
		Actor: objectRef(atespace, name),
		EgressPolicy: &ateapi.EgressPolicy{
			Metadata: &ateapi.ResourceMetadata{
				Atespace: atespace,
				Name:     SingletonName,
			},
			Rules: rules,
		},
	})
	if status.Code(err) == codes.AlreadyExists {
		// Lost a create race; the next ensure pass reconciles the rules.
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating egress policy for actor %s/%s: %w", atespace, name, err)
	}
	return nil
}

// mergeEgressRules folds the desired single-host rules into the existing
// rule set. A desired pair is satisfied when some tls-passthrough rule
// already contains the hostname with every wanted port; an unsatisfied pair
// is repaired by stripping the hostname from tls rules that don't cover the
// wanted ports (this is what self-corrects a stale callback port) and
// appending the desired rule. Rules not touching a desired hostname — the
// egress approval flow's grants — are never modified or dropped, and legacy
// cleartext callback rules are migrated away while the callback host is being
// repaired.
func (l *Lifecycle) mergeEgressRules(existing, desired []*ateapi.EgressRule) ([]*ateapi.EgressRule, bool) {
	out := append([]*ateapi.EgressRule(nil), existing...)
	drift := false
	for _, d := range desired {
		host, ports := desiredHostPorts(d)
		if host == "" {
			continue
		}
		if tpCovers(out, host, ports) {
			continue
		}
		drift = true
		out = stripTlsHostname(out, host)
		if host == l.CallbackHost {
			out = dropHttpHostname(out, host)
		}
		out = append(out, d)
	}
	return out, drift
}

// desiredHostPorts reads the single hostname/ports pair a desired rule
// carries (desiredEgressRules builds exactly one rule per host).
func desiredHostPorts(d *ateapi.EgressRule) (string, []int32) {
	tp := d.GetTlsPassthrough()
	if tp == nil || len(tp.GetHostnames()) == 0 {
		return "", nil
	}
	return tp.GetHostnames()[0], tp.GetPorts().GetNumbers()
}

// tpCovers reports whether some tls rule lets host reach every wanted port.
func tpCovers(rules []*ateapi.EgressRule, host string, ports []int32) bool {
	for _, r := range rules {
		tp := r.GetTlsPassthrough()
		if tp == nil || !ruleHasHostname(tp.GetHostnames(), host) {
			continue
		}
		if tp.GetPorts().GetAll() != nil {
			return true // all-ports rule covers everything; never strip it
		}
		if hasAllPorts(tp.GetPorts().GetNumbers(), ports) {
			return true
		}
	}
	return false
}

func hasAllPorts(have, want []int32) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// stripTlsHostname removes host from every tls rule carrying it, dropping
// rules left without hostnames.
func stripTlsHostname(rules []*ateapi.EgressRule, host string) []*ateapi.EgressRule {
	var out []*ateapi.EgressRule
	for _, r := range rules {
		tp := r.GetTlsPassthrough()
		if tp == nil || !ruleHasHostname(tp.GetHostnames(), host) {
			out = append(out, r)
			continue
		}
		if hn := dropHostname(tp.GetHostnames(), host); len(hn) > 0 {
			out = append(out, &ateapi.EgressRule{TlsPassthrough: &ateapi.TlsPassthroughRule{
				Hostnames: hn,
				Ports:     tp.GetPorts(),
			}})
		}
	}
	return out
}

// dropHttpHostname strips host from cleartext rules (the legacy callback
// migration), keeping rules that still name other hosts.
func dropHttpHostname(rules []*ateapi.EgressRule, host string) []*ateapi.EgressRule {
	var out []*ateapi.EgressRule
	for _, r := range rules {
		h := r.GetHttp()
		if h == nil || !ruleHasHostname(h.GetHostnames(), host) {
			out = append(out, r)
			continue
		}
		if hn := dropHostname(h.GetHostnames(), host); len(hn) > 0 {
			out = append(out, &ateapi.EgressRule{Http: &ateapi.HttpRule{
				Hostnames: hn,
				Ports:     h.GetPorts(),
			}})
		}
	}
	return out
}

// EnsureCallbackRule guarantees the callback rule exists with exactly the
// configured host AND port for an actor, migrating older cleartext-http
// callback rules to TLS rules. S8: the old hostname-only comparison let a
// stale hard-coded-8443 rule mask a differently configured port, silently
// killing the approval flow.
func (l *Lifecycle) EnsureCallbackRule(ctx context.Context, atespace, name string) error {
	return l.ensureEgressRules(ctx, atespace, name, l.desiredCallbackRules())
}

// GetActor returns the actor record, normalized to nil when absent.
func (l *Lifecycle) GetActor(ctx context.Context, atespace, name string) (*ateapi.Actor, error) {
	actor, err := l.client.GetActor(ctx, &ateapi.GetActorRequest{Actor: objectRef(atespace, name)})
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get actor %s/%s: %w", atespace, name, err)
	}
	return actor, nil
}

// EnsureCreated creates the actor (and its egress policy) when missing.
func (l *Lifecycle) EnsureCreated(ctx context.Context, atespace, name string) error {
	if err := createActor(ctx, l.client, atespace, name, l.TemplateAtespace, l.TemplateName); err != nil {
		return err
	}
	// Guarantee the policy in the same pass so a fresh actor never resumes
	// policy-less; EnsureReady's every-pass ensureEgressPolicy repairs
	// anything this create loses (S8).
	if err := l.EnsureEgressPolicy(ctx, atespace, name); err != nil {
		return err
	}
	return nil
}

// Resume makes the actor RUNNING. ResumeActor returns only after the
// template's wakeup probe answers HTTP 200, so the actor's HTTP listener is
// genuinely serving when this returns.
func (l *Lifecycle) Resume(ctx context.Context, atespace, name string) error {
	_, err := l.client.ResumeActor(ctx, &ateapi.ResumeActorRequest{Actor: objectRef(atespace, name)})
	if err != nil {
		return fmt.Errorf("resume actor %s/%s: %w", atespace, name, err)
	}
	return nil
}

// Suspend checkpoints the actor. mode selects durable vs node-only captures.
func (l *Lifecycle) Suspend(ctx context.Context, atespace, name string, durability ateapi.DurabilityMode) error {
	resp, err := l.client.SuspendActor(ctx, &ateapi.SuspendActorRequest{
		Actor:   objectRef(atespace, name),
		Options: &ateapi.SuspendOptions{Mode: durability},
	})
	if err != nil {
		return fmt.Errorf("suspend actor %s/%s: %w", atespace, name, err)
	}
	_ = resp
	return nil
}

// Revert rolls an actor back to its durable snapshot (the recovery substrate
// prescribes for crashed or un-restorable actors).
func (l *Lifecycle) Revert(ctx context.Context, atespace, name string) error {
	resp, err := l.client.RevertActor(ctx, &ateapi.RevertActorRequest{Actor: objectRef(atespace, name)})
	if err != nil {
		// Reverting a suspended actor without a node-local snapshot is a
		// no-op on the substrate side; treat NotFound-style refusals as such.
		if status.Code(err) == codes.FailedPrecondition {
			return nil
		}
		return fmt.Errorf("revert actor %s/%s: %w", atespace, name, err)
	}
	_ = resp
	return nil
}

// Delete destroys the actor and its durable data.
func (l *Lifecycle) Delete(ctx context.Context, atespace, name string) error {
	_, err := l.client.DeleteActor(ctx, &ateapi.DeleteActorRequest{Actor: objectRef(atespace, name)})
	if status.Code(err) == codes.NotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("delete actor %s/%s: %w", atespace, name, err)
	}
	return nil
}

// ListActors returns actor metadata in one atespace (shim-created actors
// carry the shim's prefix, which the caller filters on).
func (l *Lifecycle) ListActors(ctx context.Context, atespace string) ([]*ateapi.Actor, error) {
	resp, err := l.client.ListActors(ctx, &ateapi.ListActorsRequest{Atespace: atespace})
	if err != nil {
		return nil, fmt.Errorf("list actors in %s: %w", atespace, err)
	}
	return resp.GetActors(), nil
}

// GetEgressPolicyForTest exposes the policy read (diagnostics only).
func (l *Lifecycle) GetEgressPolicyForTest(ctx context.Context, atespace, name string) (*ateapi.EgressPolicy, error) {
	return l.GetEgressPolicy(ctx, atespace, name)
}

// GetEgressPolicy returns the actor's singleton egress policy, or nil when
// the actor has none yet.
func (l *Lifecycle) GetEgressPolicy(ctx context.Context, atespace, name string) (*ateapi.EgressPolicy, error) {
	pol, err := l.client.GetActorEgressPolicy(ctx, &ateapi.GetActorEgressPolicyRequest{
		Actor: objectRef(atespace, name),
		Name:  SingletonName,
	})
	if status.Code(err) == codes.NotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get egress policy for actor %s/%s: %w", atespace, name, err)
	}
	return pol, nil
}

// UpdateEgressPolicy replaces the actor's egress policy. The stored metadata
// uid and version ride along as the substrate preconditions.
func (l *Lifecycle) UpdateEgressPolicy(ctx context.Context, atespace, name string, pol *ateapi.EgressPolicy) error {
	md := pol.GetMetadata()
	_, err := l.client.UpdateActorEgressPolicy(ctx, &ateapi.UpdateActorEgressPolicyRequest{
		Actor:        objectRef(atespace, name),
		EgressPolicy: pol,
	})
	if err != nil {
		return fmt.Errorf("update egress policy for actor %s/%s (version %v): %w",
			atespace, name, md.GetVersion(), err)
	}
	return nil
}

// WaitActorTemplateGolden blocks until the template's golden snapshot is
// built. It fails fast when the template reconciler reports an error, and
// returns immediately for a template that opted out of the golden snapshot.
func WaitActorTemplateGolden(ctx context.Context, client *APIClient, atespace, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	ref := objectRef(atespace, name)
	var lastErr error
	for {
		template, err := client.GetActorTemplate(ctx, &ateapi.GetActorTemplateRequest{ActorTemplate: ref})
		lastErr = err
		if err == nil {
			if template.GetSnapshotConfig().GetGoldenSnapshotConfig().GetMode() == ateapi.GoldenSnapshotMode_GOLDEN_SNAPSHOT_MODE_DISABLED {
				// The template opted out: no golden snapshot will ever appear,
				// and none is needed.
				return nil
			}
			goldenStatus := template.GetStatus().GetGoldenSnapshotStatus()
			if goldenStatus.GetGoldenTag().GetName() != "" {
				return nil
			}
			if msg := goldenStatus.GetErrorMessage(); msg != "" {
				return fmt.Errorf("actor template %s/%s failed: %s", atespace, name, msg)
			}
		}
		if time.Now().After(deadline) {
			if lastErr != nil {
				return fmt.Errorf("timed out waiting for actor template %s/%s golden snapshot: last error: %w", atespace, name, lastErr)
			}
			return fmt.Errorf("timed out waiting for actor template %s/%s golden snapshot", atespace, name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// CreateActorTemplateAndWait creates the rendered template and waits for its
// golden snapshot to build on some worker.
func CreateActorTemplateAndWait(ctx context.Context, client *APIClient, template *ateapi.ActorTemplate, timeout time.Duration) error {
	ref := template.GetMetadata()
	atespace, name := ref.GetAtespace(), ref.GetName()
	if err := EnsureAtespace(ctx, client, atespace); err != nil {
		return fmt.Errorf("ensuring atespace %s: %w", atespace, err)
	}
	if err := CreateActorTemplate(ctx, client, template); err != nil {
		return err
	}
	return WaitActorTemplateGolden(ctx, client, atespace, name, timeout)
}
