// Actor lifecycle over the ate gRPC control plane. Adapted from
// agent-substrate/substrate cmd/ate-setup/internal/steps/substrate.go
// (Apache-2.0, Copyright 2026 The Agent Substrate Authors).
package substrate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
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

// createActorEgressPolicy gives actor an egress policy with tls-passthrough
// rules for hosts, leaving an existing policy in place (idempotent).
func createActorEgressPolicy(ctx context.Context, client *APIClient, atespace, name string, hosts []string, callbackHost string) error {
	rules := make([]*ateapi.EgressRule, 0, len(hosts))
	for _, h := range hosts {
		// Base allowlist hosts are TLS services: 443 only.
		rules = append(rules, &ateapi.EgressRule{
			TlsPassthrough: &ateapi.TlsPassthroughRule{
				Hostnames: []string{h},
				Ports:     &ateapi.Ports{Numbers: []int32{443}},
			},
		})
	}
	if callbackHost != "" {
		// The in-sandbox DNS resolver only serves hosts with TLS rules, so
		// the callback rides tls-passthrough; the shim terminates TLS on its
		// callback port with a self-signed cert (agents use -k).
		port := "8443"
		if i := strings.LastIndex(callbackHost, ":"); i >= 0 {
			port = strings.TrimPrefix(callbackHost[i+1:], ":")
		}
		name := strings.SplitN(callbackHost, ":", 2)[0]
		rules = append(rules, callbackRule(name, port))
	}
	_, err := client.CreateActorEgressPolicy(ctx, &ateapi.CreateActorEgressPolicyRequest{
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
		return nil
	}
	if err != nil {
		return fmt.Errorf("creating egress policy for actor %s/%s: %w", atespace, name, err)
	}
	return nil
}

// callbackRule is the allow rule for the shim's egress callback hostname.
// TLS-passthrough is required: the in-sandbox DNS only resolves hosts whose
// policy holds a TLS rule, and the shim terminates TLS itself (-k on the
// actor side against the self-signed cert).
func ruleHasHostname(hostnames []string, host string) bool {
	for _, h := range hostnames {
		if h == host {
			return true
		}
	}
	return false
}

// callbackRule allows the shim's callback listener port only.
func callbackRule(host, port string) *ateapi.EgressRule {
	portNum, err := strconv.ParseInt(port, 10, 32)
	if err != nil {
		portNum = 8443
	}
	return &ateapi.EgressRule{
		TlsPassthrough: &ateapi.TlsPassthroughRule{
			Hostnames: []string{host},
			Ports:     &ateapi.Ports{Numbers: []int32{int32(portNum)}},
		},
	}
}

// EnsureCallbackRule guarantees the callback rule exists for an existing
// actor, migrating older cleartext-http callback rules to TLS rules.
func (l *Lifecycle) EnsureCallbackRule(ctx context.Context, atespace, name string) error {
	if l.CallbackHost == "" {
		return nil
	}
	pol, err := l.GetEgressPolicy(ctx, atespace, name)
	if err != nil {
		return err
	}
	if pol == nil {
		return fmt.Errorf("actor %s/%s has no egress policy", atespace, name)
	}
	for _, r := range pol.Rules {
		if r.GetTlsPassthrough() != nil {
			for _, h := range r.GetTlsPassthrough().GetHostnames() {
				if h == l.CallbackHost {
					return nil
				}
			}
		}
	}
	// Drop the legacy cleartext callback rule if present.
	kept := make([]*ateapi.EgressRule, 0, len(pol.Rules)+1)
	for _, r := range pol.Rules {
		if r.GetHttp() != nil && ruleHasHostname(r.GetHttp().GetHostnames(), l.CallbackHost) {
			continue
		}
		kept = append(kept, r)
	}
	port := l.CallbackPort
	if port == "" {
		port = "8443"
	}
	pol.Rules = append(kept, callbackRule(l.CallbackHost, port))
	return l.UpdateEgressPolicy(ctx, atespace, name, pol)
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
	// An egress policy exists whenever the shim needs one: the base
	// allowlist, or the callback rule alone (an empty EgressHosts used to
	// silently disable the whole approval flow).
	if len(l.EgressHosts) > 0 || l.CallbackHost != "" {
		if err := createActorEgressPolicy(ctx, l.client, atespace, name, l.EgressHosts, l.CallbackHost); err != nil {
			return err
		}
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
