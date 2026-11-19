// Diagnostics-only helpers (not part of the shim's runtime surface).
package substrate

import (
	"context"

	"github.com/viveksupe/Trident/third_party/ateapi"
)

// NewAPIClientForTest dials the control plane with the default env wiring.
func NewAPIClientForTest() (*APIClient, error) {
	kcfg, err := kubeConfigForEnv()
	if err != nil {
		return nil, err
	}
	return NewAPIClient(context.Background(), kcfg, "", "",
		envDefault("TRI_API_SERVICE", "api"), envDefault("TRI_CLIENT_SA", "ate-client"),
		envDefault("ATE_NAMESPACE", "ate-system"))
}

// GetTemplateForTest fetches an ActorTemplate (diagnostics).
func GetTemplateForTest(ctx context.Context, c *APIClient, atespace, name string) (*ateapi.ActorTemplate, error) {
	return c.GetActorTemplate(ctx, &ateapi.GetActorTemplateRequest{
		ActorTemplate: &ateapi.ObjectRef{Atespace: atespace, Name: name},
	})
}

// GetEgressPolicyForTest fetches an actor's egress policy (diagnostics).
func GetEgressPolicyForTest(ctx context.Context, c *APIClient, atespace, name string) (*ateapi.EgressPolicy, error) {
	lc := &Lifecycle{client: c}
	return lc.GetEgressPolicy(ctx, atespace, name)
}

// ActorInfo is a diagnostics view of one actor.
type ActorInfo struct {
	Atespace string
	Name     string
	Template string
	State    string
}

// ListActorInfosForTest lists actors with their template + state.
func ListActorInfosForTest(ctx context.Context, c *APIClient, atespace string) ([]ActorInfo, error) {
	lc := &Lifecycle{client: c, TemplateAtespace: atespace}
	actors, err := lc.ListActors(ctx, atespace)
	if err != nil {
		return nil, err
	}
	var out []ActorInfo
	for _, a := range actors {
		out = append(out, ActorInfo{
			Atespace: atespace,
			Name:     a.GetMetadata().GetName(),
			Template: a.GetActorTemplate().GetName(),
			State:    a.GetStatus().GetState().String(),
		})
	}
	return out, nil
}

// DeleteActorForTest destroys an actor (files in its durable volume are lost).
func DeleteActorForTest(ctx context.Context, c *APIClient, atespace, name string) error {
	lc := &Lifecycle{client: c}
	return lc.Delete(ctx, atespace, name)
}

// SuspendAllForTest suspends every actor in atespace (diagnostics).
func SuspendAllForTest(ctx context.Context, c *APIClient, atespace string) (int, error) {
	lc := &Lifecycle{client: c, TemplateAtespace: atespace}
	actors, err := lc.ListActors(ctx, atespace)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range actors {
		name := a.GetMetadata().GetName()
		if name == "" || a.GetStatus().GetState() != ateapi.ActorState_ACTOR_STATE_RUNNING {
			continue
		}
		if err := lc.Suspend(ctx, atespace, name, ateapi.DurabilityMode_DURABILITY_MODE_ASYNCHRONOUS); err != nil {
			continue
		}
		n++
	}
	return n, nil
}

// CycleActorForTest suspends then resumes an actor (diagnostics).
func CycleActorForTest(ctx context.Context, c *APIClient, atespace, name string) error {
	lc := &Lifecycle{client: c}
	if err := lc.Suspend(ctx, atespace, name, ateapi.DurabilityMode_DURABILITY_MODE_SYNCHRONOUS); err != nil {
		return err
	}
	return lc.Resume(ctx, atespace, name)
}

// MigrateCallbackRuleForTest runs the callback-rule migration for an actor
// (diagnostics).
func MigrateCallbackRuleForTest(ctx context.Context, c *APIClient, atespace, name, callbackHost string) error {
	lc := &Lifecycle{client: c, TemplateAtespace: atespace, TemplateName: name, CallbackHost: callbackHost}
	return lc.EnsureCallbackRule(ctx, atespace, name)
}
