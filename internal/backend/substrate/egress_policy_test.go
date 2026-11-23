package substrate

import (
	"context"
	"slices"
	"testing"
)

// newPolicyLifecycle wires a Lifecycle with the shim's egress configuration
// onto a fake control client.
func newPolicyLifecycle(f *fakeControl) *Lifecycle {
	return &Lifecycle{
		client:      newTestAPIClient(f),
		EgressHosts: []string{"api.example.com"},
		// The shim listens on a non-default port on purpose: any code that
		// re-derives 8443 from the host string regresses S8.
		CallbackHost: "trident-callback.ot-workerpool.svc",
		CallbackPort: "9443",
	}
}

// TestEnsureEgressPolicyCreatesMissingPolicy covers the strand case: a
// policy that was never created (fire-once create failed) is created on the
// next ensure, with the callback rule on the CONFIGURED port.
func TestEnsureEgressPolicyCreatesMissingPolicy(t *testing.T) {
	f := &fakeControl{}
	l := newPolicyLifecycle(f)

	if err := l.EnsureEgressPolicy(context.Background(), "test", "actor-1"); err != nil {
		t.Fatalf("EnsureEgressPolicy: %v", err)
	}
	if f.createPolicyCalls != 1 || f.getPolicyCalls != 1 || f.updatePolicyCalls != 0 {
		t.Fatalf("create=%d get=%d update=%d, want create=1 get=1 update=0",
			f.createPolicyCalls, f.getPolicyCalls, f.updatePolicyCalls)
	}

	tp := findTls(f.policy.GetRules(), "api.example.com")
	if tp == nil || !slices.Contains(tp.GetPorts().GetNumbers(), int32(443)) {
		t.Fatalf("base host rule missing or not on 443: %v", f.policy.GetRules())
	}
	cb := findTls(f.policy.GetRules(), "trident-callback.ot-workerpool.svc")
	if cb == nil {
		t.Fatal("callback rule missing from created policy")
	}
	if !slices.Contains(cb.GetPorts().GetNumbers(), int32(9443)) {
		t.Fatalf("callback rule must use configured port 9443, got %v", cb.GetPorts().GetNumbers())
	}
	if slices.Contains(cb.GetPorts().GetNumbers(), int32(8443)) {
		t.Fatalf("hard-coded 8443 leaked into the created callback rule: %v", cb.GetPorts().GetNumbers())
	}
}

// TestEnsureEgressPolicyUpdatesOnHostDrift: a TRI_EGRESS_HOSTS change must
// propagate to existing actors (S8: fire-once creation never did), while
// approval-granted rules are preserved and a converged policy triggers no
// further writes.
func TestEnsureEgressPolicyUpdatesOnHostDrift(t *testing.T) {
	f := &fakeControl{
		policy: testPolicy(
			tlsRule("api.example.com", []int32{443}),
			// egress-approval grant: must survive the ensure untouched.
			tlsRule("granted.example.org", []int32{443}),
			httpRule("granted.example.org", 80),
		),
	}
	l := newPolicyLifecycle(f)
	l.EgressHosts = []string{"api.example.com", "new.example.com"}

	if err := l.EnsureEgressPolicy(context.Background(), "test", "actor-1"); err != nil {
		t.Fatalf("EnsureEgressPolicy: %v", err)
	}
	if f.updatePolicyCalls != 1 || f.createPolicyCalls != 0 {
		t.Fatalf("update=%d create=%d, want update=1 create=0", f.updatePolicyCalls, f.createPolicyCalls)
	}
	rules := f.lastUpdateRules
	if tp := findTls(rules, "new.example.com"); tp == nil || !slices.Contains(tp.GetPorts().GetNumbers(), int32(443)) {
		t.Fatalf("new host missing from updated rules: %v", rules)
	}
	if tp := findTls(rules, "granted.example.org"); tp == nil {
		t.Fatalf("approval grant was dropped by the ensure: %v", rules)
	}
	if !hasHttpRule(rules, "granted.example.org") {
		t.Fatalf("approval grant http rule was dropped by the ensure: %v", rules)
	}
	// Callback repaired onto the configured port in the same write.
	cb := findTls(rules, "trident-callback.ot-workerpool.svc")
	if cb == nil || !slices.Contains(cb.GetPorts().GetNumbers(), int32(9443)) {
		t.Fatalf("callback rule not on configured port: %v", rules)
	}

	// Fixed point: a second pass over the converged policy writes nothing.
	if err := l.EnsureEgressPolicy(context.Background(), "test", "actor-1"); err != nil {
		t.Fatalf("second EnsureEgressPolicy: %v", err)
	}
	if f.updatePolicyCalls != 1 || f.createPolicyCalls != 0 {
		t.Fatalf("converged policy still writes: update=%d create=%d", f.updatePolicyCalls, f.createPolicyCalls)
	}
	if f.getPolicyCalls != 2 {
		t.Fatalf("policy must be read on every ensure, got %d reads", f.getPolicyCalls)
	}
}

// TestEnsureEgressPolicyRepairsStaleCallbackPort: the pre-S8 policy carries
// the hard-coded 8443 rule and possibly a legacy cleartext callback rule;
// both must self-correct to the configured port.
func TestEnsureEgressPolicyRepairsStaleCallbackPort(t *testing.T) {
	f := &fakeControl{
		policy: testPolicy(
			tlsRule("trident-callback.ot-workerpool.svc", []int32{8443}),
			httpRule("trident-callback.ot-workerpool.svc", 80),
			tlsRule("api.example.com", []int32{443}),
		),
	}
	l := newPolicyLifecycle(f)

	if err := l.EnsureEgressPolicy(context.Background(), "test", "actor-1"); err != nil {
		t.Fatalf("EnsureEgressPolicy: %v", err)
	}
	if f.updatePolicyCalls != 1 {
		t.Fatalf("stale callback port must trigger one update, got %d", f.updatePolicyCalls)
	}
	rules := f.lastUpdateRules
	if hasHttpRule(rules, "trident-callback.ot-workerpool.svc") {
		t.Fatalf("legacy cleartext callback rule survived migration: %v", rules)
	}
	covered := 0
	for _, r := range rules {
		tp := r.GetTlsPassthrough()
		if tp == nil || !ruleHasHostname(tp.GetHostnames(), "trident-callback.ot-workerpool.svc") {
			continue
		}
		covered++
		if !slices.Contains(tp.GetPorts().GetNumbers(), int32(9443)) {
			t.Fatalf("callback rule not on 9443: %v", tp.GetPorts().GetNumbers())
		}
		if slices.Contains(tp.GetPorts().GetNumbers(), int32(8443)) {
			t.Fatalf("stale 8443 survived the repair: %v", tp.GetPorts().GetNumbers())
		}
	}
	if covered != 1 {
		t.Fatalf("want exactly one callback rule after repair, got %d", covered)
	}
}

// TestEnsureCallbackRulePortAware: EnsureCallbackRule compares host AND port
// — a matching rule is a no-op, a wrong port is repaired even though the
// hostname matches, and a missing policy is created instead of erroring.
func TestEnsureCallbackRulePortAware(t *testing.T) {
	t.Run("matching port is a no-op", func(t *testing.T) {
		f := &fakeControl{policy: testPolicy(tlsRule("trident-callback.ot-workerpool.svc", []int32{9443}))}
		l := newPolicyLifecycle(f)
		if err := l.EnsureCallbackRule(context.Background(), "test", "actor-1"); err != nil {
			t.Fatalf("EnsureCallbackRule: %v", err)
		}
		if f.updatePolicyCalls != 0 || f.createPolicyCalls != 0 {
			t.Fatalf("matching rule must not write: update=%d create=%d", f.updatePolicyCalls, f.createPolicyCalls)
		}
	})

	t.Run("hostname match with wrong port is repaired", func(t *testing.T) {
		f := &fakeControl{policy: testPolicy(tlsRule("trident-callback.ot-workerpool.svc", []int32{8443}))}
		l := newPolicyLifecycle(f)
		if err := l.EnsureCallbackRule(context.Background(), "test", "actor-1"); err != nil {
			t.Fatalf("EnsureCallbackRule: %v", err)
		}
		if f.updatePolicyCalls != 1 {
			t.Fatalf("wrong port must be repaired, updates=%d", f.updatePolicyCalls)
		}
		tp := findTls(f.lastUpdateRules, "trident-callback.ot-workerpool.svc")
		if tp == nil || !slices.Contains(tp.GetPorts().GetNumbers(), int32(9443)) {
			t.Fatalf("rule not repaired to 9443: %v", f.lastUpdateRules)
		}
	})

	t.Run("missing policy is created, not an error", func(t *testing.T) {
		f := &fakeControl{}
		l := newPolicyLifecycle(f)
		if err := l.EnsureCallbackRule(context.Background(), "test", "actor-1"); err != nil {
			t.Fatalf("EnsureCallbackRule on missing policy: %v", err)
		}
		if f.createPolicyCalls != 1 {
			t.Fatalf("missing policy must be created, creates=%d", f.createPolicyCalls)
		}
		tp := findTls(f.policy.GetRules(), "trident-callback.ot-workerpool.svc")
		if tp == nil || !slices.Contains(tp.GetPorts().GetNumbers(), int32(9443)) {
			t.Fatalf("created callback rule wrong: %v", f.policy.GetRules())
		}
	})

	t.Run("empty callback host disables nothing else", func(t *testing.T) {
		f := &fakeControl{}
		l := newPolicyLifecycle(f)
		l.CallbackHost = ""
		if err := l.EnsureCallbackRule(context.Background(), "test", "actor-1"); err != nil {
			t.Fatalf("EnsureCallbackRule with no callback: %v", err)
		}
		if f.getPolicyCalls != 0 || f.createPolicyCalls != 0 {
			t.Fatalf("no-callback config must be a no-op: get=%d create=%d", f.getPolicyCalls, f.createPolicyCalls)
		}
	})
}

// TestDesiredEgressRulesMergesCallbackIntoBaseHost: when the callback host
// also sits in TRI_EGRESS_HOSTS the two intents must collapse into ONE rule,
// otherwise every ensure flip-flops (permanent update storm).
func TestDesiredEgressRulesMergesCallbackIntoBaseHost(t *testing.T) {
	f := &fakeControl{}
	l := newPolicyLifecycle(f)
	l.EgressHosts = []string{"api.example.com", l.CallbackHost}

	rules := l.desiredEgressRules()
	if len(rules) != 2 {
		t.Fatalf("want 2 rules (host + merged callback), got %d: %v", len(rules), rules)
	}
	cb := findTls(rules, l.CallbackHost)
	if cb == nil {
		t.Fatal("callback rule missing")
	}
	for _, p := range []int32{443, 9443} {
		if !slices.Contains(cb.GetPorts().GetNumbers(), p) {
			t.Fatalf("merged callback rule missing port %d: %v", p, cb.GetPorts().GetNumbers())
		}
	}

	// And the merged intent converges: first ensure writes, second is silent.
	f2 := &fakeControl{}
	l2 := newPolicyLifecycle(f2)
	l2.EgressHosts = []string{"api.example.com", l2.CallbackHost}
	if err := l2.EnsureEgressPolicy(context.Background(), "test", "a"); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	if err := l2.EnsureEgressPolicy(context.Background(), "test", "a"); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	if f2.updatePolicyCalls != 0 || f2.createPolicyCalls != 1 {
		t.Fatalf("merged intent must converge after create: create=%d update=%d",
			f2.createPolicyCalls, f2.updatePolicyCalls)
	}
}
