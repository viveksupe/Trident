package substrate

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/viveksupe/Trident/internal/model"
)

// --- C3 self-heal classification suite (fix/p0-revert-escalation-classification).

// wrap mimics how Lifecycle.Revert reports errors (fmt.Errorf %w around the
// gRPC status error), so the classifier is exercised against real wrapping.
func wrap(code codes.Code, msg string) error {
	return fmt.Errorf("revert actor ts-ns/shim-x: %w", status.Error(code, msg))
}

func TestClassifyRevertError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want revertOutcome
	}{
		{"nil: revert succeeded or was a no-op", nil, revertRecovered},
		// Transient: control plane / transport problems, never purge material.
		{"unavailable", status.Error(codes.Unavailable, "conn refused"), revertTransient},
		{"deadline exceeded", status.Error(codes.DeadlineExceeded, "slow snapshot"), revertTransient},
		{"aborted", status.Error(codes.Aborted, "transaction conflict"), revertTransient},
		{"resource exhausted", status.Error(codes.ResourceExhausted, "quota"), revertTransient},
		{"internal", status.Error(codes.Internal, "server bug"), revertTransient},
		{"unknown code", status.Error(codes.Unknown, "proxy reset"), revertTransient},
		{"plain non-gRPC error", errors.New("dial tcp: connection reset by peer"), revertTransient},
		{"raw context deadline", context.DeadlineExceeded, revertTransient},
		{"raw context canceled", context.Canceled, revertTransient},
		{"wrapped transient (lifecycler wrapping)", wrap(codes.Unavailable, "api pod restarting"), revertTransient},
		{"wrapped context-style deadline", wrap(codes.DeadlineExceeded, "ctx deadline"), revertTransient},
		// Corruption allowlist (security review on C3): DataLoss alone is
		// affirmative restore-corruption evidence.
		{"wrapped data loss (only purge evidence)", wrap(codes.DataLoss, "snapshot corrupt"), revertCorruption},
		// Affirmative but NON-corruption refusals are operator-action: keep
		// the actor, Error-log, reset strikes, never auto-purge.
		{"failed precondition (benign no-op, swallowed by Revert)", wrap(codes.FailedPrecondition, "bad state"), revertOperator},
		{"invalid argument", wrap(codes.InvalidArgument, "bad template"), revertOperator},
		{"unimplemented (version skew)", wrap(codes.Unimplemented, "no such rpc"), revertOperator},
		{"permission denied (RBAC regression)", wrap(codes.PermissionDenied, "rbac"), revertOperator},
		{"already exists", wrap(codes.AlreadyExists, "dup actor"), revertOperator},
		{"unauthenticated", wrap(codes.Unauthenticated, "creds"), revertOperator},
		{"out of range", wrap(codes.OutOfRange, "truncated"), revertOperator},
		// Actor already gone: recreate, nothing to purge.
		{"not found", wrap(codes.NotFound, "no such actor"), revertAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRevertError(tc.err); got != tc.want {
				t.Fatalf("classifyRevertError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestSelfHealDecisionTransientNeverPurges drives the full classifier chain
// (gRPC status error -> classifyRevertError -> selfHealDecision) with
// transient failures and asserts a purge is never permitted — not on the
// first failure, not after a hundred, and not from a pre-existing strike
// count.
func TestSelfHealDecisionTransientNeverPurges(t *testing.T) {
	transientErrs := []error{
		wrap(codes.Unavailable, "control plane unreachable"),
		wrap(codes.DeadlineExceeded, "revert timed out"),
		wrap(codes.Aborted, "conflict"),
		wrap(codes.ResourceExhausted, "throttled"),
		wrap(codes.Internal, "internal error"),
		wrap(codes.Unknown, "unclassifiable"),
		errors.New("non-gRPC transport error"),
	}
	strikes := 0
	for call := 1; call <= 100; call++ {
		for _, err := range transientErrs {
			s, purge := selfHealDecision(strikes, classifyRevertError(err))
			if purge {
				t.Fatalf("call %d: purge permitted on transient error %v (strikes=%d)", call, err, s)
			}
			if s != 0 {
				t.Fatalf("call %d: transient error must reset the evidence chain, got strikes=%d", call, s)
			}
			strikes = s
		}
	}
	// Even starting from a pre-existing strike streak, transient evidence
	// neither escalates nor carries the streak forward.
	s, purge := selfHealDecision(selfHealEscalationN-1, classifyRevertError(wrap(codes.Unavailable, "blip")))
	if purge || s != 0 {
		t.Fatalf("transient outcome from streak %d: strikes=%d purge=%v, want 0/false", selfHealEscalationN-1, s, purge)
	}
}

// TestSelfHealDecisionPurgesAfterN is the flip side: affirmative
// restore-corruption evidence on N consecutive failing EnsureReady calls
// permits exactly one escalation point — the Nth — and not before.
func TestSelfHealDecisionPurgesAfterN(t *testing.T) {
	corrupt := classifyRevertError(wrap(codes.DataLoss, "snapshot corrupt"))
	if corrupt != revertCorruption {
		t.Fatalf("DataLoss must classify as corruption evidence, got %v", corrupt)
	}
	strikes := 0
	for call := 1; call < selfHealEscalationN; call++ {
		s, purge := selfHealDecision(strikes, corrupt)
		if purge {
			t.Fatalf("purge permitted at strike %d of %d (premature escalation)", s, selfHealEscalationN)
		}
		if s != call {
			t.Fatalf("strike count = %d, want %d", s, call)
		}
		strikes = s
	}
	strikes, purge := selfHealDecision(strikes, corrupt)
	if !purge {
		t.Fatalf("purge not permitted at strike %d (threshold %d)", strikes, selfHealEscalationN)
	}
	if strikes != selfHealEscalationN {
		t.Fatalf("strike count = %d, want %d", strikes, selfHealEscalationN)
	}
}

// TestSelfHealDecisionRequiresConsecutiveEvidence asserts the strikes must
// be *consecutive*: any non-corruption outcome (transient blip, successful
// revert, actor already gone) restarts the count, so a flapping actor is
// never purged.
func TestSelfHealDecisionRequiresConsecutiveEvidence(t *testing.T) {
	corruption := classifyRevertError(wrap(codes.DataLoss, "snapshot corrupt"))
	transient := classifyRevertError(wrap(codes.Unavailable, "blip"))

	strikes := 0
	for i := 0; i < selfHealEscalationN-1; i++ {
		var purge bool
		strikes, purge = selfHealDecision(strikes, corruption)
		if purge {
			t.Fatalf("purge at strike %d before reaching threshold", strikes)
		}
	}
	// A transient blip mid-streak resets the chain...
	strikes, purge := selfHealDecision(strikes, transient)
	if strikes != 0 || purge {
		t.Fatalf("transient must reset the streak: strikes=%d purge=%v", strikes, purge)
	}
	// ...so the next corruption evidence starts over at 1, not at the old streak.
	strikes, purge = selfHealDecision(strikes, corruption)
	if strikes != 1 || purge {
		t.Fatalf("after reset: strikes=%d purge=%v, want 1/false", strikes, purge)
	}
	// Recovered / absent outcomes reset too.
	strikes, _ = selfHealDecision(strikes, revertRecovered)
	if strikes != 0 {
		t.Fatalf("recovered outcome must reset strikes, got %d", strikes)
	}
	strikes, _ = selfHealDecision(selfHealEscalationN, revertAbsent)
	if strikes != 0 {
		t.Fatalf("absent outcome must reset strikes, got %d", strikes)
	}
}

// TestSelfHealDecisionOperatorActionNeverPurges is the security-review
// regression guard for C3: affirmative non-corruption codes — version skew
// (Unimplemented), RBAC regressions (PermissionDenied), misconfiguration
// (InvalidArgument) and the documented benign no-op (FailedPrecondition) —
// must never increment corruption strikes nor permit a purge, not even from
// an already-advanced streak; each such outcome resets the chain instead.
func TestSelfHealDecisionOperatorActionNeverPurges(t *testing.T) {
	operatorErrs := []error{
		wrap(codes.Unimplemented, "revert rpc absent (version skew)"),
		wrap(codes.PermissionDenied, "rbac regression"),
		wrap(codes.InvalidArgument, "bad template"),
		wrap(codes.FailedPrecondition, "benign no-op"),
		wrap(codes.AlreadyExists, "dup actor"),
		wrap(codes.Unauthenticated, "creds"),
		wrap(codes.OutOfRange, "truncated"),
	}
	for _, err := range operatorErrs {
		outcome := classifyRevertError(err)
		if outcome != revertOperator {
			t.Fatalf("classifyRevertError(%v) = %v, want revertOperator", err, outcome)
		}
		// Even from a streak one below threshold: no purge, chain reset.
		strikes, purge := selfHealDecision(selfHealEscalationN-1, outcome)
		if purge || strikes != 0 {
			t.Fatalf("operator outcome from streak %d: strikes=%d purge=%v, want 0/false",
				selfHealEscalationN-1, strikes, purge)
		}
		// Repeated operator outcomes never escalate, however many calls.
		strikes = 0
		for call := 1; call <= 100; call++ {
			strikes, purge = selfHealDecision(strikes, outcome)
			if purge {
				t.Fatalf("%v: purge permitted at call %d (strikes=%d)", err, call, strikes)
			}
		}
	}
	// DataLoss remains the sole code that can ever escalate.
	if got := classifyRevertError(wrap(codes.DataLoss, "snapshot corrupt")); got != revertCorruption {
		t.Fatalf("DataLoss must remain the corruption allowlist entry, got %v", got)
	}
}

func TestRetryTransientRevert(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("transient failures retried and eventually succeed", func(t *testing.T) {
		calls := 0
		err := retryTransientRevert(ctx, log, "shim-x", time.Microsecond, func(context.Context) error {
			calls++
			if calls < 3 {
				return wrap(codes.Unavailable, "flaky")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("want success on 3rd attempt, got %v", err)
		}
		if calls != 3 {
			t.Fatalf("revert called %d times, want 3", calls)
		}
	})

	t.Run("transient failures capped at revertMaxAttempts", func(t *testing.T) {
		calls := 0
		err := retryTransientRevert(ctx, log, "shim-x", time.Microsecond, func(context.Context) error {
			calls++
			return wrap(codes.Unavailable, "still down")
		})
		if calls != revertMaxAttempts {
			t.Fatalf("revert called %d times, want %d (initial + 2 retries)", calls, revertMaxAttempts)
		}
		if classifyRevertError(err) != revertTransient {
			t.Fatalf("final error must still classify as transient, got %v", classifyRevertError(err))
		}
	})

	t.Run("definitive failures are not retried", func(t *testing.T) {
		calls := 0
		err := retryTransientRevert(ctx, log, "shim-x", time.Microsecond, func(context.Context) error {
			calls++
			return wrap(codes.DataLoss, "snapshot corrupt")
		})
		if calls != 1 {
			t.Fatalf("revert called %d times, want 1 (no retry of definitive errors)", calls)
		}
		if classifyRevertError(err) != revertCorruption {
			t.Fatalf("want corruption classification, got %v", classifyRevertError(err))
		}
	})

	t.Run("operator-action failures are not retried", func(t *testing.T) {
		calls := 0
		err := retryTransientRevert(ctx, log, "shim-x", time.Microsecond, func(context.Context) error {
			calls++
			return wrap(codes.Unimplemented, "revert rpc absent (version skew)")
		})
		if calls != 1 {
			t.Fatalf("revert called %d times, want 1 (operator refusals are not transient)", calls)
		}
		if classifyRevertError(err) != revertOperator {
			t.Fatalf("want operator classification, got %v", classifyRevertError(err))
		}
	})

	t.Run("absent failures are not retried", func(t *testing.T) {
		calls := 0
		err := retryTransientRevert(ctx, log, "shim-x", time.Microsecond, func(context.Context) error {
			calls++
			return wrap(codes.NotFound, "actor gone")
		})
		if calls != 1 {
			t.Fatalf("revert called %d times, want 1", calls)
		}
		if classifyRevertError(err) != revertAbsent {
			t.Fatalf("want absent classification, got %v", classifyRevertError(err))
		}
	})

	t.Run("cancellation stops retries with a transient classification", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		calls := 0
		err := retryTransientRevert(cctx, log, "shim-x", time.Hour, func(context.Context) error {
			calls++
			return wrap(codes.Unavailable, "down")
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
		if classifyRevertError(err) != revertTransient {
			t.Fatalf("cancellation must classify transient (never purge), got %v", classifyRevertError(err))
		}
	})
}

// newTestBackend wires a Backend whose lifecycle points at the fake client.
func newTestBackend(f *fakeControl, l *Lifecycle) *Backend {
	return &Backend{
		lc:      l,
		atspace: "test",
		prefix:  "tri-",
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// TestEnsureReadyEnsuresEgressPolicyEveryPass is the S8 regression test at
// the EnsureReady level: the policy is read on every pass, a missing policy
// (failed fire-once create) is repaired, and a TRI_EGRESS_HOSTS change
// propagates to an already-running actor.
func TestEnsureReadyEnsuresEgressPolicyEveryPass(t *testing.T) {
	f := &fakeControl{actor: runningActor("test", "existing")}
	l := newPolicyLifecycle(f)
	b := newTestBackend(f, l)
	key := model.NewRouteKey("user-1", "chat-1")
	ctx := context.Background()

	// Pass 1: RUNNING actor with NO policy (fire-once create was lost) →
	// the pass creates it.
	h, _, err := b.EnsureReady(ctx, key)
	if err != nil {
		t.Fatalf("pass 1: %v", err)
	}
	if f.createPolicyCalls != 1 {
		t.Fatalf("pass 1 must repair the missing policy, creates=%d", f.createPolicyCalls)
	}
	cb := findTls(f.policy.GetRules(), l.CallbackHost)
	if cb == nil || !slices.Contains(cb.GetPorts().GetNumbers(), int32(9443)) {
		t.Fatalf("repaired policy has wrong callback rule: %v", f.policy.GetRules())
	}

	// Pass 2: converged policy → read but not written.
	if _, _, err := b.EnsureReady(ctx, key); err != nil {
		t.Fatalf("pass 2: %v", err)
	}
	if f.getPolicyCalls != 2 {
		t.Fatalf("policy must be read on every EnsureReady pass, reads=%d", f.getPolicyCalls)
	}
	if f.createPolicyCalls != 1 || f.updatePolicyCalls != 0 {
		t.Fatalf("converged policy must not be written: create=%d update=%d",
			f.createPolicyCalls, f.updatePolicyCalls)
	}

	// Host-list change → next pass patches the existing actor's policy.
	l.EgressHosts = append(l.EgressHosts, "added.example.com")
	if _, _, err := b.EnsureReady(ctx, key); err != nil {
		t.Fatalf("pass 3: %v", err)
	}
	if f.getPolicyCalls != 3 || f.updatePolicyCalls != 1 {
		t.Fatalf("host drift must produce exactly one read+update: get=%d update=%d",
			f.getPolicyCalls, f.updatePolicyCalls)
	}
	if tp := findTls(f.lastUpdateRules, "added.example.com"); tp == nil {
		t.Fatalf("new host did not reach the policy: %v", f.lastUpdateRules)
	}
	_ = h
}

// TestEnsureReadyCreatesPolicyForNewActor: the create path still guarantees
// the policy before resume, on the configured callback port.
func TestEnsureReadyCreatesPolicyForNewActor(t *testing.T) {
	f := &fakeControl{} // no actor, no policy
	l := newPolicyLifecycle(f)
	b := newTestBackend(f, l)
	key := model.NewRouteKey("user-1", "chat-2")
	ctx := context.Background()

	h, dialer, err := b.EnsureReady(ctx, key)
	if err != nil {
		t.Fatalf("EnsureReady: %v", err)
	}
	if h == nil || dialer == nil {
		t.Fatal("EnsureReady returned nil handle or dialer")
	}
	if f.createActorCalls != 1 {
		t.Fatalf("actor not created: %d", f.createActorCalls)
	}
	if f.createPolicyCalls != 1 {
		t.Fatalf("policy not created with the actor: %d", f.createPolicyCalls)
	}
	if f.resumeCalls != 1 {
		t.Fatalf("fresh actor must be resumed once, resumes=%d", f.resumeCalls)
	}
	cb := findTls(f.policy.GetRules(), l.CallbackHost)
	if cb == nil || !slices.Contains(cb.GetPorts().GetNumbers(), int32(9443)) {
		t.Fatalf("callback rule wrong on create path: %v", f.policy.GetRules())
	}
}
