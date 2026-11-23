package egress

// White-box tests for the egress approval manager and its policy seam. They
// live in package egress (not test/) so they can drive the interleavings that
// only matter against the internals: the PolicyClient fake parks a revoke
// mid-policy-read while an approval lands, and the assertions inspect the
// exact policy rules a real substrate would end up storing.

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/viveksupe/Trident/third_party/ateapi"
)

// fakePolicyClient is an in-memory PolicyClient. A key registered in blockKey
// parks the first GetEgressPolicy on blocked until release is closed, giving
// tests a deterministic window inside a revoke's read-modify-write.
type fakePolicyClient struct {
	mu      sync.Mutex
	pols    map[string]*ateapi.EgressPolicy
	updates int

	blockKey  string
	blocked   chan struct{}
	release   chan struct{}
	blockOnce sync.Once
}

func newFakePolicyClient() *fakePolicyClient {
	return &fakePolicyClient{
		pols:    map[string]*ateapi.EgressPolicy{},
		blocked: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func polKey(atespace, name string) string { return atespace + "/" + name }

func (f *fakePolicyClient) setPolicy(atespace, name string, pol *ateapi.EgressPolicy) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pols[polKey(atespace, name)] = pol
}

func (f *fakePolicyClient) policy(atespace, name string) *ateapi.EgressPolicy {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pols[polKey(atespace, name)]
}

func (f *fakePolicyClient) updateCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.updates
}

func (f *fakePolicyClient) GetEgressPolicy(_ context.Context, atespace, name string) (*ateapi.EgressPolicy, error) {
	key := polKey(atespace, name)
	f.mu.Lock()
	block := f.blockKey != "" && f.blockKey == key
	f.mu.Unlock()
	if block {
		f.blockOnce.Do(func() { close(f.blocked) })
		<-f.release // test closes it mid-flight; later reads pass instantly
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pols[key], nil
}

func (f *fakePolicyClient) UpdateEgressPolicy(_ context.Context, atespace, name string, pol *ateapi.EgressPolicy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pols[polKey(atespace, name)] = pol
	f.updates++
	return nil
}

// ruleOpensHost reports whether any rule in pol still admits host.
func ruleOpensHost(pol *ateapi.EgressPolicy, host string) bool {
	if pol == nil {
		return false
	}
	for _, r := range pol.Rules {
		if tp := r.GetTlsPassthrough(); tp != nil && containsHostname(tp.GetHostnames(), host) {
			return true
		}
		if h := r.GetHttp(); h != nil && containsHostname(h.GetHostnames(), host) {
			return true
		}
	}
	return false
}

func newTestManager(t *testing.T, pol PolicyClient) (*Manager, *Store) {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "egress.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	checker := ActorChecker(func(context.Context, string) (string, bool, error) { return "ots", true, nil })
	m := New(st, pol, checker, log)
	m.ActorPrefix = "ot-"
	return m, st
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestClearHistoryRevokeAllRemovesRuleAfterDuplicates is finding S4's first
// half: duplicate grants for one (actor, host) exist (observed + helper paths
// produce them), and the revoke-all used ONE live snapshot for every
// decision, so each duplicate saw the other as still holding the shared rule
// and neither patched the policy — the host stayed open forever behind zero
// console rows.
func TestClearHistoryRevokeAllRemovesRuleAfterDuplicates(t *testing.T) {
	const ats, actor, host = "ots", "ot-uc1", "api.example.com"
	pol := newFakePolicyClient()
	pol.setPolicy(ats, actor, &ateapi.EgressPolicy{Rules: grantRules(host)})
	m, st := newTestManager(t, pol)

	// Duplicate grants bought with a FUTURE expiry are the pair that trips
	// the stale snapshot: each duplicate sees the other still holding the
	// shared rule, so neither patches the policy (host stays open forever
	// behind zero console rows).
	if err := st.InsertWildGrant(ats, actor, host, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertWildGrant(ats, actor, host, time.Hour); err != nil {
		t.Fatal(err)
	}
	if live, _ := st.Live(); len(live) != 2 {
		t.Fatalf("want two duplicate grants, got %d", len(live))
	}

	revoked, _, err := m.ClearHistoryRevokeAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if revoked != 2 {
		t.Fatalf("revoked=%d, want both grants stamped", revoked)
	}
	if live, _ := st.Live(); len(live) != 0 {
		t.Fatalf("grants left live after clear-all: %v", live)
	}
	if got := pol.policy(ats, actor); ruleOpensHost(got, host) {
		t.Fatalf("policy still opens %s after every grant for it was revoked: %v", host, got)
	}
	if pol.updateCount() == 0 {
		t.Fatal("revoke-all never patched the policy; the rule must be removed")
	}
}

// TestRevokeKeepsConcurrentlyApprovedGrantRule is finding S4's second half:
// the other-grants check ran OUTSIDE the per-actor policy lock against the
// caller's stale snapshot, so an approval landing between the snapshot and
// removeRule had its brand-new rule torn down (live grant, closed host).
func TestRevokeKeepsConcurrentlyApprovedGrantRule(t *testing.T) {
	const (
		ats1, actor1, host1 = "ots", "ot-ua", "api.example.com"
		ats2, actor2, host2 = "ots", "ot-ub", "cdn.example.net"
	)
	pol := newFakePolicyClient()
	pol.setPolicy(ats1, actor1, &ateapi.EgressPolicy{Rules: grantRules(host1)})
	pol.setPolicy(ats2, actor2, &ateapi.EgressPolicy{Rules: grantRules(host2)})
	pol.blockKey = polKey(ats2, actor2) // the foreign revoke parks on this read
	m, st := newTestManager(t, pol)

	// Insertion order is Live() order: the foreign grant must be revoked
	// FIRST so the loop is parked when the approval lands on actor1.
	if err := st.InsertWildGrant(ats2, actor2, host2, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertWildGrant(ats1, actor1, host1, time.Hour); err != nil {
		t.Fatal(err)
	}
	req := &Request{
		Atespace:  ats1,
		ActorName: actor1,
		Host:      host1,
		Reason:    "observed deny",
		Status:    StatusPending,
	}
	if err := st.InsertRequest(req); err != nil {
		t.Fatal(err)
	}

	type clearRes struct {
		revoked int
		err     error
	}
	resCh := make(chan clearRes, 1)
	go func() {
		n, _, err := m.ClearHistoryRevokeAll(context.Background())
		resCh <- clearRes{n, err}
	}()
	waitClosed(t, pol.blocked, "revoke to reach the foreign actor's policy read")

	// The approval lands while the revoke loop is parked (different actor, so
	// its policy lock is free) and completes fully: grant row + rule. The
	// positive TTL makes the new grant unambiguously hold the shared rule.
	if err := m.Approve(context.Background(), req.ID, 24*time.Hour); err != nil {
		t.Fatalf("concurrent approval failed: %v", err)
	}
	close(pol.release)

	var res clearRes
	select {
	case res = <-resCh:
	case <-time.After(5 * time.Second):
		t.Fatal("ClearHistoryRevokeAll did not finish after release")
	}
	if res.err != nil {
		t.Fatalf("ClearHistoryRevokeAll: %v", res.err)
	}
	if res.revoked != 2 {
		t.Fatalf("revoked=%d, want foreign grant + stale grant", res.revoked)
	}

	// The approved grant must still be open in the policy...
	if !ruleOpensHost(pol.policy(ats1, actor1), host1) {
		t.Fatal("revoke tore down the rule its concurrent approval had just bought " +
			"(decision ran outside the policy lock on a stale snapshot)")
	}
	// ...while the foreign grant's rule is gone.
	if ruleOpensHost(pol.policy(ats2, actor2), host2) {
		t.Fatal("foreign grant's rule must be removed")
	}
	live, err := st.Live()
	if err != nil {
		t.Fatal(err)
	}
	if len(live) != 1 || live[0].RequestID != req.ID || !live[0].Revoked.IsZero() {
		t.Fatalf("want exactly the approved grant live, got %+v", live)
	}
}

// TestSubmitObservedEmptyHostNeverAutoApproves is finding S11's core: only
// Approve validated the host, so maybeAutoApprove (observer + helper dedup
// paths) could patch Hostnames:[""] into the policy — the substrate rejects
// it and the observer then storms Get+Update every tick — or record a grant
// with no hostname. The guards belong in approveRequestLocked, the one
// funnel every approval entry point goes through.
func TestSubmitObservedEmptyHostNeverAutoApproves(t *testing.T) {
	const ats, actor = "ots", "ot-ua"
	pol := newFakePolicyClient()
	pol.setPolicy(ats, actor, &ateapi.EgressPolicy{}) // actor policy exists, no rules
	m, st := newTestManager(t, pol)

	// Standing auto rule: without the guard it grants Hostnames:[""].
	if err := st.SetAuto(actor, 0); err != nil {
		t.Fatal(err)
	}

	r, err := m.SubmitObserved(context.Background(), ats, actor, "", "192.0.2.7",
		"blocked egress to 192.0.2.7:443 (observed in gateway logs)")
	if err != nil {
		t.Fatalf("observed deny must file (not error) so the observer remembers it: %v", err)
	}
	if r.Status != StatusPending {
		t.Fatalf("empty-host request auto-approved: status=%s", r.Status)
	}
	if n := pol.updateCount(); n != 0 {
		t.Fatalf("policy patched %d time(s) for an un-nameable host", n)
	}
	if ruleOpensHost(pol.policy(ats, actor), "") {
		t.Fatal(`policy gained a Hostnames:[""] rule`)
	}
	if live, _ := st.Live(); len(live) != 0 {
		t.Fatalf("grants created without a hostname: %v", live)
	}
	if req, err := st.GetRequest(r.ID); err != nil || req.Status != StatusPending {
		t.Fatalf("stored request must stay pending for the human: %+v %v", req, err)
	}
}

// TestObserverRemembersStructurallyUnapprovableDeny covers the observer half
// of S11: an un-nameable deny (no SNI, no PTR) must file as pending WITHOUT
// erroring, so handle()'s existing rememberSeen arms the cooldown —
// otherwise every 30s tick replays the line (the Get+Update storm) and piles
// duplicate pending rows.
func TestObserverRemembersStructurallyUnapprovableDeny(t *testing.T) {
	const ats, actor, ip = "ots", "ot-ua", "192.0.2.7"
	pol := newFakePolicyClient()
	pol.setPolicy(ats, actor, &ateapi.EgressPolicy{})
	m, st := newTestManager(t, pol)
	if err := st.SetAuto(actor, 0); err != nil {
		t.Fatal(err)
	}

	checker := ActorChecker(func(context.Context, string) (string, bool, error) { return ats, true, nil })
	o := NewObserver(m, checker, nil, "ate-system", "app=atenet-egress",
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	// Cancelled ctx models the no-PTR outcome deterministically (no network):
	// the deny files with an empty host — the structurally-un-approvable
	// outcome. The fake policy client and the store are ctx-agnostic, so the
	// pre-fix auto-approve path still runs fully under this context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	d := DenyLog{
		Actor: "spiffe://ate/worker-for-actor/" + ats + "/" + actor,
		Chain: "denied",
		Dest:  ip + ":443",
	}
	o.handle(ctx, d)

	key := actor + "|" + "" + "|" + ip // actor|host|ip with empty host
	if !o.recentlySeen(key) {
		t.Fatal("observer did not remember the structurally un-approvable deny: " +
			"every 30s tick would replay it")
	}
	pending, err := st.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Host != "" || pending[0].Status != StatusPending {
		t.Fatalf("want one pending empty-host request, got %+v", pending)
	}
	if n := pol.updateCount(); n != 0 {
		t.Fatalf("policy patched %d time(s) for an un-nameable host", n)
	}

	// The repeated line on the next tick must be absorbed by the cooldown.
	o.handle(ctx, d)
	if pending, _ := st.Pending(); len(pending) != 1 {
		t.Fatalf("repeat deny created a duplicate: %d pending", len(pending))
	}
}
