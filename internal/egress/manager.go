// Manager owns the approval lifecycle: validate actor claims, record
// requests, patch substrate egress policies on approval, and auto-revoke
// TTL grants.
package egress

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/viveksupe/Trident/third_party/ateapi"
)

// ActorChecker resolves an actor-name claim to (exists, atespace) so a
// request cannot reference an actor the shim does not manage.
type ActorChecker func(ctx context.Context, actorName string) (atespace string, ok bool, err error)

// PolicyClient is the seam between the approval flow and the substrate's
// singleton per-actor egress policy. *substrate.Lifecycle implements it in
// production (wired in cmd/trident); tests substitute an in-memory fake,
// which is what makes the revoke/approve interleavings testable at all —
// the concrete Lifecycle requires a live control plane.
type PolicyClient interface {
	// GetEgressPolicy returns the actor's singleton policy, or nil when the
	// actor has no policy yet.
	GetEgressPolicy(ctx context.Context, atespace, name string) (*ateapi.EgressPolicy, error)
	// UpdateEgressPolicy replaces the actor's singleton policy.
	UpdateEgressPolicy(ctx context.Context, atespace, name string, pol *ateapi.EgressPolicy) error
}

// Manager wires the store to substrate policies.
type Manager struct {
	store *Store
	lc    PolicyClient
	log   *slog.Logger
	check ActorChecker
	// ActorPrefix scopes which gateway-observed actors the observer claims.
	ActorPrefix string
	// RequestTTL bounds how long approvals of pending requests stay valid:
	// pending requests older than this are marked timed_out by the ticker.
	RequestTTL time.Duration
	// MaxPendingPerActor is the per-actor cap on open requests (a sandbox is
	// untrusted input: otherwise one actor can flood the console queues).
	MaxPendingPerActor int

	// policyLocks serializes read-modify-write of one actor's egress policy
	// across the console, auto-approve, observer and revoke ticker.
	policyLocks sync.Map // actor name -> *sync.Mutex
}

// lockPolicy serializes policy RMW for actor.
func (m *Manager) lockPolicy(actor string) func() {
	v, _ := m.policyLocks.LoadOrStore(actor, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// actorPrefix is read by the log observer.
func (m *Manager) actorPrefix() string { return m.ActorPrefix }

// checker is exposed for the observer.
func (m *Manager) checkerFor() ActorChecker { return m.check }

// New constructs the manager. lc is the policy seam (see PolicyClient).
func New(store *Store, lc PolicyClient, check ActorChecker, log *slog.Logger) *Manager {
	return &Manager{store: store, lc: lc, check: check, log: log, RequestTTL: 24 * time.Hour, MaxPendingPerActor: 50}
}

// Submit validates and records an actor's request for host egress.
func (m *Manager) Submit(ctx context.Context, actor, host, reason string) (*Request, error) {
	host = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(host, ".")))
	if host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if !validHost(host) {
		return nil, fmt.Errorf("invalid hostname %q", host)
	}
	if actor == "" || len(actor) > 128 {
		return nil, fmt.Errorf("invalid actor %q", actor)
	}
	if n, err := m.store.PendingCountForActor(actor); err == nil && m.MaxPendingPerActor > 0 &&
		n >= m.MaxPendingPerActor {
		return nil, fmt.Errorf("actor %q has too many open egress requests", actor)
	}
	if existing, err := m.store.PendingFor(actor, host); err == nil && len(existing) > 0 {
		// One pending request per (actor, host) is enough; a newly enabled
		// auto rule applies to it on the next ask.
		m.approvePendingIfAuto(ctx, &existing[0])
		return &existing[0], nil
	}
	atespace, ok, err := m.check(ctx, actor)
	if err != nil {
		return nil, fmt.Errorf("resolves actor claim: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("unknown actor %q", actor)
	}
	r := &Request{Atespace: atespace, ActorName: actor, Host: host, Reason: reason, Status: StatusPending}
	if err := m.store.InsertRequest(r); err != nil {
		return nil, err
	}
	if err := m.maybeAutoApprove(ctx, r); err != nil {
		return nil, err
	}
	m.log.Info("egress requested", "actor", actor, "host", host, "reason", reason)
	return r, nil
}

// approvePendingIfAuto applies an actor's standing rule to an existing
// pending request (dedup path): auto rules must catch requests filed before
// the rule was enabled, exactly as they catch fresh ones.
func (m *Manager) approvePendingIfAuto(ctx context.Context, r *Request) {
	if r.Status != StatusPending {
		return
	}
	if err := m.maybeAutoApprove(ctx, r); err != nil {
		m.log.Debug("auto-apply skipped", "request", r.ID, "err", err)
	}
}

// maybeAutoApprove fires the actor's standing rule, if any: grant immediately
// with the rule's TTL. Logged loudly — this is deliberate standing
// permission, not a silent bypass.
func (m *Manager) maybeAutoApprove(ctx context.Context, r *Request) error {
	auto, ok, err := m.store.AutoFor(r.ActorName)
	if err != nil || !ok {
		return err
	}
	var ttl time.Duration
	if auto.TTL > 0 {
		ttl = time.Duration(auto.TTL) * time.Second
	}
	if err := m.approveRequestLocked(ctx, *r, ttl); err != nil {
		return err
	}
	r.Status = StatusApproved
	r.Decided = time.Now()
	m.log.Warn("egress AUTO-approved (standing rule)", "actor", r.ActorName, "host", r.Host, "ttl", ttl)
	return nil
}

// approves the request with the rule's TTL.
func (m *Manager) approveRequestLocked(ctx context.Context, req Request, ttl time.Duration) error {
	// Policy patch FIRST, then the bookkeeping in one transaction: a failure
	// above leaves the request pending (retryable), and approval only lands
	// when a policy rule actually exists behind it. The old order (approve
	// then patch) left permanently "approved" rows with no rule behind them
	// when the substrate call failed.
	if err := m.addRule(ctx, Grant{
		Atespace: req.Atespace, ActorName: req.ActorName, Host: req.Host,
	}); err != nil {
		return err
	}
	g, _, err := m.store.DecideApproved(req.ID, ttl)
	if err != nil {
		// Roll the rule back out so no access exists without bookkeeping.
		if rbErr := m.removeRule(ctx, Grant{
			Atespace: req.Atespace, ActorName: req.ActorName, Host: req.Host,
		}); rbErr != nil {
			m.log.Warn("approval bookkeeping failed and policy rollback failed too",
				"request", req.ID, "actor", req.ActorName, "host", req.Host)
		}
		return err
	}
	_ = g
	return nil
}

// GetRequest returns one request by id (any status), or nil.
func (m *Manager) GetRequest(id int64) (*Request, error) {
	return m.store.GetRequest(id)
}

// Approve opens egress for the request's (actor, host): patch the substrate
// policy to add the tls-passthrough rule and record the grant with TTL.
func (m *Manager) Approve(ctx context.Context, requestID int64, ttl time.Duration) error {
	req, ok, err := m.requestByID(requestID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("request %d not found", requestID)
	}
	if req.Host == "" {
		return fmt.Errorf("request %d has no hostname — correct it before approving", requestID)
	}
	if !validHost(req.Host) {
		return fmt.Errorf("request %d hostname %q is not a valid hostname", requestID, req.Host)
	}
	if err := m.approveRequestLocked(ctx, req, ttl); err != nil {
		return err
	}
	m.log.Info("egress granted", "actor", req.ActorName, "host", req.Host, "ttl", ttl)
	return nil
}

// Deny marks the request denied; no policy change happens.
func (m *Manager) Deny(requestID int64) error {
	if _, err := m.store.Decide(requestID, StatusDenied); err != nil {
		return err
	}
	m.log.Info("egress denied", "request", requestID)
	return nil
}

// FullInternetHost is the wildcard grant marker: a tls-passthrough rule for
// "*" (every TLS name) on 443 plus a cleartext http rule for "*" on 80.
const FullInternetHost = "*"

// fullInternetRules opens TLS passthrough to every name on every port.
// Substrate rejects a cleartext-HTTP rule that ties with the TLS-all-ports
// rule (both could claim port 80), so cleartext HTTP to non-approved hosts
// stays unavailable; TLS covers https and any TLS-flavoured protocol on any
// port. Non-TCP and server-speaks-first protocols remain unreachable.
func fullInternetRules() []*ateapi.EgressRule {
	return []*ateapi.EgressRule{
		{
			TlsPassthrough: &ateapi.TlsPassthroughRule{
				Hostnames: []string{FullInternetHost},
				Ports:     &ateapi.Ports{All: &ateapi.AllPorts{}},
			},
		},
	}
}

// hasFullInternet reports that the policy already opens everything.
func hasFullInternet(pol *ateapi.EgressPolicy) bool {
	for _, r := range pol.Rules {
		if tp := r.GetTlsPassthrough(); tp != nil {
			if containsHostname(tp.GetHostnames(), FullInternetHost) {
				return true
			}
		}
	}
	return false
}

// hasAllPortWildcard reports that the wildcard rules already cover every
// port (vs the legacy 443/80 pair).
func hasAllPortWildcard(pol *ateapi.EgressPolicy) bool {
	for _, r := range pol.Rules {
		if tp := r.GetTlsPassthrough(); tp != nil &&
			containsHostname(tp.GetHostnames(), FullInternetHost) &&
			tp.GetPorts().GetAll() != nil {
			return true
		}
	}
	return false
}

// GrantFullInternet opens the full public web (TLS 443 + HTTP 80 for every
// hostname) for one actor and records the grant so the console shows and can
// revoke it. Deliberate escalation: logged loudly.
func (m *Manager) GrantFullInternet(ctx context.Context, atespace, actor string, ttl time.Duration) error {
	defer m.lockPolicy(actor)()
	pol, err := m.lc.GetEgressPolicy(ctx, atespace, actor)
	if err != nil {
		return err
	}
	if pol == nil {
		return fmt.Errorf("actor %s/%s has no egress policy", atespace, actor)
	}
	if !hasFullInternet(pol) || !hasAllPortWildcard(pol) {
		// New grant, or a legacy 443/80 wildcard: rewrite as the all-ports
		// wildcard in one policy write.
		var kept []*ateapi.EgressRule
		for _, r := range pol.Rules {
			if tp := r.GetTlsPassthrough(); tp != nil && containsHostname(tp.GetHostnames(), FullInternetHost) {
				continue
			}
			if h := r.GetHttp(); h != nil && containsHostname(h.GetHostnames(), FullInternetHost) {
				continue
			}
			kept = append(kept, r)
		}
		pol.Rules = append(kept, fullInternetRules()...)
		if err := m.lc.UpdateEgressPolicy(ctx, atespace, actor, pol); err != nil {
			return err
		}
	}
	// Record the grant so the console shows it and can revoke it.
	if existing, err := m.store.GrantForWild(actor, FullInternetHost); err != nil || existing == nil || existing.ID == 0 {
		if err2 := m.store.InsertWildGrant(atespace, actor, FullInternetHost, ttl); err2 != nil {
			return err2
		}
	} else if ttl > 0 {
		if err := m.store.SetWildTTL(existing.ID, time.Now().Add(ttl)); err != nil {
			return err
		}
	}
	m.log.Warn("egress FULL INTERNET granted (wildcard *)", "actor", actor, "ttl", ttl)
	return nil
}

// PurgeActor drops all bookkeeping for a deleted actor. The substrate egress
// policy does not need patching: it is nested under the actor and destroyed
// with it.
func (m *Manager) PurgeActor(_ context.Context, actor string) error {
	if err := m.store.PurgeActor(actor); err != nil {
		return err
	}
	m.log.Info("egress bookkeeping purged for actor", "actor", actor)
	return nil
}

// RevokeAll closes every live grant and returns how many were closed.
func (m *Manager) RevokeAll(ctx context.Context) (int, error) {
	live, err := m.store.Live()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, g := range live {
		if err := m.Revoke(ctx, g.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// ClearHistoryRevokeAll revokes every live grant (patching each actor's
// substrate policy), then drops decided requests and closed grants from the
// console. Auto-approve rules are untouched (they govern future requests).
func (m *Manager) ClearHistoryRevokeAll(ctx context.Context) (revoked int, cleared int64, err error) {
	live, err := m.store.Live()
	if err != nil {
		return 0, 0, err
	}
	for _, g := range live {
		if err := m.revokeGrant(ctx, live, g); err != nil {
			m.log.Warn("clear-history revoke failed", "actor", g.ActorName, "host", g.Host, "err", err)
			continue
		}
		revoked++
		m.log.Info("egress grant closed (clear history)", "actor", g.ActorName, "host", g.Host)
	}
	n, err := m.store.ClearHistory()
	return revoked, n, err
}

// Revoke closes a live grant: patch the policy and stamp the grant revoked.
func (m *Manager) Revoke(ctx context.Context, grantID int64) error {
	live, err := m.store.Live()
	if err != nil {
		return err
	}
	for _, g := range live {
		if g.ID != grantID {
			continue
		}
		return m.revokeGrant(ctx, live, g)
	}
	return fmt.Errorf("grant %d not live", grantID)
}

// revokeGrant closes one grant. The policy is only patched when no OTHER
// live grant for the same (actor, host) keeps the rule alive — duplicate
// grants exist (observed + helper paths) and revoking one must not revoke
// the access the other bought, nor drop baseline rules the host shares.
func (m *Manager) revokeGrant(ctx context.Context, live []Grant, g Grant) error {
	now := time.Now()
	for _, other := range live {
		if other.ID == g.ID || other.ActorName != g.ActorName || other.Host != g.Host {
			continue
		}
		if other.Expires.IsZero() || other.Expires.After(now) {
			// Another live grant still holds this rule: only stamp this one.
			if err := m.store.MarkRevoked(g.ID); err != nil {
				return err
			}
			m.log.Info("egress grant closed (other grants keep the rule)", "actor", g.ActorName, "host", g.Host)
			return nil
		}
	}
	if err := m.removeRule(ctx, g); err != nil {
		return err
	}
	if err := m.store.MarkRevoked(g.ID); err != nil {
		return err
	}
	m.log.Info("egress revoked", "actor", g.ActorName, "host", g.Host)
	return nil
}

// RunRevokeTicker revokes expired TTL grants every interval. Blocking.
func (m *Manager) RunRevokeTicker(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sweep(ctx)
		}
	}
}

func (m *Manager) sweep(ctx context.Context) {
	live, err := m.store.Live()
	if err != nil {
		m.log.Warn("egress sweep failed", "err", err)
		return
	}
	now := time.Now()
	for _, g := range live {
		if !g.Expires.IsZero() && now.After(g.Expires) {
			m.log.Info("revoking expired egress grant", "actor", g.ActorName, "host", g.Host)
			if err := m.revokeGrant(ctx, live, g); err != nil {
				m.log.Warn("revoke failed", "grant", g.ID, "err", err)
			}
		}
	}
	if stale, err := m.expireStaleRequests(); err != nil {
		m.log.Warn("request expiry sweep failed", "err", err)
	} else if stale > 0 {
		m.log.Info("timed out stale egress requests", "count", stale)
	}
}

// expireStaleRequests marks pending requests older than RequestTTL timed out.
func (m *Manager) expireStaleRequests() (int, error) {
	pending, err := m.store.Pending()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range pending {
		if time.Since(r.Created) > m.RequestTTL {
			if _, err := m.store.Decide(r.ID, StatusTimedOut); err != nil {
				// One bad row must not orphan the rest of the sweep.
				m.log.Warn("stale-request expiry failed", "request", r.ID, "err", err)
				continue
			}
			n++
		}
	}
	return n, nil
}

// addRule patches the actor's policy: append a tls-passthrough host if
// absent. Serialized per actor and retried once on update failure
// (re-fetching the fresh policy metadata first) so a concurrent console /
// observer write can't wedge the grant behind a stale-version rejection.
func (m *Manager) addRule(ctx context.Context, g Grant) (err error) {
	defer m.lockPolicy(g.ActorName)()
	for attempt := 0; attempt < 2; attempt++ {
		if err = m.addRuleOnce(ctx, g); err == nil {
			return nil
		}
	}
	return err
}

func (m *Manager) addRuleOnce(ctx context.Context, g Grant) error {
	pol, err := m.lc.GetEgressPolicy(ctx, g.Atespace, g.ActorName)
	if err != nil {
		return err
	}
	if pol == nil {
		return fmt.Errorf("actor %s/%s has no egress policy", g.Atespace, g.ActorName)
	}
	if hasTightGrant(pol, g.Host) {
		return nil
	}
	// Add the tight 80/443 pair; older all-ports rules for this host are
	// replaced in the same write.
	pol.Rules = append(dropLegacyForHost(pol.Rules, g.Host), grantRules(g.Host)...)
	return m.lc.UpdateEgressPolicy(ctx, g.Atespace, g.ActorName, pol)
}

// removeRule patches the actor's policy: drop the host's rules (only the
// refcount-free paths call it — see revokeGrant).
func (m *Manager) removeRule(ctx context.Context, g Grant) (err error) {
	defer m.lockPolicy(g.ActorName)()
	for attempt := 0; attempt < 2; attempt++ {
		var pol *ateapi.EgressPolicy
		if pol, err = m.lc.GetEgressPolicy(ctx, g.Atespace, g.ActorName); err != nil {
			return err
		}
		if pol == nil {
			return nil
		}
		pol.Rules = dropLegacyForHost(pol.Rules, g.Host)
		if err = m.lc.UpdateEgressPolicy(ctx, g.Atespace, g.ActorName, pol); err == nil {
			return nil
		}
	}
	return err
}

// dropLegacyForHost removes all rules matching host (any-port legacy rules
// included) and prunes empty multi-host rules.
func dropLegacyForHost(rules []*ateapi.EgressRule, host string) []*ateapi.EgressRule {
	var out []*ateapi.EgressRule
	for _, r := range rules {
		if tp := r.GetTlsPassthrough(); tp != nil && containsHostname(tp.GetHostnames(), host) {
			if hn := dropHostname(tp.GetHostnames(), host); len(hn) > 0 {
				out = append(out, &ateapi.EgressRule{
					TlsPassthrough: &ateapi.TlsPassthroughRule{
						Hostnames: hn,
						Ports:     tp.GetPorts(),
					},
				})
			}
			continue
		}
		if h := r.GetHttp(); h != nil && containsHostname(h.GetHostnames(), host) {
			if hn := dropHostname(h.GetHostnames(), host); len(hn) > 0 {
				out = append(out, &ateapi.EgressRule{
					Http: &ateapi.HttpRule{
						Hostnames: hn,
						Ports:     h.GetPorts(),
					},
				})
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// grantRules is the exact opening a domain approval buys: TLS on 443 and
// cleartext HTTP on 80. Nothing else.
func grantRules(host string) []*ateapi.EgressRule {
	return []*ateapi.EgressRule{
		{
			TlsPassthrough: &ateapi.TlsPassthroughRule{
				Hostnames: []string{host},
				Ports:     &ateapi.Ports{Numbers: []int32{443}},
			},
		},
		{
			Http: &ateapi.HttpRule{
				Hostnames: []string{host},
				Ports:     &ateapi.Ports{Numbers: []int32{80}},
			},
		},
	}
}

// hasTightGrant reports that host already has the exact 80/443 grant.
func hasTightGrant(pol *ateapi.EgressPolicy, host string) bool {
	tlsOK, httpOK := false, false
	for _, r := range pol.Rules {
		if tp := r.GetTlsPassthrough(); tp != nil &&
			containsHostname(tp.GetHostnames(), host) == true &&
			tp.GetPorts().GetNumbers() != nil {
			for _, p := range tp.GetPorts().GetNumbers() {
				if p == 443 {
					tlsOK = true
				}
			}
		}
		if h := r.GetHttp(); h != nil &&
			containsHostname(h.GetHostnames(), host) == true &&
			h.GetPorts().GetNumbers() != nil {
			for _, p := range h.GetPorts().GetNumbers() {
				if p == 80 {
					httpOK = true
				}
			}
		}
	}
	return tlsOK && httpOK
}

func containsHostname(hostnames []string, host string) bool {
	for _, h := range hostnames {
		if h == host {
			return true
		}
	}
	return false
}

func dropHostname(hostnames []string, host string) []string {
	var out []string
	for _, h := range hostnames {
		if h != host {
			out = append(out, h)
		}
	}
	return out
}

// validHost accepts RFC-1123 DNS names (LDH labels) as the policy validators
// do. Wildcards are rejected everywhere else: a "*" grant exists ONLY
// through GrantFullInternet, which logs loudly — an actor-controlled
// Submit("*") must not silently bypass it (a standing auto rule used to
// turn "*" into "every host on 80/443").
func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, r := range h {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
		default:
			return false
		}
	}
	labels := strings.Split(strings.TrimSuffix(h, "."), ".")
	for _, l := range labels {
		if l == "" || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
	}
	return true
}

// State is the console payload.
type State struct {
	Pending []Request  `json:"pending"`
	Live    []Grant    `json:"live"`
	History []Request  `json:"history"`
	Autos   []AutoRule `json:"autos"`
	// Per-list pagination (1-based pages; totals for the UI).
	Page         int `json:"page"`
	PerPage      int `json:"per_page"`
	PendingTotal int `json:"pending_total"`
	PendingPages int `json:"pending_pages"`
	LivePage     int `json:"live_page"`
	LiveTotal    int `json:"live_total"`
	LivePages    int `json:"live_pages"`
	HistoryPage  int `json:"history_page"`
	HistoryTotal int `json:"history_total"`
	HistoryPages int `json:"history_pages"`
	AutosPage    int `json:"autos_page"`
	AutosTotal   int `json:"autos_total"`
	AutosPages   int `json:"autos_pages"`
}

// PagedParams selects one page per list.
type PagedParams struct {
	PendingPage, LivePage, HistoryPage, AutosPage, PerPage int
}

// requestByID resolves a request through the store's index (the old
// pending-page + last-50-history scan 404'd older requests, which looped the
// helper's wait forever).
func (m *Manager) requestByID(id int64) (Request, bool, error) {
	r, err := m.store.GetRequest(id)
	if err != nil || r == nil {
		return Request{}, false, err
	}
	return *r, true, nil
}

// SetAuto toggles a per-actor auto-approve rule.
func (m *Manager) SetAuto(actor string, ttlSeconds int64) error {
	if err := m.store.SetAuto(actor, ttlSeconds); err != nil {
		return err
	}
	m.log.Warn("auto-approve rule set", "actor", actor, "ttl_seconds", ttlSeconds)
	return nil
}

// ClearAuto removes a per-actor auto-approve rule.
func (m *Manager) ClearAuto(actor string) error {
	if err := m.store.ClearAuto(actor); err != nil {
		return err
	}
	m.log.Info("auto-approve rule removed", "actor", actor)
	return nil
}

// SnapshotPage returns the console view with pending requests paginated
// (page is 1-based; perPage ≤ 0 means a sane default; page beyond the end
// clamps to the last page).
func (m *Manager) SnapshotPage(p PagedParams) (State, error) {
	perPage := p.PerPage
	if perPage <= 0 || perPage > 100 {
		perPage = 25
	}
	page := p.PendingPage
	if page < 1 {
		page = 1
	}
	pending, total, err := m.store.PendingPaged(perPage, (page-1)*perPage)
	if err != nil {
		return State{}, err
	}
	pages := (total + perPage - 1) / perPage
	if pages < 1 {
		pages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > pages {
		page = pages
	}
	st, err := m.snapshotCommon()
	if err != nil {
		return State{}, err
	}
	st.Pending, st.Page, st.PerPage, st.PendingTotal, st.PendingPages = pending, page, perPage, total, pages
	return st, nil
}

// Snapshot returns the console's view (all pendings, one page).
func (m *Manager) Snapshot() (State, error) {
	return m.SnapshotPage(PagedParams{})
}

func (m *Manager) snapshotCommon() (State, error) {
	live, err := m.store.Live()
	if err != nil {
		return State{}, err
	}
	hist, err := m.store.History(50)
	if err != nil {
		return State{}, err
	}
	sort.Slice(hist, func(i, j int) bool { return hist[i].ID > hist[j].ID })
	autos, err := m.store.Autos()
	if err != nil {
		return State{}, err
	}
	return State{
		Live: orEmpty(live), History: orEmpty(hist), Autos: orEmpty(autos),
	}, nil
}

func orEmpty[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
