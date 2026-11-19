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
	"time"

	"github.com/viveksupe/Trident/third_party/ateapi"

	"github.com/viveksupe/Trident/internal/backend/substrate"
)

// ActorChecker resolves an actor-name claim to (exists, atespace) so a
// request cannot reference an actor the shim does not manage.
type ActorChecker func(ctx context.Context, actorName string) (atespace string, ok bool, err error)

// Manager wires the store to substrate policies.
type Manager struct {
	store *Store
	lc    *substrate.Lifecycle
	log   *slog.Logger
	check ActorChecker
	// ActorPrefix scopes which gateway-observed actors the observer claims.
	ActorPrefix string
	// RequestTTL bounds how long approvals of pending requests stay valid:
	// pending requests older than this are marked timed_out by the ticker.
	RequestTTL time.Duration
}

// actorPrefix is read by the log observer.
func (m *Manager) actorPrefix() string { return m.ActorPrefix }

// checker is exposed for the observer.
func (m *Manager) checkerFor() ActorChecker { return m.check }

// New constructs the manager.
func New(store *Store, lc *substrate.Lifecycle, check ActorChecker, log *slog.Logger) *Manager {
	return &Manager{store: store, lc: lc, check: check, log: log, RequestTTL: 24 * time.Hour}
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

// approveRequestLocked performs the grant + policy patch common to the
// console approve path and auto-approval.
func (m *Manager) approveRequestLocked(ctx context.Context, req Request, ttl time.Duration) error {
	if _, err := m.store.Decide(req.ID, StatusApproved); err != nil {
		return err
	}
	g, err := m.store.GrantForRequest(req.ID)
	if err != nil {
		return err
	}
	if ttl > 0 {
		if err := m.store.SetTTL(req.ID, time.Now().Add(ttl)); err != nil {
			return err
		}
		g.Expires = time.Now().Add(ttl)
	}
	return m.addRule(ctx, g)
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

// fullInternetRules are the two rules that open the whole public web.
func fullInternetRules() []*ateapi.EgressRule {
	return []*ateapi.EgressRule{
		{
			TlsPassthrough: &ateapi.TlsPassthroughRule{
				Hostnames: []string{FullInternetHost},
				Ports:     &ateapi.Ports{Numbers: []int32{443}},
			},
		},
		{
			Http: &ateapi.HttpRule{
				Hostnames: []string{FullInternetHost},
				Ports:     &ateapi.Ports{Numbers: []int32{80}},
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

// GrantFullInternet opens the full public web (TLS 443 + HTTP 80 for every
// hostname) for one actor and records the grant so the console shows and can
// revoke it. Deliberate escalation: logged loudly.
func (m *Manager) GrantFullInternet(ctx context.Context, atespace, actor string, ttl time.Duration) error {
	pol, err := m.lc.GetEgressPolicy(ctx, atespace, actor)
	if err != nil {
		return err
	}
	if pol == nil {
		return fmt.Errorf("actor %s/%s has no egress policy", atespace, actor)
	}
	if !hasFullInternet(pol) {
		pol.Rules = append(pol.Rules, fullInternetRules()...)
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
		if err := m.removeRule(ctx, g); err != nil {
			m.log.Warn("clear-history revoke failed", "actor", g.ActorName, "host", g.Host, "err", err)
			continue
		}
		if err := m.store.MarkRevoked(g.ID); err != nil {
			return revoked, 0, err
		}
		revoked++
		m.log.Info("egress revoked (clear history)", "actor", g.ActorName, "host", g.Host)
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
		if err := m.removeRule(ctx, g); err != nil {
			return err
		}
		if err := m.store.MarkRevoked(g.ID); err != nil {
			return err
		}
		m.log.Info("egress revoked", "actor", g.ActorName, "host", g.Host)
		return nil
	}
	return fmt.Errorf("grant %d not live", grantID)
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
			if err := m.Revoke(ctx, g.ID); err != nil {
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
				return n, err
			}
			n++
		}
	}
	return n, nil
}

// addRule patches the actor's policy: append a tls-passthrough host if absent.
func (m *Manager) addRule(ctx context.Context, g Grant) error {
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

// removeRule patches the actor's policy: drop the tls-passthrough host.
func (m *Manager) removeRule(ctx context.Context, g Grant) error {
	pol, err := m.lc.GetEgressPolicy(ctx, g.Atespace, g.ActorName)
	if err != nil {
		return err
	}
	if pol == nil {
		return nil
	}
	pol.Rules = dropLegacyForHost(pol.Rules, g.Host)
	return m.lc.UpdateEgressPolicy(ctx, g.Atespace, g.ActorName, pol)
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

// validHost accepts RFC-ish DNS hostnames as the policy validators do.
func validHost(h string) bool {
	if h == "" || strings.Contains(h, "/") || strings.Contains(h, ":") {
		return false
	}
	labels := strings.Split(strings.TrimSuffix(h, "."), ".")
	for _, l := range labels {
		if l == "" || strings.Contains(l, " ") {
			return false
		}
	}
	return len(labels) >= 1
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

// requestByID scans pending+history for a request.
func (m *Manager) requestByID(id int64) (Request, bool, error) {
	pending, _, err := m.store.PendingPaged(1000, 0)
	if err != nil {
		return Request{}, false, err
	}
	for _, r := range pending {
		if r.ID == id {
			return r, true, nil
		}
	}
	hist, err := m.store.History(500)
	if err != nil {
		return Request{}, false, err
	}
	for _, r := range hist {
		if r.ID == id {
			return r, true, nil
		}
	}
	return Request{}, false, nil
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
