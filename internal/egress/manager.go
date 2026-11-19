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
		// One pending request per (actor, host) is enough.
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

	// Auto-approve rules shortcut the human: grant immediately with the
	// rule's TTL. Logged loudly — this is deliberate standing permission,
	// not a silent bypass.
	if auto, ok, err := m.store.AutoFor(actor); err == nil && ok {
		var ttl time.Duration
		if auto.TTL > 0 {
			ttl = time.Duration(auto.TTL) * time.Second
		}
		if err := m.approveRequestLocked(ctx, *r, ttl); err != nil {
			return nil, err
		}
		r.Status = StatusApproved
		r.Decided = time.Now()
		m.log.Warn("egress AUTO-approved (standing rule)", "actor", actor, "host", host, "ttl", ttl)
		return r, nil
	}

	m.log.Info("egress requested", "actor", actor, "host", host, "reason", reason)
	return r, nil
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
}

// requestByID scans pending+history for a request.
func (m *Manager) requestByID(id int64) (Request, bool, error) {
	pending, err := m.store.Pending()
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

// Snapshot returns the console's view.
func (m *Manager) Snapshot() (State, error) {
	pending, err := m.store.Pending()
	if err != nil {
		return State{}, err
	}
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
		Pending: orEmpty(pending), Live: orEmpty(live),
		History: orEmpty(hist), Autos: orEmpty(autos),
	}, nil
}

func orEmpty[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}
