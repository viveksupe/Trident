// Substrate-backed Backend: per-actor lifecycle through the ate control plane
// and data-plane dialing through atenet tunnels.
package substrate

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/viveksupe/Trident/third_party/ateapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/model"
)

// Lifecycle wraps the control plane with this shim's template parameters.
type Lifecycle struct {
	client           *APIClient
	TemplateAtespace string
	TemplateName     string
	EgressHosts      []string
	// CallbackHost, when set (name only, e.g.
	// "trident-callback.ot-workerpool.svc"), is added to every actor's base
	// egress policy as a tls-passthrough rule on CallbackPort: the egress
	// approval request channel back to the shim.
	CallbackHost string
	CallbackPort string
}

// Backend implements backend.Backend over substrate.
type Backend struct {
	lc          *Lifecycle
	dialer      *RouterDialer
	atspace     string
	prefix      string
	actorPort   int
	actorAPIKey string
	durability  ateapi.DurabilityMode
	log         *slog.Logger
	// ops is the bounded per-actor lifecycle op table: name -> opEntry
	// (finding R3 — the old sync.Map was insert-only and grew forever with
	// actor churn). Records are evicted at terminal points of this backend's
	// ownership model (Delete, self-heal purge) and capped at opCacheMax
	// with oldest-first eviction as a safety net. Only lockOp/evictOp touch
	// the table: Backend.Get and Handle.Key never consult it, so evicting a
	// record cannot change caller-visible behavior — the next op re-creates
	// it.
	ops opCache
	// opCacheMax caps ops; <= 0 selects defaultOpCacheMax (set from
	// TRI_OPS_CACHE_MAX in NewBackend).
	opCacheMax int
	// selfHealStrikes tracks, per actor name, how many *consecutive*
	// EnsureReady calls have produced affirmative restore-corruption evidence
	// (finding C3). Delete — which purges the actor's durable /home/user
	// volume — is only permitted at selfHealEscalationN strikes. Entries are
	// cleared on success, on any non-corruption outcome, and after a purge,
	// and are dropped together with the op record when a terminal Delete
	// evicts them (finding R3). Entries are only ever created for actors
	// that showed restore-corruption evidence, so any residue is bounded by
	// corrupt-actor names, not by actor churn.
	selfHealStrikes sync.Map // actor name -> int
}

var _ backend.Backend = (*Backend)(nil)

// LC exposes the lifecycle client (used by the egress approval manager).
func (b *Backend) LC() *Lifecycle { return b.lc }

// NewBackend connects the control plane and the router dialer, pulling the
// remaining connection settings from the environment (they are
// deployment-specific rather than per-session):
//
//	TRI_API_SERVICE       (default "api")        ate-api-server Service name
//	TRI_API_TOKEN_FILE    (default "")           pre-minted ateapi bearer token
//	ATE_NAMESPACE         (default ate-system)   substrate system namespace
//	KUBECONFIG            (default "")           kubeconfig when out-of-cluster
func NewBackend(log *slog.Logger, cfg *config.Config) (backend.Backend, error) {
	apiService := envDefault("TRI_API_SERVICE", "api")
	tokenFile := envDefault("TRI_API_TOKEN_FILE", "")
	systemNS := envDefault("ATE_NAMESPACE", cfg.APINamespace)
	kubeconfigPath := os.Getenv("KUBECONFIG")

	kcfg, err := kubeConfig(kubeconfigPath, "")
	if err != nil {
		return nil, fmt.Errorf("k8s config: %w", err)
	}

	client, err := NewAPIClient(context.Background(), kcfg, "", tokenFile, apiService, cfg.ClientSA, systemNS)
	if err != nil {
		return nil, err
	}
	routeNS := cfg.RouteNamespace
	if routeNS == "" {
		routeNS = systemNS
	}
	dialer, err := NewRouterDialer(context.Background(), kcfg, routeNS, "atenet-router", cfg.RouteSA)
	if err != nil {
		client.Close()
		return nil, err
	}

	durability := ateapi.DurabilityMode_DURABILITY_MODE_ASYNCHRONOUS
	if cfg.SuspendDurability == "sync" {
		durability = ateapi.DurabilityMode_DURABILITY_MODE_SYNCHRONOUS
	}

	// Callback host/port parse once in config.Validate (was re-parsed from
	// two different string slices on three call paths).
	return &Backend{
		lc: &Lifecycle{
			client:           client,
			TemplateAtespace: cfg.TemplateAtespace(),
			TemplateName:     cfg.TemplateName(),
			EgressHosts:      cfg.EgressHosts,
			CallbackHost:     cfg.CallbackHost,
			CallbackPort:     cfg.CallbackPort,
		},
		dialer:      dialer,
		atspace:     cfg.Atespace,
		prefix:      cfg.ActorPrefix,
		actorPort:   cfg.ActorPort,
		actorAPIKey: cfg.ActorAPIKey,
		durability:  durability,
		log:         log,
		opCacheMax:  opCacheMaxFromEnv(),
	}, nil
}

// callbackHostName was folded into config's once-only splitCallback.

func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// defaultOpCacheMax bounds the op table when TRI_OPS_CACHE_MAX is unset or
// invalid: far above any real shim's actor count (the pool keeps concurrent
// actors to dozens) while still a hard ceiling.
const defaultOpCacheMax = 4096

// opEntry is one actor's lifecycle op mutex plus its insertion sequence
// (oldest-first eviction at the cap).
type opEntry struct {
	mu  sync.Mutex
	seq uint64
}

// opCache is a bounded actor-name -> opEntry table (finding R3).
//
// Correctness invariants:
//
//   - A goroutine runs a lifecycle op only while holding the entry that is
//     CURRENT in the table for its name: lock re-checks after acquiring and
//     retries against the replacement record otherwise. This is what makes
//     eviction safe — a waiter that fetched a record evicted from under it
//     detects the staleness and re-serializes instead of running
//     concurrently with the holder of the replacement record.
//   - Eviction never removes a record whose mutex is held: cap eviction
//     TryLocks candidates (TryLock never blocks, so it cannot deadlock
//     against lock's verify, which takes c.mu while holding an entry), and
//     terminal eviction is performed by the op holding the record itself.
//
// The cap is best-effort under load: if every record at the cap is mid-op,
// an insert may temporarily exceed it — the ceiling is then
// max(opCacheMax, in-flight lifecycle ops), still bounded.
type opCache struct {
	mu      sync.Mutex
	entries map[string]*opEntry
	seq     uint64
}

// lock acquires (creating and cap-evicting as needed) the record for name
// and returns its unlock function, which must be called exactly once.
func (c *opCache) lock(name string, max int) func() {
	for {
		c.mu.Lock()
		if c.entries == nil {
			c.entries = make(map[string]*opEntry)
		}
		e, ok := c.entries[name]
		if !ok {
			c.evictForCapLocked(max)
			e = &opEntry{seq: c.seq}
			c.seq++
			c.entries[name] = e
		}
		c.mu.Unlock()

		e.mu.Lock()
		c.mu.Lock()
		current := c.entries[name] == e
		c.mu.Unlock()
		if current {
			return e.mu.Unlock
		}
		// Evicted while we waited: drop the stale record and re-serialize on
		// whatever is current now (an evicted record is re-created on next
		// use — tradeoff documented on the struct).
		e.mu.Unlock()
	}
}

// evictForCapLocked makes room for one more record by removing the OLDEST
// entry whose op is not in flight; if the oldest is mid-op the next-oldest
// goes instead, so a single long-running op cannot defeat the cap. Caller
// holds c.mu.
func (c *opCache) evictForCapLocked(max int) {
	if max <= 0 || len(c.entries) < max {
		return
	}
	type candidate struct {
		name string
		e    *opEntry
	}
	list := make([]candidate, 0, len(c.entries))
	for n, e := range c.entries {
		list = append(list, candidate{n, e})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].e.seq < list[j].e.seq })
	for _, x := range list {
		if x.e.mu.TryLock() {
			delete(c.entries, x.name)
			x.e.mu.Unlock()
			return
		}
	}
	// Every record at the cap is mid-op: allowing one more is bounded by
	// the number of concurrent lifecycle ops.
}

// remove drops name's record. The caller must hold the record's op (via
// lock) so nothing is running under it.
func (c *opCache) remove(name string) {
	c.mu.Lock()
	delete(c.entries, name)
	c.mu.Unlock()
}

// size reports the number of records (tests / diagnostics).
func (c *opCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// lockOp serializes lifecycle ops per actor on the bounded table (finding
// R3; replaces the insert-only sync.Map). Evicted records are re-created on
// next use with identical locking semantics for callers.
func (b *Backend) lockOp(name string) func() {
	max := b.opCacheMax
	if max <= 0 {
		max = defaultOpCacheMax
	}
	return b.ops.lock(name, max)
}

// evictOp drops ALL of name's per-actor bookkeeping — the op record and the
// self-heal strike chain — at a terminal point in this backend's ownership
// model. Callers MUST hold name's op (lockOp) so no other op runs under the
// record being removed.
//
// Deliberately NOT called for actors that can still resume (Suspend, every
// EnsureReady failure classification): keeping their records preserves
// serialization across retries and is conservative — an unnecessary record
// costs a few bytes, a wrongly-dropped strike chain would delay a justified
// purge.
func (b *Backend) evictOp(name string) {
	b.ops.remove(name)
	b.selfHealStrikes.Delete(name)
}

// opCacheMaxFromEnv reads TRI_OPS_CACHE_MAX (max per-actor op-table
// records); unset, invalid or non-positive falls back to defaultOpCacheMax.
func opCacheMaxFromEnv() int {
	if v := os.Getenv("TRI_OPS_CACHE_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return defaultOpCacheMax
}

// EnsureReady creates the actor if missing, resumes it if suspended, and
// returns a tunnel dialer for its HTTP port.
func (b *Backend) EnsureReady(ctx context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	name := key.ActorName(b.prefix)
	unlock := b.lockOp(name)
	// purged marks the terminal self-heal delete below; the deferred
	// eviction runs while the op is still held (evict, then unlock) so no
	// other op can slip in under the record being dropped (finding R3).
	purged := false
	defer func() {
		if purged {
			b.evictOp(name)
		}
		unlock()
	}()

	var created time.Time
	existing, err := b.lc.GetActor(ctx, b.atspace, name)
	if err != nil {
		return nil, nil, err
	}
	if existing == nil {
		b.log.Info("creating actor", "actor", name, "key", key.LogString())
		if err := b.lc.EnsureCreated(ctx, b.atspace, name); err != nil {
			return nil, nil, err
		}
	} else if t := existing.GetMetadata().GetCreateTime(); t != nil {
		created = t.AsTime()
	}

	state := ateapi.ActorState_ACTOR_STATE_UNSPECIFIED
	if existing != nil {
		state = existing.GetStatus().GetState()
	}
	if state != ateapi.ActorState_ACTOR_STATE_RUNNING {
		b.log.Info("resuming actor", "actor", name, "state", state)
		if err := b.lc.Resume(ctx, b.atspace, name); err != nil {
			// Self-heal path: a restore failure (e.g. runsc restore crash on a
			// partial snapshot) is recovered by reverting to the durable
			// snapshot, then re-creating-if-missing and resuming. Delete —
			// which purges the actor's durable /home/user volume — is NEVER
			// reached from a single failure: escalation requires affirmative
			// restore-corruption evidence (DataLoss) in selfHealEscalationN
			// consecutive EnsureReady calls (finding C3).
			b.log.Warn("resume failed; attempting self-heal",
				"actor", name, "key", key.LogString(), "err", err)

			revErr := revertWithRetry(ctx, b.lc, b.log, b.atspace, name)
			outcome := classifyRevertError(revErr)
			strikes, purge := b.recordSelfHealOutcome(name, outcome)
			if purge {
				// Error level, route key included, strictly before the purge.
				b.log.Error("purging actor after repeated restore-corruption evidence",
					"actor", name, "key", key.LogString(),
					"evidence", strikes, "threshold", selfHealEscalationN, "err", revErr)
				if delErr := b.lc.Delete(ctx, b.atspace, name); delErr != nil {
					return nil, nil, fmt.Errorf("delete during self-heal: %w", delErr)
				}
				// Terminal for this actor instance: the deferred eviction
				// drops the op record AND the strike chain (fresh actor,
				// fresh evidence chain) — finding R3. A FAILED purge delete
				// returns above instead, deliberately keeping strikes so the
				// evidence chain can retry the purge on the next failure.
				purged = true
				created = time.Time{} // dropped its durable volume with it
			} else {
				switch outcome {
				case revertCorruption:
					b.log.Error("revert failed definitively; purge withheld pending repeated evidence",
						"actor", name, "key", key.LogString(),
						"evidence", strikes, "threshold", selfHealEscalationN, "err", revErr)
				case revertOperator:
					// Security review on C3: affirmative-but-not-corruption
					// refusals (Unimplemented under substrate version skew,
					// PermissionDenied after an RBAC regression,
					// InvalidArgument, the benign FailedPrecondition no-op &c.)
					// are operator configuration problems, never evidence
					// against the actor's data. Keep the actor, no purge; the
					// strike chain resets (selfHealDecision).
					b.log.Error("revert refused for non-corruption reasons; keeping actor, operator action required",
						"actor", name, "key", key.LogString(), "err", revErr)
				case revertTransient:
					// C3: transient Revert failures (deadline, transport,
					// overload) never escalate to a purge. The recovery below
					// is non-destructive: EnsureCreated is idempotent and Resume
					// destroys nothing; if the actor still cannot resume, the
					// error surfaces and the next EnsureReady call retries.
					b.log.Warn("revert failed transiently; not escalating to delete",
						"actor", name, "key", key.LogString(), "err", revErr)
				case revertAbsent:
					b.log.Warn("revert: actor already gone; recreating without purge",
						"actor", name, "key", key.LogString())
				}
			}
			if err := b.lc.EnsureCreated(ctx, b.atspace, name); err != nil {
				return nil, nil, err
			}
			b.log.Info("resuming self-healed actor", "actor", name)
			if err := b.lc.Resume(ctx, b.atspace, name); err != nil {
				return nil, nil, fmt.Errorf("resume actor after self-heal: %w", err)
			}
		}
	}

	// The egress policy is ensured on EVERY pass (S8): fire-once creation
	// used to strand actors deny-by-default forever when one create failed,
	// and TRI_EGRESS_HOSTS changes never propagated to existing actors. Now a
	// failed create, a stale callback port, or a host-list change heals on
	// the next request. A failure here only affects egress, so warn (not
	// fail) — the next EnsureReady retries.
	if err := b.lc.EnsureEgressPolicy(ctx, b.atspace, name); err != nil {
		b.log.Warn("egress policy ensure failed; actor egress may be stale",
			"actor", name, "key", key.LogString(), "err", err)
	}

	if created.IsZero() {
		created = time.Now()
	}
	// A fully successful EnsureReady breaks any consecutive-evidence chain
	// (finding C3): strikes only accumulate across *failing* calls.
	b.clearSelfHealStrikes(name)
	return &backend.Handle{
		Key: key, Name: name, CreatedAt: created, LastReadyAt: time.Now(),
	}, &actorDialer{b: b, name: name}, nil
}

// Get returns the substrate actor record for the route, if present.
func (b *Backend) Get(ctx context.Context, key model.RouteKey) (*backend.Handle, error) {
	actor, err := b.lc.GetActor(ctx, b.atspace, key.ActorName(b.prefix))
	if err != nil || actor == nil {
		return nil, err
	}
	var created time.Time
	if t := actor.GetMetadata().GetCreateTime(); t != nil {
		created = t.AsTime()
	}
	return &backend.Handle{Key: key, Name: key.ActorName(b.prefix), CreatedAt: created}, nil
}

// Suspend checkpoints the actor (MEMORY fidelity keeps agent processes).
func (b *Backend) Suspend(ctx context.Context, h *backend.Handle) error {
	// A suspended actor can always resume, so its record is kept — only
	// terminal delete evicts (finding R3, conservative side).
	unlock := b.lockOp(h.Name)
	defer unlock()
	return b.lc.Suspend(ctx, b.atspace, h.Name, b.durability)
}

// Delete destroys the actor.
func (b *Backend) Delete(ctx context.Context, h *backend.Handle) error {
	unlock := b.lockOp(h.Name)
	defer func() {
		// Terminal for this actor in our ownership model — evict whether the
		// delete completed or failed (finding R3): completed → nothing left
		// to serialize; failed → unknown control-plane state whose next
		// contact is a fresh EnsureReady, and a stale strike chain must not
		// count against a possibly-recreated actor (clearing only ever
		// delays a purge, never causes one). Evicting under the op keeps
		// lockOp's staleness check sound.
		b.evictOp(h.Name)
		unlock()
	}()
	return b.lc.Delete(ctx, b.atspace, h.Name)
}

// ListReady lists every actor in the shim's atespace (the atespace is
// shim-owned; names may pre-date the current naming scheme after upgrades).
func (b *Backend) ListReady(ctx context.Context) ([]backend.Handle, error) {
	actors, err := b.lc.ListActors(ctx, b.atspace)
	if err != nil {
		return nil, err
	}
	var out []backend.Handle
	for _, a := range actors {
		var created time.Time
		if t := a.GetMetadata().GetCreateTime(); t != nil {
			created = t.AsTime()
		}
		out = append(out, backend.Handle{Name: a.GetMetadata().GetName(), CreatedAt: created})
	}
	return out, nil
}

// ReportLine is one preloaded-report from an actor's local report file.
type ReportLine struct {
	Actor     string
	Atespace  string
	Host      string
	Requestor string
}

// sweepReport reads (and truncates) an actor's DNS-failure report file via
// its open_terminal /execute channel. Returns nothing when the file does not
// exist. Runs through the same tunnel the facade proxies with, so no extra
// actor→shim network path is needed.
func (b *Backend) SweepReports(ctx context.Context, h *backend.Handle) ([]ReportLine, error) {
	conn, err := b.dialer.DialActor(ctx, b.atspace, h.Name, b.actorPort)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return conn, nil },
		},
		Timeout: 30 * time.Second,
	}
	// Read first, then (only after a successful read) clear: one command that
	// truncates while reading loses the reports when the response is lost or
	// unparseable.
	body := strings.NewReader(`{"command":"cat /tmp/.ot-egress/seen.jsonl 2>/dev/null; echo SWEEPMARK","cwd":"/home/user"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://actor/execute?wait=15", body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+b.actorAPIKey)
	req.Header.Set("X-User-Id", "trident-sweeper")
	req.Header.Set("X-Session-Id", "sweep")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sweep: %s", resp.Status)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var out struct {
		Output []struct {
			Data string `json:"data"`
		} `json:"output"`
	}
	if json.Unmarshal(raw, &out) != nil {
		return nil, fmt.Errorf("sweep: bad response")
	}
	text := ""
	for _, o := range out.Output {
		text += o.Data
	}
	var lines []ReportLine
	parsed := true
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "{") || strings.Contains(l, "SWEEPMARK") {
			continue
		}
		var rec struct {
			Host      string `json:"host"`
			Requestor string `json:"requestor"`
		}
		if json.Unmarshal([]byte(l), &rec) != nil || rec.Host == "" {
			parsed = false
			continue
		}
		lines = append(lines, ReportLine{
			Actor: h.Name, Atespace: b.atspace,
			Host: rec.Host, Requestor: rec.Requestor,
		})
	}
	if !parsed {
		// The file may hold more lines than the response carried; leave it
		// for the next tick instead of truncating it on a bad read.
		return lines, fmt.Errorf("sweep: partial read, report file left intact")
	}
	// Read + parse succeeded: clear the file in its own command.
	if body2, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://actor/execute?wait=5",
		strings.NewReader(`{"command":": > /tmp/.ot-egress/seen.jsonl","cwd":"/home/user"}`)); err == nil {
		body2.Header.Set("Content-Type", "application/json")
		body2.Header.Set("Authorization", "Bearer "+b.actorAPIKey)
		if resp, err := client.Do(body2); err == nil {
			_ = resp.Body.Close()
		}
	}
	return lines, nil
}

// ActorDetails returns state/template/created for the console panel.
func (b *Backend) ActorDetails(ctx context.Context, name string) (state, template, created string) {
	a, err := b.lc.GetActor(ctx, b.atspace, name)
	if err != nil || a == nil {
		return "", "", ""
	}
	state = a.GetStatus().GetState().String()
	template = a.GetActorTemplate().GetName()
	if t := a.GetMetadata().GetCreateTime(); t != nil {
		created = t.AsTime().UTC().Format(time.RFC3339)
	}
	return state, template, created
}

// actorDialer manufactures CONNECT-tunnel connections to one actor's port.
// Each tunnel is independent: router request parking and auto-resume apply
// per request inside it.
type actorDialer struct {
	b    *Backend
	name string
}

var _ backend.Dialer = (*actorDialer)(nil)

// DialConn opens a new CONNECT tunnel.
func (d *actorDialer) DialConn(ctx context.Context, _ string) (net.Conn, error) {
	return d.b.dialer.DialActor(ctx, d.b.atspace, d.name, d.b.actorPort)
}

// --- resume self-heal escalation (finding C3) ------------------------------

const (
	// selfHealEscalationN is how many consecutive EnsureReady calls must
	// each produce affirmative restore-corruption evidence before the
	// self-heal path may purge (Delete) an actor. Delete destroys the actor's
	// durable /home/user volume, so the bar is deliberately high: a transient
	// blip can never satisfy it, and neither can a single definitive failure.
	selfHealEscalationN = 3

	// revertMaxAttempts bounds one self-heal Revert: the first attempt plus
	// up to 2 retries of transient failures (spec budget: retry 2-3x).
	revertMaxAttempts = 3

	// revertRetryBackoff is the delay before the first transient Revert
	// retry; it doubles after every subsequent retry.
	revertRetryBackoff = 500 * time.Millisecond
)

// revertOutcome classifies a Revert result for self-heal escalation.
type revertOutcome int

const (
	// revertRecovered: Revert succeeded (or was the substrate's documented
	// no-op, e.g. FailedPrecondition on a suspended actor without a
	// node-local snapshot). Normal recovery; nothing to escalate.
	revertRecovered revertOutcome = iota
	// revertTransient: transport, deadline, overload — or an error that
	// cannot be classified at all. Retried with backoff and NEVER escalated
	// to a purge.
	revertTransient
	// revertAbsent: the actor is already gone; recreating loses no data.
	revertAbsent
	// revertCorruption: the control plane affirmatively reported a damaged
	// snapshot/restore (the DataLoss allowlist). Escalates to a purge only
	// once it repeats selfHealEscalationN times consecutively.
	revertCorruption
	// revertOperator: an affirmative but NON-corruption refusal — version
	// skew (Unimplemented), RBAC regression (PermissionDenied),
	// misconfiguration (InvalidArgument), the documented benign no-op
	// (FailedPrecondition) or any other unclassified affirmative code.
	// Configuration problems are never corruption evidence: keep the actor,
	// Error-log with the route key, reset the strike chain, never auto-purge
	// (security review on C3).
	revertOperator
)

// transientRevertCodes lists the gRPC codes attributable to transport,
// caller deadlines, or load (the A6-retryable subset), plus Internal and
// Canceled. status.Code reports Unknown for *any* non-gRPC error, so Unknown
// is deliberately transient too. Neither group can ever grant a purge: that
// requires affirmative DataLoss (see classifyRevertError).
var transientRevertCodes = map[codes.Code]bool{
	codes.Unavailable:       true,
	codes.DeadlineExceeded:  true,
	codes.Aborted:           true,
	codes.ResourceExhausted: true,
	codes.Internal:          true,
	codes.Canceled:          true,
	codes.Unknown:           true,
	codes.OK:                true, // unreachable for err != nil; defensive
}

// classifyRevertError is a pure classifier from a Revert error to the
// self-heal outcome buckets. It unwraps fmt.Errorf %w chains (status.Code
// resolves through errors.As), which is how Lifecycle.Revert reports errors.
func classifyRevertError(err error) revertOutcome {
	if err == nil {
		return revertRecovered
	}
	code := status.Code(err)
	if code == codes.NotFound {
		return revertAbsent
	}
	if transientRevertCodes[code] {
		return revertTransient
	}
	// Corruption allowlist (security review on C3): only DataLoss
	// affirmatively describes a damaged snapshot/restore. Every other
	// affirmative non-transient code — Unimplemented (Revert RPC absent
	// under version skew), PermissionDenied (RBAC regression),
	// InvalidArgument, FailedPrecondition (already swallowed as a benign
	// no-op by Lifecycle.Revert; classified here defensively) or any future
	// unclassified code — is an operator-action configuration problem, not
	// evidence against the actor's data: fail closed against purges.
	if code == codes.DataLoss {
		return revertCorruption
	}
	return revertOperator
}

// selfHealDecision is the pure escalation classifier: given the actor's
// previous consecutive-evidence strike count and this call's classified
// outcome, it returns the updated strike count and whether a purge
// (Delete — which destroys durable data) is permitted. Only revertCorruption
// (the DataLoss allowlist) increments the chain; every other outcome —
// transient, operator-action, absent, recovered — resets it to zero, so
// neither transient failures nor configuration problems can ever trigger a
// purge, no matter how often they occur.
func selfHealDecision(prevStrikes int, outcome revertOutcome) (strikes int, purge bool) {
	if outcome != revertCorruption {
		return 0, false
	}
	strikes = prevStrikes + 1
	return strikes, strikes >= selfHealEscalationN
}

// recordSelfHealOutcome applies selfHealDecision to the actor's stored
// strike count and persists the result. A zero count deletes the entry, so
// the map only ever holds actors with strikes in flight.
func (b *Backend) recordSelfHealOutcome(name string, outcome revertOutcome) (strikes int, purge bool) {
	prev := 0
	if v, ok := b.selfHealStrikes.Load(name); ok {
		prev, _ = v.(int)
	}
	strikes, purge = selfHealDecision(prev, outcome)
	if strikes == 0 {
		b.selfHealStrikes.Delete(name)
	} else {
		b.selfHealStrikes.Store(name, strikes)
	}
	return strikes, purge
}

// clearSelfHealStrikes breaks an actor's consecutive-evidence chain: after
// a fully successful EnsureReady or a completed purge, the next definitive
// failure starts counting from scratch.
func (b *Backend) clearSelfHealStrikes(name string) {
	b.selfHealStrikes.Delete(name)
}

// revertWithRetry runs Lifecycle.Revert, retrying only transient failures
// with backoff; definitive and absent answers return immediately.
func revertWithRetry(ctx context.Context, lc *Lifecycle, log *slog.Logger, atespace, name string) error {
	return retryTransientRevert(ctx, log, name, revertRetryBackoff, func(ctx context.Context) error {
		return lc.Revert(ctx, atespace, name)
	})
}

// retryTransientRevert is the testable core of revertWithRetry: it calls
// revert, and while the outcome classifies as revertTransient it retries up
// to revertMaxAttempts total attempts with exponential backoff. On context
// cancellation it returns the ctx error, which classifies as transient —
// and therefore never escalates to a purge.
func retryTransientRevert(ctx context.Context, log *slog.Logger, name string, backoff time.Duration, revert func(context.Context) error) error {
	var err error
	for attempt := 1; attempt <= revertMaxAttempts; attempt++ {
		if attempt > 1 {
			log.Warn("transient revert failure; retrying",
				"actor", name, "attempt", attempt, "backoff", backoff, "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		err = revert(ctx)
		if err == nil || classifyRevertError(err) != revertTransient {
			return err
		}
	}
	return err
}
