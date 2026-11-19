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
	"strings"
	"sync"
	"time"

	"github.com/viveksupe/Trident/third_party/ateapi"

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
	// per-actor lifecycle op serialization
	ops sync.Map // actor name -> *sync.Mutex
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

	callbackHost := ""
	callbackPort := ""
	if cfg.EgressCallback != "" {
		callbackHost = callbackHostName(cfg.EgressCallback)
		callbackPort = strings.TrimPrefix(cfg.EgressCallback[strings.LastIndex(cfg.EgressCallback, ":")+1:], ":")
	}

	return &Backend{
		lc: &Lifecycle{
			client:           client,
			TemplateAtespace: cfg.TemplateAtespace(),
			TemplateName:     cfg.TemplateName(),
			EgressHosts:      cfg.EgressHosts,
			CallbackHost:     callbackHost,
			CallbackPort:     callbackPort,
		},
		dialer:      dialer,
		atspace:     cfg.Atespace,
		prefix:      cfg.ActorPrefix,
		actorPort:   cfg.ActorPort,
		actorAPIKey: cfg.ActorAPIKey,
		durability:  durability,
		log:         log,
	}, nil
}

// callbackHostName splits "host[:port]" and returns the host part.
func callbackHostName(cb string) string {
	if i := strings.Index(cb, ":"); i >= 0 {
		return cb[:i]
	}
	return cb
}

func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

// opLock returns a per-actor mutex, serializing lifecycle ops per actor.
func (b *Backend) opLock(name string) *sync.Mutex {
	m, _ := b.ops.LoadOrStore(name, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// EnsureReady creates the actor if missing, resumes it if suspended, and
// returns a tunnel dialer for its HTTP port.
func (b *Backend) EnsureReady(ctx context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	name := key.ActorName(b.prefix)
	mu := b.opLock(name)
	mu.Lock()
	defer mu.Unlock()

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
			// snapshot, or — when even that snapshot is unusable — by deleting
			// and recreating the actor from the template's golden snapshot.
			b.log.Warn("resume failed; attempting self-heal", "actor", name, "err", err)
			if revErr := b.lc.Revert(ctx, b.atspace, name); revErr != nil {
				b.log.Warn("revert failed; deleting and recreating the actor",
					"actor", name, "err", revErr)
				if delErr := b.lc.Delete(ctx, b.atspace, name); delErr != nil {
					return nil, nil, fmt.Errorf("delete during self-heal: %w", delErr)
				}
				created = time.Time{} // dropped its durable volume with it
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

	// Actors created before the egress-request flow existed lack the callback
	// allow rule; ensure it once per resume cycle (cheap: read+patch, no-op
	// when present).
	if err := b.lc.EnsureCallbackRule(ctx, b.atspace, name); err != nil {
		b.log.Warn("callback rule sync failed (egress requests disabled for this actor)",
			"actor", name, "err", err)
	}

	if created.IsZero() {
		created = time.Now()
	}
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
	mu := b.opLock(h.Name)
	mu.Lock()
	defer mu.Unlock()
	return b.lc.Suspend(ctx, b.atspace, h.Name, b.durability)
}

// Delete destroys the actor.
func (b *Backend) Delete(ctx context.Context, h *backend.Handle) error {
	mu := b.opLock(h.Name)
	mu.Lock()
	defer mu.Unlock()
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
	body := strings.NewReader(`{"command":"cat /tmp/.ot-egress/seen.jsonl 2>/dev/null && echo SWEEPMARK; : > /tmp/.ot-egress/seen.jsonl","cwd":"/home/user"}`)
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
			continue
		}
		lines = append(lines, ReportLine{
			Actor: h.Name, Atespace: b.atspace,
			Host: rec.Host, Requestor: rec.Requestor,
		})
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
