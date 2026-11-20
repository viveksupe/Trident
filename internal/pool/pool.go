// Package pool owns the chat→actor map: on-demand creation through the Backend,
// in-flight request refcounts, and the idle suspend / max-age cleanup ticker.
package pool

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/sessionmap"
	"golang.org/x/sync/singleflight"
)

// session is one live mapping entry.
type session struct {
	handle     *backend.Handle
	dialer     backend.Dialer
	lastActive time.Time
	inflight   int64 // open HTTP requests (incl. spliced WS); suspend waits for zero
}

// Pool reconciles route keys to backend actors.
type Pool struct {
	backend backend.Backend
	store   *sessionmap.Store
	// OnActorDeleted, when set, fires after a successful full delete
	// (console purge or long-idle sweep) so side stores can clean up.
	OnActorDeleted func(actorName string)
	log            *slog.Logger
	idleTTL        time.Duration
	deleteIdleTTL  time.Duration
	maxAge         time.Duration
	// AllowSuspend enables the idle suspend ticker (disable it for dev backends
	// whose suspend semantics differ, e.g. plain docker stop).
	AllowSuspend bool
	// WarmWindow suppresses per-request EnsureReady when the actor was active
	// this recently (a backend probe per request adds avoidable latency).
	WarmWindow time.Duration

	sf  singleflight.Group
	mu  sync.Mutex
	ses map[model.RouteKey]*session
	now func() time.Time
}

// New constructs a pool. store may be nil (in-memory only, no restart persistence).
func New(b backend.Backend, store *sessionmap.Store, log *slog.Logger, idleTTL, deleteIdleTTL, maxAge time.Duration) *Pool {
	return &Pool{
		backend: b, store: store, log: log,
		idleTTL: idleTTL, deleteIdleTTL: deleteIdleTTL, maxAge: maxAge,
		AllowSuspend: true, WarmWindow: 5 * time.Second,
		ses: map[model.RouteKey]*session{}, now: time.Now,
	}
}

// Ready is the triple Acquire hands to the facade.
type Ready struct {
	Handle backend.Handle
	Dialer backend.Dialer
}

// Acquire ensures the actor for key is ready and registers an in-flight request.
// The returned inflight must hit Done() when the request (or spliced WS) ends.
func (p *Pool) Acquire(ctx context.Context, key model.RouteKey) (Ready, *Inflight, error) {
	v, err, _ := p.sf.Do(key.LogString(), func() (any, error) {
		return p.ensure(ctx, key)
	})
	if err != nil {
		return Ready{}, nil, err
	}
	ses := v.(*session)

	p.mu.Lock()
	ses.lastActive = p.now()
	if p.store != nil {
		_ = p.store.SetLastSeen(key, ses.lastActive)
	}
	ses.inflight++
	p.mu.Unlock()

	inf := &Inflight{onDone: func() {
		p.mu.Lock()
		ses.inflight--
		ses.lastActive = p.now()
		if p.store != nil {
			_ = p.store.SetLastSeen(key, ses.lastActive)
		}
		p.mu.Unlock()
	}}
	return Ready{Handle: *ses.handle, Dialer: ses.dialer}, inf, nil
}

// ensure returns the session, verifying/warming the actor in the backend when
// the last known-active point is stale.
func (p *Pool) ensure(ctx context.Context, key model.RouteKey) (*session, error) {
	p.mu.Lock()
	ses, ok := p.ses[key]
	warm := ok && p.now().Sub(ses.lastActive) < p.WarmWindow
	p.mu.Unlock()

	if warm {
		return ses, nil
	}

	h, dialer, err := p.backend.EnsureReady(ctx, key)
	if err != nil {
		if ok {
			// Keep serving the warm-but-stale session: if the actor is truly
			// dead the proxied request surfaces it.
			p.log.Warn("backend EnsureReady failed; keeping last-known session",
				"key", key.LogString(), "err", err)
			return ses, nil
		}
		return nil, fmt.Errorf("actor not ready: %w", err)
	}

	p.mu.Lock()
	if ok {
		ses.handle, ses.dialer = h, dialer
		p.mu.Unlock()
		return ses, nil
	}
	ses = &session{handle: h, dialer: dialer, lastActive: p.now()}
	p.ses[key] = ses
	p.mu.Unlock()

	if p.store != nil {
		_ = p.store.Put(sessionmap.Entry{
			UserID: key.UserID, ChatID: key.ChatID, ActorName: h.Name,
			CreatedAt: h.CreatedAt,
		})
	}
	return ses, nil
}

// Inflight represents one open request against an actor; Done must be called
// exactly once to release the refcount.
type Inflight struct {
	onDone func()
	done   bool
}

// Done releases the in-flight refcount.
func (i *Inflight) Done() {
	if !i.done {
		i.done = true
		i.onDone()
	}
}

// RunTicker reconciles lifecycle every interval: suspend idle sessions (only if
// AllowSuspend), delete max-age sessions. Blocking; call it in a goroutine.
func (p *Pool) RunTicker(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.sweep(ctx)
		}
	}
}

func (p *Pool) sweep(ctx context.Context) {
	now := p.now()
	type victim struct {
		key    model.RouteKey
		handle *backend.Handle
		remove bool
	}
	var toSweep []victim

	p.mu.Lock()
	for key, ses := range p.ses {
		// Never touch sessions with in-flight requests (HTTP or spliced WS).
		if ses.inflight > 0 {
			continue
		}
		switch {
		case now.Sub(ses.handle.CreatedAt) > p.maxAge:
			p.log.Info("deleting expired actor", "key", key.LogString(), "actor", ses.handle.Name)
			toSweep = append(toSweep, victim{key, ses.handle, true})
		case p.AllowSuspend && now.Sub(ses.lastActive) > p.deleteIdleTTL:
			// Idle past the delete TTL (deleted chats, abandoned sessions):
			// full delete frees the durable volume.
			p.log.Info("deleting long-idle actor", "key", key.LogString(), "actor", ses.handle.Name,
				"idle", now.Sub(ses.lastActive))
			toSweep = append(toSweep, victim{key, ses.handle, true})
		case p.AllowSuspend && now.Sub(ses.lastActive) > p.idleTTL:
			p.log.Info("suspending idle actor", "key", key.LogString(), "actor", ses.handle.Name,
				"idle", now.Sub(ses.lastActive))
			toSweep = append(toSweep, victim{key, ses.handle, false})
		}
	}
	p.mu.Unlock()

	for _, v := range toSweep {
		ctxT, cancel := context.WithTimeout(ctx, 5*time.Minute)
		var err error
		if v.remove {
			err = p.backend.Delete(ctxT, v.handle)
			if err == nil && p.store != nil {
				_ = p.store.Delete(v.key)
			}
			if err == nil && p.OnActorDeleted != nil {
				p.OnActorDeleted(v.handle.Name)
			}
		} else {
			err = p.backend.Suspend(ctxT, v.handle)
			if err == nil {
				p.log.Info("suspended idle actor", "actor", v.handle.Name)
			}
		}
		if err != nil {
			p.log.Warn("lifecycle sweep failed", "actor", v.handle.Name, "err", err)
		}
		cancel()
		p.mu.Lock()
		delete(p.ses, v.key)
		p.mu.Unlock()
	}
}

// ForgetByActorName drops the mapping for an actor (after its console-side
// deletion) and prunes the persisted row.
func (p *Pool) ForgetByActorName(name string) {
	p.mu.Lock()
	var keys []model.RouteKey
	for key, ses := range p.ses {
		if ses.handle != nil && ses.handle.Name == name {
			keys = append(keys, key)
		}
	}
	p.mu.Unlock()
	for _, key := range keys {
		p.mu.Lock() //nolint:staticcheck // two-phase is fine here
		delete(p.ses, key)
		p.mu.Unlock()
		if p.store != nil {
			_ = p.store.Delete(key)
		}
	}
}

// IdleInfo is an actor's last known activity: Tracked marks in-memory
// sessions (accurate), other entries come from the persisted row (survives
// shim restarts; falls back to row creation when never recorded).
type IdleInfo struct {
	LastSeen time.Time
	Tracked  bool
}

func (i IdleInfo) Time() time.Time {
	if i.Tracked {
		return i.LastSeen
	}
	return i.LastSeen
}

// Seed hydrates supervision for a route whose actor already exists in the
// backend but has not been requested yet in this shim process: it joins the
// idle sweep with the restart moment as its activity baseline (its old
// WebSocket died with the previous process, so a prompt suspend is safe —
// the snapshot preserves the session).
func (p *Pool) Seed(ctx context.Context, key model.RouteKey, handle *backend.Handle) {
	found, inflight, err := p.Acquire(ctx, key)
	if err != nil {
		p.log.Debug("seed skipped (not ready)", "key", key.LogString(), "err", err)
		return
	}
	_ = found
	inflight.Done()
}

// IdleEtas maps actor name → last known activity: in-memory sessions first,
// otherwise the persisted row (survives shim restarts).
func (p *Pool) IdleEtas() map[string]IdleInfo {
	out := map[string]IdleInfo{}
	p.mu.Lock()
	for _, ses := range p.ses {
		if ses.handle != nil {
			out[ses.handle.Name] = IdleInfo{LastSeen: ses.lastActive, Tracked: true}
		}
	}
	p.mu.Unlock()
	if p.store != nil {
		if entries, err := p.store.All(); err == nil {
			for _, e := range entries {
				if _, ok := out[e.ActorName]; ok {
					continue
				}
				la := e.LastSeen
				if la.IsZero() {
					la = e.CreatedAt // conservative: row began at creation
				}
				out[e.ActorName] = IdleInfo{LastSeen: la}
			}
		}
	}
	return out
}

// LiveKeys returns the route keys currently tracked (for the report sweeper).
func (p *Pool) LiveKeys() []model.RouteKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]model.RouteKey, 0, len(p.ses))
	for k := range p.ses {
		out = append(out, k)
	}
	return out
}

// Count reports how many live sessions the pool tracks.
func (p *Pool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.ses)
}
