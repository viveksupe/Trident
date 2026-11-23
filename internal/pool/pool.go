// Package pool owns the chat→actor map: on-demand creation through the Backend,
// in-flight request refcounts, and the idle suspend / max-age cleanup ticker.
package pool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/sessionmap"
	"golang.org/x/sync/singleflight"
)

// ErrActorCapReached reports that admitting this route key as a NEW actor
// would exceed TRI_MAX_ACTORS (global) or TRI_MAX_ACTORS_PER_USER. The
// facade maps it via errors.Is to a 429 with a static detail — the wrapped
// message may name caps and identities for logs but never reaches a client.
var ErrActorCapReached = errors.New("actor capacity reached")

// session is one live mapping entry. lock ordering: life (per session) THEN
// mu (pool) — Acquire routes through life, the sweep takes life before its
// substrate call, so neither can hold both with the outer mutex first.
type session struct {
	handle     *backend.Handle
	dialer     backend.Dialer
	lastActive time.Time
	inflight   int64 // open HTTP requests (incl. spliced WS); suspend waits for zero
	sweeping   bool  // a suspend/delete is running; Acquire waits for it
	// lastErr is the most recent EnsureReady failure on the keep-last-known
	// path: surfaced by Acquire when no dialer has ever been established.
	lastErr error
	life    sync.Mutex
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

	// MaxActors / MaxActorsPerUser are the creation caps (R3): 0 disables a
	// cap (pool default; config.Load ships production 256/32). Wire them
	// from config before the first Acquire. "Live" for the count = ready,
	// mid-create AND suspended-not-deleted actors; resuming an existing
	// actor never counts as a create, and a completed full delete (sweep or
	// console purge) frees its slot. See checkCapLocked.
	MaxActors        int
	MaxActorsPerUser int

	sf  singleflight.Group
	mu  sync.Mutex
	ses map[model.RouteKey]*session
	now func() time.Time
	// lastSeenDirty buffers activity timestamps flushed to sqlite in one
	// batch per sweep tick — per-request writes under the pool mutex
	// serialized every request behind disk I/O.
	lastSeenDirty map[model.RouteKey]time.Time
}

// New constructs a pool. store may be nil (in-memory only, no restart persistence).
func New(b backend.Backend, store *sessionmap.Store, log *slog.Logger, idleTTL, deleteIdleTTL, maxAge time.Duration) *Pool {
	return &Pool{
		backend: b, store: store, log: log,
		idleTTL: idleTTL, deleteIdleTTL: deleteIdleTTL, maxAge: maxAge,
		AllowSuspend: true, WarmWindow: 5 * time.Second,
		ses: map[model.RouteKey]*session{}, now: time.Now,
		lastSeenDirty: map[model.RouteKey]time.Time{},
	}
}

// Ready is the triple Acquire hands to the facade. Dialer is always non-nil:
// Acquire fails rather than hand back a session that never completed an
// EnsureReady in this process (Seed after restart, backend outage).
type Ready struct {
	Handle backend.Handle
	Dialer backend.Dialer
}

// hold waits out any in-flight lifecycle op on the session registered for
// key and returns it with sess.life held (nil when none is registered).
// Callers must release life and re-establish any assumptions after the
// backend call — the sweep may have replaced or removed the entry meanwhile.
func (p *Pool) hold(key model.RouteKey) *session {
	for {
		p.mu.Lock()
		ses := p.ses[key]
		p.mu.Unlock()
		if ses == nil {
			return nil
		}
		ses.life.Lock()
		p.mu.Lock()
		cur := p.ses[key]
		if cur == ses && !ses.sweeping {
			p.mu.Unlock()
			return ses
		}
		p.mu.Unlock()
		ses.life.Unlock() // replaced or swept away while we waited: retry
	}
}

// Acquire ensures the actor for key is ready and registers an in-flight request.
// The returned inflight must hit Done() when the request (or spliced WS) ends.
func (p *Pool) Acquire(ctx context.Context, key model.RouteKey) (Ready, *Inflight, error) {
	ses, err := p.acquireSession(ctx, key)
	if err != nil {
		return Ready{}, nil, err
	}

	inf := &Inflight{onDone: func() {
		now := p.now()
		p.mu.Lock()
		ses.inflight--
		ses.lastActive = now
		p.lastSeenDirty[key] = now
		p.mu.Unlock()
	}}

	// A session that has never completed an EnsureReady in this process has
	// no dialer — Seed stores handle-only on purpose, and the keep-last-known
	// path can return a seeded session during a backend outage. Handing that
	// to the proxy nil-derefs in the transport's DialContext, so fail with
	// the facade's 502-mapped error instead. Snapshot under p.mu (ensure
	// writes handle/dialer/lastErr there) and release the refcount attach
	// just took.
	p.mu.Lock()
	handle, dialer, lastErr := ses.handle, ses.dialer, ses.lastErr
	p.mu.Unlock()
	if handle == nil || dialer == nil {
		inf.Done()
		if lastErr != nil {
			return Ready{}, nil, fmt.Errorf("warming: no dialer yet (last EnsureReady failed: %w)", lastErr)
		}
		return Ready{}, nil, errors.New("warming: no dialer yet")
	}
	return Ready{Handle: *handle, Dialer: dialer}, inf, nil
}

// acquireSession resolves the session and registers this caller's refcount.
// Every caller attaches AFTER the (shared) ensure returns — singleflight's
// "shared" flag is true for the executor too when others joined, so the
// leader cannot be told apart that way.
func (p *Pool) acquireSession(ctx context.Context, key model.RouteKey) (*session, error) {
	for {
		// Detached: the leader's ctx must not kill the ensure for waiters,
		// and the two-segment key (user + chat) is joined unambiguously —
		// "a/b"+"c" and "a"+"b/c" must not share a singleflight bucket
		// (that handed one caller the OTHER key's session).
		v, err, _ := p.sf.Do(key.SfKey(), func() (any, error) {
			return p.ensure(context.WithoutCancel(ctx), key)
		})
		if err != nil {
			return nil, err
		}
		ses := v.(*session)
		if p.attach(key, ses) {
			return ses, nil
		}
		// The session lost the map slot between ensure and attach (a sweep
		// won the lifecycle lock first): run a fresh ensure — EnsureReady
		// resumes or recreates the actor.
	}
}

// attach registers a caller's refcount under the session's lifecycle lock.
// False means the session lost the map slot (swept/purged meanwhile) and the
// caller must re-acquire.
func (p *Pool) attach(key model.RouteKey, ses *session) bool {
	for {
		ses.life.Lock()
		p.mu.Lock()
		if cur := p.ses[key]; cur != ses {
			p.mu.Unlock()
			ses.life.Unlock()
			return false
		}
		if !ses.sweeping {
			ses.inflight++
			ses.lastActive = p.now()
			p.lastSeenDirty[key] = ses.lastActive
			p.mu.Unlock()
			ses.life.Unlock()
			return true
		}
		p.mu.Unlock()
		ses.life.Unlock()
		// A suspend/delete is running on this session; wait it out. Its
		// completion drops the map slot and the caller's next ensure
		// resumes or recreates the actor.
		time.Sleep(25 * time.Millisecond)
	}
}

// checkCapLocked admits at most MaxActors / MaxActorsPerUser NEW actors.
// Callers hold p.mu and have verified no session is registered for key —
// the check and the registration below it happen in one critical section,
// so concurrent creates serialize here and cannot jointly overshoot a cap.
//
// The count is derived rather than maintained: a live actor is a registered
// session ∪ a sessionmap row without one. The union counts every state
// exactly once —
//
//	mid-create:  registered, row not yet written  → session
//	ready:       both                            → session (row excluded)
//	suspended:   slot dropped, row kept          → row
//	restarted:   rows seed or await their request → row
//
// and frees on both sides at once (full delete drops the slot and the row;
// a failed create drops the rolled-back slot), so no decrement bookkeeping
// can drift. A row for key means the sandbox exists: this registration only
// RESUMES it, so it is admitted unconditionally — existing sessions keep
// working at the cap. Without a store (dev/test pools) only registered
// sessions count; production always persists (TRI_STATE_DB).
//
// Rows are read only on this cold create path (never per request). A store
// read error fails OPEN: a cap check must not take the proxy down with a
// transient sqlite hiccup.
func (p *Pool) checkCapLocked(key model.RouteKey) error {
	if p.MaxActors <= 0 && p.MaxActorsPerUser <= 0 {
		return nil // caps disabled
	}
	var rows map[model.RouteKey]sessionmap.Entry
	if p.store != nil {
		var err error
		if rows, err = p.store.All(); err != nil {
			p.log.Warn("actor cap check: store read failed; allowing create", "err", err)
			return nil
		}
	}
	if _, exists := rows[key]; exists {
		return nil // resume of an existing actor, not a new create
	}
	live, userLive := len(p.ses), 0
	for k := range p.ses {
		if k.UserID == key.UserID {
			userLive++
		}
	}
	for rk := range rows {
		if _, registered := p.ses[rk]; registered {
			continue // counted via its session already
		}
		live++
		if rk.UserID == key.UserID {
			userLive++
		}
	}
	if p.MaxActors > 0 && live+1 > p.MaxActors {
		return fmt.Errorf("creating %s would exceed TRI_MAX_ACTORS=%d (live %d): %w",
			key.LogString(), p.MaxActors, live, ErrActorCapReached)
	}
	if p.MaxActorsPerUser > 0 && userLive+1 > p.MaxActorsPerUser {
		return fmt.Errorf("creating %s would exceed TRI_MAX_ACTORS_PER_USER=%d (user live %d): %w",
			key.LogString(), p.MaxActorsPerUser, userLive, ErrActorCapReached)
	}
	return nil
}

// ensure returns the session (life NOT held — callers attach afterwards),
// verifying/warming the actor in the backend when the last known-active
// point is stale. life is held only across the backend interaction, so a
// concurrent sweep cannot act mid-ensure; the attach step afterwards either
// lands on this session or the caller retries through a fresh ensure.
func (p *Pool) ensure(ctx context.Context, key model.RouteKey) (*session, error) {
	ses := p.hold(key)
	if ses != nil && ses.dialer != nil && p.now().Sub(ses.lastActive) < p.WarmWindow {
		ses.life.Unlock()
		return ses, nil // warm
	}
	if ses == nil {
		// Create-and-hold under the outer mutex; if a concurrent ensure won
		// the slot in the meantime, restart through the normal hold path.
		ses = &session{lastActive: p.now()}
		ses.life.Lock()
		p.mu.Lock()
		if existing := p.ses[key]; existing != nil {
			p.mu.Unlock()
			ses.life.Unlock()
			return p.ensure(ctx, key)
		}
		// Creation cap (R3): checked here, in the same critical section as
		// the registration, so the check→create gap is atomic under p.mu.
		// A rejected create registers nothing — no residue, no slot held.
		if err := p.checkCapLocked(key); err != nil {
			p.mu.Unlock()
			ses.life.Unlock()
			return nil, err
		}
		p.ses[key] = ses
		p.mu.Unlock()
	}

	h, dialer, err := p.backend.EnsureReady(ctx, key)
	if err != nil {
		if ses.handle != nil {
			// Keep the last-known session: a warm one still has its dialer and
			// keeps serving (a truly dead actor surfaces in the proxied
			// request); a cold one (seeded, dialer never established) fails
			// in Acquire as "warming" instead of being handed out nil.
			p.log.Warn("backend EnsureReady failed; keeping last-known session",
				"key", key.LogString(), "err", err)
			p.mu.Lock()
			ses.lastErr = err
			p.mu.Unlock()
			ses.life.Unlock()
			return ses, nil
		}
		p.mu.Lock()
		if p.ses[key] == ses {
			delete(p.ses, key)
		}
		p.mu.Unlock()
		ses.life.Unlock()
		return nil, fmt.Errorf("actor not ready: %w", err)
	}

	p.mu.Lock()
	if p.ses[key] != ses {
		// The slot was freed under us (console purge forgets without the
		// lifecycle lock): re-register; EnsureReady recreated the actor.
		p.ses[key] = ses
	}
	ses.handle, ses.dialer = h, dialer
	ses.lastErr = nil
	ses.lastActive = p.now()
	p.mu.Unlock()
	if p.store != nil {
		_ = p.store.Put(sessionmap.Entry{
			UserID: key.UserID, ChatID: key.ChatID, ActorName: h.Name,
			CreatedAt: h.CreatedAt,
		})
	}
	ses.life.Unlock()
	return ses, nil
}

// Inflight represents one open request against an actor; Done must be called
// exactly once to release the refcount.
type Inflight struct {
	onDone func()
	once   sync.Once
}

// Done releases the in-flight refcount (idempotent; a late extra call is a
// no-op rather than a data race).
func (i *Inflight) Done() { i.once.Do(i.onDone) }

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
			p.flushLastSeen()
		}
	}
}

// flushLastSeen persists buffered activity timestamps outside the pool mutex.
func (p *Pool) flushLastSeen() {
	if p.store == nil {
		return
	}
	p.mu.Lock()
	if len(p.lastSeenDirty) == 0 {
		p.mu.Unlock()
		return
	}
	dirty := p.lastSeenDirty
	p.lastSeenDirty = map[model.RouteKey]time.Time{}
	p.mu.Unlock()
	if err := p.store.SetLastSeenBatch(dirty); err != nil {
		p.log.Debug("last-seen flush failed", "err", err)
	}
}

func (p *Pool) sweep(ctx context.Context) {
	now := p.now()
	type victim struct {
		key model.RouteKey
		ses *session
		// mode: max-age or long-idle → full delete; short idle → suspend
		remove bool
	}
	var toSweep []victim

	p.mu.Lock()
	for key, ses := range p.ses {
		// Never touch sessions with in-flight requests (HTTP or spliced WS),
		// ones already being swept by a concurrent pass, or ones still inside
		// EnsureReady: those are registered into the map before the backend
		// returns (handle == nil) and must not be aged out mid-create —
		// dereferencing the nil handle here would panic RunTicker (and the
		// process) on any tick landing inside an actor create.
		if ses.inflight > 0 || ses.sweeping || ses.handle == nil {
			continue
		}
		var victimReason string
		switch {
		case now.Sub(ses.handle.CreatedAt) > p.maxAge:
			victimReason = "deleting expired actor"
			toSweep = append(toSweep, victim{key, ses, true})
		case p.AllowSuspend && now.Sub(ses.lastActive) > p.deleteIdleTTL:
			// Idle past the delete TTL (deleted chats, abandoned sessions):
			// full delete frees the durable volume.
			victimReason = "deleting long-idle actor"
			toSweep = append(toSweep, victim{key, ses, true})
		case p.AllowSuspend && now.Sub(ses.lastActive) > p.idleTTL:
			victimReason = "suspending idle actor"
			toSweep = append(toSweep, victim{key, ses, false})
		default:
			continue
		}
		ses.sweeping = true // blocks Acquire until the lifecycle op decides
		p.log.Info(victimReason, "key", key.LogString(), "actor", ses.handle.Name,
			"idle", now.Sub(ses.lastActive))
	}
	p.mu.Unlock()

	for _, v := range toSweep {
		p.doSweep(ctx, v.key, v.ses, v.remove)
	}
}

// doSweep performs one lifecycle op under the session's lifecycle lock: the
// in-flight state is re-checked AFTER every concurrent Acquire (held inside
// ensure until it registers its refcount) has finished, so a busy actor is
// never suspended or deleted behind a request.
func (p *Pool) doSweep(ctx context.Context, key model.RouteKey, ses *session, remove bool) {
	ses.life.Lock()

	p.mu.Lock()
	busy := ses.inflight > 0
	p.mu.Unlock()
	if busy {
		// A request slipped in between the pick and the lifecycle lock.
		p.mu.Lock()
		ses.sweeping = false
		p.mu.Unlock()
		ses.life.Unlock()
		return
	}

	ctxT, cancel := context.WithTimeout(ctx, 5*time.Minute)
	var err error
	var stillTracked bool
	if remove {
		err = p.backend.Delete(ctxT, ses.handle)
		if err == nil {
			// Purge the persisted row + egress bookkeeping only when the map
			// slot still points at THIS session — a recreated actor (same
			// key, fresh actor after the delete) must keep its bookkeeping.
			p.mu.Lock()
			stillTracked = p.ses[key] == ses
			if stillTracked {
				if p.store != nil {
					_ = p.store.Delete(key)
				}
				delete(p.ses, key)
			}
			p.mu.Unlock()
		}
	} else {
		err = p.backend.Suspend(ctxT, ses.handle)
		if err == nil {
			p.log.Info("suspended idle actor", "actor", ses.handle.Name)
		}
	}
	cancel()
	if err != nil {
		p.log.Warn("lifecycle sweep failed", "actor", ses.handle.Name, "err", err)
	}

	// Drop the map slot when this pass still owns the key (for both suspend
	// and delete: the next Acquire walks EnsureReady and resumes/recreates
	// through the backend as before). The OnActorDeleted hook fires only
	// when the bookkeeping was not adopted by a recreated actor.
	p.mu.Lock()
	if p.ses[key] == ses {
		delete(p.ses, key)
	}
	if remove && err == nil && stillTracked && p.OnActorDeleted != nil {
		p.OnActorDeleted(ses.handle.Name)
	}
	ses.sweeping = false
	p.mu.Unlock()
	ses.life.Unlock()
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

func (i IdleInfo) Time() time.Time { return i.LastSeen }

// AcquireForSweep is the report-sweeper's read path: it serves already-ready
// actors WITHOUT counting chat activity (no lastActive touch — otherwise the
// sweeps keep every actor forever "live" and idle suspension never fires) and
// without resuming suspended ones (their pending reports wait for the next
// real touch).
func (p *Pool) AcquireForSweep(key model.RouteKey) (backend.Handle, bool) {
	p.mu.Lock()
	ses, ok := p.ses[key]
	p.mu.Unlock()
	if !ok || ses.handle == nil {
		return backend.Handle{}, false
	}
	return *ses.handle, true
}

// Seed hydrates supervision for a route whose actor already exists in the
// backend but has not been requested yet in this shim process: it joins the
// idle sweep with the restart moment as its activity baseline (its old
// WebSocket died with the previous process, so a prompt idle suspend is safe
// — the snapshot preserves the session). No EnsureReady call: seeding must
// not resume every suspended actor at once (a thundering herd after a busy
// restart); the first real request resumes on demand.
//
// Seeding never counts as a new create (R3): the sessionmap row it comes
// from already counts against the actor caps — checkCapLocked sees row and
// session as one actor — so reconcile neither inflates nor bypasses them.
func (p *Pool) Seed(_ context.Context, key model.RouteKey, handle *backend.Handle) {
	p.mu.Lock()
	if _, ok := p.ses[key]; ok {
		p.mu.Unlock()
		return
	}
	// Pre-age the baseline past WarmWindow so the first real request walks
	// EnsureReady (which populates the dialer) instead of serving a nil one.
	baseline := p.now().Add(-p.WarmWindow - time.Second)
	ses := &session{handle: handle, lastActive: baseline}
	p.ses[key] = ses
	p.lastSeenDirty[key] = baseline
	p.mu.Unlock()
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
