// trident: Open WebUI "Open Terminal" protocol front for Agent Substrate actors.
//
// Subcommands:
//
//	serve      (default) run the facade
//	bootstrap  create the ActorTemplate + wait for its golden snapshot (substrate mode)
//	version    print version
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/backend/fakedocker"
	"github.com/viveksupe/Trident/internal/backend/substrate"
	"github.com/viveksupe/Trident/internal/config"
	"github.com/viveksupe/Trident/internal/egress"
	"github.com/viveksupe/Trident/internal/facade"
	"github.com/viveksupe/Trident/internal/model"
	"github.com/viveksupe/Trident/internal/pool"
	"github.com/viveksupe/Trident/internal/sessionmap"
)

var version = "dev"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 {
		switch args[0] {
		case "serve", "bootstrap", "version", "-h", "--help":
			cmd = args[0]
			args = args[1:]
		}
	}

	log := newLogger()

	switch cmd {
	case "version":
		fmt.Println("trident", version)
	case "--help", "-h":
		fmt.Fprintln(os.Stderr, "usage: trident [serve|bootstrap|version]")
	case "serve":
		if err := serveCmd(log); err != nil {
			log.Error("serve failed", "err", err)
			os.Exit(1)
		}
	case "bootstrap":
		if err := bootstrapCmd(log, args); err != nil {
			log.Error("bootstrap failed", "err", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "usage: trident [serve|bootstrap|version]")
		os.Exit(2)
	}
}

func newLogger() *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	if os.Getenv("TRI_LOG_LEVEL") == "debug" {
		opts.Level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}

func serveCmd(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("trident starting", "backend", cfg.Backend, "listen", cfg.ListenAddr)
	if cfg.KeyRewriteNeeded() {
		// The actor speaks the actor key (baked into the ActorTemplate); the
		// facade translates Authorization headers and the first frame of
		// terminal/agent WebSocket upgrades ("type":"auth") front-key-in.
		log.Info("TRI_ACTOR_API_KEY differs from TRI_API_KEY: credentials are translated on proxy (Authorization header + WS auth frame rewrite)")
	}

	store, err := sessionmap.Open(cfg.StateDB)
	if err != nil {
		return fmt.Errorf("session map: %w", err)
	}
	defer store.Close() //nolint:errcheck // nothing depends on the close result

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	backendImpl, err := loadBackend(cfg)
	if err != nil {
		return err
	}

	// Egress approval flow (substrate backend).
	var egressManager *egress.Manager
	sweeper, canSweep := backendImpl.(interface {
		SweepReports(ctx context.Context, h *backend.Handle) ([]substrate.ReportLine, error)
	})
	if cfg.EgressCallback != "" {
		if sb, ok := backendImpl.(*substrate.Backend); ok {
			egStore, err := egress.Open(cfg.StateDB)
			if err != nil {
				return fmt.Errorf("egress store: %w", err)
			}
			defer egStore.Close()
			lc := sb.LC()
			checker := func(ctx context.Context, actorName string) (string, bool, error) {
				if !strings.HasPrefix(actorName, cfg.ActorPrefix) {
					return "", false, nil
				}
				actor, err := lc.GetActor(ctx, cfg.Atespace, actorName)
				if err != nil {
					return "", false, err
				}
				if actor == nil {
					return "", false, nil
				}
				return cfg.Atespace, true, nil
			}
			egressManager = egress.New(egStore, lc, checker, log)
			egressManager.ActorPrefix = cfg.ActorPrefix
			go egressManager.RunRevokeTicker(ctx, 30*time.Second)
			log.Info("egress approval flow enabled", "callback", cfg.EgressCallback)

			// Passive side: ingest the egress gateway's deny logs so agent
			// attempts surface as pending approvals without the helper.
			if os.Getenv("TRI_EGRESS_OBSERVER") != "false" {
				kc, err := substrate.NewKubeClient(os.Getenv("KUBECONFIG"))
				if err != nil {
					log.Warn("egress observer disabled", "err", err)
				} else {
					obs := egress.NewObserver(egressManager, checker, kc,
						envDefault("ATE_NAMESPACE", "ate-system"),
						envDefault("TRI_EGRESS_OBSERVER_POD_SELECTOR", "app=atenet-egress"), log)
					go func() {
						t := time.NewTicker(30 * time.Second)
						defer t.Stop()
						for {
							select {
							case <-ctx.Done():
								return
							case <-t.C:
								obs.Tick(ctx)
							}
						}
					}()
					log.Info("egress observer enabled (gateway deny logs → approvals)")
				}
			}
		} else {
			log.Warn("TRI_EGRESS_CALLBACK set but backend is not substrate; egress flow disabled")
		}
	}
	pl := pool.New(backendImpl, store, log, cfg.IdleTTL, cfg.DeleteIdleTTL, cfg.MaxAge)
	if egressManager != nil {
		// Console purges and long-idle sweeps also wipe this actor's egress
		// bookkeeping (pendings, grants, standing rules).
		pl.OnActorDeleted = func(actorName string) {
			_ = egressManager.PurgeActor(context.Background(), actorName)
		}
	}
	if cfg.Backend == config.BackendDocker {
		pl.AllowSuspend = false // docker stop loses container state; actors stay up
	}
	go pl.RunTicker(ctx, 30*time.Second)

	// Passive, primary channel: sweep actors' local DNS-failure report files
	// through the proxied /execute channel — no actor→shim egress needed.
	if egressManager != nil && canSweep {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					for _, key := range pl.LiveKeys() {
						handle, tracked := pl.AcquireForSweep(key)
						if !tracked {
							continue
						}
						lines, err := sweeper.SweepReports(ctx, &handle)
						if err != nil {
							continue
						}
						for _, l := range lines {
							if _, err := egressManager.SubmitObserved(ctx, l.Atespace, l.Actor, l.Host, "", "name resolution blocked (reported by the sandbox)"); err == nil {
								log.Info("swept DNS-failure report", "actor", l.Actor, "host", l.Host)
							}
						}
					}
				}
			}
		}()
		log.Info("egress report sweeper enabled (exec channel)")
	}
	var eflow egressPurger
	if egressManager != nil {
		eflow = egressManager
	}
	if err := reconcileOnRestart(ctx, log, backendImpl, store, eflow, pl); err != nil {
		log.Warn("restart reconciliation failed (continuing)", "err", err)
	}

	fs := facade.New(cfg, pl, log)
	fs.SetBackend(backendImpl)
	if egressManager != nil {
		fs.SetEgress(egressManager)
	}

	// TLS callback listener: actors reach this over tls-passthrough with a
	// self-signed cert (the actor side uses curl -k). Enabled whenever the
	// egress callback flow is on. It serves ONLY the actor-facing egress
	// endpoints — never the console or the front-side proxy (the shared key
	// an actor holds would otherwise let it cross tenants or self-approve).
	if egressManager != nil {
		tlsAddr := envDefault("TRI_TLS_LISTEN_ADDR", ":8443")
		go func() {
			cert, err := substrate.SelfSignedCallbackCert(substrate.CallbackHostname(cfg.EgressCallback))
			if err != nil {
				log.Error("tls callback cert generation failed", "err", err)
				return
			}
			s := &http.Server{
				Addr:              tlsAddr,
				Handler:           fs.CallbackHandler(),
				ReadHeaderTimeout: 10 * time.Second,
				TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}},
			}
			log.Info("tls callback listener (egress callback endpoints only)", "addr", tlsAddr, "host", substrate.CallbackHostname(cfg.EgressCallback))
			go func() {
				<-ctx.Done()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = s.Shutdown(shutdownCtx)
			}()
			if err := s.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("tls callback listener failed", "err", err)
			}
		}()
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           fs.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No WriteTimeout: spliced WS + streaming responses live long.
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("facade listening", "addr", cfg.ListenAddr, "atespace", cfg.Atespace)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("trident stopped")
	return nil
}

func bootstrapCmd(log *slog.Logger, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	var img string
	var wait time.Duration
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	fs.StringVar(&img, "image", "", "actor image ref (repo@sha256:...) — required")
	fs.DurationVar(&wait, "wait", 15*time.Minute, "max wait for the golden snapshot")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if img == "" {
		return errors.New("-image is required (output of scripts/build-actor-image.sh)")
	}
	return substrate.RunBootstrap(log, cfg, img, wait)
}

// egressPurger is the slice of the egress manager reconcileOnRestart needs.
type egressPurger interface {
	PurgeActor(ctx context.Context, actor string) error
}

// reconcileOnRestart prunes persisted session-map rows whose actors no
// longer exist in the backend (deleted externally or expired) and reports
// actors that are still live. Actor names are derived deterministically from
// the route key, so surviving mappings need no migration.
func reconcileOnRestart(ctx context.Context, log *slog.Logger, backendImpl backend.Backend, store *sessionmap.Store, eflow egressPurger, pl *pool.Pool) error {
	all, err := store.All()
	if err != nil || len(all) == 0 {
		return err
	}
	known := map[string]bool{}
	actors, err := backendImpl.ListReady(ctx)
	if err != nil {
		// ListReady only ever returns a provably complete listing or an
		// error (S9: ListActors follows NextPageToken and refuses an empty
		// page behind a continuation token). Refusing here is the only safe
		// answer: pruning session rows or egress bookkeeping on a truncated
		// list would orphan live actors and release them from idle
		// supervision. Nothing above this point mutated any state.
		return err
	}
	for _, a := range actors {
		known[a.Name] = true
	}
	keep := map[model.RouteKey]sessionmap.Entry{}
	for key, entry := range all {
		if known[entry.ActorName] {
			keep[key] = entry
		} else {
			log.Info("pruning session map entry (actor gone)", "key", key.LogString(), "actor", entry.ActorName)
		}
	}
	log.Info("session map reconciled", "kept", len(keep), "pruned", len(all)-len(keep))
	// Hydrate supervision for actors that exist but have not been requested
	// in this process yet — otherwise they escape the idle sweep and run
	// forever. The restart moment is the activity baseline (the old browser
	// WebSocket died with the previous shim).
	for key, entry := range keep {
		pl.Seed(ctx, key, &backend.Handle{Name: entry.ActorName, CreatedAt: entry.CreatedAt})
	}
	// Egress bookkeeping for actors the backend no longer has: purge it at
	// startup too (TTL deletes that happened while the shim was down).
	if eflow != nil {
		for key := range all {
			if _, ok := keep[key]; !ok {
				_ = eflow.PurgeActor(context.Background(), all[key].ActorName)
			}
		}
	}
	return store.Prune(keep)
}

// loadBackend instantiates the configured backend.
func loadBackend(cfg *config.Config) (backend.Backend, error) {
	switch cfg.Backend {
	case config.BackendDocker:
		img := os.Getenv("TRI_DOCKER_IMAGE")
		if img == "" {
			return nil, errors.New("TRI_DOCKER_IMAGE is required for TRI_BACKEND=docker (e.g. ot-actor:dev)")
		}
		var extraEnv []string
		if e := os.Getenv("TRI_DOCKER_ENV"); e != "" {
			for _, kv := range strings.Split(e, ",") {
				if kv = strings.TrimSpace(kv); kv != "" {
					extraEnv = append(extraEnv, kv)
				}
			}
		}
		return fakedocker.New(cfg.ActorPrefix, img, fmt.Sprint(cfg.ActorPort), cfg.ActorAPIKey, extraEnv), nil
	case config.BackendSubstrate:
		return substrate.NewBackend(logFromConfig(cfg), cfg)
	default:
		return nil, fmt.Errorf("unknown backend %q", cfg.Backend)
	}
}

// logFromConfig produces the backend-level logger (single-file helper).
func logFromConfig(_ *config.Config) *slog.Logger { return newLogger() }

func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
