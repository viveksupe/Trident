// Console "Sandbox actors" panel: list/inspect + delete + suspend actors
// (manual cleanup).
package facade

import (
	"context"

	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/viveksupe/Trident/internal/pool"

	"github.com/viveksupe/Trident/internal/backend"
)

type actorView struct {
	Name       string `json:"name"`
	State      string `json:"state"`
	Template   string `json:"template"`
	Created    string `json:"created,omitempty"`
	LastActive string `json:"last_active,omitempty"`
	SuspendETA string `json:"suspend_eta,omitempty"` // next idle suspend
	PurgeETA   string `json:"purge_eta,omitempty"`   // projected full purge
	Live       bool   `json:"live,omitempty"`        // activity in the last 60s
}

// actorsState lists the backend's actors (name + template).
func (s *Server) actorsState(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	if s.backend == nil {
		writeJSON(w, http.StatusOK, map[string]any{"actors": []actorView{}})
		return
	}
	hs, err := s.backend.ListReady(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, detail{err.Error()})
		return
	}
	lastActives := map[string]pool.IdleInfo{}
	if s.pl != nil {
		lastActives = s.pl.IdleEtas()
	}
	out := make([]actorView, 0, len(hs))
	for _, h := range hs {
		v := actorView{Name: h.Name}
		if a, ok := s.backend.(interface {
			ActorDetails(ctx context.Context, name string) (state, template, created string)
		}); ok {
			v.State, v.Template, v.Created = a.ActorDetails(r.Context(), h.Name)
		}
		if la, ok := lastActives[h.Name]; ok {
			base := la.Time()
			// An ETA in the past means the stored baseline predates the TTL
			// (old rows): fall back to the creation-time cap instead of
			// claiming an immediate purge.
			suspend := base.Add(s.cfg.IdleTTL)
			if suspend.Before(time.Now()) {
				suspend = time.Time{}
			} else if la.Tracked {
				v.SuspendETA = suspend.UTC().Format(time.RFC3339)
			}
			v.LastActive = base.UTC().Format(time.RFC3339)
			purge := base.Add(s.cfg.DeleteIdleTTL)
			if v.Created != "" {
				if created, err := time.Parse(time.RFC3339, v.Created); err == nil {
					if cap := created.Add(s.cfg.MaxAge); cap.Before(purge) {
						purge = cap
					}
				}
			}
			if purge.Before(time.Now()) && v.Created != "" {
				if created, err := time.Parse(time.RFC3339, v.Created); err == nil {
					purge = created.Add(s.cfg.MaxAge)
				}
			}
			if !purge.Before(time.Now()) {
				v.PurgeETA = purge.UTC().Format(time.RFC3339)
			}
			v.Live = time.Since(base) < time.Minute
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"actors": out})
}

// managedActor reports whether name matches this shim's prefix (console
// delete/suspend must not touch actors in the atespace that other tooling
// owns).
func (s *Server) managedActor(name string) bool {
	return strings.HasPrefix(name, s.cfg.ActorPrefix)
}

// actorsDelete destroys (or suspends) one actor by name.
func (s *Server) actorsDelete(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	var body struct {
		Name   string `json:"name"`
		Action string `json:"action"` // delete | suspend | internet
		TTL    string `json:"ttl"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, detail{"name is required"})
		return
	}
	body.Action = orDefault(body.Action, "delete")
	if !s.managedActor(body.Name) {
		writeJSON(w, http.StatusBadRequest, detail{"actor is not managed by this shim (" + s.cfg.ActorPrefix + "* names only)"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	h := &backend.Handle{Name: body.Name}
	var err error
	switch body.Action {
	case "suspend":
		err = s.backend.Suspend(ctx, h)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]string{"status": "suspended"})
			return
		}
	case "internet":
		if s.egress == nil {
			writeJSON(w, http.StatusBadRequest, detail{"egress flow disabled"})
			return
		}
		ttl, terr := parseTTL(body.TTL, true)
		if terr != nil {
			writeJSON(w, http.StatusBadRequest, detail{"bad ttl: " + terr.Error()})
			return
		}
		if terr = s.egress.GrantFullInternet(ctx, s.cfg.Atespace, body.Name, ttl); terr != nil {
			writeJSON(w, http.StatusInternalServerError, detail{terr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "full internet granted"})
		return
	case "delete":
		err = s.backend.Delete(ctx, h) // also drops its egress rules implicitly
	default:
		writeJSON(w, http.StatusBadRequest, detail{"action must be delete|suspend|internet"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, detail{err.Error()})
		return
	}
	if body.Action == "delete" {
		if s.pl != nil {
			s.pl.ForgetByActorName(body.Name)
		}
		// ForgetByActorName only purges pool map slots + the session row — it
		// fires no OnActorDeleted hook — so the per-actor proxy caches must
		// go here too, or every console-deleted actor pins its Transport,
		// dialer and idle conns (R3).
		s.evictActor(body.Name)
		if s.egress != nil {
			_ = s.egress.PurgeActor(ctx, body.Name)
		}
	}
	// substrate releases the actor's snapshots and durable volume on delete
	// (the actor is the sole owner of both); the egress policy is nested
	// under the actor and goes with it.
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted (state + snapshots purged)"})
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
