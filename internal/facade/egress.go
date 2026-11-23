// Egress approval flow: actor-side callback API (reach-able only through the
// substrate egress gateway via the pre-approved callback host) and the
// human console (Bearer-token, LAN-reachable).
package facade

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/viveksupe/Trident/internal/egress"
)

//go:embed egress_console.html
var egressConsoleHTML string

//go:embed actors_console.html
var actorsConsoleHTML string

// helperScript is served to actors via the callback host (no auth; actors
// reach the shim only over the pre-approved cleartext callback rule).
// writeConsolePage is a method on Server (see below).

// writeConsolePage serves a console page. The console token is NEVER embedded
// in the page (the console API requires it as Bearer/X-Console-Token): the
// human saves it in the token widget once per browser.
func (s *Server) writeConsolePage(w http.ResponseWriter, html string) {
	// Defense in depth: strip any accidental default-token marker.
	page := strings.Replace(html, "/*DEFAULT_TOKEN_INJECT*/\"\"", `""`, 1)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

const helperScript = `#!/bin/sh
# tri-egress-request <hostname> [reason] — ask the human to allow egress.
# usage: curl -s http://OT-SHIM-CALLBACK/_tri/egress/helper.sh | sh -s -- example.com
set -u
host="$1"; [ -n "${2:-}" ] && reason="$2" || reason=""
case "$host" in ""|-h|--help) echo "usage: tri-egress-request <hostname> [reason]" >&2; exit 2;; esac
# The shim renders its own callback address here when it serves this helper;
# an TRI_EGRESS_CALLBACK env var in the actor overrides it.
svc="${TRI_EGRESS_CALLBACK:-%%CB%%}"
actor="$(hostname 2>/dev/null || echo unknown)"
# jq builds the body so every hostile character stays escaped.
if ! body=$(jq -nc --arg actor "$actor" --arg host "$host" --arg reason "$reason" \
      '{actor:$actor,host:$host,reason:$reason}' 2>/dev/null); then
  echo "jq is required by this helper but not available" >&2; exit 1
fi
resp=$(curl -k -sS -X POST "https://$svc/_tri/egress/request" -H "Content-Type: application/json" --data "$body") || exit 1
id=$(printf '%s' "$resp" | jq -r .id 2>/dev/null) || exit 1
[ "$id" != "null" ] && [ -n "$id" ] || { echo "$resp" >&2; exit 1; }
echo "egress request #$id for '$host' submitted — waiting for approval (Ctrl-C cancels this wait only)" >&2
while true; do
  status=$(curl -k -sS "https://$svc/_tri/egress/request/$id?actor=$(printf '%s' "$actor" | od -An -tx1 | tr -d ' \n' | sed 's/../%&/g')" \
    | jq -r .status) || exit 1
  case "$status" in
    approved)  echo "approved — retry your connection now"; exit 0 ;;
    denied)    echo "denied by the human operator" >&2; exit 1 ;;
    timed_out) echo "request expired" >&2; exit 1 ;;
  esac
  sleep 3
done
`

// RegisterEgressActor registers ONLY the actor-facing callback endpoints
// (helper script, request submission, status polling) on mux. The TLS
// callback listener is built from this register alone: actors can reach this
// listener by design (it sits behind the pre-approved callback rule), so the
// human console and the front-side proxy must never be served here. The
// guard makes the register self-contained: both listeners now pick one half
// of the split each, and neither half appears without a live egress flow.
func (s *Server) RegisterEgressActor(mux *http.ServeMux) {
	if s.egress == nil || s.cfg.EgressCallback == "" {
		return
	}
	mux.HandleFunc("GET /_tri/egress/helper.sh", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rendered := strings.ReplaceAll(helperScript, "%%CB%%", s.cfg.EgressCallback)
		_, _ = w.Write([]byte(rendered))
	})
	mux.HandleFunc("POST /_tri/egress/request", s.egressRequest)
	// The actor-side DNS-failure reporter (LD_PRELOAD hook) uses the same
	// payload shape; reason distinguishes the source.
	mux.HandleFunc("POST /_tri/egress/dns-hit", s.egressRequest)
	mux.HandleFunc("GET /_tri/egress/request/{id}", s.egressRequestStatus)
}

// RegisterEgressConsole registers the human console routes (Bearer console
// token; LAN-reachable by design). Part of Handler()'s main listener only —
// never the callback listener.
func (s *Server) RegisterEgressConsole(mux *http.ServeMux) {
	if s.egress == nil || s.cfg.EgressCallback == "" {
		// The console APIs dereference s.egress; without a live flow there
		// is nothing to show or decide.
		return
	}
	// Compat: pre-rename console bookmarks keep working.
	for _, legacy := range []struct{ from, to string }{
		{"/_tri/console/egress", "/_trident/console/egress"},
		{"/_tri/console/actors", "/_trident/console/actors"},
	} {
		mux.HandleFunc("GET "+legacy.from, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, strings.Replace(r.URL.Path, "/_tri/console", "/_trident/console", 1), http.StatusFound)
		})
		to := legacy.to
		page := egressConsoleHTML
		if strings.HasSuffix(to, "actors") {
			page = actorsConsoleHTML
		}
		handlerTo := to
		mux.HandleFunc("GET "+handlerTo, func(w http.ResponseWriter, r *http.Request) {
			s.writeConsolePage(w, page)
		})
	}

	mux.HandleFunc("GET /_trident/console/egress/api/state", s.egressState)
	mux.HandleFunc("POST /_trident/console/egress/api/request/{id}/approve", s.decideHandler(true))
	mux.HandleFunc("POST /_trident/console/egress/api/request/{id}/deny", s.decideHandler(false))
	mux.HandleFunc("POST /_trident/console/egress/api/grant/{id}/revoke", s.egressRevoke)

	// Bulk maintenance.
	mux.HandleFunc("POST /_trident/console/egress/api/grants/revoke-all", s.egressRevokeAll)
	mux.HandleFunc("POST /_trident/console/egress/api/history/clear", s.egressClearHistory)
	// Sandbox actor maintenance (cleanup).

	mux.HandleFunc("GET /_trident/console/actors/api/state", s.actorsState)
	mux.HandleFunc("POST /_trident/console/actors/api/actor", s.actorsDelete)

	// Auto-approve rules (per actor).
	mux.HandleFunc("POST /_trident/console/egress/api/auto", s.egressAutoSet)
	mux.HandleFunc("DELETE /_trident/console/egress/api/auto/{actor}", s.egressAutoClear)
}

// egressRevokeAll closes every live grant.
func (s *Server) egressRevokeAll(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	n, err := s.egress.RevokeAll(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, detail{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"revoked": n})
}

// egressClearHistory drops decided requests and closed grants.
func (s *Server) egressClearHistory(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	revoked, cleared, err := s.egress.ClearHistoryRevokeAll(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, detail{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"cleared": cleared, "revoked": revoked})
}

// egressAutoSet registers or updates a standing auto-approve rule.
func (s *Server) egressAutoSet(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	var body struct {
		Actor string `json:"actor"`
		TTL   string `json:"ttl"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Actor == "" {
		writeJSON(w, http.StatusBadRequest, detail{"actor is required"})
		return
	}
	d, err := parseTTL(body.TTL, true)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, detail{"bad ttl: " + err.Error()})
		return
	}
	ttlSeconds := int64(d / time.Second) // 0 = permanent
	if err := s.egress.SetAuto(body.Actor, ttlSeconds); err != nil {
		writeJSON(w, http.StatusInternalServerError, detail{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "auto-approve set"})
}

// egressAutoClear removes a standing auto-approve rule.
func (s *Server) egressAutoClear(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	if err := s.egress.ClearAuto(r.PathValue("actor")); err != nil {
		writeJSON(w, http.StatusBadRequest, detail{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "auto-approve cleared"})
}

// parseTTL accepts a Go duration plus a "d"-days suffix ("45m", "3h", "7d",
// "1d12h"). Empty returns 0 = permanent.
func parseTTL(s string, zeroOK bool) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" || s == "permanent" {
		return 0, nil
	}
	if i := strings.Index(s, "d"); i > 0 && isAllDigits(s[:i]) {
		days, err := strconv.ParseInt(s[:i], 10, 64)
		if err != nil || days > 365 {
			return 0, fmt.Errorf("bad days in %q", s)
		}
		rest := s[i+1:]
		d, err := time.ParseDuration(rest)
		if rest != "" && err != nil {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(days)*24*time.Hour + d, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, fmt.Errorf("bad duration %q (e.g. 45m, 3h, 7d12h, permanent)", s)
	}
	return d, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// decideHandler returns the approve/deny console handler for a request id.
func (s *Server) decideHandler(approved bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.consoleAuthed(w, r) {
			return
		}
		id, err := pathID(r)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, detail{err.Error()})
			return
		}
		if approved {
			var body struct {
				TTL  string `json:"ttl"`
				Host string `json:"hostname"`
			}
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
				_ = json.NewDecoder(r.Body).Decode(&body) // empty body = permanent
			}
			ttl, perr := parseTTL(body.TTL, true)
			if perr != nil {
				writeJSON(w, http.StatusBadRequest, detail{"bad ttl: " + perr.Error()})
				return
			}
			if err := s.egress.ApproveHost(r.Context(), id, ttl, body.Host); err != nil {
				writeJSON(w, http.StatusBadRequest, detail{err.Error()})
				return
			}
			s.log.Info("egress approved via console", "request", id, "ttl", ttl)
			writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
			return
		}
		if err := s.egress.Deny(id); err != nil {
			writeJSON(w, http.StatusBadRequest, detail{err.Error()})
			return
		}
		s.log.Info("egress denied via console", "request", id)
		writeJSON(w, http.StatusOK, map[string]string{"status": "denied"})
	}
}

func (s *Server) egressRevoke(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	id, err := pathID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, detail{err.Error()})
		return
	}
	if err := s.egress.Revoke(r.Context(), id); err != nil {
		writeJSON(w, http.StatusBadRequest, detail{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// consoleAuthed requires the human-only console token — deliberately NOT the
// front-side API key (agents hold that one; agents must never self-approve).
func (s *Server) consoleAuthed(w http.ResponseWriter, r *http.Request) bool {
	tok := bearerToken(r.Header.Get("Authorization"))
	if tok == "" {
		tok = r.Header.Get("X-Console-Token")
	}
	if tok == "" || !s.cfg.KeyMatchesConsole(tok) {
		writeJSON(w, http.StatusUnauthorized, detail{"console token required"})
		return false
	}
	return true
}

// egressConsole serves the page itself unauthenticated — it's static markup
// with no data; only its API calls (state/approve/deny/revoke) require the
// human console token. A browser that has not saved a token yet gets the
// login form, not a JSON error.
func (s *Server) egressState(w http.ResponseWriter, r *http.Request) {
	if !s.consoleAuthed(w, r) {
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("pending_page"))
	live, _ := strconv.Atoi(q.Get("live_page"))
	hist, _ := strconv.Atoi(q.Get("history_page"))
	per, _ := strconv.Atoi(q.Get("per_page"))
	state, err := s.egress.SnapshotPage(egress.PagedParams{PendingPage: page, LivePage: live, HistoryPage: hist, PerPage: per})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, detail{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

// maxBodyBytes caps every actor-facing request body (a sandboxed agent is
// untrusted input: unbounded reads are a memory DoS at best).
const maxBodyBytes = 32 << 10

// egressRequest is the actor-side entrypoint.
func (s *Server) egressRequest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Actor  string `json:"actor"`
		Host   string `json:"host"`
		Reason string `json:"reason"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, detail{"bad json"})
		return
	}
	if len(body.Actor) > 128 || len(body.Host) > 253 || len(body.Reason) > 512 {
		writeJSON(w, http.StatusBadRequest, detail{"field too long"})
		return
	}
	req, err := s.egress.Submit(r.Context(), body.Actor, body.Host, body.Reason)
	if err != nil {
		if errors.Is(err, egress.ErrTooManyPending) {
			// The global pending cap is a queue-full condition, not a bad
			// request: 429 tells the helper to back off and retry.
			writeJSON(w, http.StatusTooManyRequests, detail{err.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, detail{err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, req)
}

// egressRequestStatus answers the helper's poll. The requesting actor may
// only see its own requests: the ?actor= claim is MANDATORY — request ids
// are sequential int64s, so an optional claim would let anyone who can
// reach this listener enumerate every pending request's status. A missing
// claim is a 400; a WRONG claim reads as 404, so the check itself never
// confirms that an id exists (no enumeration oracle).
func (s *Server) egressRequestStatus(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, detail{err.Error()})
		return
	}
	claim := r.URL.Query().Get("actor")
	if claim == "" {
		writeJSON(w, http.StatusBadRequest, detail{"actor claim is required"})
		return
	}
	req, err := s.egress.GetRequest(id)
	if err != nil || req == nil {
		writeJSON(w, http.StatusNotFound, detail{"unknown request"})
		return
	}
	if claim != req.ActorName {
		writeJSON(w, http.StatusNotFound, detail{"unknown request"})
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func pathID(r *http.Request) (int64, error) {
	return strconv.ParseInt(r.PathValue("id"), 10, 64)
}
