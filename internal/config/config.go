// Package config loads trident configuration from environment variables and flags.
package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Backend kinds.
const (
	BackendSubstrate = "substrate"
	BackendDocker    = "docker"
)

// DialMode selects how the data plane reaches actors on the substrate side.
const (
	DialInCluster   = "in-cluster"
	DialPortForward = "portforward"
)

// Config is the full runtime configuration. Every value has an env var (TRI_*),
// and most have a flag override registered in cmd/trident.
type Config struct {
	ListenAddr   string // TRI_LISTEN_ADDR
	APIKey       string // TRI_API_KEY  (front-side key; REQUIRED)
	ActorAPIKey  string // TRI_ACTOR_API_KEY (falls back to APIKey, which Validate rejects — a separate secret is required)
	ConsoleToken string // TRI_CONSOLE_TOKEN (REQUIRED when the egress flow is on; must differ from TRI_API_KEY)

	// EgressCallback, when set ("host" or "host:port", e.g.
	// "trident-callback.ot-workerpool.svc:8080"), is the one cleartext-HTTP
	// host pre-approved in every actor's base egress policy so actors can
	// submit egress-allowlist requests and fetch the helper script. Empty
	// disables the request flow.
	EgressCallback string // TRI_EGRESS_CALLBACK
	CallbackHost   string // parsed once in Load
	CallbackPort   string

	Backend        string // TRI_BACKEND: substrate | docker
	StateDB        string // TRI_STATE_DB
	ActorPrefix    string // TRI_ACTOR_PREFIX
	Atespace       string // TRI_ATESPACE
	TemplateRef    string // TRI_TEMPLATE_REF "atespace/name"
	APINamespace   string // TRI_API_NAMESPACE
	ClientSA       string // TRI_CLIENT_SA
	RouteNamespace string // TRI_ROUTE_NAMESPACE
	RouteSA        string // TRI_ROUTE_SA
	Dial           string // TRI_DIAL
	ActorPort      int    // TRI_ACTOR_PORT
	IdleTTL        time.Duration
	DeleteIdleTTL  time.Duration // idle before full delete (frees durable volume)
	MaxAge         time.Duration

	// Actor-creation caps (R3): a new create past either cap fails with
	// pool.ErrActorCapReached, which the facade serves as 429 with a static
	// detail. "Live" counts every actor whose sandbox exists and is not yet
	// fully deleted — ready, suspended-not-deleted and mid-create alike;
	// existing actors that can only resume are never treated as new
	// creates. 0 disables a cap (unlimited). See pool.Pool.checkCapLocked.
	MaxActors         int    // TRI_MAX_ACTORS: global cap on simultaneously live actors
	MaxActorsPerUser  int    // TRI_MAX_ACTORS_PER_USER: same cap per X-User-Id identity
	SuspendDurability string // TRI_SUSPEND_DURABILITY: async | sync
	EgressHosts       []string
	Features          map[string]bool // TRI_FEATURES_JSON
}

// DefaultFeatures matches the v1 scope: core features on, browser/desktop off.
func DefaultFeatures() map[string]bool {
	return map[string]bool{
		"terminal":  true,
		"notebooks": true,
		"system":    true,
		"git":       true,
		"events":    true,
		"agents":    true,
		"browser":   false,
		"desktop":   false,
	}
}

func DefaultEgressHosts() []string {
	return []string{
		"api.anthropic.com",
		"api.openai.com",
		"sentry.io",
		"pypi.org",
		"files.pythonhosted.org",
		"registry.npmjs.org",
	}
}

// Load reads configuration from the environment. Order: struct defaults,
// then legacy OTS_* aliases (only for names the TRI_* chain leaves below
// them — the chain keeps the aliased value as its fallback), then TRI_* env.
// ActorAPIKey is derived last, after every alias has had its say.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:     "127.0.0.1:8080",
		Backend:        BackendDocker,
		StateDB:        "sessionmap.db",
		ActorPrefix:    "ot-",
		Atespace:       "ots-webui",
		TemplateRef:    "ots-webui/open-terminal",
		APINamespace:   "ate-system",
		ClientSA:       "ate-client",
		RouteNamespace: "ate-system",
		RouteSA:        "atenet-client",
		Dial:           DialInCluster,
		ActorPort:      8000,
		IdleTTL:        10 * time.Minute,
		DeleteIdleTTL:  48 * time.Hour,
		MaxAge:         168 * time.Hour,
		// Header-pair floods (R3): each distinct route key mints its own
		// 500m/768Mi sandbox, so production ships bounded by default.
		// 256 ≈ system-wide ceiling; 32 ≈ no legitimate human chat load.
		// Export 0 explicitly to go unlimited.
		MaxActors:         256,
		MaxActorsPerUser:  32,
		SuspendDurability: "async",
		Features:          DefaultFeatures(),
		EgressHosts:       DefaultEgressHosts(),
	}
	// Legacy aliases seed the values first (only reaching fields the TRI_*
	// reads below don't override); OTS_EGRESS_HOSTS / OTS_FEATURES_JSON
	// REPLACE the defaults rather than merging into them.
	applyLegacyAliases(c)

	c.ListenAddr = envOr("TRI_LISTEN_ADDR", c.ListenAddr)
	c.Backend = envOr("TRI_BACKEND", c.Backend)
	c.StateDB = envOr("TRI_STATE_DB", c.StateDB)
	c.ActorPrefix = envOr("TRI_ACTOR_PREFIX", c.ActorPrefix)
	c.Atespace = envOr("TRI_ATESPACE", c.Atespace)
	c.TemplateRef = envOr("TRI_TEMPLATE_REF", c.TemplateRef)
	c.APINamespace = envOr("TRI_API_NAMESPACE", c.APINamespace)
	c.ClientSA = envOr("TRI_CLIENT_SA", c.ClientSA)
	c.RouteNamespace = envOr("TRI_ROUTE_NAMESPACE", c.RouteNamespace)
	c.RouteSA = envOr("TRI_ROUTE_SA", c.RouteSA)
	c.Dial = envOr("TRI_DIAL", c.Dial)
	c.SuspendDurability = envOr("TRI_SUSPEND_DURABILITY", c.SuspendDurability)

	// The three secrets ride the same envOr(TRI_X, seeded) chain as every
	// other field: TRI_* wins when set, but an *unset* TRI_* must no longer
	// wipe the OTS_* value applyLegacyAliases seeded above — the documented
	// legacy migration path has to work with OTS_* names alone. ActorAPIKey
	// keeps its own seed too, so OTS_ACTOR_API_KEY survives.
	c.APIKey = envOr("TRI_API_KEY", c.APIKey)
	c.ConsoleToken = envOr("TRI_CONSOLE_TOKEN", c.ConsoleToken)
	c.EgressCallback = envOr("TRI_EGRESS_CALLBACK", c.EgressCallback)
	c.ActorAPIKey = envOr("TRI_ACTOR_API_KEY", c.ActorAPIKey)
	// The front-key fallback derives only AFTER the alias merge: OTS_API_KEY
	// alone must yield ActorAPIKey == APIKey, not an empty key. Whether that
	// fallback is acceptable to Validate is decided there, once every alias
	// and env read has had its say.
	if c.ActorAPIKey == "" {
		c.ActorAPIKey = c.APIKey
	}
	if c.EgressCallback != "" {
		c.CallbackHost, c.CallbackPort = splitCallback(c.EgressCallback)
	}

	var err error
	if c.ActorPort, err = envInt("TRI_ACTOR_PORT", c.ActorPort); err != nil {
		return nil, err
	}
	if c.IdleTTL, err = envDur("TRI_IDLE_TTL", c.IdleTTL); err != nil {
		return nil, err
	}
	if c.DeleteIdleTTL, err = envDur("TRI_DELETE_IDLE_TTL", c.DeleteIdleTTL); err != nil {
		return nil, err
	}
	if c.MaxAge, err = envDur("TRI_MAX_AGE", c.MaxAge); err != nil {
		return nil, err
	}
	if c.MaxActors, err = envInt("TRI_MAX_ACTORS", c.MaxActors); err != nil {
		return nil, err
	}
	if c.MaxActorsPerUser, err = envInt("TRI_MAX_ACTORS_PER_USER", c.MaxActorsPerUser); err != nil {
		return nil, err
	}
	// TRI_EGRESS_HOSTS REPLACES the default allowlist (an operator may need
	// to drop default hosts like sentry.io or npm).
	if v := os.Getenv("TRI_EGRESS_HOSTS"); v != "" {
		c.EgressHosts = hostsFrom(v)
	}
	if v := os.Getenv("TRI_FEATURES_JSON"); v != "" {
		feats := DefaultFeatures()
		if err := json.Unmarshal([]byte(v), &feats); err != nil {
			return nil, fmt.Errorf("TRI_FEATURES_JSON: %w", err)
		}
		c.Features = feats
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// hostsFrom splits a comma-separated host list.
func hostsFrom(v string) []string {
	var out []string
	for _, h := range strings.Split(v, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// splitCallback splits "host:port" (a bare host becomes port 8443).
func splitCallback(cb string) (host, port string) {
	if i := strings.LastIndex(cb, ":"); i >= 0 {
		return cb[:i], strings.TrimPrefix(cb[i+1:], ":")
	}
	return cb, "8443"
}

// legacyEnvAliases maps pre-rename OTS_* variables onto their TRI_* fields
// (used only when the TRI_* name is unset, so existing env files and
// container definitions keep working).
var legacyEnvAliases = map[string]string{
	"ListenAddr":        "OTS_LISTEN_ADDR",
	"APIKey":            "OTS_API_KEY",
	"ActorAPIKey":       "OTS_ACTOR_API_KEY",
	"ConsoleToken":      "OTS_CONSOLE_TOKEN",
	"Backend":           "OTS_BACKEND",
	"StateDB":           "OTS_STATE_DB",
	"ActorPrefix":       "OTS_ACTOR_PREFIX",
	"Atespace":          "OTS_ATESPACE",
	"TemplateRef":       "OTS_TEMPLATE_REF",
	"APINamespace":      "OTS_API_NAMESPACE",
	"EgressCallback":    "OTS_EGRESS_CALLBACK",
	"IdleTTL":           "OTS_IDLE_TTL",
	"DeleteIdleTTL":     "OTS_DELETE_IDLE_TTL",
	"MaxAge":            "OTS_MAX_AGE",
	"SuspendDurability": "OTS_SUSPEND_DURABILITY",
	"EgressHosts":       "OTS_EGRESS_HOSTS",
	"Features":          "OTS_FEATURES_JSON",
}

// applyLegacyAliases seeds unset TRI_* values from their pre-rename OTS_*
// names. It runs before the TRI_* env chain reads, which override aliased
// values — a stale OTS_API_KEY can no longer shadow TRI_API_KEY.
func applyLegacyAliases(c *Config) {
	for field, env := range legacyEnvAliases {
		v, ok := os.LookupEnv(env)
		if !ok || v == "" {
			continue
		}
		switch field {
		case "ListenAddr", "APIKey", "ActorAPIKey", "ConsoleToken", "Backend",
			"StateDB", "ActorPrefix", "Atespace", "TemplateRef",
			"APINamespace", "EgressCallback", "SuspendDurability":
			setStringField(c, field, v)
		case "IdleTTL", "DeleteIdleTTL", "MaxAge":
			if d, err := time.ParseDuration(v); err == nil {
				switch field {
				case "IdleTTL":
					c.IdleTTL = d
				case "DeleteIdleTTL":
					c.DeleteIdleTTL = d
				case "MaxAge":
					c.MaxAge = d
				}
			}
		case "EgressHosts":
			c.EgressHosts = hostsFrom(v)
		case "Features":
			var m map[string]bool
			if json.Unmarshal([]byte(v), &m) == nil {
				c.Features = m
			}
		}
	}
}

func setStringField(c *Config, field, v string) {
	switch field {
	case "ListenAddr":
		c.ListenAddr = v
	case "APIKey":
		c.APIKey = v
	case "ActorAPIKey":
		c.ActorAPIKey = v
	case "ConsoleToken":
		c.ConsoleToken = v
	case "Backend":
		c.Backend = v
	case "StateDB":
		c.StateDB = v
	case "ActorPrefix":
		c.ActorPrefix = v
	case "Atespace":
		c.Atespace = v
	case "TemplateRef":
		c.TemplateRef = v
	case "APINamespace":
		c.APINamespace = v
	case "EgressCallback":
		c.EgressCallback = v
	case "SuspendDurability":
		c.SuspendDurability = v
	}
}

// Validate enforces invariants so misconfiguration fails fast at startup.
func (c *Config) Validate() error {
	if c.APIKey == "" {
		return errors.New("TRI_API_KEY is required (the front-side API key Open WebUI uses)")
	}
	if c.ActorAPIKey == "" {
		return errors.New("TRI_ACTOR_API_KEY is empty after defaults (agents would render with no key)")
	}
	if c.EgressCallback != "" {
		// The egress flow must stay human-only: sandboxes are rendered with
		// the actor key (OPEN_TERMINAL_API_KEY) and are let through the
		// callback rule to this process, so the console token MUST be its
		// own secret — separate from the front-side key, which every Open
		// WebUI component presents — or anything holding that key could
		// self-approve egress.
		if c.ConsoleToken == "" {
			return errors.New("TRI_CONSOLE_TOKEN is required when TRI_EGRESS_CALLBACK is set (must be distinct from TRI_API_KEY — agents know the API key)")
		}
		if c.ConsoleToken == c.APIKey {
			return errors.New("TRI_CONSOLE_TOKEN must differ from TRI_API_KEY: agents hold the API key and could self-approve egress")
		}
	}
	// Actor-key distinctness is enforced UNCONDITIONALLY — no egress gate,
	// no backend condition. The sandbox environment (OPEN_TERMINAL_API_KEY)
	// is rendered with the actor key on both backends, so distinct keys are
	// what keep the front-side credential (the one Open WebUI presents to the
	// facade) out of every sandbox, and what makes the facade's
	// Authorization-header and WS auth-frame translation — which only
	// engages when the keys differ — protect actors at all. Until per-actor
	// key injection lands (a distinct key per actor instead of one org-wide
	// secret), separation is enforced at this key layer: fail startup loudly
	// rather than silently collapse the two keys.
	if c.ActorAPIKey == c.APIKey {
		return errors.New("TRI_ACTOR_API_KEY must differ from TRI_API_KEY: an equal key puts the front-side credential in every sandbox, letting in-sandbox agents authenticate to the facade as any user (set TRI_ACTOR_API_KEY to a separate secret and rebuild the actor template)")
	}
	switch c.Backend {
	case BackendSubstrate, BackendDocker:
	default:
		return fmt.Errorf("TRI_BACKEND must be \"substrate\" or \"docker\", got %q", c.Backend)
	}
	switch c.Dial {
	case DialInCluster, DialPortForward:
	default:
		return fmt.Errorf("TRI_DIAL must be \"in-cluster\" or \"portforward\", got %q", c.Dial)
	}
	switch c.SuspendDurability {
	case "async", "sync":
	default:
		return fmt.Errorf("TRI_SUSPEND_DURABILITY must be \"async\" or \"sync\"")
	}
	if c.ActorPort <= 0 || c.ActorPort > 65535 {
		return fmt.Errorf("TRI_ACTOR_PORT out of range: %d", c.ActorPort)
	}
	if c.IdleTTL <= 0 || c.DeleteIdleTTL <= 0 || c.MaxAge <= 0 {
		return errors.New("TRI_IDLE_TTL, TRI_DELETE_IDLE_TTL and TRI_MAX_AGE must be positive")
	}
	if c.MaxActors < 0 || c.MaxActorsPerUser < 0 {
		return errors.New("TRI_MAX_ACTORS and TRI_MAX_ACTORS_PER_USER must be >= 0 (0 disables the cap; a negative value would reject every create)")
	}
	if !validActorPrefix(c.ActorPrefix) {
		return fmt.Errorf("TRI_ACTOR_PREFIX %q must be 2-15 lowercase-alphanumeric characters ending in '-'", c.ActorPrefix)
	}
	parts := strings.SplitN(c.TemplateRef, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("TRI_TEMPLATE_REF must be \"<atespace>/<name>\", got %q", c.TemplateRef)
	}
	return nil
}

// TemplateAtespace / TemplateName split TemplateRef.
func (c *Config) TemplateAtespace() string {
	return strings.SplitN(c.TemplateRef, "/", 2)[0]
}
func (c *Config) TemplateName() string {
	return strings.SplitN(c.TemplateRef, "/", 2)[1]
}

// KeyMatches reports whether the presented bearer token matches the front-side key
// in constant time.
func (c *Config) KeyMatches(presented string) bool {
	if presented == "" {
		return false
	}
	return hashEquals(presented, c.APIKey)
}

// KeyMatchesConsole reports whether the presented token matches the
// human-only egress console token (constant time on hashed values).
func (c *Config) KeyMatchesConsole(presented string) bool {
	if presented == "" || c.ConsoleToken == "" {
		return false
	}
	return hashEquals(presented, c.ConsoleToken)
}

// ActorKeyRewrite distinguishes the (optional) token rewrite mode.
func (c *Config) KeyRewriteNeeded() bool { return c.ActorAPIKey != c.APIKey }

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			return 0, fmt.Errorf("%s: %w", key, err)
		}
		return n, nil
	}
	return def, nil
}

func envDur(key string, def time.Duration) (time.Duration, error) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", key, err)
		}
		return d, nil
	}
	return def, nil
}

// validActorPrefix enforces TRI_ACTOR_PREFIX's documented contract:
// non-empty, 2..15 characters, all lowercase alphanumeric plus '-', ending
// in '-', with a lowercase-alphanumeric first rune — so it can actually
// front a name (rejects "", "-" and "-x", which are DNS-unsafe or ambiguous
// as a prefix). The 15-char cap is the budget model.ActorName assumes:
// prefix (<=15) + "u" + 8-hex user hash + "-" + canonicalSegment's 38-char
// reserve = 63, the maximum DNS-1123 label length; a longer prefix
// silently overflows it and the first actor create fails.
func validActorPrefix(s string) bool {
	if len(s) < 2 || len(s) > 15 {
		return false
	}
	if s[len(s)-1] != '-' {
		return false
	}
	if c := s[0]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
		return false
	}
	return validName(s)
}

func validName(s string) bool {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// hashEquals compares two secrets in constant time over their SHA-256
// digests (crypto/subtle; the digest also hides the key length).
func hashEquals(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}
