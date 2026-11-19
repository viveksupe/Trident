// Package config loads trident configuration from environment variables and flags.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	ActorAPIKey  string // TRI_ACTOR_API_KEY (defaults to APIKey)
	ConsoleToken string // TRI_CONSOLE_TOKEN (REQUIRED when the egress flow is on; must differ from TRI_API_KEY)

	// EgressCallback, when set ("host" or "host:port", e.g.
	// "trident-callback.ot-workerpool.svc:8080"), is the one cleartext-HTTP
	// host pre-approved in every actor's base egress policy so actors can
	// submit egress-allowlist requests and fetch the helper script. Empty
	// disables the request flow.
	EgressCallback string // TRI_EGRESS_CALLBACK

	Backend           string // TRI_BACKEND: substrate | docker
	StateDB           string // TRI_STATE_DB
	ActorPrefix       string // TRI_ACTOR_PREFIX
	Atespace          string // TRI_ATESPACE
	TemplateRef       string // TRI_TEMPLATE_REF "atespace/name"
	APINamespace      string // TRI_API_NAMESPACE
	ClientSA          string // TRI_CLIENT_SA
	RouteNamespace    string // TRI_ROUTE_NAMESPACE
	RouteSA           string // TRI_ROUTE_SA
	Dial              string // TRI_DIAL
	ActorPort         int    // TRI_ACTOR_PORT
	IdleTTL           time.Duration
	DeleteIdleTTL     time.Duration // idle before full delete (frees durable volume)
	MaxAge            time.Duration
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

// Load reads configuration from the environment. Callers may mutate fields afterwards.
func Load() (*Config, error) {
	c := &Config{
		ListenAddr:        "127.0.0.1:8080",
		Backend:           BackendDocker,
		StateDB:           "sessionmap.db",
		ActorPrefix:       "ot-",
		Atespace:          "ots-webui",
		TemplateRef:       "ots-webui/open-terminal",
		APINamespace:      "ate-system",
		ClientSA:          "ate-client",
		RouteNamespace:    "ate-system",
		RouteSA:           "atenet-client",
		Dial:              DialInCluster,
		ActorPort:         8000,
		IdleTTL:           10 * time.Minute,
		DeleteIdleTTL:     48 * time.Hour,
		MaxAge:            168 * time.Hour,
		SuspendDurability: "async",
		Features:          DefaultFeatures(),
		EgressHosts:       DefaultEgressHosts(),
	}
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

	c.APIKey = os.Getenv("TRI_API_KEY")
	c.ActorAPIKey = envOr("TRI_ACTOR_API_KEY", c.APIKey)
	c.ConsoleToken = os.Getenv("TRI_CONSOLE_TOKEN")
	c.EgressCallback = os.Getenv("TRI_EGRESS_CALLBACK")

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
	if v := os.Getenv("TRI_EGRESS_HOSTS"); v != "" {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				c.EgressHosts = append(c.EgressHosts, h)
			}
		}
	}
	if v := os.Getenv("TRI_FEATURES_JSON"); v != "" {
		if err := json.Unmarshal([]byte(v), &c.Features); err != nil {
			return nil, fmt.Errorf("TRI_FEATURES_JSON: %w", err)
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate enforces invariants so misconfiguration fails fast at startup.
func (c *Config) Validate() error {
	if c.APIKey == "" {
		return errors.New("TRI_API_KEY is required (the front-side API key Open WebUI uses)")
	}
	if c.EgressCallback != "" {
		// Agents receive the front-side key in their environment (it doubles
		// as OPEN_TERMINAL_API_KEY) and can reach the shim through the
		// callback rule, so the console token MUST be a separate human-only
		// secret — otherwise an in-sandbox agent could self-approve.
		if c.ConsoleToken == "" {
			return errors.New("TRI_CONSOLE_TOKEN is required when TRI_EGRESS_CALLBACK is set (must be distinct from TRI_API_KEY — agents know the API key)")
		}
		if c.ConsoleToken == c.APIKey {
			return errors.New("TRI_CONSOLE_TOKEN must differ from TRI_API_KEY: agents hold the API key and could self-approve egress")
		}
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
	if c.ActorPrefix == "" || !validName(c.ActorPrefix) {
		return fmt.Errorf("TRI_ACTOR_PREFIX %q must be a DNS-1123-safe prefix ending in '-'", c.ActorPrefix)
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
	return constantTimeEquals(presented, c.APIKey)
}

// ConsoleTokenHintOff reports whether the default-token prefill in the
// console UI is disabled (TRI_CONSOLE_SHOW_DEFAULT=false).
func (c *Config) ConsoleTokenHintOff() bool {
	return os.Getenv("TRI_CONSOLE_SHOW_DEFAULT") == "false"
}

// KeyMatchesConsole reports whether the presented token matches the
// human-only egress console token (constant time).
func (c *Config) KeyMatchesConsole(presented string) bool {
	if presented == "" || c.ConsoleToken == "" {
		return false
	}
	return constantTimeEquals(presented, c.ConsoleToken)
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
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
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

func constantTimeEquals(a, b string) bool {
	if len(a) != len(b) {
		// still burn time proportional to len(a) to keep timing flat-ish
		for i := 0; i < len(a); i++ {
			_ = a[i]
		}
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
