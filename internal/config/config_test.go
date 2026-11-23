package config

import (
	"strings"
	"testing"
	"time"
)

// clearEnv blanks every TRI_*/OTS_* variable Load reads. Each table case then
// sets only the vars it is about, so an ambient developer or CI environment
// (a stray OTS_API_KEY, TRI_ACTOR_PREFIX, ...) can never leak into a case.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, env := range []string{
		// TRI_* names Load reads.
		"TRI_LISTEN_ADDR", "TRI_API_KEY", "TRI_ACTOR_API_KEY", "TRI_CONSOLE_TOKEN",
		"TRI_EGRESS_CALLBACK", "TRI_BACKEND", "TRI_STATE_DB", "TRI_ACTOR_PREFIX",
		"TRI_ATESPACE", "TRI_TEMPLATE_REF", "TRI_API_NAMESPACE", "TRI_CLIENT_SA",
		"TRI_ROUTE_NAMESPACE", "TRI_ROUTE_SA", "TRI_DIAL", "TRI_ACTOR_PORT",
		"TRI_IDLE_TTL", "TRI_DELETE_IDLE_TTL", "TRI_MAX_AGE",
		"TRI_SUSPEND_DURABILITY", "TRI_EGRESS_HOSTS", "TRI_FEATURES_JSON",
		// OTS_* legacy aliases.
		"OTS_LISTEN_ADDR", "OTS_API_KEY", "OTS_ACTOR_API_KEY", "OTS_CONSOLE_TOKEN",
		"OTS_BACKEND", "OTS_STATE_DB", "OTS_ACTOR_PREFIX", "OTS_ATESPACE",
		"OTS_TEMPLATE_REF", "OTS_API_NAMESPACE", "OTS_EGRESS_CALLBACK",
		"OTS_IDLE_TTL", "OTS_DELETE_IDLE_TTL", "OTS_MAX_AGE",
		"OTS_SUSPEND_DURABILITY", "OTS_EGRESS_HOSTS", "OTS_FEATURES_JSON",
	} {
		t.Setenv(env, "")
	}
}

func TestLoadLegacyAliasChain(t *testing.T) {
	tests := []struct {
		name  string
		env   map[string]string
		check func(t *testing.T, c *Config)
	}{
		{
			// All four secrets/callback via TRI_* names only.
			name: "TRI only",
			env: map[string]string{
				"TRI_API_KEY":         "front-tri",
				"TRI_ACTOR_API_KEY":   "actor-tri",
				"TRI_CONSOLE_TOKEN":   "console-tri",
				"TRI_EGRESS_CALLBACK": "cb.example:8443",
			},
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "front-tri" {
					t.Errorf("APIKey = %q, want front-tri", c.APIKey)
				}
				if c.ActorAPIKey != "actor-tri" {
					t.Errorf("ActorAPIKey = %q, want actor-tri", c.ActorAPIKey)
				}
				if c.ConsoleToken != "console-tri" {
					t.Errorf("ConsoleToken = %q, want console-tri", c.ConsoleToken)
				}
				if c.EgressCallback != "cb.example:8443" || c.CallbackHost != "cb.example" || c.CallbackPort != "8443" {
					t.Errorf("callback = %q/%q:%q, want cb.example:8443", c.EgressCallback, c.CallbackHost, c.CallbackPort)
				}
			},
		},
		{
			// The pre-fix code seeded these from OTS_* and then let empty
			// TRI_* getenv wipe them: this case used to die with
			// "TRI_API_KEY is required" (and silently disabled the egress
			// flow / collapsed the actor key).
			name: "OTS only",
			env: map[string]string{
				"OTS_API_KEY":         "front-ots",
				"OTS_ACTOR_API_KEY":   "actor-ots",
				"OTS_CONSOLE_TOKEN":   "console-ots",
				"OTS_EGRESS_CALLBACK": "cb-ots.example:9443",
			},
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "front-ots" {
					t.Errorf("APIKey = %q, want front-ots (OTS seed must survive)", c.APIKey)
				}
				if c.ActorAPIKey != "actor-ots" {
					t.Errorf("ActorAPIKey = %q, want actor-ots (OTS seed must survive)", c.ActorAPIKey)
				}
				if c.ConsoleToken != "console-ots" {
					t.Errorf("ConsoleToken = %q, want console-ots (OTS seed must survive)", c.ConsoleToken)
				}
				if c.EgressCallback != "cb-ots.example:9443" || c.CallbackHost != "cb-ots.example" || c.CallbackPort != "9443" {
					t.Errorf("callback = %q/%q:%q, want cb-ots.example:9443 (OTS seed must survive)",
						c.EgressCallback, c.CallbackHost, c.CallbackPort)
				}
			},
		},
		{
			// TRI_* beats OTS_* whenever both are set — the legacy name may
			// never shadow the current one.
			name: "TRI overrides OTS", env: map[string]string{
				"TRI_API_KEY":         "front-tri",
				"OTS_API_KEY":         "front-ots",
				"TRI_ACTOR_API_KEY":   "actor-tri",
				"OTS_ACTOR_API_KEY":   "actor-ots",
				"TRI_EGRESS_CALLBACK": "cb-tri.example:8443",
				"OTS_EGRESS_CALLBACK": "cb-ots.example:8443",
				"OTS_CONSOLE_TOKEN":   "console-ots", // only OTS set: seed wins
			},
			check: func(t *testing.T, c *Config) {
				if c.APIKey != "front-tri" {
					t.Errorf("APIKey = %q, want front-tri (TRI must override OTS)", c.APIKey)
				}
				if c.ActorAPIKey != "actor-tri" {
					t.Errorf("ActorAPIKey = %q, want actor-tri (TRI must override OTS)", c.ActorAPIKey)
				}
				if c.EgressCallback != "cb-tri.example:8443" {
					t.Errorf("EgressCallback = %q, want cb-tri.example:8443 (TRI must override OTS)", c.EgressCallback)
				}
				if c.ConsoleToken != "console-ots" {
					t.Errorf("ConsoleToken = %q, want console-ots (unset TRI keeps the OTS seed)", c.ConsoleToken)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			c, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			tc.check(t, c)
		})
	}
}

// validConfig returns a Config that satisfies every check except the one a
// test deliberately varies.
func validConfig() *Config {
	return &Config{
		APIKey:            "front-key",
		ActorAPIKey:       "actor-key",
		Backend:           BackendDocker,
		ActorPrefix:       "ot-",
		TemplateRef:       "ots-webui/open-terminal",
		ActorPort:         8000,
		IdleTTL:           time.Minute,
		DeleteIdleTTL:     time.Hour,
		MaxAge:            24 * time.Hour,
		SuspendDurability: "async",
		Dial:              DialInCluster,
	}
}

// The front-key fallback plus unconditional distinctness: a config that sets
// only the front key (TRI_* or OTS_*) must fail startup with exactly one
// clear validation error pointing at TRI_ACTOR_API_KEY — not with the
// generic "empty after defaults" message (which would mean the fallback
// never derived the key) and not with the legacy "TRI_API_KEY is required"
// wipe symptom.
func TestLoadFrontKeyWithoutActorKeyFailsLoud(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
	}{
		{"TRI_API_KEY only", map[string]string{"TRI_API_KEY": "front-only"}},
		{"OTS_API_KEY only", map[string]string{"OTS_API_KEY": "front-only"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil {
				t.Fatal("a front key with no distinct actor key must fail startup")
			}
			if !strings.Contains(err.Error(), "must differ") {
				t.Fatalf("want the post-merge distinctness error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "TRI_ACTOR_API_KEY") {
				t.Fatalf("error must tell the operator to set TRI_ACTOR_API_KEY: %v", err)
			}
		})
	}
}

// Equal actor/front keys are rejected on BOTH backends and regardless of the
// egress flow. Before this finding docker and egress-off configs passed
// validation with one shared key.
func TestValidateActorKeyDistinctUnconditionally(t *testing.T) {
	for _, backend := range []string{BackendDocker, BackendSubstrate} {
		for _, callback := range []string{"", "cb.example:8443"} {
			name := backend + "/egress-off"
			if callback != "" {
				name = backend + "/egress-on"
			}
			t.Run(name, func(t *testing.T) {
				c := validConfig()
				c.Backend = backend
				c.EgressCallback = callback
				c.ActorAPIKey = c.APIKey // the collapse S1 forbids
				if callback != "" {
					c.ConsoleToken = "human-only-secret" // keep the gated checks happy
				}
				err := c.Validate()
				if err == nil {
					t.Fatalf("equal actor/front keys must be rejected (backend=%s egress=%q)", backend, callback)
				}
				if !strings.Contains(err.Error(), "TRI_ACTOR_API_KEY must differ") {
					t.Fatalf("want the actor-key distinctness error, got: %v", err)
				}
			})
		}
		t.Run(backend+"/distinct-ok", func(t *testing.T) {
			c := validConfig()
			c.Backend = backend
			if err := c.Validate(); err != nil {
				t.Fatalf("distinct keys must validate: %v", err)
			}
		})
	}
}

// The console-token checks keep their pre-existing shape: gated on
// TRI_EGRESS_CALLBACK, compared only against TRI_API_KEY, and checked
// before the (now unconditional) actor-key distinctness error.
func TestValidateConsoleTokenGating(t *testing.T) {
	t.Run("egress unset: no console requirements", func(t *testing.T) {
		c := validConfig()
		c.ConsoleToken = ""
		if err := c.Validate(); err != nil {
			t.Fatalf("console token must not be required without the egress flow: %v", err)
		}
		c.ConsoleToken = c.APIKey
		if err := c.Validate(); err != nil {
			t.Fatalf("console token may equal the front key without the egress flow: %v", err)
		}
	})
	t.Run("egress set: token required", func(t *testing.T) {
		c := validConfig()
		c.EgressCallback = "cb.example:8443"
		c.ConsoleToken = ""
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "TRI_CONSOLE_TOKEN") {
			t.Fatalf("want TRI_CONSOLE_TOKEN required error, got: %v", err)
		}
	})
	t.Run("egress set: token must differ from front key", func(t *testing.T) {
		c := validConfig()
		c.EgressCallback = "cb.example:8443"
		c.ConsoleToken = c.APIKey
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "TRI_CONSOLE_TOKEN") {
			t.Fatalf("want TRI_CONSOLE_TOKEN distinctness error, got: %v", err)
		}
	})
	t.Run("egress set: console checked before actor key", func(t *testing.T) {
		c := validConfig()
		c.EgressCallback = "cb.example:8443"
		c.ConsoleToken = ""
		c.ActorAPIKey = c.APIKey
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "TRI_CONSOLE_TOKEN") {
			t.Fatalf("console error must surface first, got: %v", err)
		}
	})
	t.Run("egress set: fully distinct passes", func(t *testing.T) {
		c := validConfig()
		c.EgressCallback = "cb.example:8443"
		c.ConsoleToken = "human-only-secret"
		if err := c.Validate(); err != nil {
			t.Fatalf("distinct console token must validate: %v", err)
		}
	})
}
