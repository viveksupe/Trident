// Bootstrap: render the embedded ActorTemplate manifest and create it (and
// wait for its golden snapshot) on the substrate control plane. This replaces
// `kubectl ate create actor-template` so users need nothing beyond the shim
// binary and a kubeconfig.
package substrate

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"

	"github.com/viveksupe/Trident/third_party/ateapi"
	"os"
	"strings"
	"time"

	"github.com/viveksupe/Trident/internal/config"
)

//go:embed open-terminal-template.yaml
var templateManifest string

// RunBootstrap creates the ActorTemplate from the embedded manifest rendered
// with image and the shim config (keys, feature flags, resources), then waits
// for the golden snapshot. Idempotent: an existing template is kept.
func RunBootstrap(log *slog.Logger, cfg *config.Config, image string, wait time.Duration) error {
	kubeconfigPath := os.Getenv("KUBECONFIG")
	kcfg, err := kubeConfig(kubeconfigPath, "")
	if err != nil {
		return fmt.Errorf("k8s config: %w", err)
	}
	systemNS := envDefault("ATE_NAMESPACE", cfg.APINamespace)
	client, err := NewAPIClient(context.Background(), kcfg, "", envDefault("TRI_API_TOKEN_FILE", ""), envDefault("TRI_API_SERVICE", "api"), cfg.ClientSA, systemNS)
	if err != nil {
		return err
	}
	defer client.Close()

	manifest := renderTemplate(templateManifest, cfg, image)
	template, err := ActorTemplateFromManifest([]byte(manifest))
	if err != nil {
		return fmt.Errorf("rendered ActorTemplate is invalid: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	log.Info("creating ActorTemplate (idempotent)",
		"atespace", cfg.TemplateAtespace(), "name", cfg.TemplateName(), "image", image)
	if err := CreateActorTemplateAndWait(ctx, client, template, wait); err != nil {
		return err
	}
	log.Info("ActorTemplate ready (golden snapshot built); actors can now be created from it")
	return nil
}

// RenderTemplateForTest exposes the render pipeline for template tests.
func RenderTemplateForTest(cfg *config.Config, image string) string {
	return renderTemplate(templateManifest, cfg, image)
}

// MemoryFidelity re-exports the snapshot enum the template pins.
func MemoryFidelity() ateapi.SnapshotFidelity {
	return ateapi.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY
}

// renderTemplate substitutes ${...} placeholders in the embedded manifest.
func renderTemplate(manifest string, cfg *config.Config, image string) string {
	feature := func(name string) bool {
		v, ok := cfg.Features[name]
		return ok && v
	}
	replacements := [][2]string{
		{"${ATESPACE}", cfg.TemplateAtespace()},
		{"${TEMPLATE_NAME}", cfg.TemplateName()},
		{"${WORKLOAD_IMAGE}", image},
		{"${TRI_API_KEY}", cfg.ActorAPIKey},
		{"${ENABLE_TERMINAL}", on(feature("terminal"))},
		{"${ENABLE_NOTEBOOKS}", on(feature("notebooks"))},
		{"${ENABLE_SYSTEM_PROMPT}", on(feature("system"))},
		{"${ENABLE_BROWSER}", on(feature("browser"))},
		{"${ENABLE_DESKTOP}", on(feature("desktop"))},
		{"${ANTHROPIC_API_KEY}", os.Getenv("ANTHROPIC_API_KEY")},
		{"${OPENAI_API_KEY}", os.Getenv("OPENAI_API_KEY")},
		{"${ACTOR_PORT}", fmt.Sprintf("%d", cfg.ActorPort)},
		{"${CPU_MILLICORES}", envDefault("TRI_CPU_MILLICORES", "2000")},
		{"${MEMORY_BYTES}", envDefault("TRI_MEMORY_BYTES", "4294967296")},
		{"${EGRESS_CALLBACK}", cfg.EgressCallback},
	}
	for _, r := range replacements {
		manifest = strings.ReplaceAll(manifest, r[0], r[1])
	}
	return manifest
}

func on(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
