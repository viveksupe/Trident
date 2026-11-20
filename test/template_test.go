package test

import (
	"os"
	"testing"
	"time"

	"github.com/viveksupe/Trident/internal/backend/substrate"
	"github.com/viveksupe/Trident/internal/config"
)

func TestRenderedActorTemplateStrictParses(t *testing.T) {
	cfg := &config.Config{
		APIKey: "tpl-key", ActorAPIKey: "tpl-key",
		Atespace: "ots-webui", TemplateRef: "ots-webui/open-terminal", ActorPort: 8000,
		Features: config.DefaultFeatures(), EgressHosts: config.DefaultEgressHosts(),
	}
	t.Setenv("ANTS", "")
	os.Unsetenv("ANTHROPIC_API_KEY")
	rendered := substrate.RenderTemplateForTest(cfg, "ghcr.io/example/ot-actor@sha256:abc")
	tmpl, err := substrate.ActorTemplateFromManifest([]byte(rendered))
	if err != nil {
		t.Fatalf("strict protojson parse failed: %v", err)
	}
	if tmpl.GetMetadata().GetAtespace() != "ots-webui" || tmpl.GetMetadata().GetName() != "open-terminal" {
		t.Fatalf("bad metadata: %+v", tmpl.GetMetadata())
	}
	c := tmpl.GetContainers()
	if len(c) != 1 || c[0].GetImage() != "ghcr.io/example/ot-actor@sha256:abc" {
		t.Fatalf("bad containers: %+v", c)
	}
	probe := c[0].GetWakeupProbe().GetHttpGet()
	if probe.GetPath() != "/health" || probe.GetPort() != 8000 {
		t.Fatalf("bad wakeup probe: %+v", probe)
	}
	env := map[string]string{}
	for _, e := range c[0].GetEnv() {
		env[e.GetName()] = e.GetValue()
	}
	if env["OPEN_TERMINAL_API_KEY"] != "tpl-key" || env["ENABLE_BROWSER"] != "false" || env["ENABLE_TERMINAL"] != "true" {
		t.Fatalf("bad env: %v", env)
	}
	if tmpl.GetSnapshotConfig().GetPreferredFidelity() != substrate.MemoryFidelity() {
		t.Fatalf("bad snapshot fidelity: %v", tmpl.GetSnapshotConfig())
	}
	foundDurable := false
	for _, v := range tmpl.GetVolumes() {
		if v.GetDurableDir() != nil {
			foundDurable = true
		}
	}
	if !foundDurable {
		t.Fatalf("no durable_dir volume")
	}
	if n := tmpl.GetResources().GetLimits().GetCpuMillicores(); n != 1000 {
		t.Fatalf("bad cpu limit (want 1000): %d", n)
	}
	if tmpl.GetWorkerSelector().GetMatchLabels()["workload"] != "ot-terminal" {
		t.Fatalf("bad worker selector: %v", tmpl.GetWorkerSelector())
	}
	_ = time.Second
}
