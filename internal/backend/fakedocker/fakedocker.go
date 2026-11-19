// Package fakedocker implements the backend.Backend contract over local Docker
// containers: one open-terminal container per route key. It exists so the entire
// facade can be developed and e2e-tested without a substrate cluster
// (plan milestone M0 / demo fallback mode).
package fakedocker

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/viveksupe/Trident/internal/backend"
	"github.com/viveksupe/Trident/internal/model"
)

// Backend manages docker containers named "<prefix><hash8>".
type Backend struct {
	Prefix      string   // container name prefix
	Image       string   // e.g. ot-actor:dev
	ActorPort   string   // the port open-terminal listens on inside the container ("8000")
	ActorAPIKey string   // injected as OPEN_TERMINAL_API_KEY
	Env         []string // extra env K=V passed into the container
}

var _ backend.Backend = (*Backend)(nil)

// New builds a docker backend.
func New(prefix, image, actorPort, actorAPIKey string, env []string) *Backend {
	return &Backend{Prefix: prefix, Image: image, ActorPort: actorPort, ActorAPIKey: actorAPIKey, Env: env}
}

func (b *Backend) containerName(key model.RouteKey) string {
	return b.Prefix + model.Hash8(key.UserID) + "c" + model.Hash8(key.ChatID)
}

type containerInspect struct {
	State struct {
		Running bool   `json:"Running"`
		Status  string `json:"Status"`
	} `json:"State"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
	Created string `json:"Created"`
}

func (b *Backend) docker(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func (b *Backend) inspect(ctx context.Context, name string) (*containerInspect, error) {
	out, err := b.docker(ctx, "container", "inspect", name)
	if err != nil {
		return nil, err
	}
	var cs []containerInspect
	if err := json.Unmarshal(out, &cs); err != nil || len(cs) != 1 {
		return nil, fmt.Errorf("inspect %s: bad output: %v", name, err)
	}
	return &cs[0], nil
}

func (b *Backend) mappedHostPort(ci *containerInspect) (string, bool) {
	mapping, ok := ci.NetworkSettings.Ports[b.ActorPort+"/tcp"]
	if !ok || len(mapping) == 0 {
		return "", false
	}
	return mapping[0].HostPort, true
}

// EnsureReady creates or starts the container and waits for its HTTP listener.
func (b *Backend) EnsureReady(ctx context.Context, key model.RouteKey) (*backend.Handle, backend.Dialer, error) {
	name := b.containerName(key)
	created := time.Now().UTC()
	ci, err := b.inspect(ctx, name)
	switch {
	case err != nil:
		args := []string{"run", "-d", "--name", name,
			"--cpu-shares", "512",
			"-p", b.ActorPort, // publish on a random 127.0.0.1 port
			"-e", "OPEN_TERMINAL_API_KEY=" + b.ActorAPIKey,
		}
		for _, kv := range b.Env {
			args = append(args, "-e", kv)
		}
		args = append(args, b.Image)
		if _, err := b.docker(ctx, args...); err != nil {
			return nil, nil, fmt.Errorf("run container %s: %w", name, err)
		}
		ci, err = b.inspect(ctx, name)
		if err != nil {
			return nil, nil, err
		}
	case !ci.State.Running:
		if _, err := b.docker(ctx, "start", name); err != nil {
			return nil, nil, fmt.Errorf("start container %s: %w", name, err)
		}
	}

	if t, perr := time.Parse(time.RFC3339Nano, ci.Created); perr == nil {
		created = t
	}
	hostPort, ok := b.mappedHostPort(ci)
	if !ok {
		return nil, nil, fmt.Errorf("container %s has no published port for %s/tcp", name, b.ActorPort)
	}

	addr := "127.0.0.1:" + hostPort
	if err := waitHealth(ctx, addr); err != nil {
		return nil, nil, fmt.Errorf("health for %s at %s: %w", name, addr, err)
	}

	return &backend.Handle{Key: key, Name: name, CreatedAt: created, LastReadyAt: time.Now()},
		backend.TCPDialer{Addr: addr}, nil
}

// Get returns the container handle for the route if present.
func (b *Backend) Get(ctx context.Context, key model.RouteKey) (*backend.Handle, error) {
	ci, err := b.inspect(ctx, b.containerName(key))
	if err != nil {
		return nil, nil //nolint:nilnil // absent is a normal answer
	}
	var created time.Time
	if t, perr := time.Parse(time.RFC3339Nano, ci.Created); perr == nil {
		created = t
	}
	return &backend.Handle{Key: key, Name: b.containerName(key), CreatedAt: created}, nil
}

// Suspend stops the container (docker has no snapshot; dev semantics).
func (b *Backend) Suspend(ctx context.Context, h *backend.Handle) error {
	_, err := b.docker(ctx, "stop", h.Name)
	return err
}

// Delete removes the container and its writable layer.
func (b *Backend) Delete(ctx context.Context, h *backend.Handle) error {
	_, _ = b.docker(ctx, "rm", "-f", h.Name)
	return nil
}

// ListReady returns handles for every shim-managed container.
func (b *Backend) ListReady(ctx context.Context) ([]backend.Handle, error) {
	out, err := b.docker(ctx, "ps", "--filter", "name="+b.Prefix, "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	var hs []backend.Handle
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line == "" {
			continue
		}
		hs = append(hs, backend.Handle{Name: line})
	}
	return hs, nil
}

// waitHealth polls GET /health until it answers, bounded by ctx and a deadline.
func waitHealth(ctx context.Context, addr string) error {
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for {
		if err := probeHealth(ctx, addr); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for /health on %s: %v", addr, lastErr)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// probeHealth performs one GET http://addr/health; nil error means healthy.
func probeHealth(ctx context.Context, addr string) error {
	var d net.Dialer
	d.Timeout = 2 * time.Second
	client := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{DialContext: d.DialContext},
	}
	ctxT, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctxT, http.MethodGet, "http://"+addr+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)) //nolint:errcheck
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("health returned %s", resp.Status)
}
