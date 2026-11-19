// Package backend abstracts "where actors run" so the facade can be validated
// against a local dev backend (docker) before wiring Agent Substrate.
package backend

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/viveksupe/Trident/internal/model"
)

// Handle describes one running-or-suspended actor.
type Handle struct {
	// RouteKey identity this handle was created for.
	Key model.RouteKey
	// Name is backend-specific (substrate actor name or docker container name).
	Name string
	// CreatedAt / LastReadyAt for lifecycle decisions.
	CreatedAt   time.Time
	LastReadyAt time.Time
	// LiveStreams counts attached WS streams; suspend must wait for zero.
	LiveStreams int64
}

// Endpoint is a dial target for an actor's HTTP listener.
type Endpoint struct {
	// Host and Port of the actor HTTP server reachable via DialConn.
	Host string
	Port string
}

// Dialer manufactures new net.Conn sessions to a specific actor.
type Dialer interface {
	DialConn(ctx context.Context, network string) (net.Conn, error)
}

// Backend manages the actor lifecycle for one substrate/cluster/docker host.
type Backend interface {
	// EnsureReady makes the actor for key exist and be serving (create if
	// missing, resume if suspended). Returns the handle and a dialer for it.
	EnsureReady(ctx context.Context, key model.RouteKey) (*Handle, Dialer, error)

	// Get returns the existing handle for key, or nil if the backend does not
	// know it.
	Get(ctx context.Context, key model.RouteKey) (*Handle, error)

	// Suspend puts the actor to sleep (snapshot) — best effort.
	Suspend(ctx context.Context, h *Handle) error

	// Delete destroys the actor and its durable data.
	Delete(ctx context.Context, h *Handle) error

	// ListReady returns every actor the backend currently knows for this shim
	// (used to reconcile the persistent session map after a shim restart).
	ListReady(ctx context.Context) ([]Handle, error)
}

// TCPDialer is a Dialer over plain host:port, shared by the dev backends.
type TCPDialer struct{ Addr string }

var _ Dialer = TCPDialer{}

// DialConn opens a TCP connection to Addr.
func (t TCPDialer) DialConn(ctx context.Context, network string) (net.Conn, error) {
	if network == "" {
		network = "tcp"
	}
	var d net.Dialer
	d.Timeout = 10 * time.Second
	return d.DialContext(ctx, network, t.Addr)
}

func fmtErr(op string, err error, key model.RouteKey) error {
	return fmt.Errorf("%s actor %s: %w", op, key.LogString(), err)
}
