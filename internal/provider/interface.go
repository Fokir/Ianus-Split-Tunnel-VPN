//go:build windows

package provider

import (
	"context"
	"net"
	"net/netip"

	"awg-split-tunnel/internal/core"
)

// TunnelProvider is the contract every VPN protocol must implement.
type TunnelProvider interface {
	// Connect establishes the VPN tunnel. Blocks until connected or ctx cancelled.
	Connect(ctx context.Context) error

	// Disconnect tears down the VPN tunnel gracefully.
	Disconnect() error

	// State returns the current tunnel state.
	State() core.TunnelState

	// GetAdapterIP returns the local IP assigned to the VPN adapter (e.g. 10.8.1.2).
	GetAdapterIP() netip.Addr

	// DialTCP creates a TCP connection through the tunnel to the given address.
	// The connection is bound to the VPN adapter's IP.
	DialTCP(ctx context.Context, addr string) (net.Conn, error)

	// Name returns a human-readable name for this provider instance.
	Name() string

	// Protocol returns the protocol identifier (e.g. "amneziawg", "wireguard").
	Protocol() string
}
