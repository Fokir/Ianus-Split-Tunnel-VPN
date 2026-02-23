//go:build windows

package provider

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"awg-split-tunnel/internal/core"
)

// ErrUDPNotSupported is returned by providers that do not support UDP (e.g. HTTP CONNECT proxy).
var ErrUDPNotSupported = errors.New("UDP not supported by this provider")

// RawForwarder allows injecting raw IP packets directly into a VPN tunnel,
// bypassing the userspace TCP proxy and gVisor stack. Providers that support
// raw forwarding (e.g. AmneziaWG) implement this interface in addition to
// TunnelProvider. The TUNRouter uses a type assertion to detect support.
type RawForwarder interface {
	// InjectOutbound sends a raw IP packet into the tunnel for encryption
	// at Normal priority. Returns true on success, false if dropped.
	InjectOutbound(pkt []byte) bool

	// InjectOutboundPriority sends a raw IP packet at the specified priority
	// (0=High, 1=Normal, 2=Low). High-priority packets are drained first.
	InjectOutboundPriority(pkt []byte, prio byte) bool

	// SetInboundHandler installs a callback for packets arriving from the tunnel.
	// If the handler returns true, the packet is consumed (raw path); false falls
	// through to gVisor. Pass nil to remove the handler.
	SetInboundHandler(handler func(pkt []byte) bool)
}

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

	// DialUDP creates a connected UDP socket through the tunnel to the given address.
	// Each Read returns one datagram; each Write sends one datagram.
	DialUDP(ctx context.Context, addr string) (net.Conn, error)

	// Name returns a human-readable name for this provider instance.
	Name() string

	// Protocol returns the protocol identifier (e.g. "amneziawg", "wireguard").
	Protocol() string
}

// EndpointProvider is optionally implemented by providers that have remote server
// endpoints requiring bypass routes (so VPN traffic reaches the server via real NIC).
type EndpointProvider interface {
	GetServerEndpoints() []netip.AddrPort
}
