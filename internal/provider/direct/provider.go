package direct

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/platform"
)

// Provider implements TunnelProvider for direct (non-VPN) traffic.
// Routes traffic through the real NIC using platform-specific interface binding
// (IP_UNICAST_IF on Windows, IP_BOUND_IF on macOS), bypassing the TUN adapter's default route.
type Provider struct {
	mu           sync.RWMutex
	realNICIndex uint32
	localIP      netip.Addr // real NIC's own IPv4 address
	state        core.TunnelState
	binder       platform.InterfaceBinder
}

// New creates a DirectProvider that binds to the specified real NIC.
func New(realNICIndex uint32, localIP netip.Addr, binder platform.InterfaceBinder) (*Provider, error) {
	if binder == nil {
		return nil, fmt.Errorf("binder cannot be nil for DirectProvider")
	}
	if localIP.IsValid() && !localIP.Is4() {
		return nil, fmt.Errorf("localIP must be an IPv4 address for DirectProvider, got %s", localIP)
	}
	return &Provider{
		mu:           sync.RWMutex{},
		realNICIndex: realNICIndex,
		localIP:      localIP,
		state:        core.TunnelStateUp,
		binder:       binder,
	}, nil
}

// Connect is a no-op for DirectProvider (always up).
func (p *Provider) Connect(_ context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = core.TunnelStateUp
	core.Log.Infof("Direct", "Provider ready (NIC index=%d, localIP=%s)", p.realNICIndex, p.localIP)
	return nil
}

// Disconnect is a no-op.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state = core.TunnelStateDown
	core.Log.Infof("Direct", "Provider stopped")
	return nil
}

// State returns the current provider state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns an invalid addr (no VPN adapter).
func (p *Provider) GetAdapterIP() netip.Addr { return netip.Addr{} }

// DialTCP creates a TCP connection through the real NIC.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: p.binder.BindControl(p.realNICIndex),
	}
	// Bind to real NIC's IP for belt-and-suspenders with interface binding.
	if p.localIP.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: p.localIP.AsSlice()}
	}
	return dialer.DialContext(ctx, "tcp4", addr)
}

// DialUDP creates a connected UDP socket through the real NIC.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: p.binder.BindControl(p.realNICIndex),
	}
	if p.localIP.IsValid() {
		dialer.LocalAddr = &net.UDPAddr{IP: p.localIP.AsSlice()}
	}
	return dialer.DialContext(ctx, "udp4", addr)
}

// Name returns "Direct".
func (p *Provider) Name() string { return "Direct" }

// Protocol returns "direct".
func (p *Provider) Protocol() string { return "direct" }
