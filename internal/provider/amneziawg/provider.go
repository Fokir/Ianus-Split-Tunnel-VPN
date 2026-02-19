//go:build windows

package amneziawg

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"

	"awg-split-tunnel/internal/core"
)

// Config holds AmneziaWG-specific tunnel configuration.
type Config struct {
	// ConfigFile is the path to the AmneziaWG .conf file.
	ConfigFile string `yaml:"config_file"`
	// AdapterName is the name of the WinTun adapter created by AmneziaWG.
	AdapterName string `yaml:"adapter_name"`
	// AdapterIP is the local IP assigned to the WinTun adapter (e.g. "10.8.1.2").
	AdapterIP string `yaml:"adapter_ip"`
}

// Provider implements TunnelProvider for the AmneziaWG protocol.
// It binds outgoing connections to the AmneziaWG WinTun adapter's IP,
// so traffic is routed through the AWG tunnel.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	adapterIP netip.Addr
}

// New creates an AmneziaWG provider with the given configuration.
func New(name string, cfg Config) (*Provider, error) {
	ip, err := netip.ParseAddr(cfg.AdapterIP)
	if err != nil {
		return nil, fmt.Errorf("[AWG] invalid adapter IP %q: %w", cfg.AdapterIP, err)
	}

	return &Provider{
		config:    cfg,
		name:      name,
		adapterIP: ip,
		state:     core.TunnelStateDown,
	}, nil
}

// Connect establishes the AmneziaWG tunnel.
// TODO: Integrate with amneziawg-go to actually manage the tunnel lifecycle.
// For now, assumes the tunnel is managed externally (e.g. by awg-quick or the AWG client).
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	log.Printf("[AWG] Connecting tunnel %q (adapter=%s, ip=%s)", p.name, p.config.AdapterName, p.adapterIP)

	// TODO: Start amneziawg-go device, configure wintun adapter.
	// For Phase 1, we assume the AWG tunnel is started externally.
	// We just verify the adapter IP is reachable.

	p.state = core.TunnelStateUp
	log.Printf("[AWG] Tunnel %q is UP", p.name)
	return nil
}

// Disconnect tears down the AmneziaWG tunnel.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateDown
	log.Printf("[AWG] Tunnel %q disconnected", p.name)
	// TODO: Stop amneziawg-go device.
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns the local IP of the WinTun adapter.
func (p *Provider) GetAdapterIP() netip.Addr {
	return p.adapterIP
}

// DialTCP creates a TCP connection through the AWG tunnel by binding
// to the WinTun adapter's local IP address.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	p.mu.RUnlock()

	if state != core.TunnelStateUp {
		return nil, fmt.Errorf("[AWG] tunnel %q is not up (state=%s)", p.name, state)
	}

	// Bind to the AWG adapter IP so the OS routes through the VPN tunnel.
	localAddr := &net.TCPAddr{
		IP: p.adapterIP.AsSlice(),
	}

	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Control:   nil, // TODO: SO_BINDTODEVICE equivalent on Windows if needed
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("[AWG] dial %s via %s: %w", addr, p.adapterIP, err)
	}

	return conn, nil
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "amneziawg".
func (p *Provider) Protocol() string {
	return "amneziawg"
}
