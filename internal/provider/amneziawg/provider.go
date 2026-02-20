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

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// Config holds AmneziaWG-specific tunnel configuration.
type Config struct {
	// ConfigFile is the path to the AmneziaWG .conf file.
	ConfigFile string `yaml:"config_file"`
	// AdapterIP is the local IP override (optional; taken from .conf Address if empty).
	AdapterIP string `yaml:"adapter_ip"`
}

// Provider implements TunnelProvider for the AmneziaWG protocol using
// amneziawg-go with a netstack (gvisor) userspace TCP/IP stack.
// No real Wintun adapter is created; all tunnel traffic goes through netstack.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	adapterIP     netip.Addr
	peerEndpoints []netip.AddrPort
	dev           *device.Device // amneziawg-go device
	tnet          *netstack.Net  // userspace network stack
}

// New creates an AmneziaWG provider with the given configuration.
// AdapterIP is optional — if empty, it will be resolved from the .conf Address on Connect.
func New(name string, cfg Config) (*Provider, error) {
	p := &Provider{
		config: cfg,
		name:   name,
		state:  core.TunnelStateDown,
	}

	if cfg.AdapterIP != "" {
		ip, err := netip.ParseAddr(cfg.AdapterIP)
		if err != nil {
			return nil, fmt.Errorf("[AWG] invalid adapter IP %q: %w", cfg.AdapterIP, err)
		}
		p.adapterIP = ip
	}

	return p, nil
}

// Connect establishes the AmneziaWG tunnel via amneziawg-go + netstack.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	log.Printf("[AWG] Connecting tunnel %q...", p.name)

	// 1. Parse .conf file.
	parsed, err := ParseConfigFile(p.config.ConfigFile)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[AWG] parse config: %w", err)
	}

	// 2. Determine local addresses for netstack.
	localAddresses := parsed.LocalAddresses
	if len(localAddresses) == 0 {
		if !p.adapterIP.IsValid() {
			p.state = core.TunnelStateError
			return fmt.Errorf("[AWG] no local address: set adapter_ip or add Address to .conf")
		}
		localAddresses = []netip.Addr{p.adapterIP}
	}
	if !p.adapterIP.IsValid() {
		p.adapterIP = localAddresses[0]
	}

	// 3. Create userspace TUN via netstack (no real Wintun adapter).
	tunDev, tnet, err := netstack.CreateNetTUN(localAddresses, parsed.DNSServers, parsed.MTU)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[AWG] create netstack TUN: %w", err)
	}

	// 4. Create WG device with default UDP bind.
	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[AWG:%s] ", p.name))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	// 5. Apply UAPI configuration (keys, endpoints, obfuscation params).
	if err := dev.IpcSet(parsed.UAPIConfig); err != nil {
		dev.Close()
		p.state = core.TunnelStateError
		return fmt.Errorf("[AWG] apply config: %w", err)
	}

	// 6. Bring device up.
	if err := dev.Up(); err != nil {
		dev.Close()
		p.state = core.TunnelStateError
		return fmt.Errorf("[AWG] device up: %w", err)
	}

	p.dev = dev
	p.tnet = tnet
	p.peerEndpoints = parsed.PeerEndpoints
	p.state = core.TunnelStateUp
	log.Printf("[AWG] Tunnel %q is UP (ip=%s, mtu=%d)", p.name, p.adapterIP, parsed.MTU)
	return nil
}

// Disconnect tears down the AmneziaWG tunnel.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.dev != nil {
		p.dev.Close()
		p.dev = nil
		p.tnet = nil
	}

	p.state = core.TunnelStateDown
	log.Printf("[AWG] Tunnel %q disconnected", p.name)
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns the local IP of the tunnel (from config or .conf Address).
func (p *Provider) GetAdapterIP() netip.Addr {
	return p.adapterIP
}

// DialTCP creates a TCP connection through the AWG tunnel via netstack.
// Calls DialContextTCPAddrPort directly, bypassing DialContext's regex parsing
// and DNS lookup overhead (~1μs + allocations saved per connection).
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	tnet := p.tnet
	p.mu.RUnlock()

	if state != core.TunnelStateUp {
		return nil, fmt.Errorf("[AWG] tunnel %q is not up (state=%d)", p.name, state)
	}

	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[AWG] invalid address %q: %w", addr, err)
	}
	return tnet.DialContextTCPAddrPort(ctx, ap)
}

// DialUDP creates a connected UDP socket through the AWG tunnel via netstack.
// Calls DialUDPAddrPort directly, bypassing DialContext's regex and DNS overhead.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	tnet := p.tnet
	p.mu.RUnlock()

	if state != core.TunnelStateUp {
		return nil, fmt.Errorf("[AWG] tunnel %q is not up (state=%d)", p.name, state)
	}

	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[AWG] invalid address %q: %w", addr, err)
	}
	return tnet.DialUDPAddrPort(netip.AddrPort{}, ap)
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "amneziawg".
func (p *Provider) Protocol() string {
	return "amneziawg"
}

// GetPeerEndpoints returns the WireGuard server endpoints parsed from the config.
// Used by PacketRouter to add kernel-level static bypass filters.
func (p *Provider) GetPeerEndpoints() []netip.AddrPort {
	return p.peerEndpoints
}
