package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"awg-split-tunnel/internal/core"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// Config holds WireGuard-specific tunnel configuration.
type Config struct {
	// ConfigFile is the path to the WireGuard .conf file.
	ConfigFile string `yaml:"config_file"`
	// AdapterIP is the local IP override (optional; taken from .conf Address if empty).
	AdapterIP string `yaml:"adapter_ip"`
}

// Provider implements TunnelProvider for the standard WireGuard protocol using
// amneziawg-go with a netstack (gvisor) userspace TCP/IP stack.
// AmneziaWG is a superset of WireGuard — without obfuscation params it acts as standard WG.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	adapterIP     netip.Addr
	peerEndpoints []netip.AddrPort
	dev           *device.Device
	tnet          *netstack.Net
}

// New creates a WireGuard provider with the given configuration.
func New(name string, cfg Config) (*Provider, error) {
	p := &Provider{
		config: cfg,
		name:   name,
		state:  core.TunnelStateDown,
	}

	if cfg.AdapterIP != "" {
		ip, err := netip.ParseAddr(cfg.AdapterIP)
		if err != nil {
			return nil, fmt.Errorf("[WG] invalid adapter IP %q: %w", cfg.AdapterIP, err)
		}
		p.adapterIP = ip
	}

	return p, nil
}

// Connect establishes the WireGuard tunnel via amneziawg-go + netstack.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	core.Log.Infof("WG", "Connecting tunnel %q...", p.name)

	parsed, err := ParseConfigFile(p.config.ConfigFile)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[WG] parse config: %w", err)
	}

	localAddresses := parsed.LocalAddresses
	if len(localAddresses) == 0 {
		if !p.adapterIP.IsValid() {
			p.state = core.TunnelStateError
			return fmt.Errorf("[WG] no local address: set adapter_ip or add Address to .conf")
		}
		localAddresses = []netip.Addr{p.adapterIP}
	}
	if !p.adapterIP.IsValid() {
		p.adapterIP = localAddresses[0]
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddresses, parsed.DNSServers, parsed.MTU)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[WG] create netstack TUN: %w", err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("[WG:%s] ", p.name))
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	if err := dev.IpcSet(parsed.UAPIConfig); err != nil {
		dev.Close()
		p.state = core.TunnelStateError
		return fmt.Errorf("[WG] apply config: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		p.state = core.TunnelStateError
		return fmt.Errorf("[WG] device up: %w", err)
	}

	p.dev = dev
	p.tnet = tnet
	p.peerEndpoints = parsed.PeerEndpoints
	p.state = core.TunnelStateUp
	core.Log.Infof("WG", "Tunnel %q is UP (ip=%s, mtu=%d)", p.name, p.adapterIP, parsed.MTU)
	return nil
}

// Disconnect tears down the WireGuard tunnel.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.tnet != nil {
		p.tnet.SetInboundHandler(nil)
	}

	if p.dev != nil {
		p.dev.Close()
		p.dev = nil
		p.tnet = nil
	}

	p.state = core.TunnelStateDown
	core.Log.Infof("WG", "Tunnel %q disconnected", p.name)
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns the local IP of the tunnel.
func (p *Provider) GetAdapterIP() netip.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.adapterIP
}

// DialTCP creates a TCP connection through the WireGuard tunnel via netstack.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	tnet := p.tnet
	p.mu.RUnlock()

	if state != core.TunnelStateUp {
		return nil, fmt.Errorf("[WG] tunnel %q is not up (state=%d)", p.name, state)
	}

	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[WG] invalid address %q: %w", addr, err)
	}
	return tnet.DialContextTCPAddrPort(ctx, ap)
}

// DialUDP creates a connected UDP socket through the WireGuard tunnel via netstack.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	tnet := p.tnet
	p.mu.RUnlock()

	if state != core.TunnelStateUp {
		return nil, fmt.Errorf("[WG] tunnel %q is not up (state=%d)", p.name, state)
	}

	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[WG] invalid address %q: %w", addr, err)
	}
	return tnet.DialUDPAddrPort(netip.AddrPort{}, ap)
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "wireguard".
func (p *Provider) Protocol() string {
	return "wireguard"
}

// GetServerEndpoints returns the WireGuard server endpoints parsed from the config.
// Implements provider.EndpointProvider for bypass route management.
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.peerEndpoints
}

// ---------------------------------------------------------------------------
// RawForwarder implementation — raw IP forwarding bypassing gVisor
// ---------------------------------------------------------------------------

// InjectOutbound sends a raw IP packet into the WireGuard tunnel at Normal priority.
func (p *Provider) InjectOutbound(pkt []byte) bool {
	p.mu.RLock()
	tnet := p.tnet
	p.mu.RUnlock()

	if tnet == nil {
		return false
	}
	return tnet.InjectOutbound(pkt)
}

// InjectOutboundPriority sends a raw IP packet at the specified priority level.
func (p *Provider) InjectOutboundPriority(pkt []byte, prio byte) bool {
	p.mu.RLock()
	tnet := p.tnet
	p.mu.RUnlock()

	if tnet == nil {
		return false
	}
	return tnet.InjectOutboundPriority(pkt, prio)
}

// SetInboundHandler installs a callback for packets arriving from the tunnel.
func (p *Provider) SetInboundHandler(handler func(pkt []byte) bool) {
	p.mu.RLock()
	tnet := p.tnet
	p.mu.RUnlock()

	if tnet != nil {
		tnet.SetInboundHandler(handler)
	}
}

// IpcGet returns the WireGuard IPC status string, including peer handshake times.
// Used by the health monitor to detect stale peers.
func (p *Provider) IpcGet() (string, error) {
	p.mu.RLock()
	dev := p.dev
	p.mu.RUnlock()
	if dev == nil {
		return "", fmt.Errorf("device not initialized")
	}
	return dev.IpcGet()
}
