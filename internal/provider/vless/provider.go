//go:build windows

package vless

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"awg-split-tunnel/internal/core"

	xcore "github.com/xtls/xray-core/core"
	xnet "github.com/xtls/xray-core/common/net"
)

// Provider implements TunnelProvider for the VLESS protocol with optional
// Reality/TLS security, using xray-core as an in-process library.
// Traffic is routed through xray's VLESS outbound via DialTCP/DialUDP (proxy path).
// Does NOT implement RawForwarder — not an IP-level tunnel.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	serverAddr netip.AddrPort // resolved server endpoint for bypass routes
	instance   *xcore.Instance
}

// New creates a VLESS provider with the given configuration.
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("[VLESS] server address is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("[VLESS] invalid port %d", cfg.Port)
	}
	if cfg.UUID == "" {
		return nil, fmt.Errorf("[VLESS] UUID is required")
	}

	return &Provider{
		config: cfg,
		name:   name,
		state:  core.TunnelStateDown,
	}, nil
}

// Connect starts the xray-core instance with the VLESS + Reality configuration.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	core.Log.Infof("VLESS", "Connecting tunnel %q to %s:%d...", p.name, p.config.Address, p.config.Port)

	// Resolve server address for bypass routes.
	serverStr := fmt.Sprintf("%s:%d", p.config.Address, p.config.Port)
	if ap, err := netip.ParseAddrPort(serverStr); err == nil {
		p.serverAddr = ap
	} else {
		ips, err := net.DefaultResolver.LookupHost(ctx, p.config.Address)
		if err != nil {
			p.state = core.TunnelStateError
			return fmt.Errorf("[VLESS] resolve %q: %w", p.config.Address, err)
		}
		if len(ips) > 0 {
			if addr, err := netip.ParseAddr(ips[0]); err == nil {
				p.serverAddr = netip.AddrPortFrom(addr, uint16(p.config.Port))
			}
		}
	}

	// Build xray JSON config.
	configBytes, err := buildXrayJSON(p.config)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[VLESS] build config: %w", err)
	}

	// Start xray-core instance.
	instance, err := xcore.StartInstance("json", configBytes)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[VLESS] start xray instance: %w", err)
	}

	p.instance = instance
	p.state = core.TunnelStateUp
	core.Log.Infof("VLESS", "Tunnel %q is UP (server=%s, security=%s)", p.name, serverStr, p.config.Security)
	return nil
}

// Disconnect shuts down the xray-core instance.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.instance != nil {
		if err := p.instance.Close(); err != nil {
			core.Log.Warnf("VLESS", "Error closing xray instance for %q: %v", p.name, err)
		}
		p.instance = nil
	}

	p.state = core.TunnelStateDown
	core.Log.Infof("VLESS", "Tunnel %q disconnected", p.name)
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns an invalid address — VLESS has no local VPN adapter IP.
func (p *Provider) GetAdapterIP() netip.Addr {
	return netip.Addr{}
}

// DialTCP creates a TCP connection through the VLESS tunnel via xray-core.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	inst := p.instance
	p.mu.RUnlock()

	if state != core.TunnelStateUp || inst == nil {
		return nil, fmt.Errorf("[VLESS] tunnel %q is not up (state=%d)", p.name, state)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] invalid address %q: %w", addr, err)
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
	return xcore.Dial(ctx, inst, dest)
}

// DialUDP creates a UDP connection through the VLESS tunnel via xray-core.
// Returns a net.Conn wrapper around the PacketConn returned by xray.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	inst := p.instance
	p.mu.RUnlock()

	if state != core.TunnelStateUp || inst == nil {
		return nil, fmt.Errorf("[VLESS] tunnel %q is not up (state=%d)", p.name, state)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] invalid address %q: %w", addr, err)
	}

	var port uint16
	fmt.Sscanf(portStr, "%d", &port)

	// xray DialUDP returns a PacketConn, wrap it as a connected net.Conn.
	pconn, err := xcore.DialUDP(ctx, inst)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] dial UDP: %w", err)
	}

	targetAddr := &net.UDPAddr{
		IP:   net.ParseIP(host),
		Port: int(port),
	}

	return &packetConnWrapper{
		PacketConn: pconn,
		remoteAddr: targetAddr,
	}, nil
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "vless".
func (p *Provider) Protocol() string {
	return "vless"
}

// GetServerEndpoints returns the VLESS server endpoint for bypass route management.
// Implements provider.EndpointProvider.
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	if p.serverAddr.IsValid() {
		return []netip.AddrPort{p.serverAddr}
	}
	return nil
}

// SetInterfaceName sets the network interface name for socket binding (IP_UNICAST_IF).
// Must be called before Connect. Implements provider.SocketBindProvider.
func (p *Provider) SetInterfaceName(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.config.InterfaceName = name
}

// packetConnWrapper adapts a net.PacketConn to a connected net.Conn by adding
// a fixed remote address for Read/Write.
type packetConnWrapper struct {
	net.PacketConn
	remoteAddr net.Addr
}

func (w *packetConnWrapper) Read(b []byte) (int, error) {
	n, _, err := w.PacketConn.ReadFrom(b)
	return n, err
}

func (w *packetConnWrapper) Write(b []byte) (int, error) {
	return w.PacketConn.WriteTo(b, w.remoteAddr)
}

func (w *packetConnWrapper) RemoteAddr() net.Addr {
	return w.remoteAddr
}
