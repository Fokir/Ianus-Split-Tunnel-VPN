package socks5

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"

	"golang.org/x/net/proxy"
)

// Config holds SOCKS5-specific tunnel configuration.
type Config struct {
	// Server is the SOCKS5 proxy hostname or IP.
	Server string `yaml:"server"`
	// Port is the SOCKS5 proxy port.
	Port int `yaml:"port"`
	// Username for SOCKS5 authentication (optional).
	Username string `yaml:"username"`
	// Password for SOCKS5 authentication (optional).
	Password string `yaml:"password"`
	// UDPEnabled controls whether UDP ASSOCIATE is attempted (default true).
	UDPEnabled bool `yaml:"udp_enabled"`
}

// Provider implements TunnelProvider for SOCKS5 proxy protocol.
// Traffic is routed through the SOCKS5 server via DialTCP/DialUDP (proxy path).
// Does NOT implement RawForwarder — not an IP-level tunnel.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	serverAddr netip.AddrPort // resolved server endpoint for bypass routes
	dialer     proxy.Dialer   // SOCKS5 dialer for TCP connections
}

// New creates a SOCKS5 provider with the given configuration.
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("[SOCKS5] server address is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("[SOCKS5] invalid port %d", cfg.Port)
	}

	p := &Provider{
		config: cfg,
		name:   name,
		state:  core.TunnelStateDown,
	}

	return p, nil
}

// Connect establishes the SOCKS5 connection by validating the proxy is reachable.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	serverStr := net.JoinHostPort(p.config.Server, fmt.Sprintf("%d", p.config.Port))
	core.Log.Infof("SOCKS5", "Connecting tunnel %q to %s...", p.name, serverStr)

	// Resolve server address for bypass routes.
	if ap, err := netip.ParseAddrPort(serverStr); err == nil {
		p.serverAddr = ap
	} else {
		// Server might be a hostname — resolve it.
		ips, err := net.DefaultResolver.LookupHost(ctx, p.config.Server)
		if err != nil {
			p.state = core.TunnelStateError
			return fmt.Errorf("[SOCKS5] resolve %q: %w", p.config.Server, err)
		}
		if len(ips) > 0 {
			if addr, err := netip.ParseAddr(ips[0]); err == nil {
				p.serverAddr = netip.AddrPortFrom(addr, uint16(p.config.Port))
			}
		}
	}

	// Build SOCKS5 dialer.
	var auth *proxy.Auth
	if p.config.Username != "" {
		auth = &proxy.Auth{
			User:     p.config.Username,
			Password: p.config.Password,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", serverStr, auth, proxy.Direct)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[SOCKS5] create dialer: %w", err)
	}

	// Probe: verify the SOCKS5 server is reachable with a quick TCP handshake.
	probeConn, err := net.DialTimeout("tcp", serverStr, 10*time.Second)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[SOCKS5] server unreachable at %s: %w", serverStr, err)
	}
	probeConn.Close()

	p.dialer = dialer
	p.state = core.TunnelStateUp
	core.Log.Infof("SOCKS5", "Tunnel %q is UP (server=%s)", p.name, serverStr)
	return nil
}

// Disconnect tears down the SOCKS5 connection state.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.dialer = nil
	p.state = core.TunnelStateDown
	core.Log.Infof("SOCKS5", "Tunnel %q disconnected", p.name)
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns an invalid address — SOCKS5 has no local VPN adapter IP.
func (p *Provider) GetAdapterIP() netip.Addr {
	return netip.Addr{}
}

// DialTCP creates a TCP connection through the SOCKS5 proxy.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	dialer := p.dialer
	p.mu.RUnlock()

	if state != core.TunnelStateUp || dialer == nil {
		return nil, fmt.Errorf("[SOCKS5] tunnel %q is not up (state=%d)", p.name, state)
	}

	// Use context-aware dialing if the dialer supports it.
	if cd, ok := dialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, "tcp", addr)
	}
	return dialer.Dial("tcp", addr)
}

// DialUDP creates a UDP connection through the SOCKS5 proxy via UDP ASSOCIATE.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	p.mu.RUnlock()

	if state != core.TunnelStateUp {
		return nil, fmt.Errorf("[SOCKS5] tunnel %q is not up (state=%d)", p.name, state)
	}

	if !p.config.UDPEnabled {
		return nil, provider.ErrUDPNotSupported
	}

	serverStr := net.JoinHostPort(p.config.Server, fmt.Sprintf("%d", p.config.Port))

	var auth *socks5Auth
	if p.config.Username != "" {
		auth = &socks5Auth{
			username: p.config.Username,
			password: p.config.Password,
		}
	}

	return dialUDPAssociate(ctx, serverStr, auth, addr)
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "socks5".
func (p *Provider) Protocol() string {
	return "socks5"
}

// GetServerEndpoints returns the SOCKS5 server endpoint for bypass route management.
// Implements provider.EndpointProvider.
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	if p.serverAddr.IsValid() {
		return []netip.AddrPort{p.serverAddr}
	}
	return nil
}
