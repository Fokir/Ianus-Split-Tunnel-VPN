//go:build windows

package vless

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"awg-split-tunnel/internal/core"

	xlog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	xcore "github.com/xtls/xray-core/core"
)

const ipUnicastIF = 31 // IP_UNICAST_IF socket option

// xrayLogBridge forwards xray-core internal log messages to our logging system.
type xrayLogBridge struct{}

func (b *xrayLogBridge) Handle(msg xlog.Message) {
	core.Log.Debugf("xray", "%s", msg.String())
}

// Provider implements TunnelProvider for the VLESS protocol with optional
// Reality/TLS security, using xray-core as an in-process library.
// Traffic is routed through xray's VLESS outbound via DialTCP/DialUDP (proxy path).
// Does NOT implement RawForwarder — not an IP-level tunnel.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	realNICIndex uint32         // real NIC index for DNS resolution bypass
	serverAddr   netip.AddrPort // resolved server endpoint for bypass routes
	instance     *xcore.Instance
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
		// Resolve hostname through the real NIC to bypass TUN DNS (10.255.0.1).
		// TUN DNS may route queries to an unregistered tunnel during startup,
		// causing "temporary error during hostname resolution".
		var ips []string
		var err error
		if p.realNICIndex > 0 {
			ips, err = p.resolveViaRealNIC(ctx, p.config.Address)
		} else {
			ips, err = net.DefaultResolver.LookupHost(ctx, p.config.Address)
		}
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
	core.Log.Infof("VLESS", "xray config: %s", string(configBytes))

	// Start xray-core instance.
	instance, err := xcore.StartInstance("json", configBytes)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[VLESS] start xray instance: %w", err)
	}

	// Bridge xray-core internal logs to our logging system.
	// Must be called after StartInstance since it replaces the handler
	// that xray's log feature registers during initialization.
	xlog.RegisterHandler(&xrayLogBridge{})

	p.instance = instance
	p.state = core.TunnelStateUp
	core.Log.Infof("VLESS", "Tunnel %q is UP (server=%s, security=%s, network=%s, flow=%s)",
		p.name, serverStr, p.config.Security, p.config.Network, p.config.Flow)
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

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	core.Log.Debugf("VLESS", "DialTCP %s via tunnel %q", addr, p.name)
	start := time.Now()

	dest := xnet.TCPDestination(xnet.ParseAddress(host), xnet.Port(port))
	conn, err := xcore.Dial(dialCtx, inst, dest)
	if err != nil {
		core.Log.Warnf("VLESS", "DialTCP %s failed after %s: %v", addr, time.Since(start), err)
		return nil, err
	}

	core.Log.Debugf("VLESS", "DialTCP %s connected in %s", addr, time.Since(start))
	return conn, nil
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

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	core.Log.Debugf("VLESS", "DialUDP %s via tunnel %q", addr, p.name)

	// xray DialUDP returns a PacketConn, wrap it as a connected net.Conn.
	pconn, err := xcore.DialUDP(dialCtx, inst)
	if err != nil {
		core.Log.Warnf("VLESS", "DialUDP %s failed: %v", addr, err)
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

// SetRealNICIndex sets the real NIC interface index for DNS resolution bypass.
// Must be called before Connect.
func (p *Provider) SetRealNICIndex(index uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.realNICIndex = index
}

// resolveViaRealNIC resolves a hostname using a DNS resolver bound to the real
// NIC interface via IP_UNICAST_IF, bypassing the TUN DNS resolver entirely.
func (p *Provider) resolveViaRealNIC(ctx context.Context, host string) ([]string, error) {
	core.Log.Debugf("VLESS", "Resolving %q via real NIC (index=%d)", host, p.realNICIndex)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{
				Control: func(_, _ string, c syscall.RawConn) error {
					var setErr error
					err := c.Control(func(fd uintptr) {
						handle := syscall.Handle(fd)
						var bytes [4]byte
						binary.BigEndian.PutUint32(bytes[:], p.realNICIndex)
						idx := *(*int32)(unsafe.Pointer(&bytes[0]))
						setErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, ipUnicastIF, int(idx))
					})
					if err != nil {
						return fmt.Errorf("control: %w", err)
					}
					return setErr
				},
			}
			return dialer.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		core.Log.Warnf("VLESS", "DNS resolve %q via real NIC failed: %v", host, err)
		return nil, err
	}
	core.Log.Infof("VLESS", "Resolved %q via real NIC → %v", host, ips)
	return ips, nil
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
