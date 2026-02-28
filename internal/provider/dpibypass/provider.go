package dpibypass

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/dpi"
)

// Provider implements TunnelProvider for DPI-bypass traffic.
// It routes traffic through the real NIC (like DirectProvider) but wraps
// TCP connections in a desyncConn that manipulates TLS ClientHello packets
// to evade Deep Packet Inspection.
type Provider struct {
	name         string
	realNICIndex uint32
	localIP      netip.Addr
	bindControl  func(network, address string, c syscall.RawConn) error
	state        atomic.Int32

	mu       sync.RWMutex
	strategy *dpi.Strategy
}

// New creates a DPIBypassProvider.
// bindControl is a function that binds sockets to the real NIC (from InterfaceBinder).
func New(name string, realNICIndex uint32, localIP netip.Addr,
	bindControl func(network, address string, c syscall.RawConn) error) (*Provider, error) {

	if localIP.IsValid() && !localIP.Is4() {
		return nil, fmt.Errorf("localIP must be an IPv4 address for DPIBypassProvider, got %s", localIP)
	}

	p := &Provider{
		name:         name,
		realNICIndex: realNICIndex,
		localIP:      localIP,
		bindControl:  bindControl,
	}
	p.state.Store(int32(core.TunnelStateUp))
	return p, nil
}

// Connect is a no-op (always up, like DirectProvider).
func (p *Provider) Connect(_ context.Context) error {
	p.state.Store(int32(core.TunnelStateUp))
	core.Log.Infof("DPI", "Provider %q ready (NIC index=%d, localIP=%s)", p.name, p.realNICIndex, p.localIP)
	return nil
}

// Disconnect stops the provider.
func (p *Provider) Disconnect() error {
	p.state.Store(int32(core.TunnelStateDown))
	core.Log.Infof("DPI", "Provider %q stopped", p.name)
	return nil
}

// State returns the current provider state.
func (p *Provider) State() core.TunnelState {
	return core.TunnelState(p.state.Load())
}

// GetAdapterIP returns an invalid addr (no VPN adapter, traffic goes through real NIC).
func (p *Provider) GetAdapterIP() netip.Addr { return netip.Addr{} }

// DialTCP creates a TCP connection through the real NIC, wrapped in a desyncConn.
// The desyncConn applies DPI evasion techniques to the first TLS ClientHello.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: p.bindControl,
	}
	if p.localIP.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: p.localIP.AsSlice()}
	}

	conn, err := dialer.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, err
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		// Shouldn't happen with tcp4 dial, but fallback gracefully.
		return conn, nil
	}

	p.mu.RLock()
	strategy := p.strategy
	p.mu.RUnlock()

	if strategy == nil || len(strategy.Ops) == 0 {
		return conn, nil
	}

	return newDesyncConn(tcpConn, strategy), nil
}

// DialUDP creates a connected UDP socket through the real NIC.
// No DPI desync is applied to UDP (QUIC bypass is future work).
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: p.bindControl,
	}
	if p.localIP.IsValid() {
		dialer.LocalAddr = &net.UDPAddr{IP: p.localIP.AsSlice()}
	}
	return dialer.DialContext(ctx, "udp4", addr)
}

// Name returns the provider display name.
func (p *Provider) Name() string { return p.name }

// Protocol returns the protocol identifier.
func (p *Provider) Protocol() string { return core.ProtocolDPIBypass }

// SetStrategy atomically replaces the current DPI bypass strategy.
// New connections will use the updated strategy; existing connections are unaffected.
func (p *Provider) SetStrategy(s *dpi.Strategy) {
	p.mu.Lock()
	p.strategy = s
	p.mu.Unlock()
	if s != nil {
		core.Log.Infof("DPI", "Strategy set: %q (%s, %d ops)", s.Name, s.Source, len(s.Ops))
	} else {
		core.Log.Infof("DPI", "Strategy cleared (pass-through)")
	}
}

// GetStrategy returns the currently active strategy (may be nil).
func (p *Provider) GetStrategy() *dpi.Strategy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.strategy
}
