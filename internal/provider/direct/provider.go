//go:build windows

package direct

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"awg-split-tunnel/internal/core"
)

const (
	ipUnicastIF   = 31 // IP_UNICAST_IF socket option
	ipv6UnicastIF = 31 // IPV6_UNICAST_IF socket option
)

// Provider implements TunnelProvider for direct (non-VPN) traffic.
// Routes traffic through the real NIC using IP_UNICAST_IF socket option
// and LocalAddr binding, bypassing the TUN adapter's default route.
type Provider struct {
	realNICIndex uint32
	localIP      netip.Addr // real NIC's own IPv4 address
	state        core.TunnelState
}

// New creates a DirectProvider that binds to the specified real NIC.
func New(realNICIndex uint32, localIP netip.Addr) *Provider {
	return &Provider{
		realNICIndex: realNICIndex,
		localIP:      localIP,
		state:        core.TunnelStateUp,
	}
}

// Connect is a no-op for DirectProvider (always up).
func (p *Provider) Connect(_ context.Context) error {
	p.state = core.TunnelStateUp
	log.Printf("[Direct] Provider ready (NIC index=%d, localIP=%s)", p.realNICIndex, p.localIP)
	return nil
}

// Disconnect is a no-op.
func (p *Provider) Disconnect() error {
	p.state = core.TunnelStateDown
	log.Printf("[Direct] Provider stopped")
	return nil
}

// State returns the current provider state.
func (p *Provider) State() core.TunnelState { return p.state }

// GetAdapterIP returns an invalid addr (no VPN adapter).
func (p *Provider) GetAdapterIP() netip.Addr { return netip.Addr{} }

// DialTCP creates a TCP connection through the real NIC.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: p.bindToRealNIC,
	}
	// Bind to real NIC's IP for belt-and-suspenders with IP_UNICAST_IF.
	if p.localIP.IsValid() {
		dialer.LocalAddr = &net.TCPAddr{IP: p.localIP.AsSlice()}
	}
	return dialer.DialContext(ctx, "tcp4", addr)
}

// DialUDP creates a connected UDP socket through the real NIC.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Control: p.bindToRealNIC,
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

// bindToRealNIC sets IP_UNICAST_IF on the raw socket to force traffic through the real NIC.
// This bypasses the TUN adapter's default route.
// Reference: refs/amneziawg-go/conn/bind_windows.go:585-601
func (p *Provider) bindToRealNIC(network, address string, c syscall.RawConn) error {
	var setErr error
	err := c.Control(func(fd uintptr) {
		handle := syscall.Handle(fd)

		// IP_UNICAST_IF needs interface index in network byte order for IPv4.
		var bytes [4]byte
		binary.BigEndian.PutUint32(bytes[:], p.realNICIndex)
		idx := *(*int32)(unsafe.Pointer(&bytes[0]))

		setErr = syscall.SetsockoptInt(handle, syscall.IPPROTO_IP, ipUnicastIF, int(idx))
	})
	if err != nil {
		return fmt.Errorf("[Direct] control: %w", err)
	}
	if setErr != nil {
		return fmt.Errorf("[Direct] IP_UNICAST_IF: %w", setErr)
	}
	return nil
}
