package hysteria2

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"

	hyclient "github.com/apernet/hysteria/core/v2/client"
)

// Config holds Hysteria2-specific tunnel configuration.
type Config struct {
	// Server is the Hysteria2 server address in host:port format.
	Server string `yaml:"server"`
	// Password is the authentication password.
	Password string `yaml:"password"`
	// ObfsType is the obfuscation type ("" for none, "salamander" for Salamander XOR).
	ObfsType string `yaml:"obfs_type"`
	// ObfsPassword is the password for obfuscation (required if ObfsType is set).
	ObfsPassword string `yaml:"obfs_password"`
	// SNI is the TLS server name indication (defaults to server hostname).
	SNI string `yaml:"sni"`
	// Insecure disables TLS certificate verification.
	Insecure bool `yaml:"insecure"`
	// UpMbps is the upload bandwidth hint in Mbps (0 = auto/BBR).
	UpMbps int `yaml:"up_mbps"`
	// DownMbps is the download bandwidth hint in Mbps (0 = auto/BBR).
	DownMbps int `yaml:"down_mbps"`
}

// Provider implements TunnelProvider for Hysteria2 (QUIC-based) protocol.
// Traffic is proxied through the Hysteria2 server via DialTCP/DialUDP.
// Does NOT implement RawForwarder — not an IP-level tunnel.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	serverAddr netip.AddrPort      // resolved endpoint for bypass routes
	client     hyclient.Client     // hysteria2 QUIC client
	udpEnabled bool                // whether server supports UDP
}

// New creates a Hysteria2 provider with the given configuration.
// DNS resolution is deferred to Connect().
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("[Hysteria2] server address is required")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("[Hysteria2] password is required")
	}
	if cfg.ObfsType != "" && cfg.ObfsType != "salamander" {
		return nil, fmt.Errorf("[Hysteria2] unsupported obfuscation type %q (only \"salamander\" is supported)", cfg.ObfsType)
	}
	if cfg.ObfsType == "salamander" && cfg.ObfsPassword == "" {
		return nil, fmt.Errorf("[Hysteria2] obfs_password is required when obfs_type is \"salamander\"")
	}

	return &Provider{
		config: cfg,
		name:   name,
		state:  core.TunnelStateDown,
	}, nil
}

// Connect establishes the Hysteria2 QUIC connection to the server.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	core.Log.Infof("Hysteria2", "Connecting tunnel %q to %s...", p.name, p.config.Server)

	// Parse or resolve server address.
	host, portStr, err := net.SplitHostPort(p.config.Server)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[Hysteria2] invalid server address %q: %w", p.config.Server, err)
	}

	// Resolve server IP for bypass routes.
	serverAddr, err := resolveAddrPort(ctx, host, portStr)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[Hysteria2] resolve %q: %w", p.config.Server, err)
	}
	p.serverAddr = serverAddr

	// Determine SNI.
	sni := p.config.SNI
	if sni == "" {
		sni = host
	}

	// Build hysteria2 client config.
	hyConfig := &hyclient.Config{
		ServerAddr: net.UDPAddrFromAddrPort(serverAddr),
		Auth:       p.config.Password,
		TLSConfig: hyclient.TLSConfig{
			ServerName:         sni,
			InsecureSkipVerify: p.config.Insecure,
		},
		BandwidthConfig: hyclient.BandwidthConfig{
			MaxTx: mbpsToBps(p.config.UpMbps),
			MaxRx: mbpsToBps(p.config.DownMbps),
		},
		FastOpen: true,
	}

	// Set up obfuscation via custom ConnFactory if salamander is requested.
	if p.config.ObfsType == "salamander" {
		hyConfig.ConnFactory = &salamanderConnFactory{
			password: p.config.ObfsPassword,
		}
	}

	// Create the hysteria2 client (performs QUIC handshake + auth).
	client, info, err := hyclient.NewClient(hyConfig)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[Hysteria2] connect failed: %w", err)
	}

	p.client = client
	p.udpEnabled = info.UDPEnabled
	p.state = core.TunnelStateUp

	txInfo := "BBR"
	if info.Tx > 0 {
		txInfo = fmt.Sprintf("%d Mbps", info.Tx*8/1_000_000)
	}
	core.Log.Infof("Hysteria2", "Tunnel %q is UP (server=%s, udp=%v, tx=%s)",
		p.name, p.serverAddr, p.udpEnabled, txInfo)
	return nil
}

// Disconnect tears down the Hysteria2 QUIC connection.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		_ = p.client.Close()
		p.client = nil
	}
	p.state = core.TunnelStateDown
	core.Log.Infof("Hysteria2", "Tunnel %q disconnected", p.name)
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns an invalid address — Hysteria2 has no local VPN adapter IP.
func (p *Provider) GetAdapterIP() netip.Addr {
	return netip.Addr{}
}

// DialTCP creates a TCP connection through the Hysteria2 tunnel.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	client := p.client
	p.mu.RUnlock()

	if state != core.TunnelStateUp || client == nil {
		return nil, fmt.Errorf("[Hysteria2] tunnel %q is not up (state=%d)", p.name, state)
	}

	conn, err := client.TCP(addr)
	if err != nil {
		// Check if the error indicates the connection is permanently closed.
		// If so, transition to error state so tunnel controller can reconnect.
		p.markErrorIfClosed(err)
		return nil, fmt.Errorf("[Hysteria2] TCP dial %s: %w", addr, err)
	}
	return conn, nil
}

// DialUDP creates a UDP connection through the Hysteria2 tunnel.
// The Hysteria2 HyUDPConn is wrapped in a net.Conn adapter for compatibility.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	client := p.client
	udpEnabled := p.udpEnabled
	p.mu.RUnlock()

	if state != core.TunnelStateUp || client == nil {
		return nil, fmt.Errorf("[Hysteria2] tunnel %q is not up (state=%d)", p.name, state)
	}
	if !udpEnabled {
		return nil, provider.ErrUDPNotSupported
	}

	hyUDP, err := client.UDP()
	if err != nil {
		p.markErrorIfClosed(err)
		return nil, fmt.Errorf("[Hysteria2] UDP session: %w", err)
	}

	return &udpConnAdapter{
		hyConn:   hyUDP,
		target:   addr,
		deadline: time.Time{},
	}, nil
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "hysteria2".
func (p *Provider) Protocol() string {
	return core.ProtocolHysteria2
}

// GetServerEndpoints returns the Hysteria2 server endpoint for bypass route management.
// Implements provider.EndpointProvider.
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.serverAddr.IsValid() {
		return []netip.AddrPort{p.serverAddr}
	}
	return nil
}

// markErrorIfClosed checks if the error signals a closed connection and transitions
// the provider to Error state so that the tunnel controller triggers reconnection.
func (p *Provider) markErrorIfClosed(err error) {
	// hysteria2 wraps permanent errors as errors.ClosedError.
	// Any error from TCP/UDP calls when connection is dead will trigger this.
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.state == core.TunnelStateUp {
		p.state = core.TunnelStateError
		core.Log.Warnf("Hysteria2", "Tunnel %q connection lost: %v", p.name, err)
	}
}

// --- Helpers ---

// resolveAddrPort resolves a host:port string to a netip.AddrPort.
func resolveAddrPort(ctx context.Context, host, port string) (netip.AddrPort, error) {
	// Try parsing as an IP first (no DNS needed).
	addrPort := net.JoinHostPort(host, port)
	if ap, err := netip.ParseAddrPort(addrPort); err == nil {
		return ap, nil
	}

	// Resolve hostname.
	ips, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no addresses found for %q", host)
	}

	addr, err := netip.ParseAddr(ips[0])
	if err != nil {
		return netip.AddrPort{}, err
	}

	portNum, err := net.DefaultResolver.LookupPort(ctx, "udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(addr, uint16(portNum)), nil
}

// mbpsToBps converts megabits per second to bytes per second.
// Returns 0 if mbps is 0 (meaning auto/BBR).
func mbpsToBps(mbps int) uint64 {
	if mbps <= 0 {
		return 0
	}
	return uint64(mbps) * 1_000_000 / 8
}

// --- UDP Connection Adapter ---

// udpConnAdapter wraps HyUDPConn into a net.Conn interface.
// It binds to a specific target address for transparent proxy compatibility.
type udpConnAdapter struct {
	hyConn   hyclient.HyUDPConn
	target   string
	mu       sync.Mutex
	closed   bool
	deadline time.Time
}

func (u *udpConnAdapter) Read(b []byte) (int, error) {
	data, _, err := u.hyConn.Receive()
	if err != nil {
		return 0, err
	}
	n := copy(b, data)
	return n, nil
}

func (u *udpConnAdapter) Write(b []byte) (int, error) {
	err := u.hyConn.Send(b, u.target)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (u *udpConnAdapter) Close() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return nil
	}
	u.closed = true
	return u.hyConn.Close()
}

func (u *udpConnAdapter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 0}
}

func (u *udpConnAdapter) RemoteAddr() net.Addr {
	addr, _ := net.ResolveUDPAddr("udp", u.target)
	if addr != nil {
		return addr
	}
	return &net.UDPAddr{}
}

func (u *udpConnAdapter) SetDeadline(t time.Time) error {
	u.deadline = t
	return nil
}

func (u *udpConnAdapter) SetReadDeadline(t time.Time) error {
	return nil // HyUDPConn does not support deadlines
}

func (u *udpConnAdapter) SetWriteDeadline(t time.Time) error {
	return nil // HyUDPConn does not support deadlines
}

// --- Salamander Obfuscation ---

// salamanderConnFactory implements hyclient.ConnFactory with Salamander XOR obfuscation.
// Each UDP packet is XOR'd with a key derived from SHA-256(password).
type salamanderConnFactory struct {
	password string
}

func (f *salamanderConnFactory) New(addr net.Addr) (net.PacketConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	key := sha256.Sum256([]byte(f.password))
	return &salamanderConn{
		UDPConn: conn,
		key:     key[:],
	}, nil
}

// salamanderConn wraps a UDP connection with Salamander XOR obfuscation.
type salamanderConn struct {
	*net.UDPConn
	key []byte
}

func (c *salamanderConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if err != nil {
		return n, addr, err
	}
	xorBytes(b[:n], c.key)
	return n, addr, nil
}

func (c *salamanderConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Make a copy to avoid mutating the caller's buffer.
	buf := make([]byte, len(b))
	copy(buf, b)
	xorBytes(buf, c.key)
	return c.UDPConn.WriteTo(buf, addr)
}

// xorBytes XORs data in-place with the key (repeating the key as needed).
func xorBytes(data, key []byte) {
	kl := len(key)
	if kl == 0 {
		return
	}
	// Process 8 bytes at a time for performance.
	if kl >= 8 {
		keyU64 := binary.LittleEndian.Uint64(key[:8])
		i := 0
		for ; i+8 <= len(data); i += 8 {
			v := binary.LittleEndian.Uint64(data[i : i+8])
			binary.LittleEndian.PutUint64(data[i:i+8], v^keyU64)
		}
		for ; i < len(data); i++ {
			data[i] ^= key[i%kl]
		}
	} else {
		for i := range data {
			data[i] ^= key[i%kl]
		}
	}
}

// Compile-time interface checks.
var (
	_ provider.TunnelProvider = (*Provider)(nil)
	_ provider.EndpointProvider = (*Provider)(nil)
)
