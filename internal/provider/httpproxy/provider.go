package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"
)

// Config holds HTTP proxy-specific tunnel configuration.
type Config struct {
	// Server is the HTTP proxy hostname or IP.
	Server string `yaml:"server"`
	// Port is the HTTP proxy port.
	Port int `yaml:"port"`
	// Username for proxy authentication (Basic auth, optional).
	Username string `yaml:"username"`
	// Password for proxy authentication (Basic auth, optional).
	Password string `yaml:"password"`
	// TLS enables HTTPS proxy (CONNECT over TLS).
	TLS bool `yaml:"tls"`
	// TLSSkipVerify disables TLS certificate verification (insecure).
	TLSSkipVerify bool `yaml:"tls_skip_verify"`
}

// Provider implements TunnelProvider for HTTP CONNECT proxy protocol.
// Only supports TCP — DialUDP returns ErrUDPNotSupported.
// Does NOT implement RawForwarder — not an IP-level tunnel.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	serverAddr netip.AddrPort // resolved server endpoint for bypass routes
}

// New creates an HTTP proxy provider with the given configuration.
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("[HTTP] server address is required")
	}
	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, fmt.Errorf("[HTTP] invalid port %d", cfg.Port)
	}

	return &Provider{
		config: cfg,
		name:   name,
		state:  core.TunnelStateDown,
	}, nil
}

// Connect validates that the HTTP proxy server is reachable.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	core.Log.Infof("HTTP", "Connecting tunnel %q to %s:%d...", p.name, p.config.Server, p.config.Port)

	serverStr := fmt.Sprintf("%s:%d", p.config.Server, p.config.Port)

	// Resolve server address for bypass routes.
	if ap, err := netip.ParseAddrPort(serverStr); err == nil {
		p.serverAddr = ap
	} else {
		ips, err := net.DefaultResolver.LookupHost(ctx, p.config.Server)
		if err != nil {
			p.state = core.TunnelStateError
			return fmt.Errorf("[HTTP] resolve %q: %w", p.config.Server, err)
		}
		if len(ips) > 0 {
			if addr, err := netip.ParseAddr(ips[0]); err == nil {
				p.serverAddr = netip.AddrPortFrom(addr, uint16(p.config.Port))
			}
		}
	}

	// Probe: verify the proxy is reachable.
	probeConn, err := net.DialTimeout("tcp", serverStr, 10*time.Second)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[HTTP] server unreachable at %s: %w", serverStr, err)
	}
	probeConn.Close()

	p.state = core.TunnelStateUp
	core.Log.Infof("HTTP", "Tunnel %q is UP (server=%s, tls=%v)", p.name, serverStr, p.config.TLS)
	return nil
}

// Disconnect tears down the HTTP proxy connection state.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateDown
	core.Log.Infof("HTTP", "Tunnel %q disconnected", p.name)
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns an invalid address — HTTP proxy has no local VPN adapter IP.
func (p *Provider) GetAdapterIP() netip.Addr {
	return netip.Addr{}
}

// DialTCP creates a TCP connection through the HTTP proxy via HTTP CONNECT.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	p.mu.RUnlock()

	if state != core.TunnelStateUp {
		return nil, fmt.Errorf("[HTTP] tunnel %q is not up (state=%d)", p.name, state)
	}

	serverStr := fmt.Sprintf("%s:%d", p.config.Server, p.config.Port)

	// Connect to the proxy server.
	d := net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := d.DialContext(ctx, "tcp", serverStr)
	if err != nil {
		return nil, fmt.Errorf("[HTTP] connect to proxy: %w", err)
	}

	// Wrap in TLS if configured.
	var conn net.Conn = rawConn
	if p.config.TLS {
		tlsConn := tls.Client(rawConn, &tls.Config{
			ServerName:         p.config.Server,
			InsecureSkipVerify: p.config.TLSSkipVerify,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("[HTTP] TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	// Send HTTP CONNECT request.
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if p.config.Username != "" {
		creds := base64.StdEncoding.EncodeToString(
			[]byte(p.config.Username + ":" + p.config.Password),
		)
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", creds)
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("[HTTP] send CONNECT: %w", err)
	}

	// Read response.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("[HTTP] read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("[HTTP] CONNECT failed: %s", resp.Status)
	}

	// If there's buffered data in the reader, wrap the connection.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: br}, nil
	}

	return conn, nil
}

// DialUDP is not supported by HTTP CONNECT proxy.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	return nil, provider.ErrUDPNotSupported
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "httpproxy".
func (p *Provider) Protocol() string {
	return "httpproxy"
}

// GetServerEndpoints returns the HTTP proxy server endpoint for bypass route management.
// Implements provider.EndpointProvider.
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	if p.serverAddr.IsValid() {
		return []netip.AddrPort{p.serverAddr}
	}
	return nil
}

// bufferedConn wraps a net.Conn with a buffered reader to handle data
// that was read during the HTTP response parsing.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}
