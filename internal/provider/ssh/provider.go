package ssh

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"

	gossh "golang.org/x/crypto/ssh"
)

// Config holds SSH tunnel-specific configuration.
type Config struct {
	// Server is the SSH server hostname or IP.
	Server string `yaml:"server"`
	// Port is the SSH server port (default 22).
	Port int `yaml:"port"`
	// Username for SSH authentication.
	Username string `yaml:"username"`
	// Password for SSH password authentication (optional).
	Password string `yaml:"password"`
	// PrivateKeyPath is the path to the SSH private key file (optional, supports ~ expansion).
	PrivateKeyPath string `yaml:"private_key_path"`
	// PrivateKeyPassphrase is the passphrase for the private key (optional).
	PrivateKeyPassphrase string `yaml:"private_key_passphrase"`
	// HostKey is the expected server host key in authorized_keys format (optional).
	// If empty and InsecureSkipHostKey is false, New() returns an error.
	HostKey string `yaml:"host_key"`
	// InsecureSkipHostKey disables host key verification (NOT recommended).
	InsecureSkipHostKey bool `yaml:"insecure_skip_host_key"`
	// KeepaliveInterval is the interval in seconds between keepalive probes (default 30).
	KeepaliveInterval int `yaml:"keepalive_interval"`
}

// Provider implements TunnelProvider for SSH tunnel protocol.
// TCP connections are forwarded through the SSH channel via DialTCP.
// UDP is not supported.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	serverAddr netip.AddrPort // resolved server endpoint for bypass routes
	client     *gossh.Client  // active SSH client connection
	cancelKA   context.CancelFunc
}

var _ provider.TunnelProvider = (*Provider)(nil)
var _ provider.EndpointProvider = (*Provider)(nil)

// New creates an SSH tunnel provider with the given configuration.
// Validates config and expands ~ in private key path. Does NOT perform DNS resolution.
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("[SSH] server address is required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("[SSH] username is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 22
	}
	if cfg.Port > 65535 {
		return nil, fmt.Errorf("[SSH] invalid port %d", cfg.Port)
	}
	if cfg.KeepaliveInterval <= 0 {
		cfg.KeepaliveInterval = 30
	}

	// Validate that at least one auth method is configured.
	if cfg.Password == "" && cfg.PrivateKeyPath == "" {
		return nil, fmt.Errorf("[SSH] at least one of password or private_key_path is required")
	}

	// Require explicit host key policy.
	if cfg.HostKey == "" && !cfg.InsecureSkipHostKey {
		return nil, fmt.Errorf("[SSH] host_key is required for secure connections; set insecure_skip_host_key: true to disable verification (NOT recommended)")
	}

	// Expand ~ in private key path.
	if cfg.PrivateKeyPath != "" {
		expanded, err := expandTilde(cfg.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("[SSH] expand private key path: %w", err)
		}
		cfg.PrivateKeyPath = expanded
	}

	return &Provider{
		config: cfg,
		name:   name,
		state:  core.TunnelStateDown,
	}, nil
}

// Connect establishes the SSH connection. Blocks until connected or ctx cancelled.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	serverStr := net.JoinHostPort(p.config.Server, fmt.Sprintf("%d", p.config.Port))
	core.Log.Infof("SSH", "Connecting tunnel %q to %s...", p.name, serverStr)

	// Resolve server address for bypass routes.
	p.serverAddr = netip.AddrPort{} // reset
	if ap, err := netip.ParseAddrPort(serverStr); err == nil {
		p.serverAddr = ap
	} else {
		ips, err := net.DefaultResolver.LookupHost(ctx, p.config.Server)
		if err != nil {
			p.state = core.TunnelStateError
			return fmt.Errorf("[SSH] resolve %q: %w", p.config.Server, err)
		}
		if len(ips) > 0 {
			if addr, err2 := netip.ParseAddr(ips[0]); err2 == nil {
				p.serverAddr = netip.AddrPortFrom(addr, uint16(p.config.Port))
			}
		}
	}

	// Build auth methods.
	authMethods, err := p.buildAuthMethods()
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[SSH] build auth: %w", err)
	}

	// Build host key callback.
	hostKeyCallback, err := p.buildHostKeyCallback()
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[SSH] host key callback: %w", err)
	}

	sshConfig := &gossh.ClientConfig{
		User:            p.config.Username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	// Dial with context support.
	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, "tcp", serverStr)
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[SSH] TCP dial %s: %w", serverStr, err)
	}

	// Perform SSH handshake over the TCP connection.
	c, chans, reqs, err := gossh.NewClientConn(tcpConn, serverStr, sshConfig)
	if err != nil {
		tcpConn.Close()
		p.state = core.TunnelStateError
		return fmt.Errorf("[SSH] handshake with %s: %w", serverStr, err)
	}

	p.client = gossh.NewClient(c, chans, reqs)
	p.state = core.TunnelStateUp

	// Start keepalive goroutine.
	kaCtx, kaCancel := context.WithCancel(context.Background())
	p.cancelKA = kaCancel
	go p.keepalive(kaCtx, p.client)

	core.Log.Infof("SSH", "Tunnel %q is UP (server=%s)", p.name, serverStr)
	return nil
}

// Disconnect tears down the SSH connection.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cancelKA != nil {
		p.cancelKA()
		p.cancelKA = nil
	}

	if p.client != nil {
		p.client.Close()
		p.client = nil
	}

	p.state = core.TunnelStateDown
	core.Log.Infof("SSH", "Tunnel %q disconnected", p.name)
	return nil
}

// State returns the current tunnel state.
func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

// GetAdapterIP returns an invalid address — SSH tunnel has no local VPN adapter IP.
func (p *Provider) GetAdapterIP() netip.Addr {
	return netip.Addr{}
}

// DialTCP creates a TCP connection through the SSH tunnel to the given address.
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	client := p.client
	p.mu.RUnlock()

	if state != core.TunnelStateUp || client == nil {
		return nil, fmt.Errorf("[SSH] tunnel %q is not up (state=%d)", p.name, state)
	}

	// gossh.Client.Dial does not accept a context, so we race it against ctx.
	type dialResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan dialResult, 1)
	go func() {
		conn, err := client.Dial("tcp", addr)
		ch <- dialResult{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-ch:
		return res.conn, res.err
	}
}

// DialUDP returns an error — SSH tunnel does not support UDP.
func (p *Provider) DialUDP(_ context.Context, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("[SSH] UDP not supported")
}

// Name returns the human-readable tunnel name.
func (p *Provider) Name() string {
	return p.name
}

// Protocol returns "ssh".
func (p *Provider) Protocol() string {
	return core.ProtocolSSH
}

// GetServerEndpoints returns the SSH server endpoint for bypass route management.
// Implements provider.EndpointProvider.
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.serverAddr.IsValid() {
		return []netip.AddrPort{p.serverAddr}
	}
	return nil
}

// ---------- internal helpers ----------

// keepalive sends periodic keepalive requests to the SSH server.
// On failure, it marks the tunnel state as Error and returns.
func (p *Provider) keepalive(ctx context.Context, client *gossh.Client) {
	ticker := time.NewTicker(time.Duration(p.config.KeepaliveInterval) * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0
	const maxFailures = 3

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				consecutiveFailures++
				core.Log.Warnf("SSH", "Keepalive failed for tunnel %q (attempt %d/%d): %v",
					p.name, consecutiveFailures, maxFailures, err)
				if consecutiveFailures >= maxFailures {
					core.Log.Errorf("SSH", "Tunnel %q keepalive lost after %d failures, marking as Error",
						p.name, maxFailures)
					p.mu.Lock()
					p.state = core.TunnelStateError
					p.mu.Unlock()
					return
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
}

// buildAuthMethods constructs SSH authentication methods from the config.
func (p *Provider) buildAuthMethods() ([]gossh.AuthMethod, error) {
	var methods []gossh.AuthMethod

	// Public key authentication.
	if p.config.PrivateKeyPath != "" {
		keyData, err := os.ReadFile(p.config.PrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read private key %q: %w", p.config.PrivateKeyPath, err)
		}

		var signer gossh.Signer
		if p.config.PrivateKeyPassphrase != "" {
			signer, err = gossh.ParsePrivateKeyWithPassphrase(keyData, []byte(p.config.PrivateKeyPassphrase))
		} else {
			signer, err = gossh.ParsePrivateKey(keyData)
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key %q: %w", p.config.PrivateKeyPath, err)
		}

		methods = append(methods, gossh.PublicKeys(signer))
	}

	// Password authentication.
	if p.config.Password != "" {
		methods = append(methods, gossh.Password(p.config.Password))
	}

	return methods, nil
}

// buildHostKeyCallback constructs the host key verification callback.
func (p *Provider) buildHostKeyCallback() (gossh.HostKeyCallback, error) {
	if p.config.HostKey != "" {
		pubKey, _, _, _, err := gossh.ParseAuthorizedKey([]byte(p.config.HostKey))
		if err != nil {
			return nil, fmt.Errorf("parse host_key: %w", err)
		}
		return gossh.FixedHostKey(pubKey), nil
	}

	// InsecureSkipHostKey must be true here (validated in New).
	core.Log.Warnf("SSH", "Host key verification DISABLED for tunnel %q — vulnerable to MITM attacks", p.name)
	return gossh.InsecureIgnoreHostKey(), nil //nolint:gosec // user explicitly opted in
}

// expandTilde replaces a leading ~ with the user's home directory.
func expandTilde(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, path[1:]), nil
}
