package anyconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/platform"
)

// loadClientCert loads a TLS client certificate+key pair if configured.
func loadClientCert(cfg Config) ([]tls.Certificate, error) {
	if cfg.ClientCert == "" || cfg.ClientCert == "auto" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return nil, fmt.Errorf("load client cert: %w", err)
	}
	core.Log.Infof("AnyConnect", "Client certificate loaded from %s", cfg.ClientCert)
	return []tls.Certificate{cert}, nil
}

// Provider implements provider.TunnelProvider, provider.RawForwarder,
// provider.EndpointProvider, provider.SplitRouteProvider, and provider.AuthParamSetter
// for the Cisco AnyConnect (CSTP) protocol.
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	cid      clientID         // effective client identity (UA, version, device type)
	tlsCerts []tls.Certificate // client certificate for mutual TLS (optional)

	adapterIP       netip.Addr
	serverEndpoints []netip.AddrPort
	splitInclude    []netip.Prefix
	splitExclude    []netip.Prefix
	dns             []string

	// authParams holds ephemeral auth params (e.g. otp_code) set at connect time.
	// Not persisted to config. Cleared after each Connect attempt.
	authParams map[string]string

	// Real NIC info for bypassing TUN DNS and routing.
	realNICIndex uint32
	binder       platform.InterfaceBinder

	// pendingUDP tracks virtual UDP connections created by DialUDP.
	// Key: local ephemeral port, Value: *rawUDPConn.
	pendingUDP sync.Map

	// onSessionDrop is called when the CSTP session drops unexpectedly.
	// Set by the tunnel controller to propagate state changes.
	onSessionDrop func(tunnelID string, err error)

	cstp   *cstpConn
	cancel context.CancelFunc
}

// New creates a new AnyConnect provider.
func New(name string, cfg Config) (*Provider, error) {
	if cfg.Server == "" {
		return nil, fmt.Errorf("anyconnect: server is required")
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}
	certs, err := loadClientCert(cfg)
	if err != nil {
		return nil, err
	}
	return &Provider{
		name:     name,
		config:   cfg,
		state:    core.TunnelStateDown,
		cid:      resolveClientID(cfg.UserAgent),
		tlsCerts: certs,
	}, nil
}

func (p *Provider) Name() string    { return p.name }
func (p *Provider) Protocol() string { return "anyconnect" }

// SetAuthParams implements provider.AuthParamSetter.
// Called before Connect() to pass ephemeral credentials like OTP codes.
func (p *Provider) SetAuthParams(params map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authParams = params
}

// SetRealNICIndex sets the real NIC interface index for DNS resolution bypass.
func (p *Provider) SetRealNICIndex(index uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.realNICIndex = index
}

// SetInterfaceBinder sets the platform-specific interface binder.
func (p *Provider) SetInterfaceBinder(binder platform.InterfaceBinder) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.binder = binder
}

// SetOnSessionDrop sets a callback invoked when the CSTP session drops unexpectedly.
func (p *Provider) SetOnSessionDrop(fn func(tunnelID string, err error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onSessionDrop = fn
}

func (p *Provider) State() core.TunnelState {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.state
}

func (p *Provider) GetAdapterIP() netip.Addr {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.adapterIP
}

// GetServerEndpoints implements provider.EndpointProvider.
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.serverEndpoints
}

// GetSplitInclude returns routes that should be routed through this tunnel.
func (p *Provider) GetSplitInclude() []netip.Prefix {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.splitInclude
}

// GetSplitExclude returns routes that should NOT be routed through this tunnel.
func (p *Provider) GetSplitExclude() []netip.Prefix {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.splitExclude
}

// GetDNS returns DNS servers assigned by the VPN server.
func (p *Provider) GetDNS() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.dns
}

// Connect establishes the AnyConnect VPN tunnel.
func (p *Provider) Connect(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.state = core.TunnelStateConnecting
	core.Log.Infof("AnyConnect", "Connecting tunnel %q to %s:%d...", p.name, p.config.Server, p.config.Port)

	// 1. Resolve server address via real NIC (bypass TUN DNS / FakeIP).
	realNICIndex := p.realNICIndex
	binder := p.binder

	var controlFn func(string, string, syscall.RawConn) error
	if binder != nil && realNICIndex > 0 {
		controlFn = binder.BindControl(realNICIndex)
	}

	// Prepare credentials (consume OTP early so it's never reused).
	creds := credentials{
		Username: p.config.Username,
		Password: p.config.Password,
		Group:    p.config.Group,
	}
	if p.authParams != nil {
		if otp, ok := p.authParams["otp_code"]; ok {
			creds.OTPCode = otp
		}
		p.authParams = nil
	}

	// Auth loop: may retry on cross-host redirects.
	server := p.config.Server
	port := p.config.Port
	var sess *sessionInfo
	var tlsConn *tls.Conn
	var br *bufio.Reader

	for attempt := 0; attempt < maxRedirects; attempt++ {
		serverIP, err := p.resolveViaRealNIC(ctx, server, realNICIndex, controlFn)
		if err != nil {
			p.state = core.TunnelStateError
			return fmt.Errorf("[AnyConnect] resolve %s: %w", server, err)
		}
		serverAddr := fmt.Sprintf("%s:%d", serverIP, port)
		if ip, ok := netip.AddrFromSlice(net.ParseIP(serverIP)); ok {
			p.serverEndpoints = []netip.AddrPort{netip.AddrPortFrom(ip, uint16(port))}
		}

		// TLS dial via real NIC.
		dialer := &net.Dialer{Timeout: 15 * time.Second, Control: controlFn}
		tlsCfg := &tls.Config{
			InsecureSkipVerify: p.config.TLSSkipVerify,
			ServerName:         server,
		}
		if len(p.tlsCerts) > 0 {
			// Explicit cert file(s) provided.
			tlsCfg.Certificates = p.tlsCerts
		} else if p.config.ClientCert == "auto" {
			// Auto-discover from system certificate store.
			core.Log.Infof("AnyConnect", "Client cert mode: auto (system store)")
			tlsCfg.GetClientCertificate = findSystemCertificate
		}
		tlsConn, err = tls.DialWithDialer(dialer, "tcp", serverAddr, tlsCfg)
		if err != nil {
			p.state = core.TunnelStateError
			return fmt.Errorf("[AnyConnect] TLS dial: %w", err)
		}

		br = bufio.NewReader(tlsConn)

		core.Log.Infof("AnyConnect", "Authenticating as %q on %s...", p.config.Username, server)
		sess, err = authenticate(br, tlsConn, server, creds, p.cid)
		if err != nil {
			tlsConn.Close()
			// Cross-host redirect — reconnect to the new server.
			var re *RedirectError
			if errors.As(err, &re) {
				core.Log.Infof("AnyConnect", "Following cross-host redirect to %s", re.Host)
				server = re.Host
				if re.Port != "" {
					if p, err := strconv.Atoi(re.Port); err == nil {
						port = p
					}
				}
				continue
			}
			p.state = core.TunnelStateError
			return fmt.Errorf("[AnyConnect] auth: %w", err)
		}
		break
	}
	if sess == nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[AnyConnect] auth: too many redirects")
	}
	core.Log.Infof("AnyConnect", "Authentication successful")

	// 4. Establish CSTP tunnel.
	params, err := establishTunnel(br, tlsConn, server, sess.Cookie, p.cid)
	if err != nil {
		tlsConn.Close()
		p.state = core.TunnelStateError
		return fmt.Errorf("[AnyConnect] tunnel: %w", err)
	}

	core.Log.Infof("AnyConnect", "Tunnel established: IP=%s MTU=%d DNS=%v routes=%d",
		params.Address, params.MTU, params.DNS, len(params.SplitInclude))

	// 5. Store tunnel parameters.
	p.adapterIP = params.Address
	p.splitInclude = params.SplitInclude
	p.splitExclude = params.SplitExclude
	p.dns = params.DNS

	// 6. Start CSTP connection (read/write loops).
	cctx, ccancel := context.WithCancel(context.Background())
	_ = cctx
	p.cancel = ccancel
	p.cstp = newCSTPConn(tlsConn, br, *params, ccancel)

	// Detect session drops (server disconnect, timeout, I/O error).
	onDrop := p.onSessionDrop
	tunnelName := p.name
	p.cstp.onDisconnect = func(err error) {
		core.Log.Warnf("AnyConnect", "CSTP session dropped for %q: %v", tunnelName, err)
		p.mu.Lock()
		p.state = core.TunnelStateError
		p.cstp = nil
		p.mu.Unlock()
		if onDrop != nil {
			onDrop(tunnelName, err)
		}
	}

	p.cstp.run()

	p.state = core.TunnelStateUp
	core.Log.Infof("AnyConnect", "Tunnel %q is UP", p.name)
	return nil
}

// Disconnect tears down the VPN tunnel.
func (p *Provider) Disconnect() error {
	// Extract cstp and cancel under the lock, then release before calling
	// stop(). stop() waits for readLoop to finish, and readLoop's
	// onDisconnect callback also acquires p.mu — holding the lock here
	// would deadlock.
	p.mu.Lock()
	c := p.cstp
	p.cstp = nil
	cancel := p.cancel
	p.cancel = nil
	p.mu.Unlock()

	if c != nil {
		// Mark as clean shutdown so the readLoop's deferred onDisconnect
		// does not fire a spurious session-drop / EventAuthRequired.
		c.cleanShutdown.Store(true)
		c.stop()
	}
	if cancel != nil {
		cancel()
	}

	p.mu.Lock()
	p.state = core.TunnelStateDown
	p.adapterIP = netip.Addr{}
	p.mu.Unlock()

	core.Log.Infof("AnyConnect", "Tunnel %q disconnected", p.name)
	return nil
}

// ---- RawForwarder interface ----

// InjectOutbound sends an IP packet through the CSTP tunnel.
func (p *Provider) InjectOutbound(pkt []byte) bool {
	p.mu.RLock()
	c := p.cstp
	p.mu.RUnlock()

	if c == nil {
		return false
	}
	return c.sendData(pkt)
}

// InjectOutboundPriority sends an IP packet with priority (priority is ignored for CSTP).
func (p *Provider) InjectOutboundPriority(pkt []byte, _ byte) bool {
	return p.InjectOutbound(pkt)
}

// SetInboundHandler registers a callback for incoming IP packets from the tunnel.
// Wraps the handler with a DNS response interceptor for DialUDP connections.
func (p *Provider) SetInboundHandler(handler func(pkt []byte) bool) {
	wrapped := func(pkt []byte) bool {
		if p.interceptInbound(pkt) {
			return true
		}
		return handler(pkt)
	}

	p.mu.RLock()
	c := p.cstp
	p.mu.RUnlock()

	if c != nil {
		c.inboundHandler.Store(&wrapped)
	}
}

// resolveViaRealNIC resolves a hostname using a DNS resolver bound to the real NIC,
// bypassing the TUN DNS resolver (FakeIP).
func (p *Provider) resolveViaRealNIC(ctx context.Context, host string, realNICIndex uint32, controlFn func(string, string, syscall.RawConn) error) (string, error) {
	// If it's already an IP, return as-is.
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	if realNICIndex > 0 {
		core.Log.Debugf("AnyConnect", "Resolving %q via real NIC (index=%d)", host, realNICIndex)
	}

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Control: controlFn}
			return dialer.DialContext(ctx, network, "8.8.8.8:53")
		},
	}

	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return "", fmt.Errorf("DNS resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("DNS resolve %q: no addresses", host)
	}
	core.Log.Infof("AnyConnect", "Resolved %q via real NIC → %s", host, ips[0])
	return ips[0], nil
}

// ---- DialTCP / DialUDP ----
// AnyConnect provider uses RawForwarder for IP-level forwarding.
// DialTCP/DialUDP are not used when RawForwarder is available.

func (p *Provider) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("anyconnect: DialTCP not supported, use RawForwarder")
}

// DialUDP is implemented in dial_udp.go via raw IP packet injection through CSTP.
