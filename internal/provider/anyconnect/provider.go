package anyconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/platform"

	"golang.org/x/crypto/pkcs12"
)

// loadClientCert loads a TLS client certificate from the configured path.
// Supported formats:
//   - .p12/.pfx   — PKCS12 bundle (cert + private key, optionally password-protected)
//   - .cer/.crt/.der — DER/PEM certificate only; private key is looked up in the system store
//   - .pem        — if ClientKey is set, loads cert+key as separate PEM files;
//                    if ClientKey is empty, expects both cert and key blocks in one file
func loadClientCert(cfg Config) ([]tls.Certificate, error) {
	if cfg.ClientCert == "" || cfg.ClientCert == "auto" {
		return nil, nil
	}

	ext := strings.ToLower(filepath.Ext(cfg.ClientCert))

	switch ext {
	case ".p12", ".pfx":
		return loadPKCS12Cert(cfg.ClientCert, cfg.ClientCertPassword)

	case ".cer", ".crt", ".der":
		return loadCertWithSystemKey(cfg.ClientCert)

	default:
		// PEM format: single file (cert+key) or two separate files.
		keyFile := cfg.ClientKey
		if keyFile == "" {
			// Try single PEM file containing both CERTIFICATE and PRIVATE KEY blocks.
			keyFile = cfg.ClientCert
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, keyFile)
		if err != nil {
			if cfg.ClientKey == "" {
				return nil, fmt.Errorf("load client cert from %s: %w (hint: file must contain both CERTIFICATE and PRIVATE KEY PEM blocks, "+
					"or set client_key to a separate key file)", cfg.ClientCert, err)
			}
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		core.Log.Infof("AnyConnect", "Client certificate loaded from PEM %s", cfg.ClientCert)
		return []tls.Certificate{cert}, nil
	}
}

// loadPKCS12Cert loads a PKCS12/PFX file containing certificate, private key,
// and optionally intermediate CA certificates (full chain).
func loadPKCS12Cert(path, password string) ([]tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read PKCS12 file %s: %w", path, err)
	}

	// ToPEM extracts ALL items from the PKCS12: private key, leaf cert, and CA certs.
	// This preserves the full certificate chain, unlike pkcs12.Decode which only
	// returns the leaf.
	pemBlocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, fmt.Errorf("decode PKCS12 %s: %w (check password)", path, err)
	}

	// Encode all PEM blocks into a single byte slice.
	// tls.X509KeyPair will find all CERTIFICATE blocks (building the chain)
	// and the PRIVATE KEY block automatically.
	var pemData []byte
	for _, block := range pemBlocks {
		pemData = append(pemData, pem.EncodeToMemory(block)...)
	}

	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS12 key pair %s: %w", path, err)
	}

	if cert.Leaf == nil && len(cert.Certificate) > 0 {
		cert.Leaf, _ = x509.ParseCertificate(cert.Certificate[0])
	}
	if cert.Leaf != nil {
		core.Log.Infof("AnyConnect", "Client certificate loaded from PKCS12 %s (subject=%q, chain=%d certs)",
			path, cert.Leaf.Subject.CommonName, len(cert.Certificate))
	}
	return []tls.Certificate{cert}, nil
}

// loadCertWithSystemKey loads a DER/PEM certificate file and finds the matching
// private key in the system certificate store (Windows Cert Store / macOS Keychain).
// This handles the common Cisco AnyConnect scenario where the admin distributes
// only a .cer file and the private key was generated on-device via enrollment.
func loadCertWithSystemKey(certPath string) ([]tls.Certificate, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate file %s: %w", certPath, err)
	}

	// Try PEM decode first, fall back to raw DER.
	var certDER []byte
	if block, _ := pem.Decode(data); block != nil {
		certDER = block.Bytes
	} else {
		certDER = data // assume raw DER
	}

	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", certPath, err)
	}

	// Look up the matching private key and certificate chain in the system store.
	// findSystemKeyAndChain returns the signer and the full chain (leaf + intermediates).
	signer, chain, err := findSystemKeyAndChain(certDER)
	if err != nil {
		return nil, fmt.Errorf("find private key in system store for %s (subject=%q): %w\n"+
			"hint: import the certificate into your system certificate store, or use client_cert=auto",
			certPath, leaf.Subject.CommonName, err)
	}

	cert := tls.Certificate{
		Certificate: chain,
		PrivateKey:  signer,
		Leaf:        leaf,
	}
	core.Log.Infof("AnyConnect", "Client certificate loaded from %s, private key from system store (subject=%q, chain=%d certs)",
		certPath, leaf.Subject.CommonName, len(chain))
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

	// eventBus is used to publish tunnel events (banner, timeout, reconnect).
	eventBus *core.EventBus

	// Session resumption: saved session cookie and server address for reconnect.
	savedCookie string
	savedServer string
	savedPort   int

	// Idle timeout tracking.
	lastActivity atomic.Int64 // UnixNano timestamp of last packet sent

	// Network roaming: debounce rapid network change events.
	networkChangeMu   sync.Mutex
	networkChangeTime time.Time

	cstp   *cstpConn
	dtlsC  *dtlsConn // optional DTLS connection for UDP data transport
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

func (p *Provider) Name() string     { return p.name }
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

// SetEventBus sets the event bus for publishing tunnel events.
func (p *Provider) SetEventBus(bus *core.EventBus) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.eventBus = bus
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

// HasSavedSession returns true if a session cookie is available for resumption.
func (p *Provider) HasSavedSession() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.savedCookie != ""
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

	// Try session resumption first if we have a saved cookie.
	if p.savedCookie != "" {
		core.Log.Infof("AnyConnect", "Attempting session resumption for %q", p.name)
		if p.eventBus != nil {
			p.eventBus.PublishAsync(core.Event{
				Type:    core.EventTunnelResuming,
				Payload: core.TunnelStatePayload{TunnelID: p.name},
			})
		}
		err := p.connectWithCookie(ctx, p.savedServer, p.savedPort, p.savedCookie, controlFn)
		if err == nil {
			core.Log.Infof("AnyConnect", "Session resumed successfully for %q", p.name)
			return nil
		}
		core.Log.Warnf("AnyConnect", "Session resumption failed: %v, falling back to full auth", err)
		p.savedCookie = ""
	}

	// Auth loop: may retry on cross-host redirects.
	server := p.config.Server
	port := p.config.Port
	var sess *sessionInfo
	var tlsConn *tls.Conn
	var br *bufio.Reader

	for attempt := 0; attempt < maxRedirects; attempt++ {
		var err error
		var certSent bool
		tlsConn, br, certSent, err = p.dialTLS(ctx, server, port, controlFn)
		if err != nil {
			p.state = core.TunnelStateError
			return err
		}

		core.Log.Infof("AnyConnect", "Authenticating as %q on %s...", p.config.Username, server)
		sess, err = authenticate(br, tlsConn, server, creds, p.cid, certSent)
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
			// Server requires client certificate but TLS handshake didn't include one.
			// Load certificate from system store and reconnect with it.
			var certErr *CertRequiredError
			if errors.As(err, &certErr) && p.config.ClientCert == "auto" && len(p.tlsCerts) == 0 {
				core.Log.Infof("AnyConnect", "Server requires client certificate; loading from system store and reconnecting...")
				certs, loadErr := enumerateSystemClientCerts()
				if loadErr != nil {
					p.state = core.TunnelStateError
					return fmt.Errorf("[AnyConnect] auth: server requires client certificate but system store enumeration failed: %w", loadErr)
				}
				if len(certs) == 0 {
					p.state = core.TunnelStateError
					return fmt.Errorf("[AnyConnect] auth: server requires client certificate but no certificates found in system store; " +
						"set client_cert to a PEM file path or import a certificate")
				}
				core.Log.Infof("AnyConnect", "Loaded %d certificate(s) from system store; reconnecting with certificate...", len(certs))
				p.tlsCerts = certs
				continue // retry with p.tlsCerts populated → dialTLS will set tlsCfg.Certificates
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

	// Publish banner if present in auth response.
	if sess.Banner != "" && p.eventBus != nil {
		core.Log.Infof("AnyConnect", "Server banner: %s", sess.Banner)
		p.eventBus.PublishAsync(core.Event{
			Type: core.EventTunnelBanner,
			Payload: core.BannerPayload{
				TunnelID: p.name,
				Banner:   sess.Banner,
			},
		})
	}

	// Save session for resumption.
	p.savedCookie = sess.Cookie
	p.savedServer = server
	p.savedPort = port

	// Establish CSTP tunnel and start I/O loops.
	return p.establishAndRun(br, tlsConn, server, sess.Cookie)
}

// connectWithCookie attempts to establish a tunnel using a saved session cookie
// without performing full authentication (session resumption).
func (p *Provider) connectWithCookie(ctx context.Context, server string, port int, cookie string, controlFn func(string, string, syscall.RawConn) error) error {
	tlsConn, br, _, err := p.dialTLS(ctx, server, port, controlFn)
	if err != nil {
		return err
	}

	params, err := establishTunnel(br, tlsConn, server, cookie, p.cid)
	if err != nil {
		tlsConn.Close()
		return fmt.Errorf("session resume tunnel: %w", err)
	}

	return p.finalizeTunnel(tlsConn, br, params)
}

// dialTLS performs DNS resolution and TLS dial, with optional proxy support.
func (p *Provider) dialTLS(ctx context.Context, server string, port int, controlFn func(string, string, syscall.RawConn) error) (*tls.Conn, *bufio.Reader, bool, error) {
	serverIP, err := p.resolveViaRealNIC(ctx, server, p.realNICIndex, controlFn)
	if err != nil {
		return nil, nil, false, fmt.Errorf("[AnyConnect] resolve %s: %w", server, err)
	}
	serverAddr := fmt.Sprintf("%s:%d", serverIP, port)
	if ip, ok := netip.AddrFromSlice(net.ParseIP(serverIP)); ok {
		p.serverEndpoints = []netip.AddrPort{netip.AddrPortFrom(ip, uint16(port))}
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: p.config.TLSSkipVerify,
		ServerName:         server,
	}

	// Track whether a client certificate was actually sent during TLS handshake.
	// This allows authenticate() to give specific error messages:
	//   - "no cert configured" vs "cert sent but rejected by server".
	var certSent bool

	if len(p.tlsCerts) > 0 {
		tlsCfg.Certificates = p.tlsCerts
		// Static certificates: Go TLS will send them if the server sends CertificateRequest.
		// We set certSent=true here because the cert is available; if the server doesn't
		// request it, client-cert-request won't appear in XML either.
		certSent = true
	} else if p.config.ClientCert == "auto" {
		core.Log.Infof("AnyConnect", "Client cert mode: auto (system store)")
		tlsCfg.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert, err := findSystemCertificate(info)
			if err != nil {
				return cert, err
			}
			if len(cert.Certificate) > 0 {
				certSent = true
			}
			return cert, nil
		}
	}

	var tlsConn *tls.Conn

	if p.config.ProxyURL != "" {
		// Dial through HTTP CONNECT proxy.
		rawConn, err := dialViaProxy(ctx, serverAddr, p.config.ProxyURL, p.config.ProxyUsername, p.config.ProxyPassword, nil)
		if err != nil {
			return nil, nil, false, fmt.Errorf("[AnyConnect] proxy dial: %w", err)
		}
		tlsConn = tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, nil, false, fmt.Errorf("[AnyConnect] TLS handshake via proxy: %w", err)
		}
	} else {
		// Direct TLS dial.
		dialer := &net.Dialer{Timeout: 15 * time.Second, Control: controlFn}
		tlsConn, err = tls.DialWithDialer(dialer, "tcp", serverAddr, tlsCfg)
		if err != nil {
			return nil, nil, false, fmt.Errorf("[AnyConnect] TLS dial: %w", err)
		}
	}

	br := bufio.NewReader(tlsConn)
	return tlsConn, br, certSent, nil
}

// establishAndRun sends the CSTP CONNECT, parses tunnel params, and starts I/O loops.
func (p *Provider) establishAndRun(br *bufio.Reader, tlsConn *tls.Conn, server, cookie string) error {
	params, err := establishTunnel(br, tlsConn, server, cookie, p.cid)
	if err != nil {
		tlsConn.Close()
		p.state = core.TunnelStateError
		return fmt.Errorf("[AnyConnect] tunnel: %w", err)
	}

	return p.finalizeTunnel(tlsConn, br, params)
}

// finalizeTunnel stores tunnel params and starts I/O loops. Must be called under p.mu.
func (p *Provider) finalizeTunnel(tlsConn *tls.Conn, br *bufio.Reader, params *tunnelParams) error {
	core.Log.Infof("AnyConnect", "Tunnel established: IP=%s MTU=%d DNS=%v routes=%d ipv6=%s",
		params.Address, params.MTU, params.DNS, len(params.SplitInclude), params.AddressIPv6)

	// Log timeout parameters.
	if params.IdleTimeout > 0 {
		core.Log.Infof("AnyConnect", "Idle timeout: %d seconds", params.IdleTimeout)
	}
	if params.SessionTimeout > 0 {
		core.Log.Infof("AnyConnect", "Session timeout: %d seconds", params.SessionTimeout)
	}

	// Publish banner from tunnel headers if present.
	if params.Banner != "" && p.eventBus != nil {
		p.eventBus.PublishAsync(core.Event{
			Type: core.EventTunnelBanner,
			Payload: core.BannerPayload{
				TunnelID: p.name,
				Banner:   params.Banner,
			},
		})
	}

	// Store tunnel parameters.
	p.adapterIP = params.Address
	p.splitInclude = params.SplitInclude
	p.splitExclude = params.SplitExclude
	// Merge IPv6 split routes into the include/exclude lists.
	if len(params.SplitIncludeV6) > 0 {
		p.splitInclude = append(p.splitInclude, params.SplitIncludeV6...)
	}
	if len(params.SplitExcludeV6) > 0 {
		p.splitExclude = append(p.splitExclude, params.SplitExcludeV6...)
	}
	p.dns = params.DNS

	// Start CSTP connection (read/write loops).
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

	// Start idle/session timeout monitors.
	p.lastActivity.Store(time.Now().UnixNano())
	if params.IdleTimeout > 0 {
		go p.idleTimeoutLoop(params.IdleTimeout)
	}
	if params.SessionTimeout > 0 {
		go p.sessionTimeoutLoop(params.SessionTimeout)
	}

	p.state = core.TunnelStateUp
	core.Log.Infof("AnyConnect", "Tunnel %q is UP", p.name)

	// Attempt DTLS connection in background if enabled and server supports it.
	if p.config.DTLS && params.DTLSPort > 0 && params.DTLSSessionID != "" {
		go p.attemptDTLS(params)
	}

	return nil
}

// attemptDTLS tries to establish a DTLS connection for lower-latency data transport.
func (p *Provider) attemptDTLS(params *tunnelParams) {
	p.mu.RLock()
	server := p.savedServer
	p.mu.RUnlock()

	d, err := dialDTLS(server, params.DTLSPort, params.DTLSSessionID, p.config.TLSSkipVerify, p.config.Server)
	if err != nil {
		core.Log.Warnf("AnyConnect", "DTLS connection failed, staying on CSTP: %v", err)
		return
	}

	// Set inbound handler to match CSTP's handler.
	p.mu.RLock()
	c := p.cstp
	p.mu.RUnlock()

	if c != nil {
		if hp := c.inboundHandler.Load(); hp != nil {
			d.inboundHandler.Store(hp)
		}
	}

	// On DTLS disconnect, fall back to CSTP silently.
	d.onDisconnect = func(err error) {
		core.Log.Warnf("AnyConnect", "DTLS connection lost, falling back to CSTP: %v", err)
		p.mu.Lock()
		p.dtlsC = nil
		p.mu.Unlock()
	}

	d.run()

	p.mu.Lock()
	p.dtlsC = d
	p.mu.Unlock()

	core.Log.Infof("AnyConnect", "DTLS transport active (port %d)", params.DTLSPort)
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
	d := p.dtlsC
	p.dtlsC = nil
	cancel := p.cancel
	p.cancel = nil
	p.mu.Unlock()

	if d != nil {
		d.close()
	}
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

// ClearSession clears the saved session cookie, forcing full re-auth on next connect.
func (p *Provider) ClearSession() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.savedCookie = ""
}

// ---- RawForwarder interface ----

// InjectOutbound sends an IP packet through the DTLS tunnel (preferred) or CSTP fallback.
func (p *Provider) InjectOutbound(pkt []byte) bool {
	p.mu.RLock()
	c := p.cstp
	d := p.dtlsC
	p.mu.RUnlock()

	if c == nil {
		return false
	}
	p.lastActivity.Store(time.Now().UnixNano())
	return dtlsSendData(d, c, pkt)
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

// ---- Timeout monitors ----

// idleTimeoutLoop monitors for idle timeout and disconnects if no traffic is sent.
func (p *Provider) idleTimeoutLoop(idleSeconds int) {
	idleDuration := time.Duration(idleSeconds) * time.Second
	ticker := time.NewTicker(idleDuration / 2) // check at half the interval
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.RLock()
			c := p.cstp
			p.mu.RUnlock()
			if c == nil {
				return
			}

			lastNano := p.lastActivity.Load()
			elapsed := time.Since(time.Unix(0, lastNano))
			if elapsed >= idleDuration {
				core.Log.Warnf("AnyConnect", "Idle timeout (%s) reached for %q", idleDuration, p.name)
				if p.eventBus != nil {
					p.eventBus.PublishAsync(core.Event{
						Type: core.EventTunnelTimeout,
						Payload: core.TimeoutPayload{
							TunnelID: p.name,
							Kind:     "idle",
						},
					})
				}
				p.Disconnect()
				return
			}
		}
	}
}

// sessionTimeoutLoop disconnects when the absolute session timeout expires.
func (p *Provider) sessionTimeoutLoop(sessionSeconds int) {
	sessionDuration := time.Duration(sessionSeconds) * time.Second

	// Warn 5 minutes before expiry if session is long enough.
	warnBefore := 5 * time.Minute
	if sessionDuration > warnBefore*2 {
		warnTimer := time.NewTimer(sessionDuration - warnBefore)
		defer warnTimer.Stop()

		select {
		case <-warnTimer.C:
			p.mu.RLock()
			c := p.cstp
			p.mu.RUnlock()
			if c == nil {
				return
			}
			core.Log.Warnf("AnyConnect", "Session timeout for %q in %s", p.name, warnBefore)
			if p.eventBus != nil {
				p.eventBus.PublishAsync(core.Event{
					Type: core.EventTunnelTimeout,
					Payload: core.TimeoutPayload{
						TunnelID: p.name,
						Kind:     "session_warning",
					},
				})
			}
		}
	}

	remaining := sessionDuration
	if sessionDuration > warnBefore*2 {
		remaining = warnBefore
	}

	timer := time.NewTimer(remaining)
	defer timer.Stop()

	select {
	case <-timer.C:
		p.mu.RLock()
		c := p.cstp
		p.mu.RUnlock()
		if c == nil {
			return
		}
		core.Log.Warnf("AnyConnect", "Session timeout (%s) reached for %q", sessionDuration, p.name)
		if p.eventBus != nil {
			p.eventBus.PublishAsync(core.Event{
				Type: core.EventTunnelTimeout,
				Payload: core.TimeoutPayload{
					TunnelID: p.name,
					Kind:     "session",
				},
			})
		}
		p.Disconnect()
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

// ---- Network Roaming ----

// HandleNetworkChange is called when the network interface changes (Wi-Fi switch,
// Ethernet plug/unplug). It triggers a session resume with the saved cookie.
// Debounces rapid changes within 3 seconds.
func (p *Provider) HandleNetworkChange() {
	p.networkChangeMu.Lock()
	if time.Since(p.networkChangeTime) < 3*time.Second {
		p.networkChangeMu.Unlock()
		return
	}
	p.networkChangeTime = time.Now()
	p.networkChangeMu.Unlock()

	p.mu.RLock()
	state := p.state
	hasCookie := p.savedCookie != ""
	p.mu.RUnlock()

	if state != core.TunnelStateUp || !hasCookie {
		return
	}

	core.Log.Infof("AnyConnect", "Network change detected for %q, triggering session resume", p.name)

	// Close current connection — this will trigger onDisconnect which
	// will attempt session resume via the saved cookie.
	p.mu.Lock()
	c := p.cstp
	p.mu.Unlock()

	if c != nil {
		// Force-close the underlying connection to trigger readLoop exit.
		c.conn.Close()
	}
}

// ---- DialTCP / DialUDP ----
// AnyConnect provider uses RawForwarder for IP-level forwarding.
// DialTCP/DialUDP are not used when RawForwarder is available.

func (p *Provider) DialTCP(_ context.Context, _ string) (net.Conn, error) {
	return nil, fmt.Errorf("anyconnect: DialTCP not supported, use RawForwarder")
}

// DialUDP is implemented in dial_udp.go via raw IP packet injection through CSTP.
