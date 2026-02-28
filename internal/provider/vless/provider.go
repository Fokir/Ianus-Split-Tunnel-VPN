package vless

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/platform"

	xlog "github.com/xtls/xray-core/common/log"
	xcore "github.com/xtls/xray-core/core"
)

// xrayLogBridge forwards xray-core log messages to our logging system.
type xrayLogBridge struct{}

func (b *xrayLogBridge) Handle(msg xlog.Message) {
	s := msg.String()
	switch {
	case strings.HasPrefix(s, "[Warning]"), strings.HasPrefix(s, "[Error]"):
		core.Log.Warnf("xray", "%s", s)
	case strings.HasPrefix(s, "[Info]"):
		core.Log.Infof("xray", "%s", s)
	case strings.HasPrefix(s, "[Debug]"):
		core.Log.Debugf("xray", "%s", s)
	}
}

// Provider implements TunnelProvider for the VLESS protocol with optional
// Reality/TLS security, using xray-core as an in-process library.
// Traffic is routed through a local socks5 inbound → xray routing → VLESS outbound.
// This mirrors the V2RayN/V2RayA architecture; using xcore.Dial() directly is
// broken for XHTTP transport (returns immediate EOF).
type Provider struct {
	mu     sync.RWMutex
	config Config
	state  core.TunnelState
	name   string

	realNICIndex uint32                  // real NIC index for DNS resolution bypass
	binder       platform.InterfaceBinder // platform-specific socket binding (optional)
	serverAddr   netip.AddrPort           // resolved server endpoint for bypass routes
	instance     *xcore.Instance
	socksAddr    string // local socks5 proxy address "127.0.0.1:{port}"

	selfTestCancel context.CancelFunc // cancels running selfTest on Disconnect
	selfTestWg     sync.WaitGroup    // waits for selfTest goroutine to finish
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
	// Resolve server address for bypass routes.
	serverStr := net.JoinHostPort(p.config.Address, fmt.Sprintf("%d", p.config.Port))
	core.Log.Infof("VLESS", "Connecting tunnel %q to %s...", p.name, serverStr)
	if ap, err := netip.ParseAddrPort(serverStr); err == nil {
		p.serverAddr = ap
	} else {
		// Resolve hostname through the real NIC to bypass TUN DNS (10.255.0.1).
		// Read fields under write lock (already held), then resolve WITHOUT lock
		// to avoid deadlock — resolveViaRealNIC would try RLock on the same goroutine.
		realNICIndex := p.realNICIndex
		binder := p.binder

		resolveCtx, resolveCancel := context.WithTimeout(ctx, 10*time.Second)
		var ips []string
		var err error
		if realNICIndex > 0 {
			ips, err = resolveViaRealNIC(resolveCtx, p.config.Address, realNICIndex, binder)
		} else {
			ips, err = net.DefaultResolver.LookupHost(resolveCtx, p.config.Address)
		}
		resolveCancel()
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

	// Find a free port for the local socks5 inbound.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		p.state = core.TunnelStateError
		return fmt.Errorf("[VLESS] find free port for socks5: %w", err)
	}
	socksPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	// Build xray JSON config.
	configBytes, err := buildXrayJSON(p.config, socksPort)
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
	xlog.RegisterHandler(&xrayLogBridge{})

	p.instance = instance
	p.socksAddr = fmt.Sprintf("127.0.0.1:%d", socksPort)

	// Wait for socks5 listener to be ready (typically immediate after StartInstance).
	ready := false
	for i := 0; i < 40; i++ {
		tc, dialErr := net.DialTimeout("tcp", p.socksAddr, 100*time.Millisecond)
		if dialErr == nil {
			tc.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		instance.Close()
		p.instance = nil
		p.socksAddr = ""
		p.state = core.TunnelStateError
		return fmt.Errorf("[VLESS] socks5 listener on %s not ready after 4s — xray startup failed", p.socksAddr)
	}

	p.state = core.TunnelStateUp
	core.Log.Infof("VLESS", "Tunnel %q is UP (server=%s, security=%s, network=%s, socks5=%s)",
		p.name, serverStr, p.config.Security, p.config.Network, p.socksAddr)

	// Connectivity self-test with cancellable context (cancelled on Disconnect).
	selfTestCtx, selfTestCancel := context.WithCancel(context.Background())
	p.selfTestCancel = selfTestCancel
	p.selfTestWg.Add(1)
	go func() {
		defer p.selfTestWg.Done()
		p.selfTest(selfTestCtx)
	}()

	return nil
}

// selfTest verifies connectivity through the socks5 proxy after tunnel is up.
// The provided context is cancelled on Disconnect() to abort the test early.
func (p *Provider) selfTest(parentCtx context.Context) {
	ctx, cancel := context.WithTimeout(parentCtx, 10*time.Second)
	defer cancel()

	core.Log.Infof("VLESS", "[self-test] Dialing 1.1.1.1:80 via socks5...")
	conn, err := p.DialTCP(ctx, "1.1.1.1:80")
	if err != nil {
		core.Log.Warnf("VLESS", "[self-test] DialTCP failed: %v", err)
		return
	}
	defer conn.Close()

	req := "GET /dns-query?name=example.com&type=A HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		core.Log.Warnf("VLESS", "[self-test] Write failed: %v", err)
		return
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if n > 0 {
		resp := string(buf[:n])
		if idx := strings.Index(resp, "\r\n"); idx > 0 {
			resp = resp[:idx]
		}
		core.Log.Infof("VLESS", "[self-test] SUCCESS: got %d bytes, status=%q", n, resp)
	} else {
		core.Log.Warnf("VLESS", "[self-test] FAILED: Read returned %d bytes, err=%v", n, err)
	}
}

// Disconnect shuts down the xray-core instance.
func (p *Provider) Disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Cancel any running selfTest and wait for it to finish
	// before tearing down the instance.
	if p.selfTestCancel != nil {
		p.selfTestCancel()
		p.selfTestCancel = nil
	}
	// Wait outside the lock is not needed — selfTest only reads socksAddr under RLock,
	// and we haven't cleared instance yet. Wait with lock held is safe because
	// selfTest acquires RLock (not Lock).
	p.mu.Unlock()
	p.selfTestWg.Wait()
	p.mu.Lock()

	if p.instance != nil {
		if err := p.instance.Close(); err != nil {
			core.Log.Warnf("VLESS", "Error closing xray instance for %q: %v", p.name, err)
		}
		p.instance = nil
	}

	p.socksAddr = ""
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

// DialTCP creates a TCP connection through the VLESS tunnel via local socks5 proxy.
// Uses socks5 inbound → xray routing → VLESS outbound (same flow as V2RayN).
func (p *Provider) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	socksAddr := p.socksAddr
	p.mu.RUnlock()

	if state != core.TunnelStateUp || socksAddr == "" {
		return nil, fmt.Errorf("[VLESS] tunnel %q is not up (state=%d)", p.name, state)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] invalid address %q: %w", addr, err)
	}

	var port uint16
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] invalid target port %q: %w", portStr, err)
	}

	conn, err := dialViaSocks5(ctx, socksAddr, host, port)
	if err != nil {
		core.Log.Warnf("VLESS", "DialTCP %s failed: %v", addr, err)
		return nil, err
	}

	return conn, nil
}

// DialUDP creates a UDP connection through the VLESS tunnel via local socks5 proxy.
// Uses SOCKS5 UDP ASSOCIATE for the data path while keeping a TCP control connection open.
func (p *Provider) DialUDP(ctx context.Context, addr string) (net.Conn, error) {
	p.mu.RLock()
	state := p.state
	socksAddr := p.socksAddr
	p.mu.RUnlock()

	if state != core.TunnelStateUp || socksAddr == "" {
		return nil, fmt.Errorf("[VLESS] tunnel %q is not up (state=%d)", p.name, state)
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] invalid address %q: %w", addr, err)
	}

	var port uint16
	_, err = fmt.Sscanf(portStr, "%d", &port)
	if err != nil {
		return nil, fmt.Errorf("[VLESS] invalid target port %q: %w", portStr, err)
	}

	conn, err := dialUDPViaSocks5(ctx, socksAddr, host, port)
	if err != nil {
		core.Log.Warnf("VLESS", "DialUDP %s failed: %v", addr, err)
		return nil, err
	}

	return conn, nil
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
func (p *Provider) GetServerEndpoints() []netip.AddrPort {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.serverAddr.IsValid() {
		return []netip.AddrPort{p.serverAddr}
	}
	return nil
}

// SetRealNICIndex sets the real NIC interface index for DNS resolution bypass.
func (p *Provider) SetRealNICIndex(index uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.realNICIndex = index
}

// SetInterfaceBinder sets the platform-specific interface binder for DNS resolution bypass.
func (p *Provider) SetInterfaceBinder(binder platform.InterfaceBinder) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.binder = binder
}

// resolveViaRealNIC resolves a hostname using a DNS resolver bound to the real
// NIC interface, bypassing the TUN DNS resolver entirely.
// This is a standalone function (not a method) to avoid mutex issues — the caller
// must read realNICIndex and binder before calling.
func resolveViaRealNIC(ctx context.Context, host string, realNICIndex uint32, binder platform.InterfaceBinder) ([]string, error) {
	core.Log.Debugf("VLESS", "Resolving %q via real NIC (index=%d)", host, realNICIndex)

	var controlFn func(string, string, syscall.RawConn) error
	if binder != nil {
		controlFn = binder.BindControl(realNICIndex)
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
		core.Log.Warnf("VLESS", "DNS resolve %q via real NIC failed: %v", host, err)
		return nil, err
	}
	core.Log.Infof("VLESS", "Resolved %q via real NIC → %v", host, ips)
	return ips, nil
}

// dialViaSocks5 performs a SOCKS5 TCP CONNECT through a local socks5 proxy.
// Returns the connection after the SOCKS5 handshake, ready for data transfer.
func dialViaSocks5(ctx context.Context, socksAddr, targetHost string, targetPort uint16) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to socks5 %s: %w", socksAddr, err)
	}

	// Set deadline for the handshake phase.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	// SOCKS5 auth: no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth write: %w", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth read: %w", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: %x", authResp)
	}

	// SOCKS5 CONNECT request.
	connectReq := buildSocks5ConnectReq(targetHost, targetPort)
	if _, err := conn.Write(connectReq); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect write: %w", err)
	}

	// Read CONNECT response.
	if err := readSocks5Response(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Clear deadline — caller manages timeouts from here.
	conn.SetDeadline(time.Time{})

	return conn, nil
}

// dialUDPViaSocks5 sets up a SOCKS5 UDP ASSOCIATE session.
// Returns a net.Conn that wraps the UDP relay, with a background TCP control connection.
func dialUDPViaSocks5(ctx context.Context, socksAddr, targetHost string, targetPort uint16) (net.Conn, error) {
	var d net.Dialer
	tcpConn, err := d.DialContext(ctx, "tcp", socksAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to socks5 %s: %w", socksAddr, err)
	}

	if deadline, ok := ctx.Deadline(); ok {
		tcpConn.SetDeadline(deadline)
	}

	// SOCKS5 auth: no authentication.
	if _, err := tcpConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth write: %w", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(tcpConn, authResp); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth read: %w", err)
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 auth rejected: %x", authResp)
	}

	// UDP ASSOCIATE: CMD=0x03, DST.ADDR=0.0.0.0:0.
	udpAssocReq := []byte{
		0x05, 0x03, 0x00, 0x01, // VER, CMD=UDP_ASSOCIATE, RSV, ATYP=IPv4
		0, 0, 0, 0, // 0.0.0.0
		0, 0, // port 0
	}
	if _, err := tcpConn.Write(udpAssocReq); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp assoc write: %w", err)
	}

	// Read response header.
	var respHeader [4]byte
	if _, err := io.ReadFull(tcpConn, respHeader[:]); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp assoc header: %w", err)
	}
	if respHeader[1] != 0x00 {
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp assoc failed: status=%d", respHeader[1])
	}

	// Read relay address based on ATYP.
	var relayIP net.IP
	var relayPort uint16
	switch respHeader[3] {
	case 0x01: // IPv4
		var buf [6]byte
		if _, err := io.ReadFull(tcpConn, buf[:]); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 udp assoc read addr: %w", err)
		}
		relayIP = net.IP(buf[:4])
		relayPort = binary.BigEndian.Uint16(buf[4:6])
	case 0x04: // IPv6
		var buf [18]byte
		if _, err := io.ReadFull(tcpConn, buf[:]); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("socks5 udp assoc read addr: %w", err)
		}
		relayIP = net.IP(buf[:16])
		relayPort = binary.BigEndian.Uint16(buf[16:18])
	default:
		tcpConn.Close()
		return nil, fmt.Errorf("socks5 udp assoc: unexpected ATYP %d", respHeader[3])
	}

	// xray socks5 may return 0.0.0.0 as relay — replace with 127.0.0.1.
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}

	tcpConn.SetDeadline(time.Time{})

	relayAddr := &net.UDPAddr{IP: relayIP, Port: int(relayPort)}

	// Open local UDP socket connected to the relay.
	udpConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("dial udp relay %s: %w", relayAddr, err)
	}

	// Build SOCKS5 UDP header for the target address (prepended to every datagram).
	header := buildSocks5UDPHeader(targetHost, targetPort)

	return &socks5UDPConn{
		tcpConn:   tcpConn,
		udpConn:   udpConn,
		remoteAddr: &net.UDPAddr{IP: net.ParseIP(targetHost), Port: int(targetPort)},
		header:    header,
	}, nil
}

// buildSocks5ConnectReq builds a SOCKS5 CONNECT request for the given target.
func buildSocks5ConnectReq(host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req := make([]byte, 10)
			req[0] = 0x05 // VER
			req[1] = 0x01 // CMD=CONNECT
			req[3] = 0x01 // ATYP=IPv4
			copy(req[4:8], ip4)
			binary.BigEndian.PutUint16(req[8:10], port)
			return req
		}
		ip6 := ip.To16()
		req := make([]byte, 22)
		req[0] = 0x05
		req[1] = 0x01
		req[3] = 0x04 // ATYP=IPv6
		copy(req[4:20], ip6)
		binary.BigEndian.PutUint16(req[20:22], port)
		return req
	}
	// Domain name.
	domLen := len(host)
	req := make([]byte, 7+domLen)
	req[0] = 0x05
	req[1] = 0x01
	req[3] = 0x03 // ATYP=Domain
	req[4] = byte(domLen)
	copy(req[5:5+domLen], host)
	binary.BigEndian.PutUint16(req[5+domLen:7+domLen], port)
	return req
}

// buildSocks5UDPHeader builds the SOCKS5 UDP request header for the given target.
// Format: RSV(2) + FRAG(1) + ATYP(1) + DST.ADDR(var) + DST.PORT(2)
func buildSocks5UDPHeader(host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header := make([]byte, 10)
			header[3] = 0x01 // ATYP=IPv4
			copy(header[4:8], ip4)
			binary.BigEndian.PutUint16(header[8:10], port)
			return header
		}
		ip6 := ip.To16()
		header := make([]byte, 22)
		header[3] = 0x04 // ATYP=IPv6
		copy(header[4:20], ip6)
		binary.BigEndian.PutUint16(header[20:22], port)
		return header
	}
	domLen := len(host)
	header := make([]byte, 7+domLen)
	header[3] = 0x03 // ATYP=Domain
	header[4] = byte(domLen)
	copy(header[5:5+domLen], host)
	binary.BigEndian.PutUint16(header[5+domLen:7+domLen], port)
	return header
}

// readSocks5Response reads and validates a SOCKS5 CONNECT response,
// consuming the full response including the variable-length bind address.
func readSocks5Response(conn net.Conn) error {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return fmt.Errorf("socks5 response header: %w", err)
	}
	if header[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: status=%d", header[1])
	}
	// Read and discard BND.ADDR + BND.PORT based on ATYP.
	switch header[3] {
	case 0x01: // IPv4: 4 addr + 2 port
		var buf [6]byte
		_, err := io.ReadFull(conn, buf[:])
		return err
	case 0x04: // IPv6: 16 addr + 2 port
		var buf [18]byte
		_, err := io.ReadFull(conn, buf[:])
		return err
	case 0x03: // Domain: 1 len + N domain + 2 port
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return err
		}
		discard := make([]byte, int(lenBuf[0])+2)
		_, err := io.ReadFull(conn, discard)
		return err
	default:
		return fmt.Errorf("socks5 response: unknown ATYP %d", header[3])
	}
}

// socks5UDPConn wraps a SOCKS5 UDP ASSOCIATE session as a net.Conn.
// The TCP control connection must stay open for the UDP relay to work.
type socks5UDPConn struct {
	tcpConn    net.Conn     // TCP control connection (lifetime signal)
	udpConn    *net.UDPConn // connected UDP socket to relay
	remoteAddr net.Addr     // logical remote address
	header     []byte       // pre-built SOCKS5 UDP header for target
}

func (c *socks5UDPConn) Read(b []byte) (int, error) {
	// Read from relay, strip SOCKS5 UDP header.
	buf := make([]byte, len(b)+262) // max SOCKS5 UDP header = 262 bytes
	n, err := c.udpConn.Read(buf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("socks5 udp: packet too short (%d bytes)", n)
	}
	// Determine header length from ATYP.
	var headerLen int
	switch buf[3] {
	case 0x01:
		headerLen = 10
	case 0x04:
		headerLen = 22
	case 0x03:
		if n < 5 {
			return 0, fmt.Errorf("socks5 udp: packet too short for domain ATYP")
		}
		headerLen = 7 + int(buf[4])
	default:
		return 0, fmt.Errorf("socks5 udp: unknown ATYP %d", buf[3])
	}
	if n < headerLen {
		return 0, fmt.Errorf("socks5 udp: packet shorter than header (%d < %d)", n, headerLen)
	}
	dataLen := n - headerLen
	if dataLen > len(b) {
		dataLen = len(b)
	}
	copy(b[:dataLen], buf[headerLen:headerLen+dataLen])
	return dataLen, nil
}

func (c *socks5UDPConn) Write(b []byte) (int, error) {
	packet := make([]byte, len(c.header)+len(b))
	copy(packet, c.header)
	copy(packet[len(c.header):], b)
	if _, err := c.udpConn.Write(packet); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5UDPConn) Close() error {
	c.udpConn.Close()
	return c.tcpConn.Close()
}

func (c *socks5UDPConn) LocalAddr() net.Addr              { return c.udpConn.LocalAddr() }
func (c *socks5UDPConn) RemoteAddr() net.Addr              { return c.remoteAddr }
func (c *socks5UDPConn) SetDeadline(t time.Time) error     { return c.udpConn.SetDeadline(t) }
func (c *socks5UDPConn) SetReadDeadline(t time.Time) error  { return c.udpConn.SetReadDeadline(t) }
func (c *socks5UDPConn) SetWriteDeadline(t time.Time) error { return c.udpConn.SetWriteDeadline(t) }
