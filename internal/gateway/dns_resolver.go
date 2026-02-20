//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"
)

// DNSResolverConfig configures the local DNS resolver.
type DNSResolverConfig struct {
	// ListenAddr is the address to listen on (e.g. "10.255.0.1:53").
	ListenAddr string

	// Servers are the upstream DNS servers to query through VPN.
	Servers []netip.Addr

	// TunnelID is the VPN tunnel to route primary DNS through.
	TunnelID string

	// Timeout per upstream DNS server (default 3s).
	Timeout time.Duration

	// FallbackDirect enables direct (non-VPN) fallback when all VPN servers fail.
	FallbackDirect bool

	// Cache configures DNS response caching. Nil disables caching.
	// Use &DNSCacheConfig{} for defaults.
	Cache *DNSCacheConfig
}

// DNSResolver is a local DNS forwarder that listens on the TUN adapter IP
// and forwards queries through VPN tunnels. This bypasses the proxy/NAT path
// entirely — queries are sent directly via provider.DialUDP/DialTCP through
// the tunnel's gVisor netstack.
//
// Architecture:
//
//	App → svchost (Windows DNS Client) → 10.255.0.1:53 (loopback)
//	→ DNSResolver → provider.DialUDP → WireGuard tunnel → upstream DNS
type DNSResolver struct {
	config   DNSResolverConfig
	registry *core.TunnelRegistry
	// providers is a reference to the main providers map; read-only after startup.
	providers map[string]provider.TunnelProvider

	udpConn *net.UDPConn
	tcpLn   net.Listener

	cache *DNSCache // nil if caching disabled

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewDNSResolver creates a DNS resolver.
func NewDNSResolver(
	config DNSResolverConfig,
	registry *core.TunnelRegistry,
	providers map[string]provider.TunnelProvider,
) *DNSResolver {
	if config.Timeout == 0 {
		config.Timeout = 3 * time.Second
	}

	r := &DNSResolver{
		config:    config,
		registry:  registry,
		providers: providers,
	}

	// Initialize DNS cache if configured.
	if config.Cache != nil {
		r.cache = NewDNSCache(*config.Cache)
	}

	return r
}

// Start begins listening for DNS queries on UDP and TCP.
func (r *DNSResolver) Start(ctx context.Context) error {
	ctx, r.cancel = context.WithCancel(ctx)

	// UDP listener.
	udpAddr, err := net.ResolveUDPAddr("udp4", r.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("[DNS] resolve addr: %w", err)
	}
	r.udpConn, err = net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return fmt.Errorf("[DNS] listen UDP %s: %w", r.config.ListenAddr, err)
	}

	// TCP listener.
	r.tcpLn, err = net.Listen("tcp4", r.config.ListenAddr)
	if err != nil {
		r.udpConn.Close()
		return fmt.Errorf("[DNS] listen TCP %s: %w", r.config.ListenAddr, err)
	}

	r.wg.Add(2)
	go r.udpLoop(ctx)
	go r.tcpLoop(ctx)

	core.Log.Infof("DNS", "Resolver listening on %s (tunnel=%s, servers=%v, fallback_direct=%v)",
		r.config.ListenAddr, r.config.TunnelID, r.config.Servers, r.config.FallbackDirect)
	return nil
}

// Stop shuts down the resolver.
func (r *DNSResolver) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	if r.udpConn != nil {
		r.udpConn.Close()
	}
	if r.tcpLn != nil {
		r.tcpLn.Close()
	}
	r.wg.Wait()
	if r.cache != nil {
		r.cache.Stop()
	}
	core.Log.Infof("DNS", "Resolver stopped")
}

// ---------------------------------------------------------------------------
// UDP DNS
// ---------------------------------------------------------------------------

func (r *DNSResolver) udpLoop(ctx context.Context) {
	defer r.wg.Done()

	buf := make([]byte, 4096)
	for {
		n, clientAddr, err := r.udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				core.Log.Errorf("DNS", "UDP read error: %v", err)
				continue
			}
		}

		if n < 12 {
			continue // too small for DNS header
		}

		// Copy query (buf is reused).
		query := make([]byte, n)
		copy(query, buf[:n])

		go r.handleUDPQuery(ctx, query, clientAddr)
	}
}

func (r *DNSResolver) handleUDPQuery(ctx context.Context, query []byte, clientAddr *net.UDPAddr) {
	name := extractDNSName(query)

	// Cache lookup.
	if r.cache != nil {
		qName, qtype, qclass, err := parseDNSQuestion(query)
		if err == nil {
			queryID := getDNSTransactionID(query)
			if cached, ok := r.cache.Get(queryID, qName, qtype, qclass); ok {
				r.udpConn.WriteToUDP(cached, clientAddr)
				core.Log.Debugf("DNS", "%s cache hit (UDP)", name)
				return
			}
		}
	}

	// Try VPN tunnel first.
	resp, server, err := r.forwardUDP(ctx, r.config.TunnelID, query)
	if err == nil {
		r.cacheStore(query, resp)
		r.udpConn.WriteToUDP(resp, clientAddr)
		if name != "" {
			core.Log.Debugf("DNS", "%s → %s via %s (UDP)", name, server, r.config.TunnelID)
		}
		return
	}

	// Fallback: try direct provider.
	if r.config.FallbackDirect {
		resp, server, err = r.forwardUDP(ctx, DirectTunnelID, query)
		if err == nil {
			r.cacheStore(query, resp)
			r.udpConn.WriteToUDP(resp, clientAddr)
			if name != "" {
				core.Log.Debugf("DNS", "%s → %s via direct/fallback (UDP)", name, server)
			}
			return
		}
	}

	core.Log.Warnf("DNS", "All servers failed for %s (UDP): %v", name, err)
	// Send SERVFAIL response.
	if sf := makeServFail(query); sf != nil {
		r.udpConn.WriteToUDP(sf, clientAddr)
	}
}

func (r *DNSResolver) forwardUDP(ctx context.Context, tunnelID string, query []byte) ([]byte, netip.Addr, error) {
	prov, ok := r.providers[tunnelID]
	if !ok {
		return nil, netip.Addr{}, fmt.Errorf("tunnel %q not found", tunnelID)
	}

	entry, ok := r.registry.Get(tunnelID)
	if !ok || entry.State != core.TunnelStateUp {
		return nil, netip.Addr{}, fmt.Errorf("tunnel %q not up", tunnelID)
	}

	servers := r.config.Servers
	if len(servers) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("no DNS servers configured")
	}

	// Single server — no parallelism overhead.
	if len(servers) == 1 {
		return r.forwardUDPSingle(ctx, prov, servers[0], query)
	}

	// Fan-out to all servers in parallel, return first success.
	type result struct {
		resp   []byte
		server netip.Addr
		err    error
	}

	fanCtx, fanCancel := context.WithTimeout(ctx, r.config.Timeout)
	defer fanCancel()

	ch := make(chan result, len(servers))
	for _, srv := range servers {
		go func(server netip.Addr) {
			resp, _, err := r.forwardUDPSingle(fanCtx, prov, server, query)
			ch <- result{resp: resp, server: server, err: err}
		}(srv)
	}

	var lastErr error
	for range servers {
		res := <-ch
		if res.err != nil {
			lastErr = res.err
			continue
		}
		fanCancel() // cancel remaining goroutines
		return res.resp, res.server, nil
	}

	return nil, netip.Addr{}, fmt.Errorf("all %d servers unreachable via %s: %w", len(servers), tunnelID, lastErr)
}

// forwardUDPSingle sends a DNS query to a single server via the given provider.
func (r *DNSResolver) forwardUDPSingle(ctx context.Context, prov provider.TunnelProvider, server netip.Addr, query []byte) ([]byte, netip.Addr, error) {
	addr := net.JoinHostPort(server.String(), "53")

	conn, err := prov.DialUDP(ctx, addr)
	if err != nil {
		return nil, server, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(r.config.Timeout))
	}

	if _, err := conn.Write(query); err != nil {
		return nil, server, err
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return nil, server, err
	}

	if n < 12 {
		return nil, server, fmt.Errorf("response too short (%d bytes)", n)
	}

	return resp[:n], server, nil
}

// ---------------------------------------------------------------------------
// TCP DNS
// ---------------------------------------------------------------------------

func (r *DNSResolver) tcpLoop(ctx context.Context) {
	defer r.wg.Done()

	for {
		conn, err := r.tcpLn.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				core.Log.Errorf("DNS", "TCP accept error: %v", err)
				continue
			}
		}

		go r.handleTCPQuery(ctx, conn)
	}
}

func (r *DNSResolver) handleTCPQuery(ctx context.Context, clientConn net.Conn) {
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(10 * time.Second))

	// TCP DNS: 2-byte length prefix + message.
	var lenBuf [2]byte
	if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
		return
	}
	qLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if qLen < 12 || qLen > 4096 {
		return
	}

	query := make([]byte, qLen)
	if _, err := io.ReadFull(clientConn, query); err != nil {
		return
	}

	name := extractDNSName(query)

	// Cache lookup.
	if r.cache != nil {
		qName, qtype, qclass, parseErr := parseDNSQuestion(query)
		if parseErr == nil {
			queryID := getDNSTransactionID(query)
			if cached, ok := r.cache.Get(queryID, qName, qtype, qclass); ok {
				core.Log.Debugf("DNS", "%s cache hit (TCP)", name)
				var respLen [2]byte
				binary.BigEndian.PutUint16(respLen[:], uint16(len(cached)))
				clientConn.Write(respLen[:])
				clientConn.Write(cached)
				return
			}
		}
	}

	// Try VPN tunnel.
	resp, server, err := r.forwardTCP(ctx, r.config.TunnelID, query)
	if err != nil && r.config.FallbackDirect {
		resp, server, err = r.forwardTCP(ctx, DirectTunnelID, query)
	}

	if err != nil {
		core.Log.Warnf("DNS", "All servers failed for %s (TCP): %v", name, err)
		resp = makeServFail(query)
		if resp == nil {
			return
		}
	} else {
		r.cacheStore(query, resp)
		if name != "" {
			core.Log.Debugf("DNS", "%s → %s via %s (TCP)", name, server, r.config.TunnelID)
		}
	}

	// Write response with length prefix.
	var respLen [2]byte
	binary.BigEndian.PutUint16(respLen[:], uint16(len(resp)))
	clientConn.Write(respLen[:])
	clientConn.Write(resp)
}

func (r *DNSResolver) forwardTCP(ctx context.Context, tunnelID string, query []byte) ([]byte, netip.Addr, error) {
	prov, ok := r.providers[tunnelID]
	if !ok {
		return nil, netip.Addr{}, fmt.Errorf("tunnel %q not found", tunnelID)
	}

	entry, ok := r.registry.Get(tunnelID)
	if !ok || entry.State != core.TunnelStateUp {
		return nil, netip.Addr{}, fmt.Errorf("tunnel %q not up", tunnelID)
	}

	servers := r.config.Servers
	if len(servers) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("no DNS servers configured")
	}

	// Single server — no parallelism overhead.
	if len(servers) == 1 {
		return r.forwardTCPSingle(ctx, prov, servers[0], query)
	}

	// Fan-out to all servers in parallel, return first success.
	type result struct {
		resp   []byte
		server netip.Addr
		err    error
	}

	fanCtx, fanCancel := context.WithTimeout(ctx, r.config.Timeout)
	defer fanCancel()

	ch := make(chan result, len(servers))
	for _, srv := range servers {
		go func(server netip.Addr) {
			resp, _, err := r.forwardTCPSingle(fanCtx, prov, server, query)
			ch <- result{resp: resp, server: server, err: err}
		}(srv)
	}

	var lastErr error
	for range servers {
		res := <-ch
		if res.err != nil {
			lastErr = res.err
			continue
		}
		fanCancel()
		return res.resp, res.server, nil
	}

	return nil, netip.Addr{}, fmt.Errorf("all %d servers unreachable via %s (TCP): %w", len(servers), tunnelID, lastErr)
}

// forwardTCPSingle sends a DNS query to a single server via TCP through the given provider.
func (r *DNSResolver) forwardTCPSingle(ctx context.Context, prov provider.TunnelProvider, server netip.Addr, query []byte) ([]byte, netip.Addr, error) {
	addr := net.JoinHostPort(server.String(), "53")

	conn, err := prov.DialTCP(ctx, addr)
	if err != nil {
		return nil, server, err
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(r.config.Timeout))
	}

	// Write with length prefix.
	var qLenBuf [2]byte
	binary.BigEndian.PutUint16(qLenBuf[:], uint16(len(query)))
	if _, err := conn.Write(qLenBuf[:]); err != nil {
		return nil, server, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, server, err
	}

	// Read response length.
	var rLenBuf [2]byte
	if _, err := io.ReadFull(conn, rLenBuf[:]); err != nil {
		return nil, server, err
	}
	rLen := int(binary.BigEndian.Uint16(rLenBuf[:]))
	if rLen < 12 || rLen > 65535 {
		return nil, server, fmt.Errorf("invalid response length %d", rLen)
	}

	resp := make([]byte, rLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, server, err
	}

	return resp, server, nil
}

// ---------------------------------------------------------------------------
// DNS helpers
// ---------------------------------------------------------------------------

// extractDNSName extracts the first query name from a raw DNS message.
// Returns empty string on parse failure.
func extractDNSName(msg []byte) string {
	if len(msg) < 12 {
		return ""
	}

	// Skip header (12 bytes). Parse QNAME (sequence of length-prefixed labels).
	pos := 12
	var name []byte
	for pos < len(msg) {
		labelLen := int(msg[pos])
		if labelLen == 0 {
			break // root label
		}
		if labelLen >= 64 {
			break // pointer — stop
		}
		pos++
		if pos+labelLen > len(msg) {
			break
		}
		if len(name) > 0 {
			name = append(name, '.')
		}
		name = append(name, msg[pos:pos+labelLen]...)
		pos += labelLen
	}

	return string(name)
}

// makeServFail creates a SERVFAIL response for the given query.
// Returns nil if the query is too short.
func makeServFail(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	resp := make([]byte, len(query))
	copy(resp, query)

	// Set QR=1 (response), RCODE=2 (SERVFAIL).
	resp[2] = query[2] | 0x80 // QR=1
	resp[3] = (query[3] & 0xF0) | 0x02 // RCODE=SERVFAIL
	// Zero answer/authority/additional counts.
	resp[6], resp[7] = 0, 0
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0

	return resp
}

// cacheStore stores a DNS response in the cache if caching is enabled.
func (r *DNSResolver) cacheStore(query, resp []byte) {
	if r.cache == nil {
		return
	}
	name, qtype, qclass, err := parseDNSQuestion(query)
	if err == nil {
		r.cache.Put(name, qtype, qclass, resp)
	}
}
