package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

	// TunnelIDs are the VPN tunnels to route DNS through simultaneously.
	// Queries are sent through all tunnels in parallel, first response wins.
	TunnelIDs []string

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

	// Domain-based routing.
	domainMatcher atomic.Pointer[DomainMatcher]
	domainTable   *DomainTable

	// Goroutine limiters to prevent resource exhaustion under DNS flood.
	udpSem chan struct{} // limits concurrent UDP handlers
	tcpSem chan struct{} // limits concurrent TCP handlers

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
		udpSem:    make(chan struct{}, 200),
		tcpSem:    make(chan struct{}, 100),
	}

	// Initialize DNS cache if configured.
	if config.Cache != nil {
		r.cache = NewDNSCache(*config.Cache)
	}

	return r
}

// SetDomainMatcher atomically sets the domain matcher for DNS interception.
func (r *DNSResolver) SetDomainMatcher(m *DomainMatcher) {
	r.domainMatcher.Store(m)
}

// SetDomainTable sets the domain table for recording resolved IPs.
func (r *DNSResolver) SetDomainTable(dt *DomainTable) {
	r.domainTable = dt
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

	core.Log.Infof("DNS", "Resolver listening on %s (tunnels=%v, servers=%v, fallback_direct=%v)",
		r.config.ListenAddr, r.config.TunnelIDs, r.config.Servers, r.config.FallbackDirect)
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

// FlushCache clears the DNS response cache and domain table.
func (r *DNSResolver) FlushCache() {
	if r.cache != nil {
		r.cache.Flush()
		core.Log.Infof("DNS", "DNS cache flushed")
	}
	if r.domainTable != nil {
		r.domainTable.Flush()
		core.Log.Infof("DNS", "Domain table flushed")
	}
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

		// Limit concurrent handlers to prevent goroutine exhaustion.
		select {
		case r.udpSem <- struct{}{}:
			go func() {
				defer func() { <-r.udpSem }()
				r.handleUDPQuery(ctx, query, clientAddr)
			}()
		default:
			// Semaphore full — drop query silently (client will retry).
		}
	}
}

func (r *DNSResolver) handleUDPQuery(ctx context.Context, query []byte, clientAddr *net.UDPAddr) {
	name := extractDNSName(query)

	// Block AAAA (IPv6) queries — return empty NOERROR response.
	// IPv6 is disabled in the VPN stack; forwarding AAAA would leak IPv6 addresses.
	if isAAAAQuery(query) {
		if resp := makeEmptyResponse(query); resp != nil {
			r.udpConn.WriteToUDP(resp, clientAddr)
		}
		return
	}

	// Domain-based routing: intercept before cache/forwarding.
	// DNS forwarding goes through all configured tunnels in parallel.
	// Only the routeTunnelID (for DomainTable) reflects the domain rule's target.
	tunnelIDs := r.config.TunnelIDs
	routeTunnelID := ""
	if len(tunnelIDs) > 0 {
		routeTunnelID = tunnelIDs[0]
	}
	var domainResult DomainMatchResult
	if dm := r.domainMatcher.Load(); dm != nil && name != "" {
		domainResult = dm.Match(name)
		if domainResult.Matched {
			switch domainResult.Action {
			case core.DomainBlock:
				core.Log.Debugf("DNS", "%s blocked by domain rule (UDP)", name)
				if nxd := makeNXDomain(query); nxd != nil {
					r.udpConn.WriteToUDP(nxd, clientAddr)
				}
				return
			case core.DomainDirect:
				routeTunnelID = DirectTunnelID
			case core.DomainRoute:
				routeTunnelID = domainResult.TunnelID
			}
		}
	}

	// Cache lookup.
	if r.cache != nil {
		qName, qtype, qclass, err := parseDNSQuestion(query)
		if err == nil {
			queryID := getDNSTransactionID(query)
			if cached, ok := r.cache.Get(queryID, qName, qtype, qclass); ok {
				r.udpConn.WriteToUDP(cached, clientAddr)
				core.Log.Debugf("DNS", "%s cache hit (UDP)", name)
				// Record IPs from cached response too.
				if domainResult.Matched && r.domainTable != nil {
					r.recordDomainIPs(cached, name, routeTunnelID, domainResult.Action)
				}
				return
			}
		}
	}

	// Forward DNS query through all configured VPN tunnels in parallel.
	resp, server, usedTunnel, err := r.forwardUDPAll(ctx, tunnelIDs, query)
	if err == nil {
		r.cacheStore(query, resp)
		r.udpConn.WriteToUDP(resp, clientAddr)
		if name != "" {
			core.Log.Debugf("DNS", "%s → %s via %s (UDP, route=%s)", name, server, usedTunnel, routeTunnelID)
		}
		if domainResult.Matched && r.domainTable != nil {
			r.recordDomainIPs(resp, name, routeTunnelID, domainResult.Action)
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

	// Last resort: raw DNS via OS network stack (bypasses providers entirely).
	// Handles the case when all VPN tunnels are removed and __direct__ is unavailable.
	resp, err = r.forwardRawUDP(ctx, query)
	if err == nil {
		r.cacheStore(query, resp)
		r.udpConn.WriteToUDP(resp, clientAddr)
		if name != "" {
			core.Log.Debugf("DNS", "%s → raw fallback (UDP)", name)
		}
		return
	}

	core.Log.Warnf("DNS", "All tunnels/servers failed for %s (UDP): %v", name, err)
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

// forwardUDPAll fans out DNS queries across multiple tunnels simultaneously.
// Each tunnel independently fans out across all configured DNS servers.
// Returns the first successful response.
func (r *DNSResolver) forwardUDPAll(ctx context.Context, tunnelIDs []string, query []byte) ([]byte, netip.Addr, string, error) {
	if len(tunnelIDs) == 0 {
		return nil, netip.Addr{}, "", fmt.Errorf("no DNS tunnels configured")
	}

	// Single tunnel — no extra parallelism layer.
	if len(tunnelIDs) == 1 {
		resp, server, err := r.forwardUDP(ctx, tunnelIDs[0], query)
		return resp, server, tunnelIDs[0], err
	}

	type result struct {
		resp     []byte
		server   netip.Addr
		tunnelID string
		err      error
	}

	fanCtx, fanCancel := context.WithCancel(ctx)
	defer fanCancel()

	ch := make(chan result, len(tunnelIDs))
	for _, tid := range tunnelIDs {
		go func(tunnelID string) {
			resp, server, err := r.forwardUDP(fanCtx, tunnelID, query)
			ch <- result{resp, server, tunnelID, err}
		}(tid)
	}

	var lastErr error
	for range tunnelIDs {
		res := <-ch
		if res.err != nil {
			lastErr = res.err
			continue
		}
		fanCancel() // cancel remaining tunnel goroutines
		return res.resp, res.server, res.tunnelID, nil
	}

	return nil, netip.Addr{}, "", fmt.Errorf("all %d tunnels failed: %w", len(tunnelIDs), lastErr)
}

// forwardUDPSingle sends a DNS query to a single server via the given provider.
func (r *DNSResolver) forwardUDPSingle(ctx context.Context, prov provider.TunnelProvider, server netip.Addr, query []byte) ([]byte, netip.Addr, error) {
	addr := net.JoinHostPort(server.String(), "53")

	conn, err := prov.DialUDP(ctx, addr)
	if errors.Is(err, provider.ErrUDPNotSupported) {
		// Provider doesn't support UDP — use DNS-over-TCP (RFC 1035 §4.2.2).
		core.Log.Debugf("DNS", "UDP not supported by provider, falling back to TCP for %s", server)
		return r.forwardTCPSingle(ctx, prov, server, query)
	}
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

		// Limit concurrent handlers.
		select {
		case r.tcpSem <- struct{}{}:
			go func() {
				defer func() { <-r.tcpSem }()
				r.handleTCPQuery(ctx, conn)
			}()
		default:
			conn.Close() // reject when overloaded
		}
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

	// Block AAAA (IPv6) queries — return empty NOERROR response.
	if isAAAAQuery(query) {
		if resp := makeEmptyResponse(query); resp != nil {
			var respLen [2]byte
			binary.BigEndian.PutUint16(respLen[:], uint16(len(resp)))
			clientConn.Write(respLen[:])
			clientConn.Write(resp)
		}
		return
	}

	// Domain-based routing: intercept before cache/forwarding.
	// DNS forwarding goes through all configured tunnels in parallel.
	// Only the routeTunnelID (for DomainTable) reflects the domain rule's target.
	tunnelIDs := r.config.TunnelIDs
	routeTunnelID := ""
	if len(tunnelIDs) > 0 {
		routeTunnelID = tunnelIDs[0]
	}
	var domainResult DomainMatchResult
	if dm := r.domainMatcher.Load(); dm != nil && name != "" {
		domainResult = dm.Match(name)
		if domainResult.Matched {
			switch domainResult.Action {
			case core.DomainBlock:
				core.Log.Debugf("DNS", "%s blocked by domain rule (TCP)", name)
				if nxd := makeNXDomain(query); nxd != nil {
					var respLen [2]byte
					binary.BigEndian.PutUint16(respLen[:], uint16(len(nxd)))
					clientConn.Write(respLen[:])
					clientConn.Write(nxd)
				}
				return
			case core.DomainDirect:
				routeTunnelID = DirectTunnelID
			case core.DomainRoute:
				routeTunnelID = domainResult.TunnelID
			}
		}
	}

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
				if domainResult.Matched && r.domainTable != nil {
					r.recordDomainIPs(cached, name, routeTunnelID, domainResult.Action)
				}
				return
			}
		}
	}

	// Forward DNS query through all configured VPN tunnels in parallel.
	resp, server, usedTunnel, err := r.forwardTCPAll(ctx, tunnelIDs, query)
	if err != nil && r.config.FallbackDirect {
		resp, server, err = r.forwardTCP(ctx, DirectTunnelID, query)
		usedTunnel = DirectTunnelID
	}

	// Last resort: raw DNS via OS network stack.
	if err != nil {
		rawResp, rawErr := r.forwardRawUDP(ctx, query)
		if rawErr == nil {
			resp = rawResp
			err = nil
			usedTunnel = "raw"
		}
	}

	if err != nil {
		core.Log.Warnf("DNS", "All tunnels/servers failed for %s (TCP): %v", name, err)
		resp = makeServFail(query)
		if resp == nil {
			return
		}
	} else {
		r.cacheStore(query, resp)
		if name != "" {
			core.Log.Debugf("DNS", "%s → %s via %s (TCP, route=%s)", name, server, usedTunnel, routeTunnelID)
		}
		if domainResult.Matched && r.domainTable != nil {
			r.recordDomainIPs(resp, name, routeTunnelID, domainResult.Action)
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

// forwardTCPAll fans out DNS queries across multiple tunnels simultaneously via TCP.
// Each tunnel independently fans out across all configured DNS servers.
// Returns the first successful response.
func (r *DNSResolver) forwardTCPAll(ctx context.Context, tunnelIDs []string, query []byte) ([]byte, netip.Addr, string, error) {
	if len(tunnelIDs) == 0 {
		return nil, netip.Addr{}, "", fmt.Errorf("no DNS tunnels configured")
	}

	// Single tunnel — no extra parallelism layer.
	if len(tunnelIDs) == 1 {
		resp, server, err := r.forwardTCP(ctx, tunnelIDs[0], query)
		return resp, server, tunnelIDs[0], err
	}

	type result struct {
		resp     []byte
		server   netip.Addr
		tunnelID string
		err      error
	}

	fanCtx, fanCancel := context.WithCancel(ctx)
	defer fanCancel()

	ch := make(chan result, len(tunnelIDs))
	for _, tid := range tunnelIDs {
		go func(tunnelID string) {
			resp, server, err := r.forwardTCP(fanCtx, tunnelID, query)
			ch <- result{resp, server, tunnelID, err}
		}(tid)
	}

	var lastErr error
	for range tunnelIDs {
		res := <-ch
		if res.err != nil {
			lastErr = res.err
			continue
		}
		fanCancel() // cancel remaining tunnel goroutines
		return res.resp, res.server, res.tunnelID, nil
	}

	return nil, netip.Addr{}, "", fmt.Errorf("all %d tunnels failed (TCP): %w", len(tunnelIDs), lastErr)
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

// defaultFallbackServers are used when all configured tunnels and direct
// provider fail. These provide a last-resort DNS resolution path.
var defaultFallbackServers = []string{"8.8.8.8:53", "1.1.1.1:53"}

// forwardRawUDP sends a DNS query directly via the OS network stack (bypassing
// providers) as a last resort when all tunnels and the direct provider fail.
func (r *DNSResolver) forwardRawUDP(ctx context.Context, query []byte) ([]byte, error) {
	servers := make([]string, 0, len(r.config.Servers)+2)
	for _, s := range r.config.Servers {
		servers = append(servers, net.JoinHostPort(s.String(), "53"))
	}
	if len(servers) == 0 {
		servers = defaultFallbackServers
	}

	var lastErr error
	for _, addr := range servers {
		d := net.Dialer{Timeout: r.config.Timeout}
		conn, err := d.DialContext(ctx, "udp4", addr)
		if err != nil {
			lastErr = err
			continue
		}
		conn.SetDeadline(time.Now().Add(r.config.Timeout))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			lastErr = err
			continue
		}
		resp := make([]byte, 4096)
		n, err := conn.Read(resp)
		conn.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if n < 12 {
			lastErr = fmt.Errorf("response too short (%d bytes)", n)
			continue
		}
		return resp[:n], nil
	}
	return nil, fmt.Errorf("raw fallback DNS failed: %w", lastErr)
}

// isAAAAQuery checks if a DNS query is an AAAA (IPv6) query.
// AAAA record type = 28 (0x001C).
func isAAAAQuery(query []byte) bool {
	if len(query) < 12 {
		return false
	}
	// Skip header (12 bytes), then QNAME labels.
	pos := 12
	for pos < len(query) {
		labelLen := int(query[pos])
		if labelLen == 0 {
			pos++ // skip root label
			break
		}
		if labelLen >= 64 {
			break // pointer — shouldn't be in query
		}
		pos += 1 + labelLen
	}
	// QTYPE is 2 bytes after QNAME.
	if pos+2 > len(query) {
		return false
	}
	qtype := binary.BigEndian.Uint16(query[pos : pos+2])
	return qtype == 28 // AAAA
}

// makeEmptyResponse creates a NOERROR response with zero answer records.
// Used to suppress AAAA responses when IPv6 is disabled.
func makeEmptyResponse(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, len(query))
	copy(resp, query)
	// Set QR=1 (response), RCODE=0 (NOERROR).
	resp[2] = query[2] | 0x80 // QR=1
	resp[3] = query[3] & 0xF0 // RCODE=NOERROR
	// Zero answer/authority/additional counts.
	resp[6], resp[7] = 0, 0
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0
	return resp
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

// makeNXDomain creates an NXDOMAIN response for the given query.
func makeNXDomain(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}

	resp := make([]byte, len(query))
	copy(resp, query)

	// Set QR=1 (response), RCODE=3 (NXDOMAIN).
	resp[2] = query[2] | 0x80       // QR=1
	resp[3] = (query[3] & 0xF0) | 0x03 // RCODE=NXDOMAIN
	// Zero answer/authority/additional counts.
	resp[6], resp[7] = 0, 0
	resp[8], resp[9] = 0, 0
	resp[10], resp[11] = 0, 0

	return resp
}

// recordDomainIPs extracts A records from a DNS response and inserts them into the domain table.
func (r *DNSResolver) recordDomainIPs(resp []byte, domain string, tunnelID string, action core.DomainAction) {
	if len(resp) < 12 {
		return
	}

	// ANCOUNT = bytes 6-7.
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return
	}

	// Skip header (12 bytes) + question section.
	pos := 12
	// Skip QNAME.
	for pos < len(resp) {
		labelLen := int(resp[pos])
		if labelLen == 0 {
			pos++ // skip root label
			break
		}
		if labelLen >= 0xC0 { // pointer
			pos += 2
			break
		}
		pos += 1 + labelLen
	}
	// Skip QTYPE (2) + QCLASS (2).
	pos += 4

	// Parse answer RRs.
	recorded := 0
	for i := 0; i < ancount && pos < len(resp); i++ {
		// Skip NAME (may be pointer or labels).
		if pos >= len(resp) {
			break
		}
		if resp[pos]&0xC0 == 0xC0 { // pointer
			pos += 2
		} else {
			for pos < len(resp) {
				labelLen := int(resp[pos])
				if labelLen == 0 {
					pos++
					break
				}
				if labelLen >= 0xC0 {
					pos += 2
					break
				}
				pos += 1 + labelLen
			}
		}

		// Need at least 10 bytes: TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2).
		if pos+10 > len(resp) {
			break
		}

		rrType := binary.BigEndian.Uint16(resp[pos : pos+2])
		ttl := binary.BigEndian.Uint32(resp[pos+4 : pos+8])
		rdLength := int(binary.BigEndian.Uint16(resp[pos+8 : pos+10]))
		pos += 10

		if pos+rdLength > len(resp) {
			break
		}

		// A record: type=1, rdLength=4.
		if rrType == 1 && rdLength == 4 {
			var ip [4]byte
			copy(ip[:], resp[pos:pos+4])

			// Clamp TTL: min 60s, max 3600s.
			clampedTTL := ttl
			if clampedTTL < 60 {
				clampedTTL = 60
			}
			if clampedTTL > 3600 {
				clampedTTL = 3600
			}

			r.domainTable.Insert(ip, &DomainEntry{
				TunnelID:  tunnelID,
				Action:    action,
				Domain:    domain,
				ExpiresAt: time.Now().Unix() + int64(clampedTTL),
			})
			recorded++
		}

		pos += rdLength
	}

	if recorded > 0 {
		core.Log.Debugf("DNS", "Recorded %d IPs for %s → %s (%s)", recorded, domain, tunnelID, action)
	}
}
