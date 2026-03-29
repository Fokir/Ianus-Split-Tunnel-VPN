package gateway

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/provider"
)

// dnsLatencyRecord stores EWMA latency for a single tunnel's DNS resolution.
type dnsLatencyRecord struct {
	ewma  int64 // atomic; microseconds
	count int64 // atomic; number of measurements
}

// DNSLatencyTracker tracks per-tunnel DNS resolution latency using EWMA.
type DNSLatencyTracker struct {
	mu      sync.RWMutex
	records map[string]*dnsLatencyRecord
}

const dnsInitialLatencyUs = 100_000 // 100ms initial EWMA for new tunnels

func newDNSLatencyTracker() *DNSLatencyTracker {
	return &DNSLatencyTracker{
		records: make(map[string]*dnsLatencyRecord),
	}
}

// Record updates the EWMA for a tunnel after a successful DNS response.
// Formula: new = 0.3 * measured + 0.7 * previous (integer arithmetic).
func (t *DNSLatencyTracker) Record(tunnelID string, latencyUs int64) {
	t.mu.RLock()
	rec, ok := t.records[tunnelID]
	t.mu.RUnlock()

	if !ok {
		t.mu.Lock()
		rec, ok = t.records[tunnelID]
		if !ok {
			rec = &dnsLatencyRecord{ewma: dnsInitialLatencyUs}
			t.records[tunnelID] = rec
		}
		t.mu.Unlock()
	}

	atomic.AddInt64(&rec.count, 1)

	for {
		old := atomic.LoadInt64(&rec.ewma)
		updated := (3*latencyUs + 7*old) / 10
		if atomic.CompareAndSwapInt64(&rec.ewma, old, updated) {
			break
		}
	}
}

// GetEWMA returns the current EWMA latency in microseconds for a tunnel.
func (t *DNSLatencyTracker) GetEWMA(tunnelID string) int64 {
	t.mu.RLock()
	rec, ok := t.records[tunnelID]
	t.mu.RUnlock()
	if !ok {
		return dnsInitialLatencyUs
	}
	return atomic.LoadInt64(&rec.ewma)
}

// RankTunnels returns tunnel IDs sorted by EWMA latency (ascending).
func (t *DNSLatencyTracker) RankTunnels(tunnelIDs []string) []string {
	if len(tunnelIDs) <= 1 {
		return tunnelIDs
	}
	ranked := make([]string, len(tunnelIDs))
	copy(ranked, tunnelIDs)
	sort.Slice(ranked, func(i, j int) bool {
		return t.GetEWMA(ranked[i]) < t.GetEWMA(ranked[j])
	})
	return ranked
}

// dnsRespPool is a pool of 4KB buffers for DNS UDP response reads.
// Used in forwardUDPSingle to avoid allocating 4KB per DNS query.
var dnsRespPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

// dnsUDPConnCache pools persistent SOCKS5 UDP connections per (tunnel, server)
// pair to avoid creating a new SOCKS5 UDP ASSOCIATE for every DNS query.
// This dramatically reduces connection churn and memory usage in xray-core.
type dnsUDPConnCache struct {
	mu    sync.Mutex
	pools map[string][]net.Conn
}

func newDNSUDPConnCache() *dnsUDPConnCache {
	return &dnsUDPConnCache{
		pools: make(map[string][]net.Conn),
	}
}

const dnsUDPConnCacheMaxPerKey = 4

func (c *dnsUDPConnCache) Get(tunnelID string, server netip.Addr) net.Conn {
	key := tunnelID + "\x00" + server.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if conns := c.pools[key]; len(conns) > 0 {
		conn := conns[len(conns)-1]
		c.pools[key] = conns[:len(conns)-1]
		return conn
	}
	return nil
}

func (c *dnsUDPConnCache) Put(tunnelID string, server netip.Addr, conn net.Conn) {
	key := tunnelID + "\x00" + server.String()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.pools[key]) >= dnsUDPConnCacheMaxPerKey {
		conn.Close()
		return
	}
	c.pools[key] = append(c.pools[key], conn)
}

func (c *dnsUDPConnCache) CloseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, conns := range c.pools {
		for _, conn := range conns {
			conn.Close()
		}
		delete(c.pools, k)
	}
}

func (c *dnsUDPConnCache) InvalidateTunnel(tunnelID string) {
	prefix := tunnelID + "\x00"
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, conns := range c.pools {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix {
			for _, conn := range conns {
				conn.Close()
			}
			delete(c.pools, k)
		}
	}
}

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

	// Domain-based routing.
	domainMatcher atomic.Pointer[DomainMatcher]
	domainTable   atomic.Pointer[DomainTable]

	// FakeIP pool for synthetic IP allocation (nil if disabled).
	fakeIPPool atomic.Pointer[FakeIPPool]

	// onDirectIPs is called when DNS resolves IPs for a DomainDirect domain.
	// Used to add WFP permit rules before returning the response to the app.
	onDirectIPs func(ips []netip.Addr)

	// Goroutine limiters to prevent resource exhaustion under DNS flood.
	udpSem chan struct{} // limits concurrent UDP handlers
	tcpSem chan struct{} // limits concurrent TCP handlers

	// tunnelDNS stores per-tunnel DNS servers (tunnelID → []netip.Addr).
	// Used for tunnels like AnyConnect that provide their own DNS servers.
	tunnelDNS sync.Map

	// udpConnCache pools persistent UDP connections to avoid creating a
	// new SOCKS5 UDP ASSOCIATE per DNS query (major xray-core memory saver).
	udpConnCache *dnsUDPConnCache

	// latencyTracker tracks per-tunnel DNS resolution latency using EWMA.
	latencyTracker *DNSLatencyTracker

	started atomic.Bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
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
		config:         config,
		registry:       registry,
		providers:      providers,
		udpSem:         make(chan struct{}, 200),
		tcpSem:         make(chan struct{}, 100),
		udpConnCache:   newDNSUDPConnCache(),
		latencyTracker: newDNSLatencyTracker(),
	}

	return r
}

// SetDirectIPCallback sets the callback invoked when DNS resolves IPs for
// DomainDirect domains. The callback receives the resolved IPs and should
// add WFP permit rules before the DNS response reaches the application.
func (r *DNSResolver) SetDirectIPCallback(fn func(ips []netip.Addr)) {
	r.onDirectIPs = fn
}

// SetDomainMatcher atomically sets the domain matcher for DNS interception.
func (r *DNSResolver) SetDomainMatcher(m *DomainMatcher) {
	r.domainMatcher.Store(m)
}

// SetDomainTable sets the domain table for recording resolved IPs.
func (r *DNSResolver) SetDomainTable(dt *DomainTable) {
	r.domainTable.Store(dt)
}

// SetFakeIPPool sets the FakeIP pool for DNS response rewriting.
func (r *DNSResolver) SetFakeIPPool(pool *FakeIPPool) {
	r.fakeIPPool.Store(pool)
}

// SetTunnelDNS registers per-tunnel DNS servers. When a domain rule routes
// a query through this tunnel, these servers are used instead of global ones.
func (r *DNSResolver) SetTunnelDNS(tunnelID string, servers []netip.Addr) {
	r.tunnelDNS.Store(tunnelID, servers)
	core.Log.Infof("DNS", "Per-tunnel DNS for %q: %v", tunnelID, servers)
}

// RemoveTunnelDNS removes per-tunnel DNS servers for a tunnel.
func (r *DNSResolver) RemoveTunnelDNS(tunnelID string) {
	r.tunnelDNS.Delete(tunnelID)
}

// Start begins listening for DNS queries on UDP and TCP.
func (r *DNSResolver) Start(ctx context.Context) error {
	if !r.started.CompareAndSwap(false, true) {
		return errors.New("[DNS] resolver already started")
	}

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
	core.SuperviseWG(ctx, &r.wg, core.SupervisorConfig{Name: "dns.udp-loop"}, r.udpLoop)
	core.SuperviseWG(ctx, &r.wg, core.SupervisorConfig{Name: "dns.tcp-loop"}, r.tcpLoop)

	core.Log.Infof("DNS", "Resolver listening on %s (tunnels=%v, servers=%v, fallback_direct=%v)",
		r.config.ListenAddr, r.config.TunnelIDs, r.config.Servers, r.config.FallbackDirect)
	return nil
}

// Stop shuts down the resolver.
func (r *DNSResolver) Stop() {
	if !r.started.CompareAndSwap(true, false) {
		return
	}
	if r.cancel != nil {
		r.cancel()
	}
	if r.udpConn != nil {
		r.udpConn.Close()
	}
	if r.tcpLn != nil {
		r.tcpLn.Close()
	}
	r.udpConnCache.CloseAll()
	r.wg.Wait()
	core.Log.Infof("DNS", "Resolver stopped")
}

// FlushCache clears the domain table.
func (r *DNSResolver) FlushCache() {
	if dt := r.domainTable.Load(); dt != nil {
		dt.Flush()
		core.Log.Infof("DNS", "Domain table flushed")
	}
}

// ---------------------------------------------------------------------------
// UDP DNS
// ---------------------------------------------------------------------------

func (r *DNSResolver) udpLoop(ctx context.Context) {
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
			core.SafeGo("dns.handle-udp-query", func() {
				defer func() { <-r.udpSem }()
				r.handleUDPQuery(ctx, query, clientAddr)
			})
		default:
			// Semaphore full — drop query silently (client will retry).
		}
	}
}

func (r *DNSResolver) handleUDPQuery(ctx context.Context, query []byte, clientAddr *net.UDPAddr) {
	resp := r.Resolve(ctx, query)
	if resp != nil {
		if _, err := r.udpConn.WriteToUDP(resp, clientAddr); err != nil {
			core.Log.Warnf("DNS", "WriteToUDP to %s: %v", clientAddr, err)
		}
	}
}

// Resolve processes a raw DNS query and returns the response bytes.
// This is the core DNS resolution logic used by both the socket listener
// (via handleUDPQuery) and the TUN router's in-band DNS hijack.
func (r *DNSResolver) Resolve(ctx context.Context, query []byte) []byte {
	start := time.Now()
	name := extractDNSName(query)

	// Block AAAA (IPv6) queries — return empty NOERROR response.
	// IPv6 is disabled in the VPN stack; forwarding AAAA would leak IPv6 addresses.
	if isAAAAQuery(query) {
		return makeEmptyResponse(query)
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
				return makeNXDomain(query)
			case core.DomainDirect:
				routeTunnelID = DirectTunnelID
			case core.DomainRoute:
				routeTunnelID = domainResult.TunnelID
				// If the target tunnel has its own DNS servers, route DNS through it.
				if _, ok := r.tunnelDNS.Load(domainResult.TunnelID); ok {
					tunnelIDs = []string{domainResult.TunnelID}
				}
			}
		}
	}

	// Forward DNS query through all configured VPN tunnels in parallel.
	resp, server, usedTunnel, err := r.forwardUDPAll(ctx, tunnelIDs, query)
	if err == nil {
		// FakeIP rewriting: for domain-matched queries, rewrite A records to FakeIP
		// BEFORE caching so cache hits also return FakeIPs.
		if domainResult.Matched && domainResult.Action != core.DomainBlock {
			resp = r.rewriteResponseWithFakeIP(resp, name, routeTunnelID, domainResult.Action)
		}
		if name != "" {
			core.Log.Debugf("DNS", "%s → %s via %s (UDP, route=%s) [%s]", name, server, usedTunnel, routeTunnelID, time.Since(start))
		}
		if domainResult.Matched {
			r.recordDomainIPs(resp, name, routeTunnelID, domainResult.Action)
		}
		return resp
	}

	// Fallback: try direct provider.
	if r.config.FallbackDirect {
		resp, server, err = r.forwardUDP(ctx, DirectTunnelID, query)
		if err == nil {
			if name != "" {
				core.Log.Debugf("DNS", "%s → %s via direct/fallback (UDP) [%s]", name, server, time.Since(start))
			}
			return resp
		}
	}

	// Last resort: raw DNS via OS network stack (bypasses providers entirely).
	// Handles the case when all VPN tunnels are removed and __direct__ is unavailable.
	resp, err = r.forwardRawUDP(ctx, query)
	if err == nil {
		if name != "" {
			core.Log.Debugf("DNS", "%s → raw fallback (UDP) [%s]", name, time.Since(start))
		}
		return resp
	}

	core.Log.Warnf("DNS", "All tunnels/servers failed for %s (UDP): %v [%s]", name, err, time.Since(start))
	return makeServFail(query)
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

	// Per-tunnel DNS servers override global ones (e.g. AnyConnect corporate DNS).
	servers := r.config.Servers
	if val, ok := r.tunnelDNS.Load(tunnelID); ok {
		servers = val.([]netip.Addr)
	}
	if len(servers) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("no DNS servers configured")
	}

	// Single server — no parallelism overhead.
	if len(servers) == 1 {
		return r.forwardUDPSingle(ctx, prov, tunnelID, servers[0], query)
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
			defer func() {
				if v := recover(); v != nil {
					core.Log.Errorf("DNS", "panic in forwardUDPSingle to %s: %v", server, v)
					ch <- result{err: fmt.Errorf("panic: %v", v)}
				}
			}()
			resp, _, err := r.forwardUDPSingle(fanCtx, prov, tunnelID, server, query)
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
			defer func() {
				if v := recover(); v != nil {
					core.Log.Errorf("DNS", "panic in forwardUDP for tunnel %s: %v", tunnelID, v)
					ch <- result{err: fmt.Errorf("panic: %v", v)}
				}
			}()
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
func (r *DNSResolver) forwardUDPSingle(ctx context.Context, prov provider.TunnelProvider, tunnelID string, server netip.Addr, query []byte) ([]byte, netip.Addr, error) {
	start := time.Now()
	addr := net.JoinHostPort(server.String(), "53")

	// Try cached connection first, then fresh connection. Retry once on stale cached conn.
	for attempt := range 2 {
		var conn net.Conn
		var cached bool

		if attempt == 0 {
			conn = r.udpConnCache.Get(tunnelID, server)
		}
		if conn == nil {
			var err error
			conn, err = prov.DialUDP(ctx, addr)
			if errors.Is(err, provider.ErrUDPNotSupported) {
				// Provider doesn't support UDP — use DNS-over-TCP (RFC 1035 §4.2.2).
				core.Log.Debugf("DNS", "UDP not supported by provider, falling back to TCP for %s", server)
				return r.forwardTCPSingle(ctx, prov, tunnelID, server, query)
			}
			if err != nil {
				return nil, server, err
			}
		} else {
			cached = true
		}

		if deadline, ok := ctx.Deadline(); ok {
			conn.SetDeadline(deadline)
		} else {
			conn.SetDeadline(time.Now().Add(r.config.Timeout))
		}

		if _, err := conn.Write(query); err != nil {
			conn.Close()
			if cached {
				continue // retry with fresh connection
			}
			return nil, server, err
		}

		// Use pooled 4KB buffer for reading, then copy to right-sized result.
		// This avoids pinning 4KB per response (especially in DNS cache).
		bp := dnsRespPool.Get().(*[]byte)
		n, err := conn.Read(*bp)
		if err != nil {
			dnsRespPool.Put(bp)
			conn.Close()
			if cached {
				continue // retry with fresh connection
			}
			return nil, server, err
		}

		if n < 12 {
			dnsRespPool.Put(bp)
			conn.Close()
			return nil, server, fmt.Errorf("response too short (%d bytes)", n)
		}

		// Validate DNS transaction ID matches the query to prevent cache poisoning.
		if (*bp)[0] != query[0] || (*bp)[1] != query[1] {
			dnsRespPool.Put(bp)
			conn.Close()
			return nil, server, fmt.Errorf("DNS transaction ID mismatch (got 0x%02x%02x, want 0x%02x%02x)", (*bp)[0], (*bp)[1], query[0], query[1])
		}

		result := make([]byte, n)
		copy(result, (*bp)[:n])
		dnsRespPool.Put(bp)

		// Return connection to cache for reuse.
		conn.SetDeadline(time.Time{})
		r.udpConnCache.Put(tunnelID, server, conn)

		r.latencyTracker.Record(tunnelID, time.Since(start).Microseconds())
		return result, server, nil
	}

	return nil, server, fmt.Errorf("DNS query to %s via %s failed after retry", server, tunnelID)
}

// ---------------------------------------------------------------------------
// TCP DNS
// ---------------------------------------------------------------------------

func (r *DNSResolver) tcpLoop(ctx context.Context) {
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
			core.SafeGo("dns.handle-tcp-query", func() {
				defer func() { <-r.tcpSem }()
				r.handleTCPQuery(ctx, conn)
			})
		default:
			conn.Close() // reject when overloaded
		}
	}
}

// writeTCPDNSResponse writes a DNS response with a 2-byte length prefix to a TCP connection.
func writeTCPDNSResponse(conn net.Conn, resp []byte) error {
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(resp)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := conn.Write(resp)
	return err
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

	start := time.Now()
	name := extractDNSName(query)

	// Block AAAA (IPv6) queries — return empty NOERROR response.
	if isAAAAQuery(query) {
		if resp := makeEmptyResponse(query); resp != nil {
			if err := writeTCPDNSResponse(clientConn, resp); err != nil {
				core.Log.Warnf("DNS", "TCP write AAAA block response: %v", err)
			}
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
					if err := writeTCPDNSResponse(clientConn, nxd); err != nil {
						core.Log.Warnf("DNS", "TCP write NXDomain response: %v", err)
					}
				}
				return
			case core.DomainDirect:
				routeTunnelID = DirectTunnelID
			case core.DomainRoute:
				routeTunnelID = domainResult.TunnelID
				// If the target tunnel has its own DNS servers, route DNS through it.
				if _, ok := r.tunnelDNS.Load(domainResult.TunnelID); ok {
					tunnelIDs = []string{domainResult.TunnelID}
				}
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
		core.Log.Warnf("DNS", "All tunnels/servers failed for %s (TCP): %v [%s]", name, err, time.Since(start))
		resp = makeServFail(query)
		if resp == nil {
			return
		}
	} else {
		// FakeIP rewriting: for domain-matched queries, rewrite A records to FakeIP
		// BEFORE caching so cache hits also return FakeIPs.
		if domainResult.Matched && domainResult.Action != core.DomainBlock {
			resp = r.rewriteResponseWithFakeIP(resp, name, routeTunnelID, domainResult.Action)
		}
		if name != "" {
			core.Log.Debugf("DNS", "%s → %s via %s (TCP, route=%s) [%s]", name, server, usedTunnel, routeTunnelID, time.Since(start))
		}
		if domainResult.Matched {
			r.recordDomainIPs(resp, name, routeTunnelID, domainResult.Action)
		}
	}

	// Write response with length prefix.
	if err := writeTCPDNSResponse(clientConn, resp); err != nil {
		core.Log.Warnf("DNS", "TCP write response for %s: %v", name, err)
	}
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

	// Per-tunnel DNS servers override global ones.
	servers := r.config.Servers
	if val, ok := r.tunnelDNS.Load(tunnelID); ok {
		servers = val.([]netip.Addr)
	}
	if len(servers) == 0 {
		return nil, netip.Addr{}, fmt.Errorf("no DNS servers configured")
	}

	// Single server — no parallelism overhead.
	if len(servers) == 1 {
		return r.forwardTCPSingle(ctx, prov, tunnelID, servers[0], query)
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
			defer func() {
				if v := recover(); v != nil {
					core.Log.Errorf("DNS", "panic in forwardTCPSingle to %s: %v", server, v)
					ch <- result{err: fmt.Errorf("panic: %v", v)}
				}
			}()
			resp, _, err := r.forwardTCPSingle(fanCtx, prov, tunnelID, server, query)
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
			defer func() {
				if v := recover(); v != nil {
					core.Log.Errorf("DNS", "panic in forwardTCP for tunnel %s: %v", tunnelID, v)
					ch <- result{err: fmt.Errorf("panic: %v", v)}
				}
			}()
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
func (r *DNSResolver) forwardTCPSingle(ctx context.Context, prov provider.TunnelProvider, tunnelID string, server netip.Addr, query []byte) ([]byte, netip.Addr, error) {
	start := time.Now()
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

	r.latencyTracker.Record(tunnelID, time.Since(start).Microseconds())
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
		bp := dnsRespPool.Get().(*[]byte)
		n, err := conn.Read(*bp)
		conn.Close()
		if err != nil {
			dnsRespPool.Put(bp)
			lastErr = err
			continue
		}
		if n < 12 {
			dnsRespPool.Put(bp)
			lastErr = fmt.Errorf("response too short (%d bytes)", n)
			continue
		}
		result := make([]byte, n)
		copy(result, (*bp)[:n])
		dnsRespPool.Put(bp)
		return result, nil
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
	dt := r.domainTable.Load()
	if dt == nil || len(resp) < 12 {
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
	var directIPs []netip.Addr
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
			clampedTTL := max(60, min(ttl, 3600))

			dt.Insert(ip, &DomainEntry{
				TunnelID:  tunnelID,
				Action:    action,
				Domain:    domain,
				ExpiresAt: time.Now().Unix() + int64(clampedTTL),
			})
			recorded++

			if action == core.DomainDirect && r.onDirectIPs != nil {
				directIPs = append(directIPs, netip.AddrFrom4(ip))
			}
		}

		pos += rdLength
	}

	// Add WFP permit rules for direct IPs before returning the DNS response,
	// so the app can connect directly through the real NIC.
	if len(directIPs) > 0 {
		r.onDirectIPs(directIPs)
	}

	if recorded > 0 {
		core.Log.Debugf("DNS", "Recorded %d IPs for %s → %s (%s)", recorded, domain, tunnelID, action)
	}
}

// rewriteResponseWithFakeIP rewrites A-record IPs in a DNS response to a FakeIP,
// records the FakeIP in the DomainTable, and returns the modified response.
// Returns the original response unchanged if FakeIP allocation fails.
func (r *DNSResolver) rewriteResponseWithFakeIP(resp []byte, domain string, tunnelID string, action core.DomainAction) []byte {
	fakeIPPool := r.fakeIPPool.Load()
	if fakeIPPool == nil || len(resp) < 12 {
		return resp
	}

	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		return resp
	}

	// First pass: extract real IPs from A records.
	var realIPs [][4]byte
	pos := 12
	// Skip QNAME.
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
	pos += 4 // skip QTYPE + QCLASS

	// Collect A record positions and IPs.
	type aRecordPos struct {
		rdataOff int
		ttlOff   int
	}
	var aPositions []aRecordPos

	scanPos := pos
	for i := 0; i < ancount && scanPos < len(resp); i++ {
		if scanPos >= len(resp) {
			break
		}
		if resp[scanPos]&0xC0 == 0xC0 {
			scanPos += 2
		} else {
			for scanPos < len(resp) {
				labelLen := int(resp[scanPos])
				if labelLen == 0 {
					scanPos++
					break
				}
				if labelLen >= 0xC0 {
					scanPos += 2
					break
				}
				scanPos += 1 + labelLen
			}
		}

		if scanPos+10 > len(resp) {
			break
		}

		rrType := binary.BigEndian.Uint16(resp[scanPos : scanPos+2])
		rdLength := int(binary.BigEndian.Uint16(resp[scanPos+8 : scanPos+10]))
		ttlOff := scanPos + 4
		scanPos += 10

		if scanPos+rdLength > len(resp) {
			break
		}

		if rrType == 1 && rdLength == 4 { // A record
			var ip [4]byte
			copy(ip[:], resp[scanPos:scanPos+4])
			realIPs = append(realIPs, ip)
			aPositions = append(aPositions, aRecordPos{rdataOff: scanPos, ttlOff: ttlOff})
		}

		scanPos += rdLength
	}

	if len(realIPs) == 0 {
		return resp
	}

	// Allocate FakeIP for this domain.
	fakeIP, err := fakeIPPool.AllocateForDomain(domain, realIPs, tunnelID, action)
	if err != nil {
		core.Log.Warnf("DNS", "FakeIP allocation failed for %s: %v (using real IPs)", domain, err)
		return resp
	}

	// Clone response for in-place modification.
	modified := make([]byte, len(resp))
	copy(modified, resp)

	// Rewrite all A records to the FakeIP and set long TTL.
	for _, ap := range aPositions {
		copy(modified[ap.rdataOff:ap.rdataOff+4], fakeIP[:])
		binary.BigEndian.PutUint32(modified[ap.ttlOff:ap.ttlOff+4], 3600) // 1 hour TTL
	}

	// Record FakeIP in DomainTable (never expires — ExpiresAt=0).
	if dt := r.domainTable.Load(); dt != nil {
		dt.Insert(fakeIP, &DomainEntry{
			TunnelID:  tunnelID,
			Action:    action,
			Domain:    domain,
			ExpiresAt: 0, // never expires
		})
	}

	core.Log.Debugf("DNS", "FakeIP: %s → %d.%d.%d.%d (real: %d IPs, tunnel=%s, action=%s)",
		domain, fakeIP[0], fakeIP[1], fakeIP[2], fakeIP[3], len(realIPs), tunnelID, action)

	return modified
}
