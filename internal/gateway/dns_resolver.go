//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
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
	return &DNSResolver{
		config:    config,
		registry:  registry,
		providers: providers,
	}
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

	log.Printf("[DNS] Resolver listening on %s (tunnel=%s, servers=%v, fallback_direct=%v)",
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
	log.Printf("[DNS] Resolver stopped")
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
				log.Printf("[DNS] UDP read error: %v", err)
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

	// Try VPN tunnel first.
	resp, server, err := r.forwardUDP(ctx, r.config.TunnelID, query)
	if err == nil {
		r.udpConn.WriteToUDP(resp, clientAddr)
		if name != "" {
			log.Printf("[DNS] %s → %s via %s (UDP)", name, server, r.config.TunnelID)
		}
		return
	}

	// Fallback: try direct provider.
	if r.config.FallbackDirect {
		resp, server, err = r.forwardUDP(ctx, DirectTunnelID, query)
		if err == nil {
			r.udpConn.WriteToUDP(resp, clientAddr)
			if name != "" {
				log.Printf("[DNS] %s → %s via direct/fallback (UDP)", name, server)
			}
			return
		}
	}

	log.Printf("[DNS] All servers failed for %s (UDP): %v", name, err)
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

	for _, server := range r.config.Servers {
		addr := net.JoinHostPort(server.String(), "53")

		dialCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
		conn, err := prov.DialUDP(dialCtx, addr)
		cancel()
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(r.config.Timeout))
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			continue
		}

		resp := make([]byte, 4096)
		n, err := conn.Read(resp)
		conn.Close()

		if err != nil {
			continue
		}

		if n >= 12 {
			return resp[:n], server, nil
		}
	}

	return nil, netip.Addr{}, fmt.Errorf("all %d servers unreachable via %s", len(r.config.Servers), tunnelID)
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
				log.Printf("[DNS] TCP accept error: %v", err)
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

	// Try VPN tunnel.
	resp, server, err := r.forwardTCP(ctx, r.config.TunnelID, query)
	if err != nil && r.config.FallbackDirect {
		resp, server, err = r.forwardTCP(ctx, DirectTunnelID, query)
	}

	if err != nil {
		log.Printf("[DNS] All servers failed for %s (TCP): %v", name, err)
		resp = makeServFail(query)
		if resp == nil {
			return
		}
	} else if name != "" {
		log.Printf("[DNS] %s → %s via %s (TCP)", name, server, r.config.TunnelID)
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

	for _, server := range r.config.Servers {
		addr := net.JoinHostPort(server.String(), "53")

		dialCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
		conn, err := prov.DialTCP(dialCtx, addr)
		cancel()
		if err != nil {
			continue
		}

		conn.SetDeadline(time.Now().Add(r.config.Timeout))

		// Write with length prefix.
		var qLenBuf [2]byte
		binary.BigEndian.PutUint16(qLenBuf[:], uint16(len(query)))
		if _, err := conn.Write(qLenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		if _, err := conn.Write(query); err != nil {
			conn.Close()
			continue
		}

		// Read response length.
		var rLenBuf [2]byte
		if _, err := io.ReadFull(conn, rLenBuf[:]); err != nil {
			conn.Close()
			continue
		}
		rLen := int(binary.BigEndian.Uint16(rLenBuf[:]))
		if rLen < 12 || rLen > 65535 {
			conn.Close()
			continue
		}

		resp := make([]byte, rLen)
		if _, err := io.ReadFull(conn, resp); err != nil {
			conn.Close()
			continue
		}
		conn.Close()
		return resp, server, nil
	}

	return nil, netip.Addr{}, fmt.Errorf("all %d servers unreachable via %s (TCP)", len(r.config.Servers), tunnelID)
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
