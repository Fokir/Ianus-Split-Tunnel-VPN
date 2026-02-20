//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"log"
	"net/netip"
	"sync/atomic"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/process"
)

// DirectTunnelID is the special tunnel ID for unmatched traffic routed via real NIC.
const DirectTunnelID = "__direct__"

// TUNRouter reads packets from the WinTUN adapter and performs:
// - Process identification via GetExtendedTcpTable/UdpTable
// - Rule matching via RuleEngine
// - Lazy WFP rule addition via WFPManager
// - NAT hairpin redirect to appropriate tunnel proxy
// - DNS routing via DNSRouter
type TUNRouter struct {
	adapter   *Adapter
	flows     *FlowTable
	procID    *ProcessIdentifier
	matcher   *process.Matcher
	rules     *core.RuleEngine
	registry  *core.TunnelRegistry
	wfp       *WFPManager
	dnsRouter *DNSRouter

	tunIP [4]byte // 10.255.0.1 in network byte order

	cancel context.CancelFunc
	done   chan struct{}
}

// NewTUNRouter creates a TUN router with all dependencies.
func NewTUNRouter(
	adapter *Adapter,
	flows *FlowTable,
	procID *ProcessIdentifier,
	matcher *process.Matcher,
	rules *core.RuleEngine,
	registry *core.TunnelRegistry,
	wfp *WFPManager,
	dnsRouter *DNSRouter,
) *TUNRouter {
	return &TUNRouter{
		adapter:   adapter,
		flows:     flows,
		procID:    procID,
		matcher:   matcher,
		rules:     rules,
		registry:  registry,
		wfp:       wfp,
		dnsRouter: dnsRouter,
		tunIP:     adapter.IP().As4(),
		done:      make(chan struct{}),
	}
}

// Start begins the packet processing loop.
func (r *TUNRouter) Start(ctx context.Context) error {
	ctx, r.cancel = context.WithCancel(ctx)

	r.flows.StartTimestampUpdater(ctx)
	r.flows.StartTCPCleanup(ctx)
	r.flows.StartUDPCleanup(ctx)

	go r.packetLoop(ctx)

	log.Printf("[Gateway] TUN Router started")
	return nil
}

// Stop halts the packet processing loop.
func (r *TUNRouter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	<-r.done
	log.Printf("[Gateway] TUN Router stopped")
}

// packetLoop is the main processing goroutine.
func (r *TUNRouter) packetLoop(ctx context.Context) {
	defer close(r.done)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pkt, err := r.adapter.ReadPacket()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[Gateway] Read error: %v", err)
				continue
			}
		}

		r.processPacket(pkt)
	}
}

// processPacket parses and routes a single raw IP packet.
func (r *TUNRouter) processPacket(pkt []byte) {
	if len(pkt) < minIPv4Hdr {
		return
	}

	// Verify IPv4 (version nibble).
	if pkt[0]>>4 != 4 {
		return
	}

	ihl := int(pkt[0]&0x0f) * 4
	if ihl < minIPv4Hdr {
		return
	}

	tpOff := ihl

	switch pkt[9] { // IP protocol field (offset 9 in raw IP, not 23 like with Ethernet)
	case protoTCP:
		if len(pkt) < tpOff+minTCPHdr {
			return
		}
		m := pktMeta{
			srcIP: [4]byte(pkt[12:16]),
			dstIP: [4]byte(pkt[16:20]),
			srcP:  binary.BigEndian.Uint16(pkt[tpOff:]),
			dstP:  binary.BigEndian.Uint16(pkt[tpOff+2:]),
			flags: pkt[tpOff+13],
			tpOff: tpOff,
		}
		r.handleTCP(pkt, m)

	case protoUDP:
		if len(pkt) < tpOff+minUDPHdr {
			return
		}
		m := pktMeta{
			srcIP: [4]byte(pkt[12:16]),
			dstIP: [4]byte(pkt[16:20]),
			srcP:  binary.BigEndian.Uint16(pkt[tpOff:]),
			dstP:  binary.BigEndian.Uint16(pkt[tpOff+2:]),
			tpOff: tpOff,
		}
		r.handleUDP(pkt, m)
	}
}

// ---------------------------------------------------------------------------
// TCP handling
// ---------------------------------------------------------------------------

func (r *TUNRouter) handleTCP(pkt []byte, m pktMeta) {
	// Check if this is a proxy response (source port is a registered proxy port).
	if r.flows.IsProxySourcePort(m.srcP) {
		r.handleTCPProxyResponse(pkt, m)
		return
	}

	// SYN (new connection).
	if m.flags&tcpSYN != 0 && m.flags&tcpACK == 0 {
		r.handleTCPSYN(pkt, m)
		return
	}

	// Existing connection.
	r.handleTCPExisting(pkt, m)
}

func (r *TUNRouter) handleTCPSYN(pkt []byte, m pktMeta) {
	tunnelID, proxyPort, action := r.resolveFlow(m.srcP, false)

	switch action {
	case flowDrop:
		return // drop packet (don't write to TUN)
	case flowPass:
		// Route through direct provider.
		tunnelID = DirectTunnelID
		entry, ok := r.registry.Get(DirectTunnelID)
		if !ok {
			return
		}
		proxyPort = entry.ProxyPort
	case flowRoute:
		// tunnelID and proxyPort already set
	}

	dstIP := netip.AddrFrom4(m.dstIP)

	// Create NAT entry.
	r.flows.InsertTCP(dstIP, m.srcP, &NATEntry{
		LastActivity:    r.flows.NowSec(),
		OriginalDstIP:   dstIP,
		OriginalDstPort: m.dstP,
		TunnelID:        tunnelID,
		ProxyPort:       proxyPort,
	})

	// Hairpin: swap IPs, rewrite dst port to proxy port.
	tunSwapIPs(pkt)
	tunSetTCPPort(pkt, m.tpOff+2, proxyPort, m.tpOff+16)

	r.adapter.WritePacket(pkt)
}

func (r *TUNRouter) handleTCPProxyResponse(pkt []byte, m pktMeta) {
	dstIP := netip.AddrFrom4(m.dstIP)
	entry, ok := r.flows.GetTCP(dstIP, m.dstP)
	if !ok {
		return
	}

	// Update activity timestamp.
	atomic.StoreInt64(&entry.LastActivity, r.flows.NowSec())

	// RST: connection aborted, clean up NAT entry.
	if m.flags&tcpRST != 0 {
		r.flows.DeleteTCP(dstIP, m.dstP)
	}

	tcpCkOff := m.tpOff + 16

	// Restore original source port.
	tunSetTCPPort(pkt, m.tpOff, entry.OriginalDstPort, tcpCkOff)
	// Swap IPs.
	tunSwapIPs(pkt)
	// Overwrite srcIP with original destination IP.
	tunOverwriteSrcIP(pkt, entry.OriginalDstIP.As4(), tcpCkOff)

	r.adapter.WritePacket(pkt)
}

func (r *TUNRouter) handleTCPExisting(pkt []byte, m pktMeta) {
	dstIP := netip.AddrFrom4(m.dstIP)
	entry, ok := r.flows.GetTCP(dstIP, m.srcP)
	if !ok {
		// No NAT entry — try to create one (might be a retransmit or late SYN).
		r.handleTCPSYN(pkt, m)
		return
	}

	// Update activity timestamp.
	atomic.StoreInt64(&entry.LastActivity, r.flows.NowSec())

	// RST: clean up.
	if m.flags&tcpRST != 0 {
		r.flows.DeleteTCP(dstIP, m.srcP)
	}

	// Hairpin: swap IPs, rewrite dst port to proxy port.
	tunSwapIPs(pkt)
	tunSetTCPPort(pkt, m.tpOff+2, entry.ProxyPort, m.tpOff+16)

	r.adapter.WritePacket(pkt)
}

// ---------------------------------------------------------------------------
// UDP handling
// ---------------------------------------------------------------------------

func (r *TUNRouter) handleUDP(pkt []byte, m pktMeta) {
	dstIP := netip.AddrFrom4(m.dstIP)

	// Skip multicast and broadcast.
	if dstIP.IsMulticast() || dstIP == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return
	}

	// Check if this is a proxy response.
	if r.flows.IsUDPProxySourcePort(m.srcP) {
		r.handleUDPProxyResponse(pkt, m)
		return
	}

	// Fast path: existing NAT entry.
	entry, exists := r.flows.GetUDP(dstIP, m.srcP)
	if exists {
		atomic.StoreInt64(&entry.LastActivity, r.flows.NowSec())

		tunSwapIPs(pkt)
		tunSetUDPPort(pkt, m.tpOff+2, entry.UDPProxyPort, m.tpOff+6)

		r.adapter.WritePacket(pkt)
		return
	}

	// Slow path: new UDP flow.
	tunnelID, udpProxyPort, action := r.resolveFlow(m.srcP, true)

	// DNS special handling: override tunnel based on DNS router.
	if m.dstP == 53 && r.dnsRouter != nil {
		dnsRoute := r.dnsRouter.ResolveDNSRoute(tunnelID)
		if dnsRoute.TunnelID != "" {
			tunnelID = dnsRoute.TunnelID
			// Get the proxy port for the DNS tunnel.
			if port, ok := r.registry.GetUDPProxyPort(tunnelID); ok {
				udpProxyPort = port
			}
		}
	}

	switch action {
	case flowDrop:
		return
	case flowPass:
		tunnelID = DirectTunnelID
		if port, ok := r.registry.GetUDPProxyPort(DirectTunnelID); ok {
			udpProxyPort = port
		} else {
			return
		}
	case flowRoute:
		// Already set
	}

	if udpProxyPort == 0 {
		return
	}

	// Create NAT entry.
	r.flows.InsertUDP(dstIP, m.srcP, &UDPNATEntry{
		LastActivity:    r.flows.NowSec(),
		OriginalDstIP:   dstIP,
		OriginalDstPort: m.dstP,
		TunnelID:        tunnelID,
		UDPProxyPort:    udpProxyPort,
	})

	// Hairpin.
	tunSwapIPs(pkt)
	tunSetUDPPort(pkt, m.tpOff+2, udpProxyPort, m.tpOff+6)

	r.adapter.WritePacket(pkt)
}

func (r *TUNRouter) handleUDPProxyResponse(pkt []byte, m pktMeta) {
	dstIP := netip.AddrFrom4(m.dstIP)
	entry, ok := r.flows.GetUDP(dstIP, m.dstP)
	if !ok {
		return
	}

	udpCkOff := m.tpOff + 6

	// Restore original source port.
	tunSetUDPPort(pkt, m.tpOff, entry.OriginalDstPort, udpCkOff)
	// Swap IPs.
	tunSwapIPs(pkt)
	// Overwrite srcIP with original destination IP.
	tunOverwriteSrcIP(pkt, entry.OriginalDstIP.As4(), udpCkOff)

	r.adapter.WritePacket(pkt)
}

// ---------------------------------------------------------------------------
// Flow resolution: PID → exe path → rule match → tunnel + proxy port
// ---------------------------------------------------------------------------

type flowAction int

const (
	flowRoute flowAction = iota // route through matched tunnel
	flowPass                    // route through direct provider
	flowDrop                    // drop the packet
)

func (r *TUNRouter) resolveFlow(srcPort uint16, isUDP bool) (tunnelID string, proxyPort uint16, action flowAction) {
	// Look up PID by source port.
	pid, err := r.procID.FindPIDByPort(srcPort, isUDP)
	if err != nil {
		return "", 0, flowPass
	}

	// Get exe path.
	exePath, ok := r.matcher.GetExePath(pid)
	if !ok {
		return "", 0, flowPass
	}

	// Match rules.
	result := r.rules.Match(exePath)
	if !result.Matched {
		return "", 0, flowPass
	}

	// Drop policy always drops.
	if result.Fallback == core.PolicyDrop {
		return "", 0, flowDrop
	}

	// Get tunnel entry.
	entry, ok := r.registry.Get(result.TunnelID)
	if !ok {
		if result.Fallback == core.PolicyBlock {
			return "", 0, flowDrop
		}
		return "", 0, flowPass
	}

	if entry.State != core.TunnelStateUp {
		switch result.Fallback {
		case core.PolicyBlock:
			return "", 0, flowDrop
		case core.PolicyAllowDirect:
			return "", 0, flowPass
		}
		return "", 0, flowPass
	}

	// Lazy WFP rule: block this process on real NIC.
	if r.wfp != nil {
		r.wfp.EnsureBlocked(exePath)
	}

	if isUDP {
		udpPort, ok := r.registry.GetUDPProxyPort(result.TunnelID)
		if !ok {
			return "", 0, flowPass
		}
		return result.TunnelID, udpPort, flowRoute
	}

	return result.TunnelID, entry.ProxyPort, flowRoute
}
