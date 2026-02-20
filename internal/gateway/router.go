//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"awg-split-tunnel/internal/core"
	"awg-split-tunnel/internal/process"
	"awg-split-tunnel/internal/provider"
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
	ipFilter  atomic.Pointer[IPFilter]

	tunIP   [4]byte       // 10.255.0.1 in network byte order
	selfPID uint32        // current process PID (loop prevention)
	drops   atomic.Uint64 // WritePacket drop counter

	// Raw IP forwarding state.
	rawMu    sync.RWMutex
	rawFwders map[string]provider.RawForwarder // tunnelID → forwarder
	vpnIPs    map[string][4]byte               // tunnelID → VPN IP

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
		selfPID:   uint32(os.Getpid()),
		rawFwders: make(map[string]provider.RawForwarder),
		vpnIPs:    make(map[string][4]byte),
		done:      make(chan struct{}),
	}
}

// SetIPFilter atomically sets the IP/app filter. Safe for concurrent use.
func (r *TUNRouter) SetIPFilter(filter *IPFilter) {
	r.ipFilter.Store(filter)
}

// Start begins the packet processing loop.
func (r *TUNRouter) Start(ctx context.Context) error {
	ctx, r.cancel = context.WithCancel(ctx)

	r.flows.StartTimestampUpdater(ctx)
	r.flows.StartTCPCleanup(ctx)
	r.flows.StartUDPCleanup(ctx)
	r.flows.StartRawFlowCleanup(ctx)

	go r.packetLoop(ctx)

	core.Log.Infof("Gateway", "TUN Router started")
	return nil
}

// Stop halts the packet processing loop.
func (r *TUNRouter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	<-r.done
	core.Log.Infof("Gateway", "TUN Router stopped")
}

// writePacket sends a packet via the adapter. On failure (ring full after retry),
// increments the drop counter and logs every 10 000 drops.
func (r *TUNRouter) writePacket(pkt []byte) {
	if err := r.adapter.WritePacket(pkt); err != nil {
		if d := r.drops.Add(1); d == 1 || d%10000 == 0 {
			core.Log.Debugf("Gateway", "Packet drop #%d: %v", d, err)
		}
	}
}

// packetLoop is the main processing goroutine.
// Uses a single pre-allocated buffer to eliminate per-packet heap allocations.
func (r *TUNRouter) packetLoop(ctx context.Context) {
	defer close(r.done)

	buf := make([]byte, maxPacketSize)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := r.adapter.ReadPacket(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				core.Log.Errorf("Gateway", "Read error: %v", err)
				continue
			}
		}

		r.processPacket(buf[:n])
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
	tunnelID, proxyPort, action := r.resolveFlow(m.srcP, false, m.dstIP)

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

	// Raw forwarding path: non-direct tunnels with a raw forwarder.
	if tunnelID != DirectTunnelID {
		if rf, vpnIP, ok := r.getRawForwarder(tunnelID); ok {
			r.flows.InsertRawFlow(protoTCP, m.dstIP, m.srcP, &RawFlowEntry{
				LastActivity: r.flows.NowSec(),
				TunnelID:     tunnelID,
				VpnIP:        vpnIP,
			})
			r.handleRawOutbound(pkt, m, tunnelID, vpnIP, rf, protoTCP)
			return
		}
	}

	// Proxy fallback path (direct tunnel or no raw forwarder).
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

	r.writePacket(pkt)
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

	r.writePacket(pkt)
}

func (r *TUNRouter) handleTCPExisting(pkt []byte, m pktMeta) {
	// Check raw flow table first.
	if rawEntry, ok := r.flows.GetRawFlow(protoTCP, m.dstIP, m.srcP); ok {
		atomic.StoreInt64(&rawEntry.LastActivity, r.flows.NowSec())

		// RST: clean up raw flow.
		if m.flags&tcpRST != 0 {
			r.flows.DeleteRawFlow(protoTCP, m.dstIP, m.srcP)
		}

		if rf, vpnIP, ok := r.getRawForwarder(rawEntry.TunnelID); ok {
			r.handleRawOutbound(pkt, m, rawEntry.TunnelID, vpnIP, rf, protoTCP)
			return
		}
		// Forwarder gone — delete stale raw flow and fall through.
		r.flows.DeleteRawFlow(protoTCP, m.dstIP, m.srcP)
	}

	// Check proxy NAT table.
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

	r.writePacket(pkt)
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

	// Fast path: existing raw flow.
	if rawEntry, ok := r.flows.GetRawFlow(protoUDP, m.dstIP, m.srcP); ok {
		atomic.StoreInt64(&rawEntry.LastActivity, r.flows.NowSec())
		if rf, vpnIP, ok := r.getRawForwarder(rawEntry.TunnelID); ok {
			r.handleRawOutbound(pkt, m, rawEntry.TunnelID, vpnIP, rf, protoUDP)
			return
		}
		// Forwarder gone — delete stale raw flow and fall through.
		r.flows.DeleteRawFlow(protoUDP, m.dstIP, m.srcP)
	}

	// Fast path: existing proxy NAT entry.
	entry, exists := r.flows.GetUDP(dstIP, m.srcP)
	if exists {
		atomic.StoreInt64(&entry.LastActivity, r.flows.NowSec())

		tunSwapIPs(pkt)
		tunSetUDPPort(pkt, m.tpOff+2, entry.UDPProxyPort, m.tpOff+6)

		r.writePacket(pkt)
		return
	}

	// Slow path: new UDP flow.
	tunnelID, udpProxyPort, action := r.resolveFlow(m.srcP, true, m.dstIP)

	// DNS routing: for matched processes, route DNS through the same tunnel.
	// For unmatched processes (flowPass), DNS goes to DirectTunnelID — the local
	// DNS resolver on 10.255.0.1:53 handles VPN routing at the application layer.
	if m.dstP == 53 && r.dnsRouter != nil {
		dnsRoute := r.dnsRouter.ResolveDNSRoute(tunnelID)
		if dnsRoute.TunnelID != "" && dnsRoute.TunnelID != DirectTunnelID {
			tunnelID = dnsRoute.TunnelID
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

	// Raw forwarding for new UDP flows on non-direct tunnels.
	if tunnelID != DirectTunnelID {
		if rf, vpnIP, ok := r.getRawForwarder(tunnelID); ok {
			r.flows.InsertRawFlow(protoUDP, m.dstIP, m.srcP, &RawFlowEntry{
				LastActivity: r.flows.NowSec(),
				TunnelID:     tunnelID,
				VpnIP:        vpnIP,
			})
			r.handleRawOutbound(pkt, m, tunnelID, vpnIP, rf, protoUDP)
			return
		}
	}

	// Proxy fallback path.
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

	r.writePacket(pkt)
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

	r.writePacket(pkt)
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

func (r *TUNRouter) resolveFlow(srcPort uint16, isUDP bool, dstIP [4]byte) (tunnelID string, proxyPort uint16, action flowAction) {
	f := r.ipFilter.Load() // may be nil

	// Early drop: if a local/private IP reached TUN, there is no direct route
	// through any local interface (Docker/WSL/Hyper-V vNIC is down or absent).
	// The __direct__ proxy (bound to the physical NIC via IP_UNICAST_IF) cannot
	// deliver these packets either — drop them to avoid futile proxy timeouts.
	if f != nil && f.IsLocalBypassIP(dstIP) {
		return "", 0, flowDrop
	}

	// Look up PID by source port.
	pid, err := r.procID.FindPIDByPort(srcPort, isUDP)
	if err != nil {
		return "", 0, flowPass
	}

	// Self-process loop prevention: our own outbound traffic (e.g. direct proxy)
	// must not re-enter the proxy path, or it creates an infinite loop.
	if pid == r.selfPID {
		return "", 0, flowDrop
	}

	// Get exe path.
	exePath, ok := r.matcher.GetExePath(pid)
	if !ok {
		return "", 0, flowPass
	}

	// Pre-lowercase once for DisallowedApps + rule matching.
	exeLower := strings.ToLower(exePath)
	baseLower := filepath.Base(exeLower)

	// Check global DisallowedApps — always bypass VPN.
	if f != nil && f.IsDisallowedApp(exeLower, baseLower) {
		return "", 0, flowPass
	}

	// Match rules using pre-lowered strings.
	result := r.rules.MatchPreLowered(exeLower, baseLower)
	if !result.Matched {
		return "", 0, flowPass
	}

	// Drop policy always drops.
	if result.Fallback == core.PolicyDrop {
		return "", 0, flowDrop
	}

	// Check per-tunnel DisallowedApps.
	if f != nil && f.IsTunnelDisallowedApp(result.TunnelID, exeLower, baseLower) {
		return "", 0, flowPass
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

	// Check IP-based filtering (DisallowedIPs / AllowedIPs).
	if f != nil && f.ShouldBypassIP(result.TunnelID, dstIP) {
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

// ---------------------------------------------------------------------------
// Raw IP forwarding — bypass TCP proxy + gVisor for VPN tunnels
// ---------------------------------------------------------------------------

// RegisterRawForwarder registers a raw forwarder for a VPN tunnel.
// Must be called after the provider is connected and has a valid VPN IP.
func (r *TUNRouter) RegisterRawForwarder(tunnelID string, rf provider.RawForwarder, vpnIP [4]byte) {
	r.rawMu.Lock()
	r.rawFwders[tunnelID] = rf
	r.vpnIPs[tunnelID] = vpnIP
	r.rawMu.Unlock()

	r.flows.RegisterVpnIP(vpnIP, tunnelID)

	// Install inbound handler on the provider so decrypted packets from the
	// WireGuard tunnel hit handleInboundRaw instead of gVisor.
	rf.SetInboundHandler(r.handleInboundRaw)

	core.Log.Infof("Gateway", "Raw forwarder registered for tunnel %q (vpnIP=%d.%d.%d.%d)",
		tunnelID, vpnIP[0], vpnIP[1], vpnIP[2], vpnIP[3])
}

// getRawForwarder returns the raw forwarder and VPN IP for a tunnel (lock-free fast path).
func (r *TUNRouter) getRawForwarder(tunnelID string) (provider.RawForwarder, [4]byte, bool) {
	r.rawMu.RLock()
	rf, ok := r.rawFwders[tunnelID]
	vpnIP := r.vpnIPs[tunnelID]
	r.rawMu.RUnlock()
	return rf, vpnIP, ok
}

// handleRawOutbound rewrites the source IP and injects the packet into the tunnel.
// Returns true if the packet was handled via raw forwarding.
func (r *TUNRouter) handleRawOutbound(pkt []byte, m pktMeta, tunnelID string, vpnIP [4]byte, rf provider.RawForwarder, proto byte) bool {
	// Determine transport checksum offset.
	var transportCkOff int
	switch proto {
	case protoTCP:
		transportCkOff = m.tpOff + 16
	case protoUDP:
		transportCkOff = m.tpOff + 6
	}

	// Clamp TCP MSS on SYN packets to prevent oversized segments in tunnel.
	if proto == protoTCP {
		clampTCPMSS(pkt, m.tpOff)
	}

	// Rewrite src IP from TUN IP (10.255.0.1) to tunnel's VPN IP.
	tunOverwriteSrcIP(pkt, vpnIP, transportCkOff)

	if !rf.InjectOutbound(pkt) {
		return false
	}
	return true
}

// handleInboundRaw is called from WireGuard's receive goroutine for every
// decrypted IPv4 packet. It performs reverse NAT (VPN IP → TUN IP) and writes
// the packet to the TUN adapter. Returns true if consumed.
//
// IMPORTANT: Only consume packets that have a matching raw flow entry.
// Packets without a raw flow entry (e.g. gVisor proxy connections, DNS resolver
// connections) must fall through to gVisor by returning false.
func (r *TUNRouter) handleInboundRaw(pkt []byte) bool {
	if len(pkt) < minIPv4Hdr {
		return false
	}

	// Only handle IPv4.
	if pkt[0]>>4 != 4 {
		return false
	}

	// Extract destination IP (bytes 16-19) — this is the VPN IP.
	var dstIP [4]byte
	copy(dstIP[:], pkt[16:20])

	// Check if this destination IP is one of our VPN IPs.
	if _, ok := r.flows.LookupVpnIP(dstIP); !ok {
		return false // not for us at all
	}

	ihl := int(pkt[0]&0x0f) * 4
	if ihl < minIPv4Hdr {
		return false
	}

	proto := pkt[9]

	// Determine transport checksum offset and extract ports for flow lookup.
	var transportCkOff int
	var srcIP [4]byte
	var dstPort uint16

	switch proto {
	case protoTCP:
		if len(pkt) < ihl+minTCPHdr {
			return false
		}
		transportCkOff = ihl + 16
		copy(srcIP[:], pkt[12:16])
		dstPort = binary.BigEndian.Uint16(pkt[ihl+2:])
	case protoUDP:
		if len(pkt) < ihl+minUDPHdr {
			return false
		}
		transportCkOff = ihl + 6
		copy(srcIP[:], pkt[12:16])
		dstPort = binary.BigEndian.Uint16(pkt[ihl+2:])
	default:
		return false // ICMP etc — let gVisor handle
	}

	// Check if this response matches a raw flow entry.
	// For inbound: srcIP = original destination, dstPort = original source port.
	if _, ok := r.flows.GetRawFlow(proto, srcIP, dstPort); !ok {
		return false // no raw flow — let gVisor handle (proxy/DNS resolver traffic)
	}

	// Clamp TCP MSS on inbound SYN-ACK to prevent client sending oversized segments.
	if proto == protoTCP {
		clampTCPMSS(pkt, ihl)
	}

	// Rewrite dst IP from VPN IP to TUN IP (10.255.0.1).
	tunOverwriteDstIP(pkt, r.tunIP, transportCkOff)

	// Write to TUN adapter — this copies into WinTUN ring buffer.
	r.writePacket(pkt)
	return true
}
