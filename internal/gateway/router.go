//go:build windows

package gateway

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

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

	// Perf: inbound raw stats (reset every 10s by packetLoop).
	maxInboundRawNs atomic.Int64
	inboundCount    atomic.Int64 // total inbound raw packets
	inboundSlow     atomic.Int64 // inbound raw packets > 500µs

	// Raw IP forwarding state.
	rawMu    sync.RWMutex
	rawFwders map[string]provider.RawForwarder // tunnelID → forwarder
	vpnIPs    map[string][4]byte               // tunnelID → VPN IP

	// External byte reporting callback (for StatsCollector).
	bytesReporter func(tunnelID string, tx, rx int64)

	// Domain-based routing: resolved IP→tunnel.
	domainTable *DomainTable

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

// SetBytesReporter sets a callback invoked on every packet to report
// per-tunnel TX/RX byte counts. Must be called before Start.
func (r *TUNRouter) SetBytesReporter(fn func(tunnelID string, tx, rx int64)) {
	r.bytesReporter = fn
}

// SetDomainTable sets the domain table for IP→tunnel routing based on DNS matches.
func (r *TUNRouter) SetDomainTable(dt *DomainTable) {
	r.domainTable = dt
}

// Start begins the packet processing loop.
func (r *TUNRouter) Start(ctx context.Context) error {
	ctx, r.cancel = context.WithCancel(ctx)

	r.flows.StartTimestampUpdater(ctx)
	r.flows.StartTCPCleanup(ctx)
	r.flows.StartUDPCleanup(ctx)
	r.flows.StartRawFlowCleanup(ctx)

	go r.packetLoop(ctx)
	go r.gcPauseMonitor(ctx)

	core.Log.Infof("Gateway", "TUN Router started")
	return nil
}

// Stop halts the packet processing loop.
func (r *TUNRouter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	<-r.done
	r.flows.Wait()
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

// gcPauseMonitor periodically reports GC pause statistics.
func (r *TUNRouter) gcPauseMonitor(ctx context.Context) {
	var prevNumGC uint32
	var stats runtime.MemStats
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runtime.ReadMemStats(&stats)
			if stats.NumGC == prevNumGC {
				continue
			}
			// Report new GC cycles since last check.
			cycles := stats.NumGC - prevNumGC
			if cycles > 256 {
				cycles = 256 // PauseNs is a circular buffer of 256
			}
			var maxPause time.Duration
			for i := prevNumGC; i < stats.NumGC; i++ {
				p := time.Duration(stats.PauseNs[i%256])
				if p > maxPause {
					maxPause = p
				}
			}
			prevNumGC = stats.NumGC
			if maxPause > 500*time.Microsecond {
				core.Log.Warnf("Perf", "GC: %d cycles, maxPause=%s, heapAlloc=%dMB",
					cycles, maxPause, stats.HeapAlloc/1024/1024)
			}
		}
	}
}

// packetLoop is the main processing goroutine.
// Uses a single pre-allocated buffer to eliminate per-packet heap allocations.
func (r *TUNRouter) packetLoop(ctx context.Context) {
	defer close(r.done)

	buf := make([]byte, maxPacketSize)

	// Perf: track stall stats per 10-second window.
	var maxProcStall time.Duration
	var totalPkts, slowProcPkts int64
	stallTicker := time.NewTicker(10 * time.Second)
	defer stallTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stallTicker.C:
			maxInbound := time.Duration(r.maxInboundRawNs.Swap(0))
			inCount := r.inboundCount.Swap(0)
			inSlow := r.inboundSlow.Swap(0)
			// Only log at Warn level when there are anomalies (slow packets).
			if slowProcPkts > 0 || inSlow > 0 {
				core.Log.Warnf("Perf", "10s: outPkts=%d slowOut=%d maxProc=%s | inPkts=%d slowIn=%d maxIn=%s",
					totalPkts, slowProcPkts, maxProcStall,
					inCount, inSlow, maxInbound)
			} else {
				core.Log.Debugf("Perf", "10s: outPkts=%d | inPkts=%d maxIn=%s",
					totalPkts, inCount, maxInbound)
			}
			maxProcStall = 0
			totalPkts = 0
			slowProcPkts = 0
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

		totalPkts++
		procStart := time.Now()
		r.processPacket(buf[:n])
		procElapsed := time.Since(procStart)
		if procElapsed > maxProcStall {
			maxProcStall = procElapsed
		}
		if procElapsed > 500*time.Microsecond {
			slowProcPkts++
		}
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

	case protoICMP:
		if len(pkt) < tpOff+minICMPHdr {
			return
		}
		m := pktMeta{
			srcIP: [4]byte(pkt[12:16]),
			dstIP: [4]byte(pkt[16:20]),
			tpOff: tpOff,
		}
		r.handleICMP(pkt, m)
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
	tunnelID, proxyPort, action, rulePrio := r.resolveFlow(m.srcP, false, m.dstIP)

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
			basePrio, isAuto := mapRulePriority(rulePrio)
			prio := resolvePriority(basePrio, isAuto, pkt, protoTCP, m.tpOff, m.srcP, m.dstP)
			r.flows.InsertRawFlow(protoTCP, m.dstIP, m.srcP, &RawFlowEntry{
				LastActivity: r.flows.NowSec(),
				TunnelID:     tunnelID,
				VpnIP:        vpnIP,
				Priority:     prio,
				IsAuto:       isAuto,
			})
			r.handleRawOutbound(pkt, m, tunnelID, vpnIP, rf, protoTCP, prio)
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

	if r.bytesReporter != nil {
		r.bytesReporter(tunnelID, int64(len(pkt)), 0)
	}
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

	// Track server-side FIN for faster cleanup.
	if m.flags&tcpFIN != 0 {
		fin := atomic.OrInt32(&entry.FinSeen, 0x2)
		// Both FINs seen — schedule entry for short-lived cleanup (2s grace).
		if fin|0x2 == 0x3 {
			atomic.StoreInt64(&entry.LastActivity, r.flows.NowSec()-298)
		}
	}

	tcpCkOff := m.tpOff + 16

	// Restore original source port.
	tunSetTCPPort(pkt, m.tpOff, entry.OriginalDstPort, tcpCkOff)
	// Swap IPs.
	tunSwapIPs(pkt)
	// Overwrite srcIP with original destination IP.
	tunOverwriteSrcIP(pkt, entry.OriginalDstIP.As4(), tcpCkOff)

	if r.bytesReporter != nil {
		r.bytesReporter(entry.TunnelID, 0, int64(len(pkt)))
	}
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
			// Per-packet TCP control boost (SYN/FIN/RST bypass bulk queue).
			prio := boostTCPControl(pkt, m.tpOff, rawEntry.Priority)
			r.handleRawOutbound(pkt, m, rawEntry.TunnelID, vpnIP, rf, protoTCP, prio)
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

	// Track client-side FIN for faster cleanup.
	if m.flags&tcpFIN != 0 {
		fin := atomic.OrInt32(&entry.FinSeen, 0x1)
		// Both FINs seen — schedule entry for short-lived cleanup (2s grace).
		if fin|0x1 == 0x3 {
			atomic.StoreInt64(&entry.LastActivity, r.flows.NowSec()-298)
		}
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
			r.handleRawOutbound(pkt, m, rawEntry.TunnelID, vpnIP, rf, protoUDP, rawEntry.Priority)
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
	tunnelID, udpProxyPort, action, rulePrio := r.resolveFlow(m.srcP, true, m.dstIP)

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
			basePrio, isAuto := mapRulePriority(rulePrio)
			prio := resolvePriority(basePrio, isAuto, pkt, protoUDP, m.tpOff, m.srcP, m.dstP)
			r.flows.InsertRawFlow(protoUDP, m.dstIP, m.srcP, &RawFlowEntry{
				LastActivity: r.flows.NowSec(),
				TunnelID:     tunnelID,
				VpnIP:        vpnIP,
				Priority:     prio,
				IsAuto:       isAuto,
			})
			r.handleRawOutbound(pkt, m, tunnelID, vpnIP, rf, protoUDP, prio)
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

	if r.bytesReporter != nil {
		r.bytesReporter(entry.TunnelID, 0, int64(len(pkt)))
	}
	r.writePacket(pkt)
}

// ---------------------------------------------------------------------------
// ICMP handling
// ---------------------------------------------------------------------------

func (r *TUNRouter) handleICMP(pkt []byte, m pktMeta) {
	// Only handle Echo Request (type 8). Other ICMP types are ignored.
	if pkt[m.tpOff] != icmpEchoRequest {
		return
	}

	// Extract ICMP Identifier (bytes 4-5 of ICMP header) as pseudo-port for flow tracking.
	icmpID := binary.BigEndian.Uint16(pkt[m.tpOff+4:])

	// Fast path: existing raw flow.
	if rawEntry, ok := r.flows.GetRawFlow(protoICMP, m.dstIP, icmpID); ok {
		atomic.StoreInt64(&rawEntry.LastActivity, r.flows.NowSec())
		if rf, vpnIP, ok := r.getRawForwarder(rawEntry.TunnelID); ok {
			r.handleRawOutbound(pkt, m, rawEntry.TunnelID, vpnIP, rf, protoICMP, rawEntry.Priority)
			return
		}
		// Forwarder gone — delete stale flow and fall through.
		r.flows.DeleteRawFlow(protoICMP, m.dstIP, icmpID)
	}

	// Slow path: resolve tunnel for new ICMP flow.
	tunnelID, action := r.resolveICMPFlow(m.dstIP)

	switch action {
	case flowDrop:
		return
	case flowPass:
		return // let OS handle via real NIC
	case flowRoute:
		// continue
	}

	rf, vpnIP, ok := r.getRawForwarder(tunnelID)
	if !ok {
		return
	}

	r.flows.InsertRawFlow(protoICMP, m.dstIP, icmpID, &RawFlowEntry{
		LastActivity: r.flows.NowSec(),
		TunnelID:     tunnelID,
		VpnIP:        vpnIP,
		Priority:     PrioNormal,
	})
	r.handleRawOutbound(pkt, m, tunnelID, vpnIP, rf, protoICMP, PrioNormal)
}

// resolveICMPFlow determines which tunnel should handle an ICMP packet.
// Windows has no GetExtendedIcmpTable, so per-process routing is not possible.
// Instead we use: domain table → DNS fallback tunnel → first available VPN tunnel → pass.
func (r *TUNRouter) resolveICMPFlow(dstIP [4]byte) (tunnelID string, action flowAction) {
	f := r.ipFilter.Load()

	// Drop local/private IPs — no direct route through TUN.
	if f != nil && f.IsLocalBypassIP(dstIP) {
		return "", flowDrop
	}

	// Domain-based routing (IP→tunnel from DNS resolution).
	if r.domainTable != nil {
		if dEntry, ok := r.domainTable.Lookup(dstIP); ok {
			switch dEntry.Action {
			case core.DomainBlock:
				return "", flowDrop
			case core.DomainDirect:
				return "", flowPass
			case core.DomainRoute:
				if entry, ok := r.registry.Get(dEntry.TunnelID); ok && entry.State == core.TunnelStateUp {
					if _, _, ok := r.getRawForwarder(dEntry.TunnelID); ok {
						return dEntry.TunnelID, flowRoute
					}
				}
			}
		}
	}

	// DNS fallback tunnel — the primary VPN tunnel from config.
	if r.dnsRouter != nil {
		dnsRoute := r.dnsRouter.ResolveDNSRoute("")
		if dnsRoute.TunnelID != "" && dnsRoute.TunnelID != DirectTunnelID {
			if entry, ok := r.registry.Get(dnsRoute.TunnelID); ok && entry.State == core.TunnelStateUp {
				if _, _, ok := r.getRawForwarder(dnsRoute.TunnelID); ok {
					if f == nil || !f.ShouldBypassIP(dnsRoute.TunnelID, dstIP) {
						return dnsRoute.TunnelID, flowRoute
					}
				}
			}
		}
	}

	// Any available VPN tunnel with a raw forwarder.
	for _, entry := range r.registry.All() {
		if entry.ID == DirectTunnelID || entry.State != core.TunnelStateUp {
			continue
		}
		if f != nil && f.ShouldBypassIP(entry.ID, dstIP) {
			continue
		}
		if _, _, ok := r.getRawForwarder(entry.ID); ok {
			return entry.ID, flowRoute
		}
	}

	// No VPN tunnel available — let OS handle directly.
	return "", flowPass
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

func (r *TUNRouter) resolveFlow(srcPort uint16, isUDP bool, dstIP [4]byte) (tunnelID string, proxyPort uint16, action flowAction, rulePrio core.RulePriority) {
	f := r.ipFilter.Load() // may be nil

	// Early drop: if a local/private IP reached TUN, there is no direct route
	// through any local interface (Docker/WSL/Hyper-V vNIC is down or absent).
	// The __direct__ proxy (bound to the physical NIC via IP_UNICAST_IF) cannot
	// deliver these packets either — drop them to avoid futile proxy timeouts.
	if f != nil && f.IsLocalBypassIP(dstIP) {
		return "", 0, flowDrop, 0
	}

	// Domain-based routing: IP→tunnel from DNS resolution.
	// Domain rules have HIGHER priority than process rules.
	if r.domainTable != nil {
		if dEntry, ok := r.domainTable.Lookup(dstIP); ok {
			switch dEntry.Action {
			case core.DomainBlock:
				return "", 0, flowDrop, 0
			case core.DomainDirect:
				return "", 0, flowPass, 0
			case core.DomainRoute:
				if entry, ok := r.registry.Get(dEntry.TunnelID); ok && entry.State == core.TunnelStateUp {
					if isUDP {
						if port, ok := r.registry.GetUDPProxyPort(dEntry.TunnelID); ok {
							return dEntry.TunnelID, port, flowRoute, core.PriorityAuto
						}
					}
					return dEntry.TunnelID, entry.ProxyPort, flowRoute, core.PriorityAuto
				}
				// Tunnel down — fall through to process rules.
			}
		}
	}

	// Look up PID by source port.
	pid, err := r.procID.FindPIDByPort(srcPort, isUDP)
	if err != nil {
		return "", 0, flowPass, 0
	}

	// Self-process loop prevention: our own outbound traffic (e.g. direct proxy)
	// must not re-enter the proxy path, or it creates an infinite loop.
	if pid == r.selfPID {
		return "", 0, flowDrop, 0
	}

	// Get exe path with pre-cached lowercase variants (zero alloc on cache hit).
	exePath, exeLower, baseLower, ok := r.matcher.GetExePathLower(pid)
	if !ok {
		return "", 0, flowPass, 0
	}

	// Check global DisallowedApps — always bypass VPN.
	if f != nil && f.IsDisallowedApp(exeLower, baseLower) {
		return "", 0, flowPass, 0
	}

	// Match rules using pre-lowered strings with failover support.
	// First attempt uses the fast MatchPreLowered; failover (cold path)
	// switches to MatchPreLoweredFrom to resume from the next rule index.
	result := r.rules.MatchPreLowered(exeLower, baseLower)
	if !result.Matched {
		return "", 0, flowPass, 0
	}

	inFailover := false
	matchIdx := 0 // only used after first failover

	// Safety bound: at most len(rules) iterations to prevent infinite loops.
	maxIter := len(r.rules.GetRules())

	for iter := 0; iter < maxIter; iter++ {
		// On failover iterations, search from the next index.
		if inFailover {
			var idx int
			result, idx = r.rules.MatchPreLoweredFrom(exeLower, baseLower, matchIdx)
			if !result.Matched {
				// Failover exhausted — VPN-or-nothing: drop.
				return "", 0, flowDrop, 0
			}
			matchIdx = idx + 1
		}

		// Drop policy always drops immediately.
		if result.Fallback == core.PolicyDrop {
			return "", 0, flowDrop, 0
		}

		// Check per-tunnel DisallowedApps.
		if f != nil && f.IsTunnelDisallowedApp(result.TunnelID, exeLower, baseLower) {
			return "", 0, flowPass, 0
		}

		// Check tunnel availability.
		entry, ok := r.registry.Get(result.TunnelID)
		tunnelDown := !ok || entry.State != core.TunnelStateUp

		if tunnelDown {
			switch result.Fallback {
			case core.PolicyFailover:
				// Set up index for next iteration: if this is the first
				// failover, we need the index of the current match.
				if !inFailover {
					// Find the current match index so we can resume after it.
					_, idx := r.rules.MatchPreLoweredFrom(exeLower, baseLower, 0)
					matchIdx = idx + 1
					inFailover = true
				}
				continue
			case core.PolicyBlock:
				return "", 0, flowDrop, 0
			case core.PolicyAllowDirect:
				return "", 0, flowPass, 0
			default:
				return "", 0, flowPass, 0
			}
		}

		// Tunnel is up — check IP-based filtering (DisallowedIPs / AllowedIPs).
		if f != nil && f.ShouldBypassIP(result.TunnelID, dstIP) {
			return "", 0, flowPass, 0
		}

		// Lazy WFP rule: block this process on real NIC.
		if r.wfp != nil {
			wfpStart := time.Now()
			r.wfp.EnsureBlocked(exePath)
			if wfpElapsed := time.Since(wfpStart); wfpElapsed > time.Millisecond {
				core.Log.Warnf("Perf", "EnsureBlocked took %s (%s)", wfpElapsed, exePath)
			}
		}

		if isUDP {
			udpPort, ok := r.registry.GetUDPProxyPort(result.TunnelID)
			if !ok {
				return "", 0, flowPass, 0
			}
			return result.TunnelID, udpPort, flowRoute, result.Priority
		}

		return result.TunnelID, entry.ProxyPort, flowRoute, result.Priority
	}

	// Safety: loop bound reached — drop to be safe.
	return "", 0, flowDrop, 0
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

// handleRawOutbound rewrites the source IP, applies DSCP marking for high-priority
// traffic, and injects the packet into the tunnel at the given priority level.
// Returns true if the packet was handled via raw forwarding.
func (r *TUNRouter) handleRawOutbound(pkt []byte, m pktMeta, tunnelID string, vpnIP [4]byte, rf provider.RawForwarder, proto byte, prio byte) bool {
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

	// DSCP marking for high-priority packets (voice/video/control).
	if prio == PrioHigh {
		markDSCP(pkt, proto, m.tpOff)
	}

	if !rf.InjectOutboundPriority(pkt, prio) {
		return false
	}
	if r.bytesReporter != nil {
		r.bytesReporter(tunnelID, int64(len(pkt)), 0)
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
	case protoICMP:
		if len(pkt) < ihl+minICMPHdr {
			return false
		}
		// Only handle Echo Reply (type 0).
		if pkt[ihl] != icmpEchoReply {
			return false
		}
		// ICMP has no pseudo-header checksum — transportCkOff stays 0.
		copy(srcIP[:], pkt[12:16])
		// Use ICMP Identifier as pseudo-port for flow lookup.
		dstPort = binary.BigEndian.Uint16(pkt[ihl+4:])
	default:
		return false
	}

	// Check if this response matches a raw flow entry.
	// For inbound: srcIP = original destination, dstPort = original source port.
	inboundStart := time.Now()
	rawEntry, ok := r.flows.GetRawFlow(proto, srcIP, dstPort)
	if !ok {
		return false // no raw flow — let gVisor handle (proxy/DNS resolver traffic)
	}

	// Update activity timestamp so inbound-heavy flows (e.g. video streaming)
	// are not evicted by the cleanup goroutine.
	atomic.StoreInt64(&rawEntry.LastActivity, r.flows.NowSec())

	// Clamp TCP MSS on inbound SYN-ACK to prevent client sending oversized segments.
	if proto == protoTCP {
		clampTCPMSS(pkt, ihl)
	}

	// Rewrite dst IP from VPN IP to TUN IP (10.255.0.1).
	tunOverwriteDstIP(pkt, r.tunIP, transportCkOff)

	// Write to TUN adapter — this copies into WinTUN ring buffer.
	r.writePacket(pkt)
	if r.bytesReporter != nil {
		r.bytesReporter(rawEntry.TunnelID, 0, int64(len(pkt)))
	}

	// Perf: track inbound stats.
	r.inboundCount.Add(1)
	elapsedNs := time.Since(inboundStart).Nanoseconds()
	if elapsedNs > 500_000 { // >500µs
		r.inboundSlow.Add(1)
	}
	for {
		old := r.maxInboundRawNs.Load()
		if elapsedNs <= old {
			break
		}
		if r.maxInboundRawNs.CompareAndSwap(old, elapsedNs) {
			break
		}
	}
	return true
}
