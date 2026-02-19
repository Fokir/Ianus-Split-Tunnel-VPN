//go:build windows

package core

import (
	"context"
	"log"
	"net/netip"
	"sync"
	"time"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// NATEntry maps a redirected TCP connection back to its original destination.
type NATEntry struct {
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
}

// UDPNATEntry maps a redirected UDP flow back to its original destination.
// Includes LastActivity for timeout-based cleanup (UDP has no FIN/RST).
type UDPNATEntry struct {
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	LastActivity    time.Time
}

// PacketRouter intercepts network packets via NDISAPI, performs process-based
// routing decisions, and manages the NAT table for hairpin redirects.
type PacketRouter struct {
	api     *A.NdisApi
	filter  *D.SimplePacketFilter
	process *N.ProcessLookup

	registry *TunnelRegistry
	rules    *RuleEngine
	bus      *EventBus

	// TCP NAT table: key = "dstIP:srcPort" (invariant across hairpin redirect).
	natMu sync.RWMutex
	nat   map[string]NATEntry

	// TCP proxy port set for O(1) lookup on hot path.
	proxyPortsMu sync.RWMutex
	proxyPorts   map[uint16]struct{}

	// UDP NAT table: key = "dstIP:srcPort" (invariant across hairpin redirect).
	udpNatMu sync.RWMutex
	udpNat   map[string]UDPNATEntry

	// UDP proxy port set for O(1) lookup on hot path.
	udpProxyPortsMu sync.RWMutex
	udpProxyPorts   map[uint16]struct{}

	// Pre-allocated gopacket layers for zero-alloc parsing.
	// These are ONLY used inside the filter callback — single-threaded.
	eth     layers.Ethernet
	ip4     layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	// Pre-allocated serialize buffer for zero-alloc packet serialization.
	// ONLY used inside the filter callback — single-threaded.
	serBuf gopacket.SerializeBuffer

	adapterIndex int
}

// NewPacketRouter creates a packet router with the given dependencies.
func NewPacketRouter(
	registry *TunnelRegistry,
	rules *RuleEngine,
	bus *EventBus,
	adapterIndex int,
) (*PacketRouter, error) {
	api, err := A.NewNdisApi()
	if err != nil {
		return nil, err
	}

	pr := &PacketRouter{
		api:           api,
		process:       N.NewProcessLookup(),
		registry:      registry,
		rules:         rules,
		bus:           bus,
		nat:           make(map[string]NATEntry),
		proxyPorts:    make(map[uint16]struct{}),
		udpNat:        make(map[string]UDPNATEntry),
		udpProxyPorts: make(map[uint16]struct{}),
		decoded:       make([]gopacket.LayerType, 0, 4),
		serBuf:        gopacket.NewSerializeBuffer(),
		adapterIndex:  adapterIndex,
	}

	// Initialize zero-alloc parser.
	pr.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&pr.eth, &pr.ip4, &pr.tcp, &pr.udp, &pr.payload,
	)
	pr.parser.IgnoreUnsupported = true

	return pr, nil
}

// Start begins packet filtering on the configured adapter.
func (pr *PacketRouter) Start(ctx context.Context) error {
	adapters, err := pr.api.GetTcpipBoundAdaptersInfo()
	if err != nil {
		return err
	}

	// Log available adapters for debugging adapter_index.
	log.Printf("[Router] Found %d adapters:", adapters.AdapterCount)
	for i := 0; i < int(adapters.AdapterCount); i++ {
		name := string(adapters.AdapterNameList[i][:])
		friendly := pr.api.ConvertWindows2000AdapterName(name)
		log.Printf("[Router]   [%d] %s", i, friendly)
	}

	go pr.process.StartCleanup(ctx, time.Minute)

	pr.filter, err = D.NewSimplePacketFilter(
		ctx,
		pr.api,
		adapters,
		nil, // no incoming callback
		pr.outgoingCallback,
	)
	if err != nil {
		return err
	}

	if err := pr.filter.StartFilter(pr.adapterIndex); err != nil {
		return err
	}

	go pr.udpNATCleanup(ctx)

	log.Printf("[Router] Packet filter started on adapter %d", pr.adapterIndex)
	return nil
}

// Stop stops the packet filter and cleans up.
func (pr *PacketRouter) Stop() {
	if pr.filter != nil {
		pr.filter.Close()
	}
	if pr.api != nil {
		pr.api.Close()
	}
	log.Printf("[Router] Packet filter stopped")
}

// outgoingCallback is the NDISAPI filter callback for outgoing packets.
// CRITICAL: No allocations, no blocking, no network calls allowed here.
func (pr *PacketRouter) outgoingCallback(handle A.Handle, b *A.IntermediateBuffer) A.FilterAction {
	// Parse packet using zero-alloc DecodingLayerParser.
	if err := pr.parser.DecodeLayers(b.Buffer[:b.Length], &pr.decoded); err != nil {
		return A.FilterActionPass
	}

	var hasIPv4, hasTCP, hasUDP bool
	for _, lt := range pr.decoded {
		switch lt {
		case layers.LayerTypeIPv4:
			hasIPv4 = true
		case layers.LayerTypeTCP:
			hasTCP = true
		case layers.LayerTypeUDP:
			hasUDP = true
		}
	}
	if !hasIPv4 {
		return A.FilterActionPass
	}

	if hasTCP {
		return pr.handleTCPPacket(b, handle)
	}
	if hasUDP {
		return pr.handleUDPOutgoing(b, handle)
	}
	return A.FilterActionPass
}

// handleTCPPacket dispatches an outgoing TCP packet through the NAT/hairpin pipeline.
func (pr *PacketRouter) handleTCPPacket(b *A.IntermediateBuffer, handle A.Handle) A.FilterAction {
	srcIP, _ := netip.AddrFromSlice(pr.ip4.SrcIP)
	dstIP, _ := netip.AddrFromSlice(pr.ip4.DstIP)
	srcPort := uint16(pr.tcp.SrcPort)
	dstPort := uint16(pr.tcp.DstPort)

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)

	// Handle packets FROM proxy back to client.
	if pr.isProxySourcePort(srcPort) {
		return pr.handleProxyResponse(b, dst)
	}

	// Handle TCP SYN: new connection, perform process lookup.
	if pr.tcp.SYN && !pr.tcp.ACK {
		return pr.handleSYN(b, handle, src, dst)
	}

	// Handle existing NAT'd connections.
	return pr.handleExistingConnection(b, src, dst)
}

// handleSYN processes a new TCP connection (SYN packet).
func (pr *PacketRouter) handleSYN(
	b *A.IntermediateBuffer,
	handle A.Handle,
	src, dst netip.AddrPort,
) A.FilterAction {
	// Lookup process by connection.
	info, err := pr.process.FindProcessInfo(context.Background(), false, src, dst, false)
	if err != nil {
		return A.FilterActionPass
	}

	// Match against rules.
	result := pr.rules.Match(info.PathName)
	if !result.Matched {
		return A.FilterActionPass
	}

	// Drop policy — always block.
	if result.Fallback == PolicyDrop {
		return A.FilterActionDrop
	}

	// Get tunnel state.
	entry, ok := pr.registry.Get(result.TunnelID)
	if !ok {
		// Tunnel not registered.
		if result.Fallback == PolicyBlock {
			return A.FilterActionDrop
		}
		return A.FilterActionPass
	}

	if entry.State != TunnelStateUp {
		// Tunnel is down, apply fallback.
		switch result.Fallback {
		case PolicyBlock:
			return A.FilterActionDrop
		case PolicyAllowDirect:
			return A.FilterActionPass
		}
		return A.FilterActionPass
	}

	// Tunnel is UP — redirect through proxy via NAT hairpin.
	// Key = dstIP:srcPort — invariant across hairpin (proxy sees same key via RemoteAddr).
	natKey := netip.AddrPortFrom(dst.Addr(), src.Port()).String()
	pr.natMu.Lock()
	pr.nat[natKey] = NATEntry{
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
	}
	pr.natMu.Unlock()

	// Hairpin redirect: swap MACs and IPs, redirect to proxy port.
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
	pr.tcp.DstPort = layers.TCPPort(entry.ProxyPort)

	pr.serializePacket(b)
	return A.FilterActionRedirect
}

// handleProxyResponse handles packets from a tunnel proxy back to the client.
func (pr *PacketRouter) handleProxyResponse(b *A.IntermediateBuffer, dst netip.AddrPort) A.FilterAction {
	natKey := dst.String()

	pr.natMu.RLock()
	entry, ok := pr.nat[natKey]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Clean up NAT entry on FIN/RST.
	if pr.tcp.FIN || pr.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, natKey)
		pr.natMu.Unlock()
	}

	// Restore original source: the destination the client intended to reach.
	pr.tcp.SrcPort = layers.TCPPort(entry.OriginalDstPort)
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()

	// Overwrite source IP to the original destination IP.
	pr.ip4.SrcIP = entry.OriginalDstIP.AsSlice()

	pr.serializePacket(b)
	return A.FilterActionRedirect
}

// handleExistingConnection handles data packets for already-NAT'd connections.
func (pr *PacketRouter) handleExistingConnection(
	b *A.IntermediateBuffer,
	src, dst netip.AddrPort,
) A.FilterAction {
	natKey := netip.AddrPortFrom(dst.Addr(), src.Port()).String()

	pr.natMu.RLock()
	entry, ok := pr.nat[natKey]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Clean up NAT entry on FIN/RST.
	if pr.tcp.FIN || pr.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, natKey)
		pr.natMu.Unlock()
	}

	// Get proxy port for this tunnel.
	proxyPort, portOk := pr.registry.GetProxyPort(entry.TunnelID)
	if !portOk {
		return A.FilterActionPass
	}

	// Hairpin redirect to proxy.
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
	pr.tcp.DstPort = layers.TCPPort(proxyPort)

	pr.serializePacket(b)
	return A.FilterActionRedirect
}

// RegisterProxyPort adds a port to the proxy port set for O(1) hot-path lookup.
func (pr *PacketRouter) RegisterProxyPort(port uint16) {
	pr.proxyPortsMu.Lock()
	pr.proxyPorts[port] = struct{}{}
	pr.proxyPortsMu.Unlock()
}

// UnregisterProxyPort removes a port from the proxy port set.
func (pr *PacketRouter) UnregisterProxyPort(port uint16) {
	pr.proxyPortsMu.Lock()
	delete(pr.proxyPorts, port)
	pr.proxyPortsMu.Unlock()
}

// isProxySourcePort checks if the source port belongs to one of our tunnel proxies.
// O(1) map lookup — safe for the hot path.
func (pr *PacketRouter) isProxySourcePort(port uint16) bool {
	pr.proxyPortsMu.RLock()
	_, ok := pr.proxyPorts[port]
	pr.proxyPortsMu.RUnlock()
	return ok
}

// serializePacket recomputes checksums and writes the modified packet back.
// Uses pre-allocated serialize buffer — zero allocations on hot path.
func (pr *PacketRouter) serializePacket(b *A.IntermediateBuffer) {
	pr.tcp.SetNetworkLayerForChecksum(&pr.ip4)

	pr.serBuf.Clear()
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(pr.serBuf, opts,
		&pr.eth, &pr.ip4, &pr.tcp, gopacket.Payload(pr.tcp.Payload),
	); err != nil {
		return
	}

	data := pr.serBuf.Bytes()
	copy(b.Buffer[:len(data)], data)
	b.Length = uint32(len(data))
}

// LookupNAT returns the original destination for a NAT'd TCP connection.
// addrKey must be the string form of the remote address (e.g. "1.2.3.4:5678").
func (pr *PacketRouter) LookupNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	pr.natMu.RLock()
	entry, exists := pr.nat[addrKey]
	pr.natMu.RUnlock()
	if !exists {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}

// ---------------------------------------------------------------------------
// UDP interception, NAT hairpin, and proxy port management
// ---------------------------------------------------------------------------

// handleUDPOutgoing processes an outgoing UDP packet: new flow or existing NAT entry.
func (pr *PacketRouter) handleUDPOutgoing(b *A.IntermediateBuffer, handle A.Handle) A.FilterAction {
	srcIP, _ := netip.AddrFromSlice(pr.ip4.SrcIP)
	dstIP, _ := netip.AddrFromSlice(pr.ip4.DstIP)
	srcPort := uint16(pr.udp.SrcPort)
	dstPort := uint16(pr.udp.DstPort)

	// Skip broadcast and multicast — never tunnel these.
	if dstIP.IsMulticast() || dstIP == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return A.FilterActionPass
	}

	src := netip.AddrPortFrom(srcIP, srcPort)
	dst := netip.AddrPortFrom(dstIP, dstPort)

	// Handle packets FROM UDP proxy back to client.
	if pr.isUDPProxySourcePort(srcPort) {
		return pr.handleUDPProxyResponse(b, dst)
	}

	// NAT key: dstIP:srcPort — invariant across hairpin.
	natKey := netip.AddrPortFrom(dst.Addr(), src.Port()).String()

	// Fast path: existing NAT entry — just update activity and redirect.
	pr.udpNatMu.RLock()
	entry, exists := pr.udpNat[natKey]
	pr.udpNatMu.RUnlock()

	if exists {
		// Update last activity timestamp.
		pr.udpNatMu.Lock()
		entry.LastActivity = time.Now()
		pr.udpNat[natKey] = entry
		pr.udpNatMu.Unlock()

		udpProxyPort, ok := pr.registry.GetUDPProxyPort(entry.TunnelID)
		if !ok {
			return A.FilterActionPass
		}

		pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
		pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
		pr.udp.DstPort = layers.UDPPort(udpProxyPort)

		pr.serializeUDPPacket(b)
		return A.FilterActionRedirect
	}

	// Slow path: new flow — process lookup + rule match.
	info, err := pr.process.FindProcessInfo(context.Background(), false, src, dst, true)
	if err != nil {
		return A.FilterActionPass
	}

	result := pr.rules.Match(info.PathName)
	if !result.Matched {
		return A.FilterActionPass
	}

	if result.Fallback == PolicyDrop {
		return A.FilterActionDrop
	}

	tunnelEntry, ok := pr.registry.Get(result.TunnelID)
	if !ok {
		if result.Fallback == PolicyBlock {
			return A.FilterActionDrop
		}
		return A.FilterActionPass
	}

	if tunnelEntry.State != TunnelStateUp {
		switch result.Fallback {
		case PolicyBlock:
			return A.FilterActionDrop
		case PolicyAllowDirect:
			return A.FilterActionPass
		}
		return A.FilterActionPass
	}

	// Tunnel is UP — create NAT entry and redirect.
	pr.udpNatMu.Lock()
	pr.udpNat[natKey] = UDPNATEntry{
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
		LastActivity:    time.Now(),
	}
	pr.udpNatMu.Unlock()

	udpProxyPort, ok := pr.registry.GetUDPProxyPort(result.TunnelID)
	if !ok {
		return A.FilterActionPass
	}

	// Hairpin redirect to UDP proxy.
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
	pr.udp.DstPort = layers.UDPPort(udpProxyPort)

	pr.serializeUDPPacket(b)
	return A.FilterActionRedirect
}

// handleUDPProxyResponse handles packets from a UDP proxy back to the client.
// Restores the original server IP and port so the client sees the expected source.
func (pr *PacketRouter) handleUDPProxyResponse(b *A.IntermediateBuffer, dst netip.AddrPort) A.FilterAction {
	natKey := dst.String()

	pr.udpNatMu.RLock()
	entry, ok := pr.udpNat[natKey]
	pr.udpNatMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Restore original source: the server the client intended to reach.
	pr.udp.SrcPort = layers.UDPPort(entry.OriginalDstPort)
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
	pr.ip4.SrcIP = entry.OriginalDstIP.AsSlice()

	pr.serializeUDPPacket(b)
	return A.FilterActionRedirect
}

// serializeUDPPacket recomputes checksums and writes the modified UDP packet back.
// Uses pre-allocated serialize buffer — zero allocations on hot path.
func (pr *PacketRouter) serializeUDPPacket(b *A.IntermediateBuffer) {
	pr.udp.SetNetworkLayerForChecksum(&pr.ip4)

	pr.serBuf.Clear()
	opts := gopacket.SerializeOptions{
		FixLengths:       false,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(pr.serBuf, opts,
		&pr.eth, &pr.ip4, &pr.udp, gopacket.Payload(pr.udp.Payload),
	); err != nil {
		return
	}

	data := pr.serBuf.Bytes()
	copy(b.Buffer[:len(data)], data)
	b.Length = uint32(len(data))
}

// RegisterUDPProxyPort adds a port to the UDP proxy port set for O(1) hot-path lookup.
func (pr *PacketRouter) RegisterUDPProxyPort(port uint16) {
	pr.udpProxyPortsMu.Lock()
	pr.udpProxyPorts[port] = struct{}{}
	pr.udpProxyPortsMu.Unlock()
}

// UnregisterUDPProxyPort removes a port from the UDP proxy port set.
func (pr *PacketRouter) UnregisterUDPProxyPort(port uint16) {
	pr.udpProxyPortsMu.Lock()
	delete(pr.udpProxyPorts, port)
	pr.udpProxyPortsMu.Unlock()
}

// isUDPProxySourcePort checks if the source port belongs to one of our UDP tunnel proxies.
func (pr *PacketRouter) isUDPProxySourcePort(port uint16) bool {
	pr.udpProxyPortsMu.RLock()
	_, ok := pr.udpProxyPorts[port]
	pr.udpProxyPortsMu.RUnlock()
	return ok
}

// LookupUDPNAT returns the original destination for a NAT'd UDP flow.
// addrKey must be the string form of the remote address (e.g. "1.2.3.4:5678").
func (pr *PacketRouter) LookupUDPNAT(addrKey string) (originalDst string, tunnelID string, ok bool) {
	pr.udpNatMu.RLock()
	entry, exists := pr.udpNat[addrKey]
	pr.udpNatMu.RUnlock()
	if !exists {
		return "", "", false
	}

	dst := netip.AddrPortFrom(entry.OriginalDstIP, entry.OriginalDstPort)
	return dst.String(), entry.TunnelID, true
}

// udpNATCleanup periodically removes stale UDP NAT entries.
// DNS flows (port 53) expire after 10s; all others after 2min.
func (pr *PacketRouter) udpNATCleanup(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			pr.udpNatMu.Lock()
			for key, entry := range pr.udpNat {
				timeout := 2 * time.Minute
				if entry.OriginalDstPort == 53 {
					timeout = 10 * time.Second
				}
				if now.Sub(entry.LastActivity) > timeout {
					delete(pr.udpNat, key)
				}
			}
			pr.udpNatMu.Unlock()
		}
	}
}
