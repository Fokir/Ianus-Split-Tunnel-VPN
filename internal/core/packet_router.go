//go:build windows

package core

import (
	"context"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	A "github.com/wiresock/ndisapi-go"
	D "github.com/wiresock/ndisapi-go/driver"
	N "github.com/wiresock/ndisapi-go/netlib"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// natKey is a compact, allocation-free key for NAT maps.
// Layout: 4 bytes IPv4 address + 2 bytes port (big-endian).
// Used instead of netip.AddrPort.String() to eliminate per-packet string allocations.
type natKey [6]byte

func makeNATKey(ip netip.Addr, port uint16) natKey {
	var k natKey
	ip4 := ip.As4()
	copy(k[:4], ip4[:])
	k[4] = byte(port >> 8)
	k[5] = byte(port)
	return k
}

// NATEntry maps a redirected TCP connection back to its original destination.
type NATEntry struct {
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	ProxyPort       uint16 // cached to avoid per-packet registry lookup
}

// UDPNATEntry maps a redirected UDP flow back to its original destination.
// Includes LastActivity for timeout-based cleanup (UDP has no FIN/RST).
type UDPNATEntry struct {
	// LastActivity is first for 64-bit alignment; accessed atomically (UnixNano).
	LastActivity    int64
	OriginalDstIP   netip.Addr
	OriginalDstPort uint16
	TunnelID        string
	UDPProxyPort    uint16 // cached to avoid per-packet registry lookup
}

// PacketRouter intercepts network packets via NDISAPI, performs process-based
// routing decisions, and manages the NAT table for hairpin redirects.
type PacketRouter struct {
	api           *A.NdisApi
	filter        *D.QueuedPacketFilter
	staticFilters *D.StaticFilters
	process       *N.ProcessLookup

	registry *TunnelRegistry
	rules    *RuleEngine
	bus      *EventBus

	// TCP NAT table: key = dstIP:srcPort as [6]byte (invariant across hairpin redirect).
	natMu sync.RWMutex
	nat   map[natKey]NATEntry

	// TCP proxy port set for O(1) lookup on hot path.
	proxyPortsMu sync.RWMutex
	proxyPorts   map[uint16]struct{}

	// UDP NAT table: key = dstIP:srcPort as [6]byte (invariant across hairpin redirect).
	// Stores pointers for lock-free atomic LastActivity updates on hot path.
	udpNatMu sync.RWMutex
	udpNat   map[natKey]*UDPNATEntry

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
		nat:           make(map[natKey]NATEntry),
		proxyPorts:    make(map[uint16]struct{}),
		udpNat:        make(map[natKey]*UDPNATEntry),
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

	// Initialize kernel-level static filters with caching.
	sf, err := D.NewStaticFilters(api, true, true)
	if err != nil {
		log.Printf("[Router] Warning: static filters unavailable: %v", err)
	} else {
		pr.staticFilters = sf
		// Pass ICMP in both directions (no need to process in callback).
		sf.AddFilterBack(&D.Filter{
			Action:             A.FilterActionPass,
			Direction:          D.PacketDirectionBoth,
			SourceAddress:      net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			DestinationAddress: net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Protocol:           1, // ICMP
		})
	}

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

	pr.filter, err = D.NewQueuedPacketFilter(
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
	if pr.staticFilters != nil {
		pr.staticFilters.Close()
	}
	if pr.api != nil {
		pr.api.Close()
	}
	log.Printf("[Router] Packet filter stopped")
}

// AddEndpointBypass adds kernel-level static filters to pass VPN server
// traffic directly, bypassing the packet callback. This prevents
// double-processing of encrypted tunnel traffic and significantly improves throughput.
func (pr *PacketRouter) AddEndpointBypass(ip net.IP, port uint16) {
	if pr.staticFilters == nil {
		return
	}

	// Outgoing UDP to VPN server endpoint.
	pr.staticFilters.AddFilterBack(&D.Filter{
		Action:             A.FilterActionPass,
		Direction:          D.PacketDirectionOut,
		SourceAddress:      net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		DestinationAddress: net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		Protocol:           uint8(syscall.IPPROTO_UDP),
		DestinationPort:    [2]uint16{port, port},
	})

	// Incoming UDP from VPN server endpoint.
	pr.staticFilters.AddFilterBack(&D.Filter{
		Action:             A.FilterActionPass,
		Direction:          D.PacketDirectionIn,
		SourceAddress:      net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)},
		DestinationAddress: net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
		Protocol:           uint8(syscall.IPPROTO_UDP),
		SourcePort:         [2]uint16{port, port},
	})

	log.Printf("[Router] Added static bypass for VPN endpoint %s:%d", ip, port)
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
	nk := makeNATKey(dst.Addr(), src.Port())
	pr.natMu.Lock()
	pr.nat[nk] = NATEntry{
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
		ProxyPort:       entry.ProxyPort,
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
	nk := makeNATKey(dst.Addr(), dst.Port())

	pr.natMu.RLock()
	entry, ok := pr.nat[nk]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Clean up NAT entry on FIN/RST.
	if pr.tcp.FIN || pr.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, nk)
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
	nk := makeNATKey(dst.Addr(), src.Port())

	pr.natMu.RLock()
	entry, ok := pr.nat[nk]
	pr.natMu.RUnlock()
	if !ok {
		return A.FilterActionPass
	}

	// Clean up NAT entry on FIN/RST.
	if pr.tcp.FIN || pr.tcp.RST {
		pr.natMu.Lock()
		delete(pr.nat, nk)
		pr.natMu.Unlock()
	}

	// Hairpin redirect to proxy (proxy port cached in NAT entry — no registry lookup).
	pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
	pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
	pr.tcp.DstPort = layers.TCPPort(entry.ProxyPort)

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
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())

	pr.natMu.RLock()
	entry, exists := pr.nat[nk]
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

	// NAT key: dstIP:srcPort — invariant across hairpin. Zero-alloc binary key.
	nk := makeNATKey(dst.Addr(), src.Port())

	// Fast path: existing NAT entry — just update activity and redirect.
	pr.udpNatMu.RLock()
	entry, exists := pr.udpNat[nk]
	pr.udpNatMu.RUnlock()

	if exists {
		// Update last activity timestamp atomically — no write lock needed.
		atomic.StoreInt64(&entry.LastActivity, time.Now().UnixNano())

		pr.eth.SrcMAC, pr.eth.DstMAC = pr.eth.DstMAC, pr.eth.SrcMAC
		pr.ip4.DstIP, pr.ip4.SrcIP = pr.ip4.SrcIP.To4(), pr.ip4.DstIP.To4()
		pr.udp.DstPort = layers.UDPPort(entry.UDPProxyPort)

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
	udpProxyPort, ok := pr.registry.GetUDPProxyPort(result.TunnelID)
	if !ok {
		return A.FilterActionPass
	}

	pr.udpNatMu.Lock()
	pr.udpNat[nk] = &UDPNATEntry{
		LastActivity:    time.Now().UnixNano(),
		OriginalDstIP:   dst.Addr(),
		OriginalDstPort: dst.Port(),
		TunnelID:        result.TunnelID,
		UDPProxyPort:    udpProxyPort,
	}
	pr.udpNatMu.Unlock()

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
	nk := makeNATKey(dst.Addr(), dst.Port())

	pr.udpNatMu.RLock()
	entry, ok := pr.udpNat[nk]
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
	ap, err := netip.ParseAddrPort(addrKey)
	if err != nil {
		return "", "", false
	}
	nk := makeNATKey(ap.Addr(), ap.Port())

	pr.udpNatMu.RLock()
	entry, exists := pr.udpNat[nk]
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
				last := time.Unix(0, atomic.LoadInt64(&entry.LastActivity))
				if now.Sub(last) > timeout {
					delete(pr.udpNat, key)
				}
			}
			pr.udpNatMu.Unlock()
		}
	}
}
